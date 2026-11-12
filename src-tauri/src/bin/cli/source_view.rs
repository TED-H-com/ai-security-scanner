use super::provider_common::{deliver, envelope, error, mutate};
use super::*;
use ai_security_scanner_lib::cloudflare_provider::source_view::{
    PreparationOutcome, PrepareSourceViewRequest, inspect_source_view, prepare_source_view,
};

#[derive(Debug, Clone, Args)]
pub(super) struct PrepareArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    asset_id: String,
    #[arg(long)]
    expected_snapshot_sha256: String,
    /// Explicit canonical file or directory selectors; . selects the whole snapshot.
    #[arg(long)]
    scope_path: Vec<String>,
    #[arg(long)]
    request_id: String,
    /// Allow the selected view to reach the host's configured model service.
    #[arg(long)]
    acknowledge_model_processing: bool,
    #[arg(long)]
    confirmed_by: Option<String>,
    /// Caller-declared identifier, never a verified host identity (1–128 ASCII ID characters).
    #[arg(long)]
    host_id: Option<String>,
}
pub(super) async fn execute(
    cli: &Cli,
    command: &CloudflareCommand,
    sources: GlobalOptionSources,
) -> Option<u8> {
    match command {
        CloudflareCommand::InspectSourceView {
            input,
            expected_manifest_sha256,
            canonical_payload,
        } => {
            let mut response = envelope("inspect-source-view");
            match inspect_source_view(
                input,
                expected_manifest_sha256.as_deref(),
                canonical_payload.as_deref(),
            ) {
                Ok(result) => response["result"] = json!(result),
                Err(e) => response = error(response, e),
            }
            Some(deliver(response, cli.json))
        }
        CloudflareCommand::SourceViewStatus {
            case_id,
            request_id,
        } => {
            let mut response = envelope("source-view-status");
            response["case_id"] = json!(case_id);
            response["request_id"] = json!(request_id);
            let result = (|| -> AppResult<_> {
                let data = resolve_data_dir(cli.data_dir.clone())?;
                let storage = Storage::open_read_only(data.join("casework.db"))?;
                storage.get_case(case_id)?;
                storage
                    .source_view_receipt(case_id, request_id)?
                    .ok_or_else(|| {
                        AppError::InvalidRequest(
                            "no saved source-view receipt for this request".into(),
                        )
                    })
            })();
            match result {
                Ok(receipt) => {
                    response["case_revision"] = json!(receipt.case_revision);
                    response["result"] = json!({"receipt":receipt,"historical_only":true,"analysis_performed":false});
                }
                Err(e) => response = error(response, e),
            }
            Some(deliver(response, cli.json))
        }
        CloudflareCommand::PrepareSourceView(args) => Some(prepare(cli, args, sources).await),
        _ => None,
    }
}
async fn prepare(cli: &Cli, args: &PrepareArgs, sources: GlobalOptionSources) -> u8 {
    let mut response = envelope("prepare-source-view");
    response["case_id"] = json!(args.case_id);
    response["request_id"] = json!(args.request_id);
    if !sources.data_dir_was_explicit() || cli.data_dir.is_none() {
        return deliver(
            error(
                response,
                AppError::InvalidRequest("prepare-source-view requires explicit --data-dir".into()),
            ),
            cli.json,
        );
    }
    let request = PrepareSourceViewRequest {
        case_id: args.case_id.clone(),
        asset_id: args.asset_id.clone(),
        expected_snapshot_sha256: args.expected_snapshot_sha256.clone(),
        scope_paths: args.scope_path.clone(),
        request_id: args.request_id.clone(),
        acknowledge_model_processing: args.acknowledge_model_processing,
        confirmed_by: args.confirmed_by.clone().unwrap_or_default(),
        declared_host_id: args.host_id.clone().unwrap_or_default(),
    };
    if let Err(e) = request.normalize() {
        return deliver(error(response, e), cli.json);
    }
    let (result, signal) = match mutate(
        cli.data_dir.clone().unwrap(),
        request.case_id.clone(),
        move |context| prepare_source_view(context, &request),
    )
    .await
    {
        Ok(result) => result,
        Err(e) => return deliver(error(response, e), cli.json),
    };
    let response = preparation_response(response, result, cli.data_dir.as_ref().unwrap(), signal);
    deliver(response, cli.json)
}

fn preparation_response(
    mut response: Value,
    result: Result<AppResult<PreparationOutcome>, tokio::task::JoinError>,
    data: &Path,
    signal: u8,
) -> Value {
    match result {
        Ok(Ok(outcome @ (PreparationOutcome::Committed(_) | PreparationOutcome::Replayed(_)))) => {
            let replayed = matches!(outcome, PreparationOutcome::Replayed(_));
            let (PreparationOutcome::Committed(receipt) | PreparationOutcome::Replayed(receipt)) =
                outcome
            else {
                unreachable!()
            };
            response["command_outcome"] = json!("committed");
            response["case_revision"] = json!(receipt.case_revision);
            response["receipt"] = json!({"id":receipt.request_id,"sha256":receipt.digest});
            response["result"] = json!(receipt.result);
            response["result"]["replayed"] = json!(replayed);
            response["result"]["analysis_performed"] = json!(false);
            response["result"]["recovery"] = Value::Null;
            if let ai_security_scanner_lib::cloudflare_provider::source_view::PreparationResult::Ready {
                view_id, view_sha256, manifest_sha256, manifest_byte_length, relative_path,
            } = &receipt.result {
                let root = data.join("artifacts").join(relative_path);
                response["result"]["view"] = json!({"path":root.join("tree"),"view_id":view_id,"view_sha256":view_sha256});
                response["result"]["manifest"] = json!({"path":root.join("view.json"),"sha256":manifest_sha256,"byte_length":manifest_byte_length});
                response["result"]["blockers"] = json!([]);
            } else {
                response["result"]["view"] = Value::Null;
                response["result"]["manifest"] = Value::Null;
            }
        }
        Ok(Ok(PreparationOutcome::SavedNotCurrent(reason))) => {
            response["command_outcome"] = json!("rejected");
            response["exit_code"] = json!(3);
            response["error_code"] = json!("saved_receipt_not_current");
            response["reason"] = json!(reason);
        }
        Ok(Ok(PreparationOutcome::Interrupted)) => {
            response["exit_code"] = json!(signal);
            response["command_outcome"] = json!("interrupted");
        }
        Ok(Err(e)) => response = error(response, e),
        Err(e) => response = error(response, AppError::Internal(e.to_string())),
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_security_scanner_lib::cloudflare_provider::source_view::{
        BlockerCode, SavedNotCurrentReason, SourceViewPreparationReceipt,
    };

    #[test]
    fn committed_result_wins_over_late_signal_and_stale_replay_has_no_paths() {
        let receipt: SourceViewPreparationReceipt = serde_json::from_value(json!({
            "schema_version":"test", "case_id":"case", "asset_id":"asset", "source_id":"source",
            "request_id":"request", "request_sha256":"test", "case_revision":1, "event_sequence":1,
            "occurred_at":"test", "acknowledgement_sha256":"test", "grant":null, "grant_sha256":null,
            "analysis_performed":false, "digest":"test",
            "acknowledgement": {"schema_version":"test", "case_id":"case", "asset_id":"asset",
                "canonical_snapshot_sha256":"test", "scope":["."], "policy_id":"test", "declared_host_id":"test",
                "host_identity_verified":false, "confirmed_by":"owner", "confirmed_at":"test", "acknowledged":true},
            "result":{"status":"ready", "view_id":"view", "manifest_sha256":"test", "manifest_byte_length":1,
                "view_sha256":"test", "relative_path":"case/source-views/view"}
        })).unwrap();
        for signal in [0, 130, 143] {
            let response = preparation_response(
                envelope("prepare-source-view"),
                Ok(Ok(PreparationOutcome::Committed(receipt.clone()))),
                Path::new("data"),
                signal,
            );
            assert_eq!(response["exit_code"], 0);
            assert_eq!(response["command_outcome"], "committed");
            assert_eq!(response["result"]["status"], "ready");
            assert_eq!(response["result"]["replayed"], false);
        }
        let response = preparation_response(
            envelope("prepare-source-view"),
            Ok(Ok(PreparationOutcome::SavedNotCurrent(
                SavedNotCurrentReason::Blocker(BlockerCode::SourceAuthorizationExpired),
            ))),
            Path::new("data"),
            130,
        );
        assert_eq!(response["exit_code"], 3);
        assert_eq!(response["error_code"], "saved_receipt_not_current");
        assert_eq!(response["reason"], "source_authorization_expired");
        assert_eq!(response["retryable"], false);
        assert!(response["result"].is_null());
        assert!(response["receipt"].is_null());
        let response = preparation_response(
            envelope("prepare-source-view"),
            Ok(Ok(PreparationOutcome::Interrupted)),
            Path::new("data"),
            130,
        );
        assert_eq!(response["exit_code"], 130);
        assert!(response["result"].is_null());
    }
}
