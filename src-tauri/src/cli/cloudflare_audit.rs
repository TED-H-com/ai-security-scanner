use super::provider_common::{deliver, envelope, error, mutate};
use super::*;
use ai_security_scanner_lib::cloudflare_provider::audit::{
    self, PreparationOutcome, PrepareRequest,
    record::{CheckpointOutcome, CheckpointRequest, Refusal},
};
#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("selector").required(true).multiple(false).args(["session_id", "prepare_request_id"])))]
pub(super) struct StatusArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    session_id: Option<String>,
    #[arg(long)]
    prepare_request_id: Option<String>,
}
#[derive(Debug, Args)]
pub(super) struct RetrieveArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    session_id: String,
    #[arg(long)]
    document: Option<String>,
    #[arg(long)]
    revision: Option<String>,
    #[arg(long)]
    assignment_id: Option<String>,
    #[arg(long)]
    destination: PathBuf,
    #[arg(long)]
    expected_sha256: Option<String>,
    #[arg(long)]
    expected_head_sha256: Option<String>,
}

fn retrieve(cli: &Cli, args: &RetrieveArgs, sources: GlobalOptionSources) -> u8 {
    use audit::{
        captured::Selector,
        retrieve::{Observation, Request},
    };
    let mut value = response("retrieve-captured");
    value["case_id"] = json!(args.case_id);
    value["session_id"] = json!(args.session_id);
    value["destination"] = json!(args.destination);
    value["selector"] = json!({"document":args.document,"revision":args.revision,"assignment_id":args.assignment_id});
    let mut observed = Observation::default();
    let result = (|| -> AppResult<PathBuf> {
        if !sources.data_dir_was_explicit() || cli.data_dir.is_none() {
            return Err(AppError::InvalidRequest(
                "retrieve-captured requires explicit --data-dir".into(),
            ));
        }
        let invalid = || {
            AppError::InvalidRequest(
                "select document plus positive revision, or assignment-id".into(),
            )
        };
        let selector = match (&args.document, &args.revision, &args.assignment_id) {
            (Some(name), Some(revision), None) => Selector::Document {
                name: name.clone(),
                revision: revision
                    .parse::<u64>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(invalid)?,
            },
            (None, None, Some(id)) => Selector::Assignment {
                assignment_id: id.clone(),
            },
            _ => return Err(invalid()),
        };
        value["selector"] = json!(selector);
        let roots: Vec<_> = resolve_data_dir(None)
            .ok()
            .into_iter()
            .chain(legacy_project_data_dir())
            .collect();
        audit::retrieve::retrieve(
            cli.data_dir.as_ref().unwrap(),
            &roots,
            &Request {
                case_id: &args.case_id,
                session_id: &args.session_id,
                selector,
                destination: &args.destination,
                expected_sha256: args.expected_sha256.as_deref(),
                expected_head_sha256: args.expected_head_sha256.as_deref(),
            },
            &mut observed,
        )
    })();
    match result {
        Ok(destination) => value["destination"] = json!(destination),
        Err(e) => value = error(value, e),
    }
    value.as_object_mut().unwrap().extend(
        serde_json::to_value(observed)
            .unwrap()
            .as_object()
            .unwrap()
            .clone(),
    );
    deliver(value, cli.json)
}

fn response(operation: &str) -> Value {
    let mut value = envelope(operation);
    value["schema_version"] = json!("ai-security-scanner.cloudflare-audit-command/v1");
    value
}
pub(super) async fn execute(
    cli: &Cli,
    command: &CloudflareCommand,
    sources: GlobalOptionSources,
) -> Option<u8> {
    match command {
        CloudflareCommand::RetrieveCaptured(args) => Some(retrieve(cli, args, sources)),
        CloudflareCommand::Admit { request } => {
            use audit::admit::{AdmissionError, AdmitRequest};
            let mut value = response("admit");
            let retry_command = json!(["provider", "cloudflare", "admit", "--request", request]);
            let request = match AdmitRequest::read(request) {
                Ok(r) => r,
                Err(e) => return Some(deliver(admission_error(value, e), cli.json)),
            };
            value["case_id"] = json!(request.case_id);
            value["session_id"] = json!(request.session_id);
            value["request_id"] = json!(request.request_id);
            if !sources.data_dir_was_explicit() || cli.data_dir.is_none() {
                return Some(deliver(
                    admission_error(
                        value,
                        AdmissionError::Refused {
                            code: "invalid_request",
                            exit: 2,
                            retryable: false,
                        },
                    ),
                    cli.json,
                ));
            }
            match mutate(
                cli.data_dir.clone().unwrap(),
                request.case_id.clone(),
                move |context| Ok(audit::admit::admit(context, &request)),
            )
            .await
            {
                Ok((Ok(Ok(Ok(outcome))), _)) => {
                    value["command_outcome"] = json!(if outcome.replayed {
                        "replayed"
                    } else {
                        "committed"
                    });
                    for key in ["run_id", "task_id", "case_revision"] {
                        value[key] = outcome.receipt[key].clone();
                    }
                    value["receipt"] = outcome.receipt;
                    value["result"] = outcome.result;
                    if value["result"]["report_snapshot_state"] == "pending" {
                        value["result"]["report_snapshot_retry_command"] = retry_command;
                    }
                }
                Ok((Ok(Ok(Err(e))), _)) => value = admission_error(value, e),
                Ok((Ok(Err(e)), _)) | Err(e) => value = error(value, e),
                Ok((Err(e), _)) => value = error(value, AppError::Internal(e.to_string())),
            }
            Some(deliver(value, cli.json))
        }
        CloudflareCommand::InspectSealed {
            case_id,
            session_id,
        } => {
            let mut value = response("inspect-sealed");
            value["case_id"] = json!(case_id);
            value["session_id"] = json!(session_id);
            let mut inspect = || -> AppResult<Value> {
                let data = resolve_data_dir(cli.data_dir.clone())?;
                let storage = Storage::open_read_only(data.join("casework.db"))?;
                let case = storage.get_case(case_id)?;
                value["case_revision"] = json!(case.storage_revision());
                let verified = audit::sealed::verify(&data, &storage, case_id, session_id);
                match verified.and_then(|v| {
                    v.recheck_unchanged()?;
                    Ok(v)
                }) {
                    Ok(verified) => {
                        value["request_id"] = json!(verified.preparation_request_id);
                        value["result"] = json!(verified);
                        value["result"]["next_operation"] = json!("admit");
                        audit::admit::status(&case, session_id, &data, &mut value["result"]);
                        let receipt = storage
                            .cloudflare_audit_receipt(case_id, session_id, true)?
                            .ok_or_else(|| {
                                AppError::InvalidRequest("unknown audit preparation".into())
                            })?;
                        ai_security_scanner_lib::cloudflare_provider::restored::Context::load(
                            &storage, &receipt,
                        )?
                        .present(&mut value["result"], true);
                    }
                    Err(failure) if failure.error_code == "case_changed" => {
                        value["command_outcome"] = json!("conflict");
                        value["exit_code"] = json!(3);
                        value["retryable"] = json!(true);
                        value["error_code"] = json!(failure.error_code);
                        value["failed_check"] = json!(failure.failed_check);
                        value["error"] = json!("the case changed during verification; retry");
                    }
                    Err(failure) => {
                        value["command_outcome"] = json!("rejected");
                        value["exit_code"] = json!(2);
                        value["error_code"] = json!(failure.error_code);
                        value["failed_check"] = json!(failure.failed_check);
                        value["error"] = json!(format!(
                            "sealed audit verification failed: {}",
                            failure.failed_check
                        ));
                    }
                }
                Ok(value.clone())
            };
            let result = inspect();
            Some(deliver(
                match result {
                    Ok(v) => v,
                    Err(e) => error(value, e),
                },
                cli.json,
            ))
        }

        CloudflareCommand::Validate { request } => {
            use audit::validation::{ValidateRequest, ValidationOutcome};
            let mut value = response("validate");
            let request = match ValidateRequest::read(request) {
                Ok(request) => request,
                Err(code) => return Some(deliver(refused(value, code, None), cli.json)),
            };
            value["case_id"] = json!(request.case_id);
            value["session_id"] = json!(request.session_id);
            if !sources.data_dir_was_explicit() || cli.data_dir.is_none() {
                return Some(deliver(
                    refused(value, Refusal::InvalidRequest, None),
                    cli.json,
                ));
            }
            match mutate(
                cli.data_dir.clone().unwrap(),
                request.case_id.clone(),
                move |context| audit::validation::validate(context, &request),
            )
            .await
            {
                Ok((Ok(Ok(ValidationOutcome::Validated(result))), _)) => value["result"] = *result,
                Ok((Ok(Ok(ValidationOutcome::Rejected { error_code, reason })), _)) => {
                    value = refused(value, error_code, reason);
                }
                Ok((Ok(Err(e)), _)) | Err(e) => value = error(value, e),
                Ok((Err(e), _)) => value = error(value, AppError::Internal(e.to_string())),
            }
            Some(deliver(value, cli.json))
        }
        CloudflareCommand::Finalize { request } => {
            use audit::finalize::{FinalizeOutcome, FinalizeRequest};
            let mut value = response("finalize");
            let request = match FinalizeRequest::read(request) {
                Ok(r) => r,
                Err(code) => return Some(deliver(refused(value, code, None), cli.json)),
            };
            value["case_id"] = json!(request.case_id);
            value["session_id"] = json!(request.session_id);
            value["request_id"] = json!(request.request_id);
            if !sources.data_dir_was_explicit() || cli.data_dir.is_none() {
                return Some(deliver(
                    refused(value, Refusal::InvalidRequest, None),
                    cli.json,
                ));
            }
            match mutate(
                cli.data_dir.clone().unwrap(),
                request.case_id.clone(),
                move |context| audit::finalize::finalize(context, &request),
            )
            .await
            {
                Ok((Ok(Ok(FinalizeOutcome::Record(outcome))), signal)) => {
                    value = record_response(value, outcome, signal)
                }
                Ok((Ok(Ok(FinalizeOutcome::NotSealable(result))), _)) => {
                    value = refused(value, Refusal::NotSealable, None);
                    value["result"] = *result;
                }
                Ok((Ok(Ok(FinalizeOutcome::Validation(outcome))), _)) => match outcome {
                    audit::validation::ValidationOutcome::Rejected { error_code, reason } => {
                        value = refused(value, error_code, reason)
                    }
                    audit::validation::ValidationOutcome::Validated(_) => unreachable!(),
                },
                Ok((Ok(Err(e)), _)) | Err(e) => value = error(value, e),
                Ok((Err(e), _)) => value = error(value, AppError::Internal(e.to_string())),
            }
            Some(deliver(value, cli.json))
        }
        CloudflareCommand::Prepare { request } => {
            let mut value = response("prepare");
            let request = match PrepareRequest::read(request) {
                Ok(request) => request,
                Err(e) => return Some(deliver(error(value, e), cli.json)),
            };
            value["case_id"] = json!(request.case_id);
            value["request_id"] = json!(request.request_id);
            if !sources.data_dir_was_explicit() || cli.data_dir.is_none() {
                return Some(deliver(
                    error(
                        value,
                        AppError::InvalidRequest("prepare requires explicit --data-dir".into()),
                    ),
                    cli.json,
                ));
            }
            let result = mutate(
                cli.data_dir.clone().unwrap(),
                request.case_id.clone(),
                move |context| audit::prepare(context, &request),
            )
            .await;
            match result {
                Ok((
                    Ok(Ok(PreparationOutcome::Saved {
                        receipt,
                        replayed,
                        outcome_run,
                    })),
                    _,
                )) => {
                    value["command_outcome"] = json!("committed");
                    value["case_revision"] = json!(receipt.case_revision);
                    value["session_id"] = json!(receipt.session_id());
                    value["receipt"] =
                        json!({"id":receipt.request_id, "sha256":receipt.receipt_sha256});
                    value["result"] = json!({"receipt":receipt, "replayed":replayed});
                    if let Some(outcome_run) = outcome_run {
                        value["result"]["outcome_run"] = outcome_run;
                    }
                }
                Ok((Ok(Ok(PreparationOutcome::SavedNotCurrent(reason))), _)) => {
                    value["command_outcome"] = json!("rejected");
                    value["exit_code"] = json!(3);
                    value["error_code"] = json!("saved_receipt_not_current");
                    value["reason"] = json!(reason);
                }
                Ok((Ok(Ok(PreparationOutcome::Interrupted)), signal)) => {
                    value["command_outcome"] = json!("interrupted");
                    value["exit_code"] = json!(signal);
                }
                Ok((Ok(Err(e)), _)) | Err(e) => value = error(value, e),
                Ok((Err(e), _)) => value = error(value, AppError::Internal(e.to_string())),
            }
            Some(deliver(value, cli.json))
        }
        CloudflareCommand::Terminate { request } => {
            let mut value = response("terminate");
            let request = match audit::terminate::TerminateRequest::read(request) {
                Ok(r) => r,
                Err(code) => return Some(deliver(refused(value, code, None), cli.json)),
            };
            value["case_id"] = json!(request.case_id);
            value["request_id"] = json!(request.request_id);
            value["session_id"] = json!(request.session_id);
            if !sources.data_dir_was_explicit() || cli.data_dir.is_none() {
                return Some(deliver(
                    refused(value, Refusal::InvalidRequest, None),
                    cli.json,
                ));
            }
            match mutate(
                cli.data_dir.clone().unwrap(),
                request.case_id.clone(),
                move |context| audit::terminate::terminate(context, &request),
            )
            .await
            {
                Ok((Ok(Ok(outcome)), signal)) => value = record_response(value, outcome, signal),
                Ok((Ok(Err(e)), _)) | Err(e) => value = error(value, e),
                Ok((Err(e), _)) => value = error(value, AppError::Internal(e.to_string())),
            }
            Some(deliver(value, cli.json))
        }
        CloudflareCommand::Checkpoint { request } => {
            let mut value = response("checkpoint");
            let request = match CheckpointRequest::read(request) {
                Ok(r) => r,
                Err(code) => return Some(deliver(refused(value, code, None), cli.json)),
            };
            value["case_id"] = json!(request.case_id);
            value["request_id"] = json!(request.request_id);
            value["session_id"] = json!(request.session_id);
            if !sources.data_dir_was_explicit() || cli.data_dir.is_none() {
                return Some(deliver(
                    refused(value, Refusal::InvalidRequest, None),
                    cli.json,
                ));
            }
            match mutate(
                cli.data_dir.clone().unwrap(),
                request.case_id.clone(),
                move |context| audit::checkpoint(context, &request),
            )
            .await
            {
                Ok((Ok(Ok(outcome)), signal)) => value = record_response(value, outcome, signal),
                Ok((Ok(Err(e)), _)) | Err(e) => value = error(value, e),
                Ok((Err(e), _)) => value = error(value, AppError::Internal(e.to_string())),
            }
            Some(deliver(value, cli.json))
        }
        CloudflareCommand::Status(args) => {
            let mut value = response("status");
            value["case_id"] = json!(args.case_id);
            let result = (|| -> AppResult<_> {
                let data = resolve_data_dir(cli.data_dir.clone())?;
                let storage = Storage::open_read_only(data.join("casework.db"))?;
                let case = storage.get_case(&args.case_id)?;
                let id = args
                    .session_id
                    .as_ref()
                    .or(args.prepare_request_id.as_ref())
                    .unwrap();
                let receipt = storage
                    .cloudflare_audit_receipt(&args.case_id, id, args.session_id.is_some())?
                    .ok_or_else(|| AppError::InvalidRequest("unknown audit preparation".into()))?;
                let restored =
                    ai_security_scanner_lib::cloudflare_provider::restored::Context::load(
                        &storage, &receipt,
                    )?;
                let descriptor = receipt
                    .session_id()
                    .map(|_| audit::descriptor_state(&data, &receipt));
                let record = storage.cloudflare_audit_record(&receipt)?;
                let sealed = record.sealed().map(|(entry, seal)| {
                    let mut value = json!({"entry":entry,"seal":seal,
                        "package_path":seal.path(&data, &receipt),"sealed_state":seal.state(&data, &receipt),
                        "sealed_verification_scope":"committed_files"});
                    if restored.restored && value["sealed_state"] == "verified" {
                        match audit::sealed::verify(
                            &data, &storage, &args.case_id, receipt.session_id().unwrap(),
                        ) {
                            Ok(verified) => value["sealed_verification_scope"] = json!(verified.verification.scope),
                            Err(failure) => {
                                value["sealed_state"] = json!("mismatch");
                                value["sealed_failed_check"] = json!(failure.failed_check);
                            }
                        }
                    }
                    value
                });
                let next_admit = sealed
                    .as_ref()
                    .is_some_and(|seal| seal["sealed_state"] == "verified")
                    && !case
                        .agent_audit_admissions
                        .iter()
                        .any(|a| Some(a.identities.session_id.as_str()) == receipt.session_id());
                Ok((
                    case, receipt, descriptor, record, sealed, next_admit, data, restored,
                ))
            })();
            match result {
                Ok((case, receipt, descriptor, record, sealed, next_admit, data, restored)) => {
                    value["session_id"] = json!(receipt.session_id());
                    value["request_id"] = json!(receipt.request_id);
                    let (sequence, head) = record.head(&receipt);
                    let limit = match &receipt.result {
                        audit::PreparationResult::Prepared { facts, .. } => facts.invocation_budget,
                        _ => None,
                    };
                    let assignments: Vec<_> = record
                        .assignments
                        .iter()
                        .map(|a| {
                            let mut value = json!(a);
                            let spec = value.as_object_mut().unwrap().remove("spec").unwrap();
                            value
                                .as_object_mut()
                                .unwrap()
                                .extend(spec.as_object().unwrap().clone());
                            value
                        })
                        .collect();
                    value["case_revision"] = json!(case.storage_revision());
                    value["result"] = json!({"record_head":{"sequence":sequence,"entry_sha256":head,"receipt_sha256":receipt.receipt_sha256},
                        "entry_count":record.entries.len(),"entries":record.entries,"assignments":assignments,
                        "counts_by_role":record.counts(),"counts_by_state":record.counts_by_state(),"budget":record.budget(limit),
                        "receipt":receipt,"descriptor_state":descriptor,"historical_only":true,
                        "next_operation":{"operation":"checkpoint","available":receipt.session_id().is_some(),"actions":["issue","interrupt","submit_documents","submit_output"],"sealing":{"available":receipt.session_id().is_some(),"operation":"finalize","requires":"sealable_validation"}},
                        "documents":record.document_status(),"captured_bytes":record.captured_bytes(),
                        "document_capture":{"available":true},
                        "assignment_output_capture":{"available":true}});
                    if let Some(sealed) = sealed {
                        value["result"]["sealed_state"] = sealed["sealed_state"].clone();
                        value["result"]["sealed_verification_scope"] =
                            sealed["sealed_verification_scope"].clone();
                        if let Some(failed_check) = sealed.get("sealed_failed_check") {
                            value["result"]["sealed_failed_check"] = failed_check.clone();
                        }
                        value["result"]["package_path"] = sealed["package_path"].clone();
                        value["result"]["sealed"] = sealed["seal"].clone();
                        value["result"]["next_operation"] = if next_admit {
                            json!("admit")
                        } else {
                            Value::Null
                        };
                    }
                    audit::admit::status(
                        &case,
                        receipt.session_id().unwrap_or_default(),
                        &data,
                        &mut value["result"],
                    );
                    if let Some((entry, reason)) = record.terminated() {
                        value["result"]["terminated"] = json!({"reason":reason,
                            "occurred_at":entry.occurred_at,"entry_sha256":entry.entry_sha256});
                        value["result"]["next_operation"] = Value::Null;
                        for key in [
                            "checkpoint",
                            "sealing",
                            "document_capture",
                            "assignment_output_capture",
                        ] {
                            value["result"][key] = json!({"available":false});
                        }
                    }
                    ai_security_scanner_lib::agent_audit_failure::status(
                        &case,
                        &receipt,
                        &data,
                        &mut value["result"],
                    );
                    restored.present(&mut value["result"], record.sealed().is_some());
                    if value["result"].get("sealed_failed_check").is_some() {
                        value["result"]["next_operation"] = Value::Null;
                    }
                }
                Err(e) => value = error(value, e),
            }
            Some(deliver(value, cli.json))
        }
        _ => None,
    }
}

fn refused(mut value: Value, code: Refusal, reason: Option<audit::BlockerCode>) -> Value {
    let conflict = matches!(
        code,
        Refusal::StaleHead
            | Refusal::BundleMismatch
            | Refusal::RequestConflict
            | Refusal::SavedReceiptNotCurrent
    );
    value["command_outcome"] = json!("rejected");
    value["exit_code"] = json!(if conflict { 3 } else { 2 });
    value["error_code"] = json!(code);
    value["reason"] = json!(reason);
    value["retryable"] = json!(code == Refusal::StaleHead);
    value
}

fn record_response(mut value: Value, outcome: CheckpointOutcome, signal: u8) -> Value {
    match outcome {
        CheckpointOutcome::Saved {
            entry,
            head,
            replayed,
            budget,
            captured_bytes,
            assignment,
            receipt,
            outcome_run,
        } => {
            value["command_outcome"] = json!("committed");
            value["case_revision"] = json!(entry.case_revision);
            value["receipt"] = json!({"id":receipt.request_id,"sha256":receipt.receipt_sha256});
            value["result"] = json!({"record_head":head,
                        "entry":entry,"replayed":replayed,"budget":budget,"captured_bytes":captured_bytes});
            if let Some(outcome_run) = outcome_run {
                value["result"]["outcome_run"] = outcome_run;
            }
            if let Some(assignment) = assignment {
                if let Some(output) = &assignment.output {
                    value["result"]["disposition"] = json!(output.disposition);
                }
                value["result"]["assignment"] = json!(assignment);
            }
        }
        CheckpointOutcome::Interrupted => {
            value["command_outcome"] = json!("interrupted");
            value["exit_code"] = json!(signal);
        }
        CheckpointOutcome::DocumentRejected {
            error_code,
            document,
            validation,
        } => {
            value = refused(value, error_code, None);
            value["document"] = json!(document);
            if let Some(validation) = validation {
                value["validation"] = json!(validation);
            }
        }
        CheckpointOutcome::Rejected { error_code, reason } => {
            value = refused(value, error_code, reason)
        }
    }
    value
}

fn admission_error(mut value: Value, failure: audit::admit::AdmissionError) -> Value {
    match failure {
        audit::admit::AdmissionError::Other(e) => error(value, e),
        audit::admit::AdmissionError::Refused {
            code,
            exit,
            retryable,
        } => {
            value["command_outcome"] = json!(if exit == 4 { "failed" } else { "rejected" });
            value["exit_code"] = json!(exit);
            value["error_code"] = json!(code);
            value["retryable"] = json!(retryable);
            value
        }
    }
}
