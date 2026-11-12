use super::*;
use crate::cloudflare_provider::source_view::{
    self, OwnedContext, ReceiptChange, SavedNotCurrentReason,
};
use chrono::{DateTime, Utc};
use std::fs;

#[derive(Debug)]
pub enum PreparationOutcome {
    Saved {
        receipt: Box<PreparationReceipt>,
        replayed: bool,
        outcome_run: Option<serde_json::Value>,
    },
    SavedNotCurrent(BlockerCode),
    Interrupted,
}
pub fn prepare(
    context: &OwnedContext<'_>,
    request: &PrepareRequest,
) -> AppResult<PreparationOutcome> {
    prepare_with_clock(context, request, &Utc::now)
}
fn run_directory(request: &PrepareRequest, data: &Path) -> AppResult<()> {
    let path = &request.run_directory;
    let bad = || {
        invalid(
            "run_directory must be an absolute normalized real directory outside the data directory and source view",
        )
    };
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
        || !fs::symlink_metadata(path)
            .map_err(|_| bad())?
            .file_type()
            .is_dir()
    {
        return Err(bad());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if fs::symlink_metadata(path)
            .map_err(|_| bad())?
            .file_attributes()
            & 0x400
            != 0
        {
            return Err(bad());
        }
    }
    super::super::bundle_io::BundleRoot::open(path).map_err(|_| bad())?;
    let canonical = fs::canonicalize(path).map_err(|_| bad())?;
    let data = fs::canonicalize(data)?;
    if canonical.starts_with(&data) || data.starts_with(&canonical) {
        return Err(bad());
    }
    Ok(())
}
fn blocked(request: &PrepareRequest, code: BlockerCode, stage: &str) -> PreparationResult {
    PreparationResult::Blocked {
        request: Box::new(request.clone()),
        blockers: vec![Blocker::new(code, stage)],
    }
}
pub(crate) fn reason(reason: SavedNotCurrentReason) -> BlockerCode {
    use source_view::BlockerCode as S;
    match reason {
        SavedNotCurrentReason::Change(ReceiptChange::GrantChanged) => BlockerCode::GrantChanged,
        SavedNotCurrentReason::Blocker(S::SourceAuthorizationMissing) => {
            BlockerCode::SourceAuthorizationMissing
        }
        SavedNotCurrentReason::Blocker(S::SourceAuthorizationExpired) => {
            BlockerCode::SourceAuthorizationExpired
        }
        SavedNotCurrentReason::Blocker(S::SnapshotIntegrityFailed) => {
            BlockerCode::SnapshotIntegrityFailed
        }
        SavedNotCurrentReason::Blocker(S::SnapshotUnavailable) => BlockerCode::ViewMissing,
        SavedNotCurrentReason::Blocker(S::SourceReadFailed) => BlockerCode::ViewIntegrityFailed,
        _ => BlockerCode::SourceBindingMismatch,
    }
}
pub(crate) fn prepare_with_clock(
    context: &OwnedContext<'_>,
    request: &PrepareRequest,
    clock: &dyn Fn() -> DateTime<Utc>,
) -> AppResult<PreparationOutcome> {
    crate::cloudflare_provider::restored::guard(
        context.storage,
        &request.case_id,
        super::RECEIPT_EVENT,
        &request.request_id,
        false,
    )?;
    request.validate()?;
    if context
        .lease
        .path()
        .parent()
        .map(fs::canonicalize)
        .transpose()?
        != Some(fs::canonicalize(context.data_dir)?)
        || fs::canonicalize(context.storage.path())?
            != fs::canonicalize(context.data_dir.join("casework.db"))?
    {
        return Err(invalid("ownership context does not match storage"));
    }
    let request_sha256 = request.content_digest()?;
    let saved =
        context
            .storage
            .cloudflare_audit_receipt(&request.case_id, &request.request_id, false)?;
    if let Some(saved) = &saved {
        if saved.request_sha256 != request_sha256 {
            return Err(AppError::Conflict(
                "audit request_id has different inputs".into(),
            ));
        }
        if matches!(saved.result, PreparationResult::Blocked { .. }) {
            return Ok(PreparationOutcome::Saved {
                outcome_run: crate::agent_audit_failure::retain(context, saved),
                receipt: Box::new(saved.clone()),
                replayed: true,
            });
        }
    }
    let case = context.storage.get_case(&request.case_id)?;
    if !case.assets.iter().any(|a| a.id == request.asset_id) {
        return if saved.is_some() {
            Ok(PreparationOutcome::SavedNotCurrent(
                BlockerCode::SourceBindingMismatch,
            ))
        } else {
            Err(invalid("unknown asset"))
        };
    }
    let view = context
        .storage
        .source_view_receipt(&request.case_id, &request.source_view_request_id)?;
    let Some(view) = view.filter(|view| {
        view.digest == request.expected_source_view_receipt_sha256
            && view.asset_id == request.asset_id
    }) else {
        return if saved.is_some() {
            Ok(PreparationOutcome::SavedNotCurrent(
                BlockerCode::SourceBindingMismatch,
            ))
        } else {
            Err(invalid(
                "unknown source-view receipt or digest/asset mismatch",
            ))
        };
    };
    if let Err(error) = run_directory(request, context.data_dir) {
        return if saved.is_some() {
            Ok(PreparationOutcome::SavedNotCurrent(
                BlockerCode::RunDirectoryUnavailable,
            ))
        } else {
            Err(error)
        };
    }
    let now = clock();
    let evaluated = if !matches!(view.result, source_view::PreparationResult::Ready { .. }) {
        Err(BlockerCode::SourceViewNotReady)
    } else if view.acknowledgement.declared_host_id != request.host.host_id {
        Err(BlockerCode::HostMismatch)
    } else if request.host.delegation != Delegation::Available {
        Err(BlockerCode::DelegationUnavailable)
    } else if request
        .invocation_budget
        .is_some_and(|b| b < request.profile.floor())
    {
        Err(BlockerCode::BudgetCannotFundReconnaissanceAndReserves)
    } else {
        source_view::current_view(context.data_dir, &case, &view, now)?.map_err(reason)
    };
    if let Some(saved) = saved {
        let current = match evaluated {
            Ok(current) => current,
            Err(code) => return Ok(PreparationOutcome::SavedNotCurrent(code)),
        };
        if !source_view::effective(&current.grant, &request.asset_id, clock()) {
            return Ok(PreparationOutcome::SavedNotCurrent(
                BlockerCode::SourceAuthorizationExpired,
            ));
        }
        io::publish(context.data_dir, &saved).map_err(|e| AppError::Storage(e.to_string()))?;
        return Ok(PreparationOutcome::Saved {
            outcome_run: None,
            receipt: Box::new(saved),
            replayed: true,
        });
    }
    if context
        .cancelled
        .is_some_and(|s| s.load(std::sync::atomic::Ordering::Acquire) != 0)
    {
        return Ok(PreparationOutcome::Interrupted);
    }
    let receipt = PreparationReceipt {
        schema_version: RECEIPT_SCHEMA.into(),
        request_id: request.request_id.clone(),
        request_sha256,
        case_id: request.case_id.clone(),
        asset_id: request.asset_id.clone(),
        occurred_at: now.to_rfc3339(),
        case_revision: case.storage_revision,
        sequence: 0,
        predecessor_sha256: None,
        result: PreparationResult::Blocked {
            request: Box::new(request.clone()),
            blockers: vec![],
        },
        receipt_sha256: String::new(),
    };
    let receipt = context
        .storage
        .record_cloudflare_audit_receipt(receipt, || {
            let current = match evaluated {
                Ok(current) => current,
                Err(code) => return Ok(blocked(request, code, "preparation")),
            };
            let prepared_at = clock();
            if !source_view::effective(&current.grant, &request.asset_id, prepared_at) {
                return Ok(blocked(
                    request,
                    BlockerCode::SourceAuthorizationExpired,
                    "commit",
                ));
            }
            let facts = Box::new(Prepared {
                session_id: crate::domain::new_id(),
                provider_run_id: crate::domain::new_id(),
                provider_task_id: crate::domain::new_id(),
                attempt_id: crate::domain::new_id(),
                prepared_at: prepared_at.to_rfc3339(),
                source: SourceBinding {
                    source_view_request_id: view.request_id.clone(),
                    source_view_receipt_sha256: view.digest.clone(),
                    view_id: current.source.view_id,
                    view_sha256: current.source.view_sha256,
                    canonical_snapshot_id: current
                        .source
                        .canonical_snapshot_id
                        .ok_or_else(|| invalid("missing snapshot identity"))?,
                    canonical_snapshot_sha256: current
                        .source
                        .canonical_snapshot_sha256
                        .ok_or_else(|| invalid("missing snapshot digest"))?,
                    policy_id: current.source.policy_id,
                    scope: view.acknowledgement.scope.clone(),
                    source_ref: current.source.source_ref,
                    grant_sha256: view
                        .grant_sha256
                        .clone()
                        .ok_or_else(|| invalid("missing grant digest"))?,
                    acknowledgement_sha256: view.acknowledgement_sha256.clone(),
                },
                upstream_commit: super::super::UPSTREAM_COMMIT.into(),
                validator_resources_sha256: super::super::resources_digest(),
                profile: request.profile,
                invocation_budget: request.invocation_budget,
                applied_floor: request.profile.floor(),
                host: request.host.clone(),
                run_directory: request.run_directory.clone(),
                target_execution_allowed: false,
            });
            Ok(PreparationResult::Prepared {
                descriptor_sha256: digest(&canonical_bytes(&facts)?),
                facts,
            })
        })?;
    io::publish(context.data_dir, &receipt).map_err(|e| AppError::Storage(e.to_string()))?;
    Ok(PreparationOutcome::Saved {
        outcome_run: crate::agent_audit_failure::retain(context, &receipt),
        receipt: Box::new(receipt),
        replayed: false,
    })
}
