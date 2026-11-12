//! Read-only checks shared with the preparation coordinator. Never publishes or repairs.
use super::*;
use crate::domain::{AssessmentCase, ScanPermission, ScopeGrant};
use chrono::{DateTime, Utc};

pub(crate) struct CurrentView {
    pub source: SourceView,
    pub grant: ScopeGrant,
}
pub(crate) fn current_view(
    data: &Path,
    case: &AssessmentCase,
    receipt: &SourceViewPreparationReceipt,
    now: DateTime<Utc>,
) -> AppResult<Result<CurrentView, SavedNotCurrentReason>> {
    let (reference, grant) = match current_authority(case, receipt, now)? {
        Ok(current) => current,
        Err(reason) => return Ok(Err(reason)),
    };
    let block = |code| Ok(Err(SavedNotCurrentReason::Blocker(code)));
    let resolved = match crate::workspace_snapshot::inspect_workspace_snapshot(
        data.join("artifacts"),
        &case.id,
        &reference,
    ) {
        Ok(resolved) => resolved,
        Err(_) => return block(BlockerCode::SnapshotIntegrityFailed),
    };
    let PreparationResult::Ready {
        view_id,
        manifest_sha256,
        view_sha256,
        relative_path,
        ..
    } = &receipt.result
    else {
        return block(BlockerCode::SnapshotUnavailable);
    };
    if *relative_path != format!("{}/source-views/{view_id}", case.id) || !valid_id(view_id) {
        return block(BlockerCode::SourceBindingMismatch);
    }
    let path = data.join("artifacts").join(relative_path);
    if !path.exists() {
        return block(BlockerCode::SnapshotUnavailable);
    }
    if crate::case_archive_io::require_sealed_directory_root(&path).is_err() {
        return block(BlockerCode::SourceReadFailed);
    }
    let inspection = match inspect_source_view(
        &path,
        Some(manifest_sha256),
        resolved.manifest_path.parent(),
    ) {
        Ok(inspection) => inspection,
        Err(_) => return block(BlockerCode::SourceReadFailed),
    };
    if inspection.source.view_id != *view_id
        || inspection.source.view_sha256 != *view_sha256
        || inspection.source.canonical_snapshot_id.as_deref() != Some(&reference.snapshot_id)
        || inspection.source.canonical_snapshot_sha256.as_deref() != Some(&reference.sha256)
        || inspection.source.policy_id != receipt.acknowledgement.policy_id
    {
        return block(BlockerCode::SourceBindingMismatch);
    }
    Ok(Ok(CurrentView {
        source: inspection.source,
        grant,
    }))
}
pub(crate) fn effective(grant: &ScopeGrant, asset: &str, now: DateTime<Utc>) -> bool {
    crate::domain::grant_is_effective(grant, asset, ScanPermission::LocalArtifactRead, now)
}

/// Metadata and grant checks only: no view, snapshot or run-directory reads.
pub(crate) fn current_authority(
    case: &AssessmentCase,
    receipt: &SourceViewPreparationReceipt,
    now: DateTime<Utc>,
) -> AppResult<
    Result<
        (
            crate::workspace_snapshot::WorkspaceSnapshotReference,
            ScopeGrant,
        ),
        SavedNotCurrentReason,
    >,
> {
    let block = |code| Ok(Err(SavedNotCurrentReason::Blocker(code)));
    let Some(asset) = case.assets.iter().find(|a| a.id == receipt.asset_id) else {
        return block(BlockerCode::SourceBindingMismatch);
    };
    let (source, reference) = match prepare::source_binding(
        case,
        asset,
        &receipt.acknowledgement.canonical_snapshot_sha256,
        true,
    )? {
        Ok(binding) => binding,
        Err(code) => return block(code),
    };
    if receipt.source_id.as_deref() != Some(&source.id) {
        return block(BlockerCode::SourceBindingMismatch);
    }
    let (candidates, grant) = prepare::select_grant(case, asset, now);
    if asset.candidate || !asset.owner_confirmed || candidates.is_empty() {
        return block(BlockerCode::SourceAuthorizationMissing);
    }
    let Some(grant) = grant else {
        return block(BlockerCode::SourceAuthorizationExpired);
    };
    if Some(domain_digest(
        "ai-security-scanner.source-view-grant/v1",
        &grant,
    )?) != receipt.grant_sha256
    {
        return Ok(Err(SavedNotCurrentReason::Change(
            ReceiptChange::GrantChanged,
        )));
    }
    Ok(Ok((reference, grant)))
}
