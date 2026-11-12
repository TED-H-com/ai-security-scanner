use super::*;
use crate::case_archive_io::make_private;
use crate::domain::{AssetKind, ScanPermission, SourceConnectionStatus};
use crate::process_lease::DataDirectoryExclusiveLease;
use crate::storage::Storage;
use crate::workspace_snapshot::{
    WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY, WORKSPACE_SNAPSHOT_SCHEMA,
    WorkspaceSnapshotReference, inspect_workspace_snapshot,
};
use chrono::Utc;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareSourceViewRequest {
    pub case_id: String,
    pub asset_id: String,
    pub expected_snapshot_sha256: String,
    pub scope_paths: Vec<String>,
    pub request_id: String,
    pub acknowledge_model_processing: bool,
    pub confirmed_by: String,
    pub declared_host_id: String,
}
impl PrepareSourceViewRequest {
    pub fn normalize(&self) -> AppResult<Self> {
        if !valid_id(&self.case_id)
            || !valid_id(&self.asset_id)
            || !valid_id(&self.request_id)
            || !valid_hash(&self.expected_snapshot_sha256)
            || !self.acknowledge_model_processing
            || self.confirmed_by.trim().is_empty()
            || self.confirmed_by.len() > 200
            || self.confirmed_by.chars().any(char::is_control)
            || !valid_id(&self.declared_host_id)
        {
            return Err(invalid(
                "bounded identities, lowercase snapshot SHA-256, --acknowledge-model-processing, --confirmed-by and --host-id are required",
            ));
        }
        let mut request = self.clone();
        request.scope_paths = policy::normalize_scope(&self.scope_paths)?;
        Ok(request)
    }
}

/// The future prepare/session coordinator passes its already-held data owner.
/// This entry does not acquire a second lease or initialize a scanner runtime.
pub struct OwnedContext<'a> {
    pub storage: &'a Storage,
    pub data_dir: &'a Path,
    pub lease: &'a DataDirectoryExclusiveLease,
    pub cancelled: Option<&'a std::sync::atomic::AtomicU8>,
}
/// A replay is historical until current authority and bytes have been checked.
#[derive(Debug)]
pub enum PreparationOutcome {
    Committed(SourceViewPreparationReceipt),
    Replayed(SourceViewPreparationReceipt),
    SavedNotCurrent(SavedNotCurrentReason),
    Interrupted,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum SavedNotCurrentReason {
    Blocker(BlockerCode),
    Change(ReceiptChange),
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptChange {
    IdentityChanged,
    GrantChanged,
}

pub fn prepare_source_view(
    context: &OwnedContext<'_>,
    request: &PrepareSourceViewRequest,
) -> AppResult<PreparationOutcome> {
    prepare_with_clock(context, request, &Utc::now)
}

fn prepare_with_clock(
    context: &OwnedContext<'_>,
    request: &PrepareSourceViewRequest,
    clock: &dyn Fn() -> chrono::DateTime<Utc>,
) -> AppResult<PreparationOutcome> {
    let interrupted = std::cell::Cell::new(false);
    let checkpoint = || {
        if context
            .cancelled
            .is_some_and(|s| s.load(std::sync::atomic::Ordering::Acquire) != 0)
        {
            interrupted.set(true);
            return Err(AppError::Runtime(
                "source-view preparation interrupted".into(),
            ));
        }
        Ok(())
    };
    let result = evaluate(context, request, clock, &checkpoint);
    if interrupted.get() {
        Ok(PreparationOutcome::Interrupted)
    } else {
        result
    }
}

fn evaluate(
    context: &OwnedContext<'_>,
    request: &PrepareSourceViewRequest,
    clock: &dyn Fn() -> chrono::DateTime<Utc>,
    checkpoint: &dyn Fn() -> AppResult<()>,
) -> AppResult<PreparationOutcome> {
    crate::cloudflare_provider::restored::guard(
        context.storage,
        &request.case_id,
        super::RECEIPT_EVENT,
        &request.request_id,
        false,
    )?;
    checkpoint()?;
    let supplied_scope = request.scope_paths.clone();
    let request = request.normalize()?;
    if context
        .lease
        .path()
        .parent()
        .map(crate::internal_paths::canonicalize)
        .transpose()?
        != Some(crate::internal_paths::canonicalize(context.data_dir)?)
        || crate::internal_paths::canonicalize(context.storage.path())?
            != crate::internal_paths::canonicalize(context.data_dir.join("casework.db"))?
    {
        return Err(invalid("ownership context does not match storage"));
    }
    let request_sha256 = domain_digest("ai-security-scanner.source-view-request/v1", &request)?;
    let saved = context
        .storage
        .source_view_receipt(&request.case_id, &request.request_id)?;
    if let Some(saved) = &saved {
        if saved.request_sha256 != request_sha256 {
            return Err(AppError::Conflict(
                "source-view request_id has different inputs".into(),
            ));
        }
        if matches!(saved.result, PreparationResult::Blocked { .. }) {
            return Ok(PreparationOutcome::Replayed(saved.clone()));
        }
    }
    let case = context.storage.get_case(&request.case_id)?;
    let asset = match case.assets.iter().find(|a| a.id == request.asset_id) {
        Some(asset) => asset,
        None if saved.is_some() => {
            return Ok(PreparationOutcome::SavedNotCurrent(
                SavedNotCurrentReason::Blocker(BlockerCode::SourceBindingMismatch),
            ));
        }
        None => return Err(invalid("unknown asset")),
    };
    let now = clock();
    let acknowledgement = ModelProcessingAcknowledgement {
        schema_version: "ai-security-scanner.model-processing-acknowledgement/v1".into(),
        case_id: case.id.clone(),
        asset_id: asset.id.clone(),
        canonical_snapshot_sha256: request.expected_snapshot_sha256.clone(),
        scope: request.scope_paths.clone(),
        policy_id: policy::POLICY_ID.into(),
        declared_host_id: request.declared_host_id.clone(),
        host_identity_verified: false,
        confirmed_by: request.confirmed_by.clone(),
        confirmed_at: now.to_rfc3339(),
        acknowledged: true,
    };
    let (candidates, grant) = select_grant(&case, asset, now);
    let grant_sha256 = grant
        .as_ref()
        .map(|grant| domain_digest("ai-security-scanner.source-view-grant/v1", grant))
        .transpose()?;
    if let (Some(saved), Some(_)) = (&saved, &grant)
        && saved.grant_sha256 != grant_sha256
    {
        return Ok(PreparationOutcome::SavedNotCurrent(
            SavedNotCurrentReason::Change(ReceiptChange::GrantChanged),
        ));
    }
    let mut receipt = SourceViewPreparationReceipt {
        schema_version: RECEIPT_SCHEMA.into(),
        case_id: case.id.clone(),
        asset_id: asset.id.clone(),
        source_id: None,
        request_id: request.request_id.clone(),
        request_sha256,
        case_revision: case.storage_revision,
        event_sequence: 0,
        occurred_at: now.to_rfc3339(),
        acknowledgement_sha256: domain_digest(
            "ai-security-scanner.model-processing-acknowledgement/v1",
            &acknowledgement,
        )?,
        acknowledgement,
        grant_sha256: None,
        grant: None,
        analysis_performed: false,
        result: PreparationResult::Blocked {
            blockers: Vec::new(),
        },
        digest: String::new(),
    };
    let mut evaluate = || -> AppResult<Result<(PreparationResult, String), Blocker>> {
        let block = |code| Ok(Err(Blocker::new(code, "authority")));
        let (source, reference) = match source_binding(
            &case,
            asset,
            &request.expected_snapshot_sha256,
            saved.is_some(),
        )? {
            Ok(bound) => bound,
            Err(code) => return block(code),
        };
        if asset.candidate || !asset.owner_confirmed || candidates.is_empty() {
            return block(BlockerCode::SourceAuthorizationMissing);
        }
        let Some(grant) = grant.as_ref() else {
            return block(BlockerCode::SourceAuthorizationExpired);
        };
        receipt.grant = Some(grant.clone());
        receipt.grant_sha256 = Some(domain_digest(
            "ai-security-scanner.source-view-grant/v1",
            grant,
        )?);
        let artifacts = context.data_dir.join("artifacts");
        let resolved = match inspect_workspace_snapshot(&artifacts, &case.id, &reference) {
            Ok(r) => r,
            Err(_) => {
                return Ok(Err(Blocker::new(
                    BlockerCode::SnapshotIntegrityFailed,
                    "canonical_input",
                )));
            }
        };
        if resolved.manifest.schema_version != WORKSPACE_SNAPSHOT_SCHEMA {
            return block(BlockerCode::SnapshotExclusionAuditUnavailable);
        }
        partition::check_scope(&resolved.manifest, &supplied_scope)?;
        let case_root = artifacts.join(&case.id);
        let _root = super::super::bundle_io::BundleRoot::open(&case_root)?;
        let parent = case_root.join("source-views");
        match fs::create_dir(&parent) {
            Ok(()) => make_private(&parent, true)?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let result = io::publish(
            &parent,
            resolved
                .manifest_path
                .parent()
                .ok_or_else(|| invalid("missing canonical payload"))?,
            &reference.sha256,
            policy::Policy::new(request.scope_paths.clone()),
            checkpoint,
            &|| {
                crate::domain::grant_is_effective(
                    grant,
                    &asset.id,
                    ScanPermission::LocalArtifactRead,
                    clock(),
                )
            },
        )?;
        match result {
            Ok(mut ready) => {
                if let PreparationResult::Ready {
                    view_id,
                    relative_path,
                    ..
                } = &mut ready
                {
                    *relative_path = format!("{}/source-views/{view_id}", case.id);
                }
                Ok(Ok((ready, source.id.clone())))
            }
            Err(blocker) => Ok(Err(blocker)),
        }
    };
    match evaluate()? {
        Ok((result, source_id)) => {
            receipt.result = result;
            receipt.source_id = Some(source_id);
        }
        Err(blocker) => {
            receipt.result = PreparationResult::Blocked {
                blockers: vec![blocker],
            }
        }
    }
    checkpoint()?;
    if matches!(receipt.result, PreparationResult::Ready { .. })
        && !receipt.grant.as_ref().is_some_and(|g| {
            crate::domain::grant_is_effective(
                g,
                &asset.id,
                ScanPermission::LocalArtifactRead,
                clock(),
            )
        })
    {
        receipt.result = PreparationResult::Blocked {
            blockers: vec![Blocker::new(
                BlockerCode::SourceAuthorizationExpired,
                "commit",
            )],
        };
    }
    if let Some(saved) = saved {
        let reason = match (&saved.result, &receipt.result) {
            (_, PreparationResult::Blocked { blockers }) => {
                Some(SavedNotCurrentReason::Blocker(blockers[0].code))
            }
            (
                PreparationResult::Ready {
                    view_id: a,
                    manifest_sha256: b,
                    view_sha256: c,
                    ..
                },
                PreparationResult::Ready {
                    view_id: x,
                    manifest_sha256: y,
                    view_sha256: z,
                    ..
                },
            ) => {
                if (a, b, c) != (x, y, z) {
                    Some(SavedNotCurrentReason::Change(
                        ReceiptChange::IdentityChanged,
                    ))
                } else {
                    None
                }
            }
            _ => unreachable!("blocked receipts replay before evaluation"),
        };
        return Ok(match reason {
            Some(reason) => PreparationOutcome::SavedNotCurrent(reason),
            None => PreparationOutcome::Replayed(saved),
        });
    }
    context
        .storage
        .record_source_view_receipt(receipt, &|| {
            grant.as_ref().is_some_and(|g| {
                crate::domain::grant_is_effective(
                    g,
                    &asset.id,
                    ScanPermission::LocalArtifactRead,
                    clock(),
                )
            })
        })
        .map(PreparationOutcome::Committed)
}

pub(super) fn select_grant<'a>(
    case: &'a crate::domain::AssessmentCase,
    asset: &crate::domain::Asset,
    now: chrono::DateTime<Utc>,
) -> (
    Vec<&'a crate::domain::ScopeGrant>,
    Option<crate::domain::ScopeGrant>,
) {
    let candidates = case
        .scope_grants
        .iter()
        .filter(|g| {
            g.asset_id == asset.id
                && g.permission == ScanPermission::LocalArtifactRead
                && !g.confirmed_by.trim().is_empty()
        })
        .collect::<Vec<_>>();
    let grant = if asset.candidate || !asset.owner_confirmed {
        None
    } else {
        candidates
            .iter()
            .copied()
            .filter(|g| {
                crate::domain::grant_is_effective(
                    g,
                    &asset.id,
                    ScanPermission::LocalArtifactRead,
                    now,
                )
            })
            .min_by(|a, b| match (a.expires_at, b.expires_at) {
                (None, Some(_)) => std::cmp::Ordering::Less,
                (Some(_), None) => std::cmp::Ordering::Greater,
                _ => b
                    .expires_at
                    .cmp(&a.expires_at)
                    .then_with(|| a.id.cmp(&b.id)),
            })
            .cloned()
    };
    (candidates, grant)
}
pub(super) fn source_binding<'a>(
    case: &'a crate::domain::AssessmentCase,
    asset: &crate::domain::Asset,
    expected: &str,
    replay: bool,
) -> AppResult<Result<(&'a crate::domain::DataSource, WorkspaceSnapshotReference), BlockerCode>> {
    let block = |code| Ok(Err(code));
    if asset.kind != AssetKind::Repository {
        return block(BlockerCode::InputProfileUnsupported);
    }
    if asset.discovered_from.len() != 1 {
        return block(BlockerCode::SourceBindingMismatch);
    }
    let source = match case
        .data_sources
        .iter()
        .find(|s| s.id == asset.discovered_from[0])
    {
        Some(s) => s,
        None => return block(BlockerCode::SourceBindingMismatch),
    };
    let reference: WorkspaceSnapshotReference = match source
        .metadata
        .get(WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY)
        .cloned()
        .map(serde_json::from_value)
    {
        Some(Ok(r)) => r,
        _ => return block(BlockerCode::SourceBindingMismatch),
    };
    if reference.sha256 != expected {
        if replay {
            return block(BlockerCode::SourceBindingMismatch);
        }
        return Err(AppError::Conflict(
            "expected canonical snapshot digest is stale".into(),
        ));
    }
    if source.status != SourceConnectionStatus::Connected
        || source.kind != reference.input_profile.source_kind()
        || !source.read_only
        || asset
            .metadata
            .get("workspace_snapshot_sha256")
            .and_then(|v| v.as_str())
            != Some(reference.sha256.as_str())
        || asset
            .metadata
            .get("workspace_snapshot_id")
            .and_then(|v| v.as_str())
            != Some(reference.snapshot_id.as_str())
        || asset
            .identifiers
            .iter()
            .filter(|i| i.namespace == "ai-security-scanner:workspace-snapshot-sha256")
            .count()
            != 1
        || !asset.identifiers.iter().any(|i| {
            i.namespace == "ai-security-scanner:workspace-snapshot-sha256"
                && i.value == reference.sha256
        })
    {
        return block(BlockerCode::SourceBindingMismatch);
    }
    if !reference.input_profile.is_repository() {
        return block(BlockerCode::InputProfileUnsupported);
    }
    Ok(Ok((source, reference)))
}

#[cfg(test)]
#[path = "prepare_tests.rs"]
mod tests;
