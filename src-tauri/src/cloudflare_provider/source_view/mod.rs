//! Product-owned source selection. Preparation performs no audit or model call.
mod currency;
pub(crate) use currency::{current_authority, current_view, effective};
mod io;
mod partition;
pub mod policy;
mod prepare;

use super::bundle::{BundleFile, SourceView, file_index_digest};
use crate::domain::ScopeGrant;
use crate::error::{AppError, AppResult};
use crate::workspace_snapshot::{
    WorkspaceSnapshotExcludedEntryKind as EntryKind, WorkspaceSnapshotManifest,
};
pub use io::{SourceViewInspection, inspect_source_view};
pub use prepare::{
    OwnedContext, PreparationOutcome, PrepareSourceViewRequest, ReceiptChange,
    SavedNotCurrentReason, prepare_source_view,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const RECEIPT_EVENT: &str = "source_view.preparation_terminal";
pub const RECEIPT_SCHEMA: &str = "ai-security-scanner.source-view-preparation-receipt/v1";
const VIEW_SCHEMA: &str = "ai-security-scanner.ai-source-view/v1";
fn invalid(message: &str) -> AppError {
    AppError::InvalidRequest(format!("source view: {message}"))
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub(crate) fn canonical_bytes(value: &impl Serialize) -> AppResult<Vec<u8>> {
    // Sort explicitly, including when another feature enables serde_json's
    // insertion-ordered maps. Cargo feature unification must not affect identity.
    fn sorted(value: serde_json::Value) -> AppResult<serde_json::Value> {
        use serde_json::Value;
        Ok(match value {
            Value::Object(map) => {
                let mut entries = map.into_iter().collect::<Vec<_>>();
                entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
                Value::Object(
                    entries
                        .into_iter()
                        .map(|(key, value)| Ok((key, sorted(value)?)))
                        .collect::<AppResult<_>>()?,
                )
            }
            Value::Array(values) => {
                Value::Array(values.into_iter().map(sorted).collect::<AppResult<_>>()?)
            }
            Value::Number(ref number) if number.is_f64() => {
                return Err(invalid("identity JSON requires integer numbers"));
            }
            other => other,
        })
    }
    Ok(serde_json::to_vec(&sorted(serde_json::to_value(value)?)?)?)
}
pub(crate) fn domain_digest(domain: &str, value: &impl Serialize) -> AppResult<String> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(canonical_bytes(value)?);
    Ok(hex::encode(hasher.finalize()))
}
pub(crate) fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    CanonicalGitMetadata,
    CanonicalRepositoryGitignoreUntracked,
    OutsideScope,
    SensitiveName,
    UnsupportedPath,
    OversizeFile,
    NonUtf8Text,
    BinaryControlBytes,
    PrivateKeyMarker,
    NoIncludedDescendants,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Exclusion {
    pub path: String,
    pub reason: ExclusionReason,
    pub entry_kind: EntryKind,
    pub covers_subtree: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureIdentity {
    NotRecorded,
    Recorded { sha256: String, byte_length: u64 },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Lineage {
    pub canonical_snapshot_id: String,
    pub canonical_manifest_sha256: String,
    pub canonical_manifest_byte_length: u64,
    pub capture_record: CaptureIdentity,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewManifest {
    pub schema_version: String,
    pub identity_recipe: String,
    pub source: SourceView,
    pub policy: policy::Policy,
    pub policy_sha256: String,
    pub lineage: Lineage,
    pub exclusions: Vec<Exclusion>,
    pub included_file_count: usize,
    pub omitted_file_count: usize,
    pub included_bytes: u64,
    pub line_mapping: String,
}
impl ViewManifest {
    fn identity(&self) -> AppResult<String> {
        Ok(format!(
            "ai-view-{}",
            domain_digest(
                "ai-security-scanner.ai-source-view-identity/v1",
                &serde_json::json!({
                    "lineage": self.lineage, "policy_sha256": self.policy_sha256,
                    "file_index_sha256": self.source.view_sha256, "exclusions": self.exclusions,
                    "source_ref": self.source.source_ref,
                })
            )?
        ))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockerCode {
    SourceAuthorizationMissing,
    SourceAuthorizationExpired,
    SourceBindingMismatch,
    SnapshotUnavailable,
    SnapshotIntegrityFailed,
    SnapshotSchemaUnsupported,
    SnapshotExclusionAuditUnavailable,
    InputProfileUnsupported,
    ViewEmpty,
    ViewLimitExceeded,
    SourceReadFailed,
    SafeIoUnavailable,
}
impl BlockerCode {
    fn next_action(self) -> NextAction {
        match self {
            Self::SourceAuthorizationMissing | Self::SourceAuthorizationExpired => {
                NextAction::ApproveSource
            }
            Self::InputProfileUnsupported => NextAction::SelectRepository,
            Self::ViewEmpty => NextAction::AdjustScope,
            Self::ViewLimitExceeded => NextAction::NarrowScope,
            _ => NextAction::RefreshSnapshot,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NextAction {
    ApproveSource,
    RefreshSnapshot,
    NarrowScope,
    SelectRepository,
    AdjustScope,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blocker {
    pub code: BlockerCode,
    pub stage: String,
    pub next_action: NextAction,
    pub retryable: bool,
    pub bound: Option<String>,
    pub limit: Option<u64>,
    pub observed: Option<u64>,
}
impl Blocker {
    pub(crate) fn new(code: BlockerCode, stage: &str) -> Self {
        Self {
            code,
            stage: stage.into(),
            next_action: code.next_action(),
            retryable: false,
            bound: None,
            limit: None,
            observed: None,
        }
    }
    fn limit(bound: &str, limit: u64, observed: u64) -> Self {
        Self {
            bound: Some(bound.into()),
            limit: Some(limit),
            observed: Some(observed),
            ..Self::new(BlockerCode::ViewLimitExceeded, "partition")
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProcessingAcknowledgement {
    pub schema_version: String,
    pub case_id: String,
    pub asset_id: String,
    pub canonical_snapshot_sha256: String,
    pub scope: Vec<String>,
    pub policy_id: String,
    pub declared_host_id: String,
    pub host_identity_verified: bool,
    pub confirmed_by: String,
    pub confirmed_at: String,
    pub acknowledged: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum PreparationResult {
    Ready {
        view_id: String,
        manifest_sha256: String,
        manifest_byte_length: u64,
        view_sha256: String,
        relative_path: String,
    },
    Blocked {
        blockers: Vec<Blocker>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceViewPreparationReceipt {
    pub schema_version: String,
    pub case_id: String,
    pub asset_id: String,
    pub source_id: Option<String>,
    pub request_id: String,
    pub request_sha256: String,
    pub case_revision: i64,
    pub event_sequence: i64,
    pub occurred_at: String,
    pub acknowledgement: ModelProcessingAcknowledgement,
    pub acknowledgement_sha256: String,
    pub grant: Option<ScopeGrant>,
    pub grant_sha256: Option<String>,
    pub analysis_performed: bool,
    pub result: PreparationResult,
    pub digest: String,
}
impl SourceViewPreparationReceipt {
    pub fn content_digest(&self) -> AppResult<String> {
        let mut value = serde_json::to_value(self)?;
        value.as_object_mut().unwrap().remove("digest");
        value.as_object_mut().unwrap().remove("event_sequence");
        domain_digest("ai-security-scanner.source-view-receipt/v1", &value)
    }
}

#[cfg(test)]
#[test]
fn every_blocker_names_an_action_that_can_clear_it() {
    use BlockerCode::*;
    use NextAction::*;
    for (code, expected) in [
        (SourceAuthorizationMissing, ApproveSource),
        (SourceAuthorizationExpired, ApproveSource),
        (SourceBindingMismatch, RefreshSnapshot),
        (SnapshotUnavailable, RefreshSnapshot),
        (SnapshotIntegrityFailed, RefreshSnapshot),
        (SnapshotSchemaUnsupported, RefreshSnapshot),
        (SnapshotExclusionAuditUnavailable, RefreshSnapshot),
        (InputProfileUnsupported, SelectRepository),
        (ViewEmpty, AdjustScope),
        (ViewLimitExceeded, NarrowScope),
        (SourceReadFailed, RefreshSnapshot),
        (SafeIoUnavailable, RefreshSnapshot),
    ] {
        assert_eq!(Blocker::new(code, "test").next_action, expected);
    }
}
