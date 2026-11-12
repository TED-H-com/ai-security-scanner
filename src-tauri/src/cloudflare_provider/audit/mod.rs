//! Preparation records custody only; it never invokes a model or target code.
pub mod admit;
pub mod captured;
pub(crate) mod checkpoint;
pub mod documents;
pub mod finalize;
mod io;
mod manifest;
pub mod outputs;
pub mod retrieve;
mod rules;
pub mod sealed;
pub mod terminate;
pub mod validation;
pub use checkpoint::checkpoint;
pub(crate) mod prepare;
pub mod record;
use super::source_view::{canonical_bytes, digest, domain_digest, valid_hash, valid_id};
use crate::error::{AppError, AppResult};
pub use io::{DescriptorState, descriptor_state};
pub use prepare::{PreparationOutcome, prepare};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
pub const REQUEST_SCHEMA: &str = "ai-security-scanner.cloudflare-audit-prepare-request/v1";
pub const RECEIPT_SCHEMA: &str = "ai-security-scanner.cloudflare-audit-preparation-receipt/v1";
pub const RECEIPT_EVENT: &str = "cloudflare_audit.preparation_terminal";
fn invalid(message: &str) -> AppError {
    AppError::InvalidRequest(format!("Cloudflare preparation: {message}"))
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Quick,
    Standard,
    Deep,
}
impl Profile {
    pub fn floor(self) -> u64 {
        if matches!(self, Self::Quick) { 6 } else { 7 }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delegation {
    Available,
    Unavailable,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub host_id: String,
    pub delegation: Delegation,
    pub model: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    pub schema_version: String,
    pub request_id: String,
    pub case_id: String,
    pub asset_id: String,
    pub source_view_request_id: String,
    pub expected_source_view_receipt_sha256: String,
    pub profile: Profile,
    pub invocation_budget: Option<u64>,
    pub host: Host,
    pub run_directory: PathBuf,
}
impl PrepareRequest {
    pub fn read(path: &Path) -> AppResult<Self> {
        let value = read_request(path).map_err(|_| {
            invalid("request must be strict JSON in a regular file of at most 1 MiB")
        })?;
        if value.get("invocation_budget").is_none() {
            return Err(invalid(
                "invocation_budget is required (null or unsigned integer)",
            ));
        }
        let request: Self = serde_json::from_value(value)
            .map_err(|_| invalid("unknown or malformed request fields"))?;
        request.validate()?;
        Ok(request)
    }
    pub fn validate(&self) -> AppResult<()> {
        if self.schema_version != REQUEST_SCHEMA
            || [
                &self.request_id,
                &self.case_id,
                &self.asset_id,
                &self.source_view_request_id,
                &self.host.host_id,
            ]
            .iter()
            .any(|id| !valid_id(id))
            || !valid_hash(&self.expected_source_view_receipt_sha256)
            || self.host.model.as_ref().is_some_and(|s| {
                s.trim().is_empty() || s.len() > 200 || s.chars().any(char::is_control)
            })
        {
            return Err(invalid(
                "invalid schema, bounded identifier, digest or host declaration",
            ));
        }
        Ok(())
    }
    pub fn content_digest(&self) -> AppResult<String> {
        domain_digest(REQUEST_SCHEMA, self)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockerCode {
    SourceViewNotReady,
    HostMismatch,
    DelegationUnavailable,
    BudgetCannotFundReconnaissanceAndReserves,
    SourceAuthorizationMissing,
    SourceAuthorizationExpired,
    GrantChanged,
    SourceBindingMismatch,
    SnapshotIntegrityFailed,
    ViewMissing,
    ViewIntegrityFailed,
    RunDirectoryUnavailable,
    ValidatorResourcesChanged,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blocker {
    pub code: BlockerCode,
    pub stage: String,
    pub next_action: String,
}
impl Blocker {
    pub(crate) fn new(code: BlockerCode, stage: &str) -> Self {
        let action = match code {
            BlockerCode::HostMismatch => "use_acknowledged_host",
            BlockerCode::DelegationUnavailable => "enable_host_delegation",
            BlockerCode::BudgetCannotFundReconnaissanceAndReserves => "increase_invocation_budget",
            _ => "prepare_source_view",
        };
        Self {
            code,
            stage: stage.into(),
            next_action: action.into(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBinding {
    pub source_view_request_id: String,
    pub source_view_receipt_sha256: String,
    pub view_id: String,
    pub view_sha256: String,
    pub canonical_snapshot_id: String,
    pub canonical_snapshot_sha256: String,
    pub policy_id: String,
    pub scope: Vec<String>,
    pub source_ref: String,
    pub grant_sha256: String,
    pub acknowledgement_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub session_id: String,
    pub provider_run_id: String,
    pub provider_task_id: String,
    pub attempt_id: String,
    pub prepared_at: String,
    pub source: SourceBinding,
    pub upstream_commit: String,
    pub validator_resources_sha256: String,
    pub profile: Profile,
    pub invocation_budget: Option<u64>,
    pub applied_floor: u64,
    pub host: Host,
    pub run_directory: PathBuf,
    pub target_execution_allowed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum PreparationResult {
    Prepared {
        facts: Box<Prepared>,
        descriptor_sha256: String,
    },
    Blocked {
        request: Box<PrepareRequest>,
        blockers: Vec<Blocker>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationReceipt {
    pub schema_version: String,
    pub request_id: String,
    pub request_sha256: String,
    pub case_id: String,
    pub asset_id: String,
    pub occurred_at: String,
    pub case_revision: i64,
    pub sequence: u64,
    pub predecessor_sha256: Option<String>,
    pub result: PreparationResult,
    pub receipt_sha256: String,
}
impl PreparationReceipt {
    pub fn content_digest(&self) -> AppResult<String> {
        let mut value = serde_json::to_value(self)?;
        value.as_object_mut().unwrap().remove("receipt_sha256");
        domain_digest(RECEIPT_SCHEMA, &value)
    }
    pub fn session_id(&self) -> Option<&str> {
        match &self.result {
            PreparationResult::Prepared { facts, .. } => Some(&facts.session_id),
            _ => None,
        }
    }
    pub(crate) fn verify(&self) -> AppResult<()> {
        if self.schema_version != RECEIPT_SCHEMA
            || self.sequence != 0
            || self.predecessor_sha256.is_some()
            || self.case_revision < 1
            || !valid_id(&self.case_id)
            || !valid_id(&self.request_id)
            || self.content_digest()? != self.receipt_sha256
        {
            return Err(AppError::Storage(
                "audit receipt identity/digest mismatch".into(),
            ));
        }
        if let PreparationResult::Prepared {
            facts,
            descriptor_sha256,
        } = &self.result
            && (facts.target_execution_allowed
                || !valid_id(&facts.session_id)
                || digest(&canonical_bytes(facts)?) != *descriptor_sha256)
        {
            return Err(AppError::Storage(
                "audit descriptor identity/digest mismatch".into(),
            ));
        }
        if let PreparationResult::Blocked { request, .. } = &self.result
            && (request.validate().is_err()
                || request.request_id != self.request_id
                || request.case_id != self.case_id
                || request.asset_id != self.asset_id
                || request.content_digest()? != self.request_sha256)
        {
            return Err(AppError::Storage(
                "audit blocked request identity/digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

pub(crate) enum RequestReadError {
    File,
    Json,
}
pub(crate) fn read_request(path: &Path) -> Result<serde_json::Value, RequestReadError> {
    let bytes = crate::case_archive_io::read_bounded_regular(path, 1024 * 1024)
        .map_err(|_| RequestReadError::File)?;
    super::strict_json::parse(&bytes).map_err(|_| RequestReadError::Json)
}
