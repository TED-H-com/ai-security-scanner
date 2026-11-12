//! Inventory only: provider prose remains in its unchanged original documents.
use crate::case_archive_io::ArchiveEntry;
use crate::cloudflare_provider::audit::{captured::Selector, record::Role};
use serde::{Deserialize, Serialize};

pub(super) const SCHEMA: &str = "ai-security-scanner.provider-archive-history/v1";
pub(super) const PATH: &str = "provider-history.json";
pub(super) const CAPABILITIES: [&str; 2] = [
    "cloudflare_audit_admission/v1",
    "provider_archive_history/v1",
];
pub(super) const TERMINAL_CAPABILITY: &str = "cloudflare_audit_terminal/v1";
pub(super) const SOURCE_OMISSION: &str = "Source snapshots inside source-audit packages were not included; their bytes cannot be rechecked from this archive.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct History {
    pub schema_version: String,
    pub preparations: Vec<Preparation>,
}
impl History {
    pub fn capabilities(&self) -> Vec<String> {
        let mut capabilities = vec![CAPABILITIES[1].into()];
        if self.preparations.iter().any(|p| p.admission_id.is_some()) {
            capabilities.push(CAPABILITIES[0].into());
        }
        if self
            .preparations
            .iter()
            .any(|p| p.termination.is_some() || p.outcome_run.is_some())
        {
            capabilities.push(TERMINAL_CAPABILITY.into());
        }
        capabilities.sort();
        capabilities
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Termination {
    pub entry_sha256: String,
    pub occurred_at: String,
    pub reason: crate::cloudflare_provider::audit::record::TerminationReason,
}
fn present_termination<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Termination>, D::Error> {
    Termination::deserialize(d).map(Some)
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum State {
    Admitted,
    Sealed,
    Unsealed,
    Blocked,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Head {
    pub sequence: u64,
    pub entry_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Completeness {
    pub recorded_history: bool,
    pub accepted_captures: bool,
    pub sealed_package: bool,
    pub source_bodies: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Preparation {
    pub provider_id: String,
    pub preparation_request_id: String,
    pub session_id: Option<String>,
    pub provider_run_id: Option<String>,
    pub provider_task_id: Option<String>,
    pub state: State,
    pub recorded_head: Head,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_termination"
    )]
    pub termination: Option<Termination>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_outcome"
    )]
    pub outcome_run: Option<OutcomeRun>,
    pub seal_sha256: Option<String>,
    pub admission_id: Option<String>,
    pub admission_sha256: Option<String>,
    pub descriptor: Option<ArchiveEntry>,
    pub package: Vec<ArchiveEntry>,
    pub captured: Vec<Captured>,
    pub source_body_omissions: Vec<ArchiveEntry>,
    pub completeness: Completeness,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Captured {
    pub selector: Selector,
    pub role: Option<Role>,
    pub sha256: String,
    pub byte_length: u64,
    pub available: bool,
    pub member: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct OutcomeRun {
    pub run_id: String,
    pub task_id: String,
}
fn present_outcome<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<OutcomeRun>, D::Error> {
    OutcomeRun::deserialize(d).map(Some)
}
