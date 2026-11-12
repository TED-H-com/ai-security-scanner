//! Report-facing provider projection. Provider verdicts never mutate human triage.
use crate::domain::Severity;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderVerdict {
    Confirmed,
    NeedsValidation,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    ReportedOnly,
    WorkflowRecorded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderSourceLocation {
    pub path: String,
    pub line: u64,
    pub view_file_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentAuditRecord {
    pub fingerprint: String,
    pub verdict: ProviderVerdict,
    pub severity: Option<Severity>,
    pub native_record: Value,
    pub native_record_index: usize,
    pub native_record_sha256: String,
    pub source_locations: Vec<ProviderSourceLocation>,
    pub coverage_ids: Vec<String>,
    pub reported_verifier_assignments: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderReportedCounts {
    pub confirmed: usize,
    pub needs_validation: usize,
    pub rejected: usize,
    pub reported_confirmed_by_severity: BTreeMap<Severity, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderReportProjection {
    pub schema_version: String,
    pub provider_id: String,
    pub provenance: ProviderProvenance,
    pub reported_run_status: String,
    pub reported_counts: ProviderReportedCounts,
    pub coverage_by_status: BTreeMap<String, usize>,
    pub unresolved_candidates: Vec<String>,
    pub records: Vec<AgentAuditRecord>,
    // Keep complete native history, checks and excluded coverage, not just counts.
    pub native_coverage_ledger: Value,
}
