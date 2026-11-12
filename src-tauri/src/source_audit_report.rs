//! Frozen admission projection; rendering never consults the provider workspace.
use crate::agent_audit_admission::AgentAuditAdmission;
use crate::domain::{AssessmentCase, EngineRun, EngineTaskKind, ScanRun};
use crate::error::{AppError, AppResult};
use crate::provider_report::{AgentAuditRecord, ProviderReportProjection, ProviderVerdict};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceAuditMethod {
    pub provider: String,
    pub upstream_commit: String,
    pub validator_resources_sha256: String,
    pub profile: String,
    pub declared_invocation_limit: Option<u64>,
    pub issued_invocations: u64,
    pub remaining_invocations: Option<u64>,
    pub counts_by_role: BTreeMap<String, usize>,
    pub counts_by_state: BTreeMap<String, usize>,
    pub provenance: String,
    pub verification_scope: String,
    pub validators_reexecuted: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceAuditOutcome {
    pub state: String,
    pub incomplete_reason: Option<String>,
    pub audit_performed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceAuditGap {
    pub coverage_id: String,
    pub status: String,
    #[serde(default)]
    pub label: String,
    pub continuation_paths: Vec<String>,
    pub unresolved: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceAuditValidation {
    pub native_record: Value,
    pub native_record_index: usize,
    pub native_record_sha256: String,
    pub source_locations: Vec<crate::provider_report::ProviderSourceLocation>,
    pub coverage_ids: Vec<String>,
    pub reported_verifier_assignments: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceAuditReport {
    pub task_id: String,
    pub asset_ids: Vec<String>,
    pub admission_id: String,
    pub method: SourceAuditMethod,
    pub outcome: SourceAuditOutcome,
    pub counts: BTreeMap<String, usize>,
    pub coverage_by_status: BTreeMap<String, usize>,
    pub to_validate: Vec<SourceAuditValidation>,
    pub coverage_gaps: Vec<SourceAuditGap>,
    pub unresolved_candidates: Vec<String>,
    pub technical_detail: SourceAuditTechnical,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub withheld_code_fields: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub withheld_text_fields: usize,
}
fn is_zero(n: &usize) -> bool {
    *n == 0
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceAuditTechnical {
    pub confirmed: Vec<AgentAuditRecord>,
    pub rejected: Vec<AgentAuditRecord>,
    // Full native units retain attempts in their recorded order, including covered units.
    pub coverage_ledger: Value,
    pub lineage: Value,
    pub custody_digests: Value,
    pub admission_sha256: String,
    pub originals: Value,
}
pub fn admission<'a>(
    case: &'a AssessmentCase,
    task: &EngineRun,
) -> Option<&'a AgentAuditAdmission> {
    let EngineTaskKind::AgentAudit {
        admission_id,
        provider_id,
    } = &task.task_kind
    else {
        return None;
    };
    let mut matches = case.agent_audit_admissions.iter().filter(|a| {
        &a.admission_id == admission_id
            && &a.provider_id == provider_id
            && a.identities.task_id == task.id
            && a.identities.run_id == task.scan_run_id
            && a.identities.case_id == case.id
    });
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}
pub fn project(case: &AssessmentCase, run: &ScanRun) -> AppResult<Vec<SourceAuditReport>> {
    let mut reports = Vec::new();
    for task in &run.engine_runs {
        if !matches!(task.task_kind, EngineTaskKind::AgentAudit { .. }) {
            continue;
        }
        let a = admission(case, task)
            .ok_or_else(|| AppError::NotAvailable("Source audit admission is missing.".into()))?;
        let projection: ProviderReportProjection =
            serde_json::from_value(a.retained_projection.clone())?;
        let records = |verdict| {
            projection
                .records
                .iter()
                .filter(|r| r.verdict == verdict)
                .cloned()
                .collect()
        };
        let profile = match a.method.profile {
            crate::cloudflare_provider::audit::Profile::Quick => "quick",
            crate::cloudflare_provider::audit::Profile::Standard => "standard",
            crate::cloudflare_provider::audit::Profile::Deep => "deep",
        };
        let state = match a.outcome.state {
            crate::cloudflare_provider::audit::sealed::TerminalState::Complete => "complete",
            crate::cloudflare_provider::audit::sealed::TerminalState::Incomplete => "incomplete",
        };
        let method = SourceAuditMethod {
            provider: a.provider_id.clone(),
            upstream_commit: a.method.upstream_commit.clone(),
            validator_resources_sha256: a.method.validator_resources_sha256.clone(),
            profile: profile.into(),
            declared_invocation_limit: a.method.budget.limit,
            issued_invocations: a.method.budget.issued,
            remaining_invocations: a.method.budget.remaining,
            counts_by_role: a.counts_by_role.clone(),
            counts_by_state: a.counts_by_state.clone(),
            provenance: crate::report_renderer::enum_key(&a.provenance),
            verification_scope: a.verification_scope.clone(),
            validators_reexecuted: a.validators_reexecuted,
        };
        let outcome = SourceAuditOutcome {
            state: state.into(),
            incomplete_reason: a.outcome.incomplete_reason.clone(),
            audit_performed: a.outcome.audit_performed,
        };
        let to_validate = projection
            .records
            .iter()
            .filter(|r| r.verdict == ProviderVerdict::NeedsValidation)
            .map(|r| SourceAuditValidation {
                native_record: r.native_record.clone(),
                native_record_index: r.native_record_index,
                native_record_sha256: r.native_record_sha256.clone(),
                source_locations: r.source_locations.clone(),
                coverage_ids: r.coverage_ids.clone(),
                reported_verifier_assignments: r.reported_verifier_assignments.clone(),
            })
            .collect();
        let technical_detail = SourceAuditTechnical {
            confirmed: records(ProviderVerdict::Confirmed),
            rejected: records(ProviderVerdict::Rejected),
            coverage_ledger: projection.native_coverage_ledger.clone(),
            lineage: json!({"source": a.source, "identities": a.identities, "source_id": a.source_id, "source_view_request_id": a.source_view_request_id}),
            custody_digests: json!(a.digests),
            admission_sha256: a.admission_sha256.clone(),
            originals: json!(a.artifacts),
        };
        reports.push(SourceAuditReport {
            task_id: task.id.clone(),
            asset_ids: task.asset_ids.clone(),
            admission_id: a.admission_id.clone(),
            method,
            outcome,
            counts: BTreeMap::from([
                ("confirmed".into(), a.counts.confirmed),
                ("needs_validation".into(), a.counts.needs_validation),
                ("rejected".into(), a.counts.rejected),
                (
                    "unresolved_candidates".into(),
                    a.counts.unresolved_candidates,
                ),
            ]),
            coverage_by_status: a.counts.coverage_by_status.clone(),
            to_validate,
            coverage_gaps: gaps(&projection),
            unresolved_candidates: projection.unresolved_candidates.clone(),
            technical_detail,
            withheld_code_fields: 0,
            withheld_text_fields: 0,
        });
    }
    Ok(reports)
}
fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}
pub fn gaps(p: &ProviderReportProjection) -> Vec<SourceAuditGap> {
    p.native_coverage_ledger
        .as_array()
        .into_iter()
        .flatten()
        .filter(|unit| {
            remaining(unit, &p.unresolved_candidates) || unit["status"] == "out_of_scope"
        })
        .map(|unit| SourceAuditGap {
            coverage_id: unit["coverage_id"].as_str().unwrap_or_default().into(),
            status: unit["status"].as_str().unwrap_or_default().into(),
            label: format!(
                "{} — {}",
                unit["attack_class"].as_str().unwrap_or_default(),
                unit["surface"].as_str().unwrap_or_default()
            ),
            continuation_paths: if remaining(unit, &p.unresolved_candidates) {
                strings(&unit["starting_paths"])
            } else {
                Vec::new()
            },
            unresolved: strings(&unit["unresolved"]),
        })
        .collect()
}

fn remaining(unit: &Value, unresolved: &[String]) -> bool {
    match unit["status"].as_str() {
        Some("planned" | "in_progress" | "blocked" | "deferred") => true,
        Some("candidate") => strings(&unit["result_fingerprints"])
            .iter()
            .any(|f| unresolved.contains(f)),
        _ => false,
    }
}
impl SourceAuditGap {
    pub fn remaining(&self) -> bool {
        self.status != "out_of_scope"
    }
}
