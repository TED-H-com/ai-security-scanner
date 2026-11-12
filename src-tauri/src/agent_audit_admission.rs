mod planner;
pub(crate) mod publication;
use crate::cloudflare_provider::{
    audit::{
        SourceBinding,
        sealed::{Digests, Method, Outcome},
    },
    bundle::AuditBinding,
};
use crate::domain::AssessmentCase;
use crate::error::{AppError, AppResult};
use crate::provider_report::{ProviderProvenance, ProviderSourceLocation};
use chrono::{DateTime, Utc};
pub use planner::{
    AdmissionPlan, AdmissionRequestFacts, ArtifactCopy, PlanError, PlannerRefusal, plan_admission,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const ADMITTED_EVENT: &str = "cloudflare_audit.admitted";
pub const FORMAT_REQUIREMENT: &str = "cloudflare_audit_admission/v1";
pub const UNAVAILABLE: &str = "This output cannot include admitted source audits in this build.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderRecordRef {
    pub admission_id: String,
    pub native_record_index: usize,
    pub native_record_sha256: String,
    pub native_fingerprint: String,
    pub source_locators: Vec<ProviderSourceLocation>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBinding {
    pub member_path: String,
    pub artifact_id: String,
    pub sha256: String,
    pub byte_length: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionCounts {
    pub confirmed: usize,
    pub needs_validation: usize,
    pub rejected: usize,
    pub unresolved_candidates: usize,
    pub coverage_by_status: BTreeMap<String, usize>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAuditAdmission {
    pub admission_id: String,
    pub request_id: String,
    pub request_sha256: String,
    pub admitted_at: DateTime<Utc>,
    pub provider_id: String,
    pub provenance: ProviderProvenance,
    pub identities: AuditBinding,
    pub preparation_request_id: String,
    pub source_id: String,
    pub source_view_request_id: String,
    pub source: SourceBinding,
    pub digests: Digests,
    pub method: Method,
    pub outcome: Outcome,
    pub verification_scope: String,
    pub validators_reexecuted: bool,
    pub counts_by_role: BTreeMap<String, usize>,
    pub counts_by_state: BTreeMap<String, usize>,
    pub counts: AdmissionCounts,
    pub artifacts: Vec<ArtifactBinding>,
    // Retain the verified JSON itself, including reported_only and native payloads.
    pub retained_projection: Value,
    pub admission_sha256: String,
}

impl AgentAuditAdmission {
    pub fn receipt(&self, case_revision: i64) -> Value {
        serde_json::json!({
            "admission_id": self.admission_id, "admission_sha256": self.admission_sha256,
            "request_id": self.request_id, "request_sha256": self.request_sha256,
            "case_id": self.identities.case_id, "session_id": self.identities.session_id,
            "run_id": self.identities.run_id, "task_id": self.identities.task_id,
            "sealed_entry_sha256": self.digests.sealed_entry_sha256,
            "bundle_sha256": self.digests.bundle_sha256,
            "admitted_at": self.admitted_at, "case_revision": case_revision
        })
    }
}

pub fn check_format(case: &AssessmentCase) -> AppResult<()> {
    if let Some(requirement) = case.format_requirements.iter().find(|r| {
        r.as_str() != FORMAT_REQUIREMENT
            && r.as_str() != crate::agent_audit_failure::FORMAT_REQUIREMENT
    }) {
        return Err(AppError::NotAvailable(format!(
            "This case requires a newer version: {requirement}"
        )));
    }
    crate::agent_audit_failure::check_shape(case)?;
    Ok(())
}
pub(crate) fn check_write(case: &AssessmentCase) -> AppResult<()> {
    check_format(case)?;
    if !case.agent_audit_admissions.is_empty()
        && !case.format_requirements.contains(FORMAT_REQUIREMENT)
    {
        return Err(AppError::InvalidRequest(
            "admitted source audits require cloudflare_audit_admission/v1".into(),
        ));
    }
    let mut sessions = std::collections::BTreeSet::new();
    for a in &case.agent_audit_admissions {
        let task = case
            .scan_runs
            .iter()
            .find(|r| r.id == a.identities.run_id)
            .and_then(|r| r.engine_runs.iter().find(|t| t.id == a.identities.task_id));
        if !sessions.insert(&a.identities.session_id) || a.identities.case_id != case.id
            || !task.is_some_and(|t| matches!(&t.task_kind, crate::domain::EngineTaskKind::AgentAudit { provider_id, admission_id } if provider_id == &a.provider_id && admission_id == &a.admission_id)) {
            return Err(AppError::InvalidRequest("admission requires a unique session and its AgentAudit task discriminator".into()));
        }
    }
    Ok(())
}
pub(crate) fn check_update(previous: &AssessmentCase, next: &AssessmentCase) -> AppResult<()> {
    check_format(previous)?;
    crate::agent_audit_failure::check_update(previous, next)?;
    for admission in &previous.agent_audit_admissions {
        let retained = next
            .agent_audit_admissions
            .iter()
            .find(|a| a.admission_id == admission.admission_id);
        if retained.map(serde_json::to_value).transpose()? != Some(serde_json::to_value(admission)?)
        {
            return Err(AppError::InvalidRequest(
                "admitted source audits are immutable".into(),
            ));
        }
    }
    Ok(())
}
/// Case bundles contain every admission, even when their reports select a scanner run.
pub(crate) fn check_bundle(case: &AssessmentCase) -> AppResult<()> {
    check_write(case)?;
    for run in &case.scan_runs {
        crate::exporters::source_audit::validate(case, run)?;
        check_original_bindings(case, &run.id)?;
    }
    Ok(())
}

pub(crate) fn check_original_bindings(case: &AssessmentCase, run_id: &str) -> AppResult<()> {
    for admission in case
        .agent_audit_admissions
        .iter()
        .filter(|a| a.identities.run_id == run_id)
    {
        for binding in &admission.artifacts {
            crate::export::validate_portable_archive_path(std::path::Path::new(
                &binding.member_path,
            ))?;
            let expected = format!(
                "{}/{}/{}/{}",
                case.id, run_id, admission.identities.task_id, binding.member_path
            );
            if !case
                .raw_artifacts
                .iter()
                .any(|raw| raw.id == binding.artifact_id && raw.relative_path == expected)
            {
                return Err(AppError::InvalidRequest(
                    "Source audit original does not match its stored member binding.".into(),
                ));
            }
        }
    }
    Ok(())
}

pub fn check_report(case: &AssessmentCase) -> AppResult<()> {
    check_format(case)?;
    if !case.agent_audit_admissions.is_empty()
        || case.scan_runs.iter().flat_map(|r| &r.engine_runs).any(|t| {
            matches!(
                t.task_kind,
                crate::domain::EngineTaskKind::AgentAudit { .. }
                    | crate::domain::EngineTaskKind::AgentAuditFailure { .. }
            )
        })
    {
        return Err(AppError::NotAvailable(UNAVAILABLE.into()));
    }
    Ok(())
}

/// Later-slice formats only accept selected runs without provider tasks.
pub fn check_run_export(case: &AssessmentCase, run_id: &str) -> AppResult<()> {
    check_format(case)?;
    if case
        .scan_runs
        .iter()
        .filter(|r| r.id == run_id)
        .flat_map(|r| &r.engine_runs)
        .any(|t| {
            matches!(
                t.task_kind,
                crate::domain::EngineTaskKind::AgentAudit { .. }
                    | crate::domain::EngineTaskKind::AgentAuditFailure { .. }
            )
        })
    {
        return Err(AppError::NotAvailable(UNAVAILABLE.into()));
    }
    Ok(())
}

// Inspect only compatibility fields so older snapshot originals remain retrievable
// even when their unrelated domain/report shapes cannot be replayed by this renderer.
pub(crate) fn check_report_document(case: &Value) -> AppResult<()> {
    let requirements: std::collections::BTreeSet<String> = serde_json::from_value(
        case.get("format_requirements")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([])),
    )?;
    if let Some(r) = requirements.iter().find(|r| {
        r.as_str() != FORMAT_REQUIREMENT
            && r.as_str() != crate::agent_audit_failure::FORMAT_REQUIREMENT
    }) {
        return Err(AppError::NotAvailable(format!(
            "This case requires a newer version: {r}"
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
