//! Admission graph checks shared by audit-aware exports and attachments.
use crate::domain::{AssessmentCase, EngineTaskKind, Evidence, ScanRun};
use crate::error::{AppError, AppResult};
use crate::provider_report::{ProviderReportProjection, ProviderVerdict};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn invalid() -> AppError {
    AppError::InvalidRequest("Source audit evidence does not match its stored admission.".into())
}

pub(crate) fn validate(case: &AssessmentCase, run: &ScanRun) -> AppResult<()> {
    crate::agent_audit_admission::check_format(case)?;
    if run.case_id != case.id {
        return Err(invalid());
    }
    let mut task_ids = BTreeSet::new();
    let mut projections = BTreeMap::new();
    for task in &run.engine_runs {
        if !matches!(task.task_kind, EngineTaskKind::AgentAudit { .. }) {
            continue;
        }
        let a = crate::source_audit_report::admission(case, task).ok_or_else(|| {
            AppError::NotAvailable("Source audit admission is missing or ambiguous.".into())
        })?;
        if case
            .scan_runs
            .iter()
            .filter(|other| other.id == run.id)
            .count()
            != 1
            || case
                .scan_runs
                .iter()
                .flat_map(|r| &r.engine_runs)
                .filter(|other| other.id == task.id)
                .count()
                != 1
            || task.scan_run_id != run.id
            || task.engine_id != a.provider_id
            || !task_ids.insert(&task.id)
            || case
                .agent_audit_admissions
                .iter()
                .filter(|other| other.admission_id == a.admission_id)
                .count()
                != 1
        {
            return Err(invalid());
        }
        let mut artifacts = BTreeSet::new();
        for binding in &a.artifacts {
            let matches = case
                .raw_artifacts
                .iter()
                .filter(|raw| raw.id == binding.artifact_id)
                .collect::<Vec<_>>();
            if matches.len() != 1 || !artifacts.insert(&binding.artifact_id) {
                return Err(invalid());
            }
            let raw = matches[0];
            if raw.case_id != case.id
                || raw.run_id != run.id
                || raw.engine_run_id != task.id
                || raw.sha256 != binding.sha256
                || raw.byte_length != binding.byte_length
                || !raw.contains_sensitive_data
            {
                return Err(invalid());
            }
        }
        if case
            .raw_artifacts
            .iter()
            .filter(|raw| raw.engine_run_id == task.id)
            .count()
            != artifacts.len()
            || task.raw_artifact_ids.len() != artifacts.len()
            || task.raw_artifact_ids.iter().collect::<BTreeSet<_>>() != artifacts
        {
            return Err(invalid());
        }
        let projection: ProviderReportProjection =
            serde_json::from_value(a.retained_projection.clone()).map_err(|_| invalid())?;
        if projection.provider_id != a.provider_id {
            return Err(invalid());
        }
        projections.insert(task.id.as_str(), projection);
    }
    for observation in case
        .finding_observations
        .iter()
        .filter(|o| o.run_id == run.id)
    {
        let finding = observation.finding_snapshot.as_ref().or_else(|| {
            case.findings
                .iter()
                .find(|f| f.id == observation.finding_id)
        });
        let audit_engine = run
            .engine_runs
            .iter()
            .any(|t| task_ids.contains(&t.id) && observation.engine_ids.contains(&t.engine_id));
        if audit_engine
            && (observation.finding_snapshot.is_none()
                || finding.is_none_or(|f| f.evidence.is_empty()))
        {
            return Err(invalid());
        }
        if let Some(finding) = finding {
            if audit_engine && !finding.control_references.is_empty() {
                return Err(invalid());
            }
            for evidence in &finding.evidence {
                if audit_engine
                    || evidence.provider_record.is_some()
                    || evidence
                        .engine_run_id
                        .as_ref()
                        .is_some_and(|id| task_ids.contains(id))
                {
                    validate_evidence(case, run, evidence, &projections)?;
                }
            }
        }
    }
    // Current findings can also supply export detail when a snapshot is absent.
    for evidence in case
        .findings
        .iter()
        .flat_map(|f| &f.evidence)
        .filter(|e| e.run_id == run.id)
    {
        if evidence.provider_record.is_some()
            || evidence
                .engine_run_id
                .as_ref()
                .is_some_and(|id| task_ids.contains(id))
        {
            validate_evidence(case, run, evidence, &projections)?;
        }
    }
    Ok(())
}

fn validate_evidence(
    case: &AssessmentCase,
    run: &ScanRun,
    evidence: &Evidence,
    projections: &BTreeMap<&str, ProviderReportProjection>,
) -> AppResult<()> {
    let task = run
        .engine_runs
        .iter()
        .find(|t| Some(&t.id) == evidence.engine_run_id.as_ref())
        .ok_or_else(invalid)?;
    let a = crate::source_audit_report::admission(case, task).ok_or_else(invalid)?;
    let reference = evidence.provider_record.as_ref().ok_or_else(invalid)?;
    if evidence.run_id != run.id
        || evidence.engine_id != a.provider_id
        || reference.admission_id != a.admission_id
        || !a
            .artifacts
            .iter()
            .any(|b| b.artifact_id == evidence.artifact_id && b.sha256 == evidence.artifact_sha256)
    {
        return Err(invalid());
    }
    let projection = projections.get(task.id.as_str()).ok_or_else(invalid)?;
    let records = projection
        .records
        .iter()
        .filter(|r| r.native_record_index == reference.native_record_index)
        .collect::<Vec<_>>();
    if records.len() != 1 {
        return Err(invalid());
    }
    let record = records[0];
    if record.verdict != ProviderVerdict::Confirmed
        || record.native_record_sha256 != reference.native_record_sha256
        || record.fingerprint != reference.native_fingerprint
    {
        return Err(invalid());
    }
    Ok(())
}

/// Only called after validation, and with the export's profile-redacted case.
pub(super) fn identity(case: &AssessmentCase, evidence: &Evidence) -> Option<Value> {
    let reference = evidence.provider_record.as_ref()?;
    let a = case
        .agent_audit_admissions
        .iter()
        .find(|a| a.admission_id == reference.admission_id)?;
    let record = a.retained_projection["records"]
        .as_array()?
        .iter()
        .find(|r| {
            r["native_record_index"] == reference.native_record_index && r["verdict"] == "confirmed"
        })?;
    Some(json!({
        "provider_id": a.provider_id,
        "admission_id": a.admission_id,
        "native_fingerprint": reference.native_fingerprint,
        "native_record_sha256": reference.native_record_sha256,
        "native_record_index": reference.native_record_index,
        "provider_verdict": record["verdict"],
        "method": "Cloudflare source audit",
        "upstream_commit": a.method.upstream_commit,
    }))
}
