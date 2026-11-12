//! Immutable terminal checks derived exclusively from provider custody.
pub mod wording;
use crate::cloudflare_provider::audit::{BlockerCode, record::TerminationReason};
use crate::domain::{AssessmentCase, EngineTaskKind};
use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};

pub const FORMAT_REQUIREMENT: &str = "cloudflare_audit_terminal/v1";
pub const EVENT: &str = "cloudflare_audit.outcome_recorded";
pub const PROVIDER: &str = "cloudflare-security-audit";
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Outcome {
    pub preparation_request_id: String,
    pub preparation_receipt_sha256: String,
    pub asset_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub terminal_sha256: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    #[serde(flatten)]
    pub ending: Ending,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "ending", rename_all = "snake_case", deny_unknown_fields)]
pub enum Ending {
    Blocked {
        reasons: Vec<BlockerCode>,
    },
    Terminated {
        reason: TerminationReason,
        assignment_count: usize,
        capture_count: usize,
    },
}
fn invalid() -> AppError {
    AppError::InvalidRequest("source audit failure does not match recorded custody".into())
}
pub fn has_failure(case: &AssessmentCase) -> bool {
    case.scan_runs
        .iter()
        .flat_map(|r| &r.engine_runs)
        .any(|t| matches!(t.task_kind, EngineTaskKind::AgentAuditFailure { .. }))
}
pub(crate) fn check_shape(case: &AssessmentCase) -> AppResult<()> {
    if has_failure(case) && !case.format_requirements.contains(FORMAT_REQUIREMENT) {
        return Err(invalid());
    }
    for task in case.scan_runs.iter().flat_map(|r| &r.engine_runs) {
        if let EngineTaskKind::AgentAuditFailure {
            provider_id,
            outcome,
        } = &task.task_kind
            && (provider_id != PROVIDER
                || matches!(&outcome.ending, Ending::Blocked { reasons } if reasons.is_empty()))
        {
            return Err(invalid());
        }
    }
    Ok(())
}
pub(crate) fn check_update(previous: &AssessmentCase, next: &AssessmentCase) -> AppResult<()> {
    for run in &previous.scan_runs {
        if run
            .engine_runs
            .iter()
            .any(|t| matches!(t.task_kind, EngineTaskKind::AgentAuditFailure { .. }))
        {
            let retained = next.scan_runs.iter().find(|r| r.id == run.id);
            if retained.map(serde_json::to_value).transpose()? != Some(serde_json::to_value(run)?) {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

/// Ordinary saves may retain failure runs, but only custody writes or verified
/// archive imports may introduce them.
pub(crate) fn check_existing(
    previous: Option<&AssessmentCase>,
    next: &AssessmentCase,
) -> AppResult<()> {
    for run in &next.scan_runs {
        if run
            .engine_runs
            .iter()
            .any(|task| matches!(task.task_kind, EngineTaskKind::AgentAuditFailure { .. }))
            && !previous.is_some_and(|case| {
                case.scan_runs.iter().any(|old| {
                    old.id == run.id
                        && old.engine_runs.iter().any(|task| {
                            matches!(task.task_kind, EngineTaskKind::AgentAuditFailure { .. })
                        })
                })
            })
        {
            return Err(invalid());
        }
    }
    Ok(())
}

use crate::cloudflare_provider::audit::{
    PreparationReceipt, PreparationResult, RECEIPT_EVENT,
    record::{Entry, RECORD_EVENT, Record},
};
use crate::cloudflare_provider::source_view::{canonical_bytes, digest, domain_digest};
use crate::domain::*;
use crate::storage::CaseEvent;
use serde_json::{Value, json};

pub(crate) fn plan(
    case: &AssessmentCase,
    receipt: &PreparationReceipt,
    record: &Record,
) -> AppResult<Option<ScanRun>> {
    let (run_id, task_id, ending, terminal_sha256, time, created) = match &receipt.result {
        PreparationResult::Blocked { blockers, .. } => {
            if blockers.is_empty() {
                return Err(invalid());
            }
            let hash = domain_digest(
                FORMAT_REQUIREMENT,
                &json!([case.id, receipt.receipt_sha256]),
            )?;
            (
                format!("audit-outcome-{hash}"),
                format!("audit-check-{hash}"),
                Ending::Blocked {
                    reasons: blockers.iter().map(|b| b.code.clone()).collect(),
                },
                receipt.receipt_sha256.clone(),
                receipt.occurred_at.as_str(),
                receipt.occurred_at.as_str(),
            )
        }
        PreparationResult::Prepared { facts, .. } => {
            let Some((entry, reason)) = record.terminated() else {
                return Ok(None);
            };
            (
                facts.provider_run_id.clone(),
                facts.provider_task_id.clone(),
                Ending::Terminated {
                    reason,
                    assignment_count: record.assignments.len(),
                    capture_count: record
                        .documents
                        .values()
                        .map(|d| d.revision_count as usize)
                        .sum::<usize>()
                        + record
                            .assignments
                            .iter()
                            .filter(|a| a.output.is_some())
                            .count(),
                },
                entry.entry_sha256.clone(),
                entry.occurred_at.as_str(),
                facts.prepared_at.as_str(),
            )
        }
    };
    let occurred_at = time.parse().map_err(|_| invalid())?;
    let created_at = created.parse().map_err(|_| invalid())?;
    let blocked = matches!(ending, Ending::Blocked { .. });
    let outcome = Outcome {
        preparation_request_id: receipt.request_id.clone(),
        preparation_receipt_sha256: receipt.receipt_sha256.clone(),
        asset_id: receipt.asset_id.clone(),
        session_id: receipt.session_id().map(str::to_owned),
        terminal_sha256,
        occurred_at,
        ending,
    };
    let task = failure_task(run_id.clone(), task_id, outcome, blocked);
    Ok(Some(ScanRun {
        id: run_id,
        case_id: case.id.clone(),
        sequence: case
            .scan_runs
            .iter()
            .map(|r| r.sequence)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(invalid)?,
        created_at,
        completed_at: Some(occurred_at),
        request_outcome: None,
        report_asset_snapshots: case
            .assets
            .iter()
            .filter(|a| a.id == receipt.asset_id)
            .map(|a| ReportAssetSnapshot {
                asset: a.clone(),
                disposition: ReportAssetDisposition::RequestedForScan,
            })
            .collect(),
        knowledge_cutoff: created_at,
        ai_system_applicable: false,
        ai_system_applicability: AiSystemApplicabilityAnswer::Unknown,
        ai_generated_artifact: case.ai_generated_artifact,
        verification_baseline_run_id: None,
        scope_grant_ids: vec![],
        scope_grant_snapshots: vec![],
        engine_admission_issues: vec![],
        engine_runs: vec![task],
        campaign_id: None,
    }))
}
pub(crate) fn event(run: &ScanRun) -> AppResult<Value> {
    let task = &run.engine_runs[0];
    let EngineTaskKind::AgentAuditFailure { outcome, .. } = &task.task_kind else {
        return Err(invalid());
    };
    Ok(
        json!({"preparation_request_id":outcome.preparation_request_id,"terminal_sha256":outcome.terminal_sha256,
        "run_id":run.id,"task_id":task.id,"outcome_sha256":digest(&canonical_bytes(outcome)?)}),
    )
}
/// Validate against the same transaction/history that owns the case document.
pub(crate) fn check_custody(case: &AssessmentCase, events: &[CaseEvent]) -> AppResult<()> {
    if !has_failure(case) {
        return Ok(());
    }
    let receipts = events
        .iter()
        .filter(|e| e.event_type == RECEIPT_EVENT)
        .map(|e| serde_json::from_str::<PreparationReceipt>(&e.payload_json))
        .collect::<Result<Vec<_>, _>>()?;
    let sessions: std::collections::BTreeSet<_> = case
        .scan_runs
        .iter()
        .flat_map(|run| &run.engine_runs)
        .filter_map(|task| match &task.task_kind {
            EngineTaskKind::AgentAuditFailure { outcome, .. } => outcome.session_id.as_deref(),
            _ => None,
        })
        .collect();
    let mut records = std::collections::BTreeMap::<_, Record>::new();
    for e in events.iter().filter(|e| e.event_type == RECORD_EVENT) {
        let entry: Entry = serde_json::from_str(&e.payload_json)?;
        if !sessions.contains(entry.session_id.as_str()) {
            continue;
        }
        let receipt = receipts
            .iter()
            .find(|r| r.session_id() == Some(entry.session_id.as_str()))
            .ok_or_else(invalid)?;
        if entry.occurred_at != e.occurred_at {
            return Err(invalid());
        }
        records.entry(entry.session_id.clone()).or_default().push(
            receipt,
            entry,
            e.payload_json.len(),
        )?;
    }
    let mut seen = std::collections::BTreeSet::new();
    for run in &case.scan_runs {
        for task in &run.engine_runs {
            let EngineTaskKind::AgentAuditFailure { outcome, .. } = &task.task_kind else {
                continue;
            };
            if !seen.insert(&outcome.preparation_request_id) {
                return Err(invalid());
            }
            let matching: Vec<_> = receipts
                .iter()
                .filter(|r| r.request_id == outcome.preparation_request_id)
                .collect();
            if matching.len() != 1 {
                return Err(invalid());
            }
            let receipt = matching[0];
            receipt.verify()?;
            if receipt.case_id != case.id {
                return Err(invalid());
            }
            let empty = Record::default();
            let record = receipt
                .session_id()
                .and_then(|id| records.get(id))
                .unwrap_or(&empty);
            let expected = plan(case, receipt, record)?.ok_or_else(invalid)?;
            if run.engine_runs.len() != 1
                || run.id != expected.id
                || run.case_id != case.id
                || run.created_at != expected.created_at
                || run.completed_at != expected.completed_at
                || serde_json::to_value(task)? != serde_json::to_value(&expected.engine_runs[0])?
                || !run.scope_grant_ids.is_empty()
                || !run.scope_grant_snapshots.is_empty()
                || case
                    .findings
                    .iter()
                    .any(|f| f.first_seen_run_id == run.id || f.last_seen_run_id == run.id)
                || case.finding_observations.iter().any(|o| o.run_id == run.id)
                || case
                    .inventory_observations
                    .iter()
                    .any(|o| o.run_id == run.id)
                || case.raw_artifacts.iter().any(|a| a.run_id == run.id)
                || case
                    .agent_audit_admissions
                    .iter()
                    .any(|a| a.identities.run_id == run.id)
            {
                return Err(invalid());
            }
            let expected_event = event(run)?;
            let matching = events
                .iter()
                .filter(|e| e.event_type == EVENT)
                .map(|e| serde_json::from_str::<Value>(&e.payload_json))
                .collect::<Result<Vec<_>, _>>()?;
            if matching
                .iter()
                .filter(|e| e["preparation_request_id"] == outcome.preparation_request_id)
                .collect::<Vec<_>>()
                != vec![&expected_event]
            {
                return Err(invalid());
            }
        }
    }
    for e in events.iter().filter(|e| e.event_type == EVENT) {
        let value: Value = serde_json::from_str(&e.payload_json)?;
        if !seen
            .iter()
            .any(|id| value["preparation_request_id"] == **id)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn failure_task(run_id: String, task_id: String, outcome: Outcome, blocked: bool) -> EngineRun {
    EngineRun {
        id: task_id,
        scan_run_id: run_id,
        engine_id: PROVIDER.into(),
        asset_ids: vec![outcome.asset_id.clone()],
        finished_at: Some(outcome.occurred_at),
        task_kind: EngineTaskKind::AgentAuditFailure {
            provider_id: PROVIDER.into(),
            outcome,
        },
        localhost_tcp_observation: None,
        status: if blocked {
            EngineRunStatus::NotExecuted
        } else {
            EngineRunStatus::Failed
        },
        progress_percent: 100,
        phase: if blocked { "not_executed" } else { "failed" }.into(),
        started_at: None,
        resume_token: None,
        last_execution_report_sha256: None,
        engine_version: None,
        reported_version: None,
        image_digest: None,
        rule_version: None,
        adapter_version: String::new(),
        manifest_schema_version: None,
        source_revision: None,
        repository_url: None,
        distribution_mode: None,
        image_repository: None,
        command_sha256: None,
        execution_timeout_seconds: None,
        knowledge_input: None,
        scope_contract_sha256: None,
        comparison_scope_sha256: None,
        execution_scope_grant_ids: None,
        naabu_work_plan: None,
        naabu_attempt_requests: vec![],
        naabu_attempt_results: vec![],
        mapping_version: None,
        mapping_provenance: None,
        fingerprint_schema_version: None,
        runtime_provider: None,
        runtime_version: None,
        runtime_security_options: None,
        exit_code: None,
        cleanup_removed: None,
        cleanup_detail: None,
        gateway_refusals: None,
        warnings: vec![],
        unattributed: vec![],
        unevaluated_targets: vec![],
        security_template_executions: vec![],
        manual_review_controls: vec![],
        raw_artifact_ids: vec![],
        error_code: None,
        error_message: None,
    }
}

pub fn status(
    case: &AssessmentCase,
    receipt: &PreparationReceipt,
    data: &std::path::Path,
    result: &mut Value,
) {
    if let Some(value) = snapshot_state(case, receipt, data) {
        result["next_operation"] = if value["report_snapshot_state"] == "pending" {
            json!(if receipt.session_id().is_some() {
                "terminate_replay"
            } else {
                "prepare_replay"
            })
        } else {
            Value::Null
        };
        result["outcome_run"] = value;
    } else if matches!(receipt.result, PreparationResult::Blocked { .. }) {
        result["next_operation"] = Value::Null;
    }
}
fn snapshot_state(
    case: &AssessmentCase,
    receipt: &PreparationReceipt,
    data: &std::path::Path,
) -> Option<Value> {
    let (run, task) = case.scan_runs.iter().flat_map(|r| r.engine_runs.iter().map(move |t| (r,t))).find(|(_,t)| matches!(&t.task_kind, EngineTaskKind::AgentAuditFailure { outcome, .. } if outcome.preparation_receipt_sha256 == receipt.receipt_sha256))?;
    let mut value = json!({"run_id":run.id,"task_id":task.id,"report_snapshot_state":"retained"});
    let snapshot = crate::report_snapshot::current_run_snapshot(case, &run.id)
        .and_then(|s| {
            s.ok_or_else(|| AppError::NotAvailable("Report snapshot is not available.".into()))
        })
        .and_then(|s| s.read(&data.join("artifacts"), &case.id));
    if let Err(error) = snapshot {
        crate::cloudflare_provider::audit::admit::snapshot_failure(&mut value, &error);
    }
    Some(value)
}
pub(crate) fn retain(
    context: &crate::cloudflare_provider::source_view::OwnedContext<'_>,
    receipt: &PreparationReceipt,
) -> Option<Value> {
    let case = context.storage.get_case(&receipt.case_id).ok()?;
    let mut value = snapshot_state(&case, receipt, context.data_dir)?;
    if value["report_snapshot_state"] == "pending" {
        match crate::cloudflare_provider::audit::admit::retain_report_snapshot(
            context.storage,
            context.data_dir,
            &case.id,
            value["run_id"].as_str().unwrap(),
        ) {
            Ok(case) => value = snapshot_state(&case, receipt, context.data_dir)?,
            Err(error) => {
                crate::cloudflare_provider::audit::admit::snapshot_failure(&mut value, &error)
            }
        }
    }
    Some(value)
}

#[cfg(test)]
mod tests;
