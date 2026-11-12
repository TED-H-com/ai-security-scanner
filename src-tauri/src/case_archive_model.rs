//! Portable, complete case data and inert restore projection.
//!
//! The archive keeps this original document unchanged. `restored_case` creates
//! a separate operational projection without importing execution authority.
//! No validator in this module reads a file, opens storage, or contacts a target.

use crate::domain::{AssessmentCase, EngineRunStatus, Evidence, Finding, SourceConnectionStatus};
use crate::error::{AppError, AppResult};
use crate::orchestrator::{ExecutionCheckpoint, ExecutionStage};
use crate::storage::CaseEvent;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const CASE_SNAPSHOT_SCHEMA: &str = "ai-security-scanner.case-snapshot/v1";

/// Every serialized AssessmentCase field is retained, including source metadata,
/// observations, export history and frozen run context. `storage_revision` is
/// deliberately excluded by the domain's serde contract; the archive manifest
/// records the source revision independently from the restored DB's revision.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableCase {
    pub schema_version: String,
    pub case: AssessmentCase,
    pub source_document_sha256: String,
    pub historical_events: Vec<CaseEvent>,
}

impl PortableCase {
    pub fn validate(&self) -> AppResult<()> {
        if self.schema_version != CASE_SNAPSHOT_SCHEMA {
            return Err(invalid("unsupported portable case schema"));
        }
        sha256(&self.source_document_sha256)?;
        validate_case_graph(&self.case)?;
        let mut previous = 0;
        for event in &self.historical_events {
            if event.case_id != self.case.id || event.sequence <= previous {
                return Err(invalid("case event identity or sequence is invalid"));
            }
            if self.case.agent_audit_admissions.is_empty()
                && event.event_type == crate::agent_audit_admission::ADMITTED_EVENT
            {
                return Err(AppError::NotAvailable(
                    crate::agent_audit_admission::UNAVAILABLE.into(),
                ));
            }
            identifier(&event.event_type)?;
            chrono::DateTime::parse_from_rfc3339(&event.occurred_at)
                .map_err(|_| invalid("case event time is invalid"))?;
            serde_json::from_str::<serde_json::Value>(&event.payload_json)
                .map_err(|_| invalid("case event payload is not JSON"))?;
            previous = event.sequence;
        }
        Ok(())
    }
}

/// Refuse data this core would silently discard or normalize while decoding.
/// Older documents may omit defaulted fields, but every field they do carry
/// must survive at the same location and with the same value. A raw null or
/// empty unknown field is still unsupported data, not permission to drop it.
pub fn validate_original_document(
    original: &serde_json::Value,
    typed: &AssessmentCase,
) -> AppResult<()> {
    crate::agent_audit_admission::check_format(typed)?;
    fn retained(original: &serde_json::Value, canonical: &serde_json::Value) -> bool {
        match (original, canonical) {
            (serde_json::Value::Object(source), serde_json::Value::Object(target)) => source
                .iter()
                .all(|(key, value)| target.get(key).is_some_and(|next| retained(value, next))),
            (serde_json::Value::Array(source), serde_json::Value::Array(target)) => {
                source.len() == target.len()
                    && source.iter().zip(target).all(|(a, b)| retained(a, b))
            }
            _ => original == canonical,
        }
    }
    if !retained(original, &serde_json::to_value(typed)?) {
        return Err(invalid(
            "original case contains fields this core cannot preserve without changing them",
        ));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> AppError {
    AppError::InvalidRequest(format!("case archive: {}", message.into()))
}

fn identifier(id: &str) -> AppResult<()> {
    if id.is_empty() || id != id.trim() || id.len() > 512 || id.chars().any(char::is_control) {
        return Err(invalid("invalid record identifier"));
    }
    Ok(())
}

fn sha256(value: &str) -> AppResult<()> {
    if value.len() != 64 || !value.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid("invalid SHA-256 value"));
    }
    Ok(())
}

fn unique_ids<'a>(
    label: &str,
    values: impl Iterator<Item = &'a str>,
) -> AppResult<BTreeSet<&'a str>> {
    let mut ids = BTreeSet::new();
    for value in values {
        identifier(value)?;
        if !ids.insert(value) {
            return Err(invalid(format!("duplicate {label} identifier")));
        }
    }
    Ok(ids)
}

fn reference(ids: &BTreeSet<&str>, id: &str, label: &str) -> AppResult<()> {
    if !ids.contains(id) {
        return Err(invalid(format!("{label} refers to a missing record")));
    }
    Ok(())
}

fn references<'a>(
    ids: &BTreeSet<&str>,
    values: impl Iterator<Item = &'a str>,
    label: &str,
) -> AppResult<()> {
    for value in unique_ids(label, values)? {
        reference(ids, value, label)?;
    }
    Ok(())
}

fn terminal(status: &EngineRunStatus) -> bool {
    matches!(
        status,
        EngineRunStatus::Completed
            | EngineRunStatus::PartiallyCompleted
            | EngineRunStatus::Failed
            | EngineRunStatus::Cancelled
            | EngineRunStatus::NotExecuted
    )
}

/// Check a complete case graph before capture and again before restore publish.
/// Legacy absent snapshots/provenance remain absent; a present foreign ID is
/// never substituted with a current record. Historical frozen assets can back
/// references after their current presentation has changed.
pub fn validate_case_graph(case: &AssessmentCase) -> AppResult<()> {
    crate::agent_audit_admission::check_format(case)?;
    identifier(&case.id)?;
    let source_ids = unique_ids("source", case.data_sources.iter().map(|s| s.id.as_str()))?;
    let mut asset_ids = unique_ids("asset", case.assets.iter().map(|a| a.id.as_str()))?;
    for run in &case.scan_runs {
        let frozen = unique_ids(
            "frozen asset",
            run.report_asset_snapshots
                .iter()
                .map(|s| s.asset.id.as_str()),
        )?;
        asset_ids.extend(frozen);
    }
    let run_ids = unique_ids("run", case.scan_runs.iter().map(|r| r.id.as_str()))?;
    let task_ids = unique_ids(
        "task",
        case.scan_runs
            .iter()
            .flat_map(|r| r.engine_runs.iter().map(|t| t.id.as_str())),
    )?;
    let tasks = case
        .scan_runs
        .iter()
        .flat_map(|r| r.engine_runs.iter().map(move |t| (t.id.as_str(), (r, t))))
        .collect::<BTreeMap<_, _>>();
    let artifact_ids = unique_ids("artifact", case.raw_artifacts.iter().map(|a| a.id.as_str()))?;
    let artifacts = case
        .raw_artifacts
        .iter()
        .map(|a| (a.id.as_str(), a))
        .collect::<BTreeMap<_, _>>();
    let finding_ids = unique_ids("finding", case.findings.iter().map(|f| f.id.as_str()))?;
    let findings = case
        .findings
        .iter()
        .map(|f| (f.id.as_str(), f))
        .collect::<BTreeMap<_, _>>();
    unique_ids(
        "scope grant",
        case.scope_grants.iter().map(|g| g.id.as_str()),
    )?;
    unique_ids(
        "asset relation",
        case.asset_relations.iter().map(|r| r.id.as_str()),
    )?;
    unique_ids("coverage", case.coverage.iter().map(|c| c.id.as_str()))?;
    unique_ids(
        "observation",
        case.finding_observations.iter().map(|o| o.id.as_str()),
    )?;
    unique_ids(
        "inventory observation",
        case.inventory_observations.iter().map(|o| o.id.as_str()),
    )?;
    unique_ids("group", case.finding_groups.iter().map(|g| g.id.as_str()))?;
    unique_ids(
        "group event",
        case.finding_group_events.iter().map(|e| e.id.as_str()),
    )?;
    unique_ids(
        "workflow event",
        case.finding_workflow_events.iter().map(|e| e.id.as_str()),
    )?;
    unique_ids("comparison", case.comparisons.iter().map(|c| c.id.as_str()))?;
    unique_ids(
        "export",
        case.exports
            .iter()
            .map(|e| e.id.as_str())
            .chain(case.combined_exports.iter().map(|e| e.id.as_str())),
    )?;

    for asset in case.assets.iter().chain(
        case.scan_runs
            .iter()
            .flat_map(|r| r.report_asset_snapshots.iter().map(|s| &s.asset)),
    ) {
        references(
            &source_ids,
            asset.discovered_from.iter().map(String::as_str),
            "asset discovery source",
        )?;
    }
    for grant in &case.scope_grants {
        reference(&asset_ids, &grant.asset_id, "scope grant asset")?;
    }
    for coverage in &case.coverage {
        if let Some(id) = &coverage.asset_id {
            reference(&asset_ids, id, "coverage asset")?;
        }
        if let Some(id) = &coverage.last_run_id {
            reference(&run_ids, id, "coverage run")?;
        }
    }
    let mut sequences = BTreeSet::new();
    for run in &case.scan_runs {
        if run.case_id != case.id || run.sequence == 0 || !sequences.insert(run.sequence) {
            return Err(invalid(
                "run belongs to another case or has a duplicate sequence",
            ));
        }
        if run.completed_at.is_none()
            || (run.engine_runs.is_empty() && !run.is_terminal_no_checks())
            || run.engine_runs.iter().any(|task| !terminal(&task.status))
        {
            return Err(invalid("only terminal scan runs can be archived"));
        }
        if let Some(id) = &run.verification_baseline_run_id {
            reference(&run_ids, id, "verification baseline")?;
            if id == &run.id {
                return Err(invalid("verification baseline is the current run"));
            }
        }
        if let Some(crate::domain::ScanRequestOutcome::NoChecksCompleted {
            requested_asset_ids,
            ..
        }) = &run.request_outcome
        {
            references(
                &asset_ids,
                requested_asset_ids.iter().map(String::as_str),
                "requested asset",
            )?;
        }
        let grants = unique_ids("run grant", run.scope_grant_ids.iter().map(String::as_str))?;
        let frozen_grants = unique_ids(
            "frozen grant",
            run.scope_grant_snapshots.iter().map(|g| g.id.as_str()),
        )?;
        // Empty frozen grants are an explicit legacy absence. Live grants may
        // have been replaced; do not invent a historical grant from today's set.
        if !frozen_grants.is_empty() && grants != frozen_grants {
            return Err(invalid(
                "frozen grants do not match the run's grant identities",
            ));
        }
        for grant in &run.scope_grant_snapshots {
            reference(&asset_ids, &grant.asset_id, "frozen grant asset")?;
        }
        for task in &run.engine_runs {
            if task.scan_run_id != run.id {
                return Err(invalid("task belongs to another scan run"));
            }
            references(
                &asset_ids,
                task.asset_ids.iter().map(String::as_str),
                "task asset",
            )?;
            let task_assets = task
                .asset_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            references(
                &artifact_ids,
                task.raw_artifact_ids.iter().map(String::as_str),
                "task artifact",
            )?;
            for id in &task.raw_artifact_ids {
                let artifact = artifacts[id.as_str()];
                if artifact.run_id != run.id || artifact.engine_run_id != task.id {
                    return Err(invalid("task references another task's artifact"));
                }
            }
            if let Some(ids) = &task.execution_scope_grant_ids {
                references(
                    &grants,
                    ids.iter().map(String::as_str),
                    "task execution grant",
                )?;
            }
            for id in task
                .unevaluated_targets
                .iter()
                .map(|v| &v.asset_id)
                .chain(
                    task.security_template_executions
                        .iter()
                        .map(|v| &v.asset_id),
                )
                .chain(task.manual_review_controls.iter().map(|v| &v.asset_id))
            {
                reference(&task_assets, id, "task coverage asset")?;
            }
            if let Some(token) = &task.resume_token {
                let checkpoint = ExecutionCheckpoint::from_resume_token(token)?;
                if checkpoint.case_id != case.id
                    || checkpoint.scan_run_id != run.id
                    || checkpoint.engine_run_id != task.id
                    || checkpoint.engine_id != task.engine_id
                {
                    return Err(invalid("checkpoint belongs to another execution"));
                }
                if matches!(
                    checkpoint.stage,
                    ExecutionStage::Planned
                        | ExecutionStage::Preflight
                        | ExecutionStage::PullingImage
                        | ExecutionStage::Running
                        | ExecutionStage::CapturingArtifacts
                        | ExecutionStage::CleanupPending
                ) || (!checkpoint.cleanup_completed
                    && (checkpoint.container_name.is_some()
                        || checkpoint.managed_network.is_some()))
                {
                    return Err(invalid(
                        "execution still has a live checkpoint or cleanup obligation",
                    ));
                }
                references(
                    &artifact_ids,
                    checkpoint.artifact_ids.iter().map(String::as_str),
                    "checkpoint artifact",
                )?;
                for id in &checkpoint.artifact_ids {
                    if artifacts[id.as_str()].engine_run_id != task.id {
                        return Err(invalid("checkpoint artifact belongs to another task"));
                    }
                }
            }
            if let Some(plan) = &task.naabu_work_plan {
                if plan.identity.case_id != case.id
                    || plan.identity.scan_run_id != run.id
                    || plan.identity.engine_run_id != task.id
                    || plan.identity.engine_id != task.engine_id
                {
                    return Err(invalid("Naabu work plan belongs to another execution"));
                }
                crate::execution_coverage::reduce_naabu_attempt_coverage(
                    plan,
                    &task.naabu_attempt_requests,
                    &task.naabu_attempt_results,
                )
                .map_err(|_| invalid("Naabu attempt history is invalid"))?;
                for grant in &plan.frozen_grants {
                    if grant.case_id != case.id {
                        return Err(invalid("Naabu grant belongs to another case"));
                    }
                    reference(&task_assets, &grant.asset_id, "Naabu grant asset")?;
                    reference(&grants, &grant.grant_id, "Naabu grant")?;
                }
            } else if !task.naabu_attempt_requests.is_empty()
                || !task.naabu_attempt_results.is_empty()
            {
                return Err(invalid("Naabu attempt history has no frozen work plan"));
            }
            for result in &task.naabu_attempt_results {
                reference(
                    &artifact_ids,
                    &result.journal_raw_artifact_id,
                    "Naabu journal artifact",
                )?;
                if artifacts[result.journal_raw_artifact_id.as_str()].engine_run_id != task.id {
                    return Err(invalid("Naabu journal belongs to another task"));
                }
            }
        }
    }
    let mut artifact_paths = BTreeSet::new();
    for artifact in &case.raw_artifacts {
        if artifact.case_id != case.id {
            return Err(invalid("artifact belongs to another case"));
        }
        reference(&run_ids, &artifact.run_id, "artifact run")?;
        reference(&task_ids, &artifact.engine_run_id, "artifact task")?;
        let (run, task) = tasks[artifact.engine_run_id.as_str()];
        if artifact.run_id != run.id || !task.raw_artifact_ids.contains(&artifact.id) {
            return Err(invalid("artifact is not bound to its owning task"));
        }
        crate::export::validate_portable_archive_path(Path::new(&artifact.relative_path))?;
        let prefix = format!(
            "{}/{}/{}/",
            case.id, artifact.run_id, artifact.engine_run_id
        );
        if !artifact.relative_path.starts_with(&prefix)
            || artifact.relative_path.len() == prefix.len()
        {
            return Err(invalid(
                "raw artifact path is outside its exact case/run/task namespace",
            ));
        }
        if !artifact_paths.insert(artifact.relative_path.to_lowercase()) {
            return Err(invalid("artifact paths collide"));
        }
        sha256(&artifact.sha256)?;
    }
    for path in &artifact_paths {
        for (index, _) in path.match_indices('/') {
            if artifact_paths.contains(&path[..index]) {
                return Err(invalid("artifact file and directory paths collide"));
            }
        }
    }

    let mut evidence_identities = BTreeMap::<String, (String, String, String, String)>::new();
    let mut check_finding = |finding: &Finding, observed_run: Option<&str>| -> AppResult<()> {
        if finding.case_id != case.id {
            return Err(invalid("finding belongs to another case"));
        }
        reference(&run_ids, &finding.first_seen_run_id, "finding first run")?;
        reference(&run_ids, &finding.last_seen_run_id, "finding last run")?;
        references(
            &asset_ids,
            finding.asset_ids.iter().map(String::as_str),
            "finding asset",
        )?;
        unique_ids(
            "finding evidence",
            finding.evidence.iter().map(|e| e.id.as_str()),
        )?;
        for evidence in &finding.evidence {
            validate_evidence(
                case,
                finding,
                evidence,
                observed_run,
                &run_ids,
                &artifacts,
                &tasks,
            )?;
            // The same immutable evidence occurs in the canonical record and
            // multiple frozen projections; only conflicting bindings are invalid.
            let identity = (
                evidence.finding_id.clone(),
                evidence.run_id.clone(),
                evidence.artifact_id.clone(),
                evidence.artifact_sha256.clone(),
            );
            if let Some(previous) =
                evidence_identities.insert(evidence.id.clone(), identity.clone())
                && previous != identity
            {
                return Err(invalid("evidence identity has conflicting bindings"));
            }
        }
        Ok(())
    };
    for finding in &case.findings {
        check_finding(finding, None)?;
    }
    let mut observation_coordinates = BTreeSet::new();
    for observation in &case.finding_observations {
        reference(&run_ids, &observation.run_id, "observation run")?;
        reference(&finding_ids, &observation.finding_id, "observation finding")?;
        if !observation_coordinates.insert((&observation.run_id, &observation.finding_id))
            || observation.fingerprint != findings[observation.finding_id.as_str()].fingerprint
        {
            return Err(invalid("finding observation identity is inconsistent"));
        }
        references(
            &asset_ids,
            observation.asset_ids.iter().map(String::as_str),
            "observation asset",
        )?;
        let run = case
            .scan_runs
            .iter()
            .find(|r| r.id == observation.run_id)
            .expect("run validated");
        let engine_ids = run
            .engine_runs
            .iter()
            .map(|t| t.engine_id.as_str())
            .collect::<BTreeSet<_>>();
        for engine_id in &observation.engine_ids {
            reference(&engine_ids, engine_id, "observation engine")?;
        }
        for hash in &observation.evidence_hashes {
            sha256(hash)?;
        }
        if let Some(snapshot) = &observation.finding_snapshot {
            if snapshot.id != observation.finding_id
                || snapshot.fingerprint != observation.fingerprint
            {
                return Err(invalid(
                    "observation frozen finding has a different identity",
                ));
            }
            check_finding(snapshot, Some(&observation.run_id))?;
            let hashes = snapshot
                .evidence
                .iter()
                .map(|e| e.artifact_sha256.to_ascii_lowercase())
                .collect::<BTreeSet<_>>();
            let expected = observation
                .evidence_hashes
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect::<BTreeSet<_>>();
            if hashes != expected {
                return Err(invalid(
                    "observation evidence hashes do not match its frozen finding",
                ));
            }
        }
    }
    let mut relation_evidence_ids = evidence_identities.keys().cloned().collect::<BTreeSet<_>>();
    relation_evidence_ids.extend(artifact_ids.iter().map(|id| (*id).to_owned()));
    // Discovery relations cite connector captures, not normalized finding
    // evidence. Those source artifacts occupy a separate archive namespace.
    for source in &case.data_sources {
        if let Some(value) = source
            .metadata
            .get(crate::connectors::SNAPSHOT_ARTIFACT_METADATA_KEY)
        {
            let capture: crate::connectors::SnapshotArtifactReference =
                serde_json::from_value(value.clone())
                    .map_err(|_| invalid("connector artifact reference is invalid"))?;
            identifier(&capture.artifact_id)?;
            relation_evidence_ids.insert(capture.artifact_id);
        }
        if let Some(value) = source
            .metadata
            .get(crate::connectors::LIVE_PROVIDER_ARTIFACT_METADATA_KEY)
        {
            let captures: crate::connectors::LiveProviderArtifactSet =
                serde_json::from_value(value.clone())
                    .map_err(|_| invalid("provider artifact references are invalid"))?;
            for page in captures.pages {
                identifier(&page.artifact.artifact_id)?;
                relation_evidence_ids.insert(page.artifact.artifact_id);
            }
        }
    }
    for asset in case
        .assets
        .iter()
        .chain(case.scan_runs.iter().flat_map(|run| {
            run.report_asset_snapshots
                .iter()
                .map(|snapshot| &snapshot.asset)
        }))
    {
        if let Some(id) = asset
            .metadata
            .get("source_artifact_id")
            .and_then(serde_json::Value::as_str)
        {
            identifier(id)?;
            relation_evidence_ids.insert(id.to_owned());
        }
    }
    let relation_evidence_ids = relation_evidence_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for relation in &case.asset_relations {
        reference(&asset_ids, &relation.from_asset_id, "relation source asset")?;
        reference(&asset_ids, &relation.to_asset_id, "relation target asset")?;
        references(
            &relation_evidence_ids,
            relation.evidence_ids.iter().map(String::as_str),
            "relation evidence",
        )?;
    }
    for observation in &case.inventory_observations {
        if observation.case_id != case.id {
            return Err(invalid("inventory observation belongs to another case"));
        }
        reference(&task_ids, &observation.engine_run_id, "inventory task")?;
        let (run, task) = tasks[observation.engine_run_id.as_str()];
        if observation.run_id != run.id
            || observation.engine_id != task.engine_id
            || !task.asset_ids.contains(&observation.asset_id)
        {
            return Err(invalid(
                "inventory observation has a foreign execution or asset",
            ));
        }
        reference(
            &artifact_ids,
            &observation.artifact_id,
            "inventory artifact",
        )?;
        let artifact = artifacts[observation.artifact_id.as_str()];
        if artifact.engine_run_id != task.id
            || !artifact
                .sha256
                .eq_ignore_ascii_case(&observation.artifact_sha256)
        {
            return Err(invalid(
                "inventory observation artifact binding is inconsistent",
            ));
        }
    }
    for group in &case.finding_groups {
        if group.case_id != case.id {
            return Err(invalid("finding group belongs to another case"));
        }
        references(
            &finding_ids,
            group.finding_ids.iter().map(String::as_str),
            "group finding",
        )?;
    }
    for event in &case.finding_group_events {
        if event.case_id != case.id {
            return Err(invalid("group event belongs to another case"));
        }
        identifier(&event.group_id)?;
        // A removed group legitimately exists only in history.
        references(
            &finding_ids,
            event.finding_ids.iter().map(String::as_str),
            "group event finding",
        )?;
    }
    for event in &case.finding_workflow_events {
        if event.case_id != case.id {
            return Err(invalid("workflow event belongs to another case"));
        }
        reference(&finding_ids, &event.finding_id, "workflow finding")?;
    }
    for comparison in &case.comparisons {
        if comparison.case_id != case.id || comparison.baseline_run_id == comparison.current_run_id
        {
            return Err(invalid("comparison case or run identity is inconsistent"));
        }
        reference(&run_ids, &comparison.baseline_run_id, "comparison baseline")?;
        reference(
            &run_ids,
            &comparison.current_run_id,
            "comparison current run",
        )?;
        for diff in &comparison.diffs {
            for (id, run_id) in [
                (&diff.baseline_finding_id, &comparison.baseline_run_id),
                (&diff.current_finding_id, &comparison.current_run_id),
            ] {
                if let Some(id) = id {
                    reference(&finding_ids, id, "comparison finding")?;
                    if !case.finding_observations.iter().any(|o| {
                        o.run_id == *run_id
                            && o.finding_id == *id
                            && o.fingerprint == diff.fingerprint
                    }) {
                        return Err(invalid(
                            "comparison finding was not observed in its stated run",
                        ));
                    }
                }
            }
            for reason in &diff.reasons {
                if let Some(id) = &reason.asset_id {
                    reference(&asset_ids, id, "comparison reason asset")?;
                }
            }
        }
        for reason in &comparison.completeness_issues {
            if let Some(id) = &reason.asset_id {
                reference(&asset_ids, id, "comparison coverage asset")?;
            }
        }
        for change in &comparison.local_input_changes {
            reference(&asset_ids, &change.asset_id, "comparison local input asset")?;
            sha256(&change.baseline_sha256)?;
            sha256(&change.current_sha256)?;
        }
    }
    let mut terminal_snapshots = BTreeSet::new();
    for record in &case.run_report_snapshots {
        reference(&run_ids, &record.run_id, "terminal snapshot run")?;
        sha256(&record.run_sha256)?;
        record.snapshot.validate(&case.id)?;
        if !terminal_snapshots.insert((&record.run_id, &record.run_sha256)) {
            return Err(invalid("duplicate terminal snapshot outcome"));
        }
    }
    for export in &case.combined_exports {
        if export.case_id != case.id {
            return Err(invalid("combined export belongs to another case"));
        }
        crate::report_snapshot::validate_combined_run_ids(&export.selected_run_ids)?;
        for run_id in &export.selected_run_ids {
            reference(&run_ids, run_id, "combined export run")?;
        }
        if let Some(archive) = &export.attachment_archive {
            sha256(&archive.sha256)?;
            if archive.byte_length == 0
                || export.original_files.as_ref().is_none_or(|summary| {
                    summary.omitted_files == 0 || summary.archive_file_name.is_none()
                })
            {
                return Err(invalid(
                    "combined attachment archive has no matching omissions",
                ));
            }
        }
        if export
            .original_files
            .as_ref()
            .is_some_and(|summary| summary.omitted_files > 0)
            && export.attachment_archive.is_none()
        {
            return Err(invalid(
                "combined omitted originals have no retained archive receipt",
            ));
        }
        sha256(&export.sha256)?;
        if let Some(snapshot) = &export.report_snapshot {
            snapshot.validate(&case.id)?;
        }
    }
    for export in &case.exports {
        if export.case_id != case.id {
            return Err(invalid("export belongs to another case"));
        }
        reference(&run_ids, &export.run_id, "export run")?;
        sha256(&export.sha256)?;
        if let Some(snapshot) = &export.report_snapshot {
            snapshot.validate(&case.id)?;
        }
        if let Some(hash) = &export.coverage_manifest_sha256 {
            sha256(hash)?;
        }
    }
    Ok(())
}

fn validate_evidence(
    case: &AssessmentCase,
    finding: &Finding,
    evidence: &Evidence,
    observed_run: Option<&str>,
    run_ids: &BTreeSet<&str>,
    artifacts: &BTreeMap<&str, &crate::domain::RawArtifact>,
    tasks: &BTreeMap<&str, (&crate::domain::ScanRun, &crate::domain::EngineRun)>,
) -> AppResult<()> {
    if evidence.finding_id != finding.id || observed_run.is_some_and(|run| evidence.run_id != run) {
        return Err(invalid(
            "evidence belongs to another finding or observation run",
        ));
    }
    reference(run_ids, &evidence.run_id, "evidence run")?;
    let artifact = artifacts
        .get(evidence.artifact_id.as_str())
        .ok_or_else(|| invalid("evidence artifact is missing"))?;
    if artifact.case_id != case.id
        || artifact.run_id != evidence.run_id
        || !artifact
            .sha256
            .eq_ignore_ascii_case(&evidence.artifact_sha256)
    {
        return Err(invalid("evidence artifact binding is inconsistent"));
    }
    let (_, task) = tasks[artifact.engine_run_id.as_str()];
    if evidence
        .engine_run_id
        .as_ref()
        .is_some_and(|id| id != &task.id)
        || evidence.engine_id != task.engine_id
    {
        return Err(invalid("evidence belongs to another engine task"));
    }
    Ok(())
}

/// Operational fields removed from the restored projection. Original source
/// metadata remains intact in PortableCase for provenance and later review.
const EXECUTION_METADATA_KEYS: &[&str] = &[
    "ai_security_scanner.workspace_snapshot_reference",
    "ai_security_scanner.canonical_connector_artifact",
    "ai_security_scanner.live_provider_artifact_set",
    "provider_profile",
    "provider_identity",
    "provider_resource_scope",
    "verification_evidence_sha256",
    "authorization",
    "authorization_reference",
    "authorization_context",
    "credential_reference",
    "credential_ref",
    "credentials",
    "access_token",
    "refresh_token",
    "token",
    "local_path",
    "source_path",
    "path",
    "working_directory",
    "repository_path",
    "snapshot_path",
];

/// Build an inert, new-workspace projection. Preserve outcomes, frozen grants,
/// snapshots, findings, evidence, coverage and workflow history without edits.
/// The archive restore receipt must name these authority/path transformations;
/// this function never rewrites the original PortableCase document.
pub fn restored_case(original: &AssessmentCase) -> AppResult<AssessmentCase> {
    restored_case_with_provider(original, None)
}

pub(crate) fn restored_case_with_provider(
    original: &AssessmentCase,
    provider: Option<&crate::case_archive::VerifiedProviderHistory>,
) -> AppResult<AssessmentCase> {
    crate::case_archive::check_restore_case(original, provider)?;
    validate_case_graph(original)?;
    let mut case = original.clone();
    case.storage_revision = 0;
    case.scope_grants.clear();
    for source in &mut case.data_sources {
        if source.status != SourceConnectionStatus::NotApplicable {
            source.status = SourceConnectionStatus::NotConnected;
        }
        source.connected_at = None;
        for key in EXECUTION_METADATA_KEYS {
            source.metadata.remove(*key);
        }
    }
    for asset in &mut case.assets {
        asset.owner_confirmed = false;
        for key in EXECUTION_METADATA_KEYS {
            asset.metadata.remove(*key);
        }
    }
    for run in &mut case.scan_runs {
        for task in &mut run.engine_runs {
            task.resume_token = None;
        }
    }
    // Export history remains, but a foreign host's absolute path must never
    // become an implicit local file read. Restore can rebind verified blobs.
    for export in &mut case.combined_exports {
        if let Some(archive) = &mut export.attachment_archive {
            archive.path.clear();
        }
        export.path.clear();
    }
    for export in &mut case.exports {
        export.path.clear();
        export.coverage_manifest_path = None;
    }
    validate_case_graph(&case)?;
    Ok(case)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn demo() -> AssessmentCase {
        let mut case = crate::demo::build_demo_case();
        // The built-in synthetic demo never writes files and uses display-only
        // raw paths. This archive fixture places them in the real store's
        // case/run/task namespace, without changing evidence identities.
        for artifact in &mut case.raw_artifacts {
            artifact.relative_path = format!(
                "{}/{}/{}/{}",
                case.id, artifact.run_id, artifact.engine_run_id, artifact.relative_path,
            );
        }
        case
    }

    fn baseline(mixed: bool) -> AssessmentCase {
        let bytes: &[u8] = if mixed {
            include_bytes!("../../tests/fixtures/report-fidelity/mixed-terminal/case.json.gz")
        } else {
            include_bytes!("../../tests/fixtures/report-fidelity/all-detectors/case.json.gz")
        };
        let mut decoder = flate2::read::GzDecoder::new(bytes);
        let mut document = Vec::new();
        decoder.read_to_end(&mut document).unwrap();
        serde_json::from_slice(&document).unwrap()
    }

    #[test]
    fn demo_and_fixed_real_adapter_case_graphs_are_preserved() {
        for case in [demo(), baseline(false), baseline(true)] {
            validate_case_graph(&case).unwrap();
            let original = serde_json::to_value(&case).unwrap();
            let restored = restored_case(&case).unwrap();
            validate_case_graph(&restored).unwrap();
            assert_eq!(serde_json::to_value(&case).unwrap(), original);
            let restored_json = serde_json::to_value(&restored).unwrap();
            for field in [
                "title",
                "profile",
                "assessment_intent",
                "ai_generated_artifact",
                "requested_activities",
                "asset_relations",
                "coverage",
                "findings",
                "finding_groups",
                "finding_group_events",
                "finding_workflow_events",
                "finding_observations",
                "inventory_observations",
                "raw_artifacts",
                "comparisons",
            ] {
                assert_eq!(
                    restored_json[field], original[field],
                    "preserved field: {field}"
                );
            }
            for (before, after) in case.scan_runs.iter().zip(&restored.scan_runs) {
                assert_eq!(
                    serde_json::to_value(&before.report_asset_snapshots).unwrap(),
                    serde_json::to_value(&after.report_asset_snapshots).unwrap()
                );
                assert_eq!(
                    serde_json::to_value(&before.scope_grant_snapshots).unwrap(),
                    serde_json::to_value(&after.scope_grant_snapshots).unwrap()
                );
                for (before, after) in before.engine_runs.iter().zip(&after.engine_runs) {
                    assert_eq!(before.status, after.status);
                    assert!(after.resume_token.is_none());
                }
            }
            assert!(restored.scope_grants.is_empty());
            assert!(restored.assets.iter().all(|asset| !asset.owner_confirmed));
            assert!(restored.data_sources.iter().all(|source| matches!(
                source.status,
                SourceConnectionStatus::NotConnected | SourceConnectionStatus::NotApplicable
            )));
        }
    }

    #[test]
    fn portable_case_round_trip_keeps_every_serialized_domain_field_and_events() {
        let mut case = baseline(true);
        case.storage_revision = 42;
        let payload = serde_json::to_value(&case).unwrap();
        let portable = PortableCase {
            schema_version: CASE_SNAPSHOT_SCHEMA.into(),
            source_document_sha256: "a".repeat(64),
            historical_events: vec![CaseEvent {
                sequence: 7,
                case_id: case.id.clone(),
                event_type: "archive.fixture".into(),
                occurred_at: "2026-11-08T12:00:00Z".into(),
                payload_json: "{\"status\":\"completed\"}".into(),
            }],
            case,
        };
        portable.validate().unwrap();
        let restored: PortableCase =
            serde_json::from_slice(&serde_json::to_vec(&portable).unwrap()).unwrap();
        restored.validate().unwrap();
        assert_eq!(serde_json::to_value(&restored.case).unwrap(), payload);
        assert_eq!(restored.historical_events, portable.historical_events);
        assert_eq!(restored.case.storage_revision, 0);
        assert!(payload.get("storage_revision").is_none());
    }

    #[test]
    fn legacy_absence_is_not_replaced_with_current_context() {
        let mut case = demo();
        for run in &mut case.scan_runs {
            run.scope_grant_snapshots.clear();
            run.report_asset_snapshots.clear();
        }
        for observation in &mut case.finding_observations {
            observation.finding_snapshot = None;
        }
        for finding in &mut case.findings {
            for evidence in &mut finding.evidence {
                evidence.engine_run_id = None;
            }
        }
        validate_case_graph(&case).unwrap();
        let restored = restored_case(&case).unwrap();
        assert!(restored.scan_runs.iter().all(
            |run| run.scope_grant_snapshots.is_empty() && run.report_asset_snapshots.is_empty()
        ));
        assert!(
            restored
                .finding_observations
                .iter()
                .all(|observation| observation.finding_snapshot.is_none())
        );
    }

    #[test]
    fn duplicate_and_foreign_graph_references_are_rejected() {
        let mutations: &[fn(&mut AssessmentCase)] = &[
            |case| case.assets.push(case.assets[0].clone()),
            |case| case.scan_runs[0].case_id = "foreign-case".into(),
            |case| case.scan_runs[0].engine_runs[0].scan_run_id = "foreign-run".into(),
            |case| {
                case.scan_runs[0].engine_runs[0]
                    .asset_ids
                    .push("foreign-asset".into())
            },
            |case| case.raw_artifacts[0].engine_run_id = "foreign-task".into(),
            |case| case.findings[0].evidence[0].artifact_sha256 = "b".repeat(64),
            |case| case.finding_observations[0].finding_id = "foreign-finding".into(),
            |case| {
                case.finding_groups[0]
                    .finding_ids
                    .push("foreign-finding".into())
            },
            |case| case.finding_group_events[0].case_id = "foreign-case".into(),
        ];
        for mutation in mutations {
            let mut case = demo();
            mutation(&mut case);
            assert!(validate_case_graph(&case).is_err());
        }
    }

    #[test]
    fn active_runs_and_runtime_cleanup_obligations_are_not_portable() {
        let mut case = baseline(false);
        case.scan_runs[0].completed_at = None;
        assert!(validate_case_graph(&case).is_err());
        let mut case = baseline(false);
        case.scan_runs[0].engine_runs[0].status = EngineRunStatus::Paused;
        assert!(validate_case_graph(&case).is_err());
        let mut case = baseline(false);
        let task = &mut case.scan_runs[0].engine_runs[0];
        let mut checkpoint =
            ExecutionCheckpoint::from_resume_token(task.resume_token.as_deref().unwrap()).unwrap();
        checkpoint.stage = ExecutionStage::CleanupPending;
        checkpoint.cleanup_completed = false;
        // Keep the valid fixed runtime identity; only its lifecycle changes.
        task.resume_token = Some(serde_json::to_string(&checkpoint).unwrap());
        assert!(validate_case_graph(&case).is_err());
    }

    #[test]
    fn restore_revokes_source_capabilities_without_mutating_originals() {
        let mut case = baseline(false);
        let original_tokens = case
            .scan_runs
            .iter()
            .flat_map(|run| &run.engine_runs)
            .filter(|task| task.resume_token.is_some())
            .count();
        assert!(original_tokens > 0);
        case.data_sources[0].metadata.insert(
            "credential_reference".into(),
            serde_json::json!("opaque-foreign-reference"),
        );
        case.assets[0].metadata.insert(
            "source_path".into(),
            serde_json::json!("/foreign/working-tree"),
        );
        let restored = restored_case(&case).unwrap();
        assert!(
            case.data_sources[0]
                .metadata
                .contains_key("credential_reference")
        );
        assert!(
            !restored.data_sources[0]
                .metadata
                .contains_key("credential_reference")
        );
        assert!(!restored.assets[0].metadata.contains_key("source_path"));
        for source in &restored.data_sources {
            assert!(source.connected_at.is_none());
            for key in EXECUTION_METADATA_KEYS {
                assert!(!source.metadata.contains_key(*key));
            }
        }
        assert!(
            restored
                .exports
                .iter()
                .all(|export| export.path.is_empty() && export.coverage_manifest_path.is_none())
        );
    }

    #[test]
    fn invalid_event_order_and_unknown_portable_schema_are_rejected() {
        let case = demo();
        let event = CaseEvent {
            sequence: 1,
            case_id: case.id.clone(),
            event_type: "fixture".into(),
            occurred_at: "2026-11-08T12:00:00Z".into(),
            payload_json: "{}".into(),
        };
        let mut portable = PortableCase {
            schema_version: CASE_SNAPSHOT_SCHEMA.into(),
            case,
            source_document_sha256: "a".repeat(64),
            historical_events: vec![event.clone(), event],
        };
        assert!(portable.validate().is_err());
        portable.historical_events.clear();
        portable.schema_version = "future/v99".into();
        assert!(portable.validate().is_err());
    }

    #[test]
    fn original_case_rejects_unknown_nested_data_and_normalized_values() {
        let case = demo();
        let original = serde_json::to_value(&case).unwrap();
        validate_original_document(&original, &case).unwrap();
        for unsupported in [
            serde_json::Value::Null,
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            let mut raw = original.clone();
            raw["scan_runs"][0]["engine_runs"][0]["future_provider_context"] = unsupported;
            let decoded: AssessmentCase = serde_json::from_value(raw.clone()).unwrap();
            assert!(validate_original_document(&raw, &decoded).is_err());
        }
        let mut raw = original.clone();
        raw["findings"][0]["status"] = serde_json::json!("closed");
        let decoded: AssessmentCase = serde_json::from_value(raw.clone()).unwrap();
        assert!(validate_original_document(&raw, &decoded).is_err());
        let mut legacy = original;
        legacy.as_object_mut().unwrap().remove("assessment_intent");
        legacy
            .as_object_mut()
            .unwrap()
            .remove("requested_activities");
        let decoded: AssessmentCase = serde_json::from_value(legacy.clone()).unwrap();
        validate_original_document(&legacy, &decoded).unwrap();
    }

    #[test]
    fn raw_artifact_cannot_select_another_cases_blob_path() {
        let mut case = demo();
        case.raw_artifacts[0].relative_path =
            "another-case/another-run/another-task/output.json".into();
        assert!(validate_case_graph(&case).is_err());
    }
}
