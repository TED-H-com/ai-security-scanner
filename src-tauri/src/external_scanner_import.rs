//! Offline evidence ingestion, deliberately separate from the execution catalog.
//! Nothing here invokes a scanner, builds source, follows a URL, or executes a PoC.
use crate::artifact_store::{ArtifactContext, ArtifactStore};
use crate::domain::*;
use crate::error::{AppError, AppResult};
use crate::storage::Storage;
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAX_REPORT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FINDINGS: usize = 1_000;
const MAX_IMPORTS: usize = 16;
const IMPORT_CONCURRENCY: usize = 2;
const SOURCE_FORMAT: &str = "strix-vulnerabilities-json/v1";
const ADAPTER_VERSION: &str = "external-report-import/v1";
/// Frozen report provenance only; never interpreted as an asset identifier or grant.
pub(crate) const IMPORT_TARGET_TAG_PREFIX: &str = "external-report-target:";

pub(crate) fn imported_report_target(finding: &Finding) -> Option<&str> {
    finding
        .tags
        .iter()
        .any(|tag| tag == "external-report")
        .then_some(())?;
    finding
        .tags
        .iter()
        .find_map(|tag| tag.strip_prefix(IMPORT_TARGET_TAG_PREFIX))
        .filter(|target| !target.is_empty())
}

pub(crate) fn legacy_import_missing_target(finding: &Finding) -> bool {
    finding.tags.iter().any(|tag| tag == "external-report")
        && imported_report_target(finding).is_none()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalScannerImportRequest {
    pub report_path: PathBuf,
    pub asset_id: String,
    /// Exact upstream target explicitly associated with the selected asset.
    /// This association grants no permission to scan that target.
    pub upstream_target: String,
    /// Commitment returned by preview; prevents a different report being imported
    /// after the user reviewed its targets.
    pub source_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalScannerImportPreview {
    pub engine_id: String,
    pub source_format: String,
    pub source_sha256: String,
    pub targets: Vec<String>,
    pub finding_count: usize,
}

struct ParsedReport {
    bytes: Vec<u8>,
    rows: Vec<Value>,
    sha256: String,
    targets: BTreeSet<String>,
}

fn invalid(message: &str) -> AppError {
    AppError::InvalidRequest(message.into())
}

fn parse_timestamp(value: &str) -> AppResult<DateTime<Utc>> {
    // Native ReportState.add_vulnerability_report uses this UTC spelling.
    // RFC 3339 is accepted for older/converted retained reports too.
    NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S UTC")
        .map(|date| date.and_utc())
        .or_else(|_| DateTime::parse_from_rfc3339(value).map(|date| date.with_timezone(&Utc)))
        .map_err(|_| invalid("A Strix finding has an invalid timestamp."))
}

fn exact_text<'a>(row: &'a Value, key: &str, maximum: usize) -> AppResult<&'a str> {
    row.get(key)
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.trim() == *value
                && value.len() <= maximum
                && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            invalid(
                "The Strix report has a missing or invalid identity, target, title, or timestamp.",
            )
        })
}

fn read_regular_file(path: &Path, maximum_bytes: u64) -> AppResult<Vec<u8>> {
    // A single explicitly selected regular file. Never traverse the report
    // directory, read agent transcripts, or dereference linked attachments.
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| invalid("The selected report could not be read."))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum_bytes {
        return Err(invalid(
            "Select a regular file within the supported size limit.",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("Linked report files are not supported."));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options
        .open(path)
        .map_err(|_| invalid("The selected report could not be opened safely."))?;
    let held_metadata = file.metadata()?;
    if !held_metadata.is_file() || held_metadata.len() > maximum_bytes {
        return Err(invalid("The selected report changed while it was opened."));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if held_metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("Linked report files are not supported."));
        }
    }
    let mut bytes = Vec::new();
    file.take(maximum_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(invalid(
            "The selected file exceeds its supported size limit.",
        ));
    }
    Ok(bytes)
}

fn read_report(path: &Path) -> AppResult<ParsedReport> {
    let bytes = read_regular_file(path, MAX_REPORT_BYTES)?;
    // serde_json's default depth limit remains enabled. A byte limit also
    // bounds strings, record counts, nested values, and parser allocations.
    let rows: Vec<Value> = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("Select Strix's native vulnerabilities.json array."))?;
    if rows.len() > MAX_FINDINGS {
        return Err(invalid("The selected report exceeds 1,000 findings."));
    }
    let mut ids = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for row in &rows {
        let id = exact_text(row, "id", 128)?;
        if !ids.insert(id.to_owned()) {
            return Err(invalid("The report repeats an upstream finding ID."));
        }
        exact_text(row, "title", 2_048)?;
        let target = exact_text(row, "target", 2_048)?;
        if let Ok(url) = url::Url::parse(target)
            && (!url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some())
        {
            return Err(invalid(
                "Report targets must not contain credentials, queries, or fragments.",
            ));
        }
        parse_timestamp(exact_text(row, "timestamp", 128)?)?;
        targets.insert(target.to_owned());
    }
    Ok(ParsedReport {
        sha256: hex::encode(Sha256::digest(&bytes)),
        bytes,
        rows,
        targets,
    })
}

/// Machine orchestration uses an explicit local manifest, with no commands or
/// credentials. Paths remain exact caller-selected paths, never URL fetches.
pub fn read_import_manifest(path: &Path) -> AppResult<Vec<ExternalScannerImportRequest>> {
    let bytes = read_regular_file(path, 128 * 1024)?;
    let requests: Vec<ExternalScannerImportRequest> =
        serde_json::from_slice(&bytes).map_err(|_| {
            invalid("Select an import manifest containing report/asset/target/hash bindings.")
        })?;
    if requests.is_empty() || requests.len() > MAX_IMPORTS {
        return Err(invalid("Select between one and sixteen report bindings."));
    }
    Ok(requests)
}

pub fn preview_external_scanner_import(path: &Path) -> AppResult<ExternalScannerImportPreview> {
    let report = read_report(path)?;
    Ok(ExternalScannerImportPreview {
        engine_id: "strix".into(),
        source_format: SOURCE_FORMAT.into(),
        source_sha256: report.sha256,
        targets: report.targets.into_iter().collect(),
        finding_count: report.rows.len(),
    })
}

/// At most two bounded file readers run concurrently. Preserve request order
/// and isolate each report's failure; parsing never mutates durable state.
fn read_reports(requests: &[ExternalScannerImportRequest]) -> Vec<AppResult<ParsedReport>> {
    let mut results = Vec::with_capacity(requests.len());
    for batch in requests.chunks(IMPORT_CONCURRENCY) {
        std::thread::scope(|scope| {
            let handles: Vec<_> = batch
                .iter()
                .map(|request| {
                    scope.spawn(move || {
                        let report = read_report(&request.report_path)?;
                        if report.sha256 != request.source_sha256 {
                            return Err(invalid(
                                "The report changed after preview. Select it again.",
                            ));
                        }
                        if !report.targets.contains(&request.upstream_target) {
                            return Err(invalid(
                                "The selected upstream target is absent from this report.",
                            ));
                        }
                        Ok(report)
                    })
                })
                .collect();
            for handle in handles {
                results.push(
                    handle
                        .join()
                        .unwrap_or_else(|_| Err(invalid("The report reader could not finish."))),
                );
            }
        });
    }
    results
}

pub fn import_external_scanner_reports(
    storage: &Storage,
    artifact_root: &Path,
    case_id: &str,
    requests: &[ExternalScannerImportRequest],
) -> AppResult<AssessmentCase> {
    if requests.is_empty() || requests.len() > MAX_IMPORTS {
        return Err(invalid("Select between one and sixteen reports."));
    }
    let mut case = storage.get_case(case_id)?;
    if case.status == CaseStatus::Archived
        || case.scan_runs.iter().any(|run| run.completed_at.is_none())
    {
        return Err(invalid(
            "Finish the active scan and use an open project before importing reports.",
        ));
    }
    let mut bindings = BTreeSet::new();
    for request in requests {
        if !case.assets.iter().any(|asset| asset.id == request.asset_id)
            || request.source_sha256.len() != 64
            || !request
                .source_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || !bindings.insert((
                request.asset_id.clone(),
                request.source_sha256.clone(),
                request.upstream_target.clone(),
            ))
        {
            return Err(invalid(
                "Every import needs one existing asset and one distinct previewed report target.",
            ));
        }
    }
    let results = read_reports(requests);
    let now = Utc::now();
    let run_id = new_id();
    let selected_ids: BTreeSet<_> = requests.iter().map(|request| &request.asset_id).collect();
    let mut run = ScanRun {
        id: run_id.clone(),
        case_id: case.id.clone(),
        sequence: case
            .scan_runs
            .iter()
            .map(|run| run.sequence)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| invalid("This project has too many saved runs."))?,
        created_at: now,
        completed_at: Some(now),
        request_outcome: None,
        report_asset_snapshots: case
            .assets
            .iter()
            .filter(|asset| selected_ids.contains(&asset.id))
            .map(|asset| ReportAssetSnapshot {
                asset: asset.clone(),
                disposition: ReportAssetDisposition::RequestedForScan,
            })
            .collect(),
        knowledge_cutoff: now,
        ai_system_applicable: false,
        ai_system_applicability: AiSystemApplicabilityAnswer::Unknown,
        ai_generated_artifact: case.ai_generated_artifact,
        verification_baseline_run_id: None,
        scope_grant_ids: vec![],
        scope_grant_snapshots: vec![],
        engine_admission_issues: vec![],
        engine_runs: vec![],
        campaign_id: None,
    };
    let store = ArtifactStore::open(artifact_root)?;
    for (request, result) in requests.iter().zip(results) {
        let mut task = import_task(&run_id, request, now);
        let result = result.and_then(|report| {
            persist_report(&store, &case.id, &run_id, &task.id, request, report)
        });
        match result {
            Err(error) => {
                task.status = EngineRunStatus::Failed;
                task.phase = "External report import failed".into();
                task.error_code = Some("external_report_import_failed".into());
                task.error_message = Some(error.to_string());
            }
            Ok((artifact, findings)) => {
                task.raw_artifact_ids.push(artifact.id.clone());
                for mut finding in findings {
                    let existing = case
                        .findings
                        .iter()
                        .position(|previous| previous.fingerprint == finding.fingerprint);
                    if let Some(position) = existing {
                        let previous = &case.findings[position];
                        finding.id = previous.id.clone();
                        finding.first_seen_run_id = previous.first_seen_run_id.clone();
                        finding.status = previous.status.clone();
                        for evidence in &mut finding.evidence {
                            evidence.finding_id = finding.id.clone();
                        }
                    }
                    case.finding_observations.push(FindingObservation {
                        id: new_id(),
                        run_id: run_id.clone(),
                        finding_id: finding.id.clone(),
                        fingerprint: finding.fingerprint.clone(),
                        asset_ids: finding.asset_ids.clone(),
                        engine_ids: vec!["strix".into()],
                        severity: finding.severity.clone(),
                        confidence: finding.confidence.clone(),
                        evidence_hashes: vec![artifact.sha256.clone()],
                        observed_at: finding.evidence[0].observed_at,
                        finding_snapshot: Some(finding.clone()),
                    });
                    if let Some(position) = existing {
                        case.findings[position] = finding;
                    } else {
                        case.findings.push(finding);
                    }
                }
                case.raw_artifacts.push(artifact);
            }
        }
        run.engine_runs.push(task);
    }
    case.scan_runs.push(run);
    case.status = CaseStatus::NeedsAttention;
    case.updated_at = now;
    storage.save_case(&mut case, "external_scanner_reports_imported")?;
    Ok(case)
}

fn persist_report(
    store: &ArtifactStore,
    case_id: &str,
    run_id: &str,
    task_id: &str,
    request: &ExternalScannerImportRequest,
    report: ParsedReport,
) -> AppResult<(RawArtifact, Vec<Finding>)> {
    let context = ArtifactContext {
        case_id: case_id.into(),
        scan_run_id: run_id.into(),
        engine_run_id: task_id.into(),
    };
    let directories = store.prepare_run(&context, 1)?;
    let path = directories.output.join("vulnerabilities.json");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&path)?;
    output.write_all(&report.bytes)?;
    output.sync_all()?;
    let artifact = store.describe_file(&context, &path, "application/json", true)?;
    let findings = report
        .rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row["target"].as_str() == Some(request.upstream_target.as_str()))
        .map(|(index, row)| {
            normalize_finding(case_id, run_id, task_id, request, row, index, &artifact)
        })
        .collect::<AppResult<Vec<_>>>()?;
    Ok((artifact, findings))
}

fn import_task(
    run_id: &str,
    request: &ExternalScannerImportRequest,
    now: DateTime<Utc>,
) -> EngineRun {
    EngineRun {
        id: new_id(),
        scan_run_id: run_id.into(),
        engine_id: "strix".into(),
        task_kind: EngineTaskKind::ExternalReportImport {
            source_format: SOURCE_FORMAT.into(),
            source_sha256: request.source_sha256.clone(),
        },
        localhost_tcp_observation: None,
        asset_ids: vec![request.asset_id.clone()],
        status: EngineRunStatus::PartiallyCompleted,
        progress_percent: 100,
        phase: "Imported external findings".into(),
        started_at: None,
        finished_at: Some(now),
        resume_token: None,
        last_execution_report_sha256: Some(request.source_sha256.clone()),
        engine_version: None,
        reported_version: None,
        image_digest: None,
        rule_version: None,
        adapter_version: ADAPTER_VERSION.into(),
        manifest_schema_version: None,
        source_revision: None,
        repository_url: Some("https://github.com/usestrix/strix".into()),
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
        fingerprint_schema_version: Some(ADAPTER_VERSION.into()),
        runtime_provider: None,
        runtime_version: None,
        runtime_security_options: None,
        exit_code: None,
        cleanup_removed: None,
        cleanup_detail: None,
        gateway_refusals: None,
        warnings: vec![
            "External findings imported; original scan coverage and execution were not verified."
                .into(),
        ],
        unattributed: vec![],
        unevaluated_targets: vec![],
        security_template_executions: vec![],
        manual_review_controls: vec![],
        raw_artifact_ids: vec![],
        error_code: Some("external_report_coverage_unverified".into()),
        error_message: None,
    }
}

fn display_text(value: Option<&Value>, maximum: usize) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(|text| {
            text.chars()
                .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\t'))
                .take(maximum)
                .collect::<String>()
        })
        .filter(|text| !text.trim().is_empty())
}

fn normalize_finding(
    case_id: &str,
    run_id: &str,
    task_id: &str,
    request: &ExternalScannerImportRequest,
    row: &Value,
    index: usize,
    artifact: &RawArtifact,
) -> AppResult<Finding> {
    let source_rule = exact_text(row, "id", 128)?;
    let pointer = format!("/{index}");
    // External finding IDs are run-local. Bind to report bytes rather than
    // inventing cross-run identity for model-generated title/ID coordinates.
    let fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&(
        ADAPTER_VERSION,
        &request.asset_id,
        &request.source_sha256,
        source_rule,
    ))?));
    let id = new_id();
    let severity = match row["severity"].as_str() {
        Some("critical") => Severity::Critical,
        Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        Some("info" | "informational") => Severity::Informational,
        _ => Severity::Unknown,
    };
    let confidence = match row["confidence"].as_str() {
        Some("high") => Confidence::High,
        Some("medium") => Confidence::Medium,
        Some("low") => Confidence::Low,
        _ => Confidence::Unknown,
    };
    let observed_at = parse_timestamp(exact_text(row, "timestamp", 128)?)?;
    let cwe_ids = row["cwe"]
        .as_str()
        .filter(|value| {
            value.strip_prefix("CWE-").is_some_and(|digits| {
                !digits.is_empty()
                    && digits.len() <= 8
                    && digits.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
        .map(|value| vec![value.into()])
        .unwrap_or_default();
    let cvss = row
        .get("cvss")
        .filter(|value| {
            value
                .as_f64()
                .is_some_and(|score| (0.0..=10.0).contains(&score))
        })
        .map(|value| {
            vec![CvssScore {
                version: "3.1".into(),
                vector: None,
                base_score: value.to_string(),
                source: "strix".into(),
            }]
        })
        .unwrap_or_default();
    let advisory_aliases = row["cve"]
        .as_str()
        .filter(|value| {
            let parts: Vec<_> = value.split('-').collect();
            parts.len() == 3
                && parts[0] == "CVE"
                && parts[1].len() == 4
                && parts[2].len() >= 4
                && parts[2].len() <= 12
                && parts[1]
                    .bytes()
                    .chain(parts[2].bytes())
                    .all(|byte| byte.is_ascii_digit())
        })
        .map(|value| vec![value.to_owned()])
        .unwrap_or_default();
    let location = row["code_locations"]
        .as_array()
        .and_then(|locations| locations.first())
        .and_then(|location| {
            let file = location["file"].as_str()?;
            let line = location["start_line"].as_u64().filter(|line| *line > 0)?;
            if file.len() > 1_024 || file.chars().any(char::is_control) {
                return None;
            }
            Some(format!("{file}:{line}"))
        });
    let details = ScannerFindingDetails {
        description: display_text(row.get("description"), 4_096),
        remediation: display_text(row.get("remediation_steps"), 4_096),
        installed_version: None,
        fixed_version: None,
        aws_iam_policy: None,
        cwe_ids,
        cvss,
        benchmarks: vec![],
        advisory_aliases,
    };
    let pointer_hash = hex::encode(Sha256::digest(pointer.as_bytes()));
    let evidence_id = crate::adapters::stable_evidence_id(
        &fingerprint,
        "strix",
        source_rule,
        &artifact.sha256,
        &pointer_hash,
        task_id,
    );
    let title = exact_text(row, "title", 2_048)?.to_owned();
    let priority = match severity {
        Severity::Critical => 90,
        Severity::High => 75,
        Severity::Medium => 50,
        Severity::Low => 25,
        Severity::Informational => 10,
        Severity::Unknown => 0,
    };
    Ok(Finding {
        id: id.clone(), case_id: case_id.into(), first_seen_run_id: run_id.into(), last_seen_run_id: run_id.into(),
        fingerprint, title: title.clone(), plain_language_summary: format!("Strix reported: {title}"),
        possible_impact: display_text(row.get("impact"), 2_048).unwrap_or_else(|| "Review the imported evidence to assess the impact.".into()),
        severity, confidence, priority, priority_reasons: vec!["Upstream severity retained from an external report.".into()],
        asset_ids: vec![request.asset_id.clone()],
        evidence: vec![Evidence {
            id: evidence_id, finding_id: id, run_id: run_id.into(), engine_run_id: Some(task_id.into()),
            kind: EvidenceKind::RawToolOutput, engine_id: "strix".into(), scanner_details: Some(details),
            source_rule: Some(source_rule.into()), result_pointer_sha256: Some(pointer_hash),
            observed_at, summary: "Imported Strix finding; original proof-of-concept remains an inert evidence attachment.".into(),
            location, artifact_id: artifact.id.clone(), artifact_sha256: artifact.sha256.clone(), pointer: Some(pointer), redacted: true,
        }],
        control_references: vec![], recommendation: "Review the scanner's remediation and confirm the affected asset before applying a fix.".into(),
        verification_guidance: "Verify the fix using a separately authorized security check.".into(),
        rollback_considerations: None, official_references: vec!["https://github.com/usestrix/strix".into()],
        recommended_expert_type: "Application security engineer".into(), status: FindingStatus::Unreviewed,
        tags: vec!["external-report".into(), "strix".into(), format!("{IMPORT_TARGET_TAG_PREFIX}{}", request.upstream_target)], family: None, severity_basis_code: None,
        confidence_basis_code: None, context_factors: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn native_finding(id: &str, target: &str) -> Value {
        // Generated by the pinned upstream ReportState producer and JSON writer;
        // see the adjacent regeneration script for isolated, offline provenance.
        let mut rows: Vec<Value> = serde_json::from_str(include_str!(
            "../../tests/fixtures/external-scanners/strix-vulnerabilities.json"
        ))
        .unwrap();
        let mut row = rows.remove(0);
        row["id"] = json!(id);
        row["target"] = json!(target);
        row
    }

    fn fixture() -> (TempDir, Storage, AssessmentCase, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("casework.db")).unwrap();
        let mut case = AssessmentCase::new(
            "External evidence".into(),
            OrganizationProfile {
                organization_name: "Test".into(),
                employee_range: "".into(),
                data_classes: vec![],
                notes: None,
            },
        );
        case.assets.push(Asset {
            id: "asset-one".into(),
            kind: AssetKind::Repository,
            name: "Selected repository".into(),
            provider: None,
            region: None,
            identifiers: vec![],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: false,
            internet_exposed: None,
            contains_sensitive_data: None,
            metadata: Default::default(),
        });
        storage.save_case(&mut case, "created").unwrap();
        let path = temp.path().join("vulnerabilities.json");
        fs::write(
            &path,
            serde_json::to_vec(&vec![native_finding("vuln-0001", "/workspace/app")]).unwrap(),
        )
        .unwrap();
        (temp, storage, case, path)
    }

    fn request(path: &Path) -> ExternalScannerImportRequest {
        ExternalScannerImportRequest {
            report_path: path.into(),
            asset_id: "asset-one".into(),
            upstream_target: "/workspace/app".into(),
            source_sha256: preview_external_scanner_import(path).unwrap().source_sha256,
        }
    }

    #[test]
    fn native_findings_reopen_in_one_terminal_report_with_original_provenance() {
        let (temp, storage, case, path) = fixture();
        let before = fs::read(&path).unwrap();
        let imported = import_external_scanner_reports(
            &storage,
            &temp.path().join("artifacts"),
            &case.id,
            &[request(&path)],
        )
        .unwrap();
        assert!(imported.scope_grants.is_empty());
        let run = imported.scan_runs.last().unwrap();
        assert!(run.completed_at.is_some());
        assert_eq!(
            run.engine_runs[0].status,
            EngineRunStatus::PartiallyCompleted
        );
        assert!(run.engine_runs[0].engine_version.is_none());
        assert!(run.engine_runs[0].image_digest.is_none());
        assert!(run.engine_runs[0].started_at.is_none());
        assert_eq!(imported.findings[0].severity, Severity::High);
        assert_eq!(imported.findings[0].confidence, Confidence::Medium);
        let evidence = &imported.findings[0].evidence[0];
        assert_eq!(evidence.source_rule.as_deref(), Some("vuln-0001"));
        assert_eq!(evidence.location.as_deref(), Some("src/handler.py:12"));
        assert_eq!(
            evidence.scanner_details.as_ref().unwrap().cwe_ids,
            vec!["CWE-78"]
        );
        assert_eq!(
            evidence.observed_at.to_rfc3339(),
            "2026-10-21T12:00:00+00:00"
        );
        assert_eq!(
            fs::read(
                temp.path()
                    .join("artifacts")
                    .join(&imported.raw_artifacts[0].relative_path)
            )
            .unwrap(),
            before
        );
        assert_eq!(fs::read(path).unwrap(), before);
        let reopened = storage.get_case(&case.id).unwrap();
        let report =
            crate::beginner_report::build_beginner_master_report(&reopened, &run.id).unwrap();
        assert_eq!(report.findings.len(), 1);
        let serialized = serde_json::to_value(report).unwrap();
        assert!(serialized.to_string().contains("external_report_import"));
        assert!(
            serialized
                .to_string()
                .contains("original scanner's coverage was not verified")
        );
    }

    #[test]
    fn imported_evidence_exports_through_shared_html_report() {
        let (temp, storage, case, path) = fixture();
        let root = temp.path().join("artifacts");
        let imported =
            import_external_scanner_reports(&storage, &root, &case.id, &[request(&path)]).unwrap();
        let registry = crate::registry::EngineRegistry::load_builtin().unwrap();
        let adapters = crate::adapters::builtin_adapter_registry().unwrap();
        let service = crate::case_service::CaseService::new(
            &storage,
            &registry,
            &adapters,
            &root,
            temp.path().join("key"),
        );
        let destination = temp.path().join("report.html");
        service
            .export_document(
                &case.id,
                &imported.scan_runs[0].id,
                crate::case_service::CaseExportFormat::Html,
                &destination,
                crate::export::ExportOptions::default(),
            )
            .unwrap();
        let html = fs::read_to_string(destination).unwrap();
        assert!(html.contains("Untrusted command execution"));
        assert!(html.contains("Imported report"));
        assert!(html.contains("No scanner was executed"));
        assert!(!html.contains("MUST NEVER EXECUTE"));
    }

    #[test]
    fn imported_target_provenance_redacts_mismatched_private_targets_and_legacy_reports() {
        let (temp, storage, case, path) = fixture();
        let target = "https://private-acquisition.example.invalid/internal";
        let hostname = "private-acquisition.example.invalid";
        let mut row = native_finding("vuln-private", target);
        row["title"] = json!(format!("Injection at {target}"));
        row["impact"] = json!(format!("Data exposure on {hostname}"));
        row["description"] = json!(format!("Private endpoint {target}"));
        row["remediation_steps"] = json!(format!("Review {target}"));
        row["code_locations"] =
            json!([{ "file": format!("/private/{hostname}/main.rs"), "start_line": 10 }]);
        fs::write(&path, serde_json::to_vec(&vec![row]).unwrap()).unwrap();
        let mut binding = request(&path);
        binding.upstream_target = target.into();
        let root = temp.path().join("artifacts");
        let first =
            import_external_scanner_reports(&storage, &root, &case.id, &[binding.clone()]).unwrap();
        let old_run = first.scan_runs[0].id.clone();
        let first_snapshot = first.finding_observations[0].finding_snapshot.clone();
        let second =
            import_external_scanner_reports(&storage, &root, &case.id, &[binding]).unwrap();
        let mut reopened = storage.get_case(&case.id).unwrap();
        assert_eq!(second.findings.len(), 1);
        assert_eq!(first.findings[0].id, second.findings[0].id);
        assert_eq!(
            serde_json::to_value(&reopened.finding_observations[0].finding_snapshot).unwrap(),
            serde_json::to_value(&first_snapshot).unwrap()
        );
        assert_eq!(
            imported_report_target(first_snapshot.as_ref().unwrap()),
            Some(target)
        );
        assert_eq!(
            serde_json::to_value(&case.assets).unwrap(),
            serde_json::to_value(&reopened.assets).unwrap()
        );
        assert!(reopened.scope_grants.is_empty());
        assert!(
            reopened
                .scan_runs
                .iter()
                .all(|run| run.scope_grant_snapshots.is_empty())
        );
        // A newer canonical record cannot erase the older snapshot's target.
        reopened.findings.clear();
        let report = crate::export::beginner_report_for_export(
            &reopened,
            &old_run,
            crate::export::RedactionProfile::Standard,
        )
        .unwrap();
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains(hostname));
        assert!(report.findings[0].title.contains("Injection"));
        let unredacted = crate::export::beginner_report_for_export(
            &reopened,
            &old_run,
            crate::export::RedactionProfile::None,
        )
        .unwrap();
        assert!(serde_json::to_string(&unredacted).unwrap().contains(target));
        storage
            .save_case(&mut reopened, "review_fixture_changed")
            .unwrap();
        let registry = crate::registry::EngineRegistry::load_builtin().unwrap();
        let adapters = crate::adapters::builtin_adapter_registry().unwrap();
        let service = crate::case_service::CaseService::new(
            &storage,
            &registry,
            &adapters,
            &root,
            temp.path().join("key"),
        );
        for legacy in [false, true] {
            if legacy {
                reopened = storage.get_case(&case.id).unwrap();
                // Legacy imports remain readable but lack a trustworthy target
                // corpus. Withhold their free-form prose in Standard exports.
                for observation in &mut reopened.finding_observations {
                    if let Some(snapshot) = &mut observation.finding_snapshot {
                        snapshot
                            .tags
                            .retain(|tag| !tag.starts_with(IMPORT_TARGET_TAG_PREFIX));
                    }
                }
                storage
                    .save_case(&mut reopened, "legacy_import_fixture")
                    .unwrap();
            }
            for (format, extension) in [
                (crate::case_service::CaseExportFormat::Html, "html"),
                (crate::case_service::CaseExportFormat::CanonicalJson, "json"),
            ] {
                let destination = temp.path().join(format!("private-{legacy}.{extension}"));
                service
                    .export_document(
                        &case.id,
                        &old_run,
                        format,
                        &destination,
                        crate::export::ExportOptions::default(),
                    )
                    .unwrap();
                let exported = fs::read_to_string(destination).unwrap();
                assert!(
                    !exported.contains(hostname),
                    "legacy={legacy}, format={extension}"
                );
            }
        }
        let legacy_bundle =
            crate::export::case_for_export(&reopened, crate::export::RedactionProfile::Standard);
        assert!(
            !serde_json::to_string(&legacy_bundle)
                .unwrap()
                .contains(hostname)
        );
        // Older retained observations can lack a finding snapshot entirely.
        // The canonical legacy fallback must receive the same conservative mask.
        reopened = storage.get_case(&case.id).unwrap();
        let mut legacy_canonical = first_snapshot.unwrap();
        legacy_canonical
            .tags
            .retain(|tag| !tag.starts_with(IMPORT_TARGET_TAG_PREFIX));
        reopened.findings = vec![legacy_canonical];
        for observation in &mut reopened.finding_observations {
            observation.finding_snapshot = None;
        }
        storage
            .save_case(&mut reopened, "legacy_canonical_import_fixture")
            .unwrap();
        for (format, extension) in [
            (crate::case_service::CaseExportFormat::Html, "html"),
            (crate::case_service::CaseExportFormat::CanonicalJson, "json"),
        ] {
            let destination = temp
                .path()
                .join(format!("private-legacy-fallback.{extension}"));
            service
                .export_document(
                    &case.id,
                    &old_run,
                    format,
                    &destination,
                    crate::export::ExportOptions::default(),
                )
                .unwrap();
            let exported = fs::read_to_string(destination).unwrap();
            assert!(
                !exported.contains(hostname),
                "legacy fallback format={extension}"
            );
        }
    }

    #[test]
    fn imported_baseline_cannot_fall_back_to_unrelated_authorized_assets() {
        let (temp, storage, mut case, path) = fixture();
        let mut unrelated = case.assets[0].clone();
        unrelated.id = "previously-authorized-other-repository".into();
        case.assets.push(unrelated.clone());
        case.scope_grants.push(ScopeGrant {
            id: new_id(),
            asset_id: unrelated.id,
            permission: ScanPermission::LocalArtifactRead,
            confirmed_by: "Test owner".into(),
            confirmed_at: Utc::now(),
            expires_at: None,
            authorization_reference: None,
            notes: None,
            external_scope: None,
        });
        storage
            .save_case(&mut case, "unrelated_scope_granted")
            .unwrap();
        let root = temp.path().join("artifacts");
        let imported =
            import_external_scanner_reports(&storage, &root, &case.id, &[request(&path)]).unwrap();
        let registry = crate::registry::EngineRegistry::load_builtin().unwrap();
        let adapters = crate::adapters::builtin_adapter_registry().unwrap();
        let service = crate::case_service::CaseService::new(
            &storage,
            &registry,
            &adapters,
            &root,
            temp.path().join("key"),
        );
        for explicit in [false, true] {
            let mut plan = crate::case_service::ScanPlanRequest::default();
            if explicit {
                plan.engine_ids = vec!["gitleaks".into()];
            }
            let error = service
                .plan_rescan(&case.id, &imported.scan_runs[0].id, plan)
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("imported reports cannot authorize")
            );
        }
        assert_eq!(storage.get_case(&case.id).unwrap().scan_runs.len(), 1);
    }

    #[test]
    fn reimport_preserves_canonical_identity_and_prior_observation() {
        let (temp, storage, case, path) = fixture();
        let root = temp.path().join("artifacts");
        let first =
            import_external_scanner_reports(&storage, &root, &case.id, &[request(&path)]).unwrap();
        let second =
            import_external_scanner_reports(&storage, &root, &case.id, &[request(&path)]).unwrap();
        assert_eq!(second.findings.len(), 1);
        assert_eq!(second.finding_observations.len(), 2);
        assert_eq!(second.findings[0].id, first.findings[0].id);
        assert_eq!(
            second.finding_observations[0]
                .finding_snapshot
                .as_ref()
                .unwrap()
                .evidence[0]
                .engine_run_id,
            first.findings[0].evidence[0].engine_run_id
        );
        assert_eq!(
            crate::beginner_report::build_beginner_master_report(&second, &first.scan_runs[0].id)
                .unwrap()
                .findings
                .len(),
            1
        );
    }

    #[test]
    fn batch_manifest_is_bounded_and_rejects_unknown_fields() {
        let (temp, _storage, _case, path) = fixture();
        let manifest = temp.path().join("imports.json");
        fs::write(
            &manifest,
            serde_json::to_vec(&vec![request(&path)]).unwrap(),
        )
        .unwrap();
        assert_eq!(read_import_manifest(&manifest).unwrap().len(), 1);
        fs::write(
            &manifest,
            serde_json::to_vec(&vec![request(&path); MAX_IMPORTS + 1]).unwrap(),
        )
        .unwrap();
        assert!(read_import_manifest(&manifest).is_err());
        let mut value = serde_json::to_value(vec![request(&path)]).unwrap();
        value[0]["execute"] = json!("strix");
        fs::write(&manifest, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read_import_manifest(&manifest).is_err());
    }

    #[test]
    fn target_binding_filters_other_assets_without_granting_scope() {
        let (temp, storage, case, path) = fixture();
        fs::write(
            &path,
            serde_json::to_vec(&vec![
                native_finding("vuln-1", "/workspace/app"),
                native_finding("vuln-2", "https://other.invalid"),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            preview_external_scanner_import(&path)
                .unwrap()
                .targets
                .len(),
            2
        );
        let imported = import_external_scanner_reports(
            &storage,
            &temp.path().join("artifacts"),
            &case.id,
            &[request(&path)],
        )
        .unwrap();
        assert_eq!(imported.findings.len(), 1);
        assert_eq!(imported.findings[0].asset_ids, vec!["asset-one"]);
        assert_eq!(imported.assets.len(), 1);
        assert!(imported.scope_grants.is_empty());
    }

    #[test]
    fn changed_report_is_failed_without_erasing_successful_sibling() {
        let (temp, storage, case, path) = fixture();
        let mut stale = request(&path);
        stale.source_sha256 = "a".repeat(64);
        let imported = import_external_scanner_reports(
            &storage,
            &temp.path().join("artifacts"),
            &case.id,
            &[request(&path), stale],
        )
        .unwrap();
        assert_eq!(imported.findings.len(), 1);
        assert_eq!(
            imported.scan_runs[0].engine_runs[1].status,
            EngineRunStatus::Failed
        );
        assert!(
            imported.scan_runs[0].engine_runs[1]
                .raw_artifact_ids
                .is_empty()
        );
    }

    #[test]
    fn missing_asset_rejects_entire_request_before_writing() {
        let (temp, storage, case, path) = fixture();
        let mut input = request(&path);
        input.asset_id = "not-selected".into();
        assert!(
            import_external_scanner_reports(
                &storage,
                &temp.path().join("artifacts"),
                &case.id,
                &[input]
            )
            .is_err()
        );
        assert!(storage.get_case(&case.id).unwrap().scan_runs.is_empty());
        assert!(!temp.path().join("artifacts").exists());
    }

    #[test]
    fn malformed_and_duplicate_records_fail_closed() {
        let (_temp, _storage, _case, path) = fixture();
        let row = native_finding("vuln-1", "/workspace/app");
        for bytes in [
            b"{}".to_vec(),
            serde_json::to_vec(&vec![row.clone(), row.clone()]).unwrap(),
            serde_json::to_vec(&vec![
                json!({"id":"x","target":"a","title":"b","timestamp":"not-a-time"}),
            ])
            .unwrap(),
        ] {
            fs::write(&path, bytes).unwrap();
            assert!(preview_external_scanner_import(&path).is_err());
        }
    }

    #[test]
    fn size_depth_and_record_count_are_bounded() {
        let (_temp, _storage, _case, path) = fixture();
        fs::write(&path, vec![b' '; MAX_REPORT_BYTES as usize + 1]).unwrap();
        assert!(preview_external_scanner_import(&path).is_err());
        fs::write(&path, format!("{}0{}", "[".repeat(200), "]".repeat(200))).unwrap();
        assert!(preview_external_scanner_import(&path).is_err());
        let rows: Vec<_> = (0..=MAX_FINDINGS)
            .map(|index| native_finding(&format!("vuln-{index}"), "app"))
            .collect();
        fs::write(&path, serde_json::to_vec(&rows).unwrap()).unwrap();
        assert!(preview_external_scanner_import(&path).is_err());
    }

    #[test]
    fn empty_report_never_claims_clean_scan() {
        let (temp, storage, case, path) = fixture();
        fs::write(&path, b"[]").unwrap();
        let preview = preview_external_scanner_import(&path).unwrap();
        assert!(preview.targets.is_empty());
        let input = ExternalScannerImportRequest {
            report_path: path,
            asset_id: "asset-one".into(),
            upstream_target: "app".into(),
            source_sha256: preview.source_sha256,
        };
        let imported = import_external_scanner_reports(
            &storage,
            &temp.path().join("artifacts"),
            &case.id,
            &[input],
        )
        .unwrap();
        assert!(imported.findings.is_empty());
        assert_eq!(
            imported.scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Failed
        );
    }

    #[test]
    fn unknown_ratings_stay_unknown_and_poc_stays_in_raw_evidence() {
        let (temp, storage, case, path) = fixture();
        let mut row = native_finding("vuln-1", "/workspace/app");
        row["severity"] = json!("new-level");
        row["confidence"] = json!("confirmed");
        fs::write(&path, serde_json::to_vec(&vec![row]).unwrap()).unwrap();
        let imported = import_external_scanner_reports(
            &storage,
            &temp.path().join("artifacts"),
            &case.id,
            &[request(&path)],
        )
        .unwrap();
        let finding = &imported.findings[0];
        assert_eq!(finding.severity, Severity::Unknown);
        assert_eq!(finding.confidence, Confidence::Unknown);
        assert!(
            !serde_json::to_string(finding)
                .unwrap()
                .contains("MUST NEVER EXECUTE")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_fifo_are_rejected_without_reading() {
        let (temp, _storage, _case, path) = fixture();
        let link = temp.path().join("linked.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(preview_external_scanner_import(&link).is_err());
        let fifo = temp.path().join("pipe.json");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert!(preview_external_scanner_import(&fifo).is_err());
    }
}
