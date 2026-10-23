//! Incident context belongs to the shared report layer, never to detector wrappers.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::domain::{EngineTaskKind, EvidenceKind, Finding, FindingObservation, ScanRun};
use crate::error::{AppError, AppResult};

pub const INCIDENT_FOCUS_ID: &str = "october-2026";
const CAMPAIGN_JSON: &str = include_str!("../../engines/campaigns/october-2026.json");
static CAMPAIGN: LazyLock<Campaign> = LazyLock::new(|| {
    serde_json::from_str(CAMPAIGN_JSON).expect("checked-in incident campaign must be valid")
});

#[derive(Debug, Deserialize)]
struct Campaign {
    id: String,
    title: String,
    reviewed_at: String,
    engine_ids: Vec<String>,
    issues: Vec<CampaignIssue>,
    reason_zh_tw: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct CampaignIssue {
    id: String,
    title: String,
    kind: String,
    advisory_ids: Vec<String>,
    summary: String,
    next_action: String,
    summary_zh_tw: String,
    next_action_zh_tw: String,
    sources: Vec<String>,
    engine_ids: Vec<String>,
}

/// Restrict an existing authorized plan. This function never adds an engine,
/// target, port or scope grant. The caller also validates asset routing normally.
pub fn validate_campaign_selection(
    campaign_id: Option<&str>,
    engine_ids: &[String],
) -> AppResult<()> {
    let Some(id) = campaign_id else {
        return Ok(());
    };
    if id != CAMPAIGN.id {
        return Err(AppError::InvalidRequest("unknown incident campaign".into()));
    }
    if engine_ids.is_empty()
        || engine_ids
            .iter()
            .any(|id| !CAMPAIGN.engine_ids.contains(id))
    {
        return Err(AppError::InvalidRequest(
            "incident triage requires an explicit Trivy package-check selection; website and internal-host checks are unsupported".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IncidentCoverageStatus {
    UpstreamMatch,
    NotTested,
    InvestigationRequired,
    AdvisoryPending,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentCampaignReport {
    pub campaign_id: String,
    pub title: String,
    pub reviewed_at: String,
    pub issues: Vec<IncidentIssueCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentIssueCoverage {
    pub issue_id: String,
    pub title: String,
    pub asset_id: Option<String>,
    pub status: IncidentCoverageStatus,
    pub finding_ids: Vec<String>,
    pub reason_code: String,
    pub reason: String,
    pub next_action: String,
    pub sources: Vec<String>,
}

/// Product-owned guidance shares the frontend's translation source. Scanner
/// evidence and the saved English report remain unchanged.
pub fn incident_issue_guidance(
    issue: &IncidentIssueCoverage,
    traditional_chinese: bool,
) -> (&str, &str) {
    if !traditional_chinese {
        return (&issue.reason, &issue.next_action);
    }
    let Some(entry) = CAMPAIGN
        .issues
        .iter()
        .find(|entry| entry.id == issue.issue_id)
    else {
        return (&issue.reason, &issue.next_action);
    };
    let reason = match issue.reason_code.as_str() {
        "investigation" | "advisory_pending" => entry.summary_zh_tw.as_str(),
        code => CAMPAIGN
            .reason_zh_tw
            .get(code)
            .map(String::as_str)
            .unwrap_or(&issue.reason),
    };
    (reason, &entry.next_action_zh_tw)
}

/// Historical campaign coverage uses the same immutable selected-run records
/// as the unified report. Missing legacy snapshots cannot prove a match.
pub fn build_campaign_report_from_observations<'a>(
    run: &ScanRun,
    observations: impl IntoIterator<Item = &'a FindingObservation>,
) -> Option<IncidentCampaignReport> {
    let findings: Vec<Finding> = observations
        .into_iter()
        .filter_map(|observation| {
            let snapshot = observation.finding_snapshot.as_ref()?;
            if observation.run_id != run.id
                || observation.finding_id != snapshot.id
                || observation.fingerprint != snapshot.fingerprint
            {
                return None;
            }
            let mut selected = snapshot.clone();
            selected
                .asset_ids
                .retain(|id| observation.asset_ids.contains(id));
            selected.evidence.retain(|evidence| {
                observation
                    .evidence_hashes
                    .contains(&evidence.artifact_sha256)
                    && observation.engine_ids.contains(&evidence.engine_id)
            });
            Some(selected)
        })
        .collect();
    build_campaign_report(run, &findings)
}

/// Correlate current-run scanner identifiers. Never infer a negative result
/// from generic engine completion, banner versions, prose, or inventory.
pub fn build_campaign_report(
    run: &ScanRun,
    findings: &[Finding],
) -> Option<IncidentCampaignReport> {
    if run.campaign_id.as_deref() != Some(INCIDENT_FOCUS_ID) {
        return None;
    }
    let asset_ids: BTreeSet<String> = run
        .report_asset_snapshots
        .iter()
        .map(|snapshot| snapshot.asset.id.clone())
        .chain(
            run.engine_runs
                .iter()
                .flat_map(|engine| engine.asset_ids.iter().cloned()),
        )
        .collect();
    let mut rows = Vec::new();
    for issue in &CAMPAIGN.issues {
        if issue.kind != "vulnerability" {
            rows.push(coverage_row(
                issue,
                None,
                if issue.kind == "investigation" {
                    IncidentCoverageStatus::InvestigationRequired
                } else {
                    IncidentCoverageStatus::AdvisoryPending
                },
                Vec::new(),
                &issue.kind,
                &issue.summary,
            ));
            continue;
        }
        // A run without frozen assets still has visible unavailable coverage.
        let targets: Vec<Option<&str>> = if asset_ids.is_empty() {
            vec![None]
        } else {
            asset_ids.iter().map(|id| Some(id.as_str())).collect()
        };
        for asset_id in targets {
            let matches: BTreeSet<String> = findings
                .iter()
                .filter(|finding| current_advisory_match(issue, run, finding, asset_id))
                .map(|finding| finding.id.clone())
                .collect();
            let (status, code, reason) = if !matches.is_empty() {
                (
                    IncidentCoverageStatus::UpstreamMatch,
                    "upstream_advisory_match",
                    "The upstream scanner reported a matching advisory for this asset. Review the original finding and its evidence.",
                )
            } else {
                let applicable: Vec<_> = run
                    .engine_runs
                    .iter()
                    .filter(|engine| {
                        issue.engine_ids.contains(&engine.engine_id)
                            && asset_id.is_some_and(|id| {
                                engine.asset_ids.iter().any(|target| target == id)
                            })
                    })
                    .collect();
                // Frozen knowledge dates are display evidence, not proof that
                // a CVE exists in the feed or that its detector actually ran.
                if applicable.is_empty() {
                    (
                        IncidentCoverageStatus::NotTested,
                        "no_applicable_check",
                        "No applicable upstream check was recorded for this asset.",
                    )
                } else if applicable.iter().all(|engine| {
                    engine
                        .knowledge_input
                        .as_ref()
                        .and_then(|input| input.knowledge_date.as_deref())
                        .and_then(|date| date.get(..10))
                        .is_none_or(|date| date < CAMPAIGN.reviewed_at.as_str())
                }) {
                    (
                        IncidentCoverageStatus::NotTested,
                        "knowledge_not_current",
                        "Scanner knowledge predates this incident review or its date is unavailable. This issue has not been cleared.",
                    )
                } else {
                    (
                        IncidentCoverageStatus::NotTested,
                        "specific_check_unverified",
                        "No matching upstream finding was recorded. Execution of this specific advisory check is unverified.",
                    )
                }
            };
            rows.push(coverage_row(
                issue,
                asset_id,
                status,
                matches.into_iter().collect(),
                code,
                reason,
            ));
        }
    }
    Some(IncidentCampaignReport {
        campaign_id: CAMPAIGN.id.clone(),
        title: CAMPAIGN.title.clone(),
        reviewed_at: CAMPAIGN.reviewed_at.clone(),
        issues: rows,
    })
}

fn coverage_row(
    issue: &CampaignIssue,
    asset_id: Option<&str>,
    status: IncidentCoverageStatus,
    finding_ids: Vec<String>,
    reason_code: &str,
    reason: &str,
) -> IncidentIssueCoverage {
    IncidentIssueCoverage {
        issue_id: issue.id.clone(),
        title: issue.title.clone(),
        asset_id: asset_id.map(str::to_owned),
        status,
        finding_ids,
        reason_code: reason_code.into(),
        reason: reason.into(),
        next_action: issue.next_action.clone(),
        sources: issue.sources.clone(),
    }
}

fn current_advisory_match(
    issue: &CampaignIssue,
    run: &ScanRun,
    finding: &Finding,
    asset_id: Option<&str>,
) -> bool {
    let Some(asset_id) = asset_id else {
        return false;
    };
    if finding.case_id != run.case_id || !finding.asset_ids.iter().any(|id| id == asset_id) {
        return false;
    }
    finding.evidence.iter().any(|evidence| {
        evidence.run_id == run.id
            && evidence.finding_id == finding.id
            && !matches!(
                evidence.kind,
                EvidenceKind::UserDeclaration | EvidenceKind::Observation
            )
            && evidence.artifact_sha256.len() == 64
            && evidence
                .artifact_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            && evidence.source_rule.as_ref().is_some_and(|rule| {
                issue
                    .advisory_ids
                    .iter()
                    .any(|id| id.eq_ignore_ascii_case(rule))
                    || evidence.scanner_details.as_ref().is_some_and(|details| {
                        details.advisory_aliases.iter().any(|alias| {
                            issue
                                .advisory_ids
                                .iter()
                                .any(|id| id.eq_ignore_ascii_case(alias))
                        })
                    })
            })
            && run.engine_runs.iter().any(|engine| {
                evidence.engine_run_id.as_deref() == Some(engine.id.as_str())
                    && engine.scan_run_id == run.id
                    && engine.engine_id == evidence.engine_id
                    && issue.engine_ids.contains(&engine.engine_id)
                    && matches!(engine.task_kind, EngineTaskKind::CatalogEngine)
                    && engine.asset_ids.iter().any(|id| id == asset_id)
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{EngineRunStatus, EngineTaskKind};

    #[test]
    fn incident_focus_chinese_guidance_uses_shared_data_and_preserves_saved_report() {
        let (run, _) = fixture();
        let report = build_campaign_report(&run, &[]).unwrap();
        let before = serde_json::to_string(&report).unwrap();
        for row in &report.issues {
            let (reason, action) = incident_issue_guidance(row, true);
            assert!(
                reason
                    .chars()
                    .any(|ch| ('\u{3400}'..='\u{9fff}').contains(&ch)),
                "{}",
                row.issue_id
            );
            assert!(
                action
                    .chars()
                    .any(|ch| ('\u{3400}'..='\u{9fff}').contains(&ch)),
                "{}",
                row.issue_id
            );
            assert_eq!(
                incident_issue_guidance(row, false),
                (row.reason.as_str(), row.next_action.as_str())
            );
        }
        for code in CAMPAIGN.reason_zh_tw.keys() {
            let mut row = report.issues[0].clone();
            row.reason_code = code.clone();
            assert_eq!(
                incident_issue_guidance(&row, true).0,
                CAMPAIGN.reason_zh_tw[code]
            );
        }
        assert_eq!(serde_json::to_string(&report).unwrap(), before);
        let mut unknown = report.issues[0].clone();
        unknown.issue_id = "future-incident".into();
        assert_eq!(
            incident_issue_guidance(&unknown, true),
            (unknown.reason.as_str(), unknown.next_action.as_str())
        );
    }

    fn fixture() -> (ScanRun, Finding) {
        let case = crate::demo::build_demo_case();
        let mut run = case.scan_runs[0].clone();
        let mut finding = case.findings[0].clone();
        run.campaign_id = Some(INCIDENT_FOCUS_ID.into());
        run.report_asset_snapshots.clear();
        run.engine_runs.truncate(1);
        let task = &mut run.engine_runs[0];
        task.engine_id = "trivy".into();
        task.task_kind = EngineTaskKind::CatalogEngine;
        task.scan_run_id = run.id.clone();
        task.status = EngineRunStatus::Completed;
        task.asset_ids = vec!["asset-a".into()];
        finding.asset_ids = vec!["asset-a".into()];
        finding.case_id = run.case_id.clone();
        finding.evidence.truncate(1);
        let evidence = &mut finding.evidence[0];
        evidence.finding_id = finding.id.clone();
        evidence.run_id = run.id.clone();
        evidence.engine_run_id = Some(task.id.clone());
        evidence.engine_id = task.engine_id.clone();
        evidence.kind = EvidenceKind::PackageInventory;
        evidence.scanner_details = None;
        evidence.source_rule = Some("CVE-2026-109618".into());
        evidence.artifact_sha256 = "a".repeat(64);
        (run, finding)
    }

    fn php_row(report: &IncidentCampaignReport) -> &IncidentIssueCoverage {
        report
            .issues
            .iter()
            .find(|row| row.issue_id == "php2shell" && row.asset_id.as_deref() == Some("asset-a"))
            .unwrap()
    }

    #[test]
    fn campaign_never_expands_an_explicit_plan() {
        assert!(validate_campaign_selection(None, &[]).is_ok());
        assert!(validate_campaign_selection(Some(INCIDENT_FOCUS_ID), &["trivy".into()]).is_ok());
        assert!(validate_campaign_selection(Some("other"), &["trivy".into()]).is_err());
        assert!(validate_campaign_selection(Some(INCIDENT_FOCUS_ID), &[]).is_err());
        for engine in ["strix", "nuclei", "greenbone"] {
            assert!(
                validate_campaign_selection(Some(INCIDENT_FOCUS_ID), &[engine.into()]).is_err()
            );
            assert!(
                validate_campaign_selection(
                    Some(INCIDENT_FOCUS_ID),
                    &["trivy".into(), engine.into()]
                )
                .is_err()
            );
        }
    }

    #[test]
    fn exact_current_upstream_evidence_links_a_finding_without_rewriting_it() {
        let (run, finding) = fixture();
        let before = serde_json::to_string(&finding).unwrap();
        let report = build_campaign_report(&run, std::slice::from_ref(&finding)).unwrap();
        assert_eq!(
            php_row(&report).status,
            IncidentCoverageStatus::UpstreamMatch
        );
        assert_eq!(php_row(&report).finding_ids, vec![finding.id.clone()]);
        assert_eq!(serde_json::to_string(&finding).unwrap(), before);
    }

    #[test]
    fn completion_or_inventory_or_prose_does_not_clear_an_incident() {
        let (run, mut finding) = fixture();
        assert_eq!(
            php_row(&build_campaign_report(&run, &[]).unwrap()).status,
            IncidentCoverageStatus::NotTested
        );
        finding.evidence[0].kind = EvidenceKind::Observation;
        assert_eq!(
            php_row(&build_campaign_report(&run, &[finding.clone()]).unwrap()).status,
            IncidentCoverageStatus::NotTested
        );
        finding.evidence[0].kind = EvidenceKind::PackageInventory;
        finding.evidence[0].source_rule = Some("unrelated-rule".into());
        finding.title = "CVE-2026-109618".into();
        finding.tags = vec!["CVE-2026-109618".into()];
        assert_eq!(
            php_row(&build_campaign_report(&run, &[finding]).unwrap()).status,
            IncidentCoverageStatus::NotTested
        );
    }

    #[test]
    fn legacy_wrong_run_wrong_asset_and_imported_evidence_cannot_match() {
        let (run, finding) = fixture();
        for mode in 0..6 {
            let mut changed_run = run.clone();
            let mut changed = finding.clone();
            match mode {
                0 => changed.evidence[0].run_id = "old-run".into(),
                1 => changed.evidence[0].engine_run_id = None,
                2 => changed.asset_ids = vec!["other-asset".into()],
                3 => changed.evidence[0].artifact_sha256.clear(),
                4 => changed.evidence[0].source_rule = Some("CVE-2026-109618-extra".into()),
                _ => {
                    changed_run.engine_runs[0].task_kind = EngineTaskKind::ExternalReportImport {
                        source_format: "sarif".into(),
                        source_sha256: "a".repeat(64),
                    }
                }
            }
            assert_eq!(
                php_row(&build_campaign_report(&changed_run, &[changed]).unwrap()).status,
                IncidentCoverageStatus::NotTested,
                "mode {mode}"
            );
        }
    }

    #[test]
    fn pending_candidates_and_account_incidents_are_not_vulnerability_results() {
        let (run, finding) = fixture();
        let report = build_campaign_report(&run, &[finding]).unwrap();
        assert_eq!(
            report
                .issues
                .iter()
                .filter(|row| row.status == IncidentCoverageStatus::AdvisoryPending)
                .count(),
            6
        );
        assert_eq!(
            report
                .issues
                .iter()
                .filter(|row| row.status == IncidentCoverageStatus::InvestigationRequired)
                .count(),
            6
        );
        let pending = report
            .issues
            .iter()
            .find(|row| row.issue_id == "zdi-can-32005")
            .unwrap();
        assert!(pending.title.starts_with("ConnMan"));
        assert!(pending.finding_ids.is_empty());
        let mut ordinary = run;
        ordinary.campaign_id = None;
        assert!(build_campaign_report(&ordinary, &[]).is_none());
    }

    #[test]
    fn structured_upstream_aliases_match_only_their_own_asset_and_survive_sibling_failure() {
        let (mut run, mut finding) = fixture();
        finding.evidence[0].source_rule = Some("GHSA-upstream-identifier".into());
        finding.evidence[0].scanner_details = Some(
            serde_json::from_value(serde_json::json!({
                "advisory_aliases": ["CVE-2026-109618"]
            }))
            .unwrap(),
        );
        let mut sibling = run.engine_runs[0].clone();
        sibling.id = "failed-sibling".into();
        sibling.asset_ids = vec!["asset-b".into()];
        sibling.status = EngineRunStatus::Failed;
        run.engine_runs.push(sibling);
        let report = build_campaign_report(&run, &[finding]).unwrap();
        assert_eq!(
            php_row(&report).status,
            IncidentCoverageStatus::UpstreamMatch
        );
        let other = report
            .issues
            .iter()
            .find(|row| row.issue_id == "php2shell" && row.asset_id.as_deref() == Some("asset-b"))
            .unwrap();
        assert_eq!(other.status, IncidentCoverageStatus::NotTested);
        assert!(other.finding_ids.is_empty());
    }

    #[test]
    fn greenbone_oid_matches_its_explicit_upstream_cve_alias() {
        let (mut run, mut finding) = fixture();
        run.engine_runs[0].engine_id = "greenbone".into();
        finding.evidence[0].engine_id = "greenbone".into();
        finding.evidence[0].kind = EvidenceKind::ExternalValidation;
        finding.evidence[0].source_rule = Some("1.3.6.1.4.1.25623.1.0.100007".into());
        finding.evidence[0].scanner_details = Some(
            serde_json::from_value(serde_json::json!({
                "advisory_aliases": ["CVE-2026-109618"]
            }))
            .unwrap(),
        );
        assert_eq!(
            php_row(&build_campaign_report(&run, &[finding]).unwrap()).status,
            IncidentCoverageStatus::UpstreamMatch
        );
    }

    #[test]
    fn campaign_history_uses_frozen_observation_and_rejects_missing_snapshot() {
        let (run, finding) = fixture();
        let mut observation = FindingObservation {
            id: "observation".into(),
            run_id: run.id.clone(),
            finding_id: finding.id.clone(),
            fingerprint: finding.fingerprint.clone(),
            asset_ids: finding.asset_ids.clone(),
            engine_ids: vec!["trivy".into()],
            severity: finding.severity.clone(),
            confidence: finding.confidence.clone(),
            evidence_hashes: vec!["a".repeat(64)],
            observed_at: run.created_at,
            finding_snapshot: Some(finding.clone()),
        };
        let mut newer_canonical = finding;
        newer_canonical.evidence.clear();
        assert_eq!(
            php_row(&build_campaign_report(&run, &[newer_canonical]).unwrap()).status,
            IncidentCoverageStatus::NotTested
        );
        assert_eq!(
            php_row(&build_campaign_report_from_observations(&run, [&observation]).unwrap()).status,
            IncidentCoverageStatus::UpstreamMatch
        );
        observation.finding_snapshot = None;
        assert_eq!(
            php_row(&build_campaign_report_from_observations(&run, [&observation]).unwrap()).status,
            IncidentCoverageStatus::NotTested
        );
    }
}
