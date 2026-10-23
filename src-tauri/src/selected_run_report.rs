//! Explicit, read-only composition of terminal shared reports. A combined
//! document is a view over historical sources, never another scan execution.
use crate::beginner_report::{
    BeginnerMasterReport, BeginnerReportSummary, CoverageDimensionStatus,
};
use crate::domain::{AssessmentCase, EngineRunStatus, EngineTaskKind, Severity};
use crate::error::{AppError, AppResult};
use crate::export::{ExportOptions, ReportLocale};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MAX_SOURCES: usize = 16;
const MAX_DOCUMENT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelectedRunReportFormat {
    Html,
    Json,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelectedRunOrigin {
    RecordedChecks,
    ImportedReports,
    Mixed,
    NoChecks,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedRunReport {
    pub schema_version: String,
    pub case_id: String,
    pub project_title: String,
    pub is_demo: bool,
    pub generated_at: DateTime<Utc>,
    pub selected_run_ids: Vec<String>,
    pub redaction_profile: String,
    pub summary: SelectedRunSummary,
    pub sources: Vec<SelectedRunSource>,
    pub assets: Vec<SelectedReportAsset>,
    /// Existing within-run problem grouping only. Repeated observations across
    /// runs stay separate; no current, resolved, or cross-run clean inference.
    pub problems: Vec<SelectedProblemObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedRunSummary {
    pub source_count: usize,
    pub asset_count: usize,
    pub problem_observation_count: usize,
    pub original_finding_observation_count: usize,
    pub sources_with_imports: usize,
    pub sources_with_incomplete_coverage: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedRunSource {
    pub run_id: String,
    pub sequence: u32,
    pub created_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub origin: SelectedRunOrigin,
    /// Canonical existing projection, including exact source evidence, scanner
    /// times, task outcomes, limits, inventory, and coverage gaps.
    pub report: BeginnerMasterReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedReportAsset {
    pub asset_id: String,
    pub sources: Vec<SelectedAssetSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedAssetSource {
    pub run_id: String,
    /// The label in this source's own projection, never the newest run's label.
    pub label: Option<String>,
    pub problem_observation_count: usize,
    pub check_count: usize,
    pub coverage_gap_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedProblemObservation {
    pub source_run_id: String,
    pub representative_finding_id: String,
    pub original_finding_ids: Vec<String>,
    pub asset_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedRunReportExport {
    pub case_id: String,
    pub selected_run_ids: Vec<String>,
    pub format: SelectedRunReportFormat,
    pub path: String,
    pub sha256: String,
    pub created_at: DateTime<Utc>,
    pub redaction_profile: String,
}

pub fn preview_selected_run_report(
    case: &AssessmentCase,
    run_ids: &[String],
    options: &ExportOptions,
) -> AppResult<SelectedRunReport> {
    if !(2..=MAX_SOURCES).contains(&run_ids.len()) {
        return Err(AppError::InvalidRequest(
            "Select between two and sixteen finished reports.".into(),
        ));
    }
    if options.include_raw_artifacts {
        return Err(AppError::InvalidRequest("Combined reports include evidence references; export original files from their source report.".into()));
    }
    let mut seen = BTreeSet::new();
    let mut sources = Vec::with_capacity(run_ids.len());
    for run_id in run_ids {
        if !seen.insert(run_id.as_str()) {
            return Err(AppError::InvalidRequest(
                "Select each source report once.".into(),
            ));
        }
        let matches: Vec<_> = case
            .scan_runs
            .iter()
            .filter(|run| &run.id == run_id)
            .collect();
        let [run] = matches.as_slice() else {
            return Err(AppError::InvalidRequest(
                "A selected report is missing or ambiguous in this project.".into(),
            ));
        };
        if run.case_id != case.id {
            return Err(AppError::InvalidRequest(
                "A selected report belongs to another project.".into(),
            ));
        }
        let Some(completed_at) = run.completed_at else {
            return Err(AppError::InvalidRequest(
                "Every selected report must be finished.".into(),
            ));
        };
        if run.engine_runs.iter().any(|task| {
            matches!(
                task.status,
                EngineRunStatus::Queued
                    | EngineRunStatus::Preparing
                    | EngineRunStatus::Running
                    | EngineRunStatus::Paused
            )
        }) {
            return Err(AppError::InvalidRequest(
                "A selected report still has active checks.".into(),
            ));
        }
        let imports = run
            .engine_runs
            .iter()
            .filter(|task| matches!(task.task_kind, EngineTaskKind::ExternalReportImport { .. }))
            .count();
        let origin = match (imports, run.engine_runs.len()) {
            (_, 0) => SelectedRunOrigin::NoChecks,
            (0, _) => SelectedRunOrigin::RecordedChecks,
            (count, total) if count == total => SelectedRunOrigin::ImportedReports,
            _ => SelectedRunOrigin::Mixed,
        };
        let report = crate::export::beginner_report_for_export(case, run_id, options.redaction)?;
        sources.push(SelectedRunSource {
            run_id: run_id.clone(),
            sequence: run.sequence,
            created_at: run.created_at,
            completed_at,
            origin,
            report,
        });
    }
    let mut assets = BTreeMap::<String, Vec<SelectedAssetSource>>::new();
    let mut ranked_problems = Vec::new();
    for (source_index, source) in sources.iter().enumerate() {
        let problems: Vec<_> = source
            .report
            .problem_findings()
            .into_iter()
            .filter(|finding| {
                !finding
                    .severity_basis_code
                    .is_some_and(|basis| basis.is_exposure_observation())
            })
            .collect();
        let mut asset_ids = BTreeSet::new();
        asset_ids.extend(
            source
                .report
                .requested
                .targets
                .iter()
                .map(|target| target.asset_id.clone()),
        );
        asset_ids.extend(
            source
                .report
                .actual
                .checks
                .iter()
                .flat_map(|check| check.target_asset_ids.iter().cloned()),
        );
        asset_ids.extend(
            problems
                .iter()
                .flat_map(|finding| finding.target_asset_ids.iter().cloned()),
        );
        for asset_id in asset_ids {
            assets
                .entry(asset_id.clone())
                .or_default()
                .push(SelectedAssetSource {
                    run_id: source.run_id.clone(),
                    label: source
                        .report
                        .requested
                        .targets
                        .iter()
                        .find(|target| target.asset_id == asset_id)
                        .and_then(|target| target.label.clone()),
                    problem_observation_count: problems
                        .iter()
                        .filter(|finding| finding.target_asset_ids.contains(&asset_id))
                        .count(),
                    check_count: source
                        .report
                        .actual
                        .checks
                        .iter()
                        .filter(|check| check.target_asset_ids.contains(&asset_id))
                        .count(),
                    coverage_gap_count: source
                        .report
                        .coverage_gaps
                        .iter()
                        .filter(|gap| gap.target_asset_ids.contains(&asset_id))
                        .count()
                        + source.report.incident_focus.as_ref().map_or(0, |campaign| {
                            campaign.issues.iter().filter(|issue| {
                                issue.asset_id.as_deref() == Some(asset_id.as_str())
                                    && issue.status != crate::incident_focus::IncidentCoverageStatus::UpstreamMatch
                            }).count()
                        }),
                });
        }
        for (finding_index, finding) in problems.iter().enumerate() {
            let original_finding_ids = source
                .report
                .rendered_problem_membership()
                .get(finding.finding_id.as_str())
                .map(|group| group.finding_ids.clone())
                .unwrap_or_else(|| vec![finding.finding_id.clone()]);
            let rank = finding.priority.unwrap_or(match finding.severity {
                Severity::Critical => 100,
                Severity::High => 80,
                Severity::Medium => 60,
                Severity::Low => 40,
                Severity::Unknown => 20,
                Severity::Informational => 10,
            });
            ranked_problems.push((
                std::cmp::Reverse(rank),
                source_index,
                finding_index,
                SelectedProblemObservation {
                    source_run_id: source.run_id.clone(),
                    representative_finding_id: finding.finding_id.clone(),
                    original_finding_ids,
                    asset_ids: finding.target_asset_ids.clone(),
                },
            ));
        }
    }
    ranked_problems.sort_by_key(|(rank, source, finding, _)| (*rank, *source, *finding));
    let problems: Vec<_> = ranked_problems
        .into_iter()
        .map(|(_, _, _, observation)| observation)
        .collect();
    let summary = SelectedRunSummary {
        source_count: sources.len(),
        asset_count: assets.len(),
        problem_observation_count: problems.len(),
        original_finding_observation_count: sources
            .iter()
            .map(|source| source.report.findings.len())
            .sum(),
        sources_with_imports: sources
            .iter()
            .filter(|source| {
                matches!(
                    source.origin,
                    SelectedRunOrigin::ImportedReports | SelectedRunOrigin::Mixed
                )
            })
            .count(),
        sources_with_incomplete_coverage: sources
            .iter()
            .filter(|source| source_has_coverage_limits(source))
            .count(),
    };
    Ok(SelectedRunReport {
        schema_version: "ai-security-scanner.selected-run-report/v1".into(),
        case_id: case.id.clone(),
        project_title: sources[0].report.project_title.clone(),
        is_demo: case.is_demo,
        generated_at: Utc::now(),
        selected_run_ids: run_ids.to_vec(),
        redaction_profile: options.redaction.as_str().into(),
        summary,
        sources,
        assets: assets
            .into_iter()
            .map(|(asset_id, sources)| SelectedReportAsset { asset_id, sources })
            .collect(),
        problems,
    })
}

fn source_has_coverage_limits(source: &SelectedRunSource) -> bool {
    source.report.state.summary != BeginnerReportSummary::Complete
        || matches!(
            source.origin,
            SelectedRunOrigin::ImportedReports | SelectedRunOrigin::Mixed
        )
        || source
            .report
            .incident_focus
            .as_ref()
            .is_some_and(|campaign| {
                campaign.issues.iter().any(|issue| {
                    issue.status != crate::incident_focus::IncidentCoverageStatus::UpstreamMatch
                })
            })
}

pub fn export_selected_run_report(
    case: &AssessmentCase,
    run_ids: &[String],
    format: SelectedRunReportFormat,
    destination: &Path,
    options: &ExportOptions,
) -> AppResult<SelectedRunReportExport> {
    let report = preview_selected_run_report(case, run_ids, options)?;
    let bytes = match format {
        SelectedRunReportFormat::Json => serde_json::to_vec_pretty(&report)?,
        SelectedRunReportFormat::Html => render_html(&report, options.locale)?.into_bytes(),
    };
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(AppError::InvalidRequest(
            "The combined report exceeds 64 MiB; select fewer source reports.".into(),
        ));
    }
    let path = crate::case_service::write_new_private_file(destination, &bytes)?;
    Ok(SelectedRunReportExport {
        case_id: case.id.clone(),
        selected_run_ids: report.selected_run_ids,
        format,
        path: path.to_string_lossy().into_owned(),
        sha256: hex::encode(Sha256::digest(&bytes)),
        created_at: report.generated_at,
        redaction_profile: report.redaction_profile,
    })
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn text<'a>(locale: ReportLocale, english: &'a str, chinese: &'a str) -> &'a str {
    if locale == ReportLocale::ZhHant {
        chinese
    } else {
        english
    }
}

fn origin_label(origin: SelectedRunOrigin, locale: ReportLocale) -> &'static str {
    match origin {
        SelectedRunOrigin::RecordedChecks => text(locale, "Recorded checks", "已記錄的檢查"),
        SelectedRunOrigin::ImportedReports => text(locale, "Imported findings", "匯入的發現事項"),
        SelectedRunOrigin::Mixed => text(
            locale,
            "Recorded checks and imported findings",
            "已記錄的檢查與匯入發現",
        ),
        SelectedRunOrigin::NoChecks => text(locale, "No checks recorded", "未記錄檢查"),
    }
}

fn status_label(status: CoverageDimensionStatus, locale: ReportLocale) -> &'static str {
    match status {
        CoverageDimensionStatus::TestedComplete => {
            text(locale, "Completed in source run", "於來源輪次完成")
        }
        CoverageDimensionStatus::TestedPartial => text(locale, "Partial", "部分完成"),
        CoverageDimensionStatus::Failed => text(locale, "Failed", "失敗"),
        CoverageDimensionStatus::TimedOut => text(locale, "Timed out", "逾時"),
        CoverageDimensionStatus::Cancelled => text(locale, "Cancelled", "已取消"),
        CoverageDimensionStatus::NotTested => text(locale, "Not tested", "未測試"),
    }
}

fn severity_label(severity: &Severity, locale: ReportLocale) -> &str {
    match severity {
        Severity::Critical => text(locale, "Critical", "嚴重"),
        Severity::High => text(locale, "High", "高"),
        Severity::Medium => text(locale, "Medium", "中"),
        Severity::Low => text(locale, "Low", "低"),
        Severity::Unknown => text(locale, "Unknown", "未知"),
        Severity::Informational => text(locale, "Informational", "資訊"),
    }
}

fn render_html(report: &SelectedRunReport, locale: ReportLocale) -> AppResult<String> {
    let t = |en, zh| text(locale, en, zh);
    let source_indices: BTreeMap<_, _> = report
        .sources
        .iter()
        .enumerate()
        .map(|(i, source)| (source.run_id.as_str(), i))
        .collect();
    let mut html = format!(
        "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><title>{}</title><style>{}</style></head><body><main><header><p class=\"eyebrow\">ai-security-scanner</p><h1>{}</h1><p>{}</p><p class=\"muted\">{} {}</p></header>",
        locale.as_str(),
        escape(&report.project_title),
        STYLE,
        t("Combined security report", "整合安全報告"),
        escape(&report.project_title),
        t("Generated", "產生時間"),
        escape(&report.generated_at.to_rfc3339())
    );
    if report.is_demo {
        html.push_str(&format!(
            "<p class=\"badge\">{}</p>",
            t(
                "Demo project — sample scan results",
                "示範專案 — 範例掃描結果"
            )
        ));
    }
    html.push_str(&format!("<section class=\"summary\"><div><strong>{}</strong><span>{}</span></div><div><strong>{}</strong><span>{}</span></div><div><strong>{}</strong><span>{}</span></div><div><strong>{}</strong><span>{}</span></div></section><p>{}</p>",
        report.summary.asset_count,t("Assets", "資產"),report.summary.source_count,t("Selected reports", "已選報告"),
        report.summary.problem_observation_count,t("Problem observations", "問題觀察紀錄"),report.summary.sources_with_incomplete_coverage,t("Sources with coverage limits", "涵蓋範圍有限制的來源"),
        t("Observations retain their original report and time. Repeated observations from different reports remain separate.", "每筆觀察保留原始報告與時間；不同報告中的重複觀察會分別保留。")));
    html.push_str(&format!(
        "<section><h2>{}</h2>",
        t("Priorities and next actions", "優先事項與下一步")
    ));
    if report.problems.is_empty() {
        html.push_str(&format!("<p>{}</p>",t("The selected reports contain no problem observations. Review each source's completed checks and coverage limits below.", "所選報告沒有問題觀察紀錄；請查看下方各來源完成的檢查與涵蓋限制。")));
    }
    for (index, problem) in report.problems.iter().enumerate() {
        let source_index = source_indices[problem.source_run_id.as_str()];
        let source = &report.sources[source_index];
        let finding = source
            .report
            .findings
            .iter()
            .find(|finding| finding.finding_id == problem.representative_finding_id)
            .expect("projection binds each representative");
        let group = source.report.problem_group(&finding.finding_id);
        let title = match locale {
            ReportLocale::En => {
                crate::finding_narrative::finding_headline_english(&finding.title, finding.family)
            }
            ReportLocale::ZhHant => {
                crate::finding_narrative::finding_headline_zh_hant(&finding.title, finding.family)
            }
        };
        let policy = finding
            .evidence_references
            .iter()
            .filter_map(|evidence| evidence.scanner_details.as_ref())
            .find_map(|details| details.aws_iam_policy.as_ref());
        let unconfirmed =
            crate::beginner_report::finding_unconfirmed_by_coverage(finding, &source.report.actual);
        let (impact, action) = match locale {
            ReportLocale::En => (
                crate::finding_narrative::impact_english(
                    &finding.possible_impact,
                    finding.family,
                    &finding.context_factors,
                ),
                group
                    .and_then(|g| g.next_step_english())
                    .map(str::to_owned)
                    .unwrap_or_else(|| {
                        crate::finding_narrative::finding_next_action_english(
                            &finding.next_step,
                            finding.family,
                            policy,
                            unconfirmed,
                        )
                    }),
            ),
            ReportLocale::ZhHant => (
                crate::finding_narrative::impact_zh_hant(
                    &finding.possible_impact,
                    &finding.severity,
                    severity_label(&finding.severity, locale),
                    finding.severity_basis_code,
                    finding.family,
                    &finding.context_factors,
                ),
                group
                    .and_then(|g| g.next_step_zh_hant())
                    .map(str::to_owned)
                    .unwrap_or_else(|| {
                        crate::finding_narrative::finding_next_action_zh_hant(
                            &finding.next_step,
                            &finding.recommended_expert_type,
                            finding.family,
                            policy,
                            unconfirmed,
                        )
                    }),
            ),
        };
        let labels = problem
            .asset_ids
            .iter()
            .map(|id| {
                source
                    .report
                    .requested
                    .targets
                    .iter()
                    .find(|target| &target.asset_id == id)
                    .and_then(|target| target.label.as_deref())
                    .unwrap_or(id)
            })
            .collect::<Vec<_>>()
            .join(", ");
        html.push_str(&format!("<article class=\"finding\" id=\"problem-{}\"><div class=\"muted\">{} · {} · <a href=\"#source-{}\">{} #{}</a></div><h3>{}</h3><p>{}</p><p><strong>{}</strong> {}</p><details><summary>{} ({})</summary>",
            index+1,escape(severity_label(&finding.severity,locale)),escape(&labels),source_index+1,t("Report", "報告"),source.sequence,
            escape(&title),escape(&impact),t("Next action", "下一步"),escape(&action),t("Original findings and evidence", "原始發現與證據"),problem.original_finding_ids.len()));
        for id in &problem.original_finding_ids {
            let Some(original) = source
                .report
                .findings
                .iter()
                .find(|finding| &finding.finding_id == id)
            else {
                continue;
            };
            html.push_str(&format!(
                "<h4>{}</h4><p>{}: <code>{}</code></p>",
                escape(&original.title),
                t("Finding", "發現事項"),
                escape(id)
            ));
            for evidence in &original.evidence_references {
                html.push_str(&format!(
                    "<p>{} · {} · <time>{}</time></p><p>{}: <code>{}</code></p>",
                    escape(&evidence.engine_id),
                    escape(evidence.source_rule.as_deref().unwrap_or("—")),
                    escape(&evidence.observed_at.to_rfc3339()),
                    t("Evidence SHA-256", "證據 SHA-256"),
                    escape(&evidence.artifact_sha256)
                ));
                if let Some(details) = &evidence.scanner_details {
                    if let Some(description) = &details.description {
                        html.push_str(&format!("<p>{}</p>", escape(description)));
                    }
                    if let Some(remediation) = &details.remediation {
                        html.push_str(&format!(
                            "<p><strong>{}</strong> {}</p>",
                            t("Scanner remediation", "掃描工具修復建議"),
                            escape(remediation)
                        ));
                    }
                }
            }
        }
        html.push_str("</details></article>");
    }
    html.push_str(&format!("</section><section><h2>{}</h2><div class=\"table-wrap\"><table><thead><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>",
        t("Assets across selected reports", "各報告的資產"),t("Asset in source", "來源中的資產"),t("Report", "報告"),t("Source finished", "來源結束時間"),t("Problem observations", "問題觀察紀錄"),t("Coverage gaps", "涵蓋缺口")));
    for asset in &report.assets {
        for occurrence in &asset.sources {
            let index = source_indices[occurrence.run_id.as_str()];
            let source = &report.sources[index];
            html.push_str(&format!("<tr><td>{}</td><td><a href=\"#source-{}\">#{}</a> · {}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(occurrence.label.as_deref().unwrap_or(&asset.asset_id)),index+1,source.sequence,origin_label(source.origin,locale),escape(&source.completed_at.to_rfc3339()),occurrence.problem_observation_count,occurrence.coverage_gap_count));
        }
    }
    html.push_str("</tbody></table></div></section>");
    html.push_str(&format!(
        "<section><h2>{}</h2>",
        t("Source coverage and outcomes", "來源涵蓋範圍與結果")
    ));
    for (index, source) in report.sources.iter().enumerate() {
        html.push_str(&format!("<article class=\"source\" id=\"source-{}\"><h3>{} #{} · {}</h3><p>{} {} → {}</p><details><summary>{}</summary><p>{}: <code>{}</code></p><div class=\"table-wrap\"><table><thead><tr><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>",
            index+1,t("Report", "報告"),source.sequence,origin_label(source.origin,locale),t("Source record period", "來源紀錄期間"),escape(&source.created_at.to_rfc3339()),escape(&source.completed_at.to_rfc3339()),
            t("Recorded checks and limits", "已記錄的檢查與限制"),t("Source run", "來源輪次"),escape(&source.run_id),t("Check", "檢查"),t("Outcome in source", "來源結果"),t("Recorded end", "記錄的結束時間")));
        for check in &source.report.actual.checks {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(&check.check_id),
                status_label(check.status, locale),
                escape(
                    &check
                        .finished_at
                        .map(|date| date.to_rfc3339())
                        .unwrap_or_else(|| "—".into())
                )
            ));
        }
        html.push_str("</tbody></table></div><ul>");
        for gap in &source.report.coverage_gaps {
            let reason = if locale == ReportLocale::ZhHant {
                crate::finding_narrative::coverage_gap_prose_zh_hant(&gap.reason)
                    .unwrap_or_else(|| gap.reason.clone())
            } else {
                gap.reason.clone()
            };
            let action = if locale == ReportLocale::ZhHant {
                crate::finding_narrative::coverage_gap_prose_zh_hant(&gap.next_action)
                    .unwrap_or_else(|| gap.next_action.clone())
            } else {
                gap.next_action.clone()
            };
            html.push_str(&format!("<li>{} {}</li>", escape(&reason), escape(&action)));
        }
        html.push_str("</ul></details>");
        if let Some(campaign) = &source.report.incident_focus {
            use crate::incident_focus::IncidentCoverageStatus;
            let unresolved = campaign
                .issues
                .iter()
                .filter(|issue| issue.status != IncidentCoverageStatus::UpstreamMatch)
                .count();
            html.push_str(&format!("<section data-incident-focus><h4>{}</h4><p>{}: {}</p><details><summary>{}</summary><ul>",
                t("October incident triage", "10 月事件初步檢查"),
                t("Issues requiring further checking", "需要進一步檢查的項目"), unresolved,
                t("Incident coverage and next actions", "事件涵蓋範圍與下一步")));
            for issue in &campaign.issues {
                let status = match issue.status {
                    IncidentCoverageStatus::UpstreamMatch => t("Upstream finding", "上游發現"),
                    IncidentCoverageStatus::NotTested => t("Not tested", "未測試"),
                    IncidentCoverageStatus::InvestigationRequired => {
                        t("Investigation needed", "需要調查")
                    }
                    IncidentCoverageStatus::AdvisoryPending => {
                        t("Advisory pending", "公告對應待確認")
                    }
                };
                let target = issue
                    .asset_id
                    .as_ref()
                    .and_then(|id| {
                        source
                            .report
                            .requested
                            .targets
                            .iter()
                            .find(|target| &target.asset_id == id)
                    })
                    .and_then(|target| target.label.as_deref())
                    .unwrap_or(t("Incident context", "事件資訊"));
                let (reason, action) = crate::incident_focus::incident_issue_guidance(
                    issue,
                    locale == ReportLocale::ZhHant,
                );
                html.push_str(&format!(
                    "<li><strong>{}</strong> · {} · {}<p>{}</p><p><strong>{}</strong> {}</p></li>",
                    escape(&issue.title),
                    escape(target),
                    status,
                    escape(reason),
                    t("Next action", "下一步"),
                    escape(action)
                ));
            }
            html.push_str("</ul></details></section>");
        }
        html.push_str("</article>");
    }
    let canonical = serde_json::to_string_pretty(report)?;
    html.push_str(&format!("</section><footer><details><summary>{}</summary><p>{}</p><pre>{}</pre></details></footer></main></body></html>",
        t("Terms and source records", "條款與來源紀錄"),
        t("This document combines the selected historical reports. It does not perform a new scan, establish current clean status, infer remediation, or change a source's findings and coverage. Original evidence retains its source run and time. No original files are attached.", "本文件整合所選的歷史報告，未執行新掃描、不判定目前無問題、不推論修復狀態，也不變更來源的發現與涵蓋範圍。原始證據保留來源輪次與時間；本文件未附加原始檔案。"),escape(&canonical)));
    Ok(html)
}

const STYLE: &str = r#"
:root{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172033;background:#f3f5f9;font-size:16px}body{margin:0}main{max-width:1120px;margin:32px auto;background:white;padding:48px;border:1px solid #e2e8f0;border-radius:14px}h1{font-size:2.2rem;margin:8px 0}h2{margin-top:36px;font-size:1.4rem}h3{font-size:1.12rem}p{line-height:1.6}.eyebrow{color:#334155;letter-spacing:.08em;font-size:.8rem;font-weight:700}.muted{color:#526074;font-size:.88rem}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:28px 0}.summary div{padding:18px;background:#f3f6fa;border:1px solid #e2e8f0;border-radius:8px}.summary strong{display:block;font-size:1.8rem}.summary span{font-size:.85rem}.finding,.source{border:1px solid #dbe2eb;border-radius:8px;padding:22px;margin:16px 0}.finding{border-left:4px solid #4665ba}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:.88rem}th,td{text-align:left;padding:12px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top}th{background:#f5f7fa}a{color:#244a9d}details{margin-top:18px}summary{cursor:pointer;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.76rem;background:#f6f8fb;padding:16px}code{overflow-wrap:anywhere}footer{border-top:1px solid #dbe2eb;margin-top:36px;padding-top:12px}li{margin:12px 0;line-height:1.5}@media(max-width:650px){main{padding:20px;margin:0;border-radius:0}.summary{grid-template-columns:repeat(2,1fr)}h1{font-size:1.7rem}}@media print{body,main{background:white}main{padding:0;border:0;max-width:none}.finding,.source{break-inside:avoid}details:not([open])>summary{font-weight:normal}}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::RedactionProfile;
    use crate::external_scanner_import::{
        ExternalScannerImportRequest, import_external_scanner_reports,
        preview_external_scanner_import,
    };
    use crate::storage::Storage;
    use tempfile::TempDir;

    fn fixture() -> (
        TempDir,
        Storage,
        AssessmentCase,
        ExternalScannerImportRequest,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("casework.db")).unwrap();
        let mut case = crate::demo::build_demo_case();
        storage.save_case(&mut case, "test_fixture").unwrap();
        let path = temp.path().join("vulnerabilities.json");
        std::fs::write(
            &path,
            include_bytes!("../../tests/fixtures/external-scanners/strix-vulnerabilities.json"),
        )
        .unwrap();
        let request = ExternalScannerImportRequest {
            report_path: path.clone(),
            asset_id: case.assets[0].id.clone(),
            upstream_target: "/workspace/app".into(),
            source_sha256: preview_external_scanner_import(&path)
                .unwrap()
                .source_sha256,
        };
        let mut stale = request.clone();
        stale.source_sha256 = "0".repeat(64);
        let imported = import_external_scanner_reports(
            &storage,
            &temp.path().join("artifacts"),
            &case.id,
            &[request.clone(), stale],
        )
        .unwrap();
        (temp, storage, imported, request)
    }

    fn ids(case: &AssessmentCase) -> Vec<String> {
        case.scan_runs.iter().map(|run| run.id.clone()).collect()
    }

    #[test]
    fn mixed_sources_reuse_exact_shared_projections_and_keep_independent_failures() {
        let (_temp, _storage, case, _request) = fixture();
        let before = serde_json::to_value(&case).unwrap();
        let options = ExportOptions::default();
        let report = preview_selected_run_report(&case, &ids(&case), &options).unwrap();
        assert_eq!(report.summary.source_count, 2);
        assert_eq!(report.summary.sources_with_imports, 1);
        assert_eq!(report.sources[0].origin, SelectedRunOrigin::RecordedChecks);
        assert_eq!(report.sources[1].origin, SelectedRunOrigin::ImportedReports);
        assert!(report.is_demo);
        for source in &report.sources {
            let canonical =
                crate::export::beginner_report_for_export(&case, &source.run_id, options.redaction)
                    .unwrap();
            assert_eq!(
                serde_json::to_value(&source.report).unwrap(),
                serde_json::to_value(canonical).unwrap()
            );
            assert_eq!(source.report.run_id, source.run_id);
        }
        let imported = &report.sources[1];
        assert!(
            imported
                .report
                .actual
                .checks
                .iter()
                .any(|check| check.status == CoverageDimensionStatus::Failed)
        );
        assert!(
            imported
                .report
                .actual
                .checks
                .iter()
                .all(|check| check.status != CoverageDimensionStatus::TestedComplete)
        );
        assert!(
            report
                .problems
                .iter()
                .any(|problem| problem.source_run_id == report.sources[0].run_id)
        );
        assert!(
            report
                .problems
                .iter()
                .any(|problem| problem.source_run_id == imported.run_id)
        );
        assert_eq!(serde_json::to_value(&case).unwrap(), before);
    }

    #[test]
    fn repeated_historical_observations_stay_separate_and_unselected_run_is_excluded() {
        let (temp, storage, case, request) = fixture();
        let old_ids = ids(&case);
        let old_report =
            preview_selected_run_report(&case, &old_ids, &ExportOptions::default()).unwrap();
        let updated = import_external_scanner_reports(
            &storage,
            &temp.path().join("artifacts"),
            &case.id,
            &[request],
        )
        .unwrap();
        let all_ids = ids(&updated);
        let same_selection =
            preview_selected_run_report(&updated, &old_ids, &ExportOptions::default()).unwrap();
        assert_eq!(
            serde_json::to_value(&old_report.sources).unwrap(),
            serde_json::to_value(&same_selection.sources).unwrap()
        );
        assert!(
            !serde_json::to_string(&same_selection)
                .unwrap()
                .contains(&all_ids[2])
        );
        let repeated =
            preview_selected_run_report(&updated, &all_ids[1..], &ExportOptions::default())
                .unwrap();
        assert_eq!(repeated.problems.len(), 2);
        assert_eq!(
            repeated.problems[0].representative_finding_id,
            repeated.problems[1].representative_finding_id
        );
        assert_ne!(
            repeated.problems[0].source_run_id,
            repeated.problems[1].source_run_id
        );
        assert_eq!(repeated.summary.sources_with_incomplete_coverage, 2);
        let evidence: Vec<_> = repeated
            .sources
            .iter()
            .map(|source| &source.report.findings[0].evidence_references[0])
            .collect();
        assert_ne!(evidence[0].engine_run_id, evidence[1].engine_run_id);
        assert_eq!(
            evidence[0].observed_at.to_rfc3339(),
            "2026-10-21T12:00:00+00:00"
        );
    }

    #[test]
    fn selection_requires_unique_same_case_terminal_sources_and_no_raw_attachments() {
        let (_temp, _storage, mut case, _request) = fixture();
        let selected = ids(&case);
        let options = ExportOptions::default();
        for invalid in [
            vec![],
            vec![selected[0].clone()],
            vec![selected[0].clone(); 2],
            vec![selected[0].clone(), "missing".into()],
            vec![selected[0].clone(); 17],
        ] {
            assert!(preview_selected_run_report(&case, &invalid, &options).is_err());
        }
        let mut raw = ExportOptions::default();
        raw.include_raw_artifacts = true;
        assert!(preview_selected_run_report(&case, &selected, &raw).is_err());
        let saved_case_id = case.scan_runs[1].case_id.clone();
        case.scan_runs[1].case_id = "another-case".into();
        assert!(preview_selected_run_report(&case, &selected, &options).is_err());
        case.scan_runs[1].case_id = saved_case_id;
        case.scan_runs[1].engine_runs[0].status = EngineRunStatus::Running;
        assert!(preview_selected_run_report(&case, &selected, &options).is_err());
        case.scan_runs[1].engine_runs[0].status = EngineRunStatus::PartiallyCompleted;
        case.scan_runs[1].completed_at = None;
        assert!(preview_selected_run_report(&case, &selected, &options).is_err());
    }

    #[test]
    fn html_and_json_are_escaped_redacted_private_no_overwrite_and_read_only() {
        let (temp, _storage, mut case, _request) = fixture();
        case.title = "<script>project-secret</script>".into();
        let selected = ids(&case);
        let before = serde_json::to_value(&case).unwrap();
        for locale in [ReportLocale::En, ReportLocale::ZhHant] {
            let options = ExportOptions {
                locale,
                ..Default::default()
            };
            let path = temp
                .path()
                .join(format!("combined-{}.html", locale.as_str()));
            let receipt = export_selected_run_report(
                &case,
                &selected,
                SelectedRunReportFormat::Html,
                &path,
                &options,
            )
            .unwrap();
            assert_eq!(receipt.selected_run_ids, selected);
            let html = std::fs::read_to_string(&path).unwrap();
            assert!(html.contains("Untrusted command execution"));
            assert!(!html.contains("MUST NEVER EXECUTE"));
            assert!(!html.contains("project-secret"));
            assert!(!html.contains("<script>"));
            assert!(html.contains("2026-10-21T12:00:00+00:00"));
            assert_eq!(receipt.sha256, hex::encode(Sha256::digest(html.as_bytes())));
            assert!(
                export_selected_run_report(
                    &case,
                    &selected,
                    SelectedRunReportFormat::Html,
                    &path,
                    &options
                )
                .is_err()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
                    0
                );
            }
        }
        let options = ExportOptions {
            redaction: RedactionProfile::None,
            ..Default::default()
        };
        let report = preview_selected_run_report(&case, &selected, &options).unwrap();
        let html = render_html(&report, ReportLocale::En).unwrap();
        assert!(html.contains("&lt;script&gt;project-secret&lt;/script&gt;"));
        assert!(!html.contains("<script>"));
        let destination = temp.path().join("combined.json");
        export_selected_run_report(
            &case,
            &selected,
            SelectedRunReportFormat::Json,
            &destination,
            &options,
        )
        .unwrap();
        let reopened: SelectedRunReport =
            serde_json::from_slice(&std::fs::read(destination).unwrap()).unwrap();
        assert_eq!(reopened.selected_run_ids, selected);
        assert_eq!(
            reopened.sources[1].report.findings[0].evidence_references[0]
                .observed_at
                .to_rfc3339(),
            "2026-10-21T12:00:00+00:00"
        );
        assert_eq!(serde_json::to_value(&case).unwrap(), before);
    }
    #[test]
    fn generic_completion_keeps_incident_limits_in_summary_and_visible_source_html() {
        let (_temp, _storage, mut case, _request) = fixture();
        case.scan_runs[0].campaign_id = Some(crate::incident_focus::INCIDENT_FOCUS_ID.into());
        let mut report =
            preview_selected_run_report(&case, &ids(&case), &ExportOptions::default()).unwrap();
        let first = &report.sources[0];
        for asset in &report.assets {
            if let Some(occurrence) = asset
                .sources
                .iter()
                .find(|entry| entry.run_id == first.run_id)
            {
                let generic = first
                    .report
                    .coverage_gaps
                    .iter()
                    .filter(|gap| gap.target_asset_ids.contains(&asset.asset_id))
                    .count();
                let incident = first
                    .report
                    .incident_focus
                    .as_ref()
                    .unwrap()
                    .issues
                    .iter()
                    .filter(|issue| {
                        issue.asset_id.as_ref() == Some(&asset.asset_id)
                            && issue.status
                                != crate::incident_focus::IncidentCoverageStatus::UpstreamMatch
                    })
                    .count();
                assert_eq!(occurrence.coverage_gap_count, generic + incident);
            }
        }
        let source = &mut report.sources[0];
        // Isolate the distinction: generic execution can be complete while no
        // upstream detector established an individual incident's disposition.
        source.report.state.summary = BeginnerReportSummary::Complete;
        source.report.coverage_gaps.clear();
        let campaign = source.report.incident_focus.as_ref().unwrap();
        assert!(
            campaign
                .issues
                .iter()
                .any(|issue| issue.status
                    == crate::incident_focus::IncidentCoverageStatus::NotTested)
        );
        assert!(source_has_coverage_limits(source));
        for locale in [ReportLocale::En, ReportLocale::ZhHant] {
            let html = render_html(&report, locale).unwrap();
            let visible_sources = html.split("<footer>").next().unwrap();
            assert!(visible_sources.contains("data-incident-focus"));
            assert!(visible_sources.contains(text(locale, "Not tested", "未測試")));
            assert!(visible_sources.contains(text(
                locale,
                "Issues requiring further checking",
                "需要進一步檢查的項目"
            )));
            assert!(visible_sources.contains(text(
                locale,
                "Incident coverage and next actions",
                "事件涵蓋範圍與下一步"
            )));
        }
    }
}
