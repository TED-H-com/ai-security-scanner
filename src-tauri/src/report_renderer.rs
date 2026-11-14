//! Shared deterministic HTML and canonical JSON report rendering.
//!
//! Rendering consumes a complete caller-owned case context, export settings,
//! and already verified attachment bytes. It never loads current storage,
//! contacts scan targets, or starts scanner/AI work. Snapshot replay must use
//! the renderer identity that produced its frozen inputs and saved outputs.

use crate::beginner_report::{
    ActualCheck, BEGINNER_MASTER_REPORT_SCHEMA_VERSION, BeginnerFinding, BeginnerInventoryItem,
    BeginnerInventoryItemKind, BeginnerMasterReport, BeginnerReportSummary, CheckResultKind,
    CoverageDimensionStatus, CoverageGap, CoverageGapClass, CoverageGapKind, DataAvailability,
    FindingSnapshotSource, NextActionCode, ReportScanStage, RequestedLimitSource,
    finding_unconfirmed_by_coverage,
};
use crate::domain::{
    AssessmentCase, AssetKind, FindingDiff, FindingDiffReasonCode, FindingDiffStatus,
    FindingFamily, Id, ScanRun,
};
use crate::error::AppResult;
use crate::execution_coverage::WorkUnitOutcome;
use crate::export::{ExportOptions, ReportLocale, beginner_report_for_export, case_for_export};
use crate::exporters::export_master_framework_report;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Recipe family. Exact replay also requires the trusted core/source digest.
pub const RENDERER_RECIPE_VERSION: &str = "ai-security-scanner.report-renderer/v1";

/// A verified ZIP attachment frozen alongside the report's full case context.
/// The producer verifies task selection and SHA-256 before calling the renderer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HtmlReportAttachment {
    pub engine_id: String,
    pub engine_run_id: String,
    pub file_names: Vec<String>,
    #[serde(with = "attachment_base64")]
    pub bytes: Vec<u8>,
    pub sha256: String,
}

impl From<crate::report_attachments::ReportAttachment> for HtmlReportAttachment {
    fn from(attachment: crate::report_attachments::ReportAttachment) -> Self {
        Self {
            engine_id: attachment.engine_id,
            engine_run_id: attachment.engine_run_id,
            file_names: attachment.file_names,
            bytes: attachment.bytes,
            sha256: attachment.sha256,
        }
    }
}

mod attachment_base64 {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        STANDARD
            .decode(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

pub(crate) fn enum_key<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

pub(crate) fn case_for_document_export(
    case: &AssessmentCase,
    options: &ExportOptions,
) -> AppResult<AssessmentCase> {
    case_for_export(case, options.redaction)
}

/// Render the existing canonical report contract from the supplied frozen case.
pub fn render_canonical_json(
    case: &AssessmentCase,
    run_id: &str,
    options: &ExportOptions,
) -> AppResult<Vec<u8>> {
    let report = beginner_report_for_export(case, run_id, options.redaction)?;
    serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": BEGINNER_MASTER_REPORT_SCHEMA_VERSION,
        "product_name": "ai-security-scanner",
        "product_version": crate::product_version::current(),
        "export_kind": "beginner_master_report",
        "selected_run_id": report.run_id.clone(),
        "redaction_profile": options.redaction.as_str(),
        "raw_artifact_bytes_included": false,
        "notice": report.framework_notice.non_certification.clone(),
        "report": report,
    }))
    .map_err(Into::into)
}

pub(crate) fn readable_report_time(value: &DateTime<Utc>) -> String {
    value.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

#[derive(Clone, Copy)]
pub(crate) struct HtmlReportCatalog {
    pub(crate) locale: crate::export::ReportLocale,
}

impl HtmlReportCatalog {
    pub(crate) fn new(locale: crate::export::ReportLocale) -> Self {
        Self { locale }
    }

    pub(crate) fn text<'a>(&self, en: &'a str, zh_hant: &'a str) -> &'a str {
        match self.locale {
            crate::export::ReportLocale::En => en,
            crate::export::ReportLocale::ZhHant => zh_hant,
        }
    }

    /// A run-in label and its colon: "Severity: " in English and "嚴重程度："
    /// in Chinese, where the full-width colon carries its own spacing.
    pub(crate) fn label(&self, label: &str) -> String {
        format!("{label}{}", self.text(": ", "："))
    }

    /// A run-in label set in bold, as the report sets most of them. The
    /// English space follows the element; Chinese has none.
    pub(crate) fn strong_label(&self, label: &str) -> String {
        format!(
            "<strong>{label}{}</strong>{}",
            self.text(":", "："),
            self.text(" ", "")
        )
    }

    /// Full-width punctuation carries its own spacing; an English sentence
    /// left in a Chinese report still takes the space.
    pub(crate) fn gap_after(&self, preceding: &str) -> &'static str {
        match (self.locale, preceding.chars().next_back()) {
            (crate::export::ReportLocale::ZhHant, Some(last))
                if "。！？；：」』）".contains(last) =>
            {
                ""
            }
            _ => " ",
        }
    }

    /// The same, in italics.
    pub(crate) fn em_label(&self, label: &str) -> String {
        format!(
            "<em>{label}{}</em>{}",
            self.text(":", "："),
            self.text(" ", "")
        )
    }

    pub(crate) fn html_lang(&self) -> &'static str {
        self.locale.as_str()
    }

    pub(crate) fn format_time(&self, value: &DateTime<Utc>) -> String {
        match self.locale {
            crate::export::ReportLocale::En => readable_report_time(value),
            crate::export::ReportLocale::ZhHant => {
                value.format("%Y年%m月%d日 %H:%M:%S UTC").to_string()
            }
        }
    }

    pub(crate) fn format_number(&self, value: usize) -> String {
        // Grouping separators belong in visible labels, never in `id` or `href`.
        let digits = value.to_string();
        let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
        for (index, character) in digits.chars().enumerate() {
            if index > 0 && (digits.len() - index).is_multiple_of(3) {
                grouped.push(',');
            }
            grouped.push(character);
        }
        grouped
    }

    pub(crate) fn format_time_range(&self, from: &str, until: &str) -> String {
        match self.locale {
            crate::export::ReportLocale::En => format!("{from} to {until}"),
            crate::export::ReportLocale::ZhHant => format!("{from} 至 {until}"),
        }
    }

    pub(crate) fn format_mapping_provenance(
        &self,
        sha256: &str,
        reviewed_at: &str,
        review_process: &str,
    ) -> String {
        match self.locale {
            crate::export::ReportLocale::En => {
                format!(" · Catalog SHA-256 {sha256} · Reviewed {reviewed_at} via {review_process}")
            }
            crate::export::ReportLocale::ZhHant => {
                format!(" · 目錄 SHA-256 {sha256} · 於 {reviewed_at} 透過 {review_process} 檢閱")
            }
        }
    }

    pub(crate) fn report_stage(&self, stage: &ReportScanStage) -> &'static str {
        match stage {
            ReportScanStage::ConnectionDiagnostic => self.text(
                "Connection test (not a vulnerability scan)",
                "連線測試（不是漏洞掃描）",
            ),
            ReportScanStage::QuickDiscovery => self.text("Quick discovery", "快速探索"),
            ReportScanStage::Inventory => self.text("Inventory", "資產盤點"),
            ReportScanStage::Deep => self.text("Deep scan", "深度掃描"),
        }
    }

    pub(crate) fn asset_kind(&self, kind: &AssetKind) -> &'static str {
        match kind {
            AssetKind::CloudOrganization => self.text("Cloud organization", "雲端組織"),
            AssetKind::CloudAccount => self.text("Cloud account", "雲端帳戶"),
            AssetKind::Subscription => self.text("Subscription", "訂閱"),
            AssetKind::Project => self.text("Project", "專案"),
            AssetKind::Tenant => self.text("Tenant", "租用戶"),
            AssetKind::Domain => self.text("Domain", "網域"),
            AssetKind::IpAddress => self.text("IP address", "IP 位址"),
            AssetKind::Host => self.text("Server or workstation", "伺服器或工作站"),
            AssetKind::WebService => self.text("Web service", "網站服務"),
            AssetKind::CloudResource => self.text("Cloud resource", "雲端資源"),
            AssetKind::Identity => self.text("Identity", "身分"),
            AssetKind::Repository => self.text("Repository", "程式碼儲存庫"),
            AssetKind::FileSystem => self.text("File system", "檔案系統"),
            AssetKind::IacProject => {
                self.text("Infrastructure-as-code project", "基礎設施即程式碼專案")
            }
            AssetKind::ContainerImage => self.text("Container image", "容器映像"),
            AssetKind::ContainerRegistry => self.text("Container registry", "容器映像登錄檔"),
            AssetKind::KubernetesCluster => self.text("Kubernetes cluster", "Kubernetes 叢集"),
            AssetKind::AiModelEndpoint => self.text("AI model endpoint", "AI 模型端點"),
            AssetKind::Other => self.text("Other asset", "其他資產"),
        }
    }

    pub(crate) fn coverage_status(&self, status: &CoverageDimensionStatus) -> &'static str {
        match status {
            CoverageDimensionStatus::TestedComplete => self.text("Completed", "已完成"),
            CoverageDimensionStatus::TestedPartial => self.text("Partly completed", "部分完成"),
            CoverageDimensionStatus::Failed => self.text("Failed", "失敗"),
            CoverageDimensionStatus::TimedOut => self.text("Timed out", "逾時"),
            CoverageDimensionStatus::Cancelled => self.text("Cancelled", "已取消"),
            CoverageDimensionStatus::NotTested => self.text("Not tested", "未測試"),
        }
    }

    pub(crate) fn work_unit_outcome(&self, outcome: &WorkUnitOutcome) -> &'static str {
        match outcome {
            WorkUnitOutcome::TestedComplete => self.text("Completed", "已完成"),
            WorkUnitOutcome::TestedPartial => self.text("Partly completed", "部分完成"),
            WorkUnitOutcome::Failed => self.text("Failed", "失敗"),
            WorkUnitOutcome::TimedOut => self.text("Timed out", "逾時"),
            WorkUnitOutcome::Cancelled => self.text("Cancelled", "已取消"),
            WorkUnitOutcome::NotTested => self.text("Not tested", "未測試"),
        }
    }

    pub(crate) fn gap_kind(&self, kind: &CoverageGapKind) -> &'static str {
        match kind {
            CoverageGapKind::NotTested => self.text("Not tested", "未測試"),
            CoverageGapKind::Failed => self.text("Failed", "失敗"),
            CoverageGapKind::TimedOut => self.text("Timed out", "逾時"),
            CoverageGapKind::Cancelled => self.text("Cancelled", "已取消"),
            CoverageGapKind::Excluded => self.text("Excluded", "已排除"),
            CoverageGapKind::Truncated => {
                self.text("Reduced by a saved limit", "受已保存的限制而縮減")
            }
            CoverageGapKind::Unavailable => self.text("Details unavailable", "詳細資料無法取得"),
            CoverageGapKind::Unattributed => {
                self.text("Not linked to your asset", "未連結到你的資產")
            }
            CoverageGapKind::ManualReview => self.text("No automated verdict", "未回傳自動判定"),
        }
    }

    pub(crate) fn limit_source(&self, source: &RequestedLimitSource) -> &'static str {
        match source {
            RequestedLimitSource::FrozenTaskContract => {
                self.text("saved task settings", "已保存的工作設定")
            }
            RequestedLimitSource::FrozenScopeGrant => {
                self.text("saved scope approval", "已保存的範圍授權")
            }
        }
    }

    pub(crate) fn finding_source(&self, source: &FindingSnapshotSource) -> &'static str {
        match source {
            FindingSnapshotSource::FrozenSelectedRun => {
                self.text("Saved result from this run", "本輪已保存的結果")
            }
            FindingSnapshotSource::CurrentCanonicalLegacyFallback => self.text(
                "Current saved finding (legacy run)",
                "目前保存的問題（舊版掃描）",
            ),
            FindingSnapshotSource::ObservationOnly => {
                self.text("Saved observation only", "只有已保存的觀察紀錄")
            }
        }
    }

    pub(crate) fn identifier(&self, value: &str) -> String {
        if self.locale == crate::export::ReportLocale::En {
            return readable_identifier(value);
        }
        match value.to_ascii_lowercase().as_str() {
            "critical" => "嚴重".into(),
            "high" => "高".into(),
            "medium" => "中".into(),
            "low" => "低".into(),
            "informational" | "info" => "資訊".into(),
            // The source gave no recognized rating. Fell through to
            // `readable_identifier` before, so a Chinese report labelled such a
            // finding "Unknown" beside otherwise translated ratings.
            "unknown" => "未知".into(),
            "confirmed" => "已確認".into(),
            "high_confidence" => "高信心".into(),
            "moderate" => "中等".into(),
            "completed" => "已完成".into(),
            "partial" => "部分完成".into(),
            "failed" => "失敗".into(),
            "cancelled" => "已取消".into(),
            "unavailable" => "無法取得".into(),
            "available" => "可取得".into(),
            "created" => "已建立".into(),
            "updated" => "已更新".into(),
            "removed" => "已移除".into(),
            // The rest of `EngineRunStatus`. Only the three terminal states
            // were listed, so a run frozen while partly finished printed
            // "Partially Completed" beside translated siblings.
            "not_executed" => "未執行".into(),
            "queued" => "已排入佇列".into(),
            "preparing" => "準備中".into(),
            "running" => "執行中".into(),
            "paused" => "已暫停".into(),
            "partially_completed" => "部分完成".into(),
            // `EvidenceKind`, under a translated "證據類型" heading.
            "configuration" => "設定".into(),
            "observation" => "觀察紀錄".into(),
            "external_validation" => "外部驗證".into(),
            "source_code" => "原始碼".into(),
            "package_inventory" => "套件盤點".into(),
            "user_declaration" => "使用者聲明".into(),
            "raw_tool_output" => "掃描工具原始輸出".into(),
            // `DistributionMode`, in the execution-identity provenance line.
            "bundled_image" => "隨附映像".into(),
            "pull_pinned_image" => "拉取已釘選映像".into(),
            "build_from_pinned_source" => "由已釘選來源建置".into(),
            "external_executable" => "外部執行檔".into(),
            // Task phases, under a translated "階段" label, and task error
            // codes, under a translated "錯誤碼" label. Written whole rather
            // than grown on sighting the way the lists above were: both are
            // literals this build's own orchestrator writes, so the set is
            // knowable now, and the reader who meets one is reading the run
            // that went wrong -- the worst moment to be handed an English key.
            // The two vocabularies overlap; one arm serves both.
            "active_fixture" => "使用中的測試樣本".into(),
            "cancel_requested" => "已要求取消".into(),
            "captured_awaiting_adapter" => "已擷取，等待轉接器處理".into(),
            "capturing_artifacts" => "擷取產出中".into(),
            "cleanup_identity_unavailable" => "取不到執行環境識別，無法清理".into(),
            "cleanup_pending" => "尚待清理".into(),
            "cleanup_reconciled" => "清理已核對完成".into(),
            "connecting" => "連線中".into(),
            "dispatch_activated" => "已開始派送".into(),
            "interrupted_restart" => "中斷後重新啟動".into(),
            "interrupted_restart_cleanup_identity_unavailable" => {
                "中斷後重新啟動；取不到執行環境識別，無法清理".into()
            }
            "interrupted_restart_cleanup_pending" => "中斷後重新啟動；尚待清理".into(),
            "preflight_preparing" => "前置檢查準備中".into(),
            "queued_for_next_phase" => "已排入下一階段佇列".into(),
            "queued_for_resume" => "已排入接續佇列".into(),
            "results_partial" => "結果只有一部分".into(),
            "cancelled_before_dispatch" => "派送前已取消".into(),
            "cancelled_without_observation" => "取消時尚未產生任何觀察".into(),
            "continuation_state_changed" => "接續時狀態已改變".into(),
            "coverage_unverified_after_restart" => "重新啟動後涵蓋範圍未經確認".into(),
            "coverage_unverified_retryable" => "涵蓋範圍未經確認，可重試".into(),
            "desktop_process_restarted" => "桌面程式已重新啟動".into(),
            "execution_failed" => "執行失敗".into(),
            "execution_partially_completed" => "執行只完成一部分".into(),
            "image_pull_denied" => "映像拉取遭拒".into(),
            "legacy_request_requires_new_scan" => "舊版請求需要重新掃描".into(),
            "localhost_probe_interrupted" => "本機探測遭中斷".into(),
            "localhost_tcp_timed_out" => "本機 TCP 連線逾時".into(),
            "manifest_unavailable" => "取不到 manifest".into(),
            "normalization_incomplete" => "正規化未完成".into(),
            "pause_context" => "暫停時的狀態".into(),
            "preflight_interrupted" => "前置檢查遭中斷".into(),
            "preserved_prior_error_code" => "保留先前的錯誤碼".into(),
            "preflight_failed" => "前置檢查失敗".into(),
            "resume_release_incompatible" => "版本不相容，無法接續".into(),
            "resume_scope_changed" => "範圍已改變，無法接續".into(),
            "resume_scope_unavailable" => "取不到原範圍，無法接續".into(),
            "resume_work_plan_invalid" => "工作計畫無效，無法接續".into(),
            "runtime_cleanup_identity_unavailable" => "取不到執行環境識別，無法清理".into(),
            "runtime_cleanup_pending" => "執行環境尚待清理".into(),
            // `LocalhostTcpOutcome`.
            "reachable" => "可連線".into(),
            "closed" => "已關閉".into(),
            "timed_out" => "逾時".into(),
            _ => readable_identifier(value),
        }
    }
}

/// The coarse per-target coordinate every completed catalog check produces
/// when the case froze no finer executed dimension.
const COMPLETED_COORDINATE_DIMENSION: &str = "completed check-to-target coordinate";

/// English display for one stored coverage or tested-dimension name.
///
/// These names are composed prose, and they often open with an engine's own
/// identifier. `readable_identifier` below title-cases a word and splits it on
/// its hyphens, which is right for `not_tested` and wrong here: it printed
/// "Completed check To Target coordinate" once per finished check, and named
/// five scanners "Httpx", "Kics", "Scoutsuite", "Scubagear" and "Kube Bench".
/// Name the engine the way upstream spells it, and otherwise change nothing
/// but the first letter. The Chinese side already leaves this text alone.
/// Spells the scanner a composed coverage name is about the way the rest of
/// the report spells it, and leaves anything else byte for byte.
///
/// The backend writes these names around the engine's id. English prettifies
/// them on the way out, but the Traditional Chinese renderers translate the
/// kind and interpolate the identifier they were handed, so a Chinese reader
/// saw "checkov" in the limits and coverage rows while the tested-checks list
/// two sections above said "Checkov". This runs before those renderers.
fn engine_named(name: &str) -> String {
    let head = name.split([':', ' ']).next().unwrap_or_default();
    match crate::registry::builtin_display_name(head) {
        Some(engine) => format!("{engine}{}", &name[head.len()..]),
        None => name.to_owned(),
    }
}

pub(crate) fn readable_dimension(dimension: &str) -> String {
    let head = dimension.split([':', ' ']).next().unwrap_or_default();
    if crate::registry::builtin_display_name(head).is_some() {
        return engine_named(dimension);
    }
    let mut characters = dimension.chars();
    match characters.next() {
        Some(first) => first.to_uppercase().chain(characters).collect(),
        None => String::new(),
    }
}

pub(crate) fn report_check_label(check: &str, catalog: HtmlReportCatalog) -> String {
    if check == "Cloudflare source audit" {
        catalog
            .text("Cloudflare source audit", "Cloudflare 原始碼稽核")
            .into()
    } else {
        readable_dimension(check)
    }
}

pub(crate) fn readable_identifier(value: &str) -> String {
    let words = value
        .split(['_', '-'])
        .filter(|word| !word.is_empty())
        .map(|word| match word.to_ascii_lowercase().as_str() {
            "api" => "API".into(),
            "http" => "HTTP".into(),
            "https" => "HTTPS".into(),
            "iac" => "IaC".into(),
            "id" => "ID".into(),
            "ip" => "IP".into(),
            "ssh" => "SSH".into(),
            "tcp" => "TCP".into(),
            "tls" => "TLS".into(),
            "udp" => "UDP".into(),
            _ => {
                let mut characters = word.chars();
                match characters.next() {
                    Some(first) => first.to_uppercase().chain(characters).collect(),
                    None => String::new(),
                }
            }
        })
        .collect::<Vec<String>>();
    if words.is_empty() {
        value.into()
    } else {
        words.join(" ")
    }
}

/// English display for one requested-limit name.
///
/// Every one of these is composed as `{identifier} {what was limited}`: an
/// engine id for a saved task setting, an asset id for a saved scope grant.
/// Both are identifiers the report spells elsewhere, and title-casing them
/// broke both spellings at once -- the same run's "Limits" list said
/// "Cloudquery", "Kube Bench", "Scoutsuite", "Trufflehog", "Httpx" and "Kics"
/// beside a "Requested checks" list naming those six correctly, and it turned
/// the reader's own target into "Https://portal.example.test:443".
fn readable_limit_name(name: &str, labels: &BTreeMap<Id, String>) -> String {
    let (head, rest) = name.split_once(' ').unwrap_or((name, ""));
    let separator = if rest.is_empty() { "" } else { " " };
    if let Some(engine) = crate::registry::builtin_display_name(head) {
        return format!("{engine}{separator}{rest}");
    }
    if let Some(label) = labels.get(head) {
        return format!("{label}{separator}{rest}");
    }
    readable_identifier(&replace_target_ids(name, labels))
}

/// Who a limit was written against, and the limit it sets.
///
/// Most limit names are composed as "<holder> <what>", where the holder is a
/// built-in engine or an approved target. Three are whole names with no holder
/// at all -- "endpoint", "connection timeout", "application payload" -- and
/// splitting those on their first space would invent one, so a head that names
/// neither an engine nor a target gives `None` and the limit stays whole.
fn limit_holder_and_subject(name: &str, labels: &BTreeMap<Id, String>) -> Option<(String, String)> {
    let (head, rest) = name.split_once(' ')?;
    if rest.is_empty() {
        return None;
    }
    if let Some(engine) = crate::registry::builtin_display_name(head) {
        return Some((engine.to_owned(), rest.to_owned()));
    }
    labels
        .get(head)
        .map(|label| (label.clone(), rest.to_owned()))
}

/// The coverage name one gap row leads with, as the reader sees it.
///
/// Chinese keeps the stored text as composed; English names the engine and
/// capitalizes the sentence. Neither splits an identifier on its hyphens:
/// "naabu-tcp" has to keep matching what the reader sees in the scanner's own
/// output. The step list below reuses this so a step and the row it closes
/// name the same coverage the same way.
fn displayed_dimension(
    dimension: &str,
    catalog: HtmlReportCatalog,
    target_labels: &BTreeMap<Id, String>,
) -> String {
    match catalog.locale {
        crate::export::ReportLocale::ZhHant => replace_target_ids(dimension, target_labels),
        _ => readable_dimension(&replace_target_ids(dimension, target_labels)),
    }
}

pub(crate) fn readable_target_labels(
    report: &BeginnerMasterReport,
    catalog: HtmlReportCatalog,
) -> BTreeMap<Id, String> {
    let mut labels = BTreeMap::new();
    let mut next_number = 1usize;
    for target in &report.requested.targets {
        let label = target
            .label
            .as_deref()
            .filter(|label| !label.trim().is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{} {next_number}", catalog.text("Target", "目標")));
        labels.entry(target.asset_id.clone()).or_insert(label);
        next_number += 1;
    }
    for asset_id in report
        .actual
        .checks
        .iter()
        .flat_map(|check| &check.target_asset_ids)
        .chain(
            report
                .findings
                .iter()
                .flat_map(|finding| &finding.target_asset_ids),
        )
        .chain(
            report
                .coverage_gaps
                .iter()
                .flat_map(|gap| &gap.target_asset_ids),
        )
        .chain(&report.inventory.asset_ids)
    {
        if !labels.contains_key(asset_id) {
            labels.insert(
                asset_id.clone(),
                format!("{} {next_number}", catalog.text("Target", "目標")),
            );
            next_number += 1;
        }
    }
    labels
}

fn readable_target_list(
    asset_ids: &[Id],
    labels: &BTreeMap<Id, String>,
    catalog: HtmlReportCatalog,
) -> String {
    target_list(asset_ids, labels, catalog, html_escape)
}

/// The same list, offering a break opportunity inside each identity.
///
/// Only for a column whose width is fixed. Where a column is sized by what is
/// in it, a break opportunity is an invitation to wrap: offering one in the
/// tested table and the requested-target list let their targets fold onto
/// second lines and cost five pages across the four reports.
fn breakable_target_list(
    asset_ids: &[Id],
    labels: &BTreeMap<Id, String>,
    catalog: HtmlReportCatalog,
) -> String {
    target_list(asset_ids, labels, catalog, html_escape_breakable_identity)
}

fn target_list(
    asset_ids: &[Id],
    labels: &BTreeMap<Id, String>,
    catalog: HtmlReportCatalog,
    escape: fn(&str) -> String,
) -> String {
    if asset_ids.is_empty() {
        return catalog.text("none retained", "未保留").into();
    }
    asset_ids
        .iter()
        .map(|asset_id| {
            escape(
                labels
                    .get(asset_id)
                    .map(String::as_str)
                    .unwrap_or(catalog.text("Saved target", "已保存的目標")),
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HtmlAssetResultStatus {
    ProblemsFound,
    NoProblemsInCompletedChecks,
    IncompleteOrFailed,
    NotTested,
}

/// The asset row's own next step: the sentence the report recorded for this
/// gap, in the reader's language.
///
/// The action code still decides where a step goes. It does not replace the
/// recorded sentence with one shared by every gap of that code. A skipped
/// check and a failed check can share a code and still tell the reader
/// different things. An empty sentence leaves the row without a step of its
/// own, and the state line under the table says what that state implies.
pub(crate) fn html_gap_next_action(gap: &CoverageGap, catalog: HtmlReportCatalog) -> String {
    if gap.next_action.trim().is_empty() {
        return String::new();
    }
    match (catalog.locale, gap.unattributed.as_ref()) {
        (crate::export::ReportLocale::ZhHant, Some(unattributed)) => {
            crate::finding_narrative::unattributed_gap_zh_hant("", unattributed).2
        }
        (crate::export::ReportLocale::ZhHant, None) => {
            crate::finding_narrative::coverage_gap_prose_zh_hant(&gap.next_action)
                .unwrap_or_else(|| gap.next_action.clone())
        }
        (crate::export::ReportLocale::En, _) => gap.next_action.clone(),
    }
}

/// The assets a coverage row is about, where the report needs them said.
///
/// Each check runs on one asset, so a check that failed on three websites is
/// three rows, and they read "Failed — Nuclei" three times over. The asset is
/// what tells them apart. A report about one asset has nothing to tell apart,
/// and a row about the whole run names no asset.
fn html_gap_targets(
    asset_ids: &[Id],
    labels: &BTreeMap<Id, String>,
    catalog: HtmlReportCatalog,
) -> Option<String> {
    (labels.len() > 1 && !asset_ids.is_empty())
        .then(|| target_list(asset_ids, labels, catalog, str::to_owned))
}

/// A coverage row's name in the reader's language, as its row prints it.
fn html_gap_name(
    gap: &CoverageGap,
    catalog: HtmlReportCatalog,
    labels: &BTreeMap<Id, String>,
) -> String {
    displayed_dimension(
        &match catalog.locale {
            crate::export::ReportLocale::ZhHant => {
                crate::finding_narrative::coverage_dimension_zh_hant(&engine_named(&gap.dimension))
            }
            _ => crate::finding_narrative::coverage_dimension_english(&gap.dimension),
        },
        catalog,
        labels,
    )
}

/// The coverage rows a gap-derived step closes, each name once with every
/// asset it closes a row on.
///
/// A step can close more than one row -- two cancelled checks share a retry
/// -- and every row it closes is named. A check that failed on three
/// websites read "Nuclei; Nuclei; Nuclei" before its names were merged.
fn html_step_closes(
    report: &BeginnerMasterReport,
    step: &crate::beginner_report::BeginnerNextStep,
    catalog: HtmlReportCatalog,
    labels: &BTreeMap<Id, String>,
) -> Vec<String> {
    if step.finding_id.is_some() || step.unattributed.is_some() {
        return Vec::new();
    }
    let mut closes: Vec<(String, Vec<Id>)> = Vec::new();
    for gap in report
        .coverage_gaps
        .iter()
        .filter(|gap| gap.unattributed.is_none() && gap.next_action == step.action)
    {
        let name = html_gap_name(gap, catalog, labels);
        let index = match closes.iter().position(|(named, _)| *named == name) {
            Some(index) => index,
            None => {
                closes.push((name, Vec::new()));
                closes.len() - 1
            }
        };
        let asset_ids = &mut closes[index].1;
        for asset_id in &gap.target_asset_ids {
            if !asset_ids.contains(asset_id) {
                asset_ids.push(asset_id.clone());
            }
        }
    }
    closes
        .into_iter()
        .map(
            |(name, asset_ids)| match html_gap_targets(&asset_ids, labels, catalog) {
                Some(targets) => format!("{name} · {targets}"),
                None => name,
            },
        )
        .collect()
}

/// A gap's action, with the coverage it is about in parentheses.
///
/// "Retry this check." names nothing, and wherever it stood away from its
/// coverage row -- the summary's first thing to do, an asset's own step --
/// nothing near it said which check. Nothing to name, or no action, leaves
/// the action as it is.
pub(crate) fn html_action_about(
    action: &str,
    about: &[String],
    catalog: HtmlReportCatalog,
) -> String {
    if about.is_empty() || action.trim().is_empty() {
        return action.to_owned();
    }
    let about = about.join(catalog.text("; ", "；"));
    match catalog.locale {
        crate::export::ReportLocale::ZhHant => match action.strip_suffix('。') {
            Some(sentence) => format!("{sentence}（{about}）。"),
            None => format!("{action}（{about}）"),
        },
        _ => match action.strip_suffix('.') {
            Some(sentence) => format!("{sentence} ({about})."),
            None => format!("{action} ({about})"),
        },
    }
}

/// Read order for the asset list: what was found, then what is unknown, then
/// what is clean. A problem the run actually found is the thing a beginner can
/// act on now; an incomplete check is a gap they have to close before they
/// know. The clean assets are the answer to "is anything left", so they go
/// last rather than being interleaved with the two that need work.
fn html_asset_result_rank(status: HtmlAssetResultStatus) -> u8 {
    match status {
        HtmlAssetResultStatus::ProblemsFound => 0,
        HtmlAssetResultStatus::IncompleteOrFailed => 1,
        HtmlAssetResultStatus::NotTested => 2,
        HtmlAssetResultStatus::NoProblemsInCompletedChecks => 3,
    }
}

/// A completed catalog task records one exact coordinate for each asset it
/// actually checked. A sibling's failure can make the shared task partial
/// without undoing that completed security result for this asset.
fn html_check_completed_on_asset(check: &ActualCheck, asset_id: &str) -> bool {
    if check.effective_result_kind() != CheckResultKind::SecurityCheck {
        return false;
    }
    match check.status {
        CoverageDimensionStatus::TestedComplete => true,
        CoverageDimensionStatus::TestedPartial => check.tested_dimensions.iter().any(|dimension| {
            dimension.dimension == "completed check-to-target coordinate"
                && dimension.value.ends_with(&format!(" on asset {asset_id}"))
        }),
        _ => false,
    }
}

/// The cover and the asset rows use the same check-to-asset unit. A shared
/// partial task can therefore contribute a completed result for one asset
/// even though it contributes no fully completed task to coverage counts.
fn html_completed_asset_check_count(report: &BeginnerMasterReport) -> usize {
    let scoped = report
        .requested
        .targets
        .iter()
        .flat_map(|target| {
            report.actual.checks.iter().filter(move |check| {
                check.target_asset_ids.contains(&target.asset_id)
                    && html_check_status_on_asset(report, check, &target.asset_id)
                        == CoverageDimensionStatus::TestedComplete
            })
        })
        .count();
    scoped.max(report.coverage_counts.tested_complete)
}

/// These native rows describe dimensions outside the selected bounded
/// profile. A partial shared task must not make them look like unfinished
/// work on an asset with its own completed coordinate.
fn html_bounded_profile_limit(gap: &CoverageGap) -> bool {
    gap.next_action_code == NextActionCode::PreserveVisibleLimitation
        && matches!(
            gap.dimension.as_str(),
            "endpoint operating-system, package, application, and local-configuration coverage"
                | "RDP implementation, authentication/NLA, and endpoint host coverage"
                | "VNC implementation, authentication, and endpoint host coverage"
                | "SMTP server behavior, implementation, and endpoint host coverage"
                | "Telnet authentication, implementation, and endpoint host coverage"
                | "device product and firmware vulnerability coverage"
        )
}

fn html_check_status_on_asset(
    report: &BeginnerMasterReport,
    check: &ActualCheck,
    asset_id: &str,
) -> CoverageDimensionStatus {
    if check.status != CoverageDimensionStatus::TestedPartial {
        return check.status;
    }
    let mut gaps = report.coverage_gaps.iter().filter(|gap| {
        gap.class != CoverageGapClass::RecordNote
            && gap.task_id.as_deref() == Some(check.task_id.as_str())
            && gap.target_asset_ids.iter().any(|id| id == asset_id)
    });
    if !html_check_completed_on_asset(check, asset_id) {
        if gaps.clone().any(|gap| gap.kind == CoverageGapKind::Failed) {
            return CoverageDimensionStatus::Failed;
        }
        if gaps
            .clone()
            .any(|gap| gap.kind == CoverageGapKind::TimedOut)
        {
            return CoverageDimensionStatus::TimedOut;
        }
        if gaps
            .clone()
            .any(|gap| gap.kind == CoverageGapKind::Cancelled)
        {
            return CoverageDimensionStatus::Cancelled;
        }
        // Native Nuclei omits the coordinate for a sibling without saved
        // security-template execution and records an Unavailable gap for it.
        // The shared task's partial state is not evidence this website ran.
        if check.effective_result_kind() == CheckResultKind::SecurityCheck
            && check
                .tested_dimensions
                .iter()
                .any(|dimension| dimension.dimension == "completed check-to-target coordinate")
            && gaps.any(|gap| {
                matches!(
                    gap.kind,
                    CoverageGapKind::Unavailable | CoverageGapKind::NotTested
                )
            })
        {
            return CoverageDimensionStatus::NotTested;
        }
        return check.status;
    }
    let missing = gaps.any(|gap| {
        matches!(
            gap.kind,
            CoverageGapKind::Failed
                | CoverageGapKind::TimedOut
                | CoverageGapKind::Cancelled
                | CoverageGapKind::Truncated
                | CoverageGapKind::Unavailable
                | CoverageGapKind::Unattributed
        ) || (gap.kind == CoverageGapKind::NotTested
            && gap.next_action_code != NextActionCode::NoActionUnlessScopeChanges
            && !html_bounded_profile_limit(gap))
    });
    if missing {
        CoverageDimensionStatus::TestedPartial
    } else {
        CoverageDimensionStatus::TestedComplete
    }
}

/// The step a state implies, written once for the whole table.
///
/// Every asset in a state takes the same step from it, so a column carrying
/// that step was one sentence written once per row - nine times, in a run
/// with nine assets, under a heading promising something to do. What stays in
/// a row is the part that is the asset's own: the step its coverage gap calls
/// for, and the note that some of its checks did not finish. Only the states
/// that actually fell back to their own step are named, in the order the
/// table puts them.
///
/// `asset_specific` mirrors whether the table itself printed a per-row step
/// column: with no column this is the run's one step, and with a column it is
/// only the fallback for rows that did not write a step of their own.
fn html_asset_state_steps(
    states: &[HtmlAssetResultStatus],
    asset_specific: bool,
    catalog: HtmlReportCatalog,
) -> String {
    if states.is_empty() {
        return String::new();
    }
    let mut ordered = states.to_vec();
    ordered.sort_by_key(|state| html_asset_result_rank(*state));
    let steps = ordered
        .iter()
        .map(|state| {
            let (label, step) = match state {
                HtmlAssetResultStatus::ProblemsFound => (
                    catalog.text("Problems found", "發現問題"),
                    catalog.text(
                        "review this asset's highest-priority problem first",
                        "先檢視這個資產最高優先的問題",
                    ),
                ),
                HtmlAssetResultStatus::NoProblemsInCompletedChecks => (
                    catalog.text("No problems in completed checks", "已完成檢查未發現問題"),
                    catalog.text(
                        "open the completed-check scope and any missing checks",
                        "查看已完成檢查的範圍與缺少的檢查",
                    ),
                ),
                HtmlAssetResultStatus::IncompleteOrFailed => (
                    catalog.text("Incomplete or failed", "未完成或失敗"),
                    catalog.text(
                        "finish or retry this asset's remaining checks in the app",
                        "請在應用程式中完成或重試這個資產的其餘檢查",
                    ),
                ),
                HtmlAssetResultStatus::NotTested => (
                    catalog.text("Not tested", "尚未測試"),
                    catalog.text(
                        "choose an applicable security check for this asset, then scan it",
                        "為這個資產選擇適用的資安檢查，然後開始掃描",
                    ),
                ),
            };
            format!(
                "<strong>{}</strong>{}{}",
                html_escape(label),
                catalog.text(" \u{2014} ", "，"),
                html_escape(step),
            )
        })
        .collect::<Vec<_>>()
        .join(catalog.text("; ", "；"));
    let prefix = match asset_specific {
        false => catalog.text("Next step: ", "下一步："),
        true => catalog.text(
            "For rows without their own next step: ",
            "沒有另寫下一步的列：",
        ),
    };
    format!(
        "<p class=\"asset-result-steps\">{}{}{}</p>",
        prefix,
        steps,
        catalog.text(".", "。"),
    )
}
/// One framework reference's mapping identity: which catalog said so.
///
/// The version and the digest beside it are the same string for every
/// coordinate a run produces, because one embedded catalog produces them all.
/// Rendered here so the report can compare identities before deciding whether
/// to print one of them once or all of them where they sit.
fn html_mapping_identity(
    reference: &crate::beginner_report::FrameworkReference,
    catalog: HtmlReportCatalog,
) -> String {
    format!(
        "{}{}",
        reference.mapping_version,
        reference
            .mapping_provenance
            .as_ref()
            .map(|provenance| catalog.format_mapping_provenance(
                &provenance.catalog_sha256,
                &provenance.reviewed_at,
                &provenance.review_process,
            ))
            .unwrap_or_else(|| catalog
                .text(" · Mapping provenance unavailable", " · 對照來源無法取得")
                .to_owned()),
    )
}
/// Names the list the cover's last tile counts, the way that tile labels it.
///
/// A no-verdict check ran; it just did not return a pass or a fail. Called a
/// coverage gap it reads as untested, which is the one thing it is not.
pub(crate) fn named_coverage_items(
    gaps: usize,
    no_verdict: usize,
    catalog: HtmlReportCatalog,
) -> String {
    let counted = catalog.format_number(gaps);
    let only_no_verdict = no_verdict > 0 && no_verdict == gaps;
    match catalog.locale {
        crate::export::ReportLocale::ZhHant if only_no_verdict => {
            format!("{counted} 項未回傳判定的檢查")
        }
        crate::export::ReportLocale::ZhHant if no_verdict > 0 => {
            format!("{counted} 項未完成的檢查與待判讀結果")
        }
        crate::export::ReportLocale::ZhHant => format!("{counted} 項覆蓋缺口"),
        _ if only_no_verdict && gaps == 1 => "1 check without a verdict".to_owned(),
        _ if only_no_verdict => format!("{counted} checks without verdicts"),
        _ if no_verdict > 0 => format!("{counted} unfinished checks and results to review"),
        _ if gaps == 1 => "1 coverage gap".to_owned(),
        _ => format!("{counted} coverage gaps"),
    }
}

pub(crate) fn classified_coverage_item_counts(report: &BeginnerMasterReport) -> (usize, usize) {
    report
        .coverage_gaps
        .iter()
        .fold((0, 0), |(coverage_loss, record_notes), gap| {
            match gap.class {
                CoverageGapClass::CoverageLoss => (coverage_loss + 1, record_notes),
                CoverageGapClass::RecordNote => (coverage_loss, record_notes + 1),
            }
        })
}

pub(crate) fn coverage_kpi_entries(
    report: &BeginnerMasterReport,
    catalog: HtmlReportCatalog,
) -> [(&'static str, usize, &'static str); 2] {
    let (coverage_item_count, record_note_count) = classified_coverage_item_counts(report);
    let coverage_items_label = if report.coverage_counts.manual_review > 0 {
        catalog.text(
            "Unfinished checks and results to review",
            "未完成的檢查與待判讀結果",
        )
    } else {
        catalog.text("Coverage gaps", "涵蓋缺口")
    };
    [
        (coverage_items_label, coverage_item_count, "partial"),
        (
            catalog.text("Record notes", "記錄備註"),
            record_note_count,
            "quiet",
        ),
    ]
}

/// The four sentences a reader who reads nothing else should get.
///
/// Deliberately composed from counts this report already establishes rather
/// than from a judgement: what ran, what it found, what to do first, and what
/// was not covered. It states the top action by naming the report's own first
/// next step, so the summary and the plan cannot drift apart.
pub(crate) fn html_executive_summary(
    report: &BeginnerMasterReport,
    counts: &crate::beginner_report::CoverageCounts,
    problem_count: usize,
    catalog: HtmlReportCatalog,
) -> String {
    let severities = problem_severity_counts(report);
    let urgent = severities
        .iter()
        .filter(|(severity, _)| {
            matches!(
                severity,
                crate::domain::Severity::Critical | crate::domain::Severity::High
            )
        })
        .map(|(_, count)| *count)
        .sum::<usize>();

    let completed_asset_checks = html_completed_asset_check_count(report);
    let completed_assets = report
        .requested
        .targets
        .iter()
        .filter(|target| {
            report.actual.checks.iter().any(|check| {
                check.target_asset_ids.contains(&target.asset_id)
                    && html_check_status_on_asset(report, check, &target.asset_id)
                        == CoverageDimensionStatus::TestedComplete
            })
        })
        .count();
    let scanned = match catalog.locale {
        crate::export::ReportLocale::ZhHant if completed_assets > 0 => format!(
            "這次選了 {} 個檢查對象，其中 {} 個已有完成的檢查，共完成 {} 項。",
            catalog.format_number(report.requested.targets.len()),
            catalog.format_number(completed_assets),
            catalog.format_number(completed_asset_checks),
        ),
        crate::export::ReportLocale::ZhHant => format!(
            "這次選了 {} 個檢查對象，完成 {} 項檢查。",
            catalog.format_number(report.requested.targets.len()),
            catalog.format_number(completed_asset_checks),
        ),
        _ if completed_assets > 0 => format!(
            "This run included {} {}. It completed {} {} for {} {}.",
            catalog.format_number(report.requested.targets.len()),
            if report.requested.targets.len() == 1 {
                "asset"
            } else {
                "assets"
            },
            catalog.format_number(completed_asset_checks),
            if completed_asset_checks == 1 {
                "check"
            } else {
                "checks"
            },
            catalog.format_number(completed_assets),
            if completed_assets == 1 {
                "asset"
            } else {
                "assets"
            },
        ),
        _ => format!(
            "This run included {} {}. It completed {} {}.",
            catalog.format_number(report.requested.targets.len()),
            if report.requested.targets.len() == 1 {
                "asset"
            } else {
                "assets"
            },
            catalog.format_number(completed_asset_checks),
            if completed_asset_checks == 1 {
                "check"
            } else {
                "checks"
            },
        ),
    };

    // "Reported no problems" is said only of security checks that got far
    // enough to report. A website run whose one check failed printed "The
    // checks that completed reported no problems" straight after "This run
    // completed 0 checks", and inventory or a connection test never looked
    // for problems at all; the sentences around this one already say what
    // completed and what did not.
    let security_checks = |status: CoverageDimensionStatus| {
        report.actual.checks.iter().any(|check| {
            check.status == status
                && check.effective_result_kind() == CheckResultKind::SecurityCheck
        })
    };
    let completed_security_asset_checks = report
        .requested
        .targets
        .iter()
        .flat_map(|target| {
            report.actual.checks.iter().filter(move |check| {
                check.target_asset_ids.contains(&target.asset_id)
                    && check.effective_result_kind() == CheckResultKind::SecurityCheck
                    && html_check_status_on_asset(report, check, &target.asset_id)
                        == CoverageDimensionStatus::TestedComplete
            })
        })
        .count();
    let found = if problem_count == 0 {
        match (
            catalog.locale,
            security_checks(CoverageDimensionStatus::TestedComplete)
                || completed_security_asset_checks > 0,
            security_checks(CoverageDimensionStatus::TestedPartial),
        ) {
            (_, false, false) => None,
            (crate::export::ReportLocale::ZhHant, true, _) => Some("已完成的檢查沒有發現問題。"),
            (crate::export::ReportLocale::ZhHant, false, true) => {
                Some("目前完成的部分沒有發現問題，其餘仍未完成。")
            }
            (_, true, _) if completed_security_asset_checks.max(counts.tested_complete) == 1 => {
                Some("The check that completed reported no problems.")
            }
            (_, true, _) => Some("The checks that completed reported no problems."),
            (_, false, true) if counts.tested_partial == 1 => {
                Some("The partly completed check reported no problems.")
            }
            (_, false, true) => Some("The partly completed checks reported no problems."),
        }
        .map(str::to_owned)
    } else {
        Some(match (catalog.locale, problem_count, urgent) {
            (crate::export::ReportLocale::ZhHant, 1, 0) => {
                "發現 1 個問題，未被評為「嚴重」或「高」等級。".to_owned()
            }
            (crate::export::ReportLocale::ZhHant, 1, _) => {
                "發現 1 個問題，被評為「嚴重」或「高」等級，請優先查看。".to_owned()
            }
            (crate::export::ReportLocale::ZhHant, total, 0) => format!(
                "發現 {} 個問題，沒有被評為「嚴重」或「高」等級的項目。",
                catalog.format_number(total)
            ),
            (crate::export::ReportLocale::ZhHant, total, urgent) if urgent == total => format!(
                "發現 {} 個問題，全部被評為「嚴重」或「高」等級，請優先查看。",
                catalog.format_number(total)
            ),
            (crate::export::ReportLocale::ZhHant, total, urgent) => format!(
                "發現 {} 個問題，其中 {} 個被評為「嚴重」或「高」等級，請先查看這些項目。",
                catalog.format_number(total),
                catalog.format_number(urgent),
            ),
            (_, 1, 0) => "1 problem was found, and it is not Critical or High severity.".to_owned(),
            (_, 1, _) => "1 problem was found, and it is Critical or High severity.".to_owned(),
            (_, total, 0) => format!(
                "{} problems were found, none of them Critical or High severity.",
                catalog.format_number(total)
            ),
            (_, total, urgent) if urgent == total => format!(
                "{} problems were found, all of them Critical or High severity.",
                catalog.format_number(total)
            ),
            (_, total, urgent) => format!(
                "{} problems were found, {} of them Critical or High severity.",
                catalog.format_number(total),
                catalog.format_number(urgent),
            ),
        })
    };

    let first_action = report.next_steps.first().map(|step| {
        // A gap-derived step names the coverage it closes, as the step list
        // does: "Retry this check." was the only mention of a check in the
        // summary of a run whose one check failed.
        let action = html_action_about(
            &beginner_step_action(report, step, catalog),
            &html_step_closes(
                report,
                step,
                catalog,
                &readable_target_labels(report, catalog),
            ),
            catalog,
        );
        // A finding's fix is often shared -- one real project scan put 28
        // findings behind the same template instruction -- so the action on
        // its own said what to do but not to which problem. The step names
        // the finding it leads with.
        let named_problem = step
            .finding_id
            .as_deref()
            .and_then(|finding_id| {
                report
                    .findings
                    .iter()
                    .find(|finding| finding.finding_id == finding_id)
            })
            .and_then(|finding| {
                let title = html_problem_title(report, finding, catalog);
                let title = title.trim();
                let title = title
                    .strip_suffix('.')
                    .or_else(|| title.strip_suffix('。'))
                    .unwrap_or(title);
                (!title.is_empty()).then(|| title.to_owned())
            });
        match (catalog.locale, named_problem) {
            (crate::export::ReportLocale::ZhHant, Some(title)) => {
                format!("最先處理「{title}」：{action}")
            }
            (crate::export::ReportLocale::ZhHant, None) => format!("建議最先處理的是：{action}"),
            (_, Some(title)) => {
                format!("Start with \u{201c}{title}\u{201d}: {action}")
            }
            (_, None) => format!("The first thing to do is: {action}"),
        }
    });

    // Every state this report counts as short of a completed check. Two of
    // them were tracked and then left off the cover: the run cancelled two
    // checks and could not reach two dimensions at all, and the sentence that
    // says what was not covered counted neither.
    let untested = counts.failed
        + counts.timed_out
        + counts.cancelled
        + counts.not_tested
        + counts.unavailable;
    // The cover tile over this sentence counts the same list and, where any
    // of it is a check that ran and returned no verdict, says so in its label.
    // The sentence called all of them coverage gaps and then said the areas
    // were not tested -- which is the one thing a no-verdict check is not.
    //
    // It also stated both totals side by side while the second contained the
    // first, so a reader could add five and ten and get fifteen out of ten.
    // The second clause names what the first did not already cover.
    let (coverage_items, record_notes) = classified_coverage_item_counts(report);
    let remainder = coverage_items.saturating_sub(untested);
    let named_gaps = named_coverage_items(remainder, counts.manual_review, catalog);
    let named_checks = match catalog.locale {
        crate::export::ReportLocale::ZhHant => {
            format!("{} 項檢查沒有完成", catalog.format_number(untested))
        }
        _ if untested == 1 => "1 check did not complete".to_owned(),
        _ => format!(
            "{} checks did not complete",
            catalog.format_number(untested)
        ),
    };
    let remains = match remainder {
        1 => "remains",
        _ => "remain",
    };
    // A no-verdict check ran, so it is not one of the areas that were not
    // tested; where the list holds one, the closing sentence says what is
    // true of all of it instead.
    let closing = match (catalog.locale, counts.manual_review > 0) {
        (crate::export::ReportLocale::ZhHant, true) => "這些都沒有得到測試結果，不能視為安全。",
        (crate::export::ReportLocale::ZhHant, false) => "這些範圍未經測試，不能視為安全。",
        (_, true) => "None of that reached a tested result, so none of it can be read as clear.",
        (_, false) => "Those areas were not tested and cannot be read as clear.",
    };
    let not_covered = match (catalog.locale, untested, remainder) {
        (_, 0, 0) => None,
        (crate::export::ReportLocale::ZhHant, 0, _) => Some(format!("有 {named_gaps}——{closing}")),
        (crate::export::ReportLocale::ZhHant, _, 0) => {
            Some(format!("有 {named_checks}——{closing}"))
        }
        (crate::export::ReportLocale::ZhHant, _, _) => {
            Some(format!("有 {named_checks}，另有 {named_gaps}——{closing}"))
        }
        (_, 0, _) => Some(format!("{named_gaps} {remains}. {closing}")),
        (_, _, 0) => Some(format!("{named_checks}. {closing}")),
        (_, _, _) => Some(format!(
            "{named_checks} and {named_gaps} {remains}. {closing}"
        )),
    };

    let record_notes = match (catalog.locale, record_notes) {
        (_, 0) => None,
        (crate::export::ReportLocale::ZhHant, count) => Some(format!(
            "另有 {} 項記錄備註，說明已保存記錄的限制，而非缺少安全檢查。",
            catalog.format_number(count)
        )),
        (_, 1) => Some(
            "1 record note describes a limitation in the saved record, not a missing security check."
                .to_owned(),
        ),
        (_, count) => Some(format!(
            "{} record notes describe limitations in the saved record, not missing security checks.",
            catalog.format_number(count)
        )),
    };

    let mut sentences = vec![scanned];
    sentences.extend(found);
    let validation_count: usize = report
        .source_audits
        .iter()
        .map(|a| a.to_validate.len())
        .sum();
    let validation_action = if validation_count > 0 {
        let suffix = if validation_count == 1 { "" } else { "s" };
        let (en, zh) = if problem_count == 0 {
            (
                format!(
                    "Validate the {validation_count} source-audit item{suffix} under To validate first."
                ),
                format!("請先驗證下方「待驗證」中的 {validation_count} 個原始碼稽核項目。"),
            )
        } else {
            (
                format!(
                    "Also validate the {validation_count} source-audit item{suffix} under To validate."
                ),
                format!("另請驗證下方「待驗證」中的 {validation_count} 個原始碼稽核項目。"),
            )
        };
        Some(catalog.text(&en, &zh).to_owned())
    } else {
        None
    };
    if problem_count == 0 {
        sentences.extend(validation_action);
        sentences.extend(first_action);
    } else {
        sentences.extend(first_action);
        sentences.extend(validation_action);
    }
    sentences.extend(not_covered);
    sentences.extend(record_notes);
    format!(
        "<section class=\"executive-summary\"><h2>{}</h2>{}</section>",
        catalog.text("In short", "重點摘要"),
        sentences
            .iter()
            .map(|sentence| format!("<p>{}</p>", html_escape(sentence)))
            .collect::<String>(),
    )
}

/// The findings this report presents as problems, by severity, highest first.
///
/// Reachability records share the finding pipeline but are inventory, not
/// weaknesses, so they are excluded here for the same reason they are excluded
/// from the problem count -- a severity chart that counted them would show
/// twelve Unknown "problems" that are really open ports nobody rated.
pub(crate) fn problem_severity_counts(
    report: &BeginnerMasterReport,
) -> Vec<(crate::domain::Severity, usize)> {
    use crate::domain::Severity;
    let mut counts = BTreeMap::new();
    for finding in report.problem_findings() {
        if finding
            .severity_basis_code
            .is_some_and(|code| code.is_exposure_observation())
            && report.inventory.total > 0
        {
            continue;
        }
        *counts.entry(finding.severity.clone()).or_insert(0usize) += 1;
    }
    if counts.is_empty() {
        return Vec::new();
    }
    // Severity is a closed list, and the profile is read as one: the reader
    // who wants to know whether anything was Critical reads the Critical row.
    // Only the severities that happened had a row, for the same reason the
    // cover would have dropped a zero tile -- and with the same cost, that a
    // missing row cannot be told from an unmeasured one.
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Informational,
        Severity::Unknown,
    ] {
        counts.entry(severity).or_insert(0usize);
    }
    let mut ordered = counts.into_iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| right.0.cmp(&left.0));
    ordered
}

/// CSS class suffix for a severity, so the stylesheet owns the colour rather
/// than each call site inlining one.
pub(crate) fn severity_slug(severity: &crate::domain::Severity) -> &'static str {
    use crate::domain::Severity;
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Informational => "informational",
        Severity::Unknown => "unknown",
    }
}

/// A proportional bar per severity, widest first.
///
/// Bars are `<div>`s with a percentage width rather than a chart image: the
/// export is a single self-contained file under a `default-src 'none'` policy,
/// so there is nothing to fetch and nothing to script. The number is always
/// printed beside the bar, because the bar is the summary and the count is the
/// fact.
fn html_severity_profile(report: &BeginnerMasterReport, catalog: HtmlReportCatalog) -> String {
    let counts = problem_severity_counts(report);
    if counts.is_empty() {
        return String::new();
    }
    let largest = counts
        .iter()
        .map(|(_, count)| *count)
        .max()
        .expect("a non-empty severity profile has a largest count");
    let mut rows = String::new();
    for (severity, count) in &counts {
        // Against the largest bar, not the total: with one Critical among
        // forty Mediums, a total-relative Critical bar rounds to invisible,
        // and invisible is the wrong way to draw the one that matters most.
        let width = (count * 100).div_ceil(largest.max(1));
        rows.push_str(&format!(
            concat!(
                "<div class=\"severity-row{}\"><span class=\"severity-row__label\">{}</span>",
                "<span class=\"severity-bar\"><span class=\"severity-bar__fill severity-bar__fill--{}\" ",
                "style=\"width:{}%\"></span></span>",
                "<span class=\"severity-row__count\">{}</span></div>"
            ),
            match count {
                0 => " severity-row--none",
                _ => "",
            },
            html_escape(&catalog.identifier(&enum_key(severity))),
            severity_slug(severity),
            width,
            catalog.format_number(*count),
        ));
    }
    format!(
        "<section class=\"severity-profile\"><h2>{}</h2><p>{}</p>{rows}</section>",
        catalog.text("Problems by severity", "問題的嚴重程度分布"),
        catalog.text(
            "Severity describes possible impact. It is the scanner's rating where one was given, and this product's stated basis where none was.",
            "嚴重程度描述可能的影響。掃描工具有給評級時採用其評級，沒有給時則採用本產品載明的推導依據。"
        ),
    )
}

/// One CSS string literal, safe inside the `<style>` element that carries it.
///
/// A page margin box can only hold generated content, so text that belongs in
/// the running header has to be written into the stylesheet rather than the
/// document. Two things must hold: the quote must not close the string, and
/// nothing in the text may close the `<style>` element around it.
pub(crate) fn css_string_literal(value: &str) -> String {
    let mut literal = String::with_capacity(value.len() + 2);
    literal.push('"');
    for character in value.chars() {
        match character {
            '"' | '\\' => {
                literal.push('\\');
                literal.push(character);
            }
            '<' | '>' | '&' => literal.push_str(&format!("\\{:x} ", character as u32)),
            control if control.is_control() => {
                literal.push_str(&format!("\\{:x} ", control as u32));
            }
            other => literal.push(other),
        }
    }
    literal.push('"');
    literal
}

/// The page rule for print and PDF, including the running header and footer.
///
/// Paged output is a deliverable here, not a side effect of printing a web
/// page: this report is what leaves the room. A4 is what the reader's office
/// prints on, and the margins are sized to hold the running content.
///
/// The header and footer are page margin boxes rather than fixed-position
/// elements. A fixed box does repeat on every page, but it can only be placed
/// inside the page's content area -- a negative offset does not push it into
/// the margin, it wraps it to the other end of the page -- so it would sit on
/// top of the report's own text. Margin boxes cost the report's title having
/// to be escaped into the stylesheet, which is what `css_string_literal`
/// handles, and a browser that does not implement them simply prints without
/// a running header rather than printing a broken one.
///
/// A margin row's three boxes are anchored left, centre and right and each is
/// sized to its own content, so a border on one box stops where that box stops
/// and the rule ends mid-page. A rule that crosses the whole measure needs the
/// border on all three boxes, and a box only exists if it has real content:
/// `content:""` generates nothing, which is why the unused centre of the head
/// is a no-break space. Declaring widths is not the answer either, because the
/// boxes then overlap each other instead of sharing the row; padding is how a
/// box claims room, and the only reason the foot's centre carries any.
pub(crate) fn html_page_rule(report: &BeginnerMasterReport, catalog: HtmlReportCatalog) -> String {
    let head_rule = "border-bottom:.6pt solid #d0d5dd;padding-bottom:2.6mm;vertical-align:bottom";
    let foot_rule = "border-top:.6pt solid #d0d5dd;padding-top:2.6mm;vertical-align:top";
    let quiet = "font:7.5pt/1.3 sans-serif;color:#98a2b3";
    let mut rule = String::from("@page{size:A4;margin:24mm 15mm 20mm;");

    // The head answers what this document is, when it was produced and which
    // run produced it. An evidence document that loses its identity on page
    // two is a stack of loose paper.
    rule.push_str(&format!(
        concat!(
            "@top-left{{content:{};font:8pt/1.3 sans-serif;font-weight:600;",
            "color:#344054;letter-spacing:.01em;{}}}"
        ),
        css_string_literal(&running_head_title(html_case_title(report, catalog))),
        head_rule,
    ));
    rule.push_str(&format!("@top-center{{content:\"\\00a0\";{head_rule}}}"));
    rule.push_str(&format!(
        concat!(
            "@top-right{{content:{};font:7.5pt/1.3 ui-monospace,monospace;",
            "color:#98a2b3;white-space:nowrap;{}}}"
        ),
        css_string_literal(&format!(
            "{} {}",
            catalog.text("run", "輪次"),
            report.run_id
        )),
        head_rule,
    ));

    // The foot identifies the document and carries the one number a reader
    // looks for. This is the marker that travels with a page torn out of the
    // stack; the full terms remain at the end of the report, where there is
    // room to state them once without crowding the page number.
    rule.push_str(&format!(
        "@bottom-left{{content:{};{};{}}}",
        css_string_literal(catalog.text("Security scan report", "資安掃描報告")),
        quiet,
        foot_rule,
    ));
    rule.push_str(&format!(
        concat!(
            "@bottom-center{{content:{};{};white-space:nowrap;",
            // A gutter the centre box reserves for itself, so the caveat on
            // the left cannot run up against the timestamp in a language that
            // sets either of them wider.
            "padding-left:5mm;padding-right:5mm;{}}}"
        ),
        css_string_literal(&catalog.format_time(&report.state.last_durable_update)),
        quiet,
        foot_rule,
    ));
    rule.push_str(&format!(
        concat!(
            "@bottom-right{{content:counter(page) \" / \" counter(pages);",
            "font:9pt/1.3 sans-serif;font-weight:650;color:#123a63;",
            "letter-spacing:.02em;white-space:nowrap;{}}}"
        ),
        foot_rule,
    ));
    rule.push('}');

    // The cover states all of this at full size, one line below where the
    // running head would repeat it, and a rule under nothing is a stray line.
    rule.push_str(concat!(
        "@page:first{@top-left{content:\"\";border:0}",
        "@top-center{content:\"\";border:0}",
        "@top-right{content:\"\";border:0}}"
    ));
    rule
}

/// The case title as this locale should print it.
///
/// A case title is the user's own words and goes to the page untouched. A
/// Standard-redacted export has none to print, so the redaction writes one of
/// its own -- and it writes it before a locale is chosen, which left the
/// English stand-in on the three places a document says what it is: the tab,
/// the cover, and the running head of every page after the first. On a
/// twenty-three page Chinese redacted report that was the most repeated
/// English on the paper.
///
/// Unlike the bracket markers beside it this stand-in names nothing that has
/// to join across exports. There is one case, so there is nothing to tell it
/// apart from, and no number to keep.
fn html_case_title(report: &BeginnerMasterReport, catalog: HtmlReportCatalog) -> &str {
    match report.project_title.as_str() {
        crate::export::REDACTED_CASE_TITLE => {
            catalog.text(crate::export::REDACTED_CASE_TITLE, "已遮蔽的評估案件")
        }
        title => title,
    }
}

/// The project title, clamped to what a running head can hold.
///
/// The title is the user's own words and the cover prints all of them. Up here
/// it shares a 24mm margin with two other boxes, and a title long enough to
/// wrap past a few lines would grow upward out of the margin and print over
/// the first paragraph of every page. Clamping ends it with an ellipsis so an
/// abbreviated head reads as abbreviated rather than as a different title.
pub(crate) fn running_head_title(title: &str) -> String {
    const RUNNING_HEAD_CHARACTERS: usize = 64;
    let mut clamped = title
        .chars()
        .take(RUNNING_HEAD_CHARACTERS)
        .collect::<String>();
    if title.chars().nth(RUNNING_HEAD_CHARACTERS).is_some() {
        while clamped.ends_with(char::is_whitespace) {
            clamped.pop();
        }
        clamped.push('\u{2026}');
    }
    clamped
}

/// The run's headline counts as tiles rather than one run-on sentence.
///
/// These were a single line of bolded labels separated by interpuncts. Seven
/// numbers in a row of prose is a paragraph a reader skips; the same seven as
/// tiles is the first thing they read. A zero is kept and dimmed rather than
/// dropped: "Failed: 0" is a result, and a missing tile would leave the reader
/// to wonder whether it was zero or unmeasured.
pub(crate) fn html_kpi_tiles(tiles: &[(&str, usize, &str)], catalog: HtmlReportCatalog) -> String {
    tiles
        .iter()
        .map(|(label, value, tone)| {
            let tone = if *value == 0 { "quiet" } else { *tone };
            format!(
                concat!(
                    "<div class=\"kpi kpi--{}\"><span class=\"kpi__value\">{}</span>",
                    "<span class=\"kpi__label\">{}</span></div>"
                ),
                tone,
                catalog.format_number(*value),
                html_escape(label),
            )
        })
        .collect()
}

/// One framework owner's notice, kept whole and labelled with whose it is.
///
/// Set between one framework's controls and the next, these were four to
/// seven lines of licence a reader had to cross to reach the next table,
/// seven times over. Gathered under one heading they are still on the page,
/// still verbatim, and still attached to the framework they belong to.
pub(crate) fn source_line(
    framework: &crate::exporters::framework_report::FrameworkSummary,
    attribution: &str,
    catalog: HtmlReportCatalog,
) -> String {
    format!(
        concat!(
            "<p class=\"framework-source\"><strong>{} {} {}</strong>{}{}{}",
            "<span class=\"framework-source__url\">{}</span></p>"
        ),
        html_escape(&framework.framework),
        catalog.text("version", "版本"),
        html_escape(&framework.expected_version),
        catalog.text(" \u{2014} ", "："),
        attribution,
        catalog.gap_after(attribution),
        html_escape(&framework.source.source_url),
    )
}

/// The plain-language name of a framework summary's state.
///
/// The wire value is a stable identifier for a machine to branch on. A reader
/// gets a sentence instead, and the two must not drift: an unrecognized state
/// prints its own identifier rather than a guess.
fn framework_state_text(state: &str, catalog: HtmlReportCatalog) -> String {
    match state {
        "related_coordinates_observed" => catalog
            .text("Related references observed", "已觀察到相關框架參考")
            .to_owned(),
        "not_applicable_to_declared_context" => catalog
            .text(
                "Not applicable to the declared context",
                "不適用於已載明的情境",
            )
            .to_owned(),
        "unknown_due_to_incomplete_coverage" => catalog
            .text("Unknown — coverage is incomplete", "未知——覆蓋並不完整")
            .to_owned(),
        "no_relationship_observed" => catalog
            .text("No relationship observed", "未觀察到關聯")
            .to_owned(),
        "unknown_due_to_unanswered_context" => catalog
            .text(
                "Unknown — the context answers are incomplete",
                "未知——情境問題尚未答完",
            )
            .to_owned(),
        "no_related_coordinate_observed" => catalog
            .text("No related reference observed", "未觀察到相關框架參考")
            .to_owned(),
        other => readable_identifier(other),
    }
}

/// Why a framework's state is what it is, in the report's language.
///
/// The exporter pairs one sentence with each state identifier and writes both
/// into the canonical JSON in English, where they belong: that file is a wire
/// format. The reader-facing sentence is presentation, so it is translated
/// here, keyed on the same identifier the state text uses. A state this
/// function does not know falls back to the exporter's own sentence rather
/// than to silence -- an untranslated explanation still explains, a missing
/// one leaves a framework reporting nothing with no reason given.
pub(crate) fn framework_explanation_text(
    state: &str,
    exported: &str,
    catalog: HtmlReportCatalog,
) -> String {
    match state {
        "related_coordinates_observed" => catalog.text(
            "One or more preliminary findings carry an evidence-bound relationship to this framework. The relationship is a navigation aid, not a control result.",
            "本輪至少有一筆初步問題與這個框架存在證據綁定的關聯。這項關聯是導覽用途，不是控制項的評定結果。",
        ),
        "not_applicable_to_declared_context" => catalog.text(
            "The frozen answers explicitly identify a non-AI assessment and a non-AI-generated artifact, so references to frameworks that only describe AI systems were not inferred.",
            "已凍結的回答明確指出這不是 AI 評估、產出也不是 AI 生成，因此不會推導只描述 AI 系統的框架參考。",
        ),
        "unknown_due_to_unanswered_context" => catalog.text(
            "No reference to this AI-specific framework was inferred because at least one required AI-context answer is legacy or unanswered. This remains unknown, not not-applicable.",
            "因為至少有一項必要的 AI 情境問題屬於舊版或尚未作答，所以沒有推導這個 AI 專用框架的任何參考。這屬於未知，不是不適用。",
        ),
        "unknown_due_to_incomplete_coverage" => catalog.text(
            "No related reference was observed, but coverage is incomplete or unknown. This cannot be interpreted as a passed or implemented control.",
            "沒有觀察到相關框架參考，但涵蓋範圍不完整或未知。這不能解讀為控制項已通過或已實作。",
        ),
        "no_related_coordinate_observed" => catalog.text(
            "No selected-run finding carried an evidence-bound relationship to this framework. This is not a pass, implementation claim, or compliance conclusion.",
            "本輪沒有任何問題與這個框架存在證據綁定的關聯。這不是通過、實作聲明或合規結論。",
        ),
        _ => exported,
    }
    .to_owned()
}

/// The Chinese rendering of one framework source notice.
///
/// Four notices make up a framework's attribution and they are not one kind of
/// sentence. A citation, a copyright line and a licence name are the
/// attribution of record: they identify the work and the terms it is used
/// under, and translating them would state something the licensor did not, so
/// they print as the exporter wrote them in every locale. The sentences around
/// them are this product's own - what it selected, what it changed, and who
/// has not endorsed it - and a reader is owed those in the language the rest
/// of the report is written in. A notice with no entry here is one of the
/// first kind.
fn framework_source_notice_zh_hant(notice: &str) -> Option<&'static str> {
    Some(match notice {
        "Use of NIST source material remains subject to the source publication's notices." => {
            "NIST 原始素材的使用仍受該出版品自身的聲明規範。"
        }
        "ISO/IEC 27001:2022 control coordinates are referenced nominatively." => {
            "ISO/IEC 27001:2022 的控制項編號以指名方式引用。"
        }
        "ISO/IEC standard content remains subject to ISO's terms; this report is not a copy of the standard." => {
            "ISO/IEC 標準內容仍受 ISO 的條款規範；本報告不是該標準的複本。"
        }
        "Framework relationships and rationales in this report are project-authored navigation metadata." => {
            "本報告中的框架關聯與理由由本專案撰寫，屬於導覽用的中繼資料。"
        }
        "NIST has not reviewed or endorsed this report or integration." => {
            "NIST 未審閱或背書本報告與本整合。"
        }
        "ISO and IEC have not reviewed or endorsed this report or integration." => {
            "ISO 與 IEC 未審閱或背書本報告與本整合。"
        }
        "ai-security-scanner uses a modified, project-authored six-record metadata selection from AIDEFEND 1.20260805 at pinned commit e10c1678ee49f03f8fb0c97d446ba3fbc3543655." => {
            "ai-security-scanner 使用經改作、由本專案撰寫的六筆中繼資料選集，取自 AIDEFEND 1.20260805 的固定提交 e10c1678ee49f03f8fb0c97d446ba3fbc3543655。"
        }
        "This independent integration is not affiliated with, approved, certified, sponsored, or endorsed by AIDEFEND or its owner." => {
            "本整合為獨立進行，未與 AIDEFEND 或其擁有者有從屬關係，也未獲其核准、認證、贊助或背書。"
        }
        "Category membership is read from the CWE sets OWASP publishes for each 2021 category; the rationales beside them are project-authored navigation metadata." => {
            "類別歸屬讀自 OWASP 為 2021 各類別公布的 CWE 集合；旁邊的理由由本專案撰寫，屬於導覽用的中繼資料。"
        }
        "The OWASP Foundation has not reviewed or endorsed this report or integration." => {
            "OWASP Foundation 未審閱或背書本報告與本整合。"
        }
        "This report references three of the ten 2025 categories, the only ones the packaged engines produce evidence for; the rationales are project-authored navigation metadata." => {
            "本報告引用 2025 年十個類別中的三個，也就是內建引擎唯一能產出證據的那幾個；理由由本專案撰寫，屬於導覽用的中繼資料。"
        }
        "The OWASP Foundation and the OWASP GenAI Security Project have not reviewed or endorsed this report or integration." => {
            "OWASP Foundation 與 OWASP GenAI Security Project 未審閱或背書本報告與本整合。"
        }
        "CIS Kubernetes Benchmark v1.11 recommendation numbers and titles are referenced nominatively; they are the coordinates kube-bench itself reports against." => {
            "CIS Kubernetes Benchmark v1.11 的建議編號與標題以指名方式引用；那正是 kube-bench 自己回報時所依據的編號與標題。"
        }
        "CIS Benchmark content remains subject to the Center for Internet Security's terms of use; this report is not a copy of the benchmark." => {
            "CIS Benchmark 內容仍受 Center for Internet Security 的使用條款規範；本報告不是該基準的複本。"
        }
        "Recommendation titles are reproduced as the pinned kube-bench image reports them." => {
            "建議項目的標題，照固定版本的 kube-bench 映像回報的原樣重現。"
        }
        "The Center for Internet Security has not reviewed or endorsed this report or integration." => {
            "Center for Internet Security 未審閱或背書本報告與本整合。"
        }
        "CIS Amazon Web Services Foundations Benchmark v3.0.0 recommendation numbers and titles are referenced nominatively." => {
            "CIS Amazon Web Services Foundations Benchmark v3.0.0 的建議編號與標題以指名方式引用。"
        }
        "The recommendation-to-check relationship is the one Prowler publishes in its own CIS 3.0 compliance file." => {
            "建議項目與檢查之間的對應，採用 Prowler 在自家 CIS 3.0 合規檔中公布的版本。"
        }
        _ => return None,
    })
}
/// The Chinese rendering of a mapped control's name.
///
/// The names in the packaged catalog are two different things. AIDEFEND, both
/// OWASP lists and both CIS benchmarks are carried under the names their
/// owners publish, and kube-bench's recommendation titles are reproduced
/// exactly as the pinned image reports them, so those print as written in
/// every locale. The NIST CSF and ISO/IEC 27001 names are not the standards'
/// own wording: they are this project's short names for the coordinate, which
/// is why the attribution calls the relationships project-authored. A short
/// name this product wrote is a sentence this product owes a reader in their
/// own language. A name with no entry here is one of the owners'.
pub(crate) fn control_title_zh_hant(title: &str) -> Option<&'static str> {
    Some(match title {
        // NIST CSF 2.0
        "Vulnerability identification and recording" => "弱點的辨識與記錄",
        "Identity and credential lifecycle management" => "身分與憑證的生命週期管理",
        "Authentication of users, services, and hardware" => "使用者、服務與硬體的身分驗證",
        "Least-privilege access governance" => "最小權限的存取治理",
        "Protection of data at rest" => "靜態資料的保護",
        "Configuration management practices" => "組態管理實務",
        "Security log availability" => "資安紀錄的可用性",
        "Secure software development practices" => "安全的軟體開發實務",
        "Protection of networks and environments from unauthorized access" => {
            "網路與環境防止未經授權存取的保護"
        }
        "Resource capacity for availability" => "維持可用性的資源容量",
        // ISO/IEC 27001:2022
        "Policy-governed access" => "依政策管理的存取控制",
        "Authentication information safeguards" => "驗證資訊的保護措施",
        "Access entitlement governance" => "存取權限的治理",
        "Cloud service security responsibilities" => "雲端服務的資安責任",
        "Privileged access safeguards" => "特權存取的保護措施",
        "Capacity management" => "容量管理",
        "Technical vulnerability handling" => "技術性弱點的處理",
        "Configuration management" => "組態管理",
        "Security-relevant audit records" => "與資安有關的稽核紀錄",
        "Networks security" => "網路安全",
        "Cryptographic safeguards" => "密碼學保護措施",
        "Secure coding practices" => "安全程式撰寫實務",
        "Security testing before acceptance" => "驗收前的資安測試",
        _ => return None,
    })
}

/// A mapped control's name in the locale the report is written in.
fn control_title_text(title: &str, catalog: HtmlReportCatalog) -> String {
    match catalog.locale {
        crate::export::ReportLocale::ZhHant => control_title_zh_hant(title).unwrap_or(title),
        crate::export::ReportLocale::En => title,
    }
    .to_owned()
}
/// Where the report's framework coordinates come from and what they cover.
///
/// The consolidated mapping already existed, but only as a separate JSON
/// export: in the report itself a coordinate appeared solely inside one
/// finding's collapsed detail, so a reader could not see that this run touched
/// ten NIST CSF controls without opening fifty cards. The overview names every
/// framework the product carries, including the ones this case's answers put
/// out of scope, because a framework that reports nothing here should say why
/// rather than be missing.
///
/// These are navigation coordinates. The report claims no audit, certification,
/// or compliance determination anywhere, and this section states that in its
/// own words rather than relying on the footer to carry it.
pub(crate) fn html_framework_section(
    case: &AssessmentCase,
    run_id: &str,
    catalog: HtmlReportCatalog,
) -> String {
    let Ok(framework_report) = export_master_framework_report(case, run_id) else {
        // The framework overlay never gates the report. A case whose mapping
        // cannot be consolidated still reports its findings; it just does not
        // get this section.
        return String::new();
    };
    if framework_report.frameworks.is_empty() {
        return String::new();
    }

    let mut overview = String::new();
    let mut blocks = String::new();
    let mut sources = String::new();
    let mut not_applicable: Vec<(Vec<String>, String)> = Vec::new();
    for framework in &framework_report.frameworks {
        let state = framework_state_text(&framework.state, catalog);
        let explanation =
            framework_explanation_text(&framework.state, &framework.explanation, catalog);
        let populated = framework.control_count > 0;
        overview.push_str(&format!(
            concat!(
                "<tr><th scope=\"row\">{}<br><small>{} {}</small></th>",
                "<td><span class=\"framework-state framework-state--{}\">{}</span></td>",
                "<td class=\"numeric\">{}</td><td class=\"numeric\">{}</td></tr>"
            ),
            html_escape(&framework.framework),
            catalog.text("version", "版本"),
            html_escape(&framework.expected_version),
            if populated { "observed" } else { "quiet" },
            html_escape(&state),
            catalog.format_number(framework.control_count),
            catalog.format_number(framework.finding_count),
        ));

        let mut rows = String::new();
        for control in &framework.controls {
            let findings = control
                .relationships
                .iter()
                .map(|relationship| relationship.finding.finding_id.as_str())
                .collect::<BTreeSet<_>>();
            // The severity mix of what landed here, so a control carrying one
            // critical is not read the same as a control carrying nine lows.
            let mut severities = BTreeMap::new();
            let mut counted = BTreeSet::new();
            for relationship in &control.relationships {
                if !counted.insert(relationship.finding.finding_id.as_str()) {
                    continue;
                }
                *severities
                    .entry(relationship.finding.severity.clone())
                    .or_insert(0usize) += 1;
            }
            let mut mix = severities
                .into_iter()
                .filter_map(|(severity, count)| {
                    crate::domain::Severity::deserialize(serde_json::Value::String(severity))
                        .ok()
                        .map(|severity| (severity, count))
                })
                .collect::<Vec<_>>();
            mix.sort_by(|left, right| right.0.cmp(&left.0));
            let empty_state = match findings.is_empty() {
                true => HtmlSeverityMixEmptyState::MeasuredZero,
                false => HtmlSeverityMixEmptyState::NotMeasured,
            };
            rows.push_str(&format!(
                concat!(
                    "<tr><td><code>{}</code></td><td>{}</td>",
                    "<td class=\"numeric\">{}</td><td class=\"framework-mix\">{}</td></tr>"
                ),
                html_escape(&control.control_id),
                html_escape(&control_title_text(&control.title, catalog)),
                catalog.format_number(findings.len()),
                html_asset_severity_strip(&mix, empty_state, catalog),
            ));
        }

        let source = &framework.source;
        let attribution = [
            source.attribution_notice.as_str(),
            source.license_notice.as_str(),
            source.modifications_notice.as_str(),
            source.non_endorsement_notice.as_str(),
        ]
        .into_iter()
        .filter(|notice| !notice.is_empty())
        .map(|notice| match catalog.locale {
            crate::export::ReportLocale::ZhHant => {
                framework_source_notice_zh_hant(notice).unwrap_or(notice)
            }
            crate::export::ReportLocale::En => notice,
        })
        .map(html_escape)
        // Four notices run together as one paragraph, and in Chinese the
        // sentence terminator already closes the gap: a space after "。" is
        // an English habit. One is still needed after a citation that ends
        // in a full stop or a licence URL, so the join asks what came before
        // rather than assuming one language.
        .fold(String::new(), |mut paragraph, notice| {
            if !paragraph.is_empty() && paragraph.ends_with(|last: char| last.is_ascii()) {
                paragraph.push(' ');
            }
            paragraph.push_str(&notice);
            paragraph
        });

        // A framework the run reached nothing in does not need a card. Its
        // row in the overview above already gives its name, its state and its
        // two zeroes; a bordered block repeating them, plus one sentence of
        // why, was six lines to say what the table said in one. The sentence
        // is the part the table cannot carry, so that is what is kept.
        if rows.is_empty() {
            let label = format!(
                "{} {} {}",
                html_escape(&framework.framework),
                catalog.text("version", "版本"),
                html_escape(&framework.expected_version),
            );
            // Two frameworks skipped for the same reason get one sentence.
            // Both of this run's are skipped because the case declared a
            // non-AI assessment, and printing that sentence once per
            // framework reads as the report having lost its place.
            match not_applicable
                .iter_mut()
                .find(|(_, reason): &&mut (Vec<String>, String)| *reason == explanation)
            {
                Some((labels, _)) => labels.push(label),
                None => not_applicable.push((vec![label], explanation.clone())),
            }
            sources.push_str(&source_line(framework, &attribution, catalog));
            continue;
        }
        let body = {
            format!(
                concat!(
                    "<table class=\"framework-controls\">",
                    "<caption class=\"visually-hidden\">{} {}</caption><thead><tr>",
                    "<th scope=\"col\">{}</th><th scope=\"col\">{}</th>",
                    "<th class=\"numeric\" scope=\"col\">{}</th><th scope=\"col\">{}</th>",
                    "</tr></thead><tbody>{}</tbody></table>"
                ),
                html_escape(&framework.framework),
                catalog.text(
                    "controls with an observed reference",
                    "中觀察到框架參考的控制項"
                ),
                catalog.text("Control", "控制項"),
                catalog.text("Title", "名稱"),
                catalog.text("Findings", "問題數"),
                catalog.text("Severity mix", "嚴重程度組成"),
                rows,
            )
        };
        blocks.push_str(&format!(
            concat!(
                "<article class=\"framework-block\">",
                "<h3>{} <small>{} {}</small></h3>",
                "<p class=\"framework-block__state\">{}</p>{}",
                "</article>"
            ),
            html_escape(&framework.framework),
            catalog.text("version", "版本"),
            html_escape(&framework.expected_version),
            html_escape(&state),
            body,
        ));
        sources.push_str(&source_line(framework, &attribution, catalog));
    }
    let not_applicable = not_applicable
        .into_iter()
        .map(|(labels, reason)| {
            format!(
                "<p class=\"framework-quiet\"><strong>{}</strong>{}{}</p>",
                labels.join(catalog.text(", ", "、")),
                catalog.text(" \u{2014} ", "："),
                html_escape(&reason),
            )
        })
        .collect::<String>();
    if !sources.is_empty() {
        blocks.push_str(&format!(
            "<article class=\"framework-block framework-sources\"><h3>{}</h3>{}</article>",
            catalog.text("Framework sources and attribution", "框架來源與出處聲明"),
            sources,
        ));
    }

    format!(
        concat!(
            "<section class=\"framework-coverage\"><h2>{}</h2><p>{}</p>",
            "<table class=\"framework-overview\">",
            "<caption class=\"visually-hidden\">{}</caption><thead><tr>",
            "<th scope=\"col\">{}</th><th scope=\"col\">{}</th>",
            "<th class=\"numeric\" scope=\"col\">{}</th>",
            "<th class=\"numeric\" scope=\"col\">{}</th>",
            "</tr></thead><tbody>{}</tbody></table>{}{}</section>"
        ),
        catalog.text("Where this lands in each framework", "對應到各框架的位置"),
        catalog.text(
            "Each reference below was reached from a finding's own rule or CWE through the packaged mapping catalog. They are navigation aids for finding the relevant control text, not a compliance result: nothing here is an audit, a certification, or a pass.",
            "以下每個框架參考都是從問題本身的規則或 CWE，透過內建的對照目錄推導出來的。它們是用來找到相關控制項條文的導覽，不是合規結果：這裡沒有任何內容構成稽核、認證或通過與否的判定。",
        ),
        catalog.text(
            "Every framework in this report and what this run shows against it",
            "本報告涵蓋的每個框架，以及本輪對照後的情形",
        ),
        catalog.text("Framework", "框架"),
        catalog.text("What this run shows", "本輪的情形"),
        catalog.text("Controls", "控制項"),
        catalog.text("Findings", "問題"),
        overview,
        not_applicable,
        blocks,
    )
}

/// One next step's action sentence, composed for the report's language.
///
/// A finding-derived step's action is that finding's own recommendation and
/// needs the same composition the finding itself gets; a gap-derived step
/// carries no family and is looked up as coverage prose instead; the
/// unattributed one is composed from its payload, which is the only place the
/// identifier a beginner must add is spelled out. Shared with the executive
/// summary so its first action and this list's first entry are one sentence,
/// not two renderings of one step.
pub(crate) fn beginner_step_action(
    report: &BeginnerMasterReport,
    step: &crate::beginner_report::BeginnerNextStep,
    catalog: HtmlReportCatalog,
) -> String {
    let derived_from = step.finding_id.as_deref().and_then(|finding_id| {
        report
            .findings
            .iter()
            .find(|finding| finding.finding_id == finding_id)
    });
    let unconfirmed = derived_from
        .is_some_and(|finding| finding_unconfirmed_by_coverage(finding, &report.actual));
    let action = if derived_from.is_some_and(provider_native_narrative) {
        step.action.clone()
    } else {
        match catalog.locale {
            crate::export::ReportLocale::En => derived_from.map_or_else(
                || step.action.clone(),
                |finding| {
                    crate::finding_narrative::finding_next_action_english(
                        &step.action,
                        step.family,
                        beginner_aws_iam_policy(finding),
                        unconfirmed,
                    )
                },
            ),
            crate::export::ReportLocale::ZhHant => {
                crate::finding_narrative::finding_next_action_zh_hant(
                    &step.action,
                    step.recommended_expert_type.as_deref().unwrap_or_default(),
                    step.family,
                    derived_from.and_then(beginner_aws_iam_policy),
                    unconfirmed,
                )
            }
        }
    };
    match (catalog.locale, step.unattributed.as_ref(), derived_from) {
        (crate::export::ReportLocale::ZhHant, Some(unattributed), _) => {
            let engine_id = step
                .reason
                .split_once(' ')
                .map(|(engine, _)| engine)
                .unwrap_or(step.reason.as_str());
            let (_, _, next_action) = crate::finding_narrative::unattributed_gap_zh_hant(
                &engine_named(engine_id),
                unattributed,
            );
            next_action
        }
        (crate::export::ReportLocale::ZhHant, None, None) => {
            crate::finding_narrative::coverage_gap_prose_zh_hant(&action).unwrap_or(action)
        }
        (crate::export::ReportLocale::En, None, None) => action,
        _ => action,
    }
}

/// Severity counts for one asset's problems, worst first.
///
/// Deduplicated by finding id for the same reason the count beside it is: one
/// finding naming two assets is one problem on each, not two on either.
pub(crate) fn asset_severity_counts(
    report: &BeginnerMasterReport,
    asset_id: &Id,
) -> Vec<(crate::domain::Severity, usize)> {
    let mut seen = BTreeSet::new();
    let mut counts = BTreeMap::new();
    for finding in report.problem_findings() {
        if finding
            .severity_basis_code
            .is_some_and(|basis| basis.is_exposure_observation())
            || !finding.target_asset_ids.contains(asset_id)
            || !seen.insert(finding.finding_id.as_str())
        {
            continue;
        }
        *counts.entry(finding.severity.clone()).or_insert(0usize) += 1;
    }
    let mut ordered = counts.into_iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| right.0.cmp(&left.0));
    ordered
}

/// What one asset's problem count is made of, as a single composition bar.
///
/// "Problems found: 22" reads the same whether those are twenty-two low
/// notes or two critical ones, and that difference is the whole decision.
/// Segments are sized with `flex` rather than a percentage so the smallest
/// one still has a floor width, and every segment is named in the line below
/// the bar: the colour is the shortcut, not the only carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HtmlSeverityMixEmptyState {
    /// At least one applicable security check completed and produced no
    /// problem whose severity could contribute to the mix.
    MeasuredZero,
    /// No completed security check established a severity distribution.
    NotMeasured,
}

fn html_asset_severity_strip(
    counts: &[(crate::domain::Severity, usize)],
    empty_state: HtmlSeverityMixEmptyState,
    catalog: HtmlReportCatalog,
) -> String {
    if counts.is_empty() {
        let (class_name, label) = match empty_state {
            HtmlSeverityMixEmptyState::MeasuredZero => {
                ("zero", catalog.text("0 problems", "0 個問題"))
            }
            HtmlSeverityMixEmptyState::NotMeasured => {
                ("unmeasured", catalog.text("Not measured", "未量測"))
            }
        };
        return format!(
            "<span class=\"asset-severity__empty asset-severity__empty--{class_name}\">{}</span>",
            html_escape(label),
        );
    }
    let mut segments = String::new();
    let mut named = Vec::new();
    for (severity, count) in counts {
        // A rating and its count are one word. Separated by a plain space
        // they broke across lines in the narrow columns this legend sits in,
        // leaving "High" at the end of one line and "1 . Medium 2" at the
        // start of the next.
        let name = format!(
            "{}\u{a0}{}",
            html_escape(&catalog.identifier(&enum_key(severity))),
            catalog.format_number(*count),
        );
        segments.push_str(&format!(
            "<span class=\"asset-severity__part severity-bar__fill--{}\" style=\"flex:{count}\" title=\"{name}\"></span>",
            severity_slug(severity),
        ));
        named.push(name);
    }
    let names = named.join(" \u{b7} ");
    format!(
        "<div class=\"asset-severity\" role=\"img\" aria-label=\"{names}\">{segments}</div>\
         <p class=\"asset-severity__legend\">{names}</p>",
    )
}

/// Which engine reached which asset, as one grid.
///
/// This is the section that answers "what was not tested" at a glance. The
/// same facts are already in the report as prose and collapsed detail, but
/// spread across dozens of blocks, and a reader checking whether their
/// database server was covered should not have to open them one at a time.
/// A blank cell is deliberate and labelled: no check of that engine was
/// planned for that asset, which is not the same as one that failed.
fn html_coverage_matrix(
    report: &BeginnerMasterReport,
    labels: &BTreeMap<Id, String>,
    catalog: HtmlReportCatalog,
) -> String {
    if report.requested.targets.is_empty() || report.actual.checks.is_empty() {
        return String::new();
    }
    // One column per engine that ran, named by the check id the report already
    // uses elsewhere so the grid and the run list agree.
    let mut engines = report
        .actual
        .checks
        .iter()
        .map(|check| check.check_id.as_str())
        .collect::<Vec<_>>();
    engines.sort_unstable();
    engines.dedup();
    // A grid wider than this stops being readable and starts being a spreadsheet.
    const MAX_MATRIX_ENGINES: usize = 24;
    if engines.len() > MAX_MATRIX_ENGINES {
        return String::new();
    }

    let mut header = String::new();
    for engine in &engines {
        // The same name the run list and the finding cards use. Title-casing
        // the identifier instead spelled seven of these scanners in a way
        // their own documentation does not - "Kube Bench", "Trufflehog",
        // "Httpx" - so the grid disagreed with every other place the report
        // names the thing that produced a column.
        header.push_str(&format!(
            "<th scope=\"col\"><span class=\"matrix-engine\">{}</span></th>",
            html_escape(&report_check_label(engine, catalog)),
        ));
    }

    let mut body = String::new();
    for target in &report.requested.targets {
        let label = labels
            .get(&target.asset_id)
            .cloned()
            .unwrap_or_else(|| target.asset_id.clone());
        let mut cells = String::new();
        for engine in &engines {
            let mut status = None;
            for check in report.actual.checks.iter().filter(|check| {
                check.check_id == *engine && check.target_asset_ids.contains(&target.asset_id)
            }) {
                // Worst outcome wins the cell: an engine that completed one
                // task and failed another against the same asset has not
                // covered it, and showing the completed half would say it had.
                let asset_status = html_check_status_on_asset(report, check, &target.asset_id);
                status = Some(match status {
                    Some(existing) if worse_status(existing, asset_status) => existing,
                    _ => asset_status,
                });
            }
            let (slug, mark, text) = matrix_cell_state(status, catalog);
            // The mark carries the state, the colour repeats it, and the title
            // spells it out. Colour alone would fail a colourblind reader and
            // every black-and-white print of this report.
            cells.push_str(&format!(
                "<td class=\"matrix-cell matrix-cell--{slug}\" title=\"{}\"><span aria-hidden=\"true\">{}</span><span class=\"visually-hidden\">{}</span></td>",
                html_escape(text),
                mark,
                html_escape(text),
            ));
        }
        body.push_str(&format!(
            "<tr><th scope=\"row\">{}</th>{cells}</tr>",
            html_escape(&label),
        ));
    }

    format!(
        concat!(
            "<section><h2>{}</h2><p>{}</p>",
            "<div class=\"matrix-scroll\"><table class=\"coverage-matrix\">",
            "<caption class=\"visually-hidden\">{}</caption>",
            "<thead><tr><th scope=\"col\">{}</th>{}</tr></thead>",
            "<tbody>{}</tbody></table></div>{}</section>"
        ),
        catalog.text("What each check reached", "每個檢查涵蓋到的範圍"),
        catalog.text(
            "One row per requested asset, one column per check in this run. An empty cell means no check of that kind was planned for that asset, which is not a result.",
            "每一列是一項要求掃描的資產，每一欄是本輪的一項檢查。空白代表該資產沒有安排這類檢查，而不是檢查結果。"
        ),
        catalog.text(
            "One row per selected asset, one column per check in this run",
            "每個選定資產一列，本輪每項檢查一欄",
        ),
        catalog.text("Asset", "資產"),
        header,
        body,
        html_matrix_legend(catalog),
    )
}

/// The mark, colour class, and spelled-out name for one matrix cell.
///
/// Every state gets a distinct shape, not just a distinct colour: the marks
/// are what survives a monochrome print and a colourblind reader. `None` is an
/// empty cell rather than a mark, because "no check of this kind was planned
/// here" is the absence of a result and should not look like one.
fn matrix_cell_state(
    status: Option<CoverageDimensionStatus>,
    catalog: HtmlReportCatalog,
) -> (&'static str, &'static str, &'static str) {
    match status {
        Some(CoverageDimensionStatus::TestedComplete) => {
            ("complete", "\u{25cf}", catalog.text("Completed", "已完成"))
        }
        Some(CoverageDimensionStatus::TestedPartial) => (
            "partial",
            "\u{25d0}",
            catalog.text("Partly completed", "部分完成"),
        ),
        Some(CoverageDimensionStatus::TimedOut) => {
            ("timed-out", "\u{25d1}", catalog.text("Timed out", "逾時"))
        }
        Some(CoverageDimensionStatus::Cancelled) => {
            ("cancelled", "\u{25c7}", catalog.text("Cancelled", "已取消"))
        }
        Some(CoverageDimensionStatus::Failed) => {
            ("failed", "\u{2715}", catalog.text("Failed", "失敗"))
        }
        Some(CoverageDimensionStatus::NotTested) => (
            "not-tested",
            "\u{25cb}",
            catalog.text("Not tested", "未測試"),
        ),
        None => (
            "not-planned",
            "",
            catalog.text("No check planned", "未安排檢查"),
        ),
    }
}

/// Names every mark the grid above it uses, in the order a reader meets them.
fn html_matrix_legend(catalog: HtmlReportCatalog) -> String {
    let states = [
        Some(CoverageDimensionStatus::TestedComplete),
        Some(CoverageDimensionStatus::TestedPartial),
        Some(CoverageDimensionStatus::TimedOut),
        Some(CoverageDimensionStatus::Cancelled),
        Some(CoverageDimensionStatus::Failed),
        Some(CoverageDimensionStatus::NotTested),
        None,
    ];
    let items = states
        .into_iter()
        .map(|status| {
            let (slug, mark, text) = matrix_cell_state(status, catalog);
            format!(
                "<li><span class=\"matrix-key matrix-cell--{slug}\">{}</span> {}</li>",
                if mark.is_empty() { "&nbsp;" } else { mark },
                html_escape(text),
            )
        })
        .collect::<String>();
    format!("<ul class=\"matrix-legend\">{items}</ul>")
}

/// Whether the already-recorded status is the worse of the two.
///
/// Ordered by how much the reader should distrust the cell, not by the enum's
/// own order: an untested asset is a bigger hole than a partly tested one.
fn worse_status(existing: CoverageDimensionStatus, candidate: CoverageDimensionStatus) -> bool {
    fn rank(status: CoverageDimensionStatus) -> u8 {
        match status {
            CoverageDimensionStatus::TestedComplete => 0,
            CoverageDimensionStatus::TestedPartial => 1,
            CoverageDimensionStatus::TimedOut => 3,
            CoverageDimensionStatus::Cancelled => 4,
            CoverageDimensionStatus::Failed => 5,
            CoverageDimensionStatus::NotTested => 6,
        }
    }
    rank(existing) >= rank(candidate)
}

pub(crate) fn html_asset_result_section(
    report: &BeginnerMasterReport,
    labels: &BTreeMap<Id, String>,
    catalog: HtmlReportCatalog,
) -> String {
    if report.requested.targets.is_empty() {
        return String::new();
    }

    // Ranked, not listed in the order the targets were declared. Under a
    // heading that promises the assets needing attention, an audit run put
    // the asset carrying one problem above the asset carrying twenty-two and
    // the failed host in the middle of the healthy ones. The order within the
    // problem tier is the report's own finding order, so this section and the
    // problems section agree on what to read first.
    let mut ranked = Vec::new();
    let mut states_taking_their_own_step: Vec<HtmlAssetResultStatus> = Vec::new();
    for (declared, target) in report.requested.targets.iter().enumerate() {
        let checks = report
            .actual
            .checks
            .iter()
            .filter(|check| check.target_asset_ids.contains(&target.asset_id))
            .collect::<Vec<_>>();
        let completed_security_checks = checks
            .iter()
            .filter(|check| html_check_completed_on_asset(check, &target.asset_id))
            .count();
        let severity_counts = asset_severity_counts(report, &target.asset_id);
        let finding_count = severity_counts
            .iter()
            .map(|(_, count)| count)
            .sum::<usize>();
        let gaps = report
            .coverage_gaps
            .iter()
            .filter(|gap| gap.target_asset_ids.contains(&target.asset_id))
            .collect::<Vec<_>>();
        let has_incomplete_check = checks.iter().any(|check| {
            matches!(
                check.status,
                CoverageDimensionStatus::TestedPartial
                    | CoverageDimensionStatus::Failed
                    | CoverageDimensionStatus::TimedOut
                    | CoverageDimensionStatus::Cancelled
            ) && !(check.status == CoverageDimensionStatus::TestedPartial
                && html_check_completed_on_asset(check, &target.asset_id))
        });
        let has_incomplete_gap = gaps.iter().any(|gap| {
            gap.class != CoverageGapClass::RecordNote
                && matches!(
                    gap.kind,
                    CoverageGapKind::Failed
                        | CoverageGapKind::TimedOut
                        | CoverageGapKind::Cancelled
                        | CoverageGapKind::Truncated
                        | CoverageGapKind::Unavailable
                        | CoverageGapKind::Unattributed
                )
        });
        let unfinished_requested_gap = gaps.iter().copied().find(|gap| {
            gap.class != CoverageGapClass::RecordNote
                && gap.kind == CoverageGapKind::NotTested
                && gap.next_action_code != NextActionCode::NoActionUnlessScopeChanges
                && gap.task_id.as_ref().is_some_and(|task_id| {
                    !checks.iter().any(|check| {
                        check.task_id == task_id.as_str()
                            && check.status == CoverageDimensionStatus::TestedComplete
                    }) && !(html_bounded_profile_limit(gap)
                        && checks.iter().any(|check| {
                            check.task_id == task_id.as_str()
                                && html_check_completed_on_asset(check, &target.asset_id)
                        }))
                })
        });
        let has_unfinished_requested_check =
            completed_security_checks > 0 && unfinished_requested_gap.is_some();
        let has_incomplete_evidence =
            has_incomplete_check || has_incomplete_gap || has_unfinished_requested_check;
        let status = if finding_count > 0 {
            HtmlAssetResultStatus::ProblemsFound
        } else if has_incomplete_evidence {
            HtmlAssetResultStatus::IncompleteOrFailed
        } else if completed_security_checks > 0 {
            HtmlAssetResultStatus::NoProblemsInCompletedChecks
        } else {
            HtmlAssetResultStatus::NotTested
        };
        let preferred_incomplete_gap = gaps.iter().copied().find(|gap| {
            gap.class != CoverageGapClass::RecordNote
                && matches!(
                    gap.kind,
                    CoverageGapKind::Failed
                        | CoverageGapKind::TimedOut
                        | CoverageGapKind::Cancelled
                        | CoverageGapKind::Truncated
                        | CoverageGapKind::Unavailable
                        | CoverageGapKind::Unattributed
                )
        });
        let preferred_gap = match status {
            HtmlAssetResultStatus::IncompleteOrFailed => {
                preferred_incomplete_gap.or(unfinished_requested_gap)
            }
            HtmlAssetResultStatus::NotTested => gaps.iter().copied().find(|gap| {
                gap.class != CoverageGapClass::RecordNote && gap.kind != CoverageGapKind::Excluded
            }),
            // A cloud check looked at identity and access alone, so its clean
            // result names what the rest of the account did not get.
            HtmlAssetResultStatus::NoProblemsInCompletedChecks => gaps
                .iter()
                .copied()
                .find(|gap| gap.kind == CoverageGapKind::ManualReview)
                .or_else(|| {
                    gaps.iter().copied().find(|gap| {
                        gap.kind == CoverageGapKind::NotTested
                            && crate::beginner_report::CLOUD_SCOPE_LIMIT_DIMENSIONS
                                .contains(&gap.dimension.as_str())
                    })
                }),
            _ => None,
        };
        // The pill names the state. It used to be followed by a sentence
        // that named it again - "Problems found" beside "Problems found: 4",
        // "Not tested" beside "No completed security check is recorded for
        // this asset" - and the only thing those sentences added was a
        // number the severity mix beside them already spells out. The one
        // count a row cannot show any other way is how many completed checks
        // came back clean, so that count moved into the pill.
        let (class_name, status_label) = match status {
            HtmlAssetResultStatus::ProblemsFound => (
                "problems-found",
                catalog.text("Problems found", "發現問題").to_owned(),
            ),
            HtmlAssetResultStatus::NoProblemsInCompletedChecks => (
                "no-problems-completed",
                match catalog.locale {
                    crate::export::ReportLocale::En if completed_security_checks == 1 => {
                        "No problems in 1 completed check".to_owned()
                    }
                    crate::export::ReportLocale::En => format!(
                        "No problems in {} completed checks",
                        catalog.format_number(completed_security_checks)
                    ),
                    crate::export::ReportLocale::ZhHant => format!(
                        "{} 項已完成檢查未發現問題",
                        catalog.format_number(completed_security_checks)
                    ),
                },
            ),
            HtmlAssetResultStatus::IncompleteOrFailed => (
                "incomplete-failed",
                catalog
                    .text("Incomplete or failed", "未完成或失敗")
                    .to_owned(),
            ),
            HtmlAssetResultStatus::NotTested => (
                "not-tested",
                catalog.text("Not tested", "尚未測試").to_owned(),
            ),
        };
        // What to do next was two different things under one heading. A step
        // that follows from the state alone is the same step on every row in
        // that state, and printing it nine times said one thing nine times.
        // A step that follows from this asset's own coverage gap belongs to
        // the row, and it was being read as more of the same. The row keeps
        // what is its own; the state's step is said once, under the table.
        // The row is the asset, so the step names only the coverage it closes.
        let mut action = preferred_gap
            .map(|gap| {
                let action = html_gap_next_action(gap, catalog);
                match gap.unattributed {
                    None if gap.dimension == "Source audit coverage" => action,
                    None => {
                        html_action_about(&action, &[html_gap_name(gap, catalog, labels)], catalog)
                    }
                    Some(_) => action,
                }
            })
            .unwrap_or_default();
        let audit_task = |id: &str| report.source_audits.iter().any(|a| a.task_id == id);
        let audit_incomplete = checks
            .iter()
            .any(|c| audit_task(&c.task_id) && c.status != CoverageDimensionStatus::TestedComplete);
        if audit_incomplete
            || (status == HtmlAssetResultStatus::ProblemsFound && has_incomplete_evidence)
        {
            let other_incomplete = checks.iter().any(|c| {
                !audit_task(&c.task_id) && c.status != CoverageDimensionStatus::TestedComplete
            }) || gaps.iter().any(|g| {
                g.task_id.as_deref().is_none_or(|id| !audit_task(id))
                    && g.class != CoverageGapClass::RecordNote
                    && !matches!(
                        g.kind,
                        CoverageGapKind::Excluded | CoverageGapKind::ManualReview
                    )
            });
            let continuation = catalog.text(
                "Continue the source audit from the listed paths.",
                "請從列出的路徑繼續原始碼稽核。",
            );
            if audit_incomplete && !action.contains(continuation) {
                if !action.is_empty() {
                    action.push(' ');
                }
                action.push_str(continuation);
            }
            if !audit_incomplete || other_incomplete {
                if !action.is_empty() {
                    action.push(' ');
                }
                action.push_str(catalog.text(
                    "Some checks are incomplete. Finish or retry them in the app.",
                    "另有檢查尚未完成；請在應用程式中完成或重試。",
                ));
            }
        }
        if status == HtmlAssetResultStatus::NoProblemsInCompletedChecks
            && report.source_audits.iter().any(|audit| {
                audit.asset_ids.contains(&target.asset_id) && !audit.to_validate.is_empty()
            })
        {
            action = catalog
                .text(
                    "validate the listed source-audit items first",
                    "請先驗證列出的原始碼稽核項目",
                )
                .to_owned();
        }
        if action.is_empty() && !states_taking_their_own_step.contains(&status) {
            states_taking_their_own_step.push(status);
        }
        let target_label = labels
            .get(&target.asset_id)
            .map(String::as_str)
            .unwrap_or(catalog.text("Saved target", "已保存的目標"));
        let target_kind = target
            .asset_kind
            .as_ref()
            .map(|kind| format!("<small>{}</small>", html_escape(catalog.asset_kind(kind))))
            .unwrap_or_default();
        // Where this asset's most urgent problem sits in the report's own
        // finding order. `usize::MAX` for an asset with none, which sorts it
        // behind every asset that has one without needing a second rule.
        let first_problem = report
            .findings
            .iter()
            .position(|finding| {
                !finding
                    .severity_basis_code
                    .is_some_and(|basis| basis.is_exposure_observation())
                    && finding.target_asset_ids.contains(&target.asset_id)
            })
            .unwrap_or(usize::MAX);
        ranked.push((
            html_asset_result_rank(status),
            first_problem,
            declared,
            format!(
                concat!(
                    "<tr class=\"asset-result asset-result--{}\">",
                    "<th scope=\"row\" class=\"asset-result__identity\"><strong>{}</strong>{}</th>",
                    "<td class=\"asset-result__signal\">",
                    "<strong class=\"pill asset-result__status\">{}</strong></td>",
                    "<td class=\"asset-result__mix\">{}</td>"
                ),
                class_name,
                html_escape_breakable_identity(target_label),
                target_kind,
                html_escape(&status_label),
                html_asset_severity_strip(
                    &severity_counts,
                    match completed_security_checks {
                        0 => HtmlSeverityMixEmptyState::NotMeasured,
                        _ => HtmlSeverityMixEmptyState::MeasuredZero,
                    },
                    catalog,
                ),
            ),
            action,
        ));
    }
    ranked.sort_by_key(|(rank, first_problem, declared, _, _)| (*rank, *first_problem, *declared));
    // A column of blanks is worse than no column. It only exists on a run
    // where some asset has a step of its own to give.
    let asset_specific = ranked.iter().any(|(_, _, _, _, action)| !action.is_empty());
    let rows = ranked
        .into_iter()
        .map(|(_, _, _, row, action)| match asset_specific {
            true => format!("{row}<td>{}</td></tr>", html_escape(&action)),
            false => format!("{row}</tr>"),
        })
        .collect::<String>();
    let (action_column, action_heading) = match asset_specific {
        true => (
            "<col>",
            format!(
                "<th scope=\"col\">{}</th>",
                catalog.text("What to do next", "下一步怎麼做")
            ),
        ),
        false => ("", String::new()),
    };
    let own_step = html_asset_state_steps(&states_taking_their_own_step, asset_specific, catalog);

    format!(
        concat!(
            "<section class=\"asset-results\"><h2>{}</h2><p>{}</p>",
            "<table class=\"asset-result-table\">",
            "<caption class=\"visually-hidden\">{}</caption><colgroup><col class=\"c-asset\">",
            "<col class=\"c-state\"><col class=\"c-mix\">{}</colgroup><thead><tr>",
            "<th scope=\"col\">{}</th><th scope=\"col\">{}</th><th scope=\"col\">{}</th>{}</tr></thead>",
            "<tbody>{}</tbody></table>{}</section>"
        ),
        catalog.text("Which assets need attention", "哪些資產需要處理"),
        catalog.text(
            "Every selected asset appears once. A no-problem result applies only to the security checks that completed.",
            "每個已選資產都會列出一次；「未發現問題」只適用於已完成的資安檢查。",
        ),
        catalog.text(
            "Assets ordered by what this run found on them",
            "依本輪在各資產上的發現排序",
        ),
        action_column,
        catalog.text("Asset", "資產"),
        catalog.text("What this run shows", "本輪的情形"),
        catalog.text("Severity mix", "嚴重程度組成"),
        action_heading,
        rows,
        own_step,
    )
}

pub(crate) fn replace_target_ids(value: &str, labels: &BTreeMap<Id, String>) -> String {
    let mut identities = labels
        .iter()
        .filter(|(id, _)| !id.is_empty())
        .collect::<Vec<_>>();
    identities.sort_by(|(left_id, _), (right_id, _)| {
        right_id
            .len()
            .cmp(&left_id.len())
            .then_with(|| left_id.cmp(right_id))
    });

    let mut display = String::with_capacity(value.len());
    let mut cursor = 0usize;
    while cursor < value.len() {
        let remaining = &value[cursor..];
        if let Some(&(id, label)) = identities
            .iter()
            .find(|(id, _)| remaining.starts_with(id.as_str()))
        {
            display.push_str(label);
            cursor += id.len();
            continue;
        }

        let character = remaining
            .chars()
            .next()
            .expect("cursor remains on a valid non-empty UTF-8 suffix");
        display.push(character);
        cursor += character.len_utf8();
    }
    display
}

/// The standing sentence this build's adapters append to every evidence
/// summary they write.
///
/// It says how raw target text is kept, which is one statement about the whole
/// report rather than a fact about the record it is stapled to. Progress
/// already drops it the same way (`engineWarningPresentation.ts`); the report
/// terms carry it once instead. A summary written by another build, or by an
/// adapter that does not append it, is left exactly as stored.
pub(crate) const UNTRUSTED_EVIDENCE_CAVEAT: &str =
    " Raw target text is retained only as untrusted evidence.";

/// Scanner-authored fix text for the finding card's first layer.
///
/// Product next-action prose names the kind of change. The scanner's own
/// remediation text or reported fixed version is the specific step when it
/// supplied one. An absent suggestion adds nothing to the first layer.
/// Collapsed evidence still carries the same strings as provenance.
pub(crate) fn html_scanner_remediation_block(
    finding: &crate::beginner_report::BeginnerFinding,
    catalog: HtmlReportCatalog,
) -> String {
    let label = catalog.text("Scanner-provided remediation", "掃描工具提供的修復資訊");
    let mut unique = Vec::new();
    for reference in &finding.evidence_references {
        let Some(text) = reference
            .scanner_details
            .as_ref()
            .and_then(|details| details.remediation.as_deref())
            .map(str::trim)
            .filter(|text| !text.is_empty())
        else {
            continue;
        };
        if !unique.contains(&text) {
            unique.push(text);
        }
    }
    let mut fixed_versions = Vec::new();
    for reference in &finding.evidence_references {
        let Some(version) = reference
            .scanner_details
            .as_ref()
            .and_then(|details| details.fixed_version.as_deref())
            .map(str::trim)
            .filter(|version| !version.is_empty())
        else {
            continue;
        };
        if !fixed_versions.contains(&version) {
            fixed_versions.push(version);
        }
    }
    if unique.is_empty() && fixed_versions.is_empty() {
        return String::new();
    }
    let mut html = unique
        .into_iter()
        .map(|text| {
            format!(
                "<p class=\"finding-scanner-remediation\">{}{}</p>",
                catalog.strong_label(label),
                html_escape(text)
            )
        })
        .collect::<String>();
    if !fixed_versions.is_empty() {
        let fixed_label =
            catalog.text("Scanner-provided fixed version", "掃描工具提供的修正版版本");
        let versions = fixed_versions
            .into_iter()
            .map(html_escape)
            .collect::<Vec<_>>()
            .join(catalog.text(", ", "、"));
        html.push_str(&format!(
            "<p class=\"finding-scanner-remediation\">{}{}</p>",
            catalog.strong_label(fixed_label),
            versions
        ));
    }
    html
}

/// The places a finding names, in the words the Results page uses, from the
/// same evidence locations the technical details print raw.
///
/// The Standard-redaction placeholder is skipped: a masked report must not
/// print "Location: [redacted location]" on every card. Locations are
/// de-duplicated after formatting, so raw strings that differ only in KICS's
/// similarity hash name one place.
fn html_finding_locations(
    finding: &crate::beginner_report::BeginnerFinding,
    catalog: HtmlReportCatalog,
) -> Vec<String> {
    let mut locations: Vec<String> = Vec::new();
    for reference in &finding.evidence_references {
        let Some(raw) = reference.location.as_deref().map(str::trim) else {
            continue;
        };
        if raw.is_empty() || raw == crate::export::REDACTED_LOCATION {
            continue;
        }
        let formatted = match catalog.locale {
            crate::export::ReportLocale::En => crate::finding_narrative::location_english(raw),
            crate::export::ReportLocale::ZhHant => crate::finding_narrative::location_zh_hant(raw),
        };
        if !locations.contains(&formatted) {
            locations.push(formatted);
        }
    }
    locations
}

/// The first place, and how many others there are. One place is named on its
/// own; a longer list stays one line.
fn html_step_location_summary(locations: &[String], catalog: HtmlReportCatalog) -> Option<String> {
    let (first, rest) = locations.split_first()?;
    let extra = rest.len();
    Some(if extra == 0 {
        first.clone()
    } else {
        match catalog.locale {
            crate::export::ReportLocale::En => format!("{first} and {extra} more"),
            crate::export::ReportLocale::ZhHant => format!("{first}，另有 {extra} 處"),
        }
    })
}

/// The last character a reader sees, ignoring tags. `gap_after` uses it so a
/// confirmation sentence that ends on 。 is not followed by an ASCII space.
fn last_visible_char(html: &str) -> Option<char> {
    let mut last = None;
    let mut inside_tag = false;
    for character in html.chars() {
        match character {
            '<' => inside_tag = true,
            '>' => inside_tag = false,
            _ if !inside_tag => last = Some(character),
            _ => {}
        }
    }
    last
}

/// Where the finding is. A finding with nothing left renders no paragraph.
fn html_finding_location_block(
    finding: &crate::beginner_report::BeginnerFinding,
    catalog: HtmlReportCatalog,
) -> String {
    let locations = html_finding_locations(finding, catalog);
    if locations.is_empty() {
        return String::new();
    }
    format!(
        "<p class=\"finding-location\">{}{}</p>",
        catalog.strong_label(catalog.text("Location", "位置")),
        locations
            .into_iter()
            .map(|location| html_escape(&location))
            .collect::<Vec<_>>()
            .join(catalog.text("; ", "；"))
    )
}

/// Benchmark lines the scanner reported, one per engine, in evidence order.
fn html_benchmark_line(
    finding: &crate::beginner_report::BeginnerFinding,
    catalog: HtmlReportCatalog,
) -> Option<String> {
    let mut by_engine: Vec<(String, Vec<crate::domain::BenchmarkReference>)> = Vec::new();
    for reference in &finding.evidence_references {
        let Some(details) = reference.scanner_details.as_ref() else {
            continue;
        };
        if details.benchmarks.is_empty() {
            continue;
        }
        if let Some((_, benchmarks)) = by_engine
            .iter_mut()
            .find(|(engine_id, _)| engine_id == &reference.engine_id)
        {
            for benchmark in &details.benchmarks {
                if !benchmarks.contains(benchmark) {
                    benchmarks.push(benchmark.clone());
                }
            }
        } else {
            let mut benchmarks = Vec::new();
            for benchmark in &details.benchmarks {
                if !benchmarks.contains(benchmark) {
                    benchmarks.push(benchmark.clone());
                }
            }
            by_engine.push((reference.engine_id.clone(), benchmarks));
        }
    }
    let lines = by_engine
        .into_iter()
        .filter_map(|(engine_id, benchmarks)| {
            let engine = engine_named(&engine_id);
            match catalog.locale {
                crate::export::ReportLocale::En => {
                    crate::finding_narrative::benchmark_line_english(&engine, &benchmarks)
                }
                crate::export::ReportLocale::ZhHant => {
                    crate::finding_narrative::benchmark_line_zh_hant(&engine, &benchmarks)
                }
            }
        })
        .collect::<Vec<_>>();
    if lines.is_empty() {
        None
    } else {
        Some(lines.join(catalog.text("; ", "；")))
    }
}

/// The product order reason, in the report's language, when one was recorded.
fn html_lower_order_reason(
    finding: &crate::beginner_report::BeginnerFinding,
    catalog: HtmlReportCatalog,
) -> Option<String> {
    let guidance = crate::priority_guidance::PriorityGuidance::from_priority_reasons(
        &finding.priority_reasons,
    )?;
    let english = guidance.reason_english();
    Some(match catalog.locale {
        crate::export::ReportLocale::En => {
            crate::finding_narrative::priority_reason_english(english)
        }
        crate::export::ReportLocale::ZhHant => {
            crate::finding_narrative::priority_reason_zh_hant(english)
        }
    })
}

/// Scanner benchmark and, when this product ordered the check lower than its
/// severity suggests, the reason. Both are read from the same scanner details
/// and priority reasons the rest of the card already uses.
fn html_priority_basis_block(
    finding: &crate::beginner_report::BeginnerFinding,
    catalog: HtmlReportCatalog,
) -> String {
    let benchmark = html_benchmark_line(finding, catalog);
    let reason = html_lower_order_reason(finding, catalog);
    match (benchmark, reason) {
        (None, None) => String::new(),
        (Some(benchmark), None) => format!(
            "<p class=\"finding-priority-basis\">{}{}</p>",
            catalog.strong_label(catalog.text("Benchmark", "基準")),
            html_escape(&benchmark)
        ),
        (None, Some(reason)) => format!(
            "<p class=\"finding-priority-basis\">{}{}</p>",
            catalog.strong_label(catalog.text("Why this order", "排序原因")),
            html_escape(&reason)
        ),
        (Some(benchmark), Some(reason)) => format!(
            "<p class=\"finding-priority-basis\">{}{}<br>{}{}</p>",
            catalog.strong_label(catalog.text("Benchmark", "基準")),
            html_escape(&benchmark),
            catalog.strong_label(catalog.text("Why this order", "排序原因")),
            html_escape(&reason)
        ),
    }
}

pub(crate) fn html_evidence_reference(
    reference: &crate::beginner_report::FindingEvidenceReference,
    catalog: HtmlReportCatalog,
) -> String {
    let identity = format!(
        concat!("<code>{}</code><br>", "{} {} · {} {} · {} {}"),
        html_escape(&reference.artifact_sha256),
        catalog.text("Evidence", "證據"),
        html_escape(&reference.evidence_id),
        catalog.text("Check", "檢查"),
        html_escape(&reference.engine_id),
        catalog.text("Observed", "觀察時間"),
        html_escape(&catalog.format_time(&reference.observed_at)),
    );
    if !reference.details_frozen {
        return format!(
            "<li>{identity}<p><em>{}</em></p></li>",
            catalog.text(
                "Detailed evidence fields were not frozen for this legacy result; this report does not infer them from the current finding or another run.",
                "這筆舊版結果未凍結詳細證據欄位；本報告不會從目前的問題紀錄或其他掃描輪次推測這些內容。",
            )
        );
    }

    let unavailable = catalog.text("not provided", "未提供");
    let source_rule = reference.source_rule.as_deref().unwrap_or(unavailable);
    let summary = reference.summary.as_deref().unwrap_or(unavailable);
    let summary = summary
        .strip_suffix(UNTRUSTED_EVIDENCE_CAVEAT)
        .unwrap_or(summary);
    let kind = reference
        .kind
        .as_ref()
        .map(|kind| catalog.identifier(&enum_key(kind)))
        .unwrap_or_else(|| unavailable.into());
    let engine_run_id = reference.engine_run_id.as_deref().unwrap_or(unavailable);
    let artifact_id = reference.artifact_id.as_deref().unwrap_or(unavailable);
    // The digest above proves the retained artifact was not altered; without
    // the pointer a reader still cannot find the one record the finding came
    // from inside it. The inventory provenance has printed it all along.
    let pointer = reference.pointer.as_deref().unwrap_or(unavailable);
    let location = reference.location.as_deref().unwrap_or(unavailable);
    // A line that glues together the three rows beside it is not a summary.
    // This build's adapters write "<engine> reported rule <rule> at
    // <location>.", and the block already labels the check, the source rule
    // and the location; in the Chinese report it was the one English line in
    // an otherwise translated record. A summary that says anything else --
    // from another build, or an adapter that writes its own -- is kept.
    let restates_its_neighbours = format!(
        "{} reported rule {} at {}.",
        reference.engine_id, source_rule, location
    );
    let summary = match summary == restates_its_neighbours {
        true => String::new(),
        false => format!(
            "<dt>{}</dt><dd>{}</dd>",
            catalog.text("Evidence summary", "證據摘要"),
            html_escape(summary),
        ),
    };
    // Redaction is worth a row where it happened. Forty-eight of fifty-one
    // evidence records said "Redacted: No", which is this report's default and
    // is already stated once in the terms as the run's redaction profile. A
    // record that does not know stays on the page, because that is not the
    // same as knowing nothing was redacted.
    let redacted = match reference.redacted {
        Some(true) => format!(
            "<dt>{}</dt><dd>{}</dd>",
            catalog.text("Redacted", "已遮蔽"),
            catalog.text("Yes", "是"),
        ),
        Some(false) => String::new(),
        None => format!(
            "<dt>{}</dt><dd>{}</dd>",
            catalog.text("Redacted", "已遮蔽"),
            unavailable,
        ),
    };

    let scanner_details = match &reference.scanner_details {
        Some(details) => {
            let mut rows = String::new();
            if let Some(description) = &details.description {
                rows.push_str(&format!(
                    "<dt>{}</dt><dd>{}</dd>",
                    catalog.text(
                        "Scanner-provided description",
                        "掃描工具提供的說明"
                    ),
                    html_escape(description),
                ));
            }
            if let Some(remediation) = &details.remediation {
                rows.push_str(&format!(
                    "<dt>{}</dt><dd>{}</dd>",
                    catalog.text(
                        "Scanner-provided remediation",
                        "掃描工具提供的修復資訊"
                    ),
                    html_escape(remediation),
                ));
            }
            if let Some(installed_version) = &details.installed_version {
                rows.push_str(&format!(
                    "<dt>{}</dt><dd><code>{}</code></dd>",
                    catalog.text(
                        "Scanner-provided installed version",
                        "掃描工具提供的已安裝版本"
                    ),
                    html_escape(installed_version),
                ));
            }
            if let Some(fixed_version) = &details.fixed_version {
                rows.push_str(&format!(
                    "<dt>{}</dt><dd><code>{}</code></dd>",
                    catalog.text(
                        "Scanner-provided fixed version",
                        "掃描工具提供的修正版版本"
                    ),
                    html_escape(fixed_version),
                ));
            }
            if !details.cwe_ids.is_empty() {
                rows.push_str(&format!(
                    "<dt>{}</dt><dd>{}</dd>",
                    catalog.text("Scanner-assigned CWE", "掃描工具標定的 CWE"),
                    details
                        .cwe_ids
                        .iter()
                        .map(|cwe| format!("<code>{}</code>", html_escape(cwe)))
                        .collect::<Vec<_>>()
                        .join(catalog.text(", ", "、")),
                ));
            }
            for score in &details.cvss {
                // Each score keeps the source that published it. Two engines
                // scoring the same vulnerability differently is information the
                // reader needs, not a conflict for this product to resolve.
                let version = if score.version == "unspecified" {
                    catalog.text("version not stated", "未載明版本").to_owned()
                } else {
                    format!("v{}", html_escape(&score.version))
                };
                rows.push_str(&format!(
                    "<dt>{}</dt><dd><code>{}</code> · {} · {}{}</dd>",
                    catalog.text("Scanner-reported CVSS", "掃描工具回報的 CVSS"),
                    html_escape(&score.base_score),
                    version,
                    catalog.text("scored by ", "評分來源 "),
                    html_escape(&score.source),
                ));
                if let Some(vector) = &score.vector {
                    rows.push_str(&format!(
                        "<dt>{}</dt><dd><code>{}</code></dd>",
                        catalog.text("CVSS vector", "CVSS 向量"),
                        html_escape(vector),
                    ));
                }
            }
            if reference.engine_id == "cloudsplaining"
                && let Some(iam) = &details.aws_iam_policy
            {
                let source = match catalog.locale {
                    crate::export::ReportLocale::En => {
                        crate::finding_narrative::aws_iam_policy_source_label_english(
                            iam.policy_source,
                        )
                    }
                    crate::export::ReportLocale::ZhHant => {
                        crate::finding_narrative::aws_iam_policy_source_label_zh_hant(
                            iam.policy_source,
                        )
                    }
                };
                let value = |items: &[String]| {
                    if items.is_empty() {
                        unavailable.to_owned()
                    } else {
                        let mut preview = items
                            .iter()
                            .take(6)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" · ");
                        let omitted = items.len().saturating_sub(6);
                        if omitted > 0 {
                            preview.push_str(catalog.text(
                                &format!(" · +{omitted} more"),
                                &format!(" · 另有 {omitted} 項"),
                            ));
                        }
                        preview
                    }
                };
                let action_label = if iam.actions_complete {
                    catalog.text("Reported actions", "回報的動作")
                } else {
                    catalog.text("Retained actions", "已保留的動作")
                };
                // Cloudsplaining keys a finding on the action it found, so a
                // record carrying that one action and nothing else printed the
                // same string under two labels -- sixteen of the eighteen
                // policy records read that way. The upstream identity stays
                // wherever the list says anything more, and wherever the list
                // is not the whole list: there the identity is the only thing
                // the reader can be sure the scanner keyed on.
                let identity_is_the_whole_action_list = iam.actions_complete
                    && matches!(iam.actions.as_slice(), [only] if *only == iam.finding_identity);
                let mut fields = vec![
                    ("Policy source", "政策來源", source.to_owned()),
                    ("Policy", "政策", iam.policy_name.clone()),
                ];
                if !identity_is_the_whole_action_list {
                    fields.push((
                        "Upstream finding",
                        "上游問題",
                        iam.finding_identity.clone(),
                    ));
                }
                fields.push((action_label, action_label, value(&iam.actions)));
                for (label_en, label_zh, value) in fields {
                    rows.push_str(&format!(
                        "<dt>{}</dt><dd>{}</dd>",
                        catalog.text(label_en, label_zh),
                        html_escape(&value),
                    ));
                }
                // An empty attachment list in a complete record is not a
                // missing value: the scanner said no principal of that kind is
                // attached. Written as "not provided" it claimed the opposite
                // on thirty-six of fifty-four rows, and every policy in that
                // run was attached to exactly one kind of principal. An
                // incomplete record keeps its row, because there the value
                // really is unknown, and the note below says so.
                let mut attachment_rows = 0usize;
                for (label_en, label_zh, items) in [
                    ("Attached roles", "附加的角色", &iam.attached_to.roles),
                    ("Attached groups", "附加的群組", &iam.attached_to.groups),
                    ("Attached users", "附加的使用者", &iam.attached_to.users),
                ] {
                    if items.is_empty() && iam.attached_to.complete {
                        continue;
                    }
                    attachment_rows += 1;
                    rows.push_str(&format!(
                        "<dt>{}</dt><dd>{}</dd>",
                        catalog.text(label_en, label_zh),
                        html_escape(&value(items)),
                    ));
                }
                if attachment_rows == 0 && iam.attached_to.complete {
                    rows.push_str(&format!(
                        "<dt>{}</dt><dd>{}</dd>",
                        catalog.text("Attached to", "附加對象"),
                        catalog.text(
                            "No role, group or user is attached.",
                            "未附加任何角色、群組或使用者。",
                        ),
                    ));
                }
                if !iam.actions_complete {
                    rows.push_str(&format!(
                        "<dt>{}</dt><dd>{}</dd>",
                        catalog.text("Action detail", "動作資訊"),
                        catalog.text(
                            "The action list was shortened or sanitized for display. Open the raw evidence for the complete upstream list.",
                            "動作清單為了顯示而經過縮減或清理；完整上游清單請查看原始證據。",
                        ),
                    ));
                }
                if !iam.attached_to.complete {
                    rows.push_str(&format!(
                        "<dt>{}</dt><dd>{}</dd>",
                        catalog.text("Attachment detail", "附加資訊"),
                        catalog.text(
                            "The retained attachment list is incomplete. Confirm the current IAM attachments before changing this policy.",
                            "保留的附加清單不完整；變更此政策前請先核對目前的 IAM 附加關係。",
                        ),
                    ));
                }
            }
            if rows.is_empty() {
                format!(
                    "<p><em>{}</em></p>",
                    catalog.text(
                        "The scanner retained no structured description, remediation, or version detail for this evidence.",
                        "掃描工具未替這筆證據保留結構化說明、修復資訊或版本細節。"
                    )
                )
            } else {
                format!(
                    "<p><strong>{}</strong></p><dl>{rows}</dl>",
                    catalog.text(
                        "Scanner-provided details",
                        "掃描工具提供的詳細資料"
                    )
                )
            }
        }
        None => format!(
            "<p><em>{}</em></p>",
            catalog.text(
                "The scanner provided no structured description, remediation, or version detail for this evidence.",
                "掃描工具未替這筆證據提供結構化說明、修復資訊或版本細節。"
            )
        ),
    };

    format!(
        concat!(
            "<li>{}<dl>",
            "<dt>{}</dt><dd><code>{}</code></dd>",
            "{}",
            "<dt>{}</dt><dd>{}</dd>",
            "<dt>{}</dt><dd><code>{}</code></dd>",
            "<dt>{}</dt><dd><code>{}</code></dd>",
            "<dt>{}</dt><dd><code>{}</code></dd>",
            "{}",
            "<dt>{}</dt><dd>{}</dd>",
            "</dl>{}</li>"
        ),
        identity,
        catalog.text("Source rule", "來源規則"),
        html_escape(source_rule),
        summary,
        catalog.text("Evidence kind", "證據類型"),
        html_escape(&kind),
        catalog.text("Engine run ID", "掃描工具執行 ID"),
        html_escape(engine_run_id),
        catalog.text("Artifact ID", "成品 ID"),
        html_escape(artifact_id),
        catalog.text("Result pointer", "結果指標"),
        html_escape(pointer),
        redacted,
        catalog.text("Evidence location", "證據位置"),
        html_escape(location),
        scanner_details,
    )
}

use crate::beginner_report::finding_aws_iam_policy as beginner_aws_iam_policy;

pub(crate) fn html_official_references(
    references: &Option<Vec<String>>,
    catalog: HtmlReportCatalog,
) -> String {
    match references {
        Some(references) if !references.is_empty() => references
            .iter()
            // Render scanner URLs as inert text. The report never creates a
            // remote-loading element or turns untrusted scanner text into a
            // clickable navigation instruction.
            .map(|reference| format!("<li><code>{}</code></li>", html_escape(reference)))
            .collect(),
        Some(_) => catalog
            .text(
                "<li>No official scanner reference was retained for this selected-run finding.</li>",
                "<li>本輪保存的問題未保留掃描工具官方參照。</li>",
            )
            .into(),
        None => catalog
            .text(
                "<li>Official references were not frozen for this legacy result; none are inferred from the current finding.</li>",
                "<li>這筆舊版結果未凍結官方參照；本報告不會從目前的問題紀錄推測參照。</li>",
            )
            .into(),
    }
}

fn html_inventory_item_summary(item: &BeginnerInventoryItem, catalog: HtmlReportCatalog) -> String {
    let mut details = Vec::new();
    let kind = match &item.details {
        BeginnerInventoryItemKind::Service {
            endpoint,
            port,
            transport,
            schemes,
            http_statuses,
            tls_observations,
        } => {
            details.push(format!(
                "{} <code>{}</code>",
                catalog.text("Endpoint", "端點"),
                html_escape(endpoint)
            ));
            if let Some(port) = port {
                details.push(format!(
                    "{} {}",
                    catalog.text("port", "連接埠"),
                    // A port is an address the reader may copy, not a quantity.
                    // Digit grouping turns 8080 into 8,080, which no tool takes.
                    port
                ));
            }
            if let Some(transport) = transport {
                details.push(format!(
                    "{} <code>{}</code>",
                    catalog.text("transport", "傳輸協定"),
                    html_escape(transport)
                ));
            }
            if !schemes.is_empty() {
                details.push(format!(
                    "{} {}",
                    catalog.text("schemes", "通訊方案"),
                    schemes
                        .iter()
                        .map(|value| format!("<code>{}</code>", html_escape(value)))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !http_statuses.is_empty() {
                details.push(format!(
                    "{} {}",
                    catalog.text("HTTP status", "HTTP 狀態"),
                    // A response code is an identifier too, on the same rule.
                    http_statuses
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !tls_observations.is_empty() {
                details.push(format!(
                    "TLS {}",
                    tls_observations
                        .iter()
                        .map(|value| catalog.text(
                            if *value { "yes" } else { "no" },
                            if *value { "是" } else { "否" }
                        ))
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            catalog.text("Service", "服務")
        }
        BeginnerInventoryItemKind::SoftwareComponent {
            name,
            version,
            package_type,
            purl,
        } => {
            details.push(format!(
                "{} <code>{}</code>",
                catalog.text("Name", "名稱"),
                html_escape(name)
            ));
            for (label, value) in [
                (catalog.text("version", "版本"), version.as_deref()),
                (
                    catalog.text("package type", "套件類型"),
                    package_type.as_deref(),
                ),
                ("purl", purl.as_deref()),
            ] {
                if let Some(value) = value {
                    details.push(format!("{label} <code>{}</code>", html_escape(value)));
                }
            }
            catalog.text("Software component", "軟體元件")
        }
        BeginnerInventoryItemKind::CloudResource {
            resource_type,
            native_id,
            display_name,
        } => {
            details.push(format!(
                "{} <code>{}</code>",
                catalog.text("Resource type", "資源類型"),
                html_escape(resource_type)
            ));
            for (label, value) in [
                (catalog.text("native ID", "原生 ID"), native_id.as_deref()),
                (
                    catalog.text("display name", "顯示名稱"),
                    display_name.as_deref(),
                ),
            ] {
                if let Some(value) = value {
                    details.push(format!("{label} <code>{}</code>", html_escape(value)));
                }
            }
            catalog.text("Cloud resource", "雲端資源")
        }
        BeginnerInventoryItemKind::WorkflowComponent {
            component_type,
            name,
            model,
            is_guardrail,
        } => {
            details.push(format!(
                "{} <code>{}</code>",
                catalog.text("Name", "名稱"),
                html_escape(name)
            ));
            details.push(format!(
                "{} <code>{}</code>",
                catalog.text("component type", "元件類型"),
                html_escape(component_type)
            ));
            if let Some(model) = model {
                details.push(format!(
                    "{} <code>{}</code>",
                    catalog.text("model", "模型"),
                    html_escape(model)
                ));
            }
            if let Some(is_guardrail) = is_guardrail {
                details.push(
                    catalog
                        .text(
                            if *is_guardrail {
                                "guardrail yes"
                            } else {
                                "guardrail no"
                            },
                            if *is_guardrail {
                                "護欄：是"
                            } else {
                                "護欄：否"
                            },
                        )
                        .to_owned(),
                );
            }
            catalog.text("Workflow component", "工作流程元件")
        }
        BeginnerInventoryItemKind::WorkflowRelationship {
            source,
            target,
            condition,
        } => {
            details.push(format!(
                "<code>{}</code> → <code>{}</code>",
                html_escape(source),
                html_escape(target)
            ));
            if let Some(condition) = condition {
                details.push(format!(
                    "{} <code>{}</code>",
                    catalog.text("condition", "條件"),
                    html_escape(condition)
                ));
            }
            catalog.text("Workflow relationship", "工作流程關係")
        }
    };
    format!("<strong>{kind}</strong> — {}", details.join(" · "))
}

fn html_inventory_sources(item: &BeginnerInventoryItem, catalog: HtmlReportCatalog) -> String {
    let sources = item
        .sources
        .iter()
        .map(|source| {
            format!(
                concat!(
                    "<li><strong>{}</strong> <code>{}</code> · ",
                    "{} <code>{}</code> · {} <code>{}</code>",
                    "<br>{} <code>{}</code> · SHA-256 <code>{}</code>",
                    "<br>{} <code>{}</code> · {} {}</li>"
                ),
                catalog.text("Observation", "觀察紀錄"),
                html_escape(&source.observation_id),
                catalog.text("engine", "掃描工具"),
                html_escape(&source.engine_id),
                catalog.text("engine run", "掃描工具執行"),
                html_escape(&source.engine_run_id),
                catalog.text("artifact", "成品"),
                html_escape(&source.artifact_id),
                html_escape(&source.artifact_sha256),
                catalog.text("pointer", "資料指標"),
                html_escape(&source.pointer),
                catalog.text("observed", "觀察時間"),
                html_escape(&catalog.format_time(&source.observed_at)),
            )
        })
        .collect::<String>();
    if sources.is_empty() {
        catalog
            .text(
                "<li>No selected-run source provenance was retained.</li>",
                "<li>未保留本輪的來源追溯資料。</li>",
            )
            .into()
    } else {
        sources
    }
}

fn html_typed_inventory_section(
    report: &BeginnerMasterReport,
    target_labels: &BTreeMap<Id, String>,
    catalog: HtmlReportCatalog,
) -> String {
    if report.inventory.total == 0 {
        return String::new();
    }

    let sample = report
        .inventory
        .representative_sample
        .iter()
        .take(3)
        .map(|item| {
            format!(
                "<li class=\"inventory-sample-item\">{}</li>",
                html_inventory_item_summary(item, catalog)
            )
        })
        .collect::<String>();
    let mut grouped = String::new();
    for asset_id in &report.inventory.asset_ids {
        let label = target_labels
            .get(asset_id)
            .map(String::as_str)
            .unwrap_or(catalog.text("Saved target", "已保存的目標"));
        let items = report
            .inventory
            .items
            .iter()
            .filter(|item| item.asset_id == *asset_id)
            .map(|item| {
                format!(
                    concat!(
                        "<li>{}<details class=\"source-provenance\"><summary>{}</summary>",
                        "<ul>{}</ul></details></li>"
                    ),
                    html_inventory_item_summary(item, catalog),
                    catalog.text("Source provenance", "來源追溯資料"),
                    html_inventory_sources(item, catalog),
                )
            })
            .collect::<String>();
        grouped.push_str(&format!(
            "<section><h4>{} <code>{}</code></h4><ul>{}</ul></section>",
            html_escape(label),
            html_escape(asset_id),
            items,
        ));
    }
    let workflow_counts = [
        (
            "Workflow components",
            "工作流程元件",
            report.inventory.counts.workflow_components,
        ),
        (
            "Workflow relationships",
            "工作流程關係",
            report.inventory.counts.workflow_relationships,
        ),
    ]
    .into_iter()
    .filter(|(_, _, count)| *count > 0)
    .map(|(en, zh, count)| {
        format!(
            "{}{}",
            catalog.strong_label(catalog.text(en, zh)),
            catalog.format_number(count)
        )
    })
    .collect::<Vec<_>>()
    .join(" · ");
    let workflow_counts = if workflow_counts.is_empty() {
        String::new()
    } else {
        format!("<p>{workflow_counts}</p>")
    };

    format!(
        concat!(
            "<section><h2>{}</h2><p>{}</p>",
            "<p>{}{} · {}{} · ",
            "{}{} · {}{} · ",
            "{}{} · {}{}</p>",
            "{}",
            "<p>{}{}</p>",
            "<h3>{}</h3><ul class=\"inventory-sample\">{}</ul>",
            "<details class=\"inventory-complete\"><summary><strong>{}</strong></summary>{}</details></section>"
        ),
        catalog.text("Inventory observations", "盤點觀察"),
        catalog.text(
            "Inventory observations are separate from vulnerability findings and remediation priorities.",
            "盤點觀察與漏洞問題及修復優先順序分開呈現。",
        ),
        catalog.strong_label(catalog.text("Total", "總數")),
        catalog.format_number(report.inventory.total),
        catalog.strong_label(catalog.text("Services", "服務")),
        catalog.format_number(report.inventory.counts.services),
        catalog.strong_label(catalog.text("Software components", "軟體元件")),
        catalog.format_number(report.inventory.counts.software_components),
        catalog.strong_label(catalog.text("Cloud resources", "雲端資源")),
        catalog.format_number(report.inventory.counts.cloud_resources),
        catalog.strong_label(catalog.text("Inventoried assets", "已盤點資產")),
        catalog.format_number(report.inventory.asset_ids.len()),
        catalog.strong_label(catalog.text("Representative records", "代表性紀錄")),
        catalog.format_number(report.inventory.representative_sample.len().min(3)),
        workflow_counts,
        catalog.strong_label(catalog.text("Inventoried asset list", "已盤點資產清單")),
        readable_target_list(
            &report.inventory.asset_ids,
            target_labels,
            catalog,
        ),
        catalog.text("Representative sample (maximum 3)", "代表性樣本（最多 3 筆）"),
        sample,
        catalog.text("Complete inventory by asset", "依資產列出的完整盤點清單"),
        grouped,
    )
}

/// Every redaction marker this build writes, named in Traditional Chinese.
///
/// A redacted case is assembled before a locale is chosen -- the same case is
/// exported as canonical JSON and rendered in both languages -- so the markers
/// go in in English. Left that way, a Chinese standard-redacted report carried
/// three hundred and fifty-three English brackets sitting under translated
/// labels, in the one export a reader is most likely to hand to someone else.
const REDACTION_MARKERS: [(&str, &str); 50] = [
    ("authority assertion", "授權陳述"),
    ("cleanup detail", "清理細節"),
    ("comparison completeness reason", "比對完整性原因"),
    ("comparison detail", "比對細節"),
    ("comparison reason", "比對原因"),
    ("control", "控制項"),
    ("control id", "控制項 ID"),
    ("coverage detail", "涵蓋細節"),
    ("data-quality warning", "資料品質警告"),
    ("display name", "顯示名稱"),
    ("endpoint", "端點"),
    ("engine error detail", "掃描工具錯誤細節"),
    ("engine warning", "掃描工具警告"),
    ("evidence summary", "證據摘要"),
    ("executed scope", "已執行的範圍"),
    ("external target", "外部目標"),
    ("finding group", "問題群組"),
    ("finding workflow reason", "問題流程原因"),
    ("grouping rationale", "群組理由"),
    ("IAM group", "IAM 群組"),
    ("IAM policy", "IAM 政策"),
    ("IAM role", "IAM 角色"),
    ("IAM user", "IAM 使用者"),
    ("identifier", "識別碼"),
    ("inventory pointer", "資料指標"),
    ("location", "位置"),
    ("manual-review control", "待人工判定的控制項"),
    ("manual-review detail", "待人工判定的細節"),
    ("model", "模型"),
    ("model identifier", "模型識別碼"),
    ("native ID", "原生 ID"),
    ("observation detail", "觀察細節"),
    ("provider", "供應商"),
    ("purl", "purl"),
    ("region", "區域"),
    ("relationship condition", "連接條件"),
    ("relationship endpoint", "連接端點"),
    ("relationship source", "連接來源"),
    ("relationship target", "連接目標"),
    ("requested scope", "要求的範圍"),
    ("result pointer", "結果指標"),
    ("scanner-provided description", "掃描工具提供的說明"),
    ("scanner-provided remediation", "掃描工具提供的修復資訊"),
    ("scope limit", "範圍限制"),
    ("service endpoint", "服務端點"),
    ("software component", "軟體元件"),
    ("target", "目標"),
    ("version", "版本"),
    ("workflow component", "工作流程元件"),
    ("purl set", "purl 集合"),
];

/// The three markers the redaction numbers as it assigns them. The number is
/// what tells one redacted target from another, so it is kept.
const NUMBERED_REDACTION_MARKERS: [(&str, &str); 7] = [
    ("address set", "位址集合"),
    ("IAM group", "IAM 群組"),
    ("IAM policy", "IAM 政策"),
    ("IAM role", "IAM 角色"),
    ("IAM user", "IAM 使用者"),
    ("network target", "網路目標"),
    ("port set", "連接埠集合"),
];

fn localized_redaction_marker(named: &str) -> Option<String> {
    if let Some((_, chinese)) = REDACTION_MARKERS
        .iter()
        .find(|(english, _)| *english == named)
    {
        return Some((*chinese).to_owned());
    }
    let (stem, number) = named.rsplit_once(' ')?;
    number.parse::<u32>().ok()?;
    NUMBERED_REDACTION_MARKERS
        .iter()
        .find(|(english, _)| *english == stem)
        .map(|(_, chinese)| format!("{chinese} {number}"))
}

/// Names every marker in a finished document, and leaves anything else alone.
///
/// Run over the built page rather than at each field: the markers arrive on
/// values the report only passes through -- a location, a policy name, a
/// scope limit with its holders after it -- and a rule applied at one of the
/// twenty places those are printed is a rule the twenty-first will miss.
pub(crate) fn localize_redaction_markers(document: &str) -> String {
    const OPEN: &str = "[redacted ";
    let mut localized = String::with_capacity(document.len());
    let mut rest = document;
    while let Some(at) = rest.find(OPEN) {
        let (before, marker) = rest.split_at(at);
        localized.push_str(before);
        let Some((named, after)) = marker[OPEN.len()..].split_once(']') else {
            localized.push_str(marker);
            return localized;
        };
        match localized_redaction_marker(named) {
            Some(chinese) => localized.push_str(&format!("（{chinese}）")),
            // An unknown marker stays exactly as the redaction wrote it. A
            // reader seeing English there is told less than they should be,
            // but never told something the redaction did not say.
            None => localized.push_str(&marker[..OPEN.len() + named.len() + 1]),
        }
        rest = after;
    }
    localized.push_str(rest);
    localized
}

/// The fixed English sentences the report model writes into a task record.
///
/// They arrive already composed, printed between a translated label and a
/// translated footnote, so left alone they are the English in an otherwise
/// Chinese record. The connection test's contract is the one that matters
/// most: it is the sentence saying the task was not a vulnerability scan, on
/// the one task a reader is most likely to mistake for one.
///
/// Only the sentences this build writes are named. Anything else a build
/// stores here is printed in the language it was stored in -- less than a
/// reader should get, but never something the record did not say.
pub(crate) fn translated_task_sentence(catalog: HtmlReportCatalog, stored: &str) -> &str {
    match stored {
        "One desktop-host TCP connection attempt; no application payload; reachability observation only." => {
            catalog.text(
                stored,
                "對桌面主機嘗試一次 TCP 連線；不送出應用層資料；只取得可連線與否的觀察。",
            )
        }
        "Stored localhost task contract: unsupported. Endpoint observation: unavailable." => {
            catalog.text(stored, "保存的本機工作契約不受支援；端點觀察無法取得。")
        }
        "Run-bound diagnostic log: unavailable. Redacted diagnostic export: separate." => catalog
            .text(
                stored,
                "本輪的診斷紀錄無法取得；已遮蔽的診斷匯出為獨立檔案。",
            ),
        stored => stored,
    }
}

pub(crate) fn html_confidence_legend(
    confidence_bases_used: &[crate::domain::ConfidenceBasisCode],
    confidence_basis_counts: &[(crate::domain::ConfidenceBasisCode, usize)],
    catalog: HtmlReportCatalog,
) -> String {
    if confidence_bases_used.is_empty() {
        return String::new();
    }
    let mut bases = confidence_bases_used.to_vec();
    bases.sort_by_key(|code| {
        std::cmp::Reverse(
            confidence_basis_counts
                .iter()
                .find_map(|(used, count)| (used == code).then_some(*count))
                .unwrap_or(0),
        )
    });
    let detection_quality_unavailable =
        bases.contains(&crate::domain::ConfidenceBasisCode::MissingDetectionQualityScore);
    bases.retain(|code| *code != crate::domain::ConfidenceBasisCode::MissingDetectionQualityScore);
    let mut explanation = String::new();
    if !bases.is_empty() {
        explanation.push_str(catalog.text(
            " where a scanner reported no confidence of its own, this product's rating comes from ",
            "當掃描工具未提供自己的信心程度時，本產品依下列基準評定：",
        ));
        explanation.push_str(
            &bases
                .iter()
                .map(|code| {
                    html_escape(match catalog.locale {
                        crate::export::ReportLocale::En => {
                            crate::finding_narrative::confidence_basis_english(*code)
                        }
                        crate::export::ReportLocale::ZhHant => {
                            crate::finding_narrative::confidence_basis_zh_hant(*code)
                        }
                    })
                })
                .collect::<Vec<_>>()
                .join(catalog.text("; ", "；")),
        );
        explanation.push_str(catalog.text(".", "。"));
    }
    if detection_quality_unavailable {
        explanation.push_str(catalog.text(
            " Unknown means the scanner did not report detection quality.",
            "未知表示掃描工具未提供偵測品質。",
        ));
    }
    format!(
        "<p class=\"finding-legend\"><strong>{}{}</strong>{}</p>",
        catalog.text("Confidence", "信心程度"),
        catalog.text(":", "："),
        explanation,
    )
}

fn html_problem_title(
    report: &BeginnerMasterReport,
    finding: &BeginnerFinding,
    catalog: HtmlReportCatalog,
) -> String {
    if finding.source_audit {
        return finding.title.clone();
    }
    report.problem_group(&finding.finding_id).map_or_else(
        || match catalog.locale {
            crate::export::ReportLocale::En => {
                crate::finding_narrative::finding_headline_english(&finding.title, finding.family)
            }
            crate::export::ReportLocale::ZhHant => {
                crate::finding_narrative::finding_headline_zh_hant(&finding.title, finding.family)
            }
        },
        |group| match catalog.locale {
            crate::export::ReportLocale::En => group.title_english(),
            crate::export::ReportLocale::ZhHant => group.title_zh_hant(),
        },
    )
}

pub(crate) fn html_problem_anchor(
    report: &BeginnerMasterReport,
    finding_id: &str,
) -> Option<String> {
    if let Some(group) = report.problem_group(finding_id) {
        return report
            .problem_findings()
            .iter()
            .position(|finding| finding.finding_id == group.representative_finding_id)
            .map(|index| format!("problem{}", index + 1));
    }
    report
        .findings
        .iter()
        .position(|finding| finding.finding_id == finding_id)
        .map(|index| format!("f{}", index + 1))
}

fn html_grouped_problem_cards(
    report: &BeginnerMasterReport,
    original_cards: &BTreeMap<Id, String>,
    target_labels: &BTreeMap<Id, String>,
    catalog: HtmlReportCatalog,
) -> (String, String, usize) {
    let mut cards = String::new();
    let mut rows = String::new();
    let mut count = 0;
    for finding in report.problem_findings() {
        if finding
            .severity_basis_code
            .is_some_and(|basis| basis.is_exposure_observation())
        {
            continue;
        }
        count += 1;
        let title = html_problem_title(report, finding, catalog);
        let anchor = html_problem_anchor(report, &finding.finding_id).unwrap();
        let severity = catalog.identifier(&enum_key(&finding.severity));
        let unconfirmed = finding_unconfirmed_by_coverage(finding, &report.actual);
        let action = if provider_native_narrative(finding) {
            finding.next_step.clone()
        } else {
            match catalog.locale {
                crate::export::ReportLocale::En => {
                    crate::finding_narrative::finding_next_action_english(
                        &finding.next_step,
                        finding.family,
                        beginner_aws_iam_policy(finding),
                        unconfirmed,
                    )
                }
                crate::export::ReportLocale::ZhHant => {
                    crate::finding_narrative::finding_next_action_zh_hant(
                        &finding.next_step,
                        &finding.recommended_expert_type,
                        finding.family,
                        beginner_aws_iam_policy(finding),
                        unconfirmed,
                    )
                }
            }
        };
        let action = report
            .problem_group(&finding.finding_id)
            .and_then(|group| match catalog.locale {
                crate::export::ReportLocale::En => group.next_step_english(),
                crate::export::ReportLocale::ZhHant => group.next_step_zh_hant(),
            })
            .map(str::to_owned)
            .unwrap_or(action);
        let targets = breakable_target_list(&finding.target_asset_ids, target_labels, catalog);
        rows.push_str(&format!("<tr><td class=\"numeric\"><a href=\"#{anchor}\">{count}</a></td><td><span class=\"pill pill--{}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            severity_slug(&finding.severity), html_escape(&severity), html_escape(&title), targets, html_escape(&action)));
        if let Some(group) = report.problem_group(&finding.finding_id) {
            let members = group
                .finding_ids
                .iter()
                .filter_map(|id| original_cards.get(id))
                .cloned()
                .collect::<String>();
            let impact = match catalog.locale {
                crate::export::ReportLocale::En => crate::finding_narrative::impact_english(
                    &finding.possible_impact,
                    finding.family,
                    &finding.context_factors,
                ),
                crate::export::ReportLocale::ZhHant => crate::finding_narrative::impact_zh_hant(
                    &finding.possible_impact,
                    &finding.severity,
                    &severity,
                    finding.severity_basis_code,
                    finding.family,
                    &finding.context_factors,
                ),
            };
            let impact = match catalog.locale {
                crate::export::ReportLocale::En => group.impact_english(),
                crate::export::ReportLocale::ZhHant => group.impact_zh_hant(),
            }
            .map(str::to_owned)
            .unwrap_or(impact);
            cards.push_str(&format!(concat!(
                "<article class=\"finding\" id=\"{}\"><h3>{}{}<span class=\"finding-asset\">— {}</span></h3><p><span class=\"pill pill--{}\">{}</span> · {} {}</p>",
                "<p>{}</p><p>{}{}</p><p>{}{}</p>",
                "<details class=\"technical finding-problem-group\"><summary>{} ({})</summary>{}</details></article>"),
                anchor, html_escape(&title), catalog.gap_after(&title), targets, severity_slug(&finding.severity), html_escape(&severity),
                catalog.format_number(group.finding_ids.len()), catalog.text("original findings", "筆原始發現"), html_escape(&impact),
                catalog.strong_label(catalog.text("Target", "目標")), targets,
                catalog.strong_label(catalog.text("What to do next", "下一步怎麼做")), html_escape(&action),
                catalog.text("Related checks", "相關檢查"), catalog.format_number(group.finding_ids.len()), members));
        } else if let Some(card) = original_cards.get(&finding.finding_id) {
            cards.push_str(card);
        }
    }
    (cards, rows, count)
}

fn html_original_report_attachments(
    attachments: &[HtmlReportAttachment],
    catalog: HtmlReportCatalog,
) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    let mut html = format!(
        "<section id=\"original-report-attachments\"><h2>{}</h2>",
        catalog.text("Original report attachments", "原始報告附件")
    );
    if attachments.is_empty() {
        html.push_str(&format!("<p>{}</p></section>", catalog.text(
            "No original files are attached. None were saved for this run, or the redaction setting excluded them.",
            "沒有附上原始檔：這輪沒有保存原始檔，或檔案已依遮蔽設定排除。")));
        return html;
    }
    html.push_str(&format!("<p>{}</p><p>{}</p>",
        catalog.text(
            "Download and extract a ZIP to open the original reports. Each attachment keeps this run’s scanner output, supporting files, and logs in their original folders. Some tools provide JSON or logs instead of an HTML report.",
            "下載 ZIP 並完整解壓縮後，即可開啟原始報告。每份附件保留本輪工具的輸出、配套檔案與紀錄，以及原本的目錄結構；部分工具提供 JSON 或紀錄檔，而非 HTML 報告。"),
        catalog.text("Keep this HTML file to retain the attachments; printing to PDF does not carry them over.",
            "請保留這份 HTML 以保存附件；列印成 PDF 不會帶出附件。")));
    html.push_str(&format!("<table class=\"attachments-table\"><thead><tr><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>",
        catalog.text("Scanner", "掃描工具"), catalog.text("Files", "檔案"), catalog.text("Attachment", "附件")));
    for (index, attachment) in attachments.iter().enumerate() {
        let file_names = attachment
            .file_names
            .iter()
            .map(|name| format!("<li><code>{}</code></li>", html_escape(name)))
            .collect::<String>();
        html.push_str(&format!(concat!(
            "<tr><th scope=\"row\">{}</th><td class=\"numeric\">{}</td><td>",
            "<a class=\"attachment-download\" download=\"original-scanner-files-{:02}.zip\" href=\"data:application/zip;base64,{}\">{}</a>",
            "<span> · {} {}</span><details><summary>{}</summary>",
            "<p>{}: <code>{}</code></p><p>SHA-256: <code>{}</code></p><ul>{}</ul></details></td></tr>"),
            html_escape(crate::report_attachments::audit_label(&attachment.engine_id, catalog.locale == ReportLocale::ZhHant).unwrap_or(&engine_named(&attachment.engine_id))), catalog.format_number(attachment.file_names.len()),
            index + 1, BASE64.encode(&attachment.bytes), catalog.text("Download ZIP", "下載 ZIP"),
            catalog.format_number(attachment.bytes.len()), catalog.text("bytes", "位元組"),
            catalog.text("File list and integrity", "檔案清單與完整性"),
            catalog.text("Check ID", "檢查 ID"), html_escape(&attachment.engine_run_id), attachment.sha256, file_names));
    }
    html.push_str("</tbody></table></section>");
    html
}

/// Version and last-updated date for one tested-checks row.
///
/// Values are escaped here because the caller inserts the line into HTML.
/// Neither value known means the row header stays the check name alone.
fn tested_check_version_line(
    tasks: &[crate::beginner_report::TechnicalTaskDetails],
    task_id: &str,
    catalog: &HtmlReportCatalog,
) -> Option<String> {
    let task = tasks.iter().find(|task| task.task_id == task_id)?;
    let crate::beginner_report::TechnicalExecution::CatalogEngine {
        engine_version,
        reported_version,
        knowledge_date,
        ..
    } = &task.execution
    else {
        return None;
    };
    let version = engine_version.as_deref().map(|version| {
        crate::beginner_report::scanner_version_label(
            version,
            reported_version.as_deref(),
            crate::beginner_report::ScannerVersionForm::Short,
            matches!(catalog.locale, crate::export::ReportLocale::ZhHant),
        )
    });
    match (version.as_deref(), knowledge_date.as_deref()) {
        (Some(version), Some(date)) => Some(format!(
            "{} {} · {} {}",
            catalog.text("Version", "版本"),
            html_escape(version),
            catalog.text("last updated", "最後更新"),
            html_escape(date),
        )),
        (Some(version), None) => Some(format!(
            "{} {}",
            catalog.text("Version", "版本"),
            html_escape(version),
        )),
        (None, Some(date)) => Some(format!(
            "{} {}",
            catalog.text("Last updated", "最後更新"),
            html_escape(date),
        )),
        (None, None) => None,
    }
}

/// `Scan {sequence}` / `第 {sequence} 次掃描`.
///
/// `ScanRun` stores no separate label. The desktop names every sequence that
/// way, and a sequence below 1 keeps the same generated name.
fn html_scan_run_name(run: &ScanRun, catalog: HtmlReportCatalog) -> String {
    match catalog.locale {
        crate::export::ReportLocale::ZhHant => format!("第 {} 次掃描", run.sequence),
        crate::export::ReportLocale::En => format!("Scan {}", run.sequence),
    }
}

/// First 12 characters, except the standard-redaction marker, which is kept whole.
fn html_snapshot_hash(value: &str) -> String {
    const REDACTED: &str = "[redacted snapshot hash]";
    if value == REDACTED {
        REDACTED.to_owned()
    } else {
        value.chars().take(12).collect()
    }
}

struct VerificationDiffCounts {
    resolved: usize,
    still_present: usize,
    newly_observed: usize,
    unable_to_verify: usize,
    moved: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ComparedProblemStatus {
    NoLongerObserved,
    StillPresent,
    New,
    VerificationIncomplete,
}

struct ComparedProblem<'a> {
    diffs: Vec<&'a FindingDiff>,
    status: ComparedProblemStatus,
    moved: bool,
    /// No longer observed reads the baseline report. Every other status reads
    /// this report, or the baseline when the problem has no current-side member.
    from_baseline: bool,
    /// The display side's card representative, or the first member's finding
    /// on that side. `None` when that side's report or finding is unavailable.
    lead: Option<&'a BeginnerFinding>,
    /// The lead's place in the display side's `problem_findings`.
    position: Option<usize>,
}

/// One report of a fix check, indexed once so a large comparison stays linear.
struct ComparisonSide<'a> {
    report: &'a BeginnerMasterReport,
    membership: BTreeMap<&'a str, &'a crate::beginner_report::ReportProblemGroup>,
    positions: BTreeMap<&'a str, usize>,
    findings: BTreeMap<&'a str, &'a BeginnerFinding>,
}

impl<'a> ComparisonSide<'a> {
    fn new(report: &'a BeginnerMasterReport) -> Self {
        Self {
            report,
            membership: report.rendered_problem_membership(),
            positions: problem_finding_positions(report),
            findings: report
                .findings
                .iter()
                .map(|finding| (finding.finding_id.as_str(), finding))
                .collect(),
        }
    }

    fn finding(&self, id: Option<&str>) -> Option<&'a BeginnerFinding> {
        id.and_then(|id| self.findings.get(id).copied())
    }
}

#[derive(Default)]
struct ComparisonNodes {
    parent: BTreeMap<String, String>,
}

impl ComparisonNodes {
    fn add(&mut self, node: &str) {
        self.parent
            .entry(node.to_owned())
            .or_insert_with(|| node.to_owned());
    }

    fn find(&mut self, node: &str) -> String {
        self.add(node);
        let mut current = node.to_owned();
        let mut path = Vec::new();
        while let Some(parent) = self.parent.get(&current).cloned() {
            if parent == current {
                break;
            }
            path.push(current);
            current = parent;
        }
        for step in path {
            self.parent.insert(step, current.clone());
        }
        current
    }

    fn unite(&mut self, left: &str, right: &str) {
        let left = self.find(left);
        let right = self.find(right);
        if left != right {
            self.parent.insert(right, left);
        }
    }
}

fn is_still_observed(diff: &FindingDiff) -> bool {
    matches!(
        diff.status,
        FindingDiffStatus::StillPresent | FindingDiffStatus::Changed
    )
}

fn location_moved(diff: &FindingDiff) -> bool {
    diff.reasons
        .iter()
        .any(|reason| reason.code == FindingDiffReasonCode::LocationMoved)
}

fn compared_problem_status(diffs: &[&FindingDiff]) -> ComparedProblemStatus {
    if diffs.iter().any(|diff| is_still_observed(diff)) {
        ComparedProblemStatus::StillPresent
    } else if diffs
        .iter()
        .any(|diff| diff.status == FindingDiffStatus::UnableToVerify)
    {
        ComparedProblemStatus::VerificationIncomplete
    } else if diffs
        .iter()
        .all(|diff| diff.status == FindingDiffStatus::Resolved)
    {
        ComparedProblemStatus::NoLongerObserved
    } else if diffs
        .iter()
        .all(|diff| diff.status == FindingDiffStatus::NewlyObserved)
    {
        ComparedProblemStatus::New
    } else {
        ComparedProblemStatus::VerificationIncomplete
    }
}

/// `B:` or `C:` plus the rendered group id, or the finding id when this report
/// does not render a group for it. A missing baseline report keeps the finding id.
fn comparison_side_node(
    prefix: &str,
    finding_id: &str,
    membership: Option<&BTreeMap<&str, &crate::beginner_report::ReportProblemGroup>>,
) -> String {
    let rendered = membership
        .and_then(|membership| membership.get(finding_id))
        .map(|group| group.group_id.as_str());
    format!("{prefix}{}", rendered.unwrap_or(finding_id))
}

/// One compared problem per connected component of the diff graph.
///
/// Each diff contributes a baseline node and a current node. Members of one
/// rendered card share a node, so they stay one problem: still present while
/// any member is observed again, and no longer observed only when every
/// member was compared and resolved.
fn compared_problems<'a>(
    diffs: &'a [FindingDiff],
    baseline: Option<&ComparisonSide<'a>>,
    current: &ComparisonSide<'a>,
) -> Vec<ComparedProblem<'a>> {
    let mut nodes = ComparisonNodes::default();
    let mut diff_nodes = Vec::with_capacity(diffs.len());
    for (index, diff) in diffs.iter().enumerate() {
        let mut pair = Vec::new();
        if let Some(id) = diff.baseline_finding_id.as_deref() {
            pair.push(comparison_side_node(
                "B:",
                id,
                baseline.map(|side| &side.membership),
            ));
        }
        if let Some(id) = diff.current_finding_id.as_deref() {
            pair.push(comparison_side_node("C:", id, Some(&current.membership)));
        }
        if pair.is_empty() {
            pair.push(format!("D:{index}"));
        }
        for node in &pair {
            nodes.add(node);
        }
        if pair.len() == 2 {
            nodes.unite(&pair[0], &pair[1]);
        }
        diff_nodes.push(pair);
    }

    let mut order = Vec::new();
    let mut buckets: BTreeMap<String, Vec<&FindingDiff>> = BTreeMap::new();
    for (index, diff) in diffs.iter().enumerate() {
        let root = nodes.find(&diff_nodes[index][0]);
        if !buckets.contains_key(&root) {
            order.push(root.clone());
        }
        buckets.entry(root).or_default().push(diff);
    }

    order
        .into_iter()
        .map(|root| {
            let members = buckets
                .remove(&root)
                .expect("comparison component keeps its diffs");
            let status = compared_problem_status(&members);
            let moved = status == ComparedProblemStatus::StillPresent
                && members
                    .iter()
                    .all(|diff| !is_still_observed(diff) || location_moved(diff));
            let from_baseline = status == ComparedProblemStatus::NoLongerObserved
                || members.iter().all(|diff| diff.current_finding_id.is_none());
            let side = if from_baseline {
                baseline
            } else {
                Some(current)
            };
            let lead = side.and_then(|side| lead_finding(&members, side, from_baseline));
            let position = side
                .zip(lead)
                .and_then(|(side, lead)| side.positions.get(lead.finding_id.as_str()).copied());
            ComparedProblem {
                diffs: members,
                status,
                moved,
                from_baseline,
                lead,
                position,
            }
        })
        .collect()
}

fn problem_counts(problems: &[ComparedProblem<'_>]) -> VerificationDiffCounts {
    let mut counts = VerificationDiffCounts {
        resolved: 0,
        still_present: 0,
        newly_observed: 0,
        unable_to_verify: 0,
        moved: 0,
    };
    for problem in problems {
        match problem.status {
            ComparedProblemStatus::NoLongerObserved => counts.resolved += 1,
            ComparedProblemStatus::StillPresent => {
                counts.still_present += 1;
                if problem.moved {
                    counts.moved += 1;
                }
            }
            ComparedProblemStatus::New => counts.newly_observed += 1,
            ComparedProblemStatus::VerificationIncomplete => counts.unable_to_verify += 1,
        }
    }
    counts
}

fn side_finding_id(diff: &FindingDiff, from_baseline: bool) -> Option<&str> {
    if from_baseline {
        diff.baseline_finding_id.as_deref()
    } else {
        diff.current_finding_id.as_deref()
    }
}

/// The report a compared problem displays from, when it is available.
fn display_side<'s, 'a>(
    problem: &ComparedProblem<'_>,
    baseline: Option<&'s ComparisonSide<'a>>,
    current: &'s ComparisonSide<'a>,
) -> Option<&'s ComparisonSide<'a>> {
    if problem.from_baseline {
        baseline
    } else {
        Some(current)
    }
}

/// The display side's lead: the representative of the rendered card that
/// comes first in `problem_findings`, otherwise the first member's finding on
/// that side.
fn lead_finding<'a>(
    diffs: &[&FindingDiff],
    side: &ComparisonSide<'a>,
    from_baseline: bool,
) -> Option<&'a BeginnerFinding> {
    let mut grouped: Option<(usize, &'a str)> = None;
    for diff in diffs {
        let Some(group) =
            side_finding_id(diff, from_baseline).and_then(|id| side.membership.get(id).copied())
        else {
            continue;
        };
        let position = side
            .positions
            .get(group.representative_finding_id.as_str())
            .copied()
            .unwrap_or(usize::MAX);
        if grouped.is_none_or(|(first, _)| position < first) {
            grouped = Some((position, group.representative_finding_id.as_str()));
        }
    }
    match grouped {
        Some((_, id)) => side.finding(Some(id)),
        None => side.finding(
            diffs
                .iter()
                .find_map(|diff| side_finding_id(diff, from_baseline)),
        ),
    }
}

fn side_severity<'a>(problem: &ComparedProblem<'a>) -> Option<&'a crate::domain::Severity> {
    problem
        .diffs
        .iter()
        .filter_map(|diff| {
            if problem.from_baseline {
                diff.baseline_severity.as_ref()
            } else {
                diff.current_severity.as_ref()
            }
        })
        .max_by_key(|severity| crate::beginner_report::severity_rank(severity))
}

fn fallback_fingerprint(problem: &ComparedProblem<'_>) -> String {
    problem
        .diffs
        .iter()
        .find(|diff| side_finding_id(diff, problem.from_baseline).is_some())
        .or_else(|| problem.diffs.first())
        .map(|diff| diff.fingerprint.clone())
        .unwrap_or_default()
}

/// The display side's group title for a grouped lead, otherwise the lead's own
/// headline. The fingerprint stands in when that side's finding is unavailable.
fn compared_problem_title(
    problem: &ComparedProblem<'_>,
    side: Option<&ComparisonSide<'_>>,
    catalog: HtmlReportCatalog,
) -> String {
    match (side, problem.lead) {
        (Some(side), Some(lead)) => html_problem_title(side.report, lead, catalog),
        _ => fallback_fingerprint(problem),
    }
}

fn baseline_member_is_secret(diff: &FindingDiff, baseline: Option<&ComparisonSide<'_>>) -> bool {
    baseline
        .and_then(|side| side.finding(diff.baseline_finding_id.as_deref()))
        .is_some_and(|finding| {
            matches!(
                finding.family,
                Some(FindingFamily::Secret | FindingFamily::McpSecret)
            )
        })
}

fn finding_headline_text(finding: &BeginnerFinding, catalog: HtmlReportCatalog) -> String {
    if finding.source_audit {
        return finding.title.clone();
    }
    match catalog.locale {
        crate::export::ReportLocale::En => {
            crate::finding_narrative::finding_headline_english(&finding.title, finding.family)
        }
        crate::export::ReportLocale::ZhHant => {
            crate::finding_narrative::finding_headline_zh_hant(&finding.title, finding.family)
        }
    }
}

/// A member's own headline, from the display side first. Never the group title.
fn html_member_headline(
    diff: &FindingDiff,
    baseline: Option<&ComparisonSide<'_>>,
    current: &ComparisonSide<'_>,
    from_baseline: bool,
    catalog: HtmlReportCatalog,
) -> String {
    let before = baseline.and_then(|side| side.finding(diff.baseline_finding_id.as_deref()));
    let after = current.finding(diff.current_finding_id.as_deref());
    let finding = if from_baseline {
        before.or(after)
    } else {
        after.or(before)
    };
    finding.map_or_else(
        || diff.fingerprint.clone(),
        |finding| finding_headline_text(finding, catalog),
    )
}

fn compared_member_status_label(
    status: &FindingDiffStatus,
    catalog: HtmlReportCatalog,
) -> &'static str {
    match status {
        FindingDiffStatus::Resolved => catalog.text("No longer observed", "這次沒有再看到"),
        FindingDiffStatus::StillPresent | FindingDiffStatus::Changed => {
            catalog.text("Still present", "仍然存在")
        }
        FindingDiffStatus::NewlyObserved => catalog.text("New", "新出現"),
        FindingDiffStatus::UnableToVerify => catalog.text("Verification incomplete", "驗證未完成"),
    }
}

/// Original findings behind every multi-member problem, under that problem's
/// card title. Omitted when every compared problem is a single finding, so
/// that section stays unchanged.
fn html_compared_original_findings(
    problems: &[ComparedProblem<'_>],
    baseline: Option<&ComparisonSide<'_>>,
    current: &ComparisonSide<'_>,
    catalog: HtmlReportCatalog,
) -> String {
    let mut items = String::new();
    for problem in problems.iter().filter(|problem| problem.diffs.len() > 1) {
        let mut members = String::new();
        for diff in &problem.diffs {
            members.push_str(&format!(
                "<li>{} \u{b7} {}</li>",
                html_escape(&html_member_headline(
                    diff,
                    baseline,
                    current,
                    problem.from_baseline,
                    catalog
                )),
                html_escape(compared_member_status_label(&diff.status, catalog)),
            ));
        }
        // A card that is still present but only partly fixed says how many of its
        // original findings this scan found.
        let found = problem
            .diffs
            .iter()
            .filter(|diff| {
                is_still_observed(diff) || diff.status == FindingDiffStatus::NewlyObserved
            })
            .count();
        let partly_fixed = if problem.status == ComparedProblemStatus::StillPresent
            && found < problem.diffs.len()
        {
            let count = catalog.format_number(problem.diffs.len());
            let found = catalog.format_number(found);
            match catalog.locale {
                crate::export::ReportLocale::En => {
                    format!(" \u{b7} {found} of {count} original findings found this time")
                }
                crate::export::ReportLocale::ZhHant => {
                    format!(" \u{b7} {count} 筆原始發現中，這次找到 {found} 筆")
                }
            }
        } else {
            String::new()
        };
        items.push_str(&format!(
            "<li>{}{}<ul>{members}</ul></li>",
            html_escape(&compared_problem_title(
                problem,
                display_side(problem, baseline, current),
                catalog
            )),
            html_escape(&partly_fixed),
        ));
    }
    if items.is_empty() {
        return String::new();
    }
    format!(
        "<details class=\"technical\"><summary><strong>{}</strong></summary><ul>{}</ul></details>",
        html_escape(catalog.text("Original findings compared", "比較的原始發現")),
        items,
    )
}

fn html_compared_problem_row(
    problem: &ComparedProblem<'_>,
    side: Option<&ComparisonSide<'_>>,
    labels: &BTreeMap<Id, String>,
    link: bool,
    catalog: HtmlReportCatalog,
) -> String {
    let title = compared_problem_title(problem, side, catalog);
    let lead = side.and(problem.lead);
    let asset_html = readable_target_list(
        lead.map_or(&[][..], |lead| lead.target_asset_ids.as_slice()),
        labels,
        catalog,
    );
    let anchor = side
        .filter(|_| link)
        .zip(lead)
        .and_then(|(side, lead)| html_problem_anchor(side.report, &lead.finding_id));
    let gap = catalog.gap_after(&title);
    let title = html_escape(&title);
    let title = match anchor {
        Some(anchor) => format!("<a href=\"#{}\">{}</a>", html_escape(&anchor), title),
        None => title,
    };
    let severity = side_severity(problem)
        .map(|severity| {
            format!(
                "<span class=\"pill pill--{}\">{}</span> ",
                severity_slug(severity),
                html_escape(&catalog.identifier(&enum_key(severity))),
            )
        })
        .unwrap_or_default();
    let originals = if problem.diffs.len() > 1 {
        format!(
            " \u{b7} {} {}",
            catalog.format_number(problem.diffs.len()),
            catalog.text("original findings", "筆原始發現"),
        )
    } else {
        String::new()
    };
    format!(
        "<li>{severity}{title}{gap}<span class=\"finding-asset\">— {asset_html}</span>{originals}</li>"
    )
}

fn html_local_copy_line(
    change: &crate::domain::LocalInputChange,
    labels: &BTreeMap<Id, String>,
    fallback_labels: &BTreeMap<Id, String>,
    catalog: HtmlReportCatalog,
) -> String {
    let name = labels
        .get(&change.asset_id)
        .or_else(|| fallback_labels.get(&change.asset_id))
        .map(String::as_str)
        .unwrap_or_else(|| catalog.text("Saved target", "已保存的目標"));
    let name = html_escape(name);
    if change.changed {
        let before = html_escape(&html_snapshot_hash(&change.baseline_sha256));
        let after = html_escape(&html_snapshot_hash(&change.current_sha256));
        match catalog.locale {
            crate::export::ReportLocale::ZhHant => format!("{name}：{before} → {after}"),
            crate::export::ReportLocale::En => format!("{name}: {before} → {after}"),
        }
    } else {
        let hash = html_escape(&html_snapshot_hash(&change.baseline_sha256));
        match catalog.locale {
            crate::export::ReportLocale::ZhHant => {
                format!("{name}：兩次掃描的檔案相同（{hash}）")
            }
            crate::export::ReportLocale::En => {
                format!("{name}: the same files in both scans ({hash})")
            }
        }
    }
}

/// Index of each first-layer problem in the order `problem_findings` lists it.
fn problem_finding_positions(report: &BeginnerMasterReport) -> BTreeMap<&str, usize> {
    report
        .problem_findings()
        .into_iter()
        .enumerate()
        .map(|(index, finding)| (finding.finding_id.as_str(), index))
        .collect()
}

/// One status's problems in the display side's `problem_findings` order.
///
/// A lead that is not in that list, including a fingerprint fallback, sorts
/// last. Equal positions keep component order.
fn ordered_compared_problems<'p, 'a>(
    problems: &'p [ComparedProblem<'a>],
    status: ComparedProblemStatus,
) -> Vec<&'p ComparedProblem<'a>> {
    let mut rows = problems
        .iter()
        .filter(|problem| problem.status == status)
        .collect::<Vec<_>>();
    rows.sort_by_key(|problem| (problem.position.is_none(), problem.position));
    rows
}

/// What changed since the earlier scan, when this run is the current side of a
/// saved fix check. Every other run gets an empty string, so its HTML is unchanged.
fn html_verification_comparison_section(
    case: &AssessmentCase,
    exported: &AssessmentCase,
    run_id: &str,
    report: &BeginnerMasterReport,
    target_labels: &BTreeMap<Id, String>,
    options: &ExportOptions,
    catalog: HtmlReportCatalog,
) -> String {
    let Some(comparison) = case
        .comparisons
        .iter()
        .rev()
        .find(|comparison| comparison.current_run_id == run_id)
    else {
        return String::new();
    };
    let Some(baseline_run) = case
        .scan_runs
        .iter()
        .find(|run| run.id == comparison.baseline_run_id)
    else {
        return String::new();
    };

    let baseline_report =
        beginner_report_for_export(case, &comparison.baseline_run_id, options.redaction).ok();
    let baseline_labels = baseline_report
        .as_ref()
        .map(|baseline| readable_target_labels(baseline, catalog))
        .unwrap_or_default();
    let baseline_side = baseline_report.as_ref().map(ComparisonSide::new);
    let current_side = ComparisonSide::new(report);
    let problems = compared_problems(&comparison.diffs, baseline_side.as_ref(), &current_side);
    let counts = problem_counts(&problems);
    let finished = catalog.format_time(
        baseline_run
            .completed_at
            .as_ref()
            .unwrap_or(&baseline_run.created_at),
    );
    let run_name = html_scan_run_name(baseline_run, catalog);
    let lead = match catalog.locale {
        crate::export::ReportLocale::ZhHant => format!("與 {finished} 完成的{run_name}比較。"),
        crate::export::ReportLocale::En => {
            format!("Compared with {run_name}, finished {finished}.")
        }
    };
    let number = |value| catalog.format_number(value);
    let moved_sentence = match catalog.locale {
        crate::export::ReportLocale::ZhHant => format!(
            "其中 {} 個仍然存在的問題只是在同一個檔案中換了行號。",
            number(counts.moved)
        ),
        crate::export::ReportLocale::En => format!(
            "{} of the still-present problems only moved to another line in the same file.",
            number(counts.moved)
        ),
    };

    let mut resolved_rows = String::new();
    let mut any_secret = false;
    for problem in ordered_compared_problems(&problems, ComparedProblemStatus::NoLongerObserved) {
        any_secret |= problem
            .diffs
            .iter()
            .any(|diff| baseline_member_is_secret(diff, baseline_side.as_ref()));
        resolved_rows.push_str(&html_compared_problem_row(
            problem,
            display_side(problem, baseline_side.as_ref(), &current_side),
            &baseline_labels,
            false,
            catalog,
        ));
    }
    let mut new_rows = String::new();
    for problem in ordered_compared_problems(&problems, ComparedProblemStatus::New) {
        let labels = if problem.from_baseline {
            &baseline_labels
        } else {
            target_labels
        };
        new_rows.push_str(&html_compared_problem_row(
            problem,
            display_side(problem, baseline_side.as_ref(), &current_side),
            labels,
            !problem.from_baseline,
            catalog,
        ));
    }

    let local_changes = exported
        .comparisons
        .iter()
        .find(|item| item.id == comparison.id)
        .map(|item| item.local_input_changes.as_slice())
        .unwrap_or(comparison.local_input_changes.as_slice());
    let mut copies = String::new();
    if !local_changes.is_empty() {
        copies.push_str(&format!(
            "<h3>{}</h3><ul>",
            html_escape(catalog.text("Folder copies compared", "比較的資料夾副本"))
        ));
        for change in local_changes {
            copies.push_str(&format!(
                "<li>{}</li>",
                html_local_copy_line(change, target_labels, &baseline_labels, catalog)
            ));
        }
        copies.push_str("</ul>");
    }
    let run_ids = format!(
        "<div><dt>{}</dt><dd><code>{}</code></dd></div><div><dt>{}</dt><dd><code>{}</code></dd></div>",
        html_escape(catalog.text("Before-fix scan", "修復前掃描")),
        html_escape(&comparison.baseline_run_id),
        html_escape(catalog.text("After-fix check", "修復後複驗")),
        html_escape(&comparison.current_run_id),
    );

    let mut html = format!(
        concat!(
            "<section class=\"verification-comparison\"><h2>{}</h2><p>{}</p>",
            "<div class=\"kpi-row\">{}</div>"
        ),
        html_escape(catalog.text("Compared with the earlier scan", "與先前掃描的比較")),
        html_escape(&lead),
        html_kpi_tiles(
            &[
                (
                    catalog.text("No longer observed", "這次沒有再看到"),
                    counts.resolved,
                    "complete",
                ),
                (
                    catalog.text("Still present", "仍然存在"),
                    counts.still_present,
                    "problems",
                ),
                (
                    catalog.text("New", "新出現"),
                    counts.newly_observed,
                    "partial"
                ),
                (
                    catalog.text("Verification incomplete", "驗證未完成"),
                    counts.unable_to_verify,
                    "partial",
                ),
            ],
            catalog,
        ),
    );
    if counts.moved > 0 {
        html.push_str(&format!("<p>{}</p>", html_escape(&moved_sentence)));
    }
    if !comparison.complete {
        let issue_count = match catalog.locale {
            crate::export::ReportLocale::ZhHant => format!(
                "需要處理的掃描工具／目標比較：{}",
                number(comparison.completeness_issues.len())
            ),
            crate::export::ReportLocale::En => format!(
                "Scanner/target comparisons needing attention: {}",
                number(comparison.completeness_issues.len())
            ),
        };
        html.push_str(&format!(
            "<p><strong>{}</strong></p><p>{}</p><p>{}</p>",
            html_escape(catalog.text(
                "Verification comparison incomplete",
                "複驗比對未完成"
            )),
            html_escape(catalog.text(
                "Some scanner/target comparisons were incomplete or used different comparison inputs. Affected findings stay under Verification incomplete and are not counted as fixed.",
                "部分掃描工具／目標的比較未完成，或使用了不同的比較條件；受影響的問題會保留在「驗證未完成」，不會算成已修復。",
            )),
            html_escape(&issue_count),
        ));
    }
    if !resolved_rows.is_empty() {
        html.push_str(&format!(
            "<h3>{}</h3><ul>{}</ul><p>{}</p>",
            html_escape(catalog.text("No longer observed", "這次沒有再看到")),
            resolved_rows,
            html_escape(catalog.text(
                "The same completed check no longer found this problem. Review the new evidence, then close it.",
                "相同檢查已完成，且沒有再找到這個問題；查看新證據後即可關閉。",
            )),
        ));
    }
    if any_secret {
        html.push_str(&format!(
            "<p>{}</p>",
            html_escape(catalog.text(
                "A secret removed from the files can still be read from version history and copies made earlier. Revoke or rotate it.",
                "從檔案移除的機密仍可能留在版本紀錄與先前的副本中，請撤銷或更換它。",
            )),
        ));
    }
    if !new_rows.is_empty() {
        html.push_str(&format!(
            "<h3>{}</h3><ul>{}</ul>",
            html_escape(catalog.text("New", "新出現")),
            new_rows,
        ));
    }
    html.push_str(&html_compared_original_findings(
        &problems,
        baseline_side.as_ref(),
        &current_side,
        catalog,
    ));
    html.push_str(&format!(
        "<details class=\"technical\"><summary><strong>{}</strong></summary><dl>{}</dl>{}</details></section>",
        html_escape(catalog.text("Scan run IDs", "掃描輪次 ID")),
        run_ids,
        copies,
    ));
    html
}

fn html_incident_focus_section(
    report: &BeginnerMasterReport,
    target_labels: &BTreeMap<Id, String>,
    catalog: HtmlReportCatalog,
) -> String {
    use crate::incident_focus::IncidentCoverageStatus;
    let Some(campaign) = &report.incident_focus else {
        return String::new();
    };
    let matches = campaign
        .issues
        .iter()
        .filter(|issue| issue.status == IncidentCoverageStatus::UpstreamMatch)
        .count();
    let rows = campaign.issues.iter().map(|issue| {
        let (reason, next_action) = crate::incident_focus::incident_issue_guidance(
            issue, catalog.locale == crate::export::ReportLocale::ZhHant,
        );
        let status = match issue.status {
            IncidentCoverageStatus::UpstreamMatch => catalog.text("Upstream finding", "上游發現"),
            IncidentCoverageStatus::NotTested => catalog.text("Not tested", "未測試"),
            IncidentCoverageStatus::InvestigationRequired => catalog.text("Investigation needed", "需要調查"),
            IncidentCoverageStatus::AdvisoryPending => catalog.text("Advisory pending", "公告對應待確認"),
        };
        let target = issue.asset_id.as_ref().and_then(|id| target_labels.get(id))
            .map(String::as_str).unwrap_or(catalog.text("Incident context", "事件資訊"));
        let sources = issue.sources.iter().filter(|source| source.starts_with("https://"))
            .map(|source| format!("<li><a href=\"{}\">{}</a></li>", html_escape(source), html_escape(source)))
            .collect::<String>();
        format!("<tr><td>{}</td><td>{}</td><td>{}</td><td><details><summary>{}</summary><p>{}</p><p>{}</p><ul>{}</ul></details></td></tr>",
            html_escape(&issue.title), html_escape(target), status,
            catalog.text("Evidence and guidance", "證據與建議"), html_escape(reason), html_escape(next_action), sources)
    }).collect::<String>();
    format!("<section data-incident-focus><h2>{}</h2><p>{}: {matches}</p><details><summary>{}</summary><p>{}</p><table><thead><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>{rows}</tbody></table></details></section>",
        catalog.text("October incident triage", "10 月事件初步檢查"),
        catalog.text("Asset/advisory matches", "資產與漏洞公告命中"),
        catalog.text("Incident coverage and next actions", "事件涵蓋範圍與下一步"),
        catalog.text("Specific advisory coverage depends on upstream detectors. A completed check does not clear an individual incident.", "特定漏洞涵蓋範圍取決於上游偵測器；完成一般檢查並不代表個別事件已排除。"),
        catalog.text("Issue", "項目"), catalog.text("Asset", "資產"),
        catalog.text("Outcome", "結果"), catalog.text("Details", "詳情"))
}

#[cfg(test)]
pub(crate) fn html_report_bytes(
    case: &AssessmentCase,
    run_id: &str,
    options: &ExportOptions,
) -> AppResult<Vec<u8>> {
    render_html(case, run_id, options, &[])
}

/// Render the shared terminal report without looking up current case storage.
/// Attachments must already satisfy the selected run and export settings.
pub fn render_html(
    case: &AssessmentCase,
    run_id: &str,
    options: &ExportOptions,
    attachments: &[HtmlReportAttachment],
) -> AppResult<Vec<u8>> {
    let exported = case_for_document_export(case, options)?;
    let report = beginner_report_for_export(case, run_id, options.redaction)?;
    let catalog = HtmlReportCatalog::new(options.locale);
    let display_time = |value: Option<&DateTime<Utc>>| {
        value
            .map(|value| catalog.format_time(value))
            .unwrap_or_else(|| catalog.text("not recorded", "未記錄").into())
    };
    let target_labels = readable_target_labels(&report, catalog);
    let typed_inventory_section = html_typed_inventory_section(&report, &target_labels, catalog);

    let connection_diagnostic = matches!(
        report.requested.stage.value,
        Some(ReportScanStage::ConnectionDiagnostic)
    );
    let non_security_only = !report.actual.checks.is_empty()
        && report
            .actual
            .checks
            .iter()
            .all(|check| check.effective_result_kind() != CheckResultKind::SecurityCheck);
    let report_summary = if connection_diagnostic {
        catalog.text("Connection test only", "僅連線測試")
    } else if non_security_only {
        catalog.text("Inventory or connectivity only", "僅完成盤點或連線工作")
    } else {
        match report.state.summary {
            BeginnerReportSummary::Complete => catalog.text("Complete", "完整"),
            BeginnerReportSummary::Partial => {
                catalog.text("Some checks are incomplete", "部分檢查未完成")
            }
            BeginnerReportSummary::NoChecksCompleted => {
                catalog.text("No checks completed", "沒有已完成的檢查")
            }
        }
    };
    let requested_stage = report
        .requested
        .stage
        .value
        .as_ref()
        .map(|stage| catalog.report_stage(stage))
        .unwrap_or(catalog.text("not retained by this run", "本輪未保留"));
    // A run with no network-discovery stage at all (every local-project,
    // website, or guided internal-system run that is not the native
    // localhost diagnostic) has nothing honest to print here: it is not
    // "not retained", it simply never had a scan-depth dimension. Omit the
    // whole paragraph rather than call it unavailable.
    let scan_depth_paragraph =
        if report.requested.stage.availability == DataAvailability::NotApplicable {
            String::new()
        } else {
            format!(
                "<p>{}{}</p>",
                catalog.strong_label(catalog.text("Scan depth", "掃描深度")),
                html_escape(requested_stage),
            )
        };
    let mut requested_targets = report
        .requested
        .targets
        .iter()
        .map(|target| {
            format!(
                "<li><strong>{}</strong>{}</li>",
                html_escape(
                    target_labels
                        .get(&target.asset_id)
                        .map(String::as_str)
                        .unwrap_or(catalog.text("Saved target", "已保存的目標")),
                ),
                target
                    .asset_kind
                    .as_ref()
                    .map(|kind| format!(" — {}", html_escape(catalog.asset_kind(kind))))
                    .unwrap_or_default(),
            )
        })
        .collect::<String>();
    if requested_targets.is_empty() {
        requested_targets.push_str(catalog.text(
            "<li>The saved run did not retain an exact requested target description.</li>",
            "<li>已保存的掃描未保留精確的要求目標說明。</li>",
        ));
    }
    // A limit is a policy and the assets it covers. Written one line per
    // holder, twenty-one engines sharing one execution timeout printed that
    // timeout twenty-one times and two targets sharing a port list printed it
    // twice: forty lines for eleven distinct policies. Holders that share a
    // policy now share its line.
    let mut grouped_limits: Vec<(String, String, &'static str, Vec<String>)> = Vec::new();
    for limit in &report.requested.limits {
        // Same rule as the coverage rows below: the identifier the name is
        // composed around is the only part telling one grant's limits from
        // another's, so it is carried through rather than prettified away.
        let name = replace_target_ids(&limit.name, &target_labels);
        let value = replace_target_ids(&limit.value, &target_labels);
        let display_value = match catalog.locale {
            crate::export::ReportLocale::ZhHant => {
                crate::finding_narrative::requested_limit_value_zh_hant(&name, &value)
            }
            _ => value,
        };
        // The source is a parenthetical in a Chinese sentence too, and the
        // half-width pair was the only ASCII bracket left in the Chinese
        // report.
        let source = catalog.limit_source(&limit.source);
        let Some((holder, subject)) = limit_holder_and_subject(&limit.name, &target_labels) else {
            let display_name = match catalog.locale {
                crate::export::ReportLocale::ZhHant => {
                    crate::finding_narrative::requested_limit_name_zh_hant(&engine_named(&name))
                }
                _ => readable_limit_name(&limit.name, &target_labels),
            };
            grouped_limits.push((display_name, display_value, source, Vec::new()));
            continue;
        };
        let display_subject = match catalog.locale {
            crate::export::ReportLocale::ZhHant => {
                crate::finding_narrative::requested_limit_name_zh_hant(&subject)
            }
            _ => readable_identifier(&subject),
        };
        match grouped_limits
            .iter_mut()
            .find(|(candidate, existing, known, holders)| {
                !holders.is_empty()
                    && *candidate == display_subject
                    && *existing == display_value
                    && *known == source
            }) {
            Some((_, _, _, holders)) => holders.push(holder),
            None => grouped_limits.push((display_subject, display_value, source, vec![holder])),
        }
    }
    // Grouping by policy left the subjects interleaved: one asset's four
    // limits, then a second asset's, and a third asset's authorized target
    // stranded past the request rates because its value first appeared late.
    // Ordered by subject the list reads as what it is - two port policies,
    // three authorized targets, two network timeouts, two request rates, three
    // execution timeouts - and the sort is stable, so values stay in the order
    // the run recorded them.
    let mut subject_order: Vec<String> = Vec::new();
    for (subject, _, _, _) in &grouped_limits {
        if !subject_order.contains(subject) {
            subject_order.push(subject.clone());
        }
    }
    grouped_limits.sort_by_key(|(subject, _, _, _)| {
        subject_order
            .iter()
            .position(|known| known == subject)
            .unwrap_or(usize::MAX)
    });
    // Where a limit came from is a property of the grant it came from, and it
    // was printed on all twelve lines to say one of two things. The list is
    // grouped under its sources instead, so a reader sees at once which limits
    // the scope approval set and which the task settings did.
    let mut source_order: Vec<&'static str> = Vec::new();
    for (_, _, source, _) in &grouped_limits {
        if !source_order.contains(source) {
            source_order.push(source);
        }
    }
    let mut requested_limits = source_order
        .into_iter()
        .map(|source| {
            let limits = grouped_limits
                .iter()
                .filter(|(_, _, known, _)| *known == source)
                .map(|(subject, value, _, holders)| {
                    // An authorized network target names itself:
                    // "203.0.113.11 -- 203.0.113.11" is one fact printed twice.
                    let named_itself =
                        matches!(holders.as_slice(), [only] if value.starts_with(only.as_str()));
                    let covered = match holders.is_empty() || named_itself {
                        true => String::new(),
                        false => format!(
                            "{}{}",
                            catalog.text(" \u{2014} ", "；適用於 "),
                            holders.join(catalog.text(", ", "、")),
                        ),
                    };
                    format!(
                        "<li>{}{}{}</li>",
                        catalog.strong_label(&html_escape(subject)),
                        html_escape(value),
                        html_escape(&covered),
                    )
                })
                .collect::<String>();
            format!(
                "<li><strong>{}{}</strong><ul>{}</ul></li>",
                catalog.text("From the ", "來自"),
                html_escape(source),
                limits,
            )
        })
        .collect::<String>();
    if requested_limits.is_empty() {
        requested_limits.push_str(catalog.text(
            "<li>No exact per-run limits were retained.</li>",
            "<li>未保留本輪的精確限制。</li>",
        ));
    }
    let mut requested_checks = report
        .requested
        .requested_check_ids
        .iter()
        .map(|check_id| {
            format!(
                "<li>{}</li>",
                html_escape(&report_check_label(check_id, catalog))
            )
        })
        .collect::<String>();
    if requested_checks.is_empty() {
        requested_checks.push_str(catalog.text(
            "<li>No exact requested check list was retained.</li>",
            "<li>未保留精確的要求檢查清單。</li>",
        ));
    }
    let mut tested_items = report
        .actual
        .checks
        .iter()
        .map(|check| {
            // A completed catalog check always produces this coarse
            // coordinate, and the row restates its own header: the engine id
            // and the asset id the line above already names, an observed time
            // equal to the finish time three words earlier, and a sentence
            // about this product's record keeping rather than about the
            // target. Eighteen of them were a third of this section.
            //
            // Dropped only when every target the header lists has one. A check
            // that proved the coordinate for some of its targets and not
            // others is telling the reader which, and that has to stay.
            let coordinates = check
                .tested_dimensions
                .iter()
                .filter(|dimension| dimension.dimension == COMPLETED_COORDINATE_DIMENSION)
                .count();
            let header_says_it = coordinates > 0 && coordinates == check.target_asset_ids.len();
            let dimensions = check
                .tested_dimensions
                .iter()
                .filter(|dimension| {
                    !header_says_it || dimension.dimension != COMPLETED_COORDINATE_DIMENSION
                })
                .map(|dimension| {
                    format!(
                        concat!("<li>{}{} — {}", "<br><small>{}{}</small></li>"),
                        catalog.strong_label(&html_escape(&match catalog.locale {
                            crate::export::ReportLocale::ZhHant => {
                                crate::finding_narrative::coverage_dimension_zh_hant(&engine_named(
                                    &dimension.dimension,
                                ))
                            }
                            _ => readable_dimension(&dimension.dimension),
                        })),
                        html_escape(&replace_target_ids(
                            &match catalog.locale {
                                crate::export::ReportLocale::ZhHant => {
                                    crate::finding_narrative::tested_value_zh_hant(
                                        &engine_named(&dimension.dimension),
                                        &dimension.value,
                                    )
                                    .unwrap_or_else(|| dimension.value.clone())
                                }
                                _ => dimension.value.clone(),
                            },
                            &target_labels,
                        )),
                        html_escape(&match catalog.locale {
                            crate::export::ReportLocale::ZhHant => {
                                crate::finding_narrative::tested_observation_zh_hant(
                                    &dimension.observation,
                                )
                                .unwrap_or_else(|| dimension.observation.clone())
                            }
                            _ => dimension.observation.clone(),
                        }),
                        catalog.label(catalog.text("Observed", "觀察時間")),
                        html_escape(&display_time(dimension.observed_at.as_ref())),
                    )
                })
                .collect::<String>();
            // Retained, and said by the header instead. "No completed
            // dimension was retained" would be false here. A check that
            // failed, timed out, was cancelled or never ran has the state
            // column to say so; the sentence under a failed website check
            // repeated that in the record's own vocabulary.
            let completed = matches!(
                check.status,
                CoverageDimensionStatus::TestedComplete | CoverageDimensionStatus::TestedPartial
            );
            let dimensions = if !dimensions.is_empty() {
                format!("<ul>{dimensions}</ul>")
            } else if header_says_it || !completed {
                String::new()
            } else {
                catalog
                    .text(
                        "<ul><li>No completed dimension was retained.</li></ul>",
                        "<ul><li>未保留已完成的檢查面向。</li></ul>",
                    )
                    .to_owned()
            };
            let dimensions = if let Some(outcome) = &check.outcome {
                let text = [&outcome.summary, &outcome.reason, &outcome.next_action]
                    .map(|s| match catalog.locale {
                        crate::export::ReportLocale::ZhHant => {
                            crate::agent_audit_failure::wording::translate(s).unwrap_or(s)
                        }
                        _ => s.as_str(),
                    })
                    .join(catalog.text(" ", ""));
                format!("<p>{}</p>", html_escape(&text))
            } else {
                dimensions
            };
            let targets = readable_target_list(&check.target_asset_ids, &target_labels, catalog);
            // Twenty-four runs at three lines apiece filled two pages with a
            // label repeated seventy-two times. The labels are the column
            // headings now and each run is one row, so a reader can compare
            // what ran against what it ran on. A run that retained detail of
            // its own keeps it, in a row of its own beneath.
            let detail = if dimensions.is_empty() {
                String::new()
            } else {
                format!("<tr class=\"tested-detail\"><td colspan=\"5\">{dimensions}</td></tr>")
            };
            let check_label = html_escape(&report_check_label(&check.check_id, catalog));
            let check_label = match tested_check_version_line(
                &report.technical_details.tasks,
                &check.task_id,
                &catalog,
            ) {
                Some(line) => format!("{check_label}<br><small>{line}</small>"),
                None => check_label,
            };
            format!(
                concat!(
                    "<tr><th scope=\"row\">{}</th><td class=\"tested-state\">{}</td><td>{}</td>",
                    "<td class=\"tested-time\">{}</td><td class=\"tested-time\">{}</td></tr>{}"
                ),
                check_label,
                html_escape(catalog.coverage_status(&check.status)),
                targets,
                html_escape(&display_time(check.started_at.as_ref())),
                html_escape(&display_time(check.finished_at.as_ref())),
                detail,
            )
        })
        .collect::<String>();
    if tested_items.is_empty() {
        tested_items.push_str(catalog.text(
            "<tr><td colspan=\"5\">No completed test dimension was saved for this run.</td></tr>",
            "<tr><td colspan=\"5\">本輪未保存任何已完成的測試面向。</td></tr>",
        ));
    }
    let network_scope_section = if report.actual.network_scopes.is_empty() {
        String::new()
    } else {
        let network_scope_items = report
            .actual
            .network_scopes
            .iter()
            .map(|scope| {
                let target_label = target_labels
                    .get(&scope.target_asset_id)
                    .map(String::as_str)
                    .unwrap_or(catalog.text("Saved target", "已保存的目標"));
                let addresses = scope
                    .address_ranges
                    .iter()
                    .map(|range| html_escape(range))
                    .collect::<Vec<_>>()
                    .join(", ");
                let ports = scope
                    .port_ranges
                    .iter()
                    .map(|range| html_escape(range))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    concat!(
                        "<li><strong>{} — {}</strong>",
                        "<br><span>{}{} (<code>{}</code>)</span>",
                        "<br><span>{}<code>{}</code> · {}{} <code>{}</code></span>",
                        "<br><small>{}{} · {}{}</small></li>"
                    ),
                    html_escape(&report_check_label(&scope.check_id, catalog)),
                    html_escape(catalog.report_stage(&scope.stage)),
                    catalog.label(catalog.text("Target", "目標")),
                    html_escape(target_label),
                    html_escape(&scope.target),
                    catalog.label(catalog.text("Addresses", "位址")),
                    addresses,
                    catalog.label(catalog.text("Ports", "連接埠")),
                    html_escape(&scope.transport.to_uppercase()),
                    ports,
                    catalog.label(catalog.text("Outcome", "結果")),
                    html_escape(catalog.work_unit_outcome(&scope.outcome)),
                    catalog.label(catalog.text("Observed", "觀察時間")),
                    html_escape(&display_time(scope.observed_at.as_ref())),
                )
            })
            .collect::<String>();
        format!(
            "<h3>{}</h3><ul>{}</ul>",
            catalog.text(
                "Exact network coverage and outcome",
                "精確網路涵蓋範圍與結果"
            ),
            network_scope_items,
        )
    };
    let render_coverage_item = |gap: &CoverageGap| {
        // An unattributed gap is composed from its payload rather than
        // printed as stored English, so the reader is told which
        // identifier to add in the language they are reading. The name of
        // the coverage is composed too, even where the prose beside it is
        // not: it is built around a check or engine id, and leaving it in
        // English opened every row of a Chinese report with a phrase the
        // reader has no way to place.
        let (dimension, reason, next_action) = match (catalog.locale, gap.unattributed.as_ref()) {
            (crate::export::ReportLocale::ZhHant, Some(unattributed)) => {
                let engine_id = gap
                    .dimension
                    .split_once(':')
                    .map(|(engine, _)| engine)
                    .unwrap_or(gap.dimension.as_str());
                crate::finding_narrative::unattributed_gap_zh_hant(
                    &engine_named(engine_id),
                    unattributed,
                )
            }
            (crate::export::ReportLocale::ZhHant, None) => (
                crate::finding_narrative::coverage_dimension_zh_hant(&engine_named(&gap.dimension)),
                // An unrecognized sentence keeps its stored English. An
                // excluded area carries the words a person typed about
                // their own case, and a run written by another build may
                // carry an explanation this one has never seen.
                crate::finding_narrative::coverage_gap_prose_zh_hant(&gap.reason)
                    .unwrap_or_else(|| gap.reason.clone()),
                crate::finding_narrative::coverage_gap_prose_zh_hant(&gap.next_action)
                    .unwrap_or_else(|| gap.next_action.clone()),
            ),
            (crate::export::ReportLocale::En, None) => (
                crate::finding_narrative::coverage_dimension_english(&gap.dimension),
                gap.reason.clone(),
                gap.next_action.clone(),
            ),
            (crate::export::ReportLocale::En, Some(_)) => (
                gap.dimension.clone(),
                gap.reason.clone(),
                gap.next_action.clone(),
            ),
        };
        let dimension = displayed_dimension(&dimension, catalog, &target_labels);
        let targets = match html_gap_targets(&gap.target_asset_ids, &target_labels, catalog) {
            Some(targets) => format!(" · {}", html_escape(&targets)),
            None => String::new(),
        };
        format!(
            "<li><strong>{} — {}</strong>{}<br>{}<br>{}{}</li>",
            html_escape(catalog.gap_kind(&gap.kind)),
            html_escape(&dimension),
            targets,
            html_escape(&replace_target_ids(&reason, &target_labels)),
            catalog.em_label(catalog.text("Next", "下一步")),
            html_escape(&replace_target_ids(&next_action, &target_labels)),
        )
    };
    let mut gap_items = report
        .coverage_gaps
        .iter()
        .filter(|gap| gap.class == CoverageGapClass::CoverageLoss)
        .map(&render_coverage_item)
        .collect::<String>();
    if gap_items.is_empty() {
        gap_items.push_str(catalog.text(
            "<li>No known coverage gap was recorded.</li>",
            "<li>沒有記錄到已知的涵蓋缺口。</li>",
        ));
    }
    let record_note_items = report
        .coverage_gaps
        .iter()
        .filter(|gap| gap.class == CoverageGapClass::RecordNote)
        .map(render_coverage_item)
        .collect::<String>();
    let record_notes_section = if record_note_items.is_empty() {
        String::new()
    } else {
        let (_, record_note_count) = classified_coverage_item_counts(&report);
        format!(
            "<h3>{} ({})</h3><ul>{}</ul>",
            catalog.text("Record notes", "記錄備註"),
            catalog.format_number(record_note_count),
            record_note_items,
        )
    };
    let next_step_items = report
        .next_steps
        .iter()
        .map(|step| {
            let derived_from = step.finding_id.as_deref().and_then(|finding_id| {
                report
                    .findings
                    .iter()
                    .find(|finding| finding.finding_id == finding_id)
            });
            let action = beginner_step_action(&report, step, catalog);
            let expert = match catalog.locale {
                crate::export::ReportLocale::En => step.recommended_expert_type.clone(),
                crate::export::ReportLocale::ZhHant => step
                    .recommended_expert_type
                    .as_ref()
                    .map(|expert| crate::finding_narrative::expert_type_zh_hant(expert).to_owned()),
            };
            // A finding-derived step's reason is the finding's headline and
            // its two ratings. A Microsoft 365 title names the passing state,
            // so the headline says the requirement was not met; every other
            // title is already the scanner's own words. The ratings are
            // labelled from the finding the step points at, the same way the
            // finding's own section labels them, rather than parsed back out
            // of the stored English. A step with no finding keeps the gap
            // prose it stored.
            let reason = if let Some(finding) = derived_from {
                match catalog.locale {
                    crate::export::ReportLocale::En => {
                        let headline = crate::finding_narrative::finding_headline_english(
                            &finding.title,
                            finding.family,
                        );
                        crate::beginner_report::finding_step_reason(
                            &headline,
                            &finding.severity,
                            &finding.confidence,
                            finding.confidence_basis_code,
                            &finding.priority_reasons,
                        )
                    }
                    crate::export::ReportLocale::ZhHant => {
                        let headline = crate::finding_narrative::finding_headline_zh_hant(
                            &finding.title,
                            finding.family,
                        );
                        format!(
                            "{} — 嚴重程度：{}；信心程度：{}",
                            headline,
                            catalog.identifier(&enum_key(&finding.severity)),
                            crate::finding_narrative::confidence_presentation_zh_hant(
                                &catalog.identifier(&enum_key(&finding.confidence)),
                                finding.confidence_basis_code,
                                &finding.priority_reasons,
                            ),
                        )
                    }
                }
            } else {
                match (catalog.locale, step.unattributed.as_ref()) {
                    (crate::export::ReportLocale::ZhHant, Some(unattributed)) => {
                        let engine_id = step
                            .reason
                            .split_once(' ')
                            .map(|(engine, _)| engine)
                            .unwrap_or(step.reason.as_str());
                        let (_, reason, _) = crate::finding_narrative::unattributed_gap_zh_hant(
                            &engine_named(engine_id),
                            unattributed,
                        );
                        reason
                    }
                    // Every other gap-derived step carries the gap's own two
                    // sentences verbatim, so they are looked up the same way the
                    // coverage row above looks them up. An unrecognized one keeps
                    // its stored English.
                    (crate::export::ReportLocale::ZhHant, None) => {
                        crate::finding_narrative::coverage_gap_prose_zh_hant(&step.reason)
                            .unwrap_or_else(|| step.reason.clone())
                    }
                    _ => step.reason.clone(),
                }
            };
            // A gap-derived step's stored reason is the coverage row's own
            // sentence, printed one section above this list. Repeating it was
            // a quarter of everything under "What to do next", and five of
            // the nine repeats said "this check" with nothing in the sentence
            // to say which one. Name the coverage the step closes instead:
            // shorter, and it answers the question the restated sentence
            // raised.
            let closes = html_step_closes(&report, step, catalog, &target_labels);
            let reason = if closes.is_empty() {
                reason
            } else {
                closes.join(catalog.text("; ", "；"))
            };
            // One instruction, stated once, over the finding that leads the
            // group. The count is how many distinct problems that instruction
            // covers. A typed policy change really is one fix; a family-level
            // instruction is the same kind of change in different places.
            let count = if step.also_resolves.is_empty() {
                1
            } else {
                step.also_resolves
                    .iter()
                    .chain(step.finding_id.iter())
                    .map(|id| {
                        report
                            .problem_group(id)
                            .map(|group| group.group_id.as_str())
                            .unwrap_or(id.as_str())
                    })
                    .collect::<BTreeSet<_>>()
                    .len()
            };
            let reason = if step.also_resolves.is_empty() || count <= 1 {
                reason
            } else {
                match catalog.locale {
                    crate::export::ReportLocale::En => {
                        crate::finding_narrative::step_group_lead_english(
                            count,
                            step.shared_fix,
                            &reason,
                        )
                    }
                    crate::export::ReportLocale::ZhHant => {
                        crate::finding_narrative::step_group_lead_zh_hant(
                            count,
                            step.shared_fix,
                            &reason,
                        )
                    }
                }
            };
            // Intra-document only: the problems table and finding cards already
            // emit `#f{n}` for this same finding. Scanner-supplied URLs stay
            // inert text; this is a link to this report's own card.
            let reason_html = match step
                .finding_id
                .as_ref()
                .and_then(|finding_id| html_problem_anchor(&report, finding_id))
            {
                Some(anchor) => format!("<a href=\"#{anchor}\">{}</a>", html_escape(&reason)),
                None => html_escape(&reason),
            };
            // Every place the step covers, the lead finding's first. A grouped
            // step's problems sit in different places, so naming only the
            // lead's would read as where all of them are.
            let location_html = derived_from
                .and_then(|lead| {
                    let mut locations = html_finding_locations(lead, catalog);
                    for other in step.also_resolves.iter().filter_map(|id| {
                        report
                            .findings
                            .iter()
                            .find(|finding| finding.finding_id == *id)
                    }) {
                        for location in html_finding_locations(other, catalog) {
                            if !locations.contains(&location) {
                                locations.push(location);
                            }
                        }
                    }
                    html_step_location_summary(&locations, catalog)
                })
                .map(|text| {
                    format!(
                        "<br>{}{}",
                        catalog.strong_label(catalog.text("Location", "位置")),
                        html_escape(&text)
                    )
                })
                .unwrap_or_default();
            // An unconfirmed finding's step already says to finish the check
            // first. Confirming the fix comes after that check has a result.
            let confirmation_html = derived_from
                .filter(|_| step.code != NextActionCode::ConfirmFindingAfterIncompleteCheck)
                .map(|finding| {
                    let text = match catalog.locale {
                        crate::export::ReportLocale::En => {
                            crate::finding_narrative::step_confirmation_english(
                                finding.verification_guidance.as_deref(),
                                &finding.title,
                                count,
                            )
                        }
                        crate::export::ReportLocale::ZhHant => {
                            crate::finding_narrative::step_confirmation_zh_hant(
                                finding.verification_guidance.as_deref(),
                                &finding.title,
                                count,
                            )
                        }
                    };
                    format!(
                        "<br>{}{}",
                        catalog.strong_label(catalog.text("To confirm", "確認方式")),
                        html_escape(&text)
                    )
                })
                .unwrap_or_default();
            // A Chinese action that ends its own sentence takes no dash: the
            // reason follows it as the next sentence.
            let separator = match catalog.gap_after(&action) {
                "" => "",
                _ => " — ",
            };
            // The expert used to follow the reason. A confirmation sentence
            // ends on 。, and the same gap rule the action uses keeps an ASCII
            // space off that mark. English still takes the space.
            let expert_gap = catalog.gap_after(
                &last_visible_char(&format!("{reason_html}{location_html}{confirmation_html}"))
                    .map(|character| character.to_string())
                    .unwrap_or_default(),
            );
            format!(
                "<li><strong>{}</strong>{}{}{}{}{}</li>",
                html_escape(&action),
                separator,
                reason_html,
                location_html,
                confirmation_html,
                expert
                    .as_ref()
                    .map(|expert| format!(
                        "{expert_gap}<em>{}{}</em>",
                        catalog.label(catalog.text("Suggested expert", "建議諮詢的專家")),
                        html_escape(expert),
                    ))
                    .unwrap_or_default(),
            )
        })
        .collect::<String>();
    // Said once, above the steps, when any finding carries it.
    let any_shared_safety = report.findings.iter().any(|finding| {
        finding
            .rollback_considerations
            .as_deref()
            .is_some_and(|english| {
                crate::finding_narrative::rollback_english(english)
                    == crate::finding_narrative::ENGLISH_ROLLBACK
            })
    });
    let shared_safety_note = if any_shared_safety {
        format!(
            "<p>{}{}</p>",
            catalog.strong_label(catalog.text("Before changing anything", "變更前考量")),
            html_escape(&match catalog.locale {
                crate::export::ReportLocale::En =>
                    crate::finding_narrative::ENGLISH_ROLLBACK.to_owned(),
                crate::export::ReportLocale::ZhHant => crate::finding_narrative::rollback_zh_hant(
                    crate::finding_narrative::ENGLISH_ROLLBACK
                ),
            })
        )
    } else {
        String::new()
    };
    let report_counts = &report.coverage_counts;
    let coverage_kpis = coverage_kpi_entries(&report, catalog);
    let coverage_items_title = if report_counts.manual_review > 0 {
        catalog.text("What needs attention", "需要留意的內容")
    } else {
        catalog.text("What was not tested", "未測試的內容")
    };

    let actual_window = catalog.format_time_range(
        &display_time(report.actual.observed_from.as_ref()),
        &display_time(report.actual.observed_until.as_ref()),
    );

    // A hundred and forty-nine copies of one sentence. Every coordinate in a
    // run comes from the same embedded catalog, so the version and digest
    // beside each reference were the same hundred-odd characters repeated
    // once per reference, inside the cards a reader opens to see a
    // coordinate. Compared rather than assumed: a run that really did draw on
    // more than one catalog keeps the identity where a reader can tell them
    // apart, and only a run with exactly one moves it to the report's terms.
    let mut mapping_identities: Vec<String> = Vec::new();
    for finding in &report.findings {
        for reference in &finding.framework_references {
            let identity = html_mapping_identity(reference, catalog);
            if !mapping_identities.contains(&identity) {
                mapping_identities.push(identity);
            }
        }
    }
    let shared_mapping = match mapping_identities.len() {
        1 => mapping_identities.pop(),
        _ => None,
    };
    let evidence_is_untrusted_text = report.findings.iter().any(|finding| {
        finding.evidence_references.iter().any(|reference| {
            reference
                .summary
                .as_deref()
                .is_some_and(|summary| summary.ends_with(UNTRUSTED_EVIDENCE_CAVEAT))
        })
    });

    let mut findings = String::new();
    let mut index_rows = String::new();
    let mut confidence_bases_used: Vec<crate::domain::ConfidenceBasisCode> = Vec::new();
    let mut confidence_basis_counts: Vec<(crate::domain::ConfidenceBasisCode, usize)> = Vec::new();
    let mut observations = String::new();
    let mut original_finding_cards = BTreeMap::<Id, String>::new();
    let mut problem_count = 0usize;
    for (index, finding) in report.findings.iter().enumerate() {
        let priority = finding
            .priority
            .map(|priority| catalog.format_number(priority as usize))
            .unwrap_or_else(|| catalog.text("not retained", "未保留").into());
        // The three sentences this product wrote about the finding. Composed
        // for the reader's language rather than printed as stored English under
        // a translated heading; legacy wording is normalized in both locales.
        let severity_label = catalog.identifier(&enum_key(&finding.severity));
        let confidence_label = catalog.identifier(&enum_key(&finding.confidence));
        let unconfirmed_by_coverage = finding_unconfirmed_by_coverage(finding, &report.actual);
        let (plain_language_risk, possible_impact, next_step, expert_type) =
            if provider_native_narrative(finding) {
                (
                    finding.plain_language_risk.clone(),
                    finding.possible_impact.clone(),
                    finding.next_step.clone(),
                    finding.recommended_expert_type.clone(),
                )
            } else {
                match catalog.locale {
                    crate::export::ReportLocale::En => (
                        crate::finding_narrative::summary_english(
                            &finding.plain_language_risk,
                            finding.family,
                        ),
                        crate::finding_narrative::impact_english(
                            &finding.possible_impact,
                            finding.family,
                            &finding.context_factors,
                        ),
                        crate::finding_narrative::finding_next_action_english(
                            &finding.next_step,
                            finding.family,
                            beginner_aws_iam_policy(finding),
                            unconfirmed_by_coverage,
                        ),
                        finding.recommended_expert_type.clone(),
                    ),
                    crate::export::ReportLocale::ZhHant => (
                        crate::finding_narrative::control_verdict_zh_hant(
                            finding.family,
                            &finding.plain_language_risk,
                        )
                        .unwrap_or_else(|| {
                            crate::finding_narrative::summary_zh_hant(
                                &finding.plain_language_risk,
                                &finding.severity,
                                &severity_label,
                                finding.severity_basis_code,
                                &confidence_label,
                                finding.confidence_basis_code,
                                &finding.priority_reasons,
                            )
                        }),
                        crate::finding_narrative::impact_zh_hant(
                            &finding.possible_impact,
                            &finding.severity,
                            &severity_label,
                            finding.severity_basis_code,
                            finding.family,
                            &finding.context_factors,
                        ),
                        crate::finding_narrative::finding_next_action_zh_hant(
                            &finding.next_step,
                            &finding.recommended_expert_type,
                            finding.family,
                            beginner_aws_iam_policy(finding),
                            unconfirmed_by_coverage,
                        ),
                        crate::finding_narrative::expert_type_zh_hant(
                            &finding.recommended_expert_type,
                        )
                        .to_owned(),
                    ),
                }
            };
        let confidence_presentation = match catalog.locale {
            crate::export::ReportLocale::En => {
                crate::finding_narrative::confidence_presentation_english(
                    &confidence_label,
                    finding.confidence_basis_code,
                    &finding.priority_reasons,
                )
            }
            crate::export::ReportLocale::ZhHant => {
                crate::finding_narrative::confidence_presentation_zh_hant(
                    &confidence_label,
                    finding.confidence_basis_code,
                    &finding.priority_reasons,
                )
            }
        };
        // Shown in the app's finding drawer since it existed; the report an
        // expert actually receives left both out, so the two surfaces
        // disagreed about what this finding asks a person to do.
        let safety = finding
            .rollback_considerations
            .as_ref()
            // The adapters attach one product-authored sentence to every
            // remediable finding, so this printed the same 115 characters on
            // all forty-five cards of a twenty-one engine run. It is advice
            // about making any change, not about this finding; it is said once
            // under "What to do next" instead. Advice an upstream wrote for
            // this finding in particular still belongs here.
            .filter(|english| {
                crate::finding_narrative::rollback_english(english)
                    != crate::finding_narrative::ENGLISH_ROLLBACK
            })
            .map(|english| match catalog.locale {
                crate::export::ReportLocale::En => {
                    crate::finding_narrative::rollback_english(english)
                }
                crate::export::ReportLocale::ZhHant => {
                    crate::finding_narrative::rollback_zh_hant(english)
                }
            });
        let verification =
            finding
                .verification_guidance
                .as_ref()
                .map(|english| match catalog.locale {
                    crate::export::ReportLocale::En => {
                        crate::finding_narrative::verification_english(
                            english,
                            Some(&finding.title),
                        )
                    }
                    crate::export::ReportLocale::ZhHant => {
                        crate::finding_narrative::verification_zh_hant(
                            english,
                            Some(&finding.title),
                        )
                    }
                });
        let safety_block = safety
            .map(|text| {
                format!(
                    "<p>{}{}</p>",
                    catalog.strong_label(catalog.text("Before changing anything", "變更前考量")),
                    html_escape(&text)
                )
            })
            .unwrap_or_default();
        let verification_block = verification
            .map(|text| {
                format!(
                    "<p>{}{}</p>",
                    catalog.strong_label(catalog.text("How to confirm the fix", "如何確認已修正")),
                    html_escape(&text)
                )
            })
            .unwrap_or_default();
        let scanner_remediation_block = html_scanner_remediation_block(finding, catalog);
        let finding_location_block = html_finding_location_block(finding, catalog);
        let priority_basis_block = html_priority_basis_block(finding, catalog);
        // The reasons are stored as English prose with no per-entry code, so
        // each is recognised by shape. One this build cannot identify stays in
        // English. A reason that places the finding lower than its severity
        // suggests is already on the card's first layer.
        let mut priority_reasons = finding
            .priority_reasons
            .iter()
            .filter(|reason| {
                !crate::finding_narrative::is_evidence_only_priority_reason(reason)
                    && crate::priority_guidance::PriorityGuidance::from_priority_reasons(
                        std::slice::from_ref(*reason),
                    )
                    .is_none()
            })
            .map(|reason| match catalog.locale {
                crate::export::ReportLocale::En => format!(
                    "<li>{}</li>",
                    html_escape(&crate::finding_narrative::priority_reason_english(reason))
                ),
                crate::export::ReportLocale::ZhHant => format!(
                    "<li>{}</li>",
                    html_escape(&crate::finding_narrative::priority_reason_zh_hant(reason))
                ),
            })
            .collect::<String>();
        if priority_reasons.is_empty() {
            priority_reasons.push_str(catalog.text(
                "<li>No separate priority reason was retained.</li>",
                "<li>未另外保留優先順序原因。</li>",
            ));
        }
        let mut evidence = finding
            .evidence_references
            .iter()
            .map(|reference| html_evidence_reference(reference, catalog))
            .collect::<String>();
        if evidence.is_empty() {
            evidence.push_str(
                catalog.text(
                    "<li>No selected-run evidence SHA-256 reference was retained for this finding.</li>",
                    "<li>此問題未保留本輪證據的 SHA-256 參照。</li>",
                ),
            );
        }
        let official_references = html_official_references(&finding.official_references, catalog);
        let mut frameworks = finding
            .framework_references
            .iter()
            .map(|reference| {
                // Report-only wording, so it stays out of the parity-guarded
                // twins: no screen renders a control reference's relationship.
                let relationship = match (catalog.locale, reference.relationship.as_str()) {
                    (crate::export::ReportLocale::ZhHant, "related") => "相關",
                    _ => &reference.relationship,
                };
                let rationale = match catalog.locale {
                    crate::export::ReportLocale::ZhHant => {
                        crate::finding_narrative::control_mapping_rationale_zh_hant(
                            &reference.rationale,
                        )
                        .unwrap_or_else(|| reference.rationale.clone())
                    }
                    _ => reference.rationale.clone(),
                };
                // Said once in the report's terms when every reference says
                // the same thing, and here when they do not.
                let mapping = match shared_mapping {
                    Some(_) => String::new(),
                    None => format!(
                        "<br>{}{}",
                        catalog.label(catalog.text("Mapping version", "對照版本")),
                        html_escape(&html_mapping_identity(reference, catalog)),
                    ),
                };
                format!(
                    concat!(
                        "<li><strong>{} {} / {}</strong> — {}",
                        "<br>{}{}",
                        "<br>{}{}{}</li>"
                    ),
                    html_escape(&reference.framework),
                    html_escape(&reference.framework_version),
                    html_escape(&reference.control_id),
                    html_escape(&control_title_text(&reference.title, catalog)),
                    catalog.label(catalog.text("Relationship", "關係")),
                    html_escape(relationship),
                    catalog.label(catalog.text("Why related", "關聯原因")),
                    html_escape(&rationale),
                    mapping,
                )
            })
            .collect::<String>();
        if frameworks.is_empty() {
            // Two different silences. A frozen selected-run finding with no
            // coordinate is one the packaged catalog carries no rule for --
            // unplaced, not unrelated -- and on a mixed run that is most of
            // them. Only a finding that is not from this run's immutable
            // snapshot has coordinates that were genuinely not retained.
            frameworks.push_str(
                if finding.snapshot_source == crate::beginner_report::FindingSnapshotSource::FrozenSelectedRun {
                    catalog.text(
                        "<li>The packaged mapping catalog has no entry for this finding's rule, so its framework position is unknown, not absent.</li>",
                        "<li>內建的對照目錄沒有此問題規則的項目，因此其框架位置為未知，而非不存在。</li>",
                    )
                } else {
                    catalog.text(
                        "<li>No framework reference was retained for the selected run.</li>",
                        "<li>未保留本輪的框架參考。</li>",
                    )
                },
            );
        }
        // The index's asset column is a fixed 9rem, so offering break points
        // inside it changes where a URL breaks, not how wide anything is. The
        // tested table and the requested-target list are sized by their
        // content: breaking there let a target wrap and cost five pages.
        let targets = breakable_target_list(&finding.target_asset_ids, &target_labels, catalog);
        if finding
            .severity_basis_code
            .is_some_and(|code| code.is_exposure_observation())
        {
            if report.inventory.total > 0 {
                // Typed inventory is authoritative for this run. Do not also
                // render legacy exposure-shaped findings as either duplicate
                // inventory or security problems.
                continue;
            }
            let observation_kind = match finding.severity_basis_code {
                Some(crate::domain::SeverityBasisCode::OpenPort) => {
                    catalog.text("Open network service", "可連線的網路服務")
                }
                _ => catalog.text("Reachable HTTP service", "可連線的 HTTP 服務"),
            };
            let details = if finding.observation_details.is_empty() {
                catalog
                    .text(
                        "Exact port or response detail was not retained.",
                        "未保留確切連接埠或回應細節。",
                    )
                    .into()
            } else {
                finding
                    .observation_details
                    .iter()
                    .map(|detail| html_escape(detail))
                    .collect::<Vec<_>>()
                    .join(" · ")
            };
            observations.push_str(&format!(
                concat!(
                    "<article id=\"f{}\"><h3>{}</h3>",
                    "<p>{}</p>",
                    "<p>{}{} · {}{}</p>",
                    "<p>{}<code>{}</code></p>",
                    "<h4>{}</h4><ul>{}</ul>",
                    "<h4>{}</h4><ul>{}</ul></article>"
                ),
                index + 1,
                observation_kind,
                catalog.text(
                    "Discovery confirmed that this service responded. Reachability is useful inventory, but it does not by itself establish a vulnerability.",
                    "探索檢查確認這項服務有回應。這是有用的盤點資料，但僅能連線本身不代表存在漏洞。",
                ),
                catalog.strong_label(catalog.text("Target", "目標")),
                targets,
                catalog.strong_label(catalog.text("Observed detail", "觀察細節")),
                details,
                catalog.strong_label(catalog.text("Record ID", "紀錄 ID")),
                html_escape(&finding.finding_id),
                catalog.text("Evidence SHA-256", "證據 SHA-256"),
                evidence,
                catalog.text("Official scanner references", "掃描工具官方參照"),
                official_references,
            ));
            continue;
        }
        problem_count += 1;
        let headline = match catalog.locale {
            crate::export::ReportLocale::En => {
                crate::finding_narrative::finding_headline_english(&finding.title, finding.family)
            }
            crate::export::ReportLocale::ZhHant => {
                crate::finding_narrative::finding_headline_zh_hant(&finding.title, finding.family)
            }
        };
        index_rows.push_str(&format!(
            concat!(
                "<tr><td class=\"numeric\"><a href=\"#f{}\">{}</a></td>",
                "<td><span class=\"pill pill--{}\">{}</span></td>",
                "<td>{}</td><td>{}</td><td>{}</td></tr>"
            ),
            index + 1,
            catalog.format_number(index + 1),
            severity_slug(&finding.severity),
            html_escape(&severity_label),
            html_escape(&headline),
            targets,
            html_escape(&next_step),
        ));
        // The rating goes in the chip; the sentence explaining where it came
        // from goes beside it. As one string it drew a rounded pill around a
        // full sentence, which then wrapped inside its own border.
        let (confidence_chip, confidence_basis) = confidence_presentation
            .strip_prefix(confidence_label.as_str())
            .map(|rest| {
                (
                    confidence_label.as_str(),
                    rest.trim_start_matches([' ', '\u{2014}', '\u{2013}', '-'])
                        .trim(),
                )
            })
            .unwrap_or((confidence_presentation.as_str(), ""));
        // A basis this product derived is one of six fixed sentences, and it
        // printed under all fifty-one cards: thirty-six of them the same
        // words. Those are a definition, so they are defined once beneath the
        // index. A basis the engine reported is that finding's own fact and
        // stays on that finding's card.
        if let Some(code) = finding.confidence_basis_code {
            if !confidence_bases_used.contains(&code) {
                confidence_bases_used.push(code);
            }
            match confidence_basis_counts
                .iter_mut()
                .find(|(used, _)| *used == code)
            {
                Some((_, count)) => *count += 1,
                None => confidence_basis_counts.push((code, 1usize)),
            }
        }
        let confidence_note =
            if finding.confidence_basis_code.is_some() || confidence_basis.is_empty() {
                String::new()
            } else {
                format!(
                    "<span class=\"finding-meta__note\">{}</span>",
                    html_escape(confidence_basis)
                )
            };
        let next_step_inline = html_escape(&next_step);
        // A handful of URLs. As a list they cost a line each plus the list's
        // own margins; inline they cost part of one line.
        let official_references_inline = match &finding.official_references {
            Some(references) if !references.is_empty() => references
                .iter()
                // Inert text, never a clickable navigation instruction built
                // from scanner output.
                .map(|reference| format!("<code>{}</code>", html_escape(reference)))
                .collect::<Vec<_>>()
                .join(" · "),
            Some(_) => catalog
                .text(
                    "No official scanner reference was retained for this selected-run finding.",
                    "本輪保存的問題未保留掃描工具官方參照。",
                )
                .to_owned(),
            None => catalog
                .text(
                    "Official references were not frozen for this legacy result; none are inferred from the current finding.",
                    "這筆舊版結果未凍結官方參照；本報告不會從目前的問題紀錄推測參照。",
                )
                .to_owned(),
        };
        let finding_card = format!(
            concat!(
                // The asset belongs in the heading, not four items into the
                // identifier line below it. On a mixed run two scanners find
                // the same CVE on a repository and on the image built from it,
                // and the two cards are titled identically; with the asset
                // buried, adjacent cards read as the report printing one
                // problem twice.
                "<article id=\"f{}\"><h3>{} <span class=\"finding-asset\">— {}</span></h3>",
                "<p class=\"finding-meta\"><span class=\"pill pill--{}\">{}{}</span>",
                "<span class=\"pill\">{}{}</span>{}",
                "<span class=\"pill\">{}{}</span><span>{} #{}</span>",
                "<span>{}{}</span></p>",
                // Where the problem is; empty when no location was retained
                // or the export masks it. The basis line follows it when the
                // scanner named a benchmark or this product ordered the check
                // lower than that severity suggests.
                "{}{}",
                // Run-in labels, not headings. Each of these carries one
                // sentence, and a heading line plus a margin above and below
                // it cost more vertical space than the sentence did. Six of
                // them per card, fifty-one cards.
                "<p>{}{}{}{}</p>",
                "<p class=\"finding-action\">{}{}</p>",
                "{}",
                "{}{}",
                "<p class=\"finding-references\">{}{}</p>",
                "<details class=\"technical finding-technical\"><summary><strong>{}</strong></summary>",
                "<p>{}{} · ",
                "{}<code>{}</code></p>",
                "<h4>{}</h4><ul>{}</ul>",
                "<h4>{}</h4><ul>{}</ul>",
                "<h4>{}</h4><ul>{}</ul></details></article>"
            ),
            index + 1,
            html_escape(&headline),
            targets,
            severity_slug(&finding.severity),
            catalog.label(catalog.text("Severity", "嚴重程度")),
            html_escape(&catalog.identifier(&enum_key(&finding.severity))),
            catalog.label(catalog.text("Confidence", "信心程度")),
            html_escape(confidence_chip),
            confidence_note,
            catalog.label(catalog.text("Priority", "優先順序")),
            html_escape(&priority),
            catalog.text("Report order", "報告順序"),
            catalog.format_number(index + 1),
            catalog.label(catalog.text("Suggested expert", "建議諮詢的專家")),
            html_escape(&expert_type),
            finding_location_block,
            priority_basis_block,
            html_escape(&plain_language_risk),
            catalog.gap_after(&plain_language_risk),
            catalog.strong_label(catalog.text("Possible impact", "可能影響")),
            html_escape(&possible_impact),
            catalog.strong_label(catalog.text("What to do next", "下一步怎麼做")),
            next_step_inline,
            scanner_remediation_block,
            safety_block,
            verification_block,
            // The upstream advisory stays in the open: it is where a reader
            // goes to understand the problem, not a record of how this
            // product handled it.
            catalog.strong_label(catalog.text("Official scanner references", "掃描工具官方參照")),
            official_references_inline,
            // Everything this product retained about how it knows. On a
            // 21-engine run these two blocks were 57% of everything printed
            // under "Problems found" -- artifact and engine-run identifiers,
            // capture hashes, and the same catalog rationale and mapping
            // provenance repeated once per reference -- read before the
            // reader reached the next problem. All of it is still here.
            catalog.text("Evidence and framework references", "證據與框架參照",),
            // The identity line and the ranking rationale moved in here with
            // it. A forty-character fingerprint and a restatement of the two
            // ratings already shown as pills are how the report knows, not
            // what it found.
            catalog.strong_label(catalog.text("Selected-run source", "本輪來源")),
            html_escape(catalog.finding_source(&finding.snapshot_source)),
            catalog.strong_label(catalog.text("Finding ID", "問題 ID")),
            html_escape(&finding.finding_id),
            catalog.text("Why this priority", "此優先順序的原因"),
            priority_reasons,
            catalog.text("Evidence SHA-256", "證據 SHA-256"),
            evidence,
            catalog.text("Related framework references", "相關框架參考"),
            frameworks,
        );
        original_finding_cards.insert(finding.finding_id.clone(), finding_card.clone());
        findings.push_str(&finding_card);
    }
    if !report.problem_groups.is_empty() {
        (findings, index_rows, problem_count) =
            html_grouped_problem_cards(&report, &original_finding_cards, &target_labels, catalog);
    }
    if findings.is_empty() {
        findings.push_str(catalog.text(
            "<p>No vulnerability finding was retained for this run.</p>",
            "<p>本輪未保留任何漏洞問題。</p>",
        ));
    }
    let observation_section = if observations.is_empty() {
        String::new()
    } else {
        format!(
            concat!(
                "<section><h2>{}</h2><p>{}</p>{}</section>"
            ),
            catalog.text(
                "Observed services (not vulnerabilities)",
                "觀察到的服務（不是漏洞）"
            ),
            catalog.text(
                "These records are separate from security problems. Confirm each expected service and run an applicable security check to look for weaknesses.",
                "這些紀錄與資安問題分開呈現。確認各項預期服務，並執行適用的資安檢查以尋找弱點。",
            ),
            observations,
        )
    };

    // Every problem on one page before any of them gets a page of its own.
    //
    // Fifty-one cards is fifty-one pages, and a reader who wants "what did
    // this find" has to read all of them and hold the answer in their head.
    // The index answers it in one table and gives the card number to turn to.
    // The definition the cards no longer repeat, given once where a reader
    // meets the ratings. Ordered by how much of this report each basis
    // actually accounts for, so the sentence opens with the one behind most
    // of the numbers rather than with whichever finding happened to sort
    // first.
    let confidence_legend =
        html_confidence_legend(&confidence_bases_used, &confidence_basis_counts, catalog);
    let finding_index = if index_rows.is_empty() {
        String::new()
    } else {
        format!(
            concat!(
                "<table class=\"finding-index\">",
                "<caption class=\"visually-hidden\">{}</caption>",
                "<colgroup><col class=\"c-num\"><col class=\"c-sev\"><col class=\"c-name\">",
                "<col class=\"c-asset\"><col></colgroup><thead><tr>",
                "<th class=\"numeric\" scope=\"col\">#</th><th scope=\"col\">{}</th>",
                "<th scope=\"col\">{}</th><th scope=\"col\">{}</th><th scope=\"col\">{}</th>",
                "</tr></thead><tbody>{}</tbody></table>"
            ),
            catalog.text(
                "Every problem found in this run, in report order",
                "本輪發現的所有問題，依報告順序排列",
            ),
            catalog.text("Severity", "嚴重程度"),
            catalog.text("Problem", "問題"),
            catalog.text("Asset", "資產"),
            catalog.text("What to do next", "下一步怎麼做"),
            index_rows,
        )
    };
    // Before the table, not after it. The paragraph above already tells a
    // reader that confidence describes evidence strength; this is the rest of
    // that sentence, and the table itself has no confidence column to explain.
    let finding_index = confidence_legend + finding_index.as_str();
    let finding_index = if report.problem_groups.is_empty() {
        finding_index
    } else {
        format!(
            "<p>{} {} · {} {}</p>{}",
            catalog.format_number(problem_count),
            catalog.text("problems", "項問題"),
            catalog.format_number(
                report
                    .findings
                    .iter()
                    .filter(|finding| !finding
                        .severity_basis_code
                        .is_some_and(|basis| basis.is_exposure_observation()))
                    .count()
            ),
            catalog.text("original findings", "筆原始發現"),
            finding_index
        )
    };

    // Twenty-four task records carried the same four lines about the same
    // diagnostic log. Whether a run's scanner log can be read back is a
    // property of the run's export, not of one task inside it, so when every
    // task agrees the section says it once and the records stay about the
    // tasks.
    let mut rendered_tasks: Vec<(String, String)> = Vec::new();
    let diagnostics_heading = catalog.text("Redacted diagnostic log", "已遮蔽的診斷紀錄");
    for task in &report.technical_details.tasks {
        let execution = match &task.execution {
            crate::beginner_report::TechnicalExecution::CatalogEngine {
                engine_id,
                engine_version,
                reported_version,
                image_digest,
                command_sha256,
                runtime_provider,
                runtime_version,
                runtime_security_options,
                distribution_mode,
                image_repository,
                adapter_version,
                rule_version,
                knowledge_date,
            } => {
                let mut values = vec![
                    format!("{} {engine_id}", catalog.text("engine", "引擎")),
                    format!("{} {adapter_version}", catalog.text("adapter", "轉換器")),
                ];
                if let Some(value) = engine_version {
                    let label = crate::beginner_report::scanner_version_label(
                        value,
                        reported_version.as_deref(),
                        crate::beginner_report::ScannerVersionForm::Exact,
                        matches!(catalog.locale, crate::export::ReportLocale::ZhHant),
                    );
                    values.push(format!(
                        "{} {label}",
                        catalog.text("engine version", "引擎版本")
                    ));
                }
                if let Some(value) = knowledge_date {
                    values.push(format!(
                        "{} {value}",
                        catalog.text("last updated", "最後更新")
                    ));
                }
                if let Some(value) = image_repository {
                    values.push(format!(
                        "{} {value}",
                        catalog.text("image repository", "映像儲存庫")
                    ));
                }
                if let Some(value) = image_digest {
                    values.push(format!("{} {value}", catalog.text("image", "映像")));
                }
                if let Some(value) = command_sha256 {
                    values.push(format!(
                        "{} {value}",
                        catalog.text("command SHA-256", "命令 SHA-256")
                    ));
                }
                if let Some(value) = runtime_provider {
                    values.push(format!("{} {value}", catalog.text("runtime", "執行環境")));
                }
                if let Some(value) = runtime_version {
                    values.push(format!(
                        "{} {value}",
                        catalog.text("runtime version", "執行環境版本")
                    ));
                }
                if let Some(value) = runtime_security_options {
                    values.push(format!(
                        "{} {value}",
                        catalog.text("runtime security", "執行環境安全設定")
                    ));
                }
                if let Some(value) = distribution_mode {
                    values.push(format!(
                        "{} {}",
                        catalog.text("distribution", "散布方式"),
                        catalog.identifier(&enum_key(value))
                    ));
                }
                if let Some(value) = rule_version {
                    values.push(format!("{} {value}", catalog.text("rules", "規則")));
                }
                values.join(catalog.text("; ", "；"))
            }
            crate::beginner_report::TechnicalExecution::BuiltInLocalhostTcp {
                endpoint,
                timeout_ms,
                payload_bytes,
                observation,
                contract,
            } => {
                let observation = observation
                    .as_ref()
                    .map(|observation| {
                        format!(
                            "{} {}; {} {}",
                            catalog.text("outcome", "結果"),
                            catalog.identifier(&enum_key(&observation.outcome)),
                            catalog.text("observed", "觀察時間"),
                            catalog.format_time(&observation.observed_at)
                        )
                    })
                    .unwrap_or_else(|| {
                        catalog
                            .text("observation not retained", "未保留觀察紀錄")
                            .into()
                    });
                let contract = translated_task_sentence(catalog, contract);
                format!(
                    "{} {endpoint}; {} {timeout_ms} ms; {} {payload_bytes} {}; {observation}; {contract}",
                    catalog.text("native endpoint", "原生端點"),
                    catalog.text("timeout", "逾時"),
                    catalog.text("payload", "承載資料"),
                    catalog.text("bytes", "位元組"),
                )
            }
            crate::beginner_report::TechnicalExecution::ExternalReportImport {
                engine_id,
                source_format,
                source_sha256,
                ..
            } => {
                format!(
                    "{}: {}; {}: {}; SHA-256: {}. {}",
                    catalog.text("Imported report", "匯入報告"),
                    engine_id,
                    catalog.text("format", "格式"),
                    source_format,
                    source_sha256,
                    catalog.text(
                        "No scanner was executed; original scan coverage remains unverified.",
                        "未執行掃描工具；原始掃描涵蓋範圍尚未驗證。"
                    )
                )
            }
            crate::beginner_report::TechnicalExecution::AgentAuditFailure {
                receipt_sha256,
                terminal_sha256,
                occurred_at,
                ending,
                ..
            } => {
                use crate::agent_audit_failure::Ending;
                let (outcome, reasons, terminal_label) = match ending {
                    Ending::Blocked { reasons } => (
                        catalog.text("Source audit did not start", "原始碼稽核未開始"),
                        reasons.iter().map(enum_key).collect::<Vec<_>>().join(", "),
                        None,
                    ),
                    Ending::Terminated { reason, .. } => (
                        catalog.text(
                            "Source audit ended before completion",
                            "原始碼稽核未完成即結束",
                        ),
                        enum_key(reason),
                        Some(catalog.text("terminal record entry SHA-256", "終態紀錄項目 SHA-256")),
                    ),
                };
                let mut values = vec![
                    outcome.to_owned(),
                    format!("{}: {reasons}", catalog.text("reason codes", "原因代碼")),
                    format!(
                        "{}: {}",
                        catalog.text("recorded time", "記錄時間"),
                        catalog.format_time(occurred_at)
                    ),
                    format!(
                        "{}: {receipt_sha256}",
                        catalog.text("preparation receipt SHA-256", "準備收據 SHA-256")
                    ),
                ];
                // A blocked outcome's terminal digest is its preparation receipt.
                if let Some(label) = terminal_label {
                    values.push(format!("{label}: {terminal_sha256}"));
                }
                if let Ending::Terminated {
                    assignment_count,
                    capture_count,
                    ..
                } = ending
                {
                    values.push(format!(
                        "{}: {assignment_count}",
                        catalog.text("assignment count", "派工筆數")
                    ));
                    values.push(format!(
                        "{}: {capture_count}",
                        catalog.text("capture count", "擷取筆數")
                    ));
                }
                values.join(catalog.text("; ", "；"))
            }
            crate::beginner_report::TechnicalExecution::AgentAudit {
                provider_id,
                admission_id,
            } => {
                format!(
                    "{}: {}; {}: {}",
                    catalog.text("Source audit", "原始碼稽核"),
                    provider_id,
                    catalog.text("Admission", "納入紀錄"),
                    admission_id
                )
            }
            crate::beginner_report::TechnicalExecution::InvalidBuiltInTask { explanation } => {
                let explanation = translated_task_sentence(catalog, explanation);
                format!(
                    "{}{explanation}",
                    catalog
                        .label(catalog.text("invalid built-in task record", "無效的內建工作紀錄"))
                )
            }
        };
        let mut evidence = task
            .evidence_sha256
            .iter()
            .map(|sha256| format!("<li><code>{}</code></li>", html_escape(sha256)))
            .collect::<String>();
        if evidence.is_empty() {
            evidence.push_str(catalog.text(
                "<li>No raw-evidence SHA-256 was retained for this task.</li>",
                "<li>此工作未保留原始證據 SHA-256。</li>",
            ));
        }
        let targets = if task.target_asset_ids.is_empty() {
            catalog.text("none retained", "未保留").into()
        } else {
            task.target_asset_ids
                .iter()
                .map(|asset_id| html_escape(asset_id))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let diagnostic_value = task
            .redacted_diagnostic_log
            .value
            .as_ref()
            .map(|value| format!("<br><code>{}</code>", html_escape(value)))
            .unwrap_or_default();
        let diagnostic_explanation =
            translated_task_sentence(catalog, &task.redacted_diagnostic_log.explanation);
        let cleanup = task
            .cleanup_removed
            .map(|removed| {
                format!(
                    "{}={}",
                    catalog.text("removed", "已移除"),
                    catalog.text(
                        if removed { "true" } else { "false" },
                        if removed { "是" } else { "否" }
                    ),
                )
            })
            .unwrap_or_else(|| catalog.text("not recorded", "未記錄").into());
        // The phase is the state under a finer name, and twenty-three of the
        // twenty-four records printed the same word twice: once title-cased as
        // the state, once as the raw snake_case key the backend stores -- which
        // in a Chinese record read "階段: completed" under a translated label.
        // It is humanized like every other identifier, and shown only where it
        // says something the state did not.
        let state = catalog.identifier(&enum_key(&task.status));
        let named_phase = catalog.identifier(&task.phase);
        let phase = match named_phase == state {
            true => String::new(),
            false => format!(
                "{}{} · ",
                catalog.strong_label(catalog.text("Phase", "階段")),
                html_escape(&named_phase),
            ),
        };
        let body = format!(
            concat!(
                "<article><h3>{} <code>{}</code></h3>",
                "<p>{}{} · {}",
                "{}{}%</p>",
                "<p>{}{} · {}{} · ",
                "{}{}</p>",
                "<p>{}{} · {}{} · ",
                "{}{}</p>",
                "<p>{}{}</p>",
                "<h4>{}</h4><ul>{}</ul>"
            ),
            catalog.text("Task", "工作"),
            html_escape(&task.task_id),
            catalog.strong_label(catalog.text("State", "狀態")),
            html_escape(&state),
            phase,
            catalog.strong_label(catalog.text("Progress", "進度")),
            catalog.format_number(task.progress_percent as usize),
            catalog.strong_label(catalog.text("Started", "開始")),
            html_escape(&display_time(task.started_at.as_ref())),
            catalog.strong_label(catalog.text("Finished", "完成")),
            html_escape(&display_time(task.finished_at.as_ref())),
            catalog.strong_label(catalog.text("Targets", "目標")),
            targets,
            catalog.strong_label(catalog.text("Exit code", "結束碼")),
            task.exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| catalog.text("not recorded", "未記錄").into()),
            catalog.strong_label(catalog.text("Error code", "錯誤碼")),
            // Humanized like the availability below it and the state above it.
            // This was the one value on the line the backend's own spelling
            // reached the page through, so a Chinese record of the run that
            // failed read "錯誤碼: execution_failed".
            html_escape(
                &task
                    .error_code
                    .as_deref()
                    .map(|code| catalog.identifier(code))
                    .unwrap_or_else(|| catalog.text("none recorded", "未記錄").to_owned())
            ),
            catalog.strong_label(catalog.text("Cleanup", "清理")),
            html_escape(&cleanup),
            catalog.strong_label(catalog.text("Execution identity", "執行識別")),
            html_escape(&execution),
            catalog.text("Evidence SHA-256", "證據 SHA-256"),
            evidence,
        );
        rendered_tasks.push((
            body,
            format!(
                concat!("<p>{}{}{}<br>{}</p>", "<p><small>{}</small></p>"),
                catalog.strong_label(catalog.text("Availability", "可用狀態")),
                html_escape(
                    &catalog.identifier(&enum_key(&task.redacted_diagnostic_log.availability))
                ),
                diagnostic_value,
                html_escape(diagnostic_explanation),
                catalog.text(
                    "Scanner messages are not included in this readable HTML report.",
                    "這份好讀的 HTML 報告不包含掃描工具訊息。",
                ),
            ),
        ));
    }
    let shared_diagnostics = match rendered_tasks.split_first() {
        Some(((_, first), rest)) if !rest.is_empty() => rest
            .iter()
            .all(|(_, block)| block == first)
            .then(|| first.clone()),
        _ => None,
    };
    let mut technical_tasks = match &shared_diagnostics {
        // A sibling of the task records below it, not a part of one. It kept
        // the h4 it had while it was still printed inside each task, which
        // left the one hole in this report's heading outline: an h4 directly
        // under the section's h2, ahead of the h3 records it summarizes.
        Some(shared) => format!(
            "<article><h3>{}</h3><p>{}</p>{}</article>",
            diagnostics_heading,
            catalog.text(
                "Every task in this run recorded the same state.",
                "本輪每個工作記錄的狀態都相同。",
            ),
            shared,
        ),
        None => String::new(),
    };
    for (body, block) in rendered_tasks {
        technical_tasks.push_str(&body);
        if shared_diagnostics.is_none() {
            technical_tasks.push_str(&format!("<h4>{diagnostics_heading}</h4>{block}"));
        }
        technical_tasks.push_str("</article>");
    }
    if technical_tasks.is_empty() {
        technical_tasks.push_str(catalog.text(
            "<p>No technical task record was retained for this run.</p>",
            "<p>本輪未保留技術工作紀錄。</p>",
        ));
    }

    let mut data_quality_warnings = report
        .data_quality_warnings
        .iter()
        .map(|warning| {
            let presented = if catalog.locale == crate::export::ReportLocale::ZhHant {
                crate::finding_narrative::data_quality_warning_zh_hant(warning)
                    .unwrap_or_else(|| warning.clone())
            } else {
                warning.clone()
            };
            format!("<li>{}</li>", html_escape(&presented))
        })
        .collect::<String>();
    if data_quality_warnings.is_empty() {
        data_quality_warnings.push_str(catalog.text(
            "<li>No report data-quality warning was recorded.</li>",
            "<li>未記錄報告資料品質警告。</li>",
        ));
    }

    // Member names a reader sees. The map key stays the finding id. A
    // Microsoft 365 title names the passing state, so the value is the
    // headline rather than that title.
    let report_finding_titles = report
        .findings
        .iter()
        .map(|finding| {
            let headline = match catalog.locale {
                crate::export::ReportLocale::En => {
                    crate::finding_narrative::finding_headline_english(
                        &finding.title,
                        finding.family,
                    )
                }
                crate::export::ReportLocale::ZhHant => {
                    crate::finding_narrative::finding_headline_zh_hant(
                        &finding.title,
                        finding.family,
                    )
                }
            };
            (finding.finding_id.as_str(), headline)
        })
        .collect::<BTreeMap<_, _>>();
    let selected_finding_ids = report_finding_titles
        .keys()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut active_group_articles = String::new();
    for group in &exported.finding_groups {
        let members = group
            .finding_ids
            .iter()
            .map(|finding_id| {
                let title = report_finding_titles
                    .get(finding_id.as_str())
                    .map(String::as_str)
                    .unwrap_or(catalog.text(
                        "Selected-run finding details unavailable",
                        "本輪問題詳細資料無法取得",
                    ));
                let selected_run_note = if selected_finding_ids.contains(finding_id.as_str()) {
                    catalog.text("observed in selected run", "本輪已觀察到")
                } else {
                    catalog.text(
                        "not observed in selected run; retained as case history",
                        "本輪未觀察到；保留為案件歷史",
                    )
                };
                format!(
                    "<li>{} <code>{}</code> — {}</li>",
                    html_escape(title),
                    html_escape(finding_id),
                    selected_run_note,
                )
            })
            .collect::<String>();
        active_group_articles.push_str(&format!(
            concat!(
                "<article><h3>{}</h3><p>{}</p><ul>{}</ul>",
                "<p>{}{} · {}{} · ",
                "{}<code>{}</code></p></article>"
            ),
            html_escape(&group.title),
            html_escape(&group.rationale),
            members,
            catalog.strong_label(catalog.text("Created by", "建立者")),
            html_escape(&group.grouped_by),
            catalog.strong_label(catalog.text("Created at", "建立時間")),
            html_escape(&catalog.format_time(&group.created_at)),
            catalog.strong_label(catalog.text("Group ID", "群組 ID")),
            html_escape(&group.id),
        ));
    }
    if active_group_articles.is_empty() {
        active_group_articles.push_str(catalog.text(
            "<p>No active presentation groups are recorded.</p>",
            "<p>沒有記錄中的有效呈現群組。</p>",
        ));
    }

    let mut grouping_history_rows = String::new();
    for event in &exported.finding_group_events {
        let member_ids = event
            .finding_ids
            .iter()
            .map(|finding_id| html_escape(finding_id))
            .collect::<Vec<_>>()
            .join(", ");
        grouping_history_rows.push_str(&format!(
            concat!(
                "<tr><td>{}</td><td>{}</td><td><code>{}</code></td>",
                "<td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"
            ),
            html_escape(&catalog.format_time(&event.occurred_at)),
            html_escape(&catalog.identifier(&enum_key(&event.action))),
            html_escape(&event.group_id),
            html_escape(&event.title),
            member_ids,
            html_escape(&event.rationale),
            html_escape(&event.actor),
        ));
    }
    if grouping_history_rows.is_empty() {
        grouping_history_rows.push_str(catalog.text(
            "<tr><td colspan=\"7\">No grouping events are recorded.</td></tr>",
            "<tr><td colspan=\"7\">沒有群組事件紀錄。</td></tr>",
        ));
    }

    let mut technical_target_identities = report
        .requested
        .targets
        .iter()
        .map(|target| {
            format!(
                "<li>{}<code>{}</code></li>",
                catalog.label(&html_escape(
                    target_labels
                        .get(&target.asset_id)
                        .map(String::as_str)
                        .unwrap_or(catalog.text("Saved target", "已保存的目標")),
                )),
                html_escape(&target.asset_id),
            )
        })
        .collect::<String>();
    if technical_target_identities.is_empty() {
        technical_target_identities.push_str(catalog.text(
            "<li>No exact requested target ID was retained.</li>",
            "<li>未保留精確的要求目標 ID。</li>",
        ));
    }
    let mut technical_check_identities = report
        .requested
        .requested_check_ids
        .iter()
        .map(|check_id| format!("<li><code>{}</code></li>", html_escape(check_id)))
        .collect::<String>();
    if technical_check_identities.is_empty() {
        technical_check_identities.push_str(catalog.text(
            "<li>No exact requested check ID was retained.</li>",
            "<li>未保留精確的要求檢查 ID。</li>",
        ));
    }

    let mut document = format!(
        concat!(
            "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">",
            "<title>{} — ai-security-scanner</title>"
        ),
        catalog.html_lang(),
        html_escape(html_case_title(&report, catalog)),
    );
    document.push_str(concat!(
        "<style>:root{--ink:#101828;--body:#344054;--muted:#667085;--line:#e4e7ec;",
        "--tint:#f9fafb;--accent:#123a63}",
        "*{box-sizing:border-box}",
        "body{font:16px/1.6 -apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Noto Sans TC\",",
        "\"PingFang TC\",\"Microsoft JhengHei\",sans-serif;max-width:1120px;margin:auto;padding:2.5rem 2rem 4rem;color:var(--body)}",
        "h1,h2,h3,h4{line-height:1.25;color:var(--ink);font-weight:650}",
        "h1{font-size:2rem;letter-spacing:-.02em;margin:.2rem 0 1rem}",
        "h2{font-size:1.3rem;margin:2.5rem 0 .5rem;padding-bottom:.4rem;border-bottom:2px solid var(--line)}",
        "h3{font-size:1.05rem;margin:1.5rem 0 .5rem}",
        "code{font-size:.9em;background:var(--tint);padding:.05rem .3rem;border-radius:.2rem}",
        "table{width:100%;border-collapse:collapse;margin:.75rem 0}",
        "th,td{border-bottom:1px solid var(--line);padding:.55rem .65rem;text-align:left;vertical-align:top}",
        "thead th{background:var(--tint);border-bottom:2px solid #d0d5dd;color:var(--ink);font-size:.85rem;",
        "text-transform:uppercase;letter-spacing:.04em}",
        "tbody tr:last-child th,tbody tr:last-child td{border-bottom:0}",
        ".numeric{text-align:right;font-variant-numeric:tabular-nums}",
        "article{border:1px solid var(--line);border-radius:.6rem;padding:.9rem 1.1rem;margin:.7rem 0;background:#fff}",
        "article h3{margin:0 0 .35rem}article p{margin:.3rem 0}article h4{margin:.7rem 0 .25rem;font-size:.92rem}",
        "article ul{margin:.25rem 0;padding-left:1.2rem}",
        ".cover{border-bottom:3px solid var(--accent);padding-bottom:1.25rem;margin-bottom:1.5rem}",
        ".cover__product{margin:0;font-size:.78rem;text-transform:uppercase;letter-spacing:.12em;color:var(--muted)}",
        ".cover__meta{display:flex;flex-wrap:wrap;gap:.4rem 2.5rem;margin:0}",
        ".cover__meta dt{font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}",
        ".cover__meta dd{margin:.1rem 0 0;color:var(--ink)}",
        ".kpi-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(7.5rem,1fr));gap:.6rem;margin:0 0 1.5rem}",
        ".kpi{border:1px solid var(--line);border-top:3px solid var(--muted);border-radius:.45rem;",
        "padding:.7rem .8rem;background:#fff;display:flex;flex-direction:column;gap:.15rem}",
        ".kpi__value{font-size:1.7rem;font-weight:680;line-height:1.1;color:var(--ink);font-variant-numeric:tabular-nums}",
        ".kpi__label{font-size:.78rem;color:var(--muted);line-height:1.3}",
        ".kpi--problems{border-top-color:#b42318}.kpi--problems .kpi__value{color:#b42318}",
        ".kpi--complete{border-top-color:#1a7f4b}.kpi--partial{border-top-color:#b54708}",
        ".kpi--failed{border-top-color:#b42318}",
        ".kpi--quiet{border-top-color:var(--line)}.kpi--quiet .kpi__value{color:var(--muted);font-weight:600}",
        ".report-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1rem}",
        ".report-card{border:1px solid var(--line);border-radius:.6rem;padding:1.15rem;background:#fff}",
        ".report-card h2{margin-top:0;font-size:1.05rem;border:0;padding:0}",
        // Nine assets were nine bordered cards over three pages, each spending
        // a full-width line on its name, another on its state, another on a
        // bar as wide as the page, and another on the same sentence of advice.
        // One row an asset says all of it, and a reader can compare them.
        ".tested-table{font-size:.84rem}",
        ".tested-table th,.tested-table td{padding:.3rem .5rem;vertical-align:top}",
        ".tested-table th[scope=\"row\"]{text-align:left;color:var(--ink)}",
        // The widest row this table can produce is known: check names come from
        // the engine catalog and the two time columns are one fixed format. So
        // nothing here has to wrap, and letting it wrap was expensive - the card
        // grew past the page, the whole card grid moved to a fresh page, and the
        // section before it was left half empty. Six pages, for a column break.
        ".tested-table th{white-space:nowrap}.tested-state{white-space:nowrap}",
        ".tested-time{white-space:nowrap;color:var(--muted);font-variant-numeric:tabular-nums}",
        ".tested-detail>td{padding-top:0}.tested-detail ul{margin:.15rem 0 .35rem}",
        ".asset-result-table{table-layout:fixed;font-size:.86rem}",
        ".asset-result-table col.c-asset{width:20%}.asset-result-table col.c-state{width:8rem}",
        ".asset-result-table col.c-mix{width:11.5rem}",
        ".asset-result-table th,.asset-result-table td{padding:.4rem .5rem;vertical-align:top}",
        ".asset-result__mix .asset-severity{display:inline-flex;width:3rem;",
        "vertical-align:middle;margin:0 .4rem 0 0}",
        ".asset-result__mix .asset-severity__legend{display:inline;margin:0;font-size:.75rem}",
        ".asset-result__mix .asset-severity__empty{font-size:.75rem;color:var(--muted)}",
        ".asset-result-steps{margin:.55rem 0 0;font-size:.82rem;color:var(--muted);line-height:1.45}",
        ".asset-result-steps strong{color:var(--body)}",
        ".asset-result__identity{text-align:left;font-weight:400}",
        ".asset-result__identity strong{display:block;color:var(--ink);overflow-wrap:anywhere}",
        ".asset-result__identity small{color:var(--muted);font-size:.82rem}",
        ".asset-result__status{white-space:normal;font-weight:600}",
        // The state used to be a coloured rule down the left of a card. In a
        // row it is the pill's own border, so the colour still names the state
        // without a card to hang it on.
        ".asset-result--problems-found .asset-result__status{color:#b42318;border-color:#f0b4ac}",
        ".asset-result--no-problems-completed .asset-result__status{color:#027a48;border-color:#a6dcc0}",
        ".asset-result--incomplete-failed .asset-result__status{color:#b54708;border-color:#f0c9a0}",
        ".asset-result--not-tested .asset-result__status{color:#667085;border-color:var(--line)}",
        "details.technical{margin-top:2.5rem;border-top:1px solid var(--line);padding-top:1rem}",
        ".finding-asset{font-weight:400;color:var(--muted)}",
        "details.finding-technical{margin-top:.55rem;padding-top:.35rem}",
        "details.finding-technical>summary{cursor:pointer;color:var(--muted)}",
        // Absolute table captions stay inside their scroll area's bounds.
        // Long engine identifiers wrap without losing any evidence text.
        "@media screen{body{overflow-wrap:anywhere}.report-card{min-width:0}.matrix-scroll{position:relative}.tested-table{overflow-wrap:normal}}",
        "@media screen and (max-width:960px){.report-grid{grid-template-columns:minmax(0,1fr)}}",
        "@media(max-width:760px){body{padding:1.25rem;overflow-wrap:anywhere}.report-grid{grid-template-columns:minmax(0,1fr)}.report-card{min-width:0}table{display:block;overflow-x:auto}}",
        ".pill{display:inline-block;border:1px solid currentColor;border-radius:1rem;padding:.08rem .6rem;font-size:.82rem;white-space:nowrap}",
        ".finding-meta{display:flex;flex-wrap:wrap;gap:.3rem .45rem;align-items:center;color:var(--muted);font-size:.85rem}",
        ".finding-index{font-size:.85rem;table-layout:fixed}",
        ".finding-index th,.finding-index td{padding:.3rem .5rem;overflow-wrap:anywhere}",
        ".finding-index col.c-num{width:2.6rem}.finding-index col.c-sev{width:5.5rem}",
        ".finding-index col.c-name{width:30%}.finding-index col.c-asset{width:9rem}",
        ".finding-index td:nth-child(3){font-weight:600;color:var(--ink)}",
        ".finding-index td:nth-child(4),.finding-index td:nth-child(5){color:var(--muted)}",
        ".finding-index .pill{font-size:.75rem;padding:.02rem .45rem}",
        ".finding-index a{color:var(--accent)}",
        ".attachments-table{table-layout:fixed}.attachments-table th:first-child{width:7rem}",
        ".attachments-table th:nth-child(2){width:4.5rem}.attachments-table td{overflow-wrap:anywhere}",
        ".attachment-download{display:inline-flex;align-items:center;min-height:44px;color:var(--accent)}",
        ".attachment-download:focus-visible{outline:2px solid var(--accent);outline-offset:2px}",
        ".attachments-table summary{cursor:pointer}.attachments-table ul{padding-left:1.2rem}",
        // An engine's own rating is two or three words. Given a row of its
        // own it broke the identifier line into three.
        ".finding-meta__note{font-size:.8rem;line-height:1.35}",
        ".finding-references{font-size:.78rem;line-height:1.35;color:var(--muted)}",
        ".finding-legend{font-size:.82rem;color:var(--muted);margin:-.4rem 0 .9rem}",
        ".finding-references code{font-size:.92em;background:none;padding:0}",
        ".finding-action{margin-top:.5rem}",
        ".finding-meta .pill{white-space:normal}",
        ".pill--critical{color:#7a271a;background:#fbeae7}.pill--high{color:#b42318;background:#fbeae7}",
        ".pill--medium{color:#b54708;background:#fdf1dc}.pill--low{color:#5c6a70;background:#f2f4f5}",
        ".pill--informational{color:#667085;background:var(--tint)}.pill--unknown{color:#475467;background:#eceff1}",
        ".executive-summary{border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:.6rem;padding:1.1rem 1.35rem;margin:1.5rem 0 2rem;background:var(--tint)}",
        ".executive-summary h2{margin:0 0 .5rem;border:0;padding:0;font-size:1.15rem}",
        ".executive-summary p{margin:.35rem 0;color:var(--ink)}",
        ".severity-profile{margin:1.5rem 0}",
        ".severity-row{display:grid;grid-template-columns:7.5rem 1fr 3.5rem;gap:.75rem;align-items:center;margin:.3rem 0}",
        ".severity-row__label{font-size:.9rem}",
        ".severity-row__count{text-align:right;font-variant-numeric:tabular-nums}",
        ".severity-row--none .severity-row__label,.severity-row--none .severity-row__count{color:var(--muted)}",
        ".severity-bar{display:block;background:#eceff1;border-radius:.2rem;height:1.1rem;overflow:hidden}",
        ".severity-bar__fill{display:block;height:100%;border-radius:.2rem}",
        ".severity-bar__fill--critical{background:#7a271a}.severity-bar__fill--high{background:#b42318}",
        ".severity-bar__fill--medium{background:#b54708}.severity-bar__fill--low{background:#7f8c8d}",
        ".severity-bar__fill--informational{background:#98a2b3}.severity-bar__fill--unknown{background:#475467}",
        ".matrix-scroll{overflow-x:auto}",
        ".coverage-matrix{font-size:.85rem;table-layout:fixed;width:auto}",
        ".coverage-matrix th,.coverage-matrix td{padding:.3rem .15rem;border:1px solid var(--line)}",
        ".coverage-matrix thead th{vertical-align:bottom;background:var(--tint);text-transform:none;",
        "letter-spacing:0;padding:.4rem .15rem}",
        ".coverage-matrix tbody th{width:auto;max-width:18rem;font-weight:600;color:var(--ink);",
        "font-size:.85rem;overflow-wrap:anywhere;padding:.3rem .6rem}",
        // Twenty-one engines will not fit across a page as horizontal labels.
        // Turning the header on its side keeps every column narrow enough that
        // the whole grid is one glance instead of a horizontal scroll.
        ".matrix-engine{display:inline-block;white-space:nowrap;writing-mode:vertical-rl;",
        "transform:rotate(180deg);font-size:.8rem;font-weight:600;color:var(--ink)}",
        ".coverage-matrix td{width:1.75rem}",
        ".matrix-cell{text-align:center;white-space:nowrap;font-size:.95rem;line-height:1}",
        ".matrix-cell--complete{background:#e7f4ec;color:#1a7f4b}.matrix-cell--partial{background:#fdf1dc;color:#b54708}",
        ".matrix-cell--failed{background:#fbe9e7;color:#b42318}.matrix-cell--timed-out{background:#fdf1dc;color:#b54708}",
        ".matrix-cell--cancelled{background:#eceff1;color:#475467}",
        ".matrix-cell--not-tested{background:#eceff1;color:#475467}.matrix-cell--not-planned{background:transparent}",
        ".matrix-legend{list-style:none;padding:0;margin:.6rem 0 0;display:flex;flex-wrap:wrap;gap:.35rem .9rem;font-size:.8rem;color:#475467}",
        ".matrix-legend li{display:flex;align-items:center;gap:.3rem}",
        ".matrix-key{display:inline-block;min-width:1.2rem;text-align:center;border:1px solid #d0d5dd;border-radius:.2rem;padding:.05rem .15rem;line-height:1}",
        ".asset-severity{display:flex;height:.55rem;border-radius:.28rem;overflow:hidden;margin:.35rem 0 .15rem;background:#eceff1}",
        ".asset-severity__part{display:block;height:100%}",
        ".asset-severity__legend{margin:0 0 .4rem;font-size:.8rem;color:#475467}",
        ".visually-hidden{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}",
        ".framework-overview th[scope=row]{font-weight:600;color:var(--ink)}",
        ".framework-overview small{color:var(--muted);font-weight:400}",
        ".framework-state{display:inline-block;font-size:.85rem;padding:.1rem .55rem;border-radius:1rem;border:1px solid var(--line)}",
        ".framework-state--observed{background:#eaf3ee;border-color:#bfdcca;color:#12603c}",
        ".framework-state--quiet{background:var(--tint);color:var(--muted)}",
        ".framework-block{padding:1.15rem 1.25rem}",
        ".framework-block h3{margin-top:0}.framework-block h3 small{color:var(--muted);font-weight:400;font-size:.85rem}",
        ".framework-block__state{margin:0;color:var(--muted);font-size:.88rem}",
        ".framework-controls{font-size:.92rem}",
        ".framework-controls td:first-child{white-space:nowrap}",
        // Bar beside its counts, not above them. Stacked, the two encodings of
        // one number cost thirty-two control rows an extra line each; side by
        // side the row is as tall as its title. The counts stay: a bar alone
        // is a colour, and this report prints in black and white.
        // Bar beside its counts, not above them. Stacked, the two encodings of
        // one number cost thirty-two control rows an extra line each. Both
        // stay inline-level so the cell remains a table cell: making the cell
        // itself a flex container took it out of the row and left every rule
        // in the table at a different height. The counts stay too -- a bar on
        // its own is a colour, and this report prints in black and white.
        ".framework-mix{width:16.5rem}",
        ".framework-mix .asset-severity{display:inline-flex;width:3.5rem;",
        "vertical-align:middle;margin:0 .45rem 0 0}",
        ".framework-mix .asset-severity__legend{display:inline;margin:0;font-size:.75rem}",
        ".framework-source{margin:.55rem 0 0;font-size:.78rem;color:var(--muted);line-height:1.4}",
        ".framework-sources h3{margin-bottom:.2rem;font-size:1rem}",
        ".framework-quiet{margin:.45rem 0 0;font-size:.85rem;color:var(--muted)}",
        ".framework-quiet strong{color:var(--body)}",
        ".framework-sources .framework-source strong{color:var(--body)}",
        ".framework-source__url{overflow-wrap:anywhere}",
    ));
    document.push_str(&html_page_rule(&report, catalog));
    document.push_str(concat!(
        "@media print{",
        "body{max-width:none;margin:0;padding:0;font-size:9.5pt;line-height:1.45;color:#000}",
        "article{padding:.6rem .75rem;margin:.45rem 0}article p{margin:.22rem 0}",
        ".finding-index{font-size:8.5pt}",
        // Sections flow. Opening every one on a fresh page cost three pages of
        // half-empty front matter - severity, coverage and the asset board are
        // each well under a page and each had one to itself - and six pages
        // over the whole report. break-after:avoid is what actually keeps a
        // heading with its section; break-before:page only guaranteed the
        // whitespace above it.
        "h2{break-after:avoid;margin-top:0;font-size:1.15rem}",
        "h1{break-after:avoid}h3,h4{break-after:avoid}",
        ".cover h1{font-size:1.9rem}",
        ".executive-summary{break-inside:avoid}",
        "p{orphans:3;widows:3}",
        // Eight tiles split into two balanced rows on a page this wide.
        ".kpi-row{grid-template-columns:repeat(4,1fr)}",
        ".kpi__value{font-size:1.5rem}",
        "article,.asset-result,.kpi,tr,.severity-row,.matrix-legend{break-inside:avoid}",
        "thead{display:table-header-group}tfoot{display:table-footer-group}",
        // A framework block runs longer than a page; keeping its heading with
        // the first rows is the most that can be promised, and promising the
        // whole block would only push it and break it anyway.
        ".framework-block{break-inside:auto}",
        ".framework-block h3,.framework-block__state{break-after:avoid}",
        // Collapsed detail is a screen affordance. On paper it is all there is,
        // so the summary becomes the heading of what follows it.
        //
        // Chrome prints a closed <details> as its summary and nothing under
        // it, so this report was promising sixty-two headings and printing
        // none of them. What the four groups cost, measured on the all-engine
        // report against its twenty-one pages: framework attribution 0,
        // the asset inventory 0, the run's task records +7, and the
        // fifty-one per-finding evidence blocks +59.
        //
        // The two that cost nothing print. They fit in whitespace the layout
        // already had, and attribution of record is the last thing that should
        // depend on a reader having clicked something. The two that cost pages
        // are the technical record the spec keeps as detail: one a reader
        // opened still prints, and a closed one is not printed as a heading
        // over nothing.
        "details[open]{display:block}",
        ".source-provenance,.inventory-complete{display:block}",
        ".source-provenance::details-content,.inventory-complete::details-content",
        "{content-visibility:visible}",
        "details:not([open]):not(.source-provenance):not(.inventory-complete){display:none}",
        "details>summary{display:block;list-style:none;font-weight:600;color:#101828;",
        "margin:.6rem 0 .2rem;break-after:avoid}",
        "details>summary::-webkit-details-marker{display:none}",
        // On paper the card's summary is a heading for the evidence that
        // follows it, not a control a reader clicks, and it was carrying a
        // control's worth of margin above and below one line of text.
        "article details.finding-technical>summary{margin:.15rem 0 .1rem;font-weight:500}",
        ".matrix-scroll{overflow:visible}",
        ".severity-bar,.severity-bar__fill,.asset-severity,.asset-severity__part,",
        ".matrix-cell,.matrix-key,.kpi,.framework-state,thead th,.pill",
        "{-webkit-print-color-adjust:exact;print-color-adjust:exact}",
        ".coverage-matrix th,.coverage-matrix td{border:.5pt solid #98a2b3}",
        "th,td{border-bottom:.5pt solid #98a2b3}",
        "a{text-decoration:none;color:#000}}</style></head><body>"
    ));
    document.push_str(&format!(
        concat!(
            "<header class=\"cover\"><p class=\"cover__product\">{}</p><h1>{}</h1>",
            "<dl class=\"cover__meta\">",
            "<div><dt>{}</dt><dd><code>{}</code></dd></div>",
            "<div><dt>{}</dt><dd>{}</dd></div>",
            "<div><dt>{}</dt><dd><strong class=\"pill\">{}</strong></dd></div>",
            "</dl></header>",
            "<section class=\"kpi-row\">{}</section>"
        ),
        catalog.text(
            "ai-security-scanner / security report",
            "ai-security-scanner／安全檢查報告"
        ),
        html_escape(html_case_title(&report, catalog)),
        catalog.text("Selected run", "選定的掃描輪次"),
        html_escape(&report.run_id),
        catalog.text("Last saved", "最後保存"),
        html_escape(&catalog.format_time(&report.state.last_durable_update)),
        catalog.text("Run state", "本輪狀態"),
        report_summary,
        html_kpi_tiles(
            &[
                (
                    catalog.text("Problems found", "發現的問題"),
                    problem_count,
                    "problems",
                ),
                (
                    catalog.text("Checks completed", "已完成檢查"),
                    html_completed_asset_check_count(&report),
                    "complete",
                ),
                (
                    catalog.text("Partly completed", "部分完成"),
                    report_counts.tested_partial,
                    "partial",
                ),
                (
                    catalog.text("Failed", "失敗"),
                    report_counts.failed,
                    "failed"
                ),
                (
                    catalog.text("Timed out", "逾時"),
                    report_counts.timed_out,
                    "partial",
                ),
                (
                    catalog.text("Not tested", "未測試"),
                    report_counts.not_tested,
                    "quiet",
                ),
                coverage_kpis[0],
                coverage_kpis[1],
            ],
            catalog,
        ),
    ));
    // Before the asset list: a reader who stops after one screen should still
    // have the run's outcome, its shape, and what was left uncovered.
    document.push_str(&html_executive_summary(
        &report,
        report_counts,
        problem_count,
        catalog,
    ));
    document.push_str(&html_verification_comparison_section(
        case,
        &exported,
        run_id,
        &report,
        &target_labels,
        options,
        catalog,
    ));
    document.push_str(&html_severity_profile(&report, catalog));
    document.push_str(&html_coverage_matrix(&report, &target_labels, catalog));
    document.push_str(&html_incident_focus_section(
        &report,
        &target_labels,
        catalog,
    ));
    document.push_str(&html_asset_result_section(&report, &target_labels, catalog));
    document.push_str(&html_source_audits(&report, catalog));
    document.push_str(&format!(
        concat!(
            "<section class=\"report-grid\"><div class=\"report-card\">",
            "<h2>{}</h2>{}",
            "<h3>{}</h3><ul>{}</ul><h3>{}</h3><ul>{}</ul>",
            "<h3>{}</h3><ul>{}</ul></div>",
            "<div class=\"report-card\"><h2>{}</h2>",
            "<p>{}{}</p>",
            "<div class=\"matrix-scroll\"><table class=\"tested-table\">",
            "<caption class=\"visually-hidden\">{}</caption>",
            "<thead><tr><th scope=\"col\">{}</th>",
            "<th scope=\"col\">{}</th><th scope=\"col\">{}</th><th scope=\"col\">{}</th>",
            "<th scope=\"col\">{}</th></tr></thead><tbody>{}</tbody></table></div>{}</div>",
            "<div class=\"report-card\"><h2>{}</h2><ul>{}</ul>{}</div></section>",
            "<section><h2>{}</h2>{}<ol>{}</ol></section>",
            "<h2>{}</h2>",
            "<p>{}</p>{}{}{}"
        ),
        catalog.text("What you asked to scan", "你要求掃描的內容"),
        scan_depth_paragraph,
        catalog.text("Targets", "目標"),
        requested_targets,
        catalog.text("Requested checks", "要求的檢查"),
        requested_checks,
        catalog.text("Limits", "限制"),
        requested_limits,
        catalog.text("What was actually tested", "實際測試的內容"),
        catalog.strong_label(catalog.text("Scan period", "檢查時間")),
        html_escape(&actual_window),
        catalog.text(
            "Every check this run started, with the targets it reached and when",
            "本輪啟動的每項檢查，以及它涵蓋的目標與時間",
        ),
        catalog.text("Check", "檢查"),
        catalog.text("State", "狀態"),
        catalog.text("Targets", "目標"),
        catalog.text("Started", "開始"),
        catalog.text("Finished", "完成"),
        tested_items,
        network_scope_section,
        coverage_items_title,
        gap_items,
        record_notes_section,
        catalog.text("What to do next", "下一步怎麼做"),
        shared_safety_note,
        next_step_items,
        catalog.text("Problems found", "發現的問題"),
        catalog.text(
            "Problems follow the report order. Severity is the scanner's rating of possible impact (this product rates it only when the scanner did not), confidence describes evidence strength, and priority is this product's recommended order. When this product places a problem lower than its severity suggests, the card says why.",
            "問題依報告順序排列。嚴重程度是掃描工具對可能影響的評級（掃描工具未評級時才由本產品評定），信心程度描述證據強度，優先順序則是本產品建議的處理次序。若本產品把某項問題排得比嚴重程度所示更後面，問題卡會說明原因。",
        ),
        finding_index,
        findings,
        observation_section,
    ));
    // Framework coordinates and inventory are context for the problems
    // above, so they follow them (spec §6.3 and §6.1).
    document.push_str(&typed_inventory_section);
    if report.source_audits.is_empty() {
        document.push_str(&html_framework_section(&exported, run_id, catalog));
    }
    document.push_str(&format!(
        concat!(
            "<details class=\"technical\"{}><summary><strong>{}</strong></summary>",
            "<h2>{}</h2>",
            "<h3>{}</h3><ul>{}</ul><h3>{}</h3><ul>{}</ul>",
            "<h2>{}</h2>{}",
            "<h2>{}</h2><ul>{}</ul>",
            "<h2>{}</h2>",
            "<p>{}</p>{}",
            "<h3>{}</h3>",
            "<table><caption class=\"visually-hidden\">{}</caption>",
            "<thead><tr><th scope=\"col\">{}</th><th scope=\"col\">{}</th>",
            "<th scope=\"col\">{}</th><th scope=\"col\">{}</th><th scope=\"col\">{}</th>",
            "<th scope=\"col\">{}</th><th scope=\"col\">{}</th>",
            "</tr></thead><tbody>{}</tbody></table></details>"
        ),
        if report.technical_details.collapsed_by_default {
            ""
        } else {
            " open"
        },
        catalog.text("Technical details", "技術詳細資料"),
        catalog.text("Exact requested identities", "精確的要求識別"),
        catalog.text("Target IDs", "目標 ID"),
        technical_target_identities,
        catalog.text("Check IDs", "檢查 ID"),
        technical_check_identities,
        catalog.text("Selected-run task details", "本輪工作詳細資料"),
        technical_tasks,
        catalog.text("Report data-quality notes", "報告資料品質備註"),
        data_quality_warnings,
        catalog.text("Reversible finding groups", "可還原的問題群組"),
        catalog.text(
            "Groups are presentation metadata only. Every canonical finding, fingerprint, evidence record, and raw artifact remains independent; removing a group appends history and does not delete its members.",
            "群組只屬於呈現用中繼資料。每筆標準問題、指紋、證據紀錄與原始成品仍彼此獨立；移除群組只會附加歷史，不會刪除成員。",
        ),
        active_group_articles,
        catalog.text("Immutable grouping history", "不可變更的群組歷史"),
        catalog.text(
            "Every grouping event recorded for this case, oldest first",
            "本案件記錄的每筆群組事件，由舊到新",
        ),
        catalog.text("Time", "時間"),
        catalog.text("Action", "動作"),
        catalog.text("Group ID", "群組 ID"),
        catalog.text("Title", "標題"),
        catalog.text("Finding IDs", "問題 ID"),
        catalog.text("Reason", "原因"),
        catalog.text("Actor", "操作者"),
        grouping_history_rows,
    ));
    if options.include_raw_artifacts {
        document.push_str(&html_original_report_attachments(attachments, catalog));
    }
    // Where the coordinates came from, once, at the end. It is a formal term
    // about this report rather than anything to do next, and it used to be
    // repeated beside every coordinate in every card.
    let mapping_terms = shared_mapping
        .map(|identity| {
            format!(
                "{}{}{}{}",
                catalog.text(
                    "Framework references come from mapping catalog ",
                    "框架參考來自對照目錄 ",
                ),
                html_escape(&identity),
                catalog.text(".", "。"),
                catalog.text(" ", ""),
            )
        })
        .unwrap_or_default();
    // Said once, and only where it is true. Every evidence summary this build
    // writes ended with it, so fifty-one records carried the same statement
    // about how the product keeps target text.
    let untrusted_evidence_terms = match evidence_is_untrusted_text {
        true => format!(
            "{}{}",
            catalog.text(
                "Target text quoted in an evidence summary is retained as untrusted input and is not interpreted by this report.",
                "證據摘要引用的目標文字，是以不受信任的輸入形式保留，本報告不會加以解讀。",
            ),
            catalog.text(" ", ""),
        ),
        false => String::new(),
    };
    document.push_str(&format!(
        concat!(
            "<footer><h2>{}</h2><p>{}</p><p>{}{}{}{}{}{}{}{}{}{}</p></footer>",
            "</body></html>"
        ),
        catalog.text("Report terms", "報告條款"),
        catalog.text(
            "Framework references are informational navigation. AIDEFEND references are an independent, unofficial mapping unless the framework owner states otherwise. This report is not an audit, certification, compliance decision, security guarantee, or automatic remediation.",
            "框架參照只供資訊導航。除非框架擁有者另有聲明，AIDEFEND 參照屬於獨立、非官方的對照。本報告不是稽核、認證、合規判定、資安保證或自動修復。",
        ),
        mapping_terms,
        // This one line is the report's own sentence rather than a label and
        // its value, and it was punctuated as English in both languages: the
        // Chinese footer ended a clause with "." and joined the next with a
        // space, beside a sibling clause already set with "：" and "；".
        catalog.text("Redaction profile: ", "遮蔽設定："),
        html_escape(catalog.text(
            match options.redaction {
                crate::export::RedactionProfile::None => "none",
                crate::export::RedactionProfile::Standard => "standard",
            },
            match options.redaction {
                crate::export::RedactionProfile::None => "無",
                crate::export::RedactionProfile::Standard => "標準",
            },
        )),
        catalog.text(". ", "。"),
        catalog.text(
            "Integrity: unsigned HTML with SHA-256 retained in the local case.",
            "完整性：未簽章的 HTML；SHA-256 保留在本機案件中。",
        ),
        catalog.text(" ", ""),
        if attachments.is_empty() {
            catalog.text(
                "Raw evidence is excluded. No scripts, forms, remote resources, scanner messages, or executable remediation are included.",
                "不包含原始證據，也不包含指令碼、表單、遠端資源、掃描工具訊息或可執行的修復動作。",
            )
        } else {
            catalog.text(
                "Original scanner files are embedded as downloadable ZIP attachments. They may contain sensitive data and active HTML; this report does not execute them. Attachments remain in the saved HTML only and are not embedded in printed or PDF copies.",
                "掃描工具原始檔以可下載的 ZIP 附件內嵌，可能含敏感資料及互動式 HTML；本報告不會執行附件。附件只保留於儲存的 HTML，不會嵌入列印或另存的 PDF。",
            )
        },
        catalog.text(" ", ""),
        untrusted_evidence_terms,
        // The inventory prints regardless of its disclosure state; the
        // technical record prints only if a reader opened it.
        if report.source_audits.is_empty() { catalog.text(
            "Framework sources and attribution are shown in the framework section. The complete asset inventory is collapsed on screen and printed in full. Per-finding evidence, source rules, framework references and the run's task records stay collapsed technical detail; a printed copy carries those only where a reader opened them before printing.",
            "框架來源與出處聲明顯示於框架區塊。完整資產清單在畫面上收合，列印時會完整輸出。各問題的證據、來源規則、框架參考與本輪工作紀錄仍屬收合的技術細節；列印出來的版本只會包含列印前已展開的部分。",
        ) } else { catalog.text(
            "The complete asset inventory is collapsed on screen and printed in full. Per-finding evidence, source rules, framework references and the run's task records stay collapsed technical detail; a printed copy carries those only where a reader opened them before printing.",
            "完整資產清單在畫面上收合，列印時會完整輸出。各問題的證據、來源規則、框架參考與本輪工作紀錄仍屬收合的技術細節；列印出來的版本只會包含列印前已展開的部分。",
        ) },
    ));
    if catalog.locale == crate::export::ReportLocale::ZhHant {
        document = localize_report_markers(
            &document,
            std::slice::from_ref(&report),
            options.redaction == crate::export::RedactionProfile::Standard,
        )?;
    }
    Ok(document.into_bytes())
}

/// One target identity, escaped, with a break opportunity at each separator a
/// reader expects a URL to break on.
///
/// The asset column is the narrowest place a full URL is printed, and
/// `overflow-wrap:anywhere` was breaking it mid-label -- "https://portal.
/// example.t" over "est:443". A seam there is ambiguous: a reader cannot tell
/// whether the name really contains what sits at the break. `<wbr>` offers the
/// separators as the places to break, and the overflow rule stays behind it for
/// a label that has no separator at all.
pub(crate) fn html_escape_breakable_identity(value: &str) -> String {
    const SEPARATORS: [char; 8] = ['/', '.', ':', '@', '?', '&', '=', '_'];
    let mut escaped = String::with_capacity(value.len());
    let mut segment_start = 0usize;
    for (index, character) in value.char_indices() {
        if SEPARATORS.contains(&character) {
            let end = index + character.len_utf8();
            escaped.push_str(&html_escape(&value[segment_start..end]));
            escaped.push_str("<wbr>");
            segment_start = end;
        }
    }
    escaped.push_str(&html_escape(&value[segment_start..]));
    escaped
}

pub(crate) fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

pub(crate) fn provider_native_narrative(finding: &BeginnerFinding) -> bool {
    finding.source_audit
        && !finding
            .evidence_references
            .iter()
            .any(|r| r.redacted == Some(true))
}

/// Protect retained provider strings from the product-marker localization pass.
/// Only strings containing marker syntax need protection; no machine identities
/// or provider text are translated, even under the explicit unredacted profile.
pub(crate) fn localize_report_markers(
    document: &str,
    reports: &[BeginnerMasterReport],
    standard: bool,
) -> AppResult<String> {
    if reports.iter().all(|r| r.source_audits.is_empty()) {
        return Ok(localize_redaction_markers(document));
    }
    fn collect(value: &serde_json::Value, key: &str, standard: bool, strings: &mut Vec<String>) {
        match value {
            serde_json::Value::String(s) if s.contains('[') && (!standard || key == "title") => {
                strings.push(html_escape(s));
                // The combined report also carries JSON-escaped source records.
                if let Ok(encoded) = serde_json::to_string(s) {
                    strings.push(html_escape(&encoded[1..encoded.len() - 1]));
                }
            }
            serde_json::Value::Array(v) => {
                for v in v {
                    collect(v, key, standard, strings);
                }
            }
            serde_json::Value::Object(v) => {
                for (k, v) in v {
                    collect(v, k, standard, strings);
                }
            }
            _ => {}
        }
    }
    let mut strings = Vec::new();
    for report in reports {
        collect(
            &serde_json::to_value(&report.source_audits)?,
            "",
            standard,
            &mut strings,
        );
    }
    strings.sort_by_key(|s| std::cmp::Reverse(s.len()));
    strings.dedup();
    // HTML entities protect brackets without inserting a sentinel into native text.
    let mut protected = document.to_owned();
    for s in strings {
        protected = protected.replace(&s, &s.replace('[', "&#91;"));
    }
    Ok(localize_redaction_markers(&protected)
        .replace(
            "[withheld in the standard profile]",
            "[已在標準設定檔中隱藏]",
        )
        .replace(
            "[withheld provider text in the standard profile]",
            "[已在標準設定檔中隱藏提供者文字]",
        )
        .replace("&#91;", "["))
}

/// Provider values are always inert text, including object keys and URL-looking values.
fn html_provider_value(value: &serde_json::Value, catalog: HtmlReportCatalog) -> String {
    use serde_json::Value;
    match value {
        Value::String(text) => format!("<div class=\"provider-text\">{}</div>", html_escape(text)),
        Value::Array(items) => format!(
            "<ul>{}</ul>",
            items
                .iter()
                .map(|v| format!("<li>{}</li>", html_provider_value(v, catalog)))
                .collect::<String>()
        ),
        Value::Object(fields) => format!(
            "<dl>{}</dl>",
            fields
                .iter()
                .map(|(key, value)| format!(
                    "<dt>{}</dt><dd>{}</dd>",
                    html_escape(key),
                    if matches!(key.as_str(), "fixed_code" | "payloads" | "instructions") {
                        format!(
                            "<div class=\"provider-code\">{}</div>",
                            html_provider_value(value, catalog)
                        )
                    } else {
                        html_provider_value(value, catalog)
                    }
                ))
                .collect::<String>()
        ),
        Value::Null => html_escape(catalog.text("not recorded", "未記錄")),
        other => html_escape(&other.to_string()),
    }
}
pub(crate) fn html_source_audits(
    report: &BeginnerMasterReport,
    catalog: HtmlReportCatalog,
) -> String {
    let mut html = String::new();
    if !report.source_audits.is_empty() {
        html.push_str("<style>.source-audit pre,.source-audit .provider-text{white-space:pre-wrap;overflow-wrap:anywhere;unicode-bidi:plaintext}.source-audit .provider-code{font-family:monospace}</style>");
    }
    for audit in &report.source_audits {
        html.push_str(&format!(
            "<section class=\"source-audit report-card\"><h2>{}</h2><p>{}</p>",
            catalog.text("Source audit", "原始碼稽核"),
            catalog.text("Cloudflare source audit", "Cloudflare 原始碼稽核")
        ));
        let m = audit.unresolved_candidates.len();
        if audit.outcome.state == "incomplete" {
            let n = audit.coverage_gaps.iter().filter(|g| g.remaining()).count();
            let copy = match (catalog.locale, n, m) {
                (ReportLocale::En, 0, 0) => "Source audit incomplete.".into(),
                (ReportLocale::ZhHant, 0, 0) => "原始碼稽核未完成。".into(),
                (ReportLocale::En, 0, 1) => {
                    "Source audit incomplete: 1 candidate finding remains unresolved.".into()
                }
                (ReportLocale::En, 1, _) => {
                    "Source audit incomplete: 1 unit remains. Continue with the listed paths."
                        .into()
                }
                (ReportLocale::En, 0, _) => {
                    format!("Source audit incomplete: {m} candidate findings remain unresolved.")
                }
                (ReportLocale::ZhHant, 0, _) => {
                    format!("原始碼稽核未完成：尚有 {m} 個候選問題未解決。")
                }
                (ReportLocale::En, _, _) => format!(
                    "Source audit incomplete: {n} units remain. Continue with the listed paths."
                ),
                (ReportLocale::ZhHant, _, _) => {
                    format!("原始碼稽核未完成：尚有 {n} 個單元未完成。請從列出的路徑繼續。")
                }
            };
            html.push_str(&format!("<p>{}</p>", html_escape(&copy)));
            if let Some(reason) = &audit.outcome.incomplete_reason
                && reason != "[withheld provider text in the standard profile]"
            {
                html.push_str(&html_provider_value(&serde_json::json!(reason), catalog));
            }
        }
        if m > 0 {
            let copy = match catalog.locale {
                ReportLocale::En if m == 1 => "1 candidate finding remains unresolved.".into(),
                ReportLocale::En => format!("{m} candidate findings remain unresolved."),
                ReportLocale::ZhHant => format!("尚有 {m} 個候選問題未解決。"),
            };
            html.push_str(&format!("<p>{}</p>", html_escape(&copy)));
        }
        if audit.counts.get("confirmed") == Some(&0) {
            html.push_str(&format!(
                "<p>{}</p>",
                catalog.text(
                    "No confirmed findings in the recorded checks.",
                    "已記錄的檢查中未發現已確認問題。"
                )
            ));
        }
        if !audit.to_validate.is_empty() {
            html.push_str(&format!(
                "<h3>{}</h3>",
                catalog.text("To validate", "待驗證")
            ));
        }
        for record in &audit.to_validate {
            let native = &record.native_record;
            html.push_str(&format!(
                "<article><h4>{}</h4>",
                html_escape(native["title"].as_str().unwrap_or_default())
            ));
            let withheld = audit.withheld_text_fields > 0 || audit.withheld_code_fields > 0;
            html.push_str(&format!(
                "<h5>{}</h5>",
                catalog.text("Evidence locations", "證據位置")
            ));
            for location in native["evidence"].as_array().into_iter().flatten() {
                let file = location["file"].as_str().unwrap_or_default();
                let line = &location["line"];
                let description = location["description"].as_str().unwrap_or_default();
                let text = if withheld {
                    format!("{file}:{line}")
                } else {
                    format!("{file}:{line} — {description}")
                };
                html.push_str(&html_provider_value(&serde_json::json!(text), catalog));
            }
            if withheld {
                html.push_str(&format!(
                    "<p>{}</p>",
                    catalog.text(
                        "Details withheld in the standard profile.",
                        "詳細內容已在標準設定檔中隱藏。"
                    )
                ));
            } else {
                for (key, en, zh) in [
                    ("description", "Description", "說明"),
                    ("claimed_root_cause", "Claim", "待驗證主張"),
                    ("blockers", "Blockers", "阻礙"),
                ] {
                    html.push_str(&format!(
                        "<h5>{}</h5>{}",
                        catalog.text(en, zh),
                        html_provider_value(&native[key], catalog)
                    ));
                }
                html.push_str(&format!(
                    "<h5>{}</h5>",
                    catalog.text("Validation plan", "驗證計畫")
                ));
                for (key, en, zh) in [
                    ("local", "Local check", "本機檢查"),
                    ("deployment", "Deployment check", "部署環境檢查"),
                ] {
                    html.push_str(&format!(
                        "<h6>{}</h6>{}",
                        catalog.text(en, zh),
                        html_provider_value(&native["validation_plan"][key], catalog)
                    ));
                }
            }
            html.push_str("</article>");
        }
        if !audit.coverage_gaps.is_empty() {
            html.push_str(&format!(
                "<h3>{}</h3><ul>",
                catalog.text("What was not tested", "未測試項目")
            ));
            for gap in &audit.coverage_gaps {
                html.push_str(&format!(
                    "<li><div class=\"provider-text\">{}\n{}</div>",
                    html_escape(&gap.label),
                    match gap.status.as_str() {
                        "planned" => catalog.text("Not started", "尚未開始"),
                        "in_progress" => catalog.text("In progress", "進行中"),
                        "blocked" => catalog.text("Blocked", "受阻"),
                        "deferred" => catalog.text("Deferred", "已延後"),
                        "candidate" => catalog.text("Unresolved candidate", "候選問題未解決"),
                        "out_of_scope" => catalog.text("Outside the audit scope", "不在稽核範圍內"),
                        _ => catalog.text("Not tested", "未測試"),
                    }
                ));
                if gap.remaining() {
                    html.push_str(&format!(
                        "<p>{}</p><pre>{}</pre>",
                        catalog.text("Continue with these paths", "請從這些路徑繼續"),
                        html_escape(&gap.continuation_paths.join("\n"))
                    ));
                }
                html.push_str("</li>");
            }
            html.push_str("</ul>");
        }
        html.push_str(&format!(
            "<details class=\"technical\"><summary>{}</summary>",
            catalog.text("Source audit technical details", "原始碼稽核技術詳細資料")
        ));
        html.push_str(&format!(
            "<p>{}: {}</p>",
            catalog.text("Issued invocations", "已發出的呼叫次數"),
            audit.method.issued_invocations
        ));
        for (en, zh, value) in [
            ("Method", "方法", serde_json::json!(audit.method)),
            ("Outcome", "結果", serde_json::json!(audit.outcome)),
            (
                "To validate records",
                "待驗證紀錄",
                serde_json::json!(audit.to_validate),
            ),
            (
                "Unresolved candidate fingerprints",
                "未解決候選問題的指紋",
                serde_json::json!(audit.unresolved_candidates),
            ),
            (
                "Counts",
                "計數",
                serde_json::json!({"records":audit.counts,"coverage":audit.coverage_by_status}),
            ),
            (
                "Confirmed records",
                "已確認紀錄",
                serde_json::json!(audit.technical_detail.confirmed),
            ),
            (
                "Rejected records",
                "已排除紀錄",
                serde_json::json!(audit.technical_detail.rejected),
            ),
            (
                "Coverage and attempts",
                "涵蓋範圍與嘗試紀錄",
                audit.technical_detail.coverage_ledger.clone(),
            ),
            (
                "View and canonical lineage",
                "檢視與標準來源沿革",
                audit.technical_detail.lineage.clone(),
            ),
            (
                "Custody digests",
                "保管摘要",
                audit.technical_detail.custody_digests.clone(),
            ),
            (
                "Admission digest",
                "納入摘要",
                serde_json::json!(audit.technical_detail.admission_sha256),
            ),
            (
                "Copied originals and digests",
                "複製的原始檔與摘要",
                audit.technical_detail.originals.clone(),
            ),
        ] {
            html.push_str(&format!(
                "<h3>{}</h3>{}",
                catalog.text(en, zh),
                html_provider_value(&value, catalog)
            ));
        }
        if audit.withheld_code_fields > 0 {
            html.push_str(&format!(
                "<p>{}: {}</p>",
                catalog.text(
                    "Code fields withheld in the standard profile",
                    "標準設定檔中隱藏的程式碼欄位"
                ),
                audit.withheld_code_fields
            ));
        }
        if audit.withheld_text_fields > 0 {
            html.push_str(&format!(
                "<p>{}: {}</p>",
                catalog.text(
                    "Text fields withheld in the standard profile",
                    "標準設定檔中隱藏的文字欄位"
                ),
                audit.withheld_text_fields
            ));
        }
        html.push_str("</details></section>");
    }
    html
}

#[cfg(test)]
mod tests {
    use super::HtmlReportAttachment;
    use sha2::Digest;

    #[test]
    fn frozen_attachment_serialization_preserves_every_byte_in_base64() {
        let bytes = (0..=u8::MAX).collect::<Vec<_>>();
        let attachment = HtmlReportAttachment {
            engine_id: "fixture-engine".into(),
            engine_run_id: "fixture-task".into(),
            file_names: vec!["original/report.json".into()],
            sha256: hex::encode(sha2::Sha256::digest(&bytes)),
            bytes,
        };
        let encoded = serde_json::to_value(&attachment).unwrap();
        assert!(encoded["bytes"].is_string());
        let restored: HtmlReportAttachment = serde_json::from_value(encoded).unwrap();
        assert_eq!(restored, attachment);
    }

    #[test]
    fn invalid_attachment_base64_is_rejected() {
        let encoded = serde_json::json!({
            "engine_id": "fixture-engine",
            "engine_run_id": "fixture-task",
            "file_names": [],
            "bytes": "not base64!",
            "sha256": "invalid",
        });
        assert!(serde_json::from_value::<HtmlReportAttachment>(encoded).is_err());
    }
}
