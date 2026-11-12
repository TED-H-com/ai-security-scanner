//! Frozen report inputs and exact original documents. Reading or replaying a
//! snapshot never opens a case database, starts a scanner, or loads executable
//! content from the snapshot. This is a report snapshot, not a case backup.

use crate::beginner_report::BEGINNER_MASTER_REPORT_SCHEMA_VERSION;
use crate::case_service::write_new_private_file;
use crate::domain::{
    AssessmentCase, CaseExport, ReportSnapshotReference, RunReportSnapshot, ScanRun,
    SelectedRunReportExport, SelectedRunReportFormat, new_id,
};
use crate::error::{AppError, AppResult};
use crate::export::ExportOptions;
use crate::report_renderer::{self, HtmlReportAttachment};
use crate::selected_run_report::{
    SELECTED_RUN_REPORT_SCHEMA, SelectedRunReport, preview_selected_run_report,
    render_selected_run_report,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};

impl ReportSnapshotReference {
    pub(crate) fn validate(&self, case_id: &str) -> AppResult<()> {
        crate::export::validate_portable_archive_path(Path::new(&self.relative_path))?;
        if self.relative_path != format!("{case_id}/report-snapshots/{}.json", self.snapshot_id)
            || self.relative_path.split('/').count() != 3
            || self.source_case_revision < 0
            || self.sha256.len() != 64
            || !self.sha256.bytes().all(|c| c.is_ascii_hexdigit())
            || self.byte_length == 0
            || self.byte_length > MAX_REPORT_SNAPSHOT_BYTES
        {
            return Err(invalid("invalid retained report snapshot reference"));
        }
        Ok(())
    }

    pub(crate) fn read(&self, artifact_root: &Path, export: &CaseExport) -> AppResult<Vec<u8>> {
        let bytes = self.read_for_run(artifact_root, &export.case_id, &export.run_id)?;
        self.verify_export(&bytes, export)?;
        Ok(bytes)
    }

    fn read_for_run(
        &self,
        artifact_root: &Path,
        case_id: &str,
        run_id: &str,
    ) -> AppResult<Vec<u8>> {
        let bytes = self.read_bytes(artifact_root, case_id)?;
        self.verify_run(&bytes, case_id, run_id)?;
        Ok(bytes)
    }

    fn read_bytes(&self, artifact_root: &Path, case_id: &str) -> AppResult<Vec<u8>> {
        self.validate(case_id)?;
        // Every component below the selected artifact root must be real. Do not
        // use ArtifactStore::open here: archive reads must not create directories
        // or change permissions in the source workspace.
        let mut path = artifact_root.to_path_buf();
        for component in std::iter::once(None).chain(self.relative_path.split('/').map(Some)) {
            if let Some(component) = component {
                path.push(component);
            }
            let metadata = std::fs::symlink_metadata(&path)?;
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err(invalid("retained snapshot path contains a reparse point"));
                }
            }
            if metadata.file_type().is_symlink() {
                return Err(invalid("retained snapshot path contains a symlink"));
            }
        }
        read_bounded_snapshot(&path)
    }

    pub(crate) fn verify_export(&self, bytes: &[u8], export: &CaseExport) -> AppResult<()> {
        let inspection = self
            .verify_run(bytes, &export.case_id, &export.run_id)?
            .verify()?;
        let document_hash = match export.format.as_deref() {
            Some("html") => &inspection.original_html_sha256,
            Some("json") => &inspection.original_json_sha256,
            _ => {
                return Err(invalid(
                    "retained report snapshot requires an HTML or JSON export",
                ));
            }
        };
        if inspection.redaction != export.redaction_profile || document_hash != &export.sha256 {
            return Err(invalid(
                "retained report snapshot does not match its export",
            ));
        }
        Ok(())
    }

    fn verify_run(&self, bytes: &[u8], case_id: &str, run_id: &str) -> AppResult<ReportSnapshot> {
        let snapshot = self.verify_identity(bytes, case_id)?;
        if snapshot.run_id != run_id || !snapshot.selected_run_ids.is_empty() {
            return Err(invalid("retained report snapshot does not match its run"));
        }
        Ok(snapshot)
    }

    pub(crate) fn read_combined(
        &self,
        artifact_root: &Path,
        export: &SelectedRunReportExport,
    ) -> AppResult<Vec<u8>> {
        let bytes = self.read_bytes(artifact_root, &export.case_id)?;
        self.verify_combined_export(&bytes, export)?;
        Ok(bytes)
    }

    pub(crate) fn verify_combined_export(
        &self,
        bytes: &[u8],
        export: &SelectedRunReportExport,
    ) -> AppResult<()> {
        let snapshot = self.verify_identity(bytes, &export.case_id)?;
        let hash = match export.format {
            SelectedRunReportFormat::Html => &snapshot.original_html.sha256,
            SelectedRunReportFormat::Json => &snapshot.original_json.sha256,
        };
        if !snapshot.run_id.is_empty()
            || snapshot.selected_run_ids != export.selected_run_ids
            || snapshot.settings.redaction != export.redaction_profile
            || hash != &export.sha256
            || snapshot.combined_original_files()? != export.original_files
            || snapshot.created_at != export.created_at
        {
            return Err(invalid(
                "retained combined snapshot does not match its export",
            ));
        }
        Ok(())
    }

    fn verify_identity(&self, bytes: &[u8], case_id: &str) -> AppResult<ReportSnapshot> {
        self.validate(case_id)?;
        if bytes.len() as u64 != self.byte_length || digest(bytes) != self.sha256 {
            return Err(invalid(
                "retained report snapshot length or digest does not match",
            ));
        }
        let snapshot: ReportSnapshot = serde_json::from_slice(bytes)?;
        let inspection = snapshot.verify()?;
        if inspection.snapshot_id != self.snapshot_id
            || inspection.case_id != case_id
            || inspection.source_case_revision != self.source_case_revision
        {
            return Err(invalid("retained report snapshot does not match its run"));
        }
        Ok(snapshot)
    }
}

impl RunReportSnapshot {
    pub(crate) fn read(&self, artifact_root: &Path, case_id: &str) -> AppResult<Vec<u8>> {
        let bytes = self
            .snapshot
            .read_for_run(artifact_root, case_id, &self.run_id)?;
        self.verify(&bytes, case_id)?;
        Ok(bytes)
    }

    pub(crate) fn verify(&self, bytes: &[u8], case_id: &str) -> AppResult<()> {
        let snapshot = self.snapshot.verify_run(bytes, case_id, &self.run_id)?;
        // Hash the frozen JSON value rather than reserializing today's domain:
        // future optional fields must not invalidate historical archive bytes.
        let inputs: serde_json::Value = serde_json::from_slice(&snapshot.inputs.bytes)?;
        let run = inputs
            .pointer("/case/scan_runs")
            .and_then(|runs| runs.as_array())
            .and_then(|runs| {
                runs.iter().find(|run| {
                    run.get("id").and_then(|id| id.as_str()) == Some(self.run_id.as_str())
                })
            })
            .ok_or_else(|| invalid("terminal snapshot run is missing"))?;
        if frozen_run_fingerprint(run.clone())? != self.run_sha256 {
            return Err(invalid(
                "terminal snapshot does not match its saved outcome",
            ));
        }
        Ok(())
    }
}

pub(crate) fn run_fingerprint(run: &ScanRun) -> AppResult<String> {
    frozen_run_fingerprint(serde_json::to_value(run)?)
}

fn frozen_run_fingerprint(mut run: serde_json::Value) -> AppResult<String> {
    // Desktop dependencies may enable serde_json's preserve_order feature.
    // Keep references portable across feature sets and JSON member order.
    run.sort_all_objects();
    Ok(digest(&serde_json::to_vec(&run)?))
}

/// A completed worker can still have cleanup or captured evidence to settle.
/// Those states remain Progress and never create a formal terminal report.
pub fn terminal_snapshot_ready(run: &ScanRun) -> bool {
    use crate::orchestrator::{ExecutionCheckpoint, ExecutionStage};
    crate::scan_coordinator::durable_run_has_final_outcome(run)
        && !crate::scan_coordinator::durable_run_needs_background_cleanup(run)
        && run.engine_runs.iter().all(|task| {
            if task.scan_run_id != run.id
                || crate::scan_coordinator::task_requires_captured_recovery(task)
            {
                return false;
            }
            match task.resume_token.as_deref() {
                Some(token) => {
                    ExecutionCheckpoint::from_resume_token(token).is_ok_and(|checkpoint| {
                        checkpoint.case_id == run.case_id
                            && checkpoint.scan_run_id == run.id
                            && checkpoint.engine_run_id == task.id
                            && checkpoint.engine_id == task.engine_id
                            && checkpoint.cleanup_completed
                            && !matches!(
                                checkpoint.stage,
                                ExecutionStage::CleanupPending
                                    | ExecutionStage::Running
                                    | ExecutionStage::CapturingArtifacts
                            )
                    })
                }
                None => {
                    task.started_at.is_none()
                        || task.status == crate::domain::EngineRunStatus::NotExecuted
                        || task.task_kind != crate::domain::EngineTaskKind::CatalogEngine
                        || task.cleanup_removed == Some(true)
                }
            }
        })
}

/// Read-only lookup; legacy runs without a retained report remain absent.
pub fn current_run_snapshot<'a>(
    case: &'a AssessmentCase,
    run_id: &str,
) -> AppResult<Option<&'a RunReportSnapshot>> {
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .ok_or_else(|| invalid("report run not found"))?;
    let hash = run_fingerprint(run)?;
    Ok(case
        .run_report_snapshots
        .iter()
        .rev()
        .find(|record| record.run_id == run_id && record.run_sha256 == hash))
}

pub const REPORT_SNAPSHOT_SCHEMA: &str = "ai-security-scanner.report-snapshot/v1";
pub const COMBINED_REPORT_SNAPSHOT_SCHEMA: &str = "ai-security-scanner.report-snapshot/v2";
pub const MAX_REPORT_SNAPSHOT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ATTACHMENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_ATTACHMENT_FILES: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RendererIdentity {
    pub recipe: String,
    pub source_sha256: String,
    pub product_version: String,
}

impl RendererIdentity {
    pub fn current() -> Self {
        Self {
            recipe: report_renderer::RENDERER_RECIPE_VERSION.into(),
            source_sha256: env!("AI_SECURITY_SCANNER_REPORT_CORE_SHA256").into(),
            product_version: crate::product_version::current().into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenInputs {
    // Includes the grouping, framework, comparison/baseline and legacy
    // context the existing renderer reads beyond BeginnerMasterReport.
    case: AssessmentCase,
    options: ExportOptions,
    attachments: Vec<HtmlReportAttachment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    combined_report: Option<SelectedRunReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    combined_attachments: Vec<crate::combined_attachments::CombinedAttachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenSettings {
    locale: String,
    redaction: String,
    include_raw_artifacts: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalDocument {
    sha256: String,
    byte_length: u64,
    #[serde(with = "base64_bytes")]
    bytes: Vec<u8>,
}

impl OriginalDocument {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            sha256: digest(&bytes),
            byte_length: bytes.len() as u64,
            bytes,
        }
    }

    fn verify(&self) -> AppResult<()> {
        if self.byte_length != self.bytes.len() as u64 || self.sha256 != digest(&self.bytes) {
            return Err(invalid("original report length or digest does not match"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportSnapshot {
    schema_version: String,
    snapshot_id: String,
    created_at: DateTime<Utc>,
    case_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    run_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    selected_run_ids: Vec<String>,
    source_case_revision: i64,
    report_schema_version: String,
    renderer: RendererIdentity,
    settings: FrozenSettings,
    attachment_count: usize,
    inputs: OriginalDocument,
    original_html: OriginalDocument,
    original_json: OriginalDocument,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportDocumentFormat {
    Html,
    Json,
}

#[derive(Debug, Serialize)]
pub struct ReportSnapshotInspection {
    pub schema_version: String,
    pub snapshot_id: String,
    pub case_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub run_id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub selected_run_ids: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub source_case_revision: i64,
    pub renderer: RendererIdentity,
    pub integrity_valid: bool,
    pub replay_available: bool,
    pub replay_unavailable_reason: Option<&'static str>,
    pub contains_sensitive_context: bool,
    pub case_restore_available: bool,
    pub locale: String,
    pub redaction: String,
    pub attachment_count: usize,
    pub original_html_sha256: String,
    pub original_json_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct ReportSnapshotReceipt {
    pub schema_version: &'static str,
    pub snapshot_id: String,
    pub operation: &'static str,
    pub path: PathBuf,
    pub sha256: String,
    pub byte_length: u64,
}

impl ReportSnapshot {
    /// Capture the complete render context, including unredacted local case
    /// data. Callers must keep this private and obtain an explicit choice when
    /// writing it to a caller-selected export destination.
    pub fn capture(
        case: &AssessmentCase,
        run_id: &str,
        options: ExportOptions,
        artifact_root: &Path,
    ) -> AppResult<Self> {
        // Production renderers enforce terminal eligibility before any saved
        // document can be mistaken for a formal report.
        crate::case_service::terminal_export_run(case, run_id)?;
        let attachments =
            crate::report_attachments::build_attachments(case, run_id, &options, artifact_root)?
                .into_iter()
                .map(HtmlReportAttachment::from)
                .collect::<Vec<_>>();
        Self::capture_with_attachments(case, run_id, options, attachments)
    }

    pub(crate) fn capture_with_attachments(
        case: &AssessmentCase,
        run_id: &str,
        options: ExportOptions,
        attachments: Vec<HtmlReportAttachment>,
    ) -> AppResult<Self> {
        let json = report_renderer::render_canonical_json(case, run_id, &options)?;
        let html = report_renderer::render_html(case, run_id, &options, &attachments)?;
        let inputs = FrozenInputs {
            case: case.clone(),
            options,
            attachments,
            combined_report: None,
            combined_attachments: Vec::new(),
        };
        let snapshot = Self {
            schema_version: REPORT_SNAPSHOT_SCHEMA.into(),
            snapshot_id: new_id(),
            created_at: Utc::now(),
            case_id: case.id.clone(),
            run_id: run_id.into(),
            selected_run_ids: Vec::new(),
            source_case_revision: case.storage_revision,
            report_schema_version: BEGINNER_MASTER_REPORT_SCHEMA_VERSION.into(),
            renderer: RendererIdentity::current(),
            settings: FrozenSettings {
                locale: inputs.options.locale.as_str().into(),
                redaction: inputs.options.redaction.as_str().into(),
                include_raw_artifacts: inputs.options.include_raw_artifacts,
            },
            attachment_count: inputs.attachments.len(),
            inputs: OriginalDocument::new(serde_json::to_vec(&inputs)?),
            original_html: OriginalDocument::new(html),
            original_json: OriginalDocument::new(json),
        };
        snapshot.verify()?;
        Ok(snapshot)
    }

    /// Freeze the complete selected-run projection, including its one generated
    /// time. Replay never recomputes this historical composition from current data.
    pub fn capture_combined(
        case: &AssessmentCase,
        run_ids: &[String],
        options: ExportOptions,
    ) -> AppResult<Self> {
        if options.include_raw_artifacts {
            return Err(invalid("combined original files require an artifact root"));
        }
        Self::capture_combined_with_originals(case, run_ids, options, Path::new(""), None)
    }

    pub fn capture_combined_with_originals(
        case: &AssessmentCase,
        run_ids: &[String],
        options: ExportOptions,
        artifact_root: &Path,
        archive_file_name: Option<&str>,
    ) -> AppResult<Self> {
        let preview_options = ExportOptions {
            include_raw_artifacts: false,
            ..options.clone()
        };
        let mut report = preview_selected_run_report(case, run_ids, &preview_options)?;
        let mut combined_attachments = Vec::new();
        if options.include_raw_artifacts {
            let (attachments, summary) =
                crate::combined_attachments::prepare(case, run_ids, &options, artifact_root)?;
            combined_attachments = attachments;
            report.original_files = Some(summary);
        }
        let mut html =
            crate::combined_attachments::render(&report, &options, &combined_attachments)?;
        let mut json = serde_json::to_vec_pretty(&report)?;
        if !combined_attachments.is_empty()
            && crate::combined_attachments::exceeds_document_budget(&html, &json)
        {
            crate::combined_attachments::omit(
                report.original_files.as_mut().expect("selected originals"),
                "combined_document_limit",
            );
            combined_attachments.clear();
        }
        if let Some(summary) = &mut report.original_files
            && summary.omitted_files > 0
        {
            let name = archive_file_name.ok_or_else(|| invalid("original files exceed combined report limits; export combine with private archive acknowledgement to retain the originals"))?;
            crate::export::validate_portable_archive_path(Path::new(name))?;
            if name.contains('/') || name.contains('\\') {
                return Err(invalid("archive filename must be a single component"));
            }
            summary.archive_file_name = Some(name.into());
            html = crate::combined_attachments::render(&report, &options, &combined_attachments)?;
            json = serde_json::to_vec_pretty(&report)?;
        }
        if crate::combined_attachments::exceeds_document_budget(&html, &json) {
            return Err(invalid(
                "The combined report exceeds 64 MiB; select fewer source reports.",
            ));
        }
        let created_at = report.generated_at;
        let inputs = FrozenInputs {
            case: case.clone(),
            options,
            attachments: Vec::new(),
            combined_report: Some(report),
            combined_attachments,
        };
        let snapshot = Self {
            schema_version: COMBINED_REPORT_SNAPSHOT_SCHEMA.into(),
            snapshot_id: new_id(),
            created_at,
            case_id: case.id.clone(),
            run_id: String::new(),
            selected_run_ids: run_ids.to_vec(),
            source_case_revision: case.storage_revision,
            report_schema_version: SELECTED_RUN_REPORT_SCHEMA.into(),
            renderer: RendererIdentity::current(),
            settings: FrozenSettings {
                locale: inputs.options.locale.as_str().into(),
                redaction: inputs.options.redaction.as_str().into(),
                include_raw_artifacts: inputs.options.include_raw_artifacts,
            },
            attachment_count: inputs.combined_attachments.len(),
            inputs: OriginalDocument::new(serde_json::to_vec(&inputs)?),
            original_html: OriginalDocument::new(html),
            original_json: OriginalDocument::new(json),
        };
        snapshot.verify()?;
        Ok(snapshot)
    }

    pub(crate) fn save_managed(&self, artifact_root: &Path) -> AppResult<ReportSnapshotReference> {
        let store = crate::artifact_store::ArtifactStore::open(artifact_root)?;
        let directory = store.prepare_report_snapshot_directory(&self.case_id)?;
        let directory = crate::internal_paths::canonicalize(directory)?;
        let receipt = self.save(&directory.join(format!("{}.json", self.snapshot_id)))?;
        Ok(ReportSnapshotReference {
            snapshot_id: self.snapshot_id.clone(),
            source_case_revision: self.source_case_revision,
            relative_path: format!(
                "{}/report-snapshots/{}.json",
                self.case_id, self.snapshot_id
            ),
            sha256: receipt.sha256,
            byte_length: receipt.byte_length,
        })
    }

    pub(crate) fn combined_original_files(
        &self,
    ) -> AppResult<Option<crate::domain::CombinedOriginalFiles>> {
        let projection: serde_json::Value = serde_json::from_slice(&self.original_json.bytes)?;
        projection
            .get("original_files")
            .map(|value| serde_json::from_value(value.clone()).map_err(Into::into))
            .transpose()
    }

    pub(crate) fn document_bytes(&self, format: ReportDocumentFormat) -> &[u8] {
        &self.document(format).bytes
    }

    /// Integrity is checked against saved hashes. It does not authenticate the
    /// producer, establish scan authorization, or certify finding correctness.
    pub fn verify(&self) -> AppResult<ReportSnapshotInspection> {
        let combined = match self.schema_version.as_str() {
            REPORT_SNAPSHOT_SCHEMA
                if !self.run_id.is_empty() && self.selected_run_ids.is_empty() =>
            {
                false
            }
            COMBINED_REPORT_SNAPSHOT_SCHEMA if self.run_id.is_empty() => {
                validate_combined_run_ids(&self.selected_run_ids)?;
                true
            }
            _ => {
                return Err(invalid(
                    "unsupported or ambiguous report snapshot selection",
                ));
            }
        };
        if self.case_id.is_empty() || self.snapshot_id.is_empty() || self.source_case_revision < 0 {
            return Err(invalid("snapshot case/run identity is inconsistent"));
        }
        if (combined && self.report_schema_version == BEGINNER_MASTER_REPORT_SCHEMA_VERSION)
            || (!combined && self.report_schema_version == SELECTED_RUN_REPORT_SCHEMA)
        {
            return Err(invalid(
                "report schema does not match the snapshot selection",
            ));
        }
        // Hash the original bytes, not a deserialized current-domain value.
        // Future enum variants/defaulted fields must not prevent retrieval of
        // exact original documents by a core without that renderer.
        self.inputs.verify()?;
        self.original_html.verify()?;
        self.original_json.verify()?;
        if self.report_schema_version == BEGINNER_MASTER_REPORT_SCHEMA_VERSION {
            let projection: serde_json::Value = serde_json::from_slice(&self.original_json.bytes)?;
            if projection.get("schema_version").and_then(|v| v.as_str())
                != Some(self.report_schema_version.as_str())
                || projection.get("selected_run_id").and_then(|v| v.as_str())
                    != Some(self.run_id.as_str())
                || projection
                    .pointer("/report/case_id")
                    .and_then(|v| v.as_str())
                    != Some(self.case_id.as_str())
            {
                return Err(invalid(
                    "saved report projection belongs to a different case or run",
                ));
            }
        }
        if combined && self.report_schema_version == SELECTED_RUN_REPORT_SCHEMA {
            let projection: serde_json::Value = serde_json::from_slice(&self.original_json.bytes)?;
            if projection.get("schema_version").and_then(|v| v.as_str())
                != Some(SELECTED_RUN_REPORT_SCHEMA)
                || projection.get("case_id").and_then(|v| v.as_str()) != Some(self.case_id.as_str())
                || projection.get("selected_run_ids")
                    != Some(&serde_json::to_value(&self.selected_run_ids)?)
            {
                return Err(invalid(
                    "saved combined projection does not match its ordered sources",
                ));
            }
        }
        // A frozen case this build cannot report on keeps its original files
        // retrievable; only replay through the current renderer is unavailable.
        let replay_available = self.renderer == RendererIdentity::current()
            && self.report_schema_version
                == if combined {
                    SELECTED_RUN_REPORT_SCHEMA
                } else {
                    BEGINNER_MASTER_REPORT_SCHEMA_VERSION
                }
            && serde_json::from_slice::<serde_json::Value>(&self.inputs.bytes).is_ok_and(
                |inputs| {
                    crate::agent_audit_admission::check_report_document(&inputs["case"]).is_ok()
                },
            );
        if replay_available {
            let inputs = self.decode_inputs()?;
            self.verify_attachments(&inputs)?;
        }
        Ok(ReportSnapshotInspection {
            schema_version: self.schema_version.clone(),
            snapshot_id: self.snapshot_id.clone(),
            case_id: self.case_id.clone(),
            run_id: self.run_id.clone(),
            selected_run_ids: self.selected_run_ids.clone(),
            created_at: self.created_at,
            source_case_revision: self.source_case_revision,
            renderer: self.renderer.clone(),
            integrity_valid: true,
            replay_available,
            replay_unavailable_reason: (!replay_available).then_some(
                "a compatible trusted renderer is not available; original files can be retrieved",
            ),
            contains_sensitive_context: true,
            case_restore_available: false,
            locale: self.settings.locale.clone(),
            redaction: self.settings.redaction.clone(),
            attachment_count: self.attachment_count,
            original_html_sha256: self.original_html.sha256.clone(),
            original_json_sha256: self.original_json.sha256.clone(),
        })
    }

    fn decode_inputs(&self) -> AppResult<FrozenInputs> {
        let inputs: FrozenInputs = serde_json::from_slice(&self.inputs.bytes)?;
        crate::agent_audit_admission::check_format(&inputs.case)?;
        if inputs.case.id != self.case_id
            || inputs.options.locale.as_str() != self.settings.locale
            || inputs.options.redaction.as_str() != self.settings.redaction
            || inputs.options.include_raw_artifacts != self.settings.include_raw_artifacts
            || inputs.attachments.len() + inputs.combined_attachments.len() != self.attachment_count
        {
            return Err(invalid("frozen report context does not match its envelope"));
        }
        match &inputs.combined_report {
            Some(report) if self.schema_version == COMBINED_REPORT_SNAPSHOT_SCHEMA => {
                if report.schema_version != SELECTED_RUN_REPORT_SCHEMA
                    || report.case_id != self.case_id
                    || report.selected_run_ids != self.selected_run_ids
                    || report.generated_at != self.created_at
                    || report.redaction_profile != self.settings.redaction
                    || report
                        .sources
                        .iter()
                        .map(|source| &source.run_id)
                        .collect::<Vec<_>>()
                        != self.selected_run_ids.iter().collect::<Vec<_>>()
                    || report.sources.iter().any(|source| {
                        !inputs
                            .case
                            .scan_runs
                            .iter()
                            .any(|run| run.id == source.run_id && run.case_id == self.case_id)
                    })
                {
                    return Err(invalid(
                        "frozen combined projection does not match its sources or settings",
                    ));
                }
            }
            None if self.schema_version == REPORT_SNAPSHOT_SCHEMA => {}
            _ => {
                return Err(invalid(
                    "frozen report selection does not match its envelope",
                ));
            }
        }
        Ok(inputs)
    }

    fn verify_attachments(&self, inputs: &FrozenInputs) -> AppResult<()> {
        if !inputs.options.include_raw_artifacts && !inputs.attachments.is_empty() {
            return Err(invalid("snapshot contains unselected original attachments"));
        }
        if let Some(report) = &inputs.combined_report {
            if !inputs.attachments.is_empty()
                || (!inputs.options.include_raw_artifacts
                    && (!inputs.combined_attachments.is_empty() || report.original_files.is_some()))
            {
                return Err(invalid(
                    "combined attachment selection does not match its inputs",
                ));
            }
            let mut seen = BTreeSet::new();
            let mut files = 0usize;
            let mut bytes = 0usize;
            for entry in &inputs.combined_attachments {
                if !self.selected_run_ids.contains(&entry.run_id)
                    || !seen.insert((&entry.run_id, &entry.attachment.engine_run_id))
                {
                    return Err(invalid("combined attachment source is invalid or repeated"));
                }
                self.verify_source_attachments(
                    inputs,
                    &entry.run_id,
                    std::slice::from_ref(&entry.attachment),
                )?;
                files = files
                    .checked_add(entry.attachment.file_names.len())
                    .ok_or_else(|| invalid("too many original files"))?;
                bytes = bytes
                    .checked_add(entry.attachment.bytes.len())
                    .ok_or_else(|| invalid("attachments too large"))?;
            }
            if files > MAX_ATTACHMENT_FILES
                || bytes > MAX_ATTACHMENT_BYTES + 8 * 1024 * 1024
                || report.original_files.as_ref().is_some_and(|summary| {
                    summary.included_files != files
                        || (summary.omitted_files > 0
                            && (!inputs.combined_attachments.is_empty()
                                || summary.archive_file_name.is_none()))
                })
            {
                return Err(invalid("combined attachment accounting is inconsistent"));
            }
            return Ok(());
        }
        if !inputs.combined_attachments.is_empty() {
            return Err(invalid(
                "single source snapshot contains combined attachments",
            ));
        }
        self.verify_source_attachments(inputs, &self.run_id, &inputs.attachments)
    }

    fn verify_source_attachments(
        &self,
        inputs: &FrozenInputs,
        run_id: &str,
        attachments: &[HtmlReportAttachment],
    ) -> AppResult<()> {
        let run = inputs
            .case
            .scan_runs
            .iter()
            .find(|run| run.id == run_id)
            .ok_or_else(|| invalid("snapshot run was not found"))?;
        let mut task_ids = BTreeSet::new();
        let mut files = 0usize;
        let mut bytes = 0usize;
        for attachment in attachments {
            let task = run.engine_runs.iter().find(|task| {
                task.id == attachment.engine_run_id && task.engine_id == attachment.engine_id
            });
            if task.is_none()
                || !task_ids.insert(&attachment.engine_run_id)
                || attachment.sha256 != digest(&attachment.bytes)
            {
                return Err(invalid(
                    "snapshot attachment task identity or digest does not match",
                ));
            }
            files = files
                .checked_add(attachment.file_names.len())
                .ok_or_else(|| invalid("snapshot attachment file count is too large"))?;
            bytes = bytes
                .checked_add(attachment.bytes.len())
                .ok_or_else(|| invalid("snapshot attachments are too large"))?;
            if files > MAX_ATTACHMENT_FILES || bytes > MAX_ATTACHMENT_BYTES + 8 * 1024 * 1024 {
                return Err(invalid("snapshot attachments exceed bounded report limits"));
            }
            for name in &attachment.file_names {
                crate::export::validate_portable_archive_path(Path::new(name))?;
            }
        }
        Ok(())
    }

    pub fn save(&self, destination: &Path) -> AppResult<ReportSnapshotReceipt> {
        self.verify()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() as u64 > MAX_REPORT_SNAPSHOT_BYTES {
            return Err(invalid("report snapshot exceeds the 256 MiB limit"));
        }
        self.publish(destination, &bytes, "snapshot")
    }

    pub fn load(path: &Path) -> AppResult<Self> {
        let bytes = read_bounded_snapshot(path)?;
        let snapshot: Self = serde_json::from_slice(&bytes)
            .map_err(|error| invalid(&format!("invalid report snapshot: {error}")))?;
        snapshot.verify()?;
        Ok(snapshot)
    }

    /// Retrieve the exact original bytes even when this core cannot replay the
    /// saved renderer. This never opens the document or executes its content.
    pub fn retrieve(
        &self,
        format: ReportDocumentFormat,
        destination: &Path,
    ) -> AppResult<ReportSnapshotReceipt> {
        self.verify()?;
        self.publish(destination, &self.document(format).bytes, "retrieve")
    }

    /// Replay only with the exact trusted renderer/input identity this build
    /// implements. A changed renderer cannot silently replace the old report.
    pub fn replay(
        &self,
        format: ReportDocumentFormat,
        destination: &Path,
    ) -> AppResult<ReportSnapshotReceipt> {
        if !self.verify()?.replay_available {
            return Err(AppError::NotAvailable(
                "compatible report renderer unavailable; use report retrieve for the original file"
                    .into(),
            ));
        }
        let inputs = self.decode_inputs()?;
        let bytes = if let Some(report) = &inputs.combined_report {
            match format {
                ReportDocumentFormat::Html => crate::combined_attachments::render(
                    report,
                    &inputs.options,
                    &inputs.combined_attachments,
                )?,
                ReportDocumentFormat::Json => render_selected_run_report(
                    report,
                    SelectedRunReportFormat::Json,
                    inputs.options.locale,
                )?,
            }
        } else {
            match format {
                ReportDocumentFormat::Html => report_renderer::render_html(
                    &inputs.case,
                    &self.run_id,
                    &inputs.options,
                    &inputs.attachments,
                )?,
                ReportDocumentFormat::Json => report_renderer::render_canonical_json(
                    &inputs.case,
                    &self.run_id,
                    &inputs.options,
                )?,
            }
        };
        if bytes != self.document(format).bytes {
            return Err(invalid(
                "replayed report differs from the saved document; no output was published",
            ));
        }
        self.publish(destination, &bytes, "replay")
    }

    fn document(&self, format: ReportDocumentFormat) -> &OriginalDocument {
        match format {
            ReportDocumentFormat::Html => &self.original_html,
            ReportDocumentFormat::Json => &self.original_json,
        }
    }

    fn publish(
        &self,
        destination: &Path,
        bytes: &[u8],
        operation: &'static str,
    ) -> AppResult<ReportSnapshotReceipt> {
        let path = write_new_private_file(destination, bytes)?;
        let path = crate::internal_paths::canonicalize(path)?;
        Ok(ReportSnapshotReceipt {
            schema_version: "ai-security-scanner.report-snapshot-receipt/v1",
            snapshot_id: self.snapshot_id.clone(),
            operation,
            path,
            sha256: digest(bytes),
            byte_length: bytes.len() as u64,
        })
    }
}

pub(crate) fn validate_combined_run_ids(run_ids: &[String]) -> AppResult<()> {
    if !(2..=16).contains(&run_ids.len())
        || run_ids.iter().any(String::is_empty)
        || run_ids.iter().collect::<BTreeSet<_>>().len() != run_ids.len()
    {
        return Err(invalid(
            "combined snapshots require two to sixteen unique ordered sources",
        ));
    }
    Ok(())
}

fn read_bounded_snapshot(path: &Path) -> AppResult<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > MAX_REPORT_SNAPSHOT_BYTES {
        return Err(invalid(
            "report snapshot must be a regular file of at most 256 MiB",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.nlink() != 1 {
            return Err(invalid("report snapshot must not have hard links"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if before.file_attributes() & 0x400 != 0 {
            return Err(invalid("report snapshot must not be a reparse point"));
        }
    }
    let mut bytes = Vec::with_capacity(before.len().min(1024 * 1024) as usize);
    (&mut file)
        .take(MAX_REPORT_SNAPSHOT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 > MAX_REPORT_SNAPSHOT_BYTES
        || before.len() != after.len()
        || after.len() != bytes.len() as u64
        || before.modified()? != after.modified()?
    {
        return Err(invalid(
            "report snapshot changed while being read or exceeds its size limit",
        ));
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn invalid(message: &str) -> AppError {
    AppError::InvalidRequest(message.into())
}

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        STANDARD.decode(value).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{EngineRunStatus, FindingStatus};
    use crate::export::{RedactionProfile, ReportLocale};
    use std::fs;

    fn capture() -> ReportSnapshot {
        let case = crate::demo::build_demo_case();
        ReportSnapshot::capture(
            &case,
            &case.scan_runs[0].id,
            ExportOptions::default(),
            Path::new("no-artifacts-needed"),
        )
        .unwrap()
    }

    #[test]
    fn frozen_report_replays_after_source_case_changes_in_both_locales() {
        let directory = tempfile::tempdir().unwrap();
        let mut case = crate::demo::build_demo_case();
        let run_id = case.scan_runs[0].id.clone();
        for locale in [ReportLocale::En, ReportLocale::ZhHant] {
            let snapshot = ReportSnapshot::capture(
                &case,
                &run_id,
                ExportOptions {
                    redaction: RedactionProfile::None,
                    locale,
                    ..Default::default()
                },
                Path::new("missing-runtime-and-artifacts"),
            )
            .unwrap();
            let saved = directory
                .path()
                .join(format!("{}.snapshot.json", locale.as_str()));
            snapshot.save(&saved).unwrap();
            case.title = "Later project title".into();
            case.findings[0].title = "Later finding text".into();
            case.findings[0].status = FindingStatus::VerifiedResolved;
            case.assets[0].name = "Later asset name".into();
            case.finding_groups.clear();
            case.comparisons.clear();
            let loaded = ReportSnapshot::load(&saved).unwrap();
            assert!(loaded.verify().unwrap().replay_available);
            for format in [ReportDocumentFormat::Html, ReportDocumentFormat::Json] {
                let destination = directory
                    .path()
                    .join(format!("{}-{format:?}", locale.as_str()));
                loaded.replay(format, &destination).unwrap();
                assert_eq!(
                    fs::read(&destination).unwrap(),
                    snapshot.document(format).bytes
                );
                assert!(
                    loaded.replay(format, &destination).is_err(),
                    "never overwrite"
                );
            }
        }
    }

    #[test]
    fn changed_renderer_is_retrieve_only_and_tampered_inputs_or_documents_fail() {
        let directory = tempfile::tempdir().unwrap();
        let mut snapshot = capture();
        snapshot.renderer.source_sha256 = "0".repeat(64);
        assert!(!snapshot.verify().unwrap().replay_available);
        let output = directory.path().join("report.html");
        assert!(
            snapshot
                .replay(ReportDocumentFormat::Html, &output)
                .is_err()
        );
        assert!(!output.exists());
        snapshot
            .retrieve(ReportDocumentFormat::Html, &output)
            .unwrap();
        assert_eq!(fs::read(output).unwrap(), snapshot.original_html.bytes);
        let mut corrupt = snapshot.clone();
        corrupt.inputs.bytes.push(b'!');
        assert!(corrupt.verify().is_err());
        let mut corrupt = snapshot.clone();
        corrupt.original_html.bytes.push(b'!');
        assert!(corrupt.verify().is_err());
        snapshot.schema_version.push_str("-future");
        assert!(snapshot.verify().is_err());
    }

    #[test]
    fn future_domain_and_report_shapes_do_not_prevent_original_retrieval() {
        let directory = tempfile::tempdir().unwrap();
        let mut snapshot = capture();
        snapshot.renderer.source_sha256 = "0".repeat(64);
        let mut inputs: serde_json::Value = serde_json::from_slice(&snapshot.inputs.bytes).unwrap();
        inputs["case"]["status"] = serde_json::json!("future-domain-state");
        inputs["new-render-context"] = serde_json::json!({"retained": true});
        snapshot.inputs = OriginalDocument::new(serde_json::to_vec(&inputs).unwrap());
        snapshot.report_schema_version = "future-report/v2".into();
        snapshot.original_json = OriginalDocument::new(b"{\"future_shape\":true}".to_vec());
        let saved = directory.path().join("future.snapshot.json");
        snapshot.save(&saved).unwrap();
        let loaded = ReportSnapshot::load(&saved).unwrap();
        assert!(!loaded.verify().unwrap().replay_available);
        let original = directory.path().join("original.html");
        loaded
            .retrieve(ReportDocumentFormat::Html, &original)
            .unwrap();
        assert_eq!(fs::read(&original).unwrap(), snapshot.original_html.bytes);
        assert!(
            loaded
                .replay(
                    ReportDocumentFormat::Html,
                    &directory.path().join("replayed.html")
                )
                .is_err()
        );
    }

    #[test]
    fn active_run_cannot_be_captured_as_a_formal_report() {
        let mut case = crate::demo::build_demo_case();
        case.scan_runs[0].completed_at = None;
        for task in &mut case.scan_runs[0].engine_runs {
            task.status = EngineRunStatus::Running;
        }
        assert!(
            ReportSnapshot::capture(
                &case,
                &case.scan_runs[0].id,
                ExportOptions::default(),
                Path::new("unused")
            )
            .is_err()
        );
    }

    #[test]
    fn original_attachment_bytes_survive_offline_replay_and_keep_redaction_selection() {
        let directory = tempfile::tempdir().unwrap();
        let artifact_root = directory.path().join("artifacts");
        let mut case = crate::demo::build_demo_case();
        case.raw_artifacts.clear();
        for run in &mut case.scan_runs {
            for task in &mut run.engine_runs {
                task.raw_artifact_ids.clear();
            }
        }
        let run_id = case.scan_runs[0].id.clone();
        let task_id = case.scan_runs[0].engine_runs[0].id.clone();
        let originals = [
            (
                "report/index.html",
                b"<html><img src='assets/chart.svg'></html>".as_slice(),
                false,
            ),
            (
                "report/assets/chart.svg",
                b"<svg><!-- retained bytes --></svg>".as_slice(),
                false,
            ),
            (
                "private.json",
                b"{\"synthetic_secret\":\"fixture-only\"}".as_slice(),
                true,
            ),
        ];
        for (name, bytes, sensitive) in originals {
            let relative_path = format!("{}/{run_id}/{task_id}/{name}", case.id);
            let path = artifact_root.join(&relative_path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
            let id = new_id();
            case.scan_runs[0].engine_runs[0]
                .raw_artifact_ids
                .push(id.clone());
            case.raw_artifacts.push(crate::domain::RawArtifact {
                id,
                case_id: case.id.clone(),
                run_id: run_id.clone(),
                engine_run_id: task_id.clone(),
                relative_path,
                media_type: "application/octet-stream".into(),
                sha256: digest(bytes),
                byte_length: bytes.len() as u64,
                created_at: case.created_at,
                contains_sensitive_data: sensitive,
            });
        }
        let mut saved = Vec::new();
        for redaction in [RedactionProfile::None, RedactionProfile::Standard] {
            let snapshot = ReportSnapshot::capture(
                &case,
                &run_id,
                ExportOptions {
                    redaction,
                    include_raw_artifacts: true,
                    ..Default::default()
                },
                &artifact_root,
            )
            .unwrap();
            let inputs = snapshot.decode_inputs().unwrap();
            assert_eq!(inputs.attachments.len(), 1);
            let mut zip =
                zip::ZipArchive::new(std::io::Cursor::new(&inputs.attachments[0].bytes)).unwrap();
            for (name, bytes, sensitive) in originals {
                let entry = format!("files/{name}");
                if redaction == RedactionProfile::Standard && sensitive {
                    assert!(zip.by_name(&entry).is_err());
                } else {
                    let mut retained = Vec::new();
                    zip.by_name(&entry)
                        .unwrap()
                        .read_to_end(&mut retained)
                        .unwrap();
                    assert_eq!(retained, bytes);
                }
            }
            let path = directory
                .path()
                .join(format!("{}.snapshot.json", redaction.as_str()));
            snapshot.save(&path).unwrap();
            saved.push((path, snapshot.original_html.bytes.clone()));
        }
        fs::remove_dir_all(&artifact_root).unwrap();
        for (index, (path, expected)) in saved.iter().enumerate() {
            let snapshot = ReportSnapshot::load(path).unwrap();
            let output = directory.path().join(format!("replayed-{index}.html"));
            snapshot
                .replay(ReportDocumentFormat::Html, &output)
                .unwrap();
            assert_eq!(fs::read(output).unwrap(), *expected);
        }
    }

    #[test]
    fn reader_rejects_oversize_and_non_regular_files() {
        let directory = tempfile::tempdir().unwrap();
        assert!(ReportSnapshot::load(directory.path()).is_err());
        let oversized = directory.path().join("large.json");
        fs::File::create(&oversized)
            .unwrap()
            .set_len(MAX_REPORT_SNAPSHOT_BYTES + 1)
            .unwrap();
        assert!(ReportSnapshot::load(&oversized).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_reader_rejects_links_and_saved_file_is_private() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().unwrap();
        let saved = directory.path().join("saved.json");
        capture().save(&saved).unwrap();
        assert_eq!(
            fs::metadata(&saved).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let linked = directory.path().join("linked.json");
        symlink(&saved, &linked).unwrap();
        assert!(ReportSnapshot::load(&linked).is_err());
        fs::remove_file(linked).unwrap();
        let hard = directory.path().join("hard.json");
        fs::hard_link(&saved, &hard).unwrap();
        assert!(ReportSnapshot::load(&hard).is_err());
    }
}
