//! Portable, private case preservation. Archive data never supplies executable
//! code, live credentials, scan authority, or a worker to restore.

mod history;
mod provider;
#[cfg(test)]
mod tests;

use crate::artifact_store::read_verified_raw_artifact;
use crate::case_archive_io::{self as transport, ArchiveEntry, ArchiveManifest, VerifiedArchive};
use crate::case_archive_model::{
    PortableCase, restored_case_with_provider, validate_case_graph, validate_original_document,
};
use crate::case_service::write_new_private_file;
use crate::domain::{AssessmentCase, new_id};
use crate::error::{AppError, AppResult};
use crate::export::ExportOptions;
use crate::report_snapshot::ReportSnapshot;
use crate::storage::Storage;
use crate::workspace_snapshot::{
    WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY, WorkspaceSnapshotReference,
    inspect_workspace_snapshot,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CASE_BYTES: u64 = 64 * 1024 * 1024;
const INDEX_SCHEMA: &str = "ai-security-scanner.archive-index/v1";
const RESTORE_SCHEMA: &str = "ai-security-scanner.restore-receipt/v1";
const RECEIPT_FILE: &str = "restore-receipt.json";
const RESTORE_TRANSFORMATIONS: &[&str] = &[
    "current scope grants removed",
    "current asset owner confirmations cleared",
    "source connections and current capability metadata disabled",
    "resume tokens removed; live workers and leases excluded",
    "selected export paths rebound; unselected export paths cleared",
];

#[derive(Debug, Default)]
pub struct ArchiveOptions {
    pub include_source_snapshots: bool,
    pub include_export_files: bool,
    pub report_snapshots: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedExport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attachment_archive: Option<String>,
    id: String,
    document: String,
    coverage: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveIndex {
    schema_version: String,
    raw_artifacts: BTreeMap<String, String>,
    reports: Vec<String>,
    exports: Vec<SavedExport>,
    source_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_history: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    historical_source_references: Vec<WorkspaceSnapshotReference>,
}

#[derive(Debug, Serialize)]
pub struct ArchiveInspection {
    pub schema_version: &'static str,
    pub archive_id: String,
    pub archive_sha256: String,
    pub case_id: String,
    pub title: String,
    pub source_case_revision: i64,
    pub run_count: usize,
    pub finding_count: usize,
    pub inventory_count: usize,
    pub raw_artifact_count: usize,
    pub report_snapshot_count: usize,
    pub replay_available_count: usize,
    pub case_data_restore_available: bool,
    pub source_snapshots_included: bool,
    pub omissions: Vec<String>,
    pub integrity_valid: bool,
    pub authenticity: &'static str,
    pub restores_scan_authority: bool,
}

#[derive(Debug, Serialize)]
pub struct ArchiveReceipt {
    pub schema_version: &'static str,
    pub archive_id: String,
    pub case_id: String,
    pub path: PathBuf,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Serialize)]
pub struct RestorePreview {
    pub archive: ArchiveInspection,
    pub destination: PathBuf,
    pub destination_available: bool,
    pub disabled_on_restore: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReceipt {
    pub schema_version: String,
    pub archive_id: String,
    pub archive_sha256: String,
    pub case_id: String,
    pub workspace_id: String,
    pub destination: PathBuf,
    pub restored_at: DateTime<Utc>,
    pub source_case_revision: i64,
    pub local_case_revision: i64,
    pub restores_scan_authority: bool,
    pub files: BTreeMap<String, String>,
    pub omissions: Vec<String>,
    pub transformations: Vec<String>,
}

// Constructed only after the full provider verifier has accepted staged bytes.
pub(crate) struct VerifiedProviderHistory {
    metadata: crate::cloudflare_provider::restored::ProviderHistory,
    case_id: String,
}
impl VerifiedProviderHistory {
    pub(crate) fn metadata(&self) -> &crate::cloudflare_provider::restored::ProviderHistory {
        &self.metadata
    }
}
pub(crate) fn check_restore_case(
    case: &AssessmentCase,
    provider: Option<&VerifiedProviderHistory>,
) -> AppResult<()> {
    if let Some(provider) = provider {
        provider.metadata.validate()?;
        if provider.case_id != case.id {
            return Err(invalid("provider restore identity mismatch"));
        }
        provider::graph(case)
    } else {
        crate::agent_audit_admission::check_report(case)
    }
}

struct LoadedArchive {
    package: VerifiedArchive,
    portable: PortableCase,
    index: ArchiveIndex,
}

struct Builder {
    directory: transport::PrivateArchiveDirectory,
    _parent_guard: transport::ArchiveParentGuard,
    files: BTreeMap<String, PathBuf>,
    entries: BTreeMap<String, ArchiveEntry>,
    staged_bytes: u64,
    paths: transport::Paths,
}

impl Builder {
    fn new() -> AppResult<Self> {
        let parent = fs::canonicalize(std::env::temp_dir())?;
        let parent_guard = transport::guard_archive_parent(&parent)?;
        let directory = transport::private_tempdir_in(&parent, "ai-scanner-archive-")?;
        Ok(Self {
            directory,
            _parent_guard: parent_guard,
            files: BTreeMap::new(),
            entries: BTreeMap::new(),
            // Reserve the bounded manifest and tar framing before any payload.
            staged_bytes: transport::MAX_ARCHIVE_MANIFEST_BYTES + 16 * 1024,
            paths: transport::Paths::default(),
        })
    }

    fn add(&mut self, name: &str, bytes: &[u8]) -> AppResult<()> {
        transport::validate_path(name)?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(invalid("archive entry exceeds 512 MiB"));
        }
        let hash = digest(bytes);
        if let Some(existing) = self.entries.get(name) {
            if existing.sha256 == hash && existing.byte_length == bytes.len() as u64 {
                return Ok(());
            }
            return Err(invalid("archive entries collide"));
        }
        // Include worst-case long-name metadata and block padding. Refuse
        // excess before filling private staging, rather than at final packing.
        let staged_bytes = self.staged_bytes + bytes.len() as u64 + 6 * 1024;
        if self.files.len() >= transport::MAX_ARCHIVE_ENTRIES
            || staged_bytes > transport::MAX_ARCHIVE_DECOMPRESSED_BYTES
        {
            return Err(invalid("archive exceeds its bounded staging budget"));
        }
        self.paths.insert(name)?;
        let path = self.directory.path().join(name);
        private_directories(path.parent().expect("entry parent"))?;
        write_new_private_file(&path, bytes)?;
        self.entries.insert(
            name.into(),
            ArchiveEntry {
                path: name.into(),
                sha256: hash,
                byte_length: bytes.len() as u64,
            },
        );
        self.files.insert(name.into(), path);
        self.staged_bytes = staged_bytes;
        Ok(())
    }

    fn add_expected(&mut self, name: &str, path: &Path, expected: &str) -> AppResult<()> {
        let bytes = read_private_input(path, MAX_FILE_BYTES)?;
        if digest(&bytes) != expected {
            return Err(invalid("retained file differs from its recorded SHA-256"));
        }
        self.add(name, &bytes)
    }
}

/// All recorded raw evidence is required. Source trees and prior external
/// exports are distinct explicit selections, with omissions in the manifest.
pub fn create_archive(
    data_dir: &Path,
    case_id: &str,
    destination: &Path,
    options: &ArchiveOptions,
) -> AppResult<ArchiveReceipt> {
    let storage = Storage::open_read_only(data_dir.join("casework.db"))?;
    let saved = storage.snapshot_case_for_archive(case_id)?;
    let provider_aware = !saved.case.agent_audit_admissions.is_empty()
        || crate::agent_audit_failure::has_failure(&saved.case);
    if provider_aware {
        provider::graph(&saved.case)?;
    } else {
        crate::agent_audit_admission::check_report(&saved.case)?;
    }
    if saved.document_json.len() as u64 > MAX_CASE_BYTES {
        return Err(invalid("original case exceeds 64 MiB"));
    }
    validate_case_graph(&saved.case)?;
    validate_original_document(&serde_json::from_str(&saved.document_json)?, &saved.case)?;
    let case = &saved.case;
    let artifact_root = data_dir.join("artifacts");
    let mut builder = Builder::new()?;
    let mut index = ArchiveIndex {
        schema_version: INDEX_SCHEMA.into(),
        raw_artifacts: BTreeMap::new(),
        reports: Vec::new(),
        exports: Vec::new(),
        source_files: Vec::new(),
        provider_history: None,
        historical_source_references: Vec::new(),
    };
    let mut omissions = vec![
        "Live credential-vault material, signing private keys, execution leases and live workers are excluded; retained evidence may contain secrets.".into(),
    ];
    if saved
        .events
        .iter()
        .any(|event| event.event_type == crate::cloudflare_provider::source_view::RECEIPT_EVENT)
        || fs::symlink_metadata(artifact_root.join(&case.id).join("source-views")).is_ok()
    {
        omissions.push("Product-generated source views are omitted; preparation receipts are historical only. Restore does not restore view bytes or renew model-processing authorization. Prepare a new view from retained sources after restore.".into());
    }
    if !provider_aware
        && (saved.events.iter().any(|event| {
            matches!(
                event.event_type.as_str(),
                crate::cloudflare_provider::audit::RECEIPT_EVENT
                    | crate::cloudflare_provider::audit::record::RECORD_EVENT
            )
        }) || fs::symlink_metadata(artifact_root.join(&case.id).join("cloudflare-sessions"))
            .is_ok())
    {
        omissions.push("Cloudflare audit records are not included; preparation events are historical only. Restored events cannot resume an audit run.".into());
    }
    builder.add("original-case.json", saved.document_json.as_bytes())?;
    let portable = PortableCase {
        schema_version: "ai-security-scanner.case-snapshot/v1".into(),
        case: case.clone(),
        source_document_sha256: digest(saved.document_json.as_bytes()),
        historical_events: saved.events,
    };
    portable.validate()?;
    let case_bytes = serde_json::to_vec(&portable)?;
    if case_bytes.len() as u64 > MAX_CASE_BYTES {
        return Err(invalid("portable case exceeds 64 MiB"));
    }
    builder.add("case.json", &case_bytes)?;
    for artifact in &case.raw_artifacts {
        let bytes =
            read_verified_raw_artifact(&artifact_root, artifact, MAX_FILE_BYTES).map_err(|e| {
                if provider_aware
                    && case
                        .agent_audit_admissions
                        .iter()
                        .any(|a| a.artifacts.iter().any(|b| b.artifact_id == artifact.id))
                {
                    provider::error(
                        if artifact_root
                            .join(&artifact.relative_path)
                            .try_exists()
                            .is_ok_and(|exists| !exists)
                        {
                            "archive_original_missing"
                        } else {
                            "archive_content_mismatch"
                        },
                    )
                } else {
                    e
                }
            })?;
        let path = format!("artifacts/{}", artifact.relative_path);
        builder.add(&path, &bytes)?;
        index.raw_artifacts.insert(artifact.id.clone(), path);
    }
    // Recorded export snapshots are historical originals and always travel
    // with the private archive, independently of external export-file selection.
    for export in &case.exports {
        if let Some(reference) = &export.report_snapshot {
            let bytes = reference.read(&artifact_root, export)?;
            add_report_named(
                case,
                &mut builder,
                &mut index,
                &bytes,
                format!("artifacts/{}", reference.relative_path),
            )?;
        }
    }
    for record in &case.run_report_snapshots {
        let bytes = record.read(&artifact_root, &case.id)?;
        add_report_named(
            case,
            &mut builder,
            &mut index,
            &bytes,
            format!("artifacts/{}", record.snapshot.relative_path),
        )?;
    }
    for export in &case.combined_exports {
        if let Some(reference) = &export.report_snapshot {
            let bytes = reference.read_combined(&artifact_root, export)?;
            add_report_named(
                case,
                &mut builder,
                &mut index,
                &bytes,
                format!("artifacts/{}", reference.relative_path),
            )?;
        }
    }
    // These are new views frozen at archive creation, never invented historical
    // reports. Explicitly supplied earlier snapshots retain their original bytes.
    for run in &case.scan_runs {
        let report =
            ReportSnapshot::capture(case, &run.id, ExportOptions::default(), &artifact_root)?;
        #[cfg(test)]
        let report = tests::fixed_report(report);
        add_report(
            case,
            &mut builder,
            &mut index,
            &serde_json::to_vec(&report)?,
        )?;
    }
    for path in &options.report_snapshots {
        let bytes = read_private_input(path, crate::report_snapshot::MAX_REPORT_SNAPSHOT_BYTES)?;
        add_report(case, &mut builder, &mut index, &bytes)?;
    }
    if options.include_export_files {
        for (ordinal, export) in case.exports.iter().enumerate() {
            let extension = match export.format.as_deref() {
                Some("html") => "html",
                Some("case_bundle") => "case.tar.gz",
                Some("json" | "framework_report" | "ocsf" | "oscal") => "json",
                _ => "bin",
            };
            let document = format!("exports/{ordinal}/report.{extension}");
            builder.add_expected(&document, Path::new(&export.path), &export.sha256)?;
            let coverage = match (
                &export.coverage_manifest_path,
                &export.coverage_manifest_sha256,
            ) {
                (Some(path), Some(hash)) => {
                    let name = format!("exports/{ordinal}/coverage.json");
                    builder.add_expected(&name, Path::new(path), hash)?;
                    Some(name)
                }
                (None, None) => None,
                _ => return Err(invalid("export coverage companion identity is incomplete")),
            };
            index.exports.push(SavedExport {
                attachment_archive: None,
                id: export.id.clone(),
                document,
                coverage,
            });
        }
        for (ordinal, export) in case.combined_exports.iter().enumerate() {
            let extension = match export.format {
                crate::domain::SelectedRunReportFormat::Html => "html",
                crate::domain::SelectedRunReportFormat::Json => "json",
            };
            let document = format!("exports/combined-{ordinal}/report.{extension}");
            builder.add_expected(&document, Path::new(&export.path), &export.sha256)?;
            let attachment_archive = if let Some(archive) = &export.attachment_archive {
                let name = format!("exports/combined-{ordinal}/originals.case.tar.gz");
                builder.add_expected(&name, Path::new(&archive.path), &archive.sha256)?;
                if builder
                    .entries
                    .get(&name)
                    .is_none_or(|entry| entry.byte_length != archive.byte_length)
                {
                    return Err(invalid("attachment archive length does not match history"));
                }
                Some(name)
            } else {
                None
            };
            index.exports.push(SavedExport {
                attachment_archive,
                id: export.id.clone(),
                document,
                coverage: None,
            });
        }
    } else if !case.exports.is_empty() || !case.combined_exports.is_empty() {
        omissions.push("Prior exported files were not selected; their complete history and signatures are retained.".into());
    }
    if provider_aware {
        index.historical_source_references = restored_source_references(data_dir, &portable)?;
    }
    if options.include_source_snapshots {
        add_sources(&portable, &artifact_root, &mut builder, &mut index)?;
        if inherited_snapshots_missing(&portable, &index)? {
            omissions.push(INHERITED_SOURCE_OMISSION.into());
        }
        if index.source_files.is_empty() && inherited_source_snapshots(&portable)?.is_empty() {
            omissions.push("No retained source snapshot was recorded; historical source completeness is unknown.".into());
        }
    } else {
        omissions.push("Source snapshots were not selected; this archive does not preserve the full assessed source tree.".into());
    }
    let mut required_capabilities = Vec::new();
    if provider_aware {
        let (provider_omissions, capabilities) = provider::create(
            data_dir,
            &portable,
            options.include_source_snapshots,
            &mut builder,
        )?;
        required_capabilities = capabilities;
        index.provider_history = Some(history::PATH.into());
        if !options.include_source_snapshots || provider_omissions {
            omissions.push(history::SOURCE_OMISSION.into());
        }
    }
    builder.add("archive-index.json", &serde_json::to_vec(&index)?)?;
    let archive_id = new_id();
    let manifest = ArchiveManifest {
        schema_version: "ai-security-scanner.archive/v1".into(),
        archive_id: archive_id.clone(),
        created_at: Utc::now(),
        producer_version: crate::product_version::current().into(),
        case_id: case.id.clone(),
        source_case_revision: saved.revision,
        case_document_sha256: digest(&case_bytes),
        required_capabilities,
        raw_artifacts_included: true,
        source_snapshots_included: options.include_source_snapshots,
        omissions,
        entries: builder.entries.into_values().collect(),
    };
    #[cfg(test)]
    let manifest = tests::fixed_manifest(manifest);
    // No output is published from a case that changed while its blobs were read.
    storage.assert_case_revision(case_id, saved.revision)?;
    transport::write_archive(&manifest, &builder.files, destination)?;
    let hash = hash_file(destination)?;
    Ok(ArchiveReceipt {
        schema_version: "ai-security-scanner.archive-receipt/v1",
        archive_id,
        case_id: case.id.clone(),
        path: fs::canonicalize(destination)?,
        sha256: hash,
        byte_length: fs::metadata(destination)?.len(),
    })
}

fn add_report(
    case: &AssessmentCase,
    builder: &mut Builder,
    index: &mut ArchiveIndex,
    bytes: &[u8],
) -> AppResult<()> {
    add_report_named(
        case,
        builder,
        index,
        bytes,
        format!("report-snapshots/{}.json", digest(bytes)),
    )
}

fn add_report_named(
    case: &AssessmentCase,
    builder: &mut Builder,
    index: &mut ArchiveIndex,
    bytes: &[u8],
    name: String,
) -> AppResult<()> {
    if bytes.len() as u64 > crate::report_snapshot::MAX_REPORT_SNAPSHOT_BYTES {
        return Err(invalid("report snapshot exceeds its supported size limit"));
    }
    let snapshot: ReportSnapshot = serde_json::from_slice(bytes)?;
    let inspection = snapshot.verify()?;
    if inspection.case_id != case.id || !snapshot_sources_belong_to_case(&inspection, case) {
        return Err(invalid(
            "report snapshot belongs to a different case or run",
        ));
    }
    builder.add(&name, bytes)?;
    if !index.reports.contains(&name) {
        index.reports.push(name);
    }
    Ok(())
}

fn snapshot_sources_belong_to_case(
    snapshot: &crate::report_snapshot::ReportSnapshotInspection,
    case: &AssessmentCase,
) -> bool {
    let sources = if snapshot.selected_run_ids.is_empty() {
        vec![&snapshot.run_id]
    } else {
        snapshot.selected_run_ids.iter().collect()
    };
    sources
        .iter()
        .all(|id| case.scan_runs.iter().any(|run| &run.id == *id))
}

fn workspace_references(
    case: &AssessmentCase,
    historical: &[WorkspaceSnapshotReference],
    require_complete: bool,
) -> AppResult<Vec<WorkspaceSnapshotReference>> {
    path_component(&case.id)?;
    let values = case
        .data_sources
        .iter()
        .filter_map(|source| {
            source
                .metadata
                .get(WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY)
        })
        .chain(
            case.scan_runs
                .iter()
                .flat_map(|run| &run.report_asset_snapshots)
                .filter_map(|snapshot| {
                    snapshot
                        .asset
                        .metadata
                        .get(WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY)
                }),
        );
    let mut refs = BTreeMap::new();
    for value in values {
        let reference: WorkspaceSnapshotReference = serde_json::from_value(value.clone())?;
        path_component(&reference.storage_id)?;
        if let Some(previous) = refs.insert(reference.storage_id.clone(), reference.clone())
            && previous != reference
        {
            return Err(invalid("source snapshot identities conflict"));
        }
    }
    for reference in historical {
        path_component(&reference.storage_id)?;
        if let Some(previous) = refs.insert(reference.storage_id.clone(), reference.clone())
            && previous != *reference
        {
            return Err(invalid("historical source references conflict"));
        }
    }
    if !require_complete {
        return Ok(refs.into_values().collect());
    }
    // Frozen assets commonly retain only the snapshot identity. A refresh may
    // have replaced the full source reference: never label that history as
    // preserved merely because the latest source tree is available.
    for asset in case.assets.iter().chain(
        case.scan_runs
            .iter()
            .flat_map(|run| &run.report_asset_snapshots)
            .map(|snapshot| &snapshot.asset),
    ) {
        let id = asset.metadata.get("workspace_snapshot_id");
        let hash = asset.metadata.get("workspace_snapshot_sha256");
        if id.is_none() && hash.is_none() {
            continue;
        }
        let known = refs.values().any(|reference| {
            id.is_none_or(|value| value.as_str() == Some(reference.snapshot_id.as_str()))
                && hash.is_none_or(|value| value.as_str() == Some(reference.sha256.as_str()))
        });
        if !known {
            return Err(invalid(
                "historical workspace source has no complete retained reference; archive without source selection or recover that snapshot first",
            ));
        }
    }
    Ok(refs.into_values().collect())
}

fn connector_references(
    case: &AssessmentCase,
) -> AppResult<Vec<crate::connectors::SnapshotArtifactReference>> {
    use crate::connectors::{
        LIVE_PROVIDER_ARTIFACT_METADATA_KEY, LIVE_PROVIDER_ARTIFACT_SET_SCHEMA,
        LiveProviderArtifactSet, SNAPSHOT_ARTIFACT_METADATA_KEY, SNAPSHOT_REFERENCE_SCHEMA,
        SnapshotArtifactReference,
    };
    let mut captures = Vec::new();
    for source in &case.data_sources {
        if let Some(value) = source.metadata.get(SNAPSHOT_ARTIFACT_METADATA_KEY) {
            captures.push(serde_json::from_value::<SnapshotArtifactReference>(
                value.clone(),
            )?);
        }
        if let Some(value) = source.metadata.get(LIVE_PROVIDER_ARTIFACT_METADATA_KEY) {
            let set: LiveProviderArtifactSet = serde_json::from_value(value.clone())?;
            if set.schema_version != LIVE_PROVIDER_ARTIFACT_SET_SCHEMA {
                return Err(invalid("unsupported connector source capture schema"));
            }
            captures.extend(set.pages.into_iter().map(|page| page.artifact));
        }
    }
    let mut refs = BTreeMap::new();
    for reference in captures {
        if reference.schema_version != SNAPSHOT_REFERENCE_SCHEMA
            || reference.artifact_id.is_empty()
            || reference.artifact_id.trim() != reference.artifact_id
            || reference.artifact_id.chars().any(char::is_control)
            || reference.sha256.as_deref().is_none_or(|hash| {
                hash.trim().len() != 64 || !hash.trim().bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(invalid(
                "connector source has no complete retained reference",
            ));
        }
        if let Some(previous) = refs.insert(reference.artifact_id.clone(), reference.clone()) {
            // Provider capture IDs address bytes. Repeated observations can
            // legitimately have different times/profiles, all of which remain
            // in the portable case; only blob identity must agree here.
            if previous.canonical_relative_path != reference.canonical_relative_path
                || !previous
                    .sha256
                    .as_deref()
                    .expect("validated digest")
                    .trim()
                    .eq_ignore_ascii_case(
                        reference
                            .sha256
                            .as_deref()
                            .expect("validated digest")
                            .trim(),
                    )
            {
                return Err(invalid("connector source artifact identities conflict"));
            }
        }
    }
    let require_capture = |value: &serde_json::Value| -> AppResult<()> {
        if value.as_str().is_none_or(|id| !refs.contains_key(id)) {
            return Err(invalid(
                "historical connector source has no complete retained reference; archive without source selection or recover that capture first",
            ));
        }
        Ok(())
    };
    // Discovery keeps the first source_artifact_id and records later captures
    // at this fixed history key. Inspect both current and frozen assets; never
    // invent a reference or search a current provider for missing history.
    for asset in case.assets.iter().chain(
        case.scan_runs
            .iter()
            .flat_map(|run| &run.report_asset_snapshots)
            .map(|snapshot| &snapshot.asset),
    ) {
        if let Some(value) = asset.metadata.get("source_artifact_id") {
            require_capture(value)?;
        }
        if let Some(values) = asset
            .metadata
            .get("ai_security_scanner.observed_values")
            .and_then(|history| history.get("source_artifact_id"))
        {
            let values = values
                .as_array()
                .ok_or_else(|| invalid("historical connector source reference list is invalid"))?;
            for value in values {
                require_capture(value)?;
            }
        }
    }
    // Relation evidence is generic: scanner raw files and finding evidence are
    // already retained independently of the optional connector source blobs.
    let mut retained_evidence = refs.keys().map(String::as_str).collect::<BTreeSet<_>>();
    retained_evidence.extend(
        case.raw_artifacts
            .iter()
            .map(|artifact| artifact.id.as_str()),
    );
    retained_evidence.extend(
        case.findings
            .iter()
            .chain(
                case.finding_observations
                    .iter()
                    .filter_map(|observation| observation.finding_snapshot.as_ref()),
            )
            .flat_map(|finding| &finding.evidence)
            .map(|evidence| evidence.id.as_str()),
    );
    for id in case
        .asset_relations
        .iter()
        .flat_map(|relation| &relation.evidence_ids)
    {
        if !retained_evidence.contains(id.as_str()) {
            return Err(invalid(
                "historical relation source has no complete retained reference; archive without source selection or recover that capture first",
            ));
        }
    }
    Ok(refs.into_values().collect())
}

// Current source capabilities were disabled on restore. Read only pinned archive
// originals to carry their inert source references into the next archive index.
fn restored_source_references(
    data: &Path,
    portable: &PortableCase,
) -> AppResult<Vec<WorkspaceSnapshotReference>> {
    let Some(event) = portable
        .historical_events
        .iter()
        .rev()
        .find(|e| e.event_type == "case.restored")
    else {
        return Ok(Vec::new());
    };
    let payload: serde_json::Value = serde_json::from_str(&event.payload_json)?;
    let receipt: RestoreReceipt = serde_json::from_slice(&read_private_input(
        &data.join(RECEIPT_FILE),
        16 * 1024 * 1024,
    )?)?;
    if payload["archive_id"] != receipt.archive_id || receipt.case_id != portable.case.id {
        return Err(invalid("historical source archive identity mismatch"));
    }
    let read = |name: &str| -> AppResult<Vec<u8>> {
        let bytes = read_private_input(&data.join(name), MAX_CASE_BYTES)?;
        if receipt.files.get(name) != Some(&digest(&bytes)) {
            return Err(invalid("historical source archive bytes changed"));
        }
        Ok(bytes)
    };
    let original: AssessmentCase = serde_json::from_slice(&read("original-case.json")?)?;
    let index: ArchiveIndex = serde_json::from_slice(&read("archive-index.json")?)?;
    workspace_references(&original, &index.historical_source_references, false)
}

fn inherited_source_snapshots(portable: &PortableCase) -> AppResult<BTreeSet<String>> {
    use crate::cloudflare_provider::audit::{PreparationReceipt, PreparationResult, RECEIPT_EVENT};
    let omitted =
        crate::cloudflare_provider::restored::omitted_sessions(&portable.historical_events)?;
    let mut snapshots = BTreeSet::new();
    for event in portable
        .historical_events
        .iter()
        .filter(|e| e.event_type == RECEIPT_EVENT)
    {
        let receipt: PreparationReceipt = serde_json::from_str(&event.payload_json)?;
        if let PreparationResult::Prepared { facts, .. } = receipt.result
            && omitted.contains(&facts.session_id)
        {
            snapshots.insert(facts.source.canonical_snapshot_id);
        }
    }
    Ok(snapshots)
}

const INHERITED_SOURCE_OMISSION: &str = "Source snapshots that were not included in the archive this case was restored from are still missing; this archive does not preserve the full assessed source tree.";

fn inherited_snapshots_missing(portable: &PortableCase, index: &ArchiveIndex) -> AppResult<bool> {
    let inherited = inherited_source_snapshots(portable)?;
    Ok(
        workspace_references(&portable.case, &index.historical_source_references, true)?
            .iter()
            .any(|reference| {
                inherited.contains(&reference.snapshot_id)
                    && !index.source_files.contains(&format!(
                        "artifacts/{}/workspace-snapshots/{}/payload/manifest.json",
                        portable.case.id, reference.storage_id
                    ))
            }),
    )
}

fn add_sources(
    portable: &PortableCase,
    root: &Path,
    builder: &mut Builder,
    index: &mut ArchiveIndex,
) -> AppResult<()> {
    let case = &portable.case;
    let omitted = inherited_source_snapshots(portable)?;
    for reference in workspace_references(case, &index.historical_source_references, true)? {
        if omitted.contains(&reference.snapshot_id)
            && !root
                .join(&case.id)
                .join("workspace-snapshots")
                .join(&reference.storage_id)
                .try_exists()?
        {
            continue;
        }
        let source = inspect_workspace_snapshot(root, &case.id, &reference)?;
        let prefix = format!(
            "artifacts/{}/workspace-snapshots/{}/payload",
            case.id, reference.storage_id
        );
        let manifest = format!("{prefix}/manifest.json");
        builder.add_expected(&manifest, &source.manifest_path, &reference.sha256)?;
        index.source_files.push(manifest);
        for file in source.manifest.files {
            let name = format!("{prefix}/tree/{}", file.relative_path);
            builder.add_expected(
                &name,
                &source.tree_path.join(&file.relative_path),
                &file.sha256,
            )?;
            index.source_files.push(name);
        }
    }
    for reference in connector_references(case)? {
        if reference.sha256.is_none() {
            return Err(invalid(
                "legacy source has no retained content digest; source completeness cannot be verified",
            ));
        }
        let bytes = crate::connectors::inspect_snapshot_reference(
            &root.join(&case.id).join("connector-snapshots"),
            &reference,
            &[reference.profile.as_str()],
        )
        .map_err(|error| invalid(&error.to_string()))?;
        let name = format!(
            "artifacts/{}/connector-snapshots/{}",
            case.id, reference.canonical_relative_path
        );
        builder.add(&name, &bytes)?;
        index.source_files.push(name);
    }
    index.source_files.sort();
    index.source_files.dedup();
    Ok(())
}

fn load_archive(path: &Path) -> AppResult<LoadedArchive> {
    load_package(transport::read_archive(path)?)
}

fn load_package(package: VerifiedArchive) -> AppResult<LoadedArchive> {
    let portable_document: serde_json::Value = serde_json::from_slice(&read_private_input(
        &package.entry_path("case.json")?,
        MAX_CASE_BYTES,
    )?)?;
    let portable: PortableCase = serde_json::from_value(portable_document.clone())?;
    let provider_aware = !portable.case.agent_audit_admissions.is_empty()
        || crate::agent_audit_failure::has_failure(&portable.case);
    if provider_aware == package.manifest.required_capabilities.is_empty() {
        return Err(provider::error("archive_history_mismatch"));
    }
    if provider_aware {
        if portable.case.agent_audit_admissions.is_empty()
            && !crate::agent_audit_failure::has_failure(&portable.case)
        {
            return Err(provider::error("archive_history_mismatch"));
        }
        provider::graph(&portable.case)?;
    } else {
        crate::agent_audit_admission::check_report(&portable.case)?;
    }
    validate_original_document(&portable_document["case"], &portable.case)?;
    if portable_document["historical_events"] != serde_json::to_value(&portable.historical_events)?
    {
        return Err(invalid(
            "historical events contain fields this core cannot preserve",
        ));
    }
    if portable.schema_version != "ai-security-scanner.case-snapshot/v1"
        || portable.case.id != package.manifest.case_id
    {
        return Err(invalid(
            "portable case schema or identity does not match the archive",
        ));
    }
    portable.validate()?;
    let original = read_private_input(&package.entry_path("original-case.json")?, MAX_CASE_BYTES)?;
    if digest(&original) != portable.source_document_sha256 {
        return Err(invalid(
            "original case bytes do not match the recorded source document",
        ));
    }
    let original_case: AssessmentCase = serde_json::from_slice(&original)?;
    validate_original_document(&serde_json::from_slice(&original)?, &original_case)?;
    if serde_json::to_value(&original_case)? != serde_json::to_value(&portable.case)? {
        return Err(invalid("portable case differs from its preserved original"));
    }
    let index: ArchiveIndex = serde_json::from_slice(&read_private_input(
        &package.entry_path("archive-index.json")?,
        16 * 1024 * 1024,
    )?)?;
    if !provider_aware && !index.historical_source_references.is_empty() {
        return Err(invalid(
            "historical source references require provider history",
        ));
    }
    if index.schema_version != INDEX_SCHEMA || !package.manifest.raw_artifacts_included {
        return Err(invalid("unsupported or incomplete archive index"));
    }
    let inherited_missing = package.manifest.source_snapshots_included
        && inherited_snapshots_missing(&portable, &index)?;
    if package
        .manifest
        .omissions
        .iter()
        .filter(|s| s.as_str() == INHERITED_SOURCE_OMISSION)
        .count()
        != usize::from(inherited_missing)
    {
        return Err(provider::error("archive_omission_mismatch"));
    }
    let case = &portable.case;
    let mut referenced = BTreeSet::from([
        "case.json".to_owned(),
        "original-case.json".into(),
        "archive-index.json".into(),
    ]);
    let entries: BTreeMap<_, _> = package
        .manifest
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    if provider_aware {
        if index.provider_history.as_deref() != Some(history::PATH) {
            return Err(provider::error("archive_history_mismatch"));
        }
        referenced.extend(provider::verify(
            package.root(),
            &portable,
            package.manifest.source_snapshots_included,
            &package
                .manifest
                .entries
                .iter()
                .map(|e| (e.path.clone(), e.clone()))
                .collect(),
        )?);
        let history: history::History = serde_json::from_slice(&read_private_input(
            &package.entry_path(history::PATH)?,
            transport::MAX_ARCHIVE_MANIFEST_BYTES,
        )?)?;
        if package.manifest.required_capabilities != history.capabilities() {
            return Err(provider::error("archive_history_mismatch"));
        }
        let omitted = history
            .preparations
            .iter()
            .any(|p| !p.source_body_omissions.is_empty());
        if package
            .manifest
            .omissions
            .iter()
            .filter(|s| s.as_str() == history::SOURCE_OMISSION)
            .count()
            != usize::from(!package.manifest.source_snapshots_included || omitted)
        {
            return Err(provider::error("archive_omission_mismatch"));
        }
    } else if index.provider_history.is_some() {
        return Err(provider::error("archive_history_mismatch"));
    }
    if index.raw_artifacts.len() != case.raw_artifacts.len() {
        return Err(invalid("raw artifact inventory is incomplete"));
    }
    for artifact in &case.raw_artifacts {
        let name = format!("artifacts/{}", artifact.relative_path);
        let entry = entries
            .get(name.as_str())
            .ok_or_else(|| invalid("raw artifact is missing"))?;
        if index.raw_artifacts.get(&artifact.id) != Some(&name)
            || entry.sha256 != artifact.sha256.to_ascii_lowercase()
            || entry.byte_length != artifact.byte_length
        {
            return Err(invalid(
                "raw artifact content identity does not match the case",
            ));
        }
        referenced.insert(name);
    }
    let mut runs_with_reports = BTreeSet::new();
    for name in &index.reports {
        if !referenced.insert(name.clone()) {
            return Err(invalid("duplicate report snapshot reference"));
        }
        let snapshot = ReportSnapshot::load(&package.entry_path(name)?)?.verify()?;
        if snapshot.case_id != case.id || !snapshot_sources_belong_to_case(&snapshot, case) {
            return Err(invalid(
                "report snapshot belongs to a different case or run",
            ));
        }
        if !snapshot.run_id.is_empty() {
            runs_with_reports.insert(snapshot.run_id);
        }
    }
    if runs_with_reports.len() != case.scan_runs.len() {
        return Err(invalid("a terminal run has no saved report"));
    }
    for export in &case.exports {
        if let Some(reference) = &export.report_snapshot {
            let name = format!("artifacts/{}", reference.relative_path);
            if !index.reports.contains(&name) {
                return Err(invalid(
                    "a recorded export snapshot is missing from the archive",
                ));
            }
            let bytes = read_private_input(
                &package.entry_path(&name)?,
                crate::report_snapshot::MAX_REPORT_SNAPSHOT_BYTES,
            )?;
            reference.verify_export(&bytes, export)?;
        }
    }
    for record in &case.run_report_snapshots {
        let name = format!("artifacts/{}", record.snapshot.relative_path);
        if !index.reports.contains(&name) {
            return Err(invalid(
                "a recorded terminal snapshot is missing from the archive",
            ));
        }
        let bytes = read_private_input(
            &package.entry_path(&name)?,
            crate::report_snapshot::MAX_REPORT_SNAPSHOT_BYTES,
        )?;
        record.verify(&bytes, &case.id)?;
    }
    for export in &case.combined_exports {
        if let Some(reference) = &export.report_snapshot {
            let name = format!("artifacts/{}", reference.relative_path);
            if !index.reports.contains(&name) {
                return Err(invalid(
                    "a recorded combined snapshot is missing from the archive",
                ));
            }
            let bytes = read_private_input(
                &package.entry_path(&name)?,
                crate::report_snapshot::MAX_REPORT_SNAPSHOT_BYTES,
            )?;
            reference.verify_combined_export(&bytes, export)?;
        }
    }
    let mut export_ids = BTreeSet::new();
    for saved in &index.exports {
        let (sha256, coverage_hash) =
            if let Some(export) = case.exports.iter().find(|export| export.id == saved.id) {
                (&export.sha256, &export.coverage_manifest_sha256)
            } else if let Some(export) = case
                .combined_exports
                .iter()
                .find(|export| export.id == saved.id)
            {
                (&export.sha256, &None)
            } else {
                return Err(invalid("export history reference is unknown"));
            };
        if !export_ids.insert(&saved.id)
            || !referenced.insert(saved.document.clone())
            || entries
                .get(saved.document.as_str())
                .is_none_or(|entry| &entry.sha256 != sha256)
        {
            return Err(invalid(
                "export original content identity does not match history",
            ));
        }
        let attachment_archive = case
            .combined_exports
            .iter()
            .find(|export| export.id == saved.id)
            .and_then(|export| export.attachment_archive.as_ref());
        match (&saved.attachment_archive, attachment_archive) {
            (Some(name), Some(archive))
                if referenced.insert(name.clone())
                    && entries.get(name.as_str()).is_some_and(|entry| {
                        entry.sha256 == archive.sha256 && entry.byte_length == archive.byte_length
                    }) => {}
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "combined attachment archive is missing or inconsistent",
                ));
            }
        }
        match (&saved.coverage, coverage_hash) {
            (Some(name), Some(hash))
                if referenced.insert(name.clone())
                    && entries
                        .get(name.as_str())
                        .is_some_and(|entry| &entry.sha256 == hash) => {}
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "export coverage companion is missing or inconsistent",
                ));
            }
        }
    }
    for name in &index.source_files {
        if !name.starts_with("artifacts/")
            || !referenced.insert(name.clone())
            || !entries.contains_key(name.as_str())
        {
            return Err(invalid("invalid or duplicate source file reference"));
        }
    }
    if !package.manifest.source_snapshots_included && !index.source_files.is_empty() {
        return Err(invalid("unselected source snapshots are present"));
    }
    if referenced.len() != entries.len() || !entries.keys().all(|name| referenced.contains(*name)) {
        return Err(invalid(
            "archive contains payloads without a case reference",
        ));
    }
    let loaded = LoadedArchive {
        package,
        portable,
        index,
    };
    if loaded.package.manifest.source_snapshots_included {
        verify_sources(&loaded, loaded.package.root())?;
    }
    Ok(loaded)
}

fn verify_sources(loaded: &LoadedArchive, root: &Path) -> AppResult<()> {
    let mut expected = BTreeSet::new();
    let mut source_directories = BTreeSet::new();
    let omitted = inherited_source_snapshots(&loaded.portable)?;
    for reference in workspace_references(
        &loaded.portable.case,
        &loaded.index.historical_source_references,
        true,
    )? {
        let relative_prefix = format!(
            "artifacts/{}/workspace-snapshots/{}/payload",
            loaded.portable.case.id, reference.storage_id
        );
        let prefix = root.join(&relative_prefix);
        if omitted.contains(&reference.snapshot_id)
            && !loaded
                .index
                .source_files
                .contains(&format!("{relative_prefix}/manifest.json"))
        {
            continue;
        }
        // Empty source directories have no tar entry. Recreate only the fixed,
        // validated manifest's declared directories inside private staging.
        let manifest: crate::workspace_snapshot::WorkspaceSnapshotManifest =
            serde_json::from_slice(&read_private_input(
                &prefix.join("manifest.json"),
                MAX_CASE_BYTES,
            )?)?;
        if manifest.directories.len() > 100_000 || manifest.files.len() > 100_000 {
            return Err(invalid("source snapshot exceeds archive entry limits"));
        }
        expected.insert(format!("{relative_prefix}/manifest.json"));
        for file in &manifest.files {
            transport::validate_path(&file.relative_path)?;
            expected.insert(format!("{relative_prefix}/tree/{}", file.relative_path));
        }
        for directory in &manifest.directories {
            transport::validate_path(directory)?;
            if directory.split('/').count() > 64 {
                return Err(invalid("source directory exceeds depth limit"));
            }
            let relative = format!("{relative_prefix}/tree/{directory}");
            for offset in relative
                .match_indices('/')
                .map(|(offset, _)| offset)
                .chain(std::iter::once(relative.len()))
            {
                source_directories.insert(relative[..offset].to_owned());
                if source_directories.len() > transport::MAX_ARCHIVE_ENTRIES {
                    return Err(invalid(
                        "source directories exceed the archive inventory limit",
                    ));
                }
            }
        }
        private_directories(&prefix.join("tree"))?;
        for directory in &manifest.directories {
            private_directories(&prefix.join("tree").join(directory))?;
        }
        inspect_workspace_snapshot(root.join("artifacts"), &loaded.portable.case.id, &reference)?;
    }
    for reference in connector_references(&loaded.portable.case)? {
        if reference.sha256.is_none() {
            return Err(invalid("source snapshot has no content identity"));
        }
        expected.insert(format!(
            "artifacts/{}/connector-snapshots/{}",
            loaded.portable.case.id, reference.canonical_relative_path
        ));
        crate::connectors::inspect_snapshot_reference(
            &root
                .join("artifacts")
                .join(&loaded.portable.case.id)
                .join("connector-snapshots"),
            &reference,
            &[reference.profile.as_str()],
        )
        .map_err(|error| invalid(&error.to_string()))?;
    }
    if expected != loaded.index.source_files.iter().cloned().collect() {
        return Err(invalid(
            "source snapshot inventory does not match recorded sources",
        ));
    }
    Ok(())
}

impl LoadedArchive {
    fn transformations(&self) -> Vec<&'static str> {
        let mut values = RESTORE_TRANSFORMATIONS.to_vec();
        if self.index.provider_history.is_some() {
            values.push("restored source audits kept as read-only history");
        }
        values
    }
    fn inspection(&self) -> AppResult<ArchiveInspection> {
        let mut replay_available_count = 0;
        for report in &self.index.reports {
            if ReportSnapshot::load(&self.package.entry_path(report)?)?
                .verify()?
                .replay_available
            {
                replay_available_count += 1;
            }
        }
        Ok(ArchiveInspection {
            schema_version: "ai-security-scanner.archive-inspection/v1",
            archive_id: self.package.manifest.archive_id.clone(),
            archive_sha256: self.package.archive_sha256.clone(),
            case_id: self.portable.case.id.clone(),
            title: self.portable.case.title.clone(),
            source_case_revision: self.package.manifest.source_case_revision,
            run_count: self.portable.case.scan_runs.len(),
            finding_count: self.portable.case.findings.len(),
            inventory_count: self.portable.case.inventory_observations.len(),
            raw_artifact_count: self.portable.case.raw_artifacts.len(),
            report_snapshot_count: self.index.reports.len(),
            replay_available_count,
            case_data_restore_available: true,
            source_snapshots_included: self.package.manifest.source_snapshots_included,
            omissions: self.package.manifest.omissions.clone(),
            integrity_valid: true,
            authenticity: "not_authenticated",
            restores_scan_authority: false,
        })
    }
}

pub fn inspect_archive(path: &Path) -> AppResult<ArchiveInspection> {
    load_archive(path)?.inspection()
}

pub fn preview_restore(archive: &Path, destination: &Path) -> AppResult<RestorePreview> {
    let loaded = load_package(transport::read_archive_for_restore(archive)?)?;
    let destination = canonical_destination(destination)?;
    let _parent_guard =
        transport::guard_archive_parent(destination.parent().expect("canonical parent"))?;
    Ok(RestorePreview {
        archive: loaded.inspection()?,
        destination_available: fs::symlink_metadata(&destination)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        destination,
        disabled_on_restore: loaded.transformations(),
    })
}

pub fn restore_archive(archive: &Path, destination: &Path) -> AppResult<RestoreReceipt> {
    restore_impl(archive, destination, RestoreFault::None)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RestoreFault {
    None,
    #[cfg(test)]
    StagedMismatch,
    #[cfg(test)]
    BeforePublish,
    #[cfg(test)]
    AfterPublish,
}

fn restore_impl(
    archive: &Path,
    destination: &Path,
    fault: RestoreFault,
) -> AppResult<RestoreReceipt> {
    let loaded = load_package(transport::read_archive_for_restore(archive)?)?;
    let destination = canonical_destination(destination)?;
    let _parent_guard =
        transport::guard_archive_parent(destination.parent().expect("canonical parent"))?;
    if fs::symlink_metadata(&destination).is_ok() {
        return existing_restore(&loaded, &destination);
    }
    let parent = destination.parent().expect("canonical parent");
    let stage = transport::private_tempdir_in(parent, ".scanner-restore-")?;
    let mut retained = BTreeMap::new();
    for entry in &loaded.package.manifest.entries {
        let path = stage.path().join(&entry.path);
        private_directories(path.parent().expect("payload parent"))?;
        let bytes = read_private_input(&loaded.package.entry_path(&entry.path)?, MAX_FILE_BYTES)?;
        write_new_private_file(&path, &bytes)?;
        #[cfg(test)]
        if fault == RestoreFault::StagedMismatch {
            fs::write(&path, b"changed staged bytes")?;
        }
        if hash_file(&path)? != entry.sha256 || bytes.len() as u64 != entry.byte_length {
            return Err(provider::error("archive_content_mismatch"));
        }
        retained.insert(entry.path.clone(), entry.sha256.clone());
    }
    if loaded.package.manifest.source_snapshots_included {
        verify_sources(&loaded, stage.path())?;
    }
    let provider = if loaded.index.provider_history.is_some() {
        provider::verify(
            stage.path(),
            &loaded.portable,
            loaded.package.manifest.source_snapshots_included,
            &loaded
                .package
                .manifest
                .entries
                .iter()
                .map(|e| (e.path.clone(), e.clone()))
                .collect(),
        )?;
        let bytes = read_private_input(
            &stage.path().join(history::PATH),
            transport::MAX_ARCHIVE_MANIFEST_BYTES,
        )?;
        let history: history::History = serde_json::from_slice(&bytes)?;
        let sessions: BTreeSet<_> = history
            .preparations
            .iter()
            .filter(|p| !p.source_body_omissions.is_empty())
            .filter_map(|p| p.session_id.clone())
            .collect();
        Some(VerifiedProviderHistory {
            case_id: loaded.portable.case.id.clone(),
            metadata: crate::cloudflare_provider::restored::ProviderHistory {
                schema_version: "ai-security-scanner.restored-provider-history/v1".into(),
                history_sha256: digest(&bytes),
                source_bodies_omitted_sessions: sessions.into_iter().collect(),
            },
        })
    } else {
        None
    };
    let mut case = if provider.is_some() {
        restored_case_with_provider(&loaded.portable.case, provider.as_ref())?
    } else {
        crate::case_archive_model::restored_case(&loaded.portable.case)?
    };
    // Original paths remain in case.json; only selected local copies become
    // operational export paths in the newly restored database.
    for export in &mut case.combined_exports {
        if let Some(saved) = loaded
            .index
            .exports
            .iter()
            .find(|saved| saved.id == export.id)
        {
            if let Some(archive) = &mut export.attachment_archive {
                archive.path = saved
                    .attachment_archive
                    .as_ref()
                    .map(|name| destination.join(name).to_string_lossy().into_owned())
                    .unwrap_or_default();
            }
            export.path = destination
                .join(&saved.document)
                .to_string_lossy()
                .into_owned();
        }
    }
    for export in &mut case.exports {
        if let Some(saved) = loaded
            .index
            .exports
            .iter()
            .find(|saved| saved.id == export.id)
        {
            export.path = destination
                .join(&saved.document)
                .to_string_lossy()
                .into_owned();
            export.coverage_manifest_path = saved
                .coverage
                .as_ref()
                .map(|name| destination.join(name).to_string_lossy().into_owned());
        } else {
            export.path.clear();
            export.coverage_manifest_path = None;
        }
    }
    case.storage_revision = loaded.package.manifest.source_case_revision;
    let storage = Storage::open(stage.path().join("casework.db"))?;
    storage.import_archived_case_with_provider(
        &mut case,
        &loaded.portable.historical_events,
        &loaded.package.manifest.archive_id,
        provider.as_ref(),
    )?;
    storage.checkpoint_for_archive_restore()?;
    fs::File::open(stage.path().join("casework.db"))?.sync_all()?;
    retained.insert(
        "casework.db".into(),
        hash_file(&stage.path().join("casework.db"))?,
    );
    let receipt = RestoreReceipt {
        schema_version: RESTORE_SCHEMA.into(),
        archive_id: loaded.package.manifest.archive_id.clone(),
        archive_sha256: loaded.package.archive_sha256.clone(),
        case_id: case.id,
        workspace_id: new_id(),
        destination: destination.clone(),
        restored_at: Utc::now(),
        source_case_revision: loaded.package.manifest.source_case_revision,
        local_case_revision: 1,
        restores_scan_authority: false,
        files: retained,
        omissions: loaded.package.manifest.omissions.clone(),
        transformations: loaded
            .transformations()
            .iter()
            .map(|value| (*value).into())
            .collect(),
    };
    write_new_private_file(
        &stage.path().join(RECEIPT_FILE),
        &serde_json::to_vec(&receipt)?,
    )?;
    write_new_private_file(
        &stage.path().join("restore-intent.json"),
        &serde_json::to_vec(&serde_json::json!({
            "schema_version": "ai-security-scanner.restore-intent/v1", "archive_sha256": receipt.archive_sha256,
            "destination": destination, "workspace_id": receipt.workspace_id, "state": "ready_to_publish",
        }))?,
    )?;
    sync_directories(stage.path())?;
    #[cfg(test)]
    if fault == RestoreFault::BeforePublish {
        return Err(invalid("injected failure before publish"));
    }
    #[cfg(not(test))]
    let _ = fault;
    transport::publish_directory_no_replace(stage.path(), &destination)?;
    sync_directory(parent)?;
    #[cfg(test)]
    if fault == RestoreFault::AfterPublish {
        return Err(invalid("injected failure after publish"));
    }
    Ok(receipt)
}

fn existing_restore(loaded: &LoadedArchive, destination: &Path) -> AppResult<RestoreReceipt> {
    if !real_directory(destination)? {
        return Err(invalid("restore destination already exists"));
    }
    let receipt: RestoreReceipt = serde_json::from_slice(&read_private_input(
        &destination.join(RECEIPT_FILE),
        16 * 1024 * 1024,
    )?)?;
    if receipt.schema_version != RESTORE_SCHEMA
        || receipt.archive_sha256 != loaded.package.archive_sha256
        || receipt.archive_id != loaded.package.manifest.archive_id
        || receipt.destination != destination
        || receipt.case_id != loaded.portable.case.id
        || receipt.restores_scan_authority
        || receipt.source_case_revision != loaded.package.manifest.source_case_revision
        || receipt.local_case_revision != 1
        || receipt.omissions != loaded.package.manifest.omissions
        || receipt.transformations != loaded.transformations()
    {
        return Err(invalid(
            "restore destination belongs to a different operation",
        ));
    }
    // Walk without following links before opening any nested retained path.
    // Only SQLite's empty WAL / coordination file may appear after a read-only
    // reopen; an added user file is a changed workspace, never a retry target.
    let actual = retained_files(destination)?;
    let expected_files: BTreeSet<_> = receipt
        .files
        .keys()
        .cloned()
        .chain([RECEIPT_FILE.into(), "restore-intent.json".into()])
        .collect();
    if actual.iter().any(|name| {
        !expected_files.contains(name)
            && !matches!(name.as_str(), "casework.db-wal" | "casework.db-shm")
    }) || !expected_files.is_subset(&actual)
    {
        return Err(invalid("restored workspace file inventory has changed"));
    }
    let intent: serde_json::Value = serde_json::from_slice(&read_private_input(
        &destination.join("restore-intent.json"),
        64 * 1024,
    )?)?;
    if intent
        != serde_json::json!({
            "schema_version": "ai-security-scanner.restore-intent/v1",
            "archive_sha256": receipt.archive_sha256, "destination": receipt.destination,
            "workspace_id": receipt.workspace_id, "state": "ready_to_publish",
        })
    {
        return Err(invalid("restore intent does not match its receipt"));
    }
    for entry in &loaded.package.manifest.entries {
        if receipt.files.get(&entry.path) != Some(&entry.sha256) {
            return Err(invalid("restore receipt differs from the verified archive"));
        }
    }
    if destination.join("casework.db-wal").try_exists()?
        && fs::metadata(destination.join("casework.db-wal"))?.len() != 0
    {
        return Err(invalid(
            "restored workspace has changed; it will not be overwritten",
        ));
    }
    for (name, hash) in &receipt.files {
        transport::validate_path(name)?;
        if hash_file(&destination.join(name))? != *hash {
            return Err(invalid(
                "restored workspace has changed; it will not be overwritten",
            ));
        }
    }
    let expected: BTreeSet<_> = loaded
        .package
        .manifest
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .chain(std::iter::once("casework.db"))
        .collect();
    if receipt
        .files
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected
    {
        return Err(invalid("restore receipt file inventory is incomplete"));
    }
    Ok(receipt)
}

fn retained_files(root: &Path) -> AppResult<BTreeSet<String>> {
    let mut files = BTreeSet::new();
    let mut directories = vec![root.to_owned()];
    let mut count = 0usize;
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            count += 1;
            if count > transport::MAX_ARCHIVE_ENTRIES * 65 {
                return Err(invalid("restored workspace inventory exceeds limits"));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err(invalid("restored workspace contains a reparse point"));
                }
            }
            if metadata.is_dir() {
                directories.push(entry.path());
            } else if metadata.is_file() {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| invalid("invalid restored path"))?;
                let name = relative
                    .to_str()
                    .ok_or_else(|| invalid("restored path is not UTF-8"))?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                transport::validate_path(&name)?;
                files.insert(name);
            } else {
                return Err(invalid(
                    "restored workspace contains a link or special file",
                ));
            }
        }
    }
    Ok(files)
}

fn canonical_destination(path: &Path) -> AppResult<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| invalid("restore requires a new workspace directory name"))?;
    transport::validate_path(
        name.to_str()
            .ok_or_else(|| invalid("destination is not UTF-8"))?,
    )?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !real_directory(parent)? {
        return Err(invalid("restore parent must be an existing real directory"));
    }
    Ok(fs::canonicalize(parent)?.join(name))
}

fn real_directory(path: &Path) -> AppResult<bool> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Ok(false);
        }
    }
    Ok(metadata.is_dir() && !metadata.file_type().is_symlink())
}

fn private_directories(path: &Path) -> AppResult<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

fn read_private_input(path: &Path, limit: u64) -> AppResult<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > limit {
        return Err(invalid("archive input is not a bounded regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.nlink() != 1 {
            return Err(invalid("archive input must not have hard links"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if before.file_attributes() & 0x400 != 0 {
            return Err(invalid("archive input must not be a reparse point"));
        }
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || after.len() != before.len()
        || after.modified()? != before.modified()?
    {
        return Err(invalid("archive input changed while being read"));
    }
    Ok(bytes)
}

fn hash_file(path: &Path) -> AppResult<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.len() > transport::MAX_ARCHIVE_DECOMPRESSED_BYTES + 128 * 1024 * 1024
    {
        return Err(invalid("invalid file for archive digest"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.nlink() != 1 {
            return Err(invalid("archive digest input has hard links"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if before.file_attributes() & 0x400 != 0 {
            return Err(invalid("archive digest input is a reparse point"));
        }
    }
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        total += length as u64;
        if total > before.len() {
            return Err(invalid("file changed during archive digest"));
        }
        hash.update(&buffer[..length]);
    }
    let after = file.metadata()?;
    if total != before.len()
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        return Err(invalid("file changed during archive digest"));
    }
    Ok(hex::encode(hash.finalize()))
}
fn path_component(value: &str) -> AppResult<()> {
    transport::validate_path(value)?;
    if value.contains('/') {
        return Err(invalid("storage identity is not one path component"));
    }
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn invalid(message: &str) -> AppError {
    AppError::InvalidRequest(message.into())
}

fn sync_directories(root: &Path) -> AppResult<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_directories(&entry.path())?;
        }
    }
    sync_directory(root)
}

fn sync_directory(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    {
        fs::File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
