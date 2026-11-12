//! Opaque, downloadable originals for one terminal HTML report. Scanner HTML
//! never becomes markup or executable code in the enclosing product report.

use crate::artifact_store::read_verified_raw_artifact;
use crate::domain::{AssessmentCase, RawArtifact};
use crate::error::{AppError, AppResult};
use crate::export::{ExportOptions, RedactionProfile, validate_portable_archive_path};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{Cursor, Write};
use std::path::Path;
use zip::write::SimpleFileOptions;

// A standalone browser document must remain bounded even for huge scanner
// outputs. Larger evidence remains exportable through the streaming case bundle.
const MAX_HTML_ATTACHMENT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HTML_ATTACHMENT_FILES: usize = 10_000;

pub(crate) struct ReportAttachment {
    pub engine_id: String,
    pub engine_run_id: String,
    pub file_names: Vec<String>,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

/// Shared selection for preview, serialization, and export-history counts.
/// No disk reads or access to another run are needed for preview.
pub(crate) fn selected_artifacts<'a>(
    case: &'a AssessmentCase,
    run_id: &str,
    options: &ExportOptions,
) -> AppResult<Vec<&'a RawArtifact>> {
    if !options.include_raw_artifacts {
        return Ok(Vec::new());
    }
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .ok_or_else(|| AppError::InvalidRequest("attachment scan run was not found".into()))?;
    let artifacts = case
        .raw_artifacts
        .iter()
        .filter(|artifact| {
            artifact.run_id == run_id
                && !(options.redaction == RedactionProfile::Standard
                    && artifact.contains_sensitive_data)
        })
        .collect::<Vec<_>>();
    let mut total = 0u64;
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for artifact in &artifacts {
        let engine = run
            .engine_runs
            .iter()
            .find(|engine| engine.id == artifact.engine_run_id && engine.scan_run_id == run_id);
        if artifact.case_id != case.id
            || engine.is_none_or(|engine| !engine.raw_artifact_ids.contains(&artifact.id))
            || !ids.insert(&artifact.id)
        {
            return Err(AppError::InvalidRequest(
                "attachment does not belong to the selected scan task".into(),
            ));
        }
        let path = attachment_path(case, artifact)?;
        // ZIP extraction on Windows is case-insensitive. Do not create two
        // names that would overwrite one another or a file/directory collision.
        let key = format!("{}/{}", artifact.engine_run_id, path).to_lowercase();
        if !paths.insert(key) {
            return Err(AppError::InvalidRequest(
                "attachment filenames collide".into(),
            ));
        }
        total = total
            .checked_add(artifact.byte_length)
            .ok_or_else(too_large)?;
        if total > MAX_HTML_ATTACHMENT_BYTES || artifacts.len() > MAX_HTML_ATTACHMENT_FILES {
            return Err(too_large());
        }
    }
    for path in &paths {
        for (offset, _) in path.match_indices('/') {
            if paths.contains(&path[..offset]) {
                return Err(AppError::InvalidRequest(
                    "attachment file and directory names collide".into(),
                ));
            }
        }
    }
    Ok(artifacts)
}

fn too_large() -> AppError {
    AppError::InvalidRequest("Original files exceed the HTML attachment limit (64 MiB or 10,000 files). Save a technical case bundle with original files instead.".into())
}

fn attachment_path<'a>(case: &AssessmentCase, artifact: &'a RawArtifact) -> AppResult<&'a str> {
    validate_portable_archive_path(Path::new(&artifact.relative_path))?;
    let prefix = format!(
        "{}/{}/{}/",
        case.id, artifact.run_id, artifact.engine_run_id
    );
    let path = artifact
        .relative_path
        .strip_prefix(&prefix)
        .ok_or_else(|| {
            AppError::InvalidRequest("attachment path is outside its recorded scan task".into())
        })?;
    validate_portable_archive_path(Path::new(path))?;
    for part in path.split('/') {
        let stem = part
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ((stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.len() == 4
                && matches!(stem.as_bytes()[3], b'1'..=b'9'));
        if reserved
            || part.ends_with(['.', ' '])
            || part
                .chars()
                .any(|c| c.is_control() || "<>\"|?*".contains(c))
        {
            return Err(AppError::InvalidRequest(
                "attachment filename cannot be safely extracted on all supported platforms".into(),
            ));
        }
    }
    Ok(path)
}

pub(crate) fn build_attachments(
    case: &AssessmentCase,
    run_id: &str,
    options: &ExportOptions,
    artifact_root: &Path,
) -> AppResult<Vec<ReportAttachment>> {
    let artifacts = selected_artifacts(case, run_id, options)?;
    if artifacts.is_empty() {
        return Ok(Vec::new());
    }
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .expect("validated run");
    let mut attachments = Vec::new();
    for engine in &run.engine_runs {
        let mut selected = artifacts
            .iter()
            .copied()
            .filter(|a| a.engine_run_id == engine.id)
            .collect::<Vec<_>>();
        if selected.is_empty() {
            continue;
        }
        selected.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let zip_options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .last_modified_time(zip::DateTime::default())
            .unix_permissions(0o600);
        let mut records = Vec::new();
        let mut file_names = Vec::new();
        for artifact in selected {
            let path = attachment_path(case, artifact)?;
            // Preserve every byte and the original directory structure, including
            // HTML images, styles and sibling reports. Read/hash the same handle.
            let bytes =
                read_verified_raw_artifact(artifact_root, artifact, MAX_HTML_ATTACHMENT_BYTES)?;
            let zip_path = format!("files/{path}");
            zip.start_file(&zip_path, zip_options).map_err(zip_error)?;
            zip.write_all(&bytes)?;
            records.push(json!({
                "artifact_id": artifact.id, "path": zip_path,
                "sha256": artifact.sha256, "bytes": artifact.byte_length,
                "media_type": artifact.media_type,
            }));
            file_names.push(path.to_owned());
        }
        let manifest = serde_json::to_vec_pretty(&json!({
            "schema_version": "1", "case_id": case.id, "run_id": run_id,
            "engine_id": engine.engine_id, "engine_run_id": engine.id,
            "engine_version": engine.engine_version, "status": engine.status,
            "started_at": engine.started_at, "finished_at": engine.finished_at,
            "files": records,
        }))?;
        zip.start_file("manifest.json", zip_options)
            .map_err(zip_error)?;
        zip.write_all(&manifest)?;
        zip.start_file("README.txt", zip_options)
            .map_err(zip_error)?;
        zip.write_all(b"Original scanner files from the selected scan run.\nExtract the entire ZIP before opening an HTML report under files/.\nFiles retain their original bytes and relative directories. Some scanners produce JSON, XML, or logs instead of HTML.\nSee manifest.json for scanner outcome, timestamps, file paths, and SHA-256 hashes. A retained file does not imply that its check completed.\nThese unredacted files may contain sensitive information.\n")?;
        let bytes = zip.finish().map_err(zip_error)?.into_inner();
        let sha256 = hex::encode(Sha256::digest(&bytes));
        attachments.push(ReportAttachment {
            engine_id: engine.engine_id.clone(),
            engine_run_id: engine.id.clone(),
            file_names,
            bytes,
            sha256,
        });
    }
    Ok(attachments)
}

fn zip_error(error: zip::result::ZipError) -> AppError {
    AppError::InvalidRequest(format!("original files could not be attached: {error}"))
}
