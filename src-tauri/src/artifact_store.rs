use crate::domain::{RawArtifact, new_id};
use crate::error::{AppError, AppResult};
use crate::naabu_work_plan::MAX_NAABU_WORK_UNITS;
use chrono::Utc;
use fs2::FileExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const HASH_BUFFER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_OUTPUT_FILES: usize = 10_000;
const MAX_LAUNCHER_V2_CONTEXT_COMPONENT_BYTES: usize = 128;
const MAX_LAUNCHER_V2_OUTPUT_RELATIVE_PATH_BYTES: usize = 512;
const LAUNCHER_V2_UNIT_ORDINAL_DIGITS: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactContext {
    pub case_id: String,
    pub scan_run_id: String,
    pub engine_run_id: String,
}

/// Exact, filesystem-independent classification of one captured launcher-v2
/// output artifact. Paths in these variants are relative to the invocation's
/// `/output` mount, not to the case artifact root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherV2OutputArtifact<'a> {
    Journal {
        output_relative_path: &'a str,
    },
    Final {
        output_relative_path: &'a str,
        unit_ordinal: u32,
        attempt: u32,
    },
    Quarantine {
        output_relative_path: &'a str,
        unit_ordinal: u32,
        attempt: u32,
    },
    Other,
}

/// Classifies only the fixed launcher-v2 namespace belonging to the exact
/// case/run/engine/attempt tuple. This intentionally parses the portable `/`
/// contract directly instead of applying host-specific path semantics.
///
/// Unknown, malformed, legacy, runtime-stream, and staging paths are ordinary
/// retained raw artifacts represented by [`LauncherV2OutputArtifact::Other`].
pub fn classify_launcher_v2_output_artifact<'a>(
    context: &ArtifactContext,
    attempt: u32,
    artifact: &'a RawArtifact,
) -> LauncherV2OutputArtifact<'a> {
    if attempt == 0
        || artifact.case_id != context.case_id
        || artifact.run_id != context.scan_run_id
        || artifact.engine_run_id != context.engine_run_id
        || !launcher_v2_context_component(&context.case_id)
        || !launcher_v2_context_component(&context.scan_run_id)
        || !launcher_v2_context_component(&context.engine_run_id)
    {
        return LauncherV2OutputArtifact::Other;
    }

    let output_prefix = format!(
        "{}/{}/{}/attempt-{attempt}/output/",
        context.case_id, context.scan_run_id, context.engine_run_id
    );
    let Some(relative) = artifact.relative_path.strip_prefix(&output_prefix) else {
        return LauncherV2OutputArtifact::Other;
    };
    if !bounded_portable_launcher_v2_path(relative) {
        return LauncherV2OutputArtifact::Other;
    }
    if relative == "launcher-v2/journal.jsonl" {
        return LauncherV2OutputArtifact::Journal {
            output_relative_path: relative,
        };
    }

    let components = relative.split('/').collect::<Vec<_>>();
    if components.len() != 4 || components[0] != "launcher-v2" {
        return LauncherV2OutputArtifact::Other;
    }
    let Some(unit_ordinal) = parse_launcher_v2_unit_ordinal(components[2]) else {
        return LauncherV2OutputArtifact::Other;
    };
    match components[1] {
        "units" if components[3] == format!("attempt-{attempt}.jsonl") => {
            LauncherV2OutputArtifact::Final {
                output_relative_path: relative,
                unit_ordinal,
                attempt,
            }
        }
        "quarantine" if components[3] == format!("attempt-{attempt}.raw.jsonl") => {
            LauncherV2OutputArtifact::Quarantine {
                output_relative_path: relative,
                unit_ordinal,
                attempt,
            }
        }
        _ => LauncherV2OutputArtifact::Other,
    }
}

fn launcher_v2_context_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LAUNCHER_V2_CONTEXT_COMPONENT_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn bounded_portable_launcher_v2_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LAUNCHER_V2_OUTPUT_RELATIVE_PATH_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        && value
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

fn parse_launcher_v2_unit_ordinal(value: &str) -> Option<u32> {
    let digits = value.strip_prefix("unit-")?;
    if digits.len() != LAUNCHER_V2_UNIT_ORDINAL_DIGITS
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let ordinal = digits.parse::<u32>().ok()?;
    (usize::try_from(ordinal).ok()? < MAX_NAABU_WORK_UNITS).then_some(ordinal)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDirectories {
    pub root: PathBuf,
    pub workspace: PathBuf,
    pub output: PathBuf,
    pub control: PathBuf,
    pub raw: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CapturePaths {
    artifact_root: PathBuf,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    stdout_file: Arc<File>,
    stderr_file: Arc<File>,
    active_writers: Arc<AtomicUsize>,
}

impl PartialEq for CapturePaths {
    fn eq(&self, other: &Self) -> bool {
        self.stdout == other.stdout && self.stderr == other.stderr
    }
}

impl Eq for CapturePaths {}

impl CapturePaths {
    /// Clone the already-open, verified product capture files for one runtime
    /// invocation. No path is reopened here: a later path replacement cannot
    /// redirect scanner output to another file or reparse point.
    pub(crate) fn clone_empty_writers(&self) -> AppResult<(CaptureWriter, CaptureWriter)> {
        let stdout = clone_empty_capture_file(&self.stdout_file, "stdout")?;
        let stderr = clone_empty_capture_file(&self.stderr_file, "stderr")?;
        self.active_writers.fetch_add(2, Ordering::AcqRel);
        Ok((
            CaptureWriter::new(stdout, self.active_writers.clone()),
            CaptureWriter::new(stderr, self.active_writers.clone()),
        ))
    }

    /// Reads at most `maximum_bytes` from the end of this invocation's already
    /// verified stderr capture. The retained file handle prevents a path swap
    /// from redirecting classification to unrelated data.
    pub(crate) fn read_stderr_tail(&self, maximum_bytes: usize) -> std::io::Result<Vec<u8>> {
        verify_capture_path_identity(&self.artifact_root, &self.stderr, &self.stderr_file)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let mut file = self.stderr_file.try_clone()?;
        let length = file.metadata()?.len();
        let maximum_bytes = u64::try_from(maximum_bytes).unwrap_or(u64::MAX);
        file.seek(SeekFrom::Start(length.saturating_sub(maximum_bytes)))?;
        let mut bytes = Vec::with_capacity(usize::try_from(length.min(maximum_bytes)).unwrap_or(0));
        file.take(maximum_bytes).read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

pub(crate) struct CaptureWriter {
    file: File,
    active_writers: Arc<AtomicUsize>,
}

impl CaptureWriter {
    fn new(file: File, active_writers: Arc<AtomicUsize>) -> Self {
        Self {
            file,
            active_writers,
        }
    }

    pub(crate) fn sync_all(&self) -> std::io::Result<()> {
        self.file.sync_all()
    }
}

impl Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.file.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Drop for CaptureWriter {
    fn drop(&mut self) {
        let previous = self.active_writers.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "capture writer count underflowed");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFile {
    pub path: PathBuf,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
    max_output_files: usize,
}

/// Read and verify already-captured raw artifacts without changing the
/// filesystem. This is intentionally separate from [`ArtifactStore::open`],
/// which creates and restricts the artifact root for new executions.
///
/// The caller can use this before persisting a resume attempt, then call it
/// again immediately before consuming the artifacts to close the ordinary
/// time-of-check/time-of-use window as far as a portable path-based API can.
pub fn inspect_raw_artifacts(artifact_root: &Path, artifacts: &[RawArtifact]) -> AppResult<()> {
    let root = verified_artifact_root(artifact_root)?;
    for artifact in artifacts {
        let file = open_verified_raw_artifact_at_root(&root, artifact)?;
        let (observed_sha256, observed_length) =
            hash_opened_file_bounded(file, artifact.byte_length + 1).map_err(|error| {
                AppError::Runtime(format!(
                    "artifact {} could not be hashed for durable reconciliation: {error}",
                    artifact.id
                ))
            })?;
        if observed_length != artifact.byte_length {
            return Err(AppError::Runtime(format!(
                "artifact {} byte length changed while it was being inspected",
                artifact.id
            )));
        }
        if !observed_sha256.eq_ignore_ascii_case(&artifact.sha256) {
            return Err(AppError::Runtime(format!(
                "artifact {} hash differs from its durable record",
                artifact.id
            )));
        }
    }

    Ok(())
}

/// Reads one already-captured raw artifact through the same no-follow,
/// bounded verification used by [`inspect_raw_artifacts`]. The returned bytes
/// and digest come from the same opened handle, so a caller never validates a
/// durable record and then consumes a separately reopened path.
pub fn read_verified_raw_artifact(
    artifact_root: &Path,
    artifact: &RawArtifact,
    maximum_bytes: u64,
) -> AppResult<Vec<u8>> {
    if artifact.byte_length > maximum_bytes {
        return Err(AppError::Runtime(format!(
            "artifact {} exceeds its bounded read limit",
            artifact.id
        )));
    }
    let root = verified_artifact_root(artifact_root)?;
    let file = open_verified_raw_artifact_at_root(&root, artifact)?;
    let capacity = usize::try_from(artifact.byte_length).map_err(|_| {
        AppError::Runtime(format!(
            "artifact {} byte length cannot be represented on this host",
            artifact.id
        ))
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            AppError::Runtime(format!(
                "artifact {} could not be read for durable reconciliation: {error}",
                artifact.id
            ))
        })?;
    if bytes.len() as u64 != artifact.byte_length {
        return Err(AppError::Runtime(format!(
            "artifact {} byte length changed while it was being read",
            artifact.id
        )));
    }
    let observed_sha256 = hex::encode(Sha256::digest(&bytes));
    if !observed_sha256.eq_ignore_ascii_case(&artifact.sha256) {
        return Err(AppError::Runtime(format!(
            "artifact {} hash differs from its durable record",
            artifact.id
        )));
    }
    Ok(bytes)
}

impl ArtifactStore {
    pub fn open(root: impl AsRef<Path>) -> AppResult<Self> {
        let root = root.as_ref();
        match fs::symlink_metadata(root) {
            Ok(metadata) if !metadata_is_directory_non_reparse(&metadata) => {
                return Err(AppError::NotAuthorized(format!(
                    "artifact root is not a regular non-reparse directory: {}",
                    root.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = root.parent().ok_or_else(|| {
                    AppError::InvalidRequest("artifact root must have a parent directory".into())
                })?;
                fs::create_dir_all(parent)?;
                match fs::create_dir(root) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
                let metadata = fs::symlink_metadata(root)?;
                if !metadata_is_directory_non_reparse(&metadata) {
                    return Err(AppError::NotAuthorized(format!(
                        "artifact root changed into a reparse path while it was created: {}",
                        root.display()
                    )));
                }
            }
            Err(error) => return Err(error.into()),
        }
        let root = fs::canonicalize(root).map_err(|error| {
            AppError::Runtime(format!(
                "artifact root {} could not be resolved: {error}",
                root.display()
            ))
        })?;
        restrict_open_directory(&root)?;
        Ok(Self {
            root,
            max_output_files: DEFAULT_MAX_OUTPUT_FILES,
        })
    }

    #[cfg(test)]
    pub fn with_max_output_files(mut self, max_output_files: usize) -> Self {
        self.max_output_files = max_output_files;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn prepare_run(
        &self,
        context: &ArtifactContext,
        attempt: u32,
    ) -> AppResult<RunDirectories> {
        if attempt == 0 {
            return Err(AppError::InvalidRequest(
                "engine execution attempt must start at one".into(),
            ));
        }

        let case_id = safe_component("case id", &context.case_id)?;
        let scan_run_id = safe_component("scan run id", &context.scan_run_id)?;
        let engine_run_id = safe_component("engine run id", &context.engine_run_id)?;
        let mut root = self.root.clone();
        for component in [
            case_id.to_owned(),
            scan_run_id.to_owned(),
            engine_run_id.to_owned(),
            format!("attempt-{attempt}"),
        ] {
            root = prepare_private_directory_component(&self.root, &root, &component)?;
        }
        let workspace = prepare_private_directory_component(&self.root, &root, "workspace")?;
        let output = prepare_private_directory_component(&self.root, &root, "output")?;
        let control = prepare_private_directory_component(&self.root, &root, "control")?;
        let raw = prepare_private_directory_component(&self.root, &root, "raw")?;
        let directories = RunDirectories {
            workspace,
            output,
            control,
            raw,
            root,
        };

        Ok(directories)
    }

    pub fn prepare_capture(&self, directories: &RunDirectories) -> AppResult<CapturePaths> {
        self.ensure_inside_root(&directories.raw)?;
        let stdout = directories.raw.join("stdout.log");
        let stderr = directories.raw.join("stderr.log");
        let stdout_file = create_or_reuse_empty_private_capture_file(&stdout)?;
        let stderr_file = create_or_reuse_empty_private_capture_file(&stderr)?;
        verify_capture_path_identity(&self.root, &stdout, &stdout_file)?;
        verify_capture_path_identity(&self.root, &stderr, &stderr_file)?;
        restrict_open_file(&stdout_file)?;
        restrict_open_file(&stderr_file)?;
        Ok(CapturePaths {
            artifact_root: self.root.clone(),
            stdout,
            stderr,
            stdout_file: Arc::new(stdout_file),
            stderr_file: Arc::new(stderr_file),
            active_writers: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn write_control_json<T: Serialize>(
        &self,
        directories: &RunDirectories,
        name: &str,
        value: &T,
    ) -> AppResult<ControlFile> {
        let name = safe_filename(name)?;
        let path = directories.control.join(name);
        self.ensure_inside_root(&directories.control)?;
        let bytes = serde_json::to_vec(value).map_err(|error| {
            AppError::Runtime(format!("control document could not be encoded: {error}"))
        })?;
        publish_or_reuse_private_control_file(&self.root, &path, &bytes)?;
        self.ensure_inside_root(&path)?;
        Ok(ControlFile {
            path,
            sha256: sha256_bytes(&bytes),
            byte_length: bytes.len() as u64,
        })
    }

    pub fn finalize_capture(
        &self,
        context: &ArtifactContext,
        capture: &CapturePaths,
    ) -> AppResult<Vec<RawArtifact>> {
        if capture.active_writers.load(Ordering::Acquire) != 0 {
            return Err(AppError::Conflict(
                "capture output is still being written; finalization was deferred".into(),
            ));
        }
        Ok(vec![
            self.describe_capture_file(
                context,
                &capture.stdout,
                &capture.stdout_file,
                "text/plain; charset=utf-8",
            )?,
            self.describe_capture_file(
                context,
                &capture.stderr,
                &capture.stderr_file,
                "text/plain; charset=utf-8",
            )?,
        ])
    }

    fn describe_capture_file(
        &self,
        context: &ArtifactContext,
        path: &Path,
        held_file: &File,
        media_type: &str,
    ) -> AppResult<RawArtifact> {
        let mut held = held_file.try_clone()?;
        held.seek(SeekFrom::Start(0))?;
        let held_length = held.metadata()?.len();
        let (sha256, byte_length) = hash_opened_file_bounded(held, held_length.saturating_add(1))?;
        if byte_length != held_length {
            return Err(AppError::Conflict(format!(
                "capture changed while it was finalized: {}",
                path.display()
            )));
        }

        // The durable artifact path must still name the exact bytes written
        // through the retained handle. A replacement symlink/reparse point is
        // refused without opening its target; a replacement regular file is
        // accepted only if its bounded bytes are identical.
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            AppError::Runtime(format!(
                "capture {} could not be inspected: {error}",
                path.display()
            ))
        })?;
        if !metadata_is_regular_non_reparse(&metadata) {
            return Err(AppError::NotAuthorized(format!(
                "capture path changed and is not a regular non-reparse file: {}",
                path.display()
            )));
        }
        let canonical = fs::canonicalize(path)?;
        self.ensure_inside_root(&canonical)?;
        let path_file = open_readonly_no_follow(path)?;
        let path_metadata = path_file.metadata()?;
        if !metadata_is_regular_non_reparse(&path_metadata)
            || path_metadata.len() != held_length
            || !opened_files_have_same_identity(held_file, &path_file)?
        {
            return Err(AppError::Conflict(format!(
                "capture path no longer identifies the prepared output: {}",
                path.display()
            )));
        }
        let (path_sha256, path_length) =
            hash_opened_file_bounded(path_file, held_length.saturating_add(1))?;
        if path_length != byte_length || path_sha256 != sha256 {
            return Err(AppError::Conflict(format!(
                "capture path no longer identifies the prepared output: {}",
                path.display()
            )));
        }
        let relative_path = canonical
            .strip_prefix(&self.root)
            .map_err(|_| {
                AppError::Runtime(format!(
                    "capture escaped the private artifact root: {}",
                    canonical.display()
                ))
            })?
            .to_string_lossy()
            .replace('\\', "/");

        Ok(RawArtifact {
            id: new_id(),
            case_id: context.case_id.clone(),
            run_id: context.scan_run_id.clone(),
            engine_run_id: context.engine_run_id.clone(),
            relative_path,
            media_type: media_type.to_owned(),
            sha256,
            byte_length,
            created_at: Utc::now(),
            contains_sensitive_data: true,
        })
    }

    pub fn collect_output_artifacts(
        &self,
        context: &ArtifactContext,
        directories: &RunDirectories,
    ) -> AppResult<Vec<RawArtifact>> {
        self.ensure_inside_root(&directories.output)?;
        let mut files = Vec::new();
        collect_regular_files(&directories.output, &mut files, self.max_output_files)?;
        files.sort();
        files
            .iter()
            .map(|path| self.describe_file(context, path, media_type_for_path(path), true))
            .collect()
    }

    pub fn describe_file(
        &self,
        context: &ArtifactContext,
        path: &Path,
        media_type: &str,
        contains_sensitive_data: bool,
    ) -> AppResult<RawArtifact> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            AppError::Runtime(format!(
                "artifact {} could not be inspected: {error}",
                path.display()
            ))
        })?;
        if !metadata_is_regular_non_reparse(&metadata) {
            return Err(AppError::Runtime(format!(
                "artifact must be a regular non-reparse file: {}",
                path.display()
            )));
        }

        let canonical = fs::canonicalize(path)?;
        self.ensure_inside_root(&canonical)?;
        let file = open_readonly_no_follow(path)?;
        if !metadata_is_regular_non_reparse(&file.metadata()?) {
            return Err(AppError::Conflict(format!(
                "artifact changed while it was opened: {}",
                path.display()
            )));
        }
        let maximum = metadata.len().saturating_add(1);
        let (sha256, byte_length) = hash_opened_file_bounded(file, maximum)?;
        if byte_length != metadata.len() {
            return Err(AppError::Conflict(format!(
                "artifact changed while it was hashed: {}",
                path.display()
            )));
        }
        let relative_path = canonical
            .strip_prefix(&self.root)
            .map_err(|_| {
                AppError::Runtime(format!(
                    "artifact escaped the private artifact root: {}",
                    canonical.display()
                ))
            })?
            .to_string_lossy()
            .replace('\\', "/");

        Ok(RawArtifact {
            id: new_id(),
            case_id: context.case_id.clone(),
            run_id: context.scan_run_id.clone(),
            engine_run_id: context.engine_run_id.clone(),
            relative_path,
            media_type: media_type.to_owned(),
            sha256,
            byte_length,
            created_at: Utc::now(),
            contains_sensitive_data,
        })
    }

    fn ensure_inside_root(&self, path: &Path) -> AppResult<()> {
        let canonical = fs::canonicalize(path).map_err(|error| {
            AppError::Runtime(format!(
                "artifact path {} could not be resolved: {error}",
                path.display()
            ))
        })?;
        if !canonical.starts_with(&self.root) {
            return Err(AppError::Runtime(format!(
                "artifact path is outside the private artifact root: {}",
                path.display()
            )));
        }
        Ok(())
    }
}

fn collect_regular_files(
    directory: &Path,
    files: &mut Vec<PathBuf>,
    max_files: usize,
) -> AppResult<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_symlink() {
            return Err(AppError::Runtime(format!(
                "scanner output may not contain symlinks: {}",
                path.display()
            )));
        }
        if file_type.is_dir() {
            collect_regular_files(&path, files, max_files)?;
        } else if file_type.is_file() {
            files.push(path);
            if files.len() > max_files {
                return Err(AppError::Runtime(format!(
                    "scanner output exceeded the artifact limit of {max_files} files"
                )));
            }
        } else {
            return Err(AppError::Runtime(format!(
                "scanner output contains an unsupported filesystem entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn prepare_private_directory_component(
    artifact_root: &Path,
    parent: &Path,
    component: &str,
) -> AppResult<PathBuf> {
    let parent_metadata = fs::symlink_metadata(parent).map_err(|error| {
        AppError::Runtime(format!(
            "private artifact parent {} could not be inspected: {error}",
            parent.display()
        ))
    })?;
    if !metadata_is_directory_non_reparse(&parent_metadata) {
        return Err(AppError::NotAuthorized(format!(
            "private artifact parent is not a regular non-reparse directory: {}",
            parent.display()
        )));
    }
    let canonical_parent = fs::canonicalize(parent)?;
    if !canonical_parent.starts_with(artifact_root) {
        return Err(AppError::NotAuthorized(format!(
            "private artifact parent escaped the artifact root: {}",
            parent.display()
        )));
    }

    let path = canonical_parent.join(component);
    match fs::create_dir(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(AppError::Runtime(format!(
                "private artifact directory {} could not be created: {error}",
                path.display()
            )));
        }
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata_is_directory_non_reparse(&metadata) {
        return Err(AppError::NotAuthorized(format!(
            "private artifact path is not a regular non-reparse directory: {}",
            path.display()
        )));
    }
    let canonical = fs::canonicalize(&path)?;
    if !canonical.starts_with(artifact_root) {
        return Err(AppError::NotAuthorized(format!(
            "private artifact directory escaped the artifact root: {}",
            path.display()
        )));
    }
    restrict_open_directory(&canonical)?;
    Ok(canonical)
}

fn safe_component<'a>(label: &str, value: &'a str) -> AppResult<&'a str> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AppError::InvalidRequest(format!(
            "{label} contains unsafe path characters"
        )));
    }
    Ok(value)
}

fn safe_filename(value: &str) -> AppResult<&str> {
    let path = Path::new(value);
    let mut components = path.components();
    let is_single_normal =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if !is_single_normal || value.is_empty() || value.contains(['/', '\\', '\0']) {
        return Err(AppError::InvalidRequest(
            "control filename must be a single safe path component".into(),
        ));
    }
    Ok(value)
}

fn normalized_artifact_relative_path(artifact: &RawArtifact) -> AppResult<&Path> {
    let relative = Path::new(&artifact.relative_path);
    let slash_components_are_normal = !artifact.relative_path.is_empty()
        && !artifact.relative_path.contains(['\\', '\0'])
        && artifact
            .relative_path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..");
    if !slash_components_are_normal
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(unsafe_artifact_path(artifact));
    }
    Ok(relative)
}

fn unsafe_artifact_path(artifact: &RawArtifact) -> AppError {
    AppError::Runtime(format!(
        "artifact {} has an unsafe or non-normalized relative path",
        artifact.id
    ))
}

fn verified_artifact_root(artifact_root: &Path) -> AppResult<PathBuf> {
    let root_metadata = fs::symlink_metadata(artifact_root).map_err(|error| {
        AppError::Runtime(format!(
            "artifact root {} is unavailable: {error}",
            artifact_root.display()
        ))
    })?;
    if !metadata_is_directory_non_reparse(&root_metadata) {
        return Err(AppError::Runtime(format!(
            "artifact root {} must be an existing non-symlink directory",
            artifact_root.display()
        )));
    }
    fs::canonicalize(artifact_root).map_err(|error| {
        AppError::Runtime(format!(
            "artifact root {} could not be resolved: {error}",
            artifact_root.display()
        ))
    })
}

fn open_verified_raw_artifact_at_root(root: &Path, artifact: &RawArtifact) -> AppResult<File> {
    let relative = normalized_artifact_relative_path(artifact)?;
    if artifact.sha256.len() != 64
        || !artifact
            .sha256
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(AppError::Runtime(format!(
            "artifact {} has an invalid durable SHA-256 digest",
            artifact.id
        )));
    }
    if artifact.byte_length == u64::MAX {
        return Err(AppError::Runtime(format!(
            "artifact {} has an unsupported durable byte length",
            artifact.id
        )));
    }

    let mut path = root.to_path_buf();
    let component_count = relative.components().count();
    for (index, component) in relative.components().enumerate() {
        let Component::Normal(component) = component else {
            return Err(unsafe_artifact_path(artifact));
        };
        path.push(component);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            AppError::Runtime(format!(
                "artifact {} is not available for durable reconciliation: {error}",
                artifact.id
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(AppError::Runtime(format!(
                "artifact {} path may not contain symlinks",
                artifact.id
            )));
        }
        if index + 1 == component_count {
            if !metadata_is_regular_non_reparse(&metadata) {
                return Err(AppError::Runtime(format!(
                    "artifact {} must be a regular non-reparse file",
                    artifact.id
                )));
            }
            if metadata.len() != artifact.byte_length {
                return Err(AppError::Runtime(format!(
                    "artifact {} byte length differs from its durable record",
                    artifact.id
                )));
            }
        } else if !metadata_is_directory_non_reparse(&metadata) {
            return Err(AppError::Runtime(format!(
                "artifact {} path contains a non-directory or reparse component",
                artifact.id
            )));
        }
    }

    let canonical = fs::canonicalize(&path).map_err(|error| {
        AppError::Runtime(format!(
            "artifact {} could not be resolved for durable reconciliation: {error}",
            artifact.id
        ))
    })?;
    if !canonical.starts_with(root) {
        return Err(AppError::Runtime(format!(
            "artifact {} escapes the private artifact root",
            artifact.id
        )));
    }

    let file = open_readonly_no_follow(&path).map_err(|error| {
        AppError::Runtime(format!(
            "artifact {} could not be opened for durable reconciliation: {error}",
            artifact.id
        ))
    })?;
    let opened_metadata = file.metadata().map_err(|error| {
        AppError::Runtime(format!(
            "artifact {} metadata could not be read after opening: {error}",
            artifact.id
        ))
    })?;
    if !metadata_is_regular_non_reparse(&opened_metadata) {
        return Err(AppError::Runtime(format!(
            "artifact {} changed and is no longer a regular non-reparse file",
            artifact.id
        )));
    }
    if opened_metadata.len() != artifact.byte_length {
        return Err(AppError::Runtime(format!(
            "artifact {} byte length differs from its durable record",
            artifact.id
        )));
    }
    Ok(file)
}

fn open_readonly_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn open_read_append_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn open_read_write_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn metadata_is_regular_non_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    let is_reparse_point = {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    };
    #[cfg(not(windows))]
    let is_reparse_point = false;
    metadata.is_file() && !metadata.file_type().is_symlink() && !is_reparse_point
}

fn metadata_is_directory_non_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    let is_reparse_point = {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    };
    #[cfg(not(windows))]
    let is_reparse_point = false;
    metadata.is_dir() && !metadata.file_type().is_symlink() && !is_reparse_point
}

fn verify_capture_path_identity(root: &Path, path: &Path, held_file: &File) -> AppResult<()> {
    verify_open_path_identity(root, path, held_file, "private capture")
}

fn verify_control_path_identity(root: &Path, path: &Path, held_file: &File) -> AppResult<()> {
    verify_open_path_identity(root, path, held_file, "private control")
}

fn verify_open_path_identity(
    root: &Path,
    path: &Path,
    held_file: &File,
    label: &str,
) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata_is_regular_non_reparse(&metadata) {
        return Err(AppError::NotAuthorized(format!(
            "{label} path is not a regular non-reparse file: {}",
            path.display()
        )));
    }
    let canonical = fs::canonicalize(path)?;
    if !canonical.starts_with(root) {
        return Err(AppError::NotAuthorized(format!(
            "{label} path escaped the artifact root: {}",
            path.display()
        )));
    }
    let reopened = open_readonly_no_follow(path)?;
    if !metadata_is_regular_non_reparse(&reopened.metadata()?)
        || !opened_files_have_same_identity(held_file, &reopened)?
    {
        return Err(AppError::Conflict(format!(
            "{label} path changed while it was prepared: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn opened_files_have_same_identity(first: &File, second: &File) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let first = first.metadata()?;
    let second = second.metadata()?;
    Ok(first.dev() == second.dev() && first.ino() == second.ino())
}

#[cfg(windows)]
fn opened_files_have_same_identity(first: &File, second: &File) -> std::io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let identity = |file: &File| -> std::io::Result<(u32, u64)> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: file owns a valid handle and information is a correctly
        // sized writable BY_HANDLE_FILE_INFORMATION output buffer.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((
            information.dwVolumeSerialNumber,
            (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        ))
    };
    Ok(identity(first)? == identity(second)?)
}

#[cfg(not(any(unix, windows)))]
fn opened_files_have_same_identity(_first: &File, _second: &File) -> std::io::Result<bool> {
    Ok(false)
}

fn hash_opened_file_bounded(mut file: File, maximum_bytes: u64) -> std::io::Result<(String, u64)> {
    let mut digest = Sha256::new();
    let mut byte_length = 0_u64;
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    let mut reader = (&mut file).take(maximum_bytes);
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        byte_length += read as u64;
    }
    Ok((hex::encode(digest.finalize()), byte_length))
}

fn create_or_reuse_empty_private_capture_file(path: &Path) -> AppResult<File> {
    let mut create = OpenOptions::new();
    create.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        create.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    match create.open(path) {
        Ok(file) => {
            verify_empty_capture_handle(&file, path)?;
            Ok(file)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata_is_regular_non_reparse(&metadata) || metadata.len() != 0 {
                return Err(AppError::Conflict(format!(
                    "existing private capture file is not an empty product preflight file: {}",
                    path.display()
                )));
            }
            let file = open_read_write_no_follow(path).map_err(|error| {
                AppError::Runtime(format!(
                    "existing private capture file {} open failed: {error}",
                    path.display()
                ))
            })?;
            verify_empty_capture_handle(&file, path)?;
            Ok(file)
        }
        Err(error) => Err(AppError::Runtime(format!(
            "private artifact file {} could not be created: {error}",
            path.display()
        ))),
    }
}

fn clone_empty_capture_file(file: &File, stream: &str) -> AppResult<File> {
    let cloned = file.try_clone().map_err(|error| {
        AppError::Runtime(format!(
            "verified {stream} capture handle could not be cloned: {error}"
        ))
    })?;
    verify_empty_capture_handle(&cloned, Path::new(stream))?;
    Ok(cloned)
}

fn verify_empty_capture_handle(file: &File, display_path: &Path) -> AppResult<()> {
    let metadata = file.metadata()?;
    if !metadata_is_regular_non_reparse(&metadata) {
        return Err(AppError::NotAuthorized(format!(
            "private capture handle is not a regular non-reparse file: {}",
            display_path.display()
        )));
    }
    if metadata.len() != 0 {
        return Err(AppError::Conflict(format!(
            "existing private capture file is not an empty product preflight file: {}",
            display_path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_open_file(file: &File) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_open_file(_file: &File) -> AppResult<()> {
    Ok(())
}

/// Publishes a new immutable control document, or reuses the exact document
/// left by an interrupted invocation. Existing bytes are never replaced: an
/// interrupted regular file may only be completed when it is an exact prefix
/// of this invocation's document. The canonical file itself is locked,
/// synced, and finally reverified; an unused staging copy would add I/O but
/// cannot make direct canonical publication atomic on Windows.
fn publish_or_reuse_private_control_file(
    artifact_root: &Path,
    path: &Path,
    expected: &[u8],
) -> AppResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata_is_regular_non_reparse(&metadata)
                || metadata.len() >= expected.len() as u64
            {
                return verify_existing_private_control_file(artifact_root, path, expected);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(AppError::Runtime(format!(
                "private control file {} could not be inspected: {error}",
                path.display()
            )));
        }
    }

    let mut create = OpenOptions::new();
    create.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        create.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    match create.open(path) {
        Ok(mut canonical) => {
            verify_control_path_identity(artifact_root, path, &canonical)?;
            restrict_open_file(&canonical)?;
            canonical.try_lock_exclusive().map_err(|error| {
                AppError::Conflict(format!(
                    "private control file is already being published: {} ({error})",
                    path.display()
                ))
            })?;
            let result = (|| -> AppResult<()> {
                canonical.write_all(expected)?;
                canonical.sync_all()?;
                verify_open_control_file(&mut canonical, expected, path)?;
                restrict_open_readonly_file(&canonical)
            })();
            let _ = canonical.unlock();
            result
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            complete_interrupted_private_control_file(artifact_root, path, expected)
        }
        Err(error) => Err(AppError::Runtime(format!(
            "private control file {} could not be published: {error}",
            path.display()
        ))),
    }
}

fn complete_interrupted_private_control_file(
    artifact_root: &Path,
    path: &Path,
    expected: &[u8],
) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::Runtime(format!(
            "interrupted private control file {} could not be inspected: {error}",
            path.display()
        ))
    })?;
    if !metadata_is_regular_non_reparse(&metadata) {
        return Err(AppError::NotAuthorized(format!(
            "existing private control path is not a regular non-reparse file: {}",
            path.display()
        )));
    }

    let mut file = open_read_append_no_follow(path).map_err(|error| {
        AppError::Runtime(format!(
            "interrupted private control file {} open failed: {error}",
            path.display()
        ))
    })?;
    verify_control_path_identity(artifact_root, path, &file)?;
    file.try_lock_exclusive().map_err(|error| {
        AppError::Conflict(format!(
            "interrupted private control file is already being reconciled: {} ({error})",
            path.display()
        ))
    })?;
    let result = (|| -> AppResult<()> {
        let length = file.metadata()?.len();
        if length > expected.len() as u64 {
            return Err(AppError::Conflict(format!(
                "existing private control file does not match the exact expected document: {}",
                path.display()
            )));
        }
        file.seek(SeekFrom::Start(0))?;
        let mut observed = Vec::with_capacity(length as usize);
        (&mut file)
            .take((expected.len() as u64).saturating_add(1))
            .read_to_end(&mut observed)?;
        if !expected.starts_with(&observed) {
            return Err(AppError::Conflict(format!(
                "existing private control file does not match the exact expected document: {}",
                path.display()
            )));
        }
        if observed.len() < expected.len() {
            file.seek(SeekFrom::End(0))?;
            file.write_all(&expected[observed.len()..])?;
            file.sync_all()?;
        }
        verify_open_control_file(&mut file, expected, path)?;
        restrict_open_readonly_file(&file)
    })();
    let _ = file.unlock();
    result
}

fn verify_open_control_file(file: &mut File, expected: &[u8], path: &Path) -> AppResult<()> {
    let metadata = file.metadata()?;
    if !metadata_is_regular_non_reparse(&metadata) || metadata.len() != expected.len() as u64 {
        return Err(AppError::Conflict(format!(
            "existing private control file does not match the exact expected document: {}",
            path.display()
        )));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut observed = Vec::with_capacity(expected.len());
    file.take((expected.len() as u64).saturating_add(1))
        .read_to_end(&mut observed)?;
    if observed != expected {
        return Err(AppError::Conflict(format!(
            "existing private control file does not match the exact expected document: {}",
            path.display()
        )));
    }
    Ok(())
}

fn verify_existing_private_control_file(
    artifact_root: &Path,
    path: &Path,
    expected: &[u8],
) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::Runtime(format!(
            "existing private control file {} could not be inspected: {error}",
            path.display()
        ))
    })?;
    if !metadata_is_regular_non_reparse(&metadata) {
        return Err(AppError::NotAuthorized(format!(
            "existing private control path is not a regular non-reparse file: {}",
            path.display()
        )));
    }
    if metadata.len() != expected.len() as u64 {
        return Err(AppError::Conflict(format!(
            "existing private control file does not match the exact expected document: {}",
            path.display()
        )));
    }

    let already_readonly = metadata.permissions().readonly();
    let mut file = if already_readonly {
        open_readonly_no_follow(path)
    } else {
        open_read_write_no_follow(path)
    }
    .map_err(|error| {
        AppError::Runtime(format!(
            "existing private control file {} open failed: {error}",
            path.display()
        ))
    })?;
    verify_control_path_identity(artifact_root, path, &file)?;
    file.try_lock_exclusive().map_err(|error| {
        AppError::Conflict(format!(
            "existing private control file is still being published: {} ({error})",
            path.display()
        ))
    })?;
    let result = (|| -> AppResult<()> {
        let opened_metadata = file.metadata()?;
        if !metadata_is_regular_non_reparse(&opened_metadata)
            || opened_metadata.len() != expected.len() as u64
        {
            return Err(AppError::Conflict(format!(
                "existing private control file changed while it was inspected: {}",
                path.display()
            )));
        }
        let maximum = (expected.len() as u64).saturating_add(1);
        let mut observed = Vec::with_capacity(expected.len());
        (&mut file).take(maximum).read_to_end(&mut observed)?;
        if observed != expected {
            return Err(AppError::Conflict(format!(
                "existing private control file does not match the exact expected document: {}",
                path.display()
            )));
        }
        if !already_readonly {
            restrict_open_readonly_file(&file)?;
        }
        Ok(())
    })();
    let _ = file.unlock();
    result
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn media_type_for_path(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "json" => "application/json",
        "jsonl" | "ndjson" => "application/x-ndjson",
        "csv" => "text/csv",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "sarif" => "application/sarif+json",
        "spdx" => "application/spdx+json",
        "txt" | "log" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(unix)]
fn restrict_open_directory(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !metadata_is_directory_non_reparse(&directory.metadata()?) {
        return Err(AppError::NotAuthorized(format!(
            "private artifact directory changed before it could be restricted: {}",
            path.display()
        )));
    }
    directory.set_permissions(fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_open_directory(path: &Path) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata_is_directory_non_reparse(&metadata) {
        return Err(AppError::NotAuthorized(format!(
            "private artifact directory changed before it could be verified: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_open_readonly_file(file: &File) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_open_readonly_file(file: &File) -> AppResult<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(true);
    file.set_permissions(permissions)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_artifact(relative_path: &str, bytes: &[u8]) -> RawArtifact {
        RawArtifact {
            id: "artifact-1".into(),
            case_id: "case-1".into(),
            run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            relative_path: relative_path.into(),
            media_type: "application/octet-stream".into(),
            sha256: sha256_bytes(bytes),
            byte_length: bytes.len() as u64,
            created_at: Utc::now(),
            contains_sensitive_data: true,
        }
    }

    fn write_raw_artifact(root: &Path, relative_path: &str, bytes: &[u8]) {
        let path = root.join(relative_path);
        fs::create_dir_all(path.parent().expect("artifact parent")).expect("artifact directories");
        fs::write(path, bytes).expect("artifact bytes");
    }

    fn context() -> ArtifactContext {
        ArtifactContext {
            case_id: "case-1".into(),
            scan_run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
        }
    }

    fn launcher_v2_artifact(output_relative_path: &str, attempt: u32) -> RawArtifact {
        let context = context();
        raw_artifact(
            &format!(
                "{}/{}/{}/attempt-{attempt}/output/{output_relative_path}",
                context.case_id, context.scan_run_id, context.engine_run_id
            ),
            b"launcher evidence",
        )
    }

    #[test]
    fn launcher_v2_classifier_returns_exact_typed_artifacts() {
        let context = context();
        let journal = launcher_v2_artifact("launcher-v2/journal.jsonl", 7);
        let final_artifact =
            launcher_v2_artifact("launcher-v2/units/unit-000042/attempt-7.jsonl", 7);
        let quarantine =
            launcher_v2_artifact("launcher-v2/quarantine/unit-000009/attempt-7.raw.jsonl", 7);

        assert_eq!(
            classify_launcher_v2_output_artifact(&context, 7, &journal),
            LauncherV2OutputArtifact::Journal {
                output_relative_path: "launcher-v2/journal.jsonl"
            }
        );
        assert_eq!(
            classify_launcher_v2_output_artifact(&context, 7, &final_artifact),
            LauncherV2OutputArtifact::Final {
                output_relative_path: "launcher-v2/units/unit-000042/attempt-7.jsonl",
                unit_ordinal: 42,
                attempt: 7,
            }
        );
        assert_eq!(
            classify_launcher_v2_output_artifact(&context, 7, &quarantine),
            LauncherV2OutputArtifact::Quarantine {
                output_relative_path: "launcher-v2/quarantine/unit-000009/attempt-7.raw.jsonl",
                unit_ordinal: 9,
                attempt: 7,
            }
        );
    }

    #[test]
    fn launcher_v2_classifier_rejects_near_matches_and_nonportable_paths() {
        let context = context();
        for relative in [
            "launcher-v2/journal.jsonl.partial",
            "launcher-v2/journal.jsonl/extra",
            "launcher-v2/units/unit-42/attempt-7.jsonl",
            "launcher-v2/units/unit-0000042/attempt-7.jsonl",
            "launcher-v2/units/unit-000512/attempt-7.jsonl",
            "launcher-v2/units/unit-999999/attempt-7.jsonl",
            "launcher-v2/units/unit-00004x/attempt-7.jsonl",
            "launcher-v2/units/unit-000042/attempt-07.jsonl",
            "launcher-v2/units/unit-000042/attempt-8.jsonl",
            "launcher-v2/units/unit-000042/attempt-7.jsonl.partial",
            "launcher-v2/units/unit-000042/attempt-7.jsonl/extra",
            "launcher-v2/quarantine/unit-000042/attempt-7.jsonl",
            "launcher-v2/quarantine/unit-000042/attempt-7.raw.jsonl.partial",
            "launcher-v2/units/../unit-000042/attempt-7.jsonl",
            "launcher-v2//units/unit-000042/attempt-7.jsonl",
            "launcher-v2\\units\\unit-000042\\attempt-7.jsonl",
            "/launcher-v2/units/unit-000042/attempt-7.jsonl",
            "launcher-v2/units/unit-000042/attempt-7.jsonl/",
            "raw/stdout.log",
            "raw/stderr.log",
        ] {
            let artifact = launcher_v2_artifact(relative, 7);
            assert_eq!(
                classify_launcher_v2_output_artifact(&context, 7, &artifact),
                LauncherV2OutputArtifact::Other,
                "unexpected classification for {relative}"
            );
        }
    }

    #[test]
    fn launcher_v2_classifier_requires_exact_context_and_attempt_directory() {
        let context = context();
        let exact = launcher_v2_artifact("launcher-v2/journal.jsonl", 7);

        let wrong_attempt_directory = launcher_v2_artifact("launcher-v2/journal.jsonl", 8);
        assert_eq!(
            classify_launcher_v2_output_artifact(&context, 7, &wrong_attempt_directory),
            LauncherV2OutputArtifact::Other
        );
        assert_eq!(
            classify_launcher_v2_output_artifact(&context, 0, &exact),
            LauncherV2OutputArtifact::Other
        );

        let mut wrong_provenance = exact.clone();
        wrong_provenance.engine_run_id = "engine-run-2".into();
        assert_eq!(
            classify_launcher_v2_output_artifact(&context, 7, &wrong_provenance),
            LauncherV2OutputArtifact::Other
        );

        let mut wrong_context = context.clone();
        wrong_context.case_id = "case-2".into();
        assert_eq!(
            classify_launcher_v2_output_artifact(&wrong_context, 7, &exact),
            LauncherV2OutputArtifact::Other
        );

        let alternate_separator = raw_artifact(
            "case-1\\run-1\\engine-run-1\\attempt-7\\output\\launcher-v2\\journal.jsonl",
            b"launcher evidence",
        );
        assert_eq!(
            classify_launcher_v2_output_artifact(&context, 7, &alternate_separator),
            LauncherV2OutputArtifact::Other
        );

        let runtime_stdout = raw_artifact(
            "case-1/run-1/engine-run-1/attempt-7/raw/stdout.log",
            b"runtime output",
        );
        assert_eq!(
            classify_launcher_v2_output_artifact(&context, 7, &runtime_stdout),
            LauncherV2OutputArtifact::Other
        );
    }

    #[test]
    fn launcher_v2_classifier_applies_bounded_ascii_contracts() {
        let mut oversized_context = context();
        oversized_context.case_id = "a".repeat(MAX_LAUNCHER_V2_CONTEXT_COMPONENT_BYTES + 1);
        let artifact = raw_artifact(
            &format!(
                "{}/run-1/engine-run-1/attempt-7/output/launcher-v2/journal.jsonl",
                oversized_context.case_id
            ),
            b"launcher evidence",
        );
        let mut artifact = artifact;
        artifact.case_id = oversized_context.case_id.clone();
        assert_eq!(
            classify_launcher_v2_output_artifact(&oversized_context, 7, &artifact),
            LauncherV2OutputArtifact::Other
        );

        let oversized_output = format!(
            "launcher-v2/{}",
            "a".repeat(MAX_LAUNCHER_V2_OUTPUT_RELATIVE_PATH_BYTES)
        );
        let artifact = launcher_v2_artifact(&oversized_output, 7);
        assert_eq!(
            classify_launcher_v2_output_artifact(&context(), 7, &artifact),
            LauncherV2OutputArtifact::Other
        );
    }

    #[test]
    fn exact_existing_control_document_is_reused_after_interruption() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path()).expect("artifact store");
        let directories = store.prepare_run(&context(), 1).expect("run directories");
        let document = serde_json::json!({
            "schema_version": 2,
            "attempt": 1,
            "units": ["unit-1", "unit-2"],
        });

        let first = store
            .write_control_json(&directories, "launcher-plan.json", &document)
            .expect("initial control document");
        let first_bytes = fs::read(&first.path).expect("initial bytes");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&first.path, fs::Permissions::from_mode(0o600))
                .expect("simulate interrupted permission hardening");
        }

        let reused = store
            .write_control_json(&directories, "launcher-plan.json", &document)
            .expect("exact control document is reusable");

        assert_eq!(reused.sha256, first.sha256);
        assert_eq!(reused.byte_length, first.byte_length);
        assert_eq!(fs::read(&reused.path).unwrap(), first_bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&reused.path).unwrap().permissions().mode() & 0o777,
                0o400
            );
        }
    }

    #[test]
    fn interrupted_prefix_control_document_is_completed_without_replacement() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path()).expect("artifact store");
        let directories = store.prepare_run(&context(), 1).expect("run directories");
        let document = serde_json::json!({
            "schema_version": 2,
            "attempt": 1,
            "units": ["unit-1", "unit-2"],
        });
        let expected = serde_json::to_vec(&document).unwrap();
        let canonical = directories.control.join("launcher-plan.json");
        fs::write(&canonical, &expected[..expected.len() / 2]).expect("interrupted prefix");

        let completed = store
            .write_control_json(&directories, "launcher-plan.json", &document)
            .expect("interrupted product control file is reconciled");

        assert_eq!(fs::read(&canonical).unwrap(), expected);
        assert_eq!(completed.sha256, sha256_bytes(&expected));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&canonical).unwrap().permissions().mode() & 0o777,
                0o400
            );
        }
    }

    #[test]
    fn changed_existing_control_document_is_never_overwritten() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path()).expect("artifact store");
        let directories = store.prepare_run(&context(), 1).expect("run directories");
        let original = serde_json::json!({"attempt": 1, "units": ["unit-1"]});
        let changed = serde_json::json!({"attempt": 1, "units": ["unit-2"]});
        let control = store
            .write_control_json(&directories, "launcher-plan.json", &original)
            .expect("initial control document");
        let original_bytes = fs::read(&control.path).expect("initial bytes");

        let error = store
            .write_control_json(&directories, "launcher-plan.json", &changed)
            .expect_err("changed control document must be refused");

        assert!(error.to_string().contains("exact expected document"));
        assert_eq!(fs::read(&control.path).unwrap(), original_bytes);
    }

    #[test]
    fn shorter_nonprefix_control_document_is_never_completed_or_overwritten() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path()).expect("artifact store");
        let directories = store.prepare_run(&context(), 1).expect("run directories");
        let path = directories.control.join("scope.json");
        let foreign_bytes = b"not-an-expected-prefix";
        fs::write(&path, foreign_bytes).expect("mismatched existing file");

        let error = store
            .write_control_json(
                &directories,
                "scope.json",
                &serde_json::json!({"scope": "expected and longer than the mismatch"}),
            )
            .expect_err("shorter mismatch must be refused");

        assert!(error.to_string().contains("exact expected document"));
        assert_eq!(fs::read(&path).unwrap(), foreign_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn existing_control_symlink_is_never_followed_or_replaced() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("artifact store");
        let directories = store.prepare_run(&context(), 1).expect("run directories");
        let outside = temp.path().join("outside.json");
        fs::write(&outside, b"outside-data").expect("outside file");
        let linked = directories.control.join("scope.json");
        symlink(&outside, &linked).expect("control symlink");

        let error = store
            .write_control_json(
                &directories,
                "scope.json",
                &serde_json::json!({"scope": "expected"}),
            )
            .expect_err("control symlink must be refused");

        assert!(error.to_string().contains("non-reparse"));
        assert_eq!(fs::read(&outside).unwrap(), b"outside-data");
        assert!(
            fs::symlink_metadata(&linked)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn capture_files_are_hashed_as_raw_artifacts() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path()).expect("artifact store");
        let directories = store.prepare_run(&context(), 1).expect("run directories");
        let capture = store.prepare_capture(&directories).expect("capture files");
        fs::write(&capture.stdout, b"scanner stdout\n").expect("stdout");
        fs::write(&capture.stderr, b"scanner stderr\n").expect("stderr");

        let artifacts = store
            .finalize_capture(&context(), &capture)
            .expect("artifacts");

        assert_eq!(artifacts.len(), 2);
        assert_eq!(artifacts[0].sha256, sha256_bytes(b"scanner stdout\n"));
        assert_eq!(artifacts[1].sha256, sha256_bytes(b"scanner stderr\n"));
        assert!(
            artifacts
                .iter()
                .all(|artifact| artifact.contains_sensitive_data)
        );
    }

    #[test]
    fn capture_finalization_refuses_while_a_verified_writer_is_live() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path()).expect("artifact store");
        let directories = store.prepare_run(&context(), 1).expect("run directories");
        let capture = store.prepare_capture(&directories).expect("capture files");
        let writers = capture
            .clone_empty_writers()
            .expect("verified writer leases");

        let error = store
            .finalize_capture(&context(), &capture)
            .expect_err("live capture writers must defer finalization");
        assert!(error.to_string().contains("still being written"));

        drop(writers);
        assert_eq!(
            store
                .finalize_capture(&context(), &capture)
                .expect("quiesced capture")
                .len(),
            2
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepared_capture_handle_cannot_be_redirected_by_later_path_replacement() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("artifact store");
        let directories = store.prepare_run(&context(), 1).expect("run directories");
        let capture = store.prepare_capture(&directories).expect("capture files");
        let retained_stdout = directories.raw.join("retained-stdout.log");
        fs::rename(&capture.stdout, &retained_stdout).expect("retain opened inode");
        let outside = temp.path().join("outside.log");
        fs::write(&outside, b"outside-must-not-change").expect("outside sentinel");
        symlink(&outside, &capture.stdout).expect("replace path after preparation");

        let (mut stdout, stderr) = capture
            .clone_empty_writers()
            .expect("clone exact prepared handles");
        stdout
            .write_all(b"scanner-output\n")
            .expect("write through held handle");
        stdout.sync_all().expect("sync held handle");
        drop((stdout, stderr));

        assert_eq!(fs::read(&retained_stdout).unwrap(), b"scanner-output\n");
        assert_eq!(fs::read(&outside).unwrap(), b"outside-must-not-change");
        assert!(
            fs::symlink_metadata(&capture.stdout)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let error = store
            .finalize_capture(&context(), &capture)
            .expect_err("finalization must refuse the replaced durable path");
        assert!(error.to_string().contains("non-reparse"));
        assert_eq!(fs::read(&outside).unwrap(), b"outside-must-not-change");
    }

    #[test]
    fn empty_preflight_capture_files_are_reused_but_nonempty_files_are_preserved() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path()).expect("artifact store");
        let directories = store.prepare_run(&context(), 1).expect("run directories");

        let first = store
            .prepare_capture(&directories)
            .expect("initial capture");
        let reused = store
            .prepare_capture(&directories)
            .expect("empty preflight capture is reusable");
        assert_eq!(reused.stdout, first.stdout);
        assert_eq!(reused.stderr, first.stderr);

        fs::write(&first.stdout, b"possible scanner output").expect("captured bytes");
        let error = store
            .prepare_capture(&directories)
            .expect_err("nonempty capture must not be discarded");
        assert!(error.to_string().contains("not an empty product preflight"));
        assert_eq!(fs::read(&first.stdout).unwrap(), b"possible scanner output");
    }

    #[test]
    fn unsafe_identifiers_cannot_escape_artifact_root() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path()).expect("artifact store");
        let mut bad = context();
        bad.case_id = "../outside".into();

        let error = store
            .prepare_run(&bad, 1)
            .expect_err("unsafe path rejected");
        assert!(error.to_string().contains("unsafe path"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_intermediate_run_directory_is_rejected_before_outside_mutation() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = tempfile::tempdir().expect("temp directory");
        let artifact_root = temp.path().join("artifacts");
        let store = ArtifactStore::open(&artifact_root).expect("artifact store");
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).expect("outside directory");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755))
            .expect("outside permissions");
        symlink(&outside, artifact_root.join("case-1")).expect("intermediate symlink");

        let error = store
            .prepare_run(&context(), 1)
            .expect_err("symlinked intermediate must be refused");

        assert!(error.to_string().contains("non-reparse"));
        assert!(!outside.join("run-1").exists());
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_artifact_root_is_rejected_without_changing_outside_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = tempfile::tempdir().expect("temp directory");
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).expect("outside directory");
        fs::write(outside.join("user-data"), b"preserve").expect("outside data");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755))
            .expect("outside permissions");
        let linked_root = temp.path().join("artifacts");
        symlink(&outside, &linked_root).expect("artifact root symlink");

        let error = ArtifactStore::open(&linked_root).expect_err("symlink root must be refused");

        assert!(error.to_string().contains("non-reparse"));
        assert_eq!(fs::read(outside.join("user-data")).unwrap(), b"preserve");
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn output_file_limit_is_enforced() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path())
            .expect("artifact store")
            .with_max_output_files(1);
        let directories = store.prepare_run(&context(), 1).expect("run directories");
        fs::write(directories.output.join("one.json"), b"{}").expect("first");
        fs::write(directories.output.join("two.json"), b"{}").expect("second");

        let error = store
            .collect_output_artifacts(&context(), &directories)
            .expect_err("limit rejected");
        assert!(error.to_string().contains("artifact limit"));
    }

    #[test]
    fn captured_artifact_inspection_accepts_an_unchanged_regular_file() {
        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("artifacts");
        let bytes = b"captured scanner evidence\n";
        write_raw_artifact(&root, "case-1/run-1/evidence.json", bytes);
        let artifact = raw_artifact("case-1/run-1/evidence.json", bytes);

        inspect_raw_artifacts(&root, &[artifact]).expect("valid artifact");
    }

    #[test]
    fn captured_artifact_inspection_rejects_a_missing_file() {
        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("artifacts");
        fs::create_dir(&root).expect("artifact root");
        let artifact = raw_artifact("case-1/run-1/missing.json", b"missing");

        let error = inspect_raw_artifacts(&root, &[artifact]).expect_err("missing file rejected");

        assert!(error.to_string().contains("not available"));
    }

    #[test]
    fn captured_artifact_inspection_requires_an_existing_root() {
        let temp = tempfile::tempdir().expect("temp directory");
        let missing_root = temp.path().join("missing-artifacts");

        let error = inspect_raw_artifacts(&missing_root, &[]).expect_err("missing root rejected");

        assert!(error.to_string().contains("artifact root"));
        assert!(
            !missing_root.exists(),
            "inspection must not create the root"
        );
    }

    #[test]
    fn captured_artifact_inspection_rejects_modified_bytes() {
        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("artifacts");
        let artifact = raw_artifact("case-1/evidence.bin", b"trusted");
        write_raw_artifact(&root, "case-1/evidence.bin", b"altered");

        let error = inspect_raw_artifacts(&root, &[artifact]).expect_err("modified file rejected");

        assert!(error.to_string().contains("hash differs"));
    }

    #[test]
    fn captured_artifact_inspection_rejects_a_changed_byte_length() {
        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("artifacts");
        let artifact = raw_artifact("case-1/evidence.bin", b"trusted");
        write_raw_artifact(&root, "case-1/evidence.bin", b"now longer");

        let error = inspect_raw_artifacts(&root, &[artifact]).expect_err("changed length rejected");

        assert!(error.to_string().contains("byte length differs"));
    }

    #[test]
    fn captured_artifact_inspection_rejects_non_normalized_or_traversing_paths() {
        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("artifacts");
        fs::create_dir(&root).expect("artifact root");

        for relative_path in [
            "../outside.bin",
            "case-1/./evidence.bin",
            "case-1//evidence.bin",
            "case-1/evidence.bin/",
            "/absolute/evidence.bin",
            "case-1\\evidence.bin",
        ] {
            let artifact = raw_artifact(relative_path, b"evidence");
            let error = inspect_raw_artifacts(&root, &[artifact])
                .expect_err("unsafe artifact path rejected");
            assert!(
                error.to_string().contains("unsafe or non-normalized"),
                "unexpected error for {relative_path}: {error}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn captured_artifact_inspection_rejects_final_and_intermediate_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("artifacts");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&root).expect("artifact root");
        fs::create_dir_all(&outside).expect("outside directory");
        fs::write(outside.join("evidence.bin"), b"evidence").expect("outside file");

        symlink(outside.join("evidence.bin"), root.join("final-link.bin")).expect("final symlink");
        let final_link = raw_artifact("final-link.bin", b"evidence");
        let final_error =
            inspect_raw_artifacts(&root, &[final_link]).expect_err("final symlink rejected");
        assert!(final_error.to_string().contains("symlink"));

        symlink(&outside, root.join("intermediate-link")).expect("intermediate symlink");
        let intermediate_link = raw_artifact("intermediate-link/evidence.bin", b"evidence");
        let intermediate_error = inspect_raw_artifacts(&root, &[intermediate_link])
            .expect_err("intermediate symlink rejected");
        assert!(intermediate_error.to_string().contains("symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn captured_artifact_inspection_rejects_a_symlink_root() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temp directory");
        let actual_root = temp.path().join("actual-artifacts");
        fs::create_dir(&actual_root).expect("actual artifact root");
        write_raw_artifact(&actual_root, "case-1/evidence.bin", b"evidence");
        let linked_root = temp.path().join("linked-artifacts");
        symlink(&actual_root, &linked_root).expect("artifact root symlink");
        let artifact = raw_artifact("case-1/evidence.bin", b"evidence");

        let error =
            inspect_raw_artifacts(&linked_root, &[artifact]).expect_err("symlink root rejected");

        assert!(error.to_string().contains("non-symlink directory"));
    }

    #[cfg(unix)]
    #[test]
    fn captured_artifact_inspection_does_not_change_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("temp directory");
        let root = temp.path().join("artifacts");
        let directory = root.join("case-1");
        let file = directory.join("evidence.bin");
        write_raw_artifact(&root, "case-1/evidence.bin", b"evidence");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o751)).expect("root permissions");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o711))
            .expect("directory permissions");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).expect("file permissions");
        let artifact = raw_artifact("case-1/evidence.bin", b"evidence");

        inspect_raw_artifacts(&root, &[artifact]).expect("valid artifact");

        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o751
        );
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o711
        );
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }
}
