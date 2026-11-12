//! Immutable, content-addressed snapshots of a user-selected local working tree.
//!
//! The snapshot intentionally represents only working-tree contents. Every entry
//! named `.git` is excluded without being opened or followed, so Git history,
//! refs, hooks, credentials, and worktree pointers are never copied. Repository
//! inputs also honor repository-local root and nested `.gitignore` files, but a
//! Git-backed tree never excludes a path that its bounded tracked-file inventory
//! identifies as tracked. An ignored regular file in a traversed source directory
//! is also retained when its name identifies a likely secret or private runtime
//! configuration; ignored directories remain pruned, so dependency, build, and
//! cache trees are not searched for exceptions. If the tracked-file inventory
//! cannot be proved, ignore filtering fails open for that repository boundary.
//! Every actual exclusion and every ignore-rule source is recorded in the
//! immutable manifest. External/global ignore configuration is deliberately not
//! consulted. Explicit non-repository profiles retain their original unfiltered
//! content semantics.
//! The caller must obtain `selected_source_directory` through a trusted backend
//! selection flow; no destination path is accepted from the frontend.

use crate::domain::{Asset, AssetIdentifier, LocalInputProfile};
use crate::error::{AppError, AppResult};
use flate2::read::MultiGzDecoder;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

pub const WORKSPACE_SNAPSHOT_SCHEMA: &str = "ai-security-scanner.workspace-snapshot/v3";
const LEGACY_WORKSPACE_SNAPSHOT_SCHEMA: &str = "ai-security-scanner.workspace-snapshot/v1";
const LEGACY_GITIGNORE_WORKSPACE_SNAPSHOT_SCHEMA: &str =
    "ai-security-scanner.workspace-snapshot/v2";
pub const WORKSPACE_SNAPSHOT_REFERENCE_SCHEMA: &str =
    "ai-security-scanner.workspace-snapshot-reference/v1";
pub const WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY: &str =
    "ai_security_scanner.workspace_snapshot_reference";
pub const WORKING_TREE_SEMANTICS: &str = "working_tree_only";
pub const LOCAL_INPUT_PROFILE_FILENAME: &str = ".ai-security-scanner-input.json";
pub const LOCAL_INPUT_PROFILE_SCHEMA: &str = "ai-security-scanner.local-input/v1";

const SNAPSHOT_DIRECTORY: &str = "workspace-snapshots";
const TREE_DIRECTORY: &str = "tree";
const MANIFEST_FILENAME: &str = "manifest.json";
const STORAGE_ID_PREFIX: &str = "workspace-artifact-";
const SNAPSHOT_ID_PREFIX: &str = "workspace-snapshot-sha256-";
// A repository is a user-selected target, while the snapshot hash identifies
// one immutable revision of its contents. Two different repositories can be
// byte-identical, so their asset identity must follow the backend-created
// source rather than collapsing them by content digest.
const ASSET_ID_PREFIX: &str = "asset-workspace-source-";
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_GITIGNORE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_GIT_TRACKED_INVENTORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_GIT_TRACKED_TOTAL_INVENTORY_BYTES: u64 = 129 * 1024 * 1024;
const MAX_GIT_TRACKED_INVENTORY_PROBES: usize = 256;
const GIT_TRACKED_TOTAL_INVENTORY_RUNTIME: Duration = Duration::from_secs(20);
const MAX_WORKSPACE_SNAPSHOT_AUDIT_BYTES: u64 = 16 * 1024 * 1024;
const HARD_MAX_FILES: usize = 200_000;
const HARD_MAX_DIRECTORIES: usize = 100_000;
const HARD_MAX_TOTAL_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const HARD_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const HARD_MAX_DEPTH: usize = 64;
const OCI_IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const OCI_IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_IMAGE_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const OCI_IMAGE_LAYER_TAR_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const OCI_MAX_LAYERS: usize = 4_096;
const OCI_MAX_TAR_ENTRIES: usize = HARD_MAX_FILES;
const OCI_MAX_UNCOMPRESSED_LAYER_BYTES: u64 = HARD_MAX_FILE_BYTES;

/// Public API name retained for the snapshot boundary; engine manifests use
/// the same domain enum so the planner and resolver cannot drift.
pub type WorkspaceInputProfile = LocalInputProfile;

/// Explicit resource limits applied before and during every copy.
///
/// `max_depth` counts nested directories below the selected root. Root-level
/// files therefore have depth zero. `max_directories` excludes the selected
/// root itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotLimits {
    pub max_files: usize,
    pub max_directories: usize,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_depth: usize,
}

impl Default for WorkspaceSnapshotLimits {
    fn default() -> Self {
        Self {
            max_files: 50_000,
            max_directories: 10_000,
            max_total_bytes: 2 * 1024 * 1024 * 1024,
            max_file_bytes: 512 * 1024 * 1024,
            max_depth: 32,
        }
    }
}

impl WorkspaceSnapshotLimits {
    fn validate(self) -> AppResult<Self> {
        if self.max_files == 0
            || self.max_total_bytes == 0
            || self.max_file_bytes == 0
            || self.max_files > HARD_MAX_FILES
            || self.max_directories > HARD_MAX_DIRECTORIES
            || self.max_total_bytes > HARD_MAX_TOTAL_BYTES
            || self.max_file_bytes > HARD_MAX_FILE_BYTES
            || self.max_depth > HARD_MAX_DEPTH
        {
            return Err(AppError::InvalidRequest(
                "workspace snapshot limits are zero or exceed the built-in safety ceiling".into(),
            ));
        }
        Ok(self)
    }
}

/// One deterministic manifest entry. Paths are normalized UTF-8 paths using
/// `/` separators and are relative to the copied tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotFile {
    pub relative_path: String,
    pub byte_length: u64,
    pub sha256: String,
}

/// The source-side filtering applied before immutable snapshot publication.
///
/// Version 1 manifests predate this field and are still accepted as the
/// legacy Git-metadata-only policy. New manifests always record a policy so a
/// verifier can distinguish repository-local `.gitignore` filtering from the
/// deliberately unfiltered non-repository input profiles.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceSnapshotExclusionPolicy {
    RepositoryGitignoreV1,
    GitMetadataOnlyV1,
    RepositoryTrackedGitignoreV2,
    GitMetadataOnlyV2,
}

/// Why one exact source entry was omitted from the copied tree.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceSnapshotExclusionReason {
    GitMetadata,
    RepositoryGitignoreUntracked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceSnapshotExcludedEntryKind {
    File,
    Directory,
    SymlinkOrSpecial,
}

/// Auditable record for every exact entry pruned before snapshot publication.
/// A directory record covers its complete unvisited subtree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotExclusion {
    pub relative_path: String,
    pub reason: WorkspaceSnapshotExclusionReason,
    pub entry_kind: WorkspaceSnapshotExcludedEntryKind,
}

/// Content proof for a repository-local ignore file used to exclude entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotIgnoreRuleSource {
    pub relative_path: String,
    pub byte_length: u64,
    pub sha256: String,
}

/// Canonical manifest bytes are compact JSON serialization of this structure.
/// No timestamp, host path, random identifier, or filesystem metadata enters
/// the manifest, making its SHA-256 stable for identical working-tree content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotManifest {
    pub schema_version: String,
    pub content_semantics: String,
    #[serde(default, skip_serializing_if = "WorkspaceInputProfile::is_repository")]
    pub input_profile: WorkspaceInputProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusion_policy: Option<WorkspaceSnapshotExclusionPolicy>,
    pub excluded_entries: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclusions: Vec<WorkspaceSnapshotExclusion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore_rule_sources: Vec<WorkspaceSnapshotIgnoreRuleSource>,
    pub directories: Vec<String>,
    pub files: Vec<WorkspaceSnapshotFile>,
    pub directory_count: usize,
    pub file_count: usize,
    pub total_bytes: u64,
}

/// Safe persisted locator. Storage paths are always derived by the backend
/// from `case_id` and this generated `storage_id`; callers cannot persist or
/// later inject an arbitrary host path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotReference {
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "WorkspaceInputProfile::is_repository")]
    pub input_profile: WorkspaceInputProfile,
    pub storage_id: String,
    pub snapshot_id: String,
    pub sha256: String,
    pub directory_count: usize,
    pub file_count: usize,
    pub total_bytes: u64,
    pub working_tree_only: bool,
}

#[derive(Debug, Clone)]
pub struct WorkspaceSnapshot {
    pub reference: WorkspaceSnapshotReference,
    pub manifest: WorkspaceSnapshotManifest,
    pub asset: Asset,
}

/// A verified backend path suitable for a read-only container bind mount.
#[derive(Debug, Clone)]
pub struct ResolvedWorkspaceSnapshot {
    pub tree_path: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest: WorkspaceSnapshotManifest,
}

/// Copies a selected directory into a private backend-owned artifact location.
///
/// The final storage identity is reserved with create-new directory semantics,
/// and the complete staging directory is moved beneath that identity in one
/// rename. Thus an existing artifact is never overwritten and no reference is
/// returned until the complete payload has been atomically published.
pub fn create_workspace_snapshot(
    artifact_root: impl AsRef<Path>,
    case_id: &str,
    source_id: &str,
    selected_source_directory: impl AsRef<Path>,
    limits: WorkspaceSnapshotLimits,
) -> AppResult<WorkspaceSnapshot> {
    create_workspace_snapshot_with_profile(
        artifact_root,
        case_id,
        source_id,
        selected_source_directory,
        WorkspaceInputProfile::RepositoryWorkingTree,
        limits,
    )
}

/// Copies one explicitly typed local input into the same immutable snapshot
/// boundary used by repository scans. The profile is backend-authored and
/// content-addressed so a scanner cannot reinterpret a repository as an image,
/// node snapshot, or Kubernetes manifest set.
pub fn create_workspace_snapshot_with_profile(
    artifact_root: impl AsRef<Path>,
    case_id: &str,
    source_id: &str,
    selected_source_directory: impl AsRef<Path>,
    input_profile: WorkspaceInputProfile,
    limits: WorkspaceSnapshotLimits,
) -> AppResult<WorkspaceSnapshot> {
    validate_safe_id("case id", case_id)?;
    validate_safe_id("source id", source_id)?;
    let limits = limits.validate()?;
    let artifact_root = prepare_existing_directory(artifact_root.as_ref(), "artifact root")?;
    let selected_source = prepare_selected_source(selected_source_directory.as_ref())?;

    if selected_source.starts_with(&artifact_root) || artifact_root.starts_with(&selected_source) {
        return Err(AppError::InvalidRequest(
            "selected working tree and artifact root must not overlap".into(),
        ));
    }
    validate_selected_input_profile(&selected_source, input_profile)?;

    let case_directory = ensure_private_child_directory(&artifact_root, case_id)?;
    let snapshots_directory = ensure_private_child_directory(&case_directory, SNAPSHOT_DIRECTORY)?;
    let staging_id = format!(".workspace-staging-{}", Uuid::new_v4().simple());
    let staging_path = create_private_generated_directory(&snapshots_directory, &staging_id)?;
    let mut cleanup = SnapshotCleanup::new(staging_path.clone());
    let tree_path = staging_path.join(TREE_DIRECTORY);
    create_private_directory(&tree_path)?;

    let mut copy_state = CopyState::default();
    let mut exclusion_state = CopyExclusionState::for_profile(input_profile);
    if input_profile.is_repository() {
        exclusion_state.register_repository_boundary(&selected_source, &[]);
    }
    let copy_context = CopyDirectoryContext {
        source_root: &selected_source,
        limits,
    };
    copy_directory(
        &selected_source,
        &tree_path,
        &[],
        0,
        copy_context,
        &mut copy_state,
        &mut exclusion_state,
    )?;
    exclusion_state.verify_tracking_proofs()?;
    validate_copied_input_files(&tree_path, &copy_state, input_profile)?;
    if !input_profile.is_repository() {
        write_input_profile_marker(&tree_path, input_profile, limits, &mut copy_state)?;
    }

    copy_state.directories.sort();
    copy_state.files.sort_by(|left, right| {
        left.relative_path
            .as_bytes()
            .cmp(right.relative_path.as_bytes())
    });
    copy_state.exclusions.sort();
    copy_state.ignore_rule_sources.sort();
    let manifest = WorkspaceSnapshotManifest {
        schema_version: WORKSPACE_SNAPSHOT_SCHEMA.into(),
        content_semantics: WORKING_TREE_SEMANTICS.into(),
        input_profile,
        exclusion_policy: Some(if input_profile.is_repository() {
            WorkspaceSnapshotExclusionPolicy::RepositoryTrackedGitignoreV2
        } else {
            WorkspaceSnapshotExclusionPolicy::GitMetadataOnlyV2
        }),
        excluded_entries: vec![".git".into()],
        exclusions: copy_state.exclusions,
        ignore_rule_sources: copy_state.ignore_rule_sources,
        directory_count: copy_state.directories.len(),
        file_count: copy_state.files.len(),
        total_bytes: copy_state.total_bytes,
        directories: copy_state.directories,
        files: copy_state.files,
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|error| {
        AppError::Internal(format!(
            "workspace snapshot manifest could not be encoded: {error}"
        ))
    })?;
    if manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(AppError::Runtime(
            "workspace snapshot manifest exceeded its safety limit".into(),
        ));
    }
    let snapshot_sha256 = sha256_bytes(&manifest_bytes);
    let manifest_path = staging_path.join(MANIFEST_FILENAME);
    write_private_readonly_file(&manifest_path, &manifest_bytes)?;
    sync_directory(&tree_path)?;
    sync_directory(&staging_path)?;
    make_snapshot_tree_readonly(&tree_path)?;

    let storage_id = format!("{STORAGE_ID_PREFIX}{}", Uuid::new_v4().simple());
    let final_container = create_private_generated_directory(&snapshots_directory, &storage_id)?;
    cleanup.track_final(final_container.clone());
    let final_payload = final_container.join("payload");
    fs::rename(&staging_path, &final_payload).map_err(|error| {
        AppError::Runtime(format!(
            "workspace snapshot could not be atomically finalized without overwrite: {error}"
        ))
    })?;
    cleanup.staging_moved();
    set_readonly_directory(&final_payload)?;
    set_readonly_directory(&final_container)?;
    sync_directory(&final_container)?;
    sync_directory(&snapshots_directory)?;

    let snapshot_id = format!("{SNAPSHOT_ID_PREFIX}{snapshot_sha256}");
    let reference = WorkspaceSnapshotReference {
        schema_version: WORKSPACE_SNAPSHOT_REFERENCE_SCHEMA.into(),
        input_profile,
        storage_id,
        snapshot_id: snapshot_id.clone(),
        sha256: snapshot_sha256.clone(),
        directory_count: manifest.directory_count,
        file_count: manifest.file_count,
        total_bytes: manifest.total_bytes,
        working_tree_only: true,
    };
    let mut asset = snapshot_asset(source_id, &snapshot_id, &snapshot_sha256, input_profile);
    crate::mcp_armor_input::annotate_repository_asset(&mut asset, &manifest)?;
    cleanup.disarm();

    Ok(WorkspaceSnapshot {
        reference,
        manifest,
        asset,
    })
}

/// Inspects and fully verifies a stored snapshot without changing the
/// filesystem.
///
/// This is the pre-persistence counterpart to [`resolve_workspace_snapshot`].
/// It never creates a directory or changes permissions. The execution worker
/// must still call `resolve_workspace_snapshot` so a change after this
/// inspection fails closed at the final mount boundary.
pub fn inspect_workspace_snapshot(
    artifact_root: impl AsRef<Path>,
    case_id: &str,
    reference: &WorkspaceSnapshotReference,
) -> AppResult<ResolvedWorkspaceSnapshot> {
    validate_safe_id("case id", case_id)?;
    validate_reference(reference)?;
    let artifact_root = inspect_existing_directory(artifact_root.as_ref(), "artifact root")?;
    verify_workspace_snapshot(&artifact_root, case_id, reference)
}

/// Resolves and fully verifies a stored snapshot before execution.
///
/// The manifest hash, all directory names, every file size/hash, and aggregate
/// counts are checked. Symlinks and special files fail closed. The returned path
/// is never taken from persisted case data; it is derived from validated IDs.
/// The artifact root's private mode is re-applied at this worker boundary; use
/// [`inspect_workspace_snapshot`] for a strictly read-only pre-persistence
/// check.
pub fn resolve_workspace_snapshot(
    artifact_root: impl AsRef<Path>,
    case_id: &str,
    reference: &WorkspaceSnapshotReference,
) -> AppResult<ResolvedWorkspaceSnapshot> {
    validate_safe_id("case id", case_id)?;
    validate_reference(reference)?;
    let artifact_root = prepare_existing_directory(artifact_root.as_ref(), "artifact root")?;
    verify_workspace_snapshot(&artifact_root, case_id, reference)
}

fn verify_workspace_snapshot(
    artifact_root: &Path,
    case_id: &str,
    reference: &WorkspaceSnapshotReference,
) -> AppResult<ResolvedWorkspaceSnapshot> {
    let case_directory = resolve_real_child_directory(artifact_root, case_id)?;
    let snapshots_directory = resolve_real_child_directory(&case_directory, SNAPSHOT_DIRECTORY)?;
    let final_container =
        resolve_real_child_directory(&snapshots_directory, &reference.storage_id)?;
    let payload = resolve_real_child_directory(&final_container, "payload")?;
    let tree_path = resolve_real_child_directory(&payload, TREE_DIRECTORY)?;
    let manifest_path = resolve_real_regular_file(&payload, MANIFEST_FILENAME)?;
    let manifest_bytes = read_bounded_stable_file(&manifest_path, MAX_MANIFEST_BYTES)?;
    let actual_manifest_sha256 = sha256_bytes(&manifest_bytes);
    if actual_manifest_sha256 != reference.sha256 {
        return Err(AppError::Runtime(
            "workspace snapshot manifest failed its SHA-256 integrity check".into(),
        ));
    }
    let manifest: WorkspaceSnapshotManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| {
            AppError::Runtime(format!("workspace snapshot manifest is invalid: {error}"))
        })?;
    validate_manifest(&manifest, reference)?;

    let verification_limits = WorkspaceSnapshotLimits {
        max_files: reference.file_count.max(1),
        max_directories: reference.directory_count,
        max_total_bytes: reference.total_bytes.max(1),
        max_file_bytes: reference.total_bytes.clamp(1, HARD_MAX_FILE_BYTES),
        max_depth: HARD_MAX_DEPTH,
    };
    let mut observed = VerificationState::default();
    verify_directory(
        &tree_path,
        &[],
        0,
        &tree_path,
        verification_limits,
        &mut observed,
    )?;
    observed.directories.sort();
    observed.files.sort_by(|left, right| {
        left.relative_path
            .as_bytes()
            .cmp(right.relative_path.as_bytes())
    });
    if observed.directories != manifest.directories || observed.files != manifest.files {
        return Err(AppError::Runtime(
            "workspace snapshot contents do not match the immutable manifest".into(),
        ));
    }
    validate_resolved_input_profile(&tree_path, reference.input_profile)?;

    Ok(ResolvedWorkspaceSnapshot {
        tree_path,
        manifest_path,
        manifest,
    })
}

#[derive(Default)]
struct CopyState {
    directories: Vec<String>,
    files: Vec<WorkspaceSnapshotFile>,
    total_bytes: u64,
    gitignore_bytes_read: u64,
    exclusions: Vec<WorkspaceSnapshotExclusion>,
    ignore_rule_sources: Vec<WorkspaceSnapshotIgnoreRuleSource>,
    audit_bytes: u64,
}

#[derive(Default)]
struct VerificationState {
    directories: Vec<String>,
    files: Vec<WorkspaceSnapshotFile>,
    total_bytes: u64,
}

enum CopyExclusionState {
    GitMetadataOnly,
    RepositoryGitignore {
        matchers: Vec<Gitignore>,
        repositories: Vec<GitTrackedRepository>,
        registered_roots: BTreeSet<String>,
        fail_open_roots: BTreeSet<String>,
        initial_probe_budget: GitInventoryProbeBudget,
        verification_probe_budget: GitInventoryProbeBudget,
    },
}

#[derive(Debug, Clone)]
struct GitTrackedRepository {
    source_root: PathBuf,
    relative_prefix: String,
    tracked_paths: BTreeSet<String>,
    tracked_match_paths: BTreeSet<String>,
    tracked_match_directories: BTreeSet<String>,
    case_insensitive: bool,
}

#[derive(Debug, Clone)]
struct GitInventoryProbeBudget {
    remaining_bytes: u64,
    remaining_runtime: Duration,
    remaining_probes: usize,
}

impl Default for GitInventoryProbeBudget {
    fn default() -> Self {
        Self {
            // Initial discovery and final revalidation receive equal halves.
            // Their sum is the single published total probe budget, while a
            // successful discovery can never consume its own revalidation.
            remaining_bytes: MAX_GIT_TRACKED_TOTAL_INVENTORY_BYTES / 2,
            remaining_runtime: GIT_TRACKED_TOTAL_INVENTORY_RUNTIME / 2,
            remaining_probes: MAX_GIT_TRACKED_INVENTORY_PROBES / 2,
        }
    }
}

impl GitInventoryProbeBudget {
    fn reserve(&mut self) -> Option<(u64, Duration)> {
        if self.remaining_probes == 0
            || self.remaining_bytes == 0
            || self.remaining_runtime.is_zero()
        {
            return None;
        }
        self.remaining_probes -= 1;
        Some((
            self.remaining_bytes.min(MAX_GIT_TRACKED_INVENTORY_BYTES),
            self.remaining_runtime,
        ))
    }

    fn consume(&mut self, elapsed: Duration, observed_bytes: Option<u64>) {
        self.remaining_runtime = self.remaining_runtime.saturating_sub(elapsed);
        match observed_bytes {
            Some(bytes) => self.remaining_bytes = self.remaining_bytes.saturating_sub(bytes),
            // A reader which did not finish may still own its complete bounded
            // buffer through an inherited pipe. Do not start another probe.
            None => self.remaining_bytes = 0,
        }
    }
}

impl CopyExclusionState {
    fn for_profile(input_profile: WorkspaceInputProfile) -> Self {
        if input_profile.is_repository() {
            Self::RepositoryGitignore {
                matchers: Vec::new(),
                repositories: Vec::new(),
                registered_roots: BTreeSet::new(),
                fail_open_roots: BTreeSet::new(),
                initial_probe_budget: GitInventoryProbeBudget::default(),
                verification_probe_budget: GitInventoryProbeBudget::default(),
            }
        } else {
            Self::GitMetadataOnly
        }
    }

    fn register_repository_boundary(&mut self, source_root: &Path, relative_components: &[String]) {
        let Self::RepositoryGitignore {
            repositories,
            registered_roots,
            fail_open_roots,
            initial_probe_budget,
            ..
        } = self
        else {
            return;
        };
        let relative_prefix = relative_components.join("/");
        if !registered_roots.insert(relative_prefix.clone()) {
            return;
        }
        let git_metadata = source_root.join(".git");
        // A `.git` indirection file can redirect inventory outside the selected
        // tree. Without a separately packaged Git/worktree resolver, retain all
        // files for that boundary instead of following it.
        let boundary_is_safe = fs::symlink_metadata(&git_metadata)
            .map(|metadata| !metadata.file_type().is_symlink() && metadata.is_dir())
            .unwrap_or(false);
        let Some(tracked_paths) = boundary_is_safe
            .then(|| load_bounded_git_tracked_inventory(source_root, initial_probe_budget))
            .flatten()
        else {
            fail_open_roots.insert(relative_prefix);
            return;
        };
        let case_insensitive = git_tracked_paths_are_case_insensitive_on_platform();
        let (tracked_match_paths, tracked_match_directories) =
            tracked_match_sets(&tracked_paths, case_insensitive);
        repositories.push(GitTrackedRepository {
            source_root: source_root.to_path_buf(),
            relative_prefix,
            tracked_paths,
            tracked_match_paths,
            tracked_match_directories,
            case_insensitive,
        });
    }

    fn register_nested_repository_if_present(
        &mut self,
        directory: &Path,
        relative_components: &[String],
    ) {
        let git_metadata = directory.join(".git");
        match fs::symlink_metadata(&git_metadata) {
            Ok(_) => self.register_repository_boundary(directory, relative_components),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                if let Self::RepositoryGitignore {
                    fail_open_roots, ..
                } = self
                {
                    fail_open_roots.insert(relative_components.join("/"));
                }
            }
        }
    }

    fn repository_path_is_ignored(
        &self,
        path: &Path,
        relative_path: &str,
        is_directory: bool,
    ) -> bool {
        let Self::RepositoryGitignore {
            matchers,
            repositories,
            fail_open_roots,
            ..
        } = self
        else {
            return false;
        };
        if fail_open_roots
            .iter()
            .any(|prefix| relative_path_is_within(relative_path, prefix))
        {
            return false;
        }
        for repository in repositories {
            let Some(repository_path) =
                strip_relative_prefix(relative_path, &repository.relative_prefix)
            else {
                continue;
            };
            let match_path = git_tracked_path_key(repository_path, repository.case_insensitive);
            if repository.tracked_match_paths.contains(&match_path)
                || (is_directory && repository.tracked_match_directories.contains(&match_path))
            {
                return false;
            }
        }
        for matcher in matchers.iter().rev() {
            let matched = matcher.matched(path, is_directory);
            if !matched.is_none() {
                return matched.is_ignore();
            }
        }
        false
    }

    fn verify_tracking_proofs(&mut self) -> AppResult<()> {
        let Self::RepositoryGitignore {
            repositories,
            verification_probe_budget,
            ..
        } = self
        else {
            return Ok(());
        };
        for repository in repositories {
            let current = load_bounded_git_tracked_inventory(
                &repository.source_root,
                verification_probe_budget,
            )
            .ok_or_else(|| {
                    AppError::Runtime(
                        "Git tracked-file inventory became unavailable while the snapshot was being copied"
                            .into(),
                    )
                })?;
            if current != repository.tracked_paths {
                return Err(AppError::Runtime(
                    "Git tracked-file inventory changed while the snapshot was being copied".into(),
                ));
            }
        }
        Ok(())
    }
}

fn relative_path_is_within(path: &str, prefix: &str) -> bool {
    prefix.is_empty()
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Keeps high-signal secret/configuration inputs available to repository secret
/// scanners even when a conventional `.gitignore` rule hides them from Git.
///
/// This exception is deliberately filename based and applies only to regular
/// files in directories the bounded snapshot walk already visits. It does not
/// reopen an ignored directory, and it never applies below a dependency, build,
/// cache, or VCS metadata component. The ordinary snapshot file-count,
/// per-file-byte, and aggregate-byte limits still govern every retained file.
fn preserve_ignored_secret_candidate(
    relative_components: &[String],
    file_type: &fs::FileType,
) -> bool {
    if !file_type.is_file() {
        return false;
    }

    let Some((file_name, ancestors)) = relative_components.split_last() else {
        return false;
    };
    if ancestors
        .iter()
        .any(|component| excluded_secret_candidate_ancestor(component))
    {
        return false;
    }

    likely_secret_config_file_name(file_name)
}

fn excluded_secret_candidate_ancestor(component: &str) -> bool {
    matches!(
        component.to_ascii_lowercase().as_str(),
        ".git"
            | ".hg"
            | ".svn"
            | "node_modules"
            | "bower_components"
            | "vendor"
            | ".venv"
            | "venv"
            | "target"
            | "build"
            | "dist"
            | "out"
            | "bin"
            | "obj"
            | ".next"
            | ".nuxt"
            | ".cache"
            | "cache"
            | "coverage"
            | ".gradle"
            | ".terraform"
            | ".serverless"
            | ".turbo"
            | ".parcel-cache"
            | ".pytest_cache"
            | ".mypy_cache"
            | ".ruff_cache"
            | "__pycache__"
            | "pods"
            | "deriveddata"
    )
}

pub(crate) const SECRET_NAME_CLASSIFIER_VERSION: u32 = 1;

pub(crate) fn likely_secret_config_file_name(file_name: &str) -> bool {
    let name = file_name.to_ascii_lowercase();
    if name == ".env" || name == ".envrc" || name.starts_with(".env.") {
        return true;
    }
    if matches!(
        name.as_str(),
        ".npmrc"
            | ".yarnrc"
            | ".pypirc"
            | ".netrc"
            | ".pgpass"
            | ".my.cnf"
            | ".git-credentials"
            | ".htpasswd"
            | "id_rsa"
            | "id_dsa"
            | "id_ecdsa"
            | "id_ed25519"
            | "terraform.tfstate"
            | "terraform.tfstate.backup"
            | "application_default_credentials.json"
    ) {
        return true;
    }
    if name.ends_with(".tfvars")
        || name.ends_with(".tfvars.json")
        || name.ends_with(".pem")
        || name.ends_with(".key")
    {
        return true;
    }

    ["secret", "secrets", "credential", "credentials"]
        .iter()
        .any(|stem| {
            name.strip_prefix(stem)
                .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('.'))
        })
}

fn strip_relative_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    if prefix.is_empty() {
        return Some(path);
    }
    if path == prefix {
        return Some("");
    }
    path.strip_prefix(prefix)?.strip_prefix('/')
}

fn git_tracked_paths_are_case_insensitive_on_platform() -> bool {
    cfg!(windows) || cfg!(target_os = "macos")
}

fn git_tracked_path_key(path: &str, case_insensitive: bool) -> String {
    if case_insensitive {
        path.to_lowercase()
    } else {
        path.to_owned()
    }
}

fn tracked_match_sets(
    tracked_paths: &BTreeSet<String>,
    case_insensitive: bool,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    for path in tracked_paths {
        files.insert(git_tracked_path_key(path, case_insensitive));
        directories.insert(String::new());
        let mut ancestor = path.as_str();
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            directories.insert(git_tracked_path_key(parent, case_insensitive));
            ancestor = parent;
        }
    }
    (files, directories)
}

#[cfg(unix)]
fn trusted_git_binary() -> Option<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let binary = Path::new("/usr/bin/git");
    for (path, expect_directory) in [
        (Path::new("/usr"), true),
        (Path::new("/usr/bin"), true),
        (binary, false),
    ] {
        let metadata = fs::symlink_metadata(path).ok()?;
        let type_matches = if expect_directory {
            metadata.is_dir()
        } else {
            metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
        };
        if metadata.file_type().is_symlink()
            || !type_matches
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return None;
        }
    }
    Some(binary.to_path_buf())
}

#[cfg(not(unix))]
fn trusted_git_binary() -> Option<PathBuf> {
    // The release does not package Git, and PATH resolution is not an
    // acceptable integrity boundary. Retain all files on these platforms.
    None
}

/// Starts every trusted-Git child that reads a scanned repository.
///
/// The repository and its configuration are examined data. The child receives
/// only this fixed environment: no user or system configuration, no prompt, no
/// pager, no transport of any kind, and no on-demand fetch of missing objects.
/// Repository configuration therefore cannot make the scanner start a program
/// or contact a network. Build every Git invocation in this crate here.
pub(crate) fn trusted_git_command(binary: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_PAGER", "")
        .env("GIT_LITERAL_PATHSPECS", "1")
        // An empty allow-list denies every transport and overrides the
        // repository's own `protocol.*.allow` settings.
        .env("GIT_ALLOW_PROTOCOL", "")
        // A partial clone never fetches a missing object on demand.
        .env("GIT_NO_LAZY_FETCH", "1");
    command
}

fn load_bounded_git_tracked_inventory(
    repository_root: &Path,
    budget: &mut GitInventoryProbeBudget,
) -> Option<BTreeSet<String>> {
    let binary = trusted_git_binary()?;
    let (maximum_bytes, maximum_runtime) = budget.reserve()?;
    let started = Instant::now();
    let mut command = trusted_git_command(&binary);
    command
        .arg("--no-optional-locks")
        .args(["-c", "core.fsmonitor=false"])
        .args(["-c", "core.untrackedCache=false"])
        .args(["-c", "core.preloadIndex=false"])
        .arg("-C")
        .arg(repository_root)
        .args(["ls-files", "--cached", "-z", "--"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let outcome = command
        .spawn()
        .ok()
        .and_then(|child| collect_bounded_child_output(child, maximum_bytes, maximum_runtime));
    budget.consume(
        started.elapsed(),
        outcome
            .as_ref()
            .map(|(_, bytes)| u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
    );
    let (status, bytes) = outcome?;
    if !status.success() || bytes.len() as u64 > maximum_bytes {
        return None;
    }
    parse_git_tracked_inventory(&bytes)
}

fn collect_bounded_child_output(
    mut child: std::process::Child,
    maximum_bytes: u64,
    timeout: Duration,
) -> Option<(std::process::ExitStatus, Vec<u8>)> {
    let mut stdout = child.stdout.take()?;
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .by_ref()
            .take(maximum_bytes + 1)
            .read_to_end(&mut bytes)
            .ok()
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    let deadline = Instant::now().checked_add(timeout)?;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    let bytes = receiver.recv_timeout(remaining).ok()??;
    Some((status, bytes))
}

fn parse_git_tracked_inventory(bytes: &[u8]) -> Option<BTreeSet<String>> {
    if bytes.is_empty() {
        return Some(BTreeSet::new());
    }
    if !bytes.ends_with(&[0]) {
        return None;
    }
    let mut paths = BTreeSet::new();
    for raw_path in bytes[..bytes.len() - 1].split(|byte| *byte == 0) {
        let path = std::str::from_utf8(raw_path).ok()?;
        if validate_normalized_relative_path(path).is_err() || !paths.insert(path.to_owned()) {
            return None;
        }
        if paths.len() > HARD_MAX_FILES {
            return None;
        }
    }
    Some(paths)
}

struct GitignoreSourceProof {
    source_path: PathBuf,
    relative_path: String,
    byte_length: u64,
    sha256: String,
}

#[derive(Clone, Copy)]
struct CopyDirectoryContext<'a> {
    source_root: &'a Path,
    limits: WorkspaceSnapshotLimits,
}

fn copy_directory(
    source_directory: &Path,
    destination_directory: &Path,
    relative_components: &[String],
    depth: usize,
    context: CopyDirectoryContext<'_>,
    state: &mut CopyState,
    exclusion_state: &mut CopyExclusionState,
) -> AppResult<()> {
    let CopyDirectoryContext {
        source_root,
        limits,
    } = context;
    let before = inspect_real_directory(source_directory, source_root)?;
    let entries = sorted_directory_entries(
        source_directory,
        limits
            .max_files
            .saturating_add(limits.max_directories)
            .saturating_add(1),
    )?;
    let gitignore_source = entries
        .iter()
        .find(|(name, _)| name == ".gitignore")
        .map(|(_, path)| path.as_path());
    let gitignore_proof = match exclusion_state {
        CopyExclusionState::RepositoryGitignore { matchers, .. } => {
            let (matcher, proof) = load_repository_gitignore(
                source_directory,
                gitignore_source,
                relative_components,
                limits,
            )?;
            if let Some(proof) = proof.as_ref() {
                state.gitignore_bytes_read = state
                    .gitignore_bytes_read
                    .checked_add(proof.byte_length)
                    .ok_or_else(|| {
                        AppError::Runtime("repository ignore-rule byte count overflowed".into())
                    })?;
                if state.gitignore_bytes_read > limits.max_total_bytes {
                    return Err(AppError::InvalidRequest(
                        "repository ignore rules exceed the snapshot total-byte safety limit"
                            .into(),
                    ));
                }
            }
            matchers.push(matcher);
            proof
        }
        CopyExclusionState::GitMetadataOnly => None,
    };
    for (name, source_path) in entries {
        let metadata = fs::symlink_metadata(&source_path).map_err(|error| {
            AppError::Runtime(format!(
                "selected working-tree entry could not be inspected: {error}"
            ))
        })?;
        let file_type = metadata.file_type();
        let mut components = relative_components.to_vec();
        components.push(name.clone());
        let relative_path = normalized_relative_path(&components)?;
        if name.eq_ignore_ascii_case(".git") {
            record_snapshot_exclusion(
                state,
                limits,
                relative_path,
                WorkspaceSnapshotExclusionReason::GitMetadata,
                excluded_entry_kind(&file_type),
            )?;
            continue;
        }
        if file_type.is_dir() {
            exclusion_state.register_nested_repository_if_present(&source_path, &components);
        }
        let ignored_untracked = name != ".gitignore"
            && exclusion_state.repository_path_is_ignored(
                &source_path,
                &relative_path,
                file_type.is_dir(),
            );
        if ignored_untracked && !preserve_ignored_secret_candidate(&components, &file_type) {
            record_snapshot_exclusion(
                state,
                limits,
                relative_path,
                WorkspaceSnapshotExclusionReason::RepositoryGitignoreUntracked,
                excluded_entry_kind(&file_type),
            )?;
            continue;
        }
        if file_type.is_symlink() {
            return Err(AppError::InvalidRequest(format!(
                "selected working tree contains a symlink at {relative_path}"
            )));
        }
        if file_type.is_dir() {
            if depth >= limits.max_depth {
                return Err(AppError::InvalidRequest(format!(
                    "selected working tree exceeds the maximum directory depth at {relative_path}"
                )));
            }
            if state.directories.len() >= limits.max_directories {
                return Err(AppError::InvalidRequest(
                    "selected working tree exceeds the directory-count limit".into(),
                ));
            }
            let destination = destination_directory.join(&name);
            create_private_directory(&destination)?;
            state.directories.push(relative_path);
            copy_directory(
                &source_path,
                &destination,
                &components,
                depth + 1,
                context,
                state,
                exclusion_state,
            )?;
        } else if file_type.is_file() {
            if state.files.len() >= limits.max_files {
                return Err(AppError::InvalidRequest(
                    "selected working tree exceeds the file-count limit".into(),
                ));
            }
            let copied = copy_regular_file(
                &source_path,
                &destination_directory.join(&name),
                &relative_path,
                source_root,
                limits,
                state.total_bytes,
            )?;
            state.total_bytes = state
                .total_bytes
                .checked_add(copied.byte_length)
                .ok_or_else(|| {
                    AppError::Runtime("workspace snapshot byte count overflowed".into())
                })?;
            state.files.push(copied);
        } else {
            return Err(AppError::InvalidRequest(format!(
                "selected working tree contains a device, FIFO, or socket at {relative_path}"
            )));
        }
    }
    if let Some(proof) = gitignore_proof {
        verify_gitignore_source(&proof)?;
        record_snapshot_ignore_rule_source(state, limits, proof)?;
    }
    if let CopyExclusionState::RepositoryGitignore { matchers, .. } = exclusion_state {
        matchers.pop().ok_or_else(|| {
            AppError::Internal("repository ignore matcher stack underflowed".into())
        })?;
    }
    let after = inspect_real_directory(source_directory, source_root)?;
    if before != after {
        return Err(AppError::Runtime(
            "selected working-tree directory changed while it was being copied".into(),
        ));
    }
    Ok(())
}

fn excluded_entry_kind(file_type: &fs::FileType) -> WorkspaceSnapshotExcludedEntryKind {
    if file_type.is_file() {
        WorkspaceSnapshotExcludedEntryKind::File
    } else if file_type.is_dir() {
        WorkspaceSnapshotExcludedEntryKind::Directory
    } else {
        WorkspaceSnapshotExcludedEntryKind::SymlinkOrSpecial
    }
}

fn record_snapshot_exclusion(
    state: &mut CopyState,
    limits: WorkspaceSnapshotLimits,
    relative_path: String,
    reason: WorkspaceSnapshotExclusionReason,
    entry_kind: WorkspaceSnapshotExcludedEntryKind,
) -> AppResult<()> {
    charge_snapshot_audit(state, limits, relative_path.len())?;
    state.exclusions.push(WorkspaceSnapshotExclusion {
        relative_path,
        reason,
        entry_kind,
    });
    Ok(())
}

fn record_snapshot_ignore_rule_source(
    state: &mut CopyState,
    limits: WorkspaceSnapshotLimits,
    proof: GitignoreSourceProof,
) -> AppResult<()> {
    charge_snapshot_audit(state, limits, proof.relative_path.len())?;
    state
        .ignore_rule_sources
        .push(WorkspaceSnapshotIgnoreRuleSource {
            relative_path: proof.relative_path,
            byte_length: proof.byte_length,
            sha256: proof.sha256,
        });
    Ok(())
}

fn charge_snapshot_audit(
    state: &mut CopyState,
    limits: WorkspaceSnapshotLimits,
    relative_path_bytes: usize,
) -> AppResult<()> {
    let maximum_records = limits
        .max_files
        .saturating_add(limits.max_directories)
        .saturating_add(1);
    if state
        .exclusions
        .len()
        .saturating_add(state.ignore_rule_sources.len())
        >= maximum_records
    {
        return Err(AppError::InvalidRequest(
            "workspace snapshot audit records exceed their safety bound".into(),
        ));
    }
    // JSON escaping can expand a validated path; charge twice the UTF-8 path
    // plus a fixed object/string envelope before retaining each record.
    let charge = u64::try_from(relative_path_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| bytes.checked_add(256))
        .ok_or_else(|| AppError::Runtime("workspace snapshot audit size overflowed".into()))?;
    let total = state
        .audit_bytes
        .checked_add(charge)
        .ok_or_else(|| AppError::Runtime("workspace snapshot audit size overflowed".into()))?;
    if total > MAX_WORKSPACE_SNAPSHOT_AUDIT_BYTES {
        return Err(AppError::InvalidRequest(
            "workspace snapshot exclusion audit exceeds its memory safety bound".into(),
        ));
    }
    state.audit_bytes = total;
    Ok(())
}

fn load_repository_gitignore(
    source_directory: &Path,
    gitignore_source: Option<&Path>,
    relative_components: &[String],
    limits: WorkspaceSnapshotLimits,
) -> AppResult<(Gitignore, Option<GitignoreSourceProof>)> {
    let Some(source_path) = gitignore_source else {
        return Ok((Gitignore::empty(), None));
    };
    let metadata = fs::symlink_metadata(source_path).map_err(|error| {
        AppError::Runtime(format!(
            "repository .gitignore could not be inspected: {error}"
        ))
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        // Git does not follow a symlink in place of a working-tree
        // .gitignore. The ordinary entry path below will either exclude this
        // entry through a parent rule or reject it under the snapshot's
        // symlink/special-file policy.
        return Ok((Gitignore::empty(), None));
    }

    let mut components = relative_components.to_vec();
    components.push(".gitignore".into());
    let relative_path = normalized_relative_path(&components)?;
    let maximum_bytes = limits.max_file_bytes.min(MAX_GITIGNORE_BYTES);
    let bytes = read_bounded_stable_file(source_path, maximum_bytes).map_err(|error| {
        AppError::InvalidRequest(format!(
            "repository ignore rules unreadable at {relative_path}: {error}"
        ))
    })?;
    let contents = std::str::from_utf8(&bytes).map_err(|_| {
        AppError::InvalidRequest(format!(
            "repository ignore rules are not valid UTF-8 at {relative_path}"
        ))
    })?;
    let mut builder = GitignoreBuilder::new(source_directory);
    for (line_index, raw_line) in contents.lines().enumerate() {
        let line = if line_index == 0 {
            raw_line.trim_start_matches('\u{feff}')
        } else {
            raw_line
        };
        builder
            .add_line(Some(source_path.to_path_buf()), line)
            .map_err(|error| {
                AppError::InvalidRequest(format!(
                    "repository ignore rule is invalid at {relative_path}:{}: {error}",
                    line_index + 1
                ))
            })?;
    }
    let matcher = builder.build().map_err(|error| {
        AppError::InvalidRequest(format!(
            "repository ignore rules could not be compiled at {relative_path}: {error}"
        ))
    })?;
    let proof = GitignoreSourceProof {
        source_path: source_path.to_path_buf(),
        relative_path,
        byte_length: bytes.len() as u64,
        sha256: sha256_bytes(&bytes),
    };
    Ok((matcher, Some(proof)))
}

fn verify_gitignore_source(proof: &GitignoreSourceProof) -> AppResult<()> {
    let verified = hash_bounded_stable_file(&proof.source_path, MAX_GITIGNORE_BYTES);
    let (sha256, byte_length) = verified.map_err(|error| {
        AppError::Runtime(format!(
            "repository ignore rules changed while the snapshot was being copied at {}: {error}",
            proof.relative_path
        ))
    })?;
    if byte_length != proof.byte_length || sha256 != proof.sha256 {
        return Err(changed_file_error(&proof.relative_path));
    }
    Ok(())
}

fn copy_regular_file(
    source_path: &Path,
    destination_path: &Path,
    relative_path: &str,
    source_root: &Path,
    limits: WorkspaceSnapshotLimits,
    total_before: u64,
) -> AppResult<WorkspaceSnapshotFile> {
    ensure_canonical_inside(source_path, source_root)?;
    let path_metadata = fs::symlink_metadata(source_path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(AppError::InvalidRequest(format!(
            "selected working-tree entry is not a regular file at {relative_path}"
        )));
    }
    let mut source = open_readonly_nofollow(source_path).map_err(|error| {
        AppError::Runtime(format!(
            "selected working-tree file could not be opened without following links at {relative_path}: {error}"
        ))
    })?;
    let opened_metadata = source.metadata()?;
    if !opened_metadata.is_file() {
        return Err(AppError::InvalidRequest(format!(
            "selected working-tree entry is not a regular file at {relative_path}"
        )));
    }
    let initial = FileFingerprint::from_metadata(&opened_metadata);
    if initial != FileFingerprint::from_metadata(&path_metadata) {
        return Err(changed_file_error(relative_path));
    }
    if initial.byte_length > limits.max_file_bytes
        || initial.byte_length > limits.max_total_bytes.saturating_sub(total_before)
    {
        return Err(AppError::InvalidRequest(format!(
            "selected working-tree file exceeds its byte limit at {relative_path}"
        )));
    }

    let mut destination = create_private_new_file(destination_path)?;
    let mut digest = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied.checked_add(read as u64).ok_or_else(|| {
            AppError::Runtime("workspace snapshot file byte count overflowed".into())
        })?;
        if copied > limits.max_file_bytes
            || copied > limits.max_total_bytes.saturating_sub(total_before)
        {
            return Err(AppError::InvalidRequest(format!(
                "selected working-tree file exceeded its byte limit while copying at {relative_path}"
            )));
        }
        destination.write_all(&buffer[..read])?;
        digest.update(&buffer[..read]);
    }
    destination.sync_all()?;
    let after_copy = FileFingerprint::from_metadata(&source.metadata()?);
    if copied != initial.byte_length || initial != after_copy {
        return Err(changed_file_error(relative_path));
    }

    // A second read prevents a same-length content change from being accepted
    // merely because a platform exposes coarse modification timestamps.
    source.seek(SeekFrom::Start(0))?;
    let before_verify = FileFingerprint::from_metadata(&source.metadata()?);
    let mut verify_digest = Sha256::new();
    let mut verified_bytes = 0_u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        verified_bytes = verified_bytes.checked_add(read as u64).ok_or_else(|| {
            AppError::Runtime("workspace snapshot verification byte count overflowed".into())
        })?;
        if verified_bytes > limits.max_file_bytes {
            return Err(changed_file_error(relative_path));
        }
        verify_digest.update(&buffer[..read]);
    }
    let after_verify = FileFingerprint::from_metadata(&source.metadata()?);
    let final_path_metadata =
        fs::symlink_metadata(source_path).map_err(|_| changed_file_error(relative_path))?;
    let verified_digest = verify_digest.finalize();
    let copied_digest = digest.clone().finalize();
    if before_verify != after_verify
        || initial != after_verify
        || after_verify != FileFingerprint::from_metadata(&final_path_metadata)
        || verified_bytes != copied
        || verified_digest != copied_digest
    {
        return Err(changed_file_error(relative_path));
    }
    drop(destination);
    set_readonly_file(destination_path)?;

    Ok(WorkspaceSnapshotFile {
        relative_path: relative_path.into(),
        byte_length: copied,
        sha256: hex::encode(digest.finalize()),
    })
}

fn verify_directory(
    directory: &Path,
    relative_components: &[String],
    depth: usize,
    tree_root: &Path,
    limits: WorkspaceSnapshotLimits,
    state: &mut VerificationState,
) -> AppResult<()> {
    let before = inspect_real_directory(directory, tree_root)?;
    for (name, path) in sorted_directory_entries(
        directory,
        limits
            .max_files
            .saturating_add(limits.max_directories)
            .saturating_add(1),
    )? {
        let mut components = relative_components.to_vec();
        components.push(name.clone());
        let relative_path = normalized_relative_path(&components)?;
        if name.eq_ignore_ascii_case(".git") {
            return Err(AppError::Runtime(
                "stored working-tree snapshot contains excluded Git metadata".into(),
            ));
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(AppError::Runtime(
                "stored working-tree snapshot contains a symlink".into(),
            ));
        }
        if metadata.is_dir() {
            if depth >= limits.max_depth || state.directories.len() >= limits.max_directories {
                return Err(AppError::Runtime(
                    "stored working-tree snapshot exceeds its directory bounds".into(),
                ));
            }
            state.directories.push(relative_path);
            verify_directory(&path, &components, depth + 1, tree_root, limits, state)?;
        } else if metadata.is_file() {
            if state.files.len() >= limits.max_files {
                return Err(AppError::Runtime(
                    "stored working-tree snapshot exceeds its file bound".into(),
                ));
            }
            let remaining = limits.max_total_bytes.saturating_sub(state.total_bytes);
            let (sha256, byte_length) =
                hash_bounded_stable_file(&path, remaining.min(HARD_MAX_FILE_BYTES))?;
            state.total_bytes = state
                .total_bytes
                .checked_add(byte_length)
                .ok_or_else(|| AppError::Runtime("snapshot byte count overflowed".into()))?;
            state.files.push(WorkspaceSnapshotFile {
                relative_path,
                byte_length,
                sha256,
            });
        } else {
            return Err(AppError::Runtime(
                "stored working-tree snapshot contains an unsupported filesystem entry".into(),
            ));
        }
    }
    let after = inspect_real_directory(directory, tree_root)?;
    if before != after {
        return Err(AppError::Runtime(
            "stored workspace snapshot changed during verification".into(),
        ));
    }
    Ok(())
}

fn validate_reference(reference: &WorkspaceSnapshotReference) -> AppResult<()> {
    if reference.schema_version != WORKSPACE_SNAPSHOT_REFERENCE_SCHEMA
        || !reference.working_tree_only
        || !valid_storage_id(&reference.storage_id)
        || !valid_sha256(&reference.sha256)
        || reference.snapshot_id != format!("{SNAPSHOT_ID_PREFIX}{}", reference.sha256)
        || reference.file_count > HARD_MAX_FILES
        || reference.directory_count > HARD_MAX_DIRECTORIES
        || reference.total_bytes > HARD_MAX_TOTAL_BYTES
    {
        return Err(AppError::InvalidRequest(
            "workspace snapshot reference is invalid or exceeds safety bounds".into(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_manifest(
    manifest: &WorkspaceSnapshotManifest,
    reference: &WorkspaceSnapshotReference,
) -> AppResult<()> {
    let totals_match = manifest.directory_count == manifest.directories.len()
        && manifest.file_count == manifest.files.len()
        && manifest.directory_count == reference.directory_count
        && manifest.file_count == reference.file_count
        && manifest.total_bytes == reference.total_bytes;
    let exclusion_policy_is_valid = match manifest.schema_version.as_str() {
        LEGACY_WORKSPACE_SNAPSHOT_SCHEMA => {
            manifest.exclusion_policy.is_none()
                && manifest.exclusions.is_empty()
                && manifest.ignore_rule_sources.is_empty()
        }
        LEGACY_GITIGNORE_WORKSPACE_SNAPSHOT_SCHEMA => {
            manifest.exclusion_policy
                == Some(if manifest.input_profile.is_repository() {
                    WorkspaceSnapshotExclusionPolicy::RepositoryGitignoreV1
                } else {
                    WorkspaceSnapshotExclusionPolicy::GitMetadataOnlyV1
                })
                && manifest.exclusions.is_empty()
                && manifest.ignore_rule_sources.is_empty()
        }
        WORKSPACE_SNAPSHOT_SCHEMA => {
            manifest.exclusion_policy
                == Some(if manifest.input_profile.is_repository() {
                    WorkspaceSnapshotExclusionPolicy::RepositoryTrackedGitignoreV2
                } else {
                    WorkspaceSnapshotExclusionPolicy::GitMetadataOnlyV2
                })
        }
        _ => false,
    };
    if !exclusion_policy_is_valid
        || manifest.content_semantics != WORKING_TREE_SEMANTICS
        || manifest.input_profile != reference.input_profile
        || manifest.excluded_entries != [".git"]
        || !totals_match
    {
        return Err(AppError::Runtime(
            "workspace snapshot manifest metadata is inconsistent".into(),
        ));
    }
    let mut previous_directory: Option<&str> = None;
    for directory in &manifest.directories {
        validate_normalized_relative_path(directory)?;
        if previous_directory.is_some_and(|previous| previous.as_bytes() >= directory.as_bytes()) {
            return Err(AppError::Runtime(
                "workspace snapshot manifest directories are not uniquely sorted".into(),
            ));
        }
        previous_directory = Some(directory);
    }
    let mut total_bytes = 0_u64;
    let mut previous_file: Option<&str> = None;
    for file in &manifest.files {
        validate_normalized_relative_path(&file.relative_path)?;
        if !valid_sha256(&file.sha256)
            || previous_file
                .is_some_and(|previous| previous.as_bytes() >= file.relative_path.as_bytes())
        {
            return Err(AppError::Runtime(
                "workspace snapshot manifest files are invalid or not uniquely sorted".into(),
            ));
        }
        total_bytes = total_bytes.checked_add(file.byte_length).ok_or_else(|| {
            AppError::Runtime("workspace snapshot manifest byte count overflowed".into())
        })?;
        previous_file = Some(&file.relative_path);
    }
    if total_bytes != manifest.total_bytes {
        return Err(AppError::Runtime(
            "workspace snapshot manifest aggregate byte count is invalid".into(),
        ));
    }
    validate_manifest_exclusion_audit(manifest)?;
    Ok(())
}

fn validate_manifest_exclusion_audit(manifest: &WorkspaceSnapshotManifest) -> AppResult<()> {
    let is_current = manifest.schema_version == WORKSPACE_SNAPSHOT_SCHEMA;
    let copied_files = manifest
        .files
        .iter()
        .map(|file| (file.relative_path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    let copied_directories = manifest
        .directories
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    let mut previous_exclusion: Option<&WorkspaceSnapshotExclusion> = None;
    for exclusion in &manifest.exclusions {
        validate_normalized_relative_path(&exclusion.relative_path)?;
        if previous_exclusion.is_some_and(|previous| previous >= exclusion)
            || copied_files.contains_key(exclusion.relative_path.as_str())
            || copied_directories.contains(exclusion.relative_path.as_str())
        {
            return Err(AppError::Runtime(
                "workspace snapshot exclusion audit is invalid or not uniquely sorted".into(),
            ));
        }
        match exclusion.reason {
            WorkspaceSnapshotExclusionReason::GitMetadata => {
                if !exclusion
                    .relative_path
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case(".git"))
                {
                    return Err(AppError::Runtime(
                        "workspace snapshot Git-metadata exclusion audit is invalid".into(),
                    ));
                }
            }
            WorkspaceSnapshotExclusionReason::RepositoryGitignoreUntracked => {
                if !manifest.input_profile.is_repository()
                    || manifest.ignore_rule_sources.is_empty()
                {
                    return Err(AppError::Runtime(
                        "workspace snapshot ignore exclusion lacks an auditable rule source".into(),
                    ));
                }
            }
        }
        previous_exclusion = Some(exclusion);
    }

    let mut previous_source: Option<&WorkspaceSnapshotIgnoreRuleSource> = None;
    for source in &manifest.ignore_rule_sources {
        validate_normalized_relative_path(&source.relative_path)?;
        let copied = copied_files.get(source.relative_path.as_str());
        if previous_source.is_some_and(|previous| previous >= source)
            || !source
                .relative_path
                .rsplit('/')
                .next()
                .is_some_and(|name| name == ".gitignore")
            || !valid_sha256(&source.sha256)
            || copied.is_none_or(|file| {
                file.byte_length != source.byte_length || file.sha256 != source.sha256
            })
        {
            return Err(AppError::Runtime(
                "workspace snapshot ignore-rule source audit is invalid or not uniquely sorted"
                    .into(),
            ));
        }
        previous_source = Some(source);
    }
    if is_current
        && !manifest.input_profile.is_repository()
        && !manifest.ignore_rule_sources.is_empty()
    {
        return Err(AppError::Runtime(
            "non-repository workspace snapshot contains repository ignore-rule audit data".into(),
        ));
    }
    Ok(())
}

fn validate_selected_input_profile(
    selected_source: &Path,
    input_profile: WorkspaceInputProfile,
) -> AppResult<()> {
    match fs::symlink_metadata(selected_source.join(LOCAL_INPUT_PROFILE_FILENAME)) {
        Ok(_) => {
            return Err(AppError::InvalidRequest(format!(
                "selected local input contains the reserved backend marker {LOCAL_INPUT_PROFILE_FILENAME}"
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(AppError::InvalidRequest(format!(
                "selected local input marker path could not be inspected: {error}"
            )));
        }
    }

    if input_profile == WorkspaceInputProfile::KubernetesNodeSnapshot {
        let node_root = selected_source.join("node-snapshot");
        let metadata = fs::symlink_metadata(&node_root).map_err(|error| {
            AppError::InvalidRequest(format!(
                "Kubernetes node input must contain a node-snapshot directory: {error}"
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AppError::InvalidRequest(
                "Kubernetes node input must contain a real node-snapshot directory".into(),
            ));
        }
    }
    Ok(())
}

fn validate_resolved_input_profile(
    tree_path: &Path,
    input_profile: WorkspaceInputProfile,
) -> AppResult<()> {
    let marker_path = tree_path.join(LOCAL_INPUT_PROFILE_FILENAME);
    if input_profile.is_repository() {
        return match fs::symlink_metadata(marker_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(AppError::Runtime(
                "repository snapshot contains a reserved local input profile marker".into(),
            )),
        };
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Marker {
        schema_version: String,
        input_profile: WorkspaceInputProfile,
    }

    let bytes = read_bounded_stable_file(&marker_path, 4 * 1024)?;
    let marker: Marker = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::Runtime("local input profile marker is invalid".into()))?;
    if marker.schema_version != LOCAL_INPUT_PROFILE_SCHEMA || marker.input_profile != input_profile
    {
        return Err(AppError::Runtime(
            "local input profile marker conflicts with its backend reference".into(),
        ));
    }
    Ok(())
}

fn validate_copied_input_files(
    tree_path: &Path,
    state: &CopyState,
    input_profile: WorkspaceInputProfile,
) -> AppResult<()> {
    let has_extension = |extensions: &[&str]| {
        state.files.iter().any(|file| {
            Path::new(&file.relative_path)
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    extensions
                        .iter()
                        .any(|expected| extension.eq_ignore_ascii_case(expected))
                })
        })
    };
    match input_profile {
        WorkspaceInputProfile::RepositoryWorkingTree => Ok(()),
        WorkspaceInputProfile::IacWorkingTree if !has_extension(&["tf", "json", "yaml", "yml"]) => {
            Err(AppError::InvalidRequest(
                "infrastructure-as-code input contains no .tf, .json, .yaml, or .yml file".into(),
            ))
        }
        WorkspaceInputProfile::KubernetesManifests if !has_extension(&["json", "yaml", "yml"]) => {
            Err(AppError::InvalidRequest(
                "Kubernetes manifest input contains no .json, .yaml, or .yml file".into(),
            ))
        }
        WorkspaceInputProfile::ContainerImageOciLayout => validate_oci_image_layout(tree_path),
        WorkspaceInputProfile::KubernetesNodeSnapshot => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct NodeSnapshotProfile {
                schema_version: String,
                profile: String,
                benchmark: String,
                captured_at: String,
                files: Vec<NodeSnapshotFile>,
                processes: Vec<NodeSnapshotProcess>,
            }

            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct NodeSnapshotFile {
                path: String,
                source_path: String,
                sha256: String,
                mode: String,
                owner: String,
                group: String,
            }

            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct NodeSnapshotProcess {
                name: String,
                command: String,
            }

            let profile_path = tree_path.join("node-snapshot/profile.json");
            let bytes = read_bounded_stable_file(&profile_path, 256 * 1024).map_err(|_| {
                AppError::InvalidRequest(
                    "Kubernetes node input requires node-snapshot/profile.json".into(),
                )
            })?;
            let identity: Value = serde_json::from_slice(&bytes).map_err(|_| {
                AppError::InvalidRequest(
                    "Kubernetes node snapshot profile.json is not valid JSON".into(),
                )
            })?;
            if identity.get("schema_version").and_then(Value::as_str) == Some("1.0.0")
                && identity.get("profile").and_then(Value::as_str)
                    == Some("cis-kubernetes-node-config")
            {
                // The catalog still pins the published schema-1 image. Keep
                // existing snapshots runnable until a product-owner release
                // moves the immutable image coordinate to the upstream-profile
                // build prepared by this source tree.
                return Ok(());
            }
            let profile: NodeSnapshotProfile = serde_json::from_slice(&bytes).map_err(|_| {
                AppError::InvalidRequest(
                    "Kubernetes node snapshot profile.json is not valid JSON".into(),
                )
            })?;
            if profile.schema_version != "2.0.0"
                || profile.profile != "cis-kubernetes-node-facts"
                || profile.benchmark != "cis-1.11"
                || chrono::DateTime::parse_from_rfc3339(&profile.captured_at).is_err()
            {
                return Err(AppError::InvalidRequest(
                    "Kubernetes node snapshot profile identity is invalid".into(),
                ));
            }

            let expected_files = BTreeSet::from([
                "ca.crt",
                "kube-proxy.yaml",
                "kubelet-config.yaml",
                "kubelet.conf",
                "kubelet.service",
            ]);
            let mut observed_files = BTreeSet::new();
            for file in &profile.files {
                let source_path_valid = file.source_path.len() > 1
                    && file.source_path.len() <= MAX_RELATIVE_PATH_BYTES
                    && file.source_path.starts_with('/')
                    && !file.source_path.contains(['\\', '\0'])
                    && !file.source_path.chars().any(char::is_control)
                    && !file
                        .source_path
                        .split('/')
                        .skip(1)
                        .any(|part| part.is_empty() || part == "." || part == "..");
                let identity_valid = |value: &str| {
                    !value.is_empty()
                        && value.len() <= 64
                        && value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                        })
                };
                let mode_valid = matches!(file.mode.len(), 3 | 4)
                    && file.mode.bytes().all(|byte| matches!(byte, b'0'..=b'7'));
                let digest = file.sha256.strip_prefix("sha256:");
                let copied = state
                    .files
                    .iter()
                    .find(|copied| copied.relative_path == format!("node-snapshot/{}", file.path));
                if !expected_files.contains(file.path.as_str())
                    || !observed_files.insert(file.path.as_str())
                    || !source_path_valid
                    || !mode_valid
                    || !identity_valid(&file.owner)
                    || !identity_valid(&file.group)
                    || digest.is_none_or(|value| !valid_sha256(value))
                    || copied.is_none_or(|copied| Some(copied.sha256.as_str()) != digest)
                {
                    return Err(AppError::InvalidRequest(
                        "Kubernetes node snapshot file facts are incomplete or invalid".into(),
                    ));
                }
            }
            if observed_files != expected_files {
                return Err(AppError::InvalidRequest(
                    "Kubernetes node snapshot requires the complete bounded file fact set".into(),
                ));
            }
            let expected_snapshot_paths = expected_files
                .iter()
                .map(|path| format!("node-snapshot/{path}"))
                .chain(std::iter::once("node-snapshot/profile.json".into()))
                .collect::<BTreeSet<_>>();
            let observed_snapshot_paths = state
                .files
                .iter()
                .filter(|file| file.relative_path.starts_with("node-snapshot/"))
                .map(|file| file.relative_path.clone())
                .collect::<BTreeSet<_>>();
            if observed_snapshot_paths != expected_snapshot_paths {
                return Err(AppError::InvalidRequest(
                    "Kubernetes node snapshot contains files outside its immutable inventory"
                        .into(),
                ));
            }

            let expected_processes = BTreeSet::from(["kube-proxy", "kubelet"]);
            let mut observed_processes = BTreeSet::new();
            for process in &profile.processes {
                if !expected_processes.contains(process.name.as_str())
                    || !observed_processes.insert(process.name.as_str())
                    || process.command.len() < process.name.len()
                    || process.command.len() > 8_192
                    || process.command.trim() != process.command
                    || process.command.chars().any(char::is_control)
                    || !process.command.contains(&process.name)
                {
                    return Err(AppError::InvalidRequest(
                        "Kubernetes node snapshot process facts are incomplete or invalid".into(),
                    ));
                }
            }
            if observed_processes != expected_processes {
                return Err(AppError::InvalidRequest(
                    "Kubernetes node snapshot requires the complete bounded process fact set"
                        .into(),
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_oci_image_layout(tree_path: &Path) -> AppResult<()> {
    let layout = read_bounded_json(tree_path, "oci-layout", 64 * 1024)?;
    if layout.get("imageLayoutVersion").and_then(Value::as_str) != Some("1.0.0") {
        return Err(AppError::InvalidRequest(
            "OCI image layout must declare imageLayoutVersion 1.0.0".into(),
        ));
    }
    let index = read_bounded_json(tree_path, "index.json", 16 * 1024 * 1024)?;
    if index.get("schemaVersion").and_then(Value::as_u64) != Some(2) {
        return Err(AppError::InvalidRequest(
            "OCI image index must use schemaVersion 2".into(),
        ));
    }
    require_oci_json_media_type(&index, OCI_IMAGE_INDEX_MEDIA_TYPE, "image index")?;
    let manifests = index
        .get("manifests")
        .and_then(Value::as_array)
        .filter(|manifests| manifests.len() == 1)
        .ok_or_else(|| {
            AppError::InvalidRequest(
                "OCI image layout must select exactly one image manifest".into(),
            )
        })?;
    require_oci_descriptor_media_type(
        &manifests[0],
        &[OCI_IMAGE_MANIFEST_MEDIA_TYPE],
        "image manifest",
    )?;
    let mut referenced_blobs = BTreeSet::new();
    referenced_blobs.insert(oci_descriptor_digest(&manifests[0])?.to_owned());
    let manifest_bytes = verify_oci_descriptor(tree_path, &manifests[0], 16 * 1024 * 1024)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| AppError::InvalidRequest("OCI image manifest is not valid JSON".into()))?;
    if manifest.get("schemaVersion").and_then(Value::as_u64) != Some(2) {
        return Err(AppError::InvalidRequest(
            "OCI image manifest must use schemaVersion 2".into(),
        ));
    }
    require_oci_json_media_type(&manifest, OCI_IMAGE_MANIFEST_MEDIA_TYPE, "image manifest")?;
    let config = manifest.get("config").ok_or_else(|| {
        AppError::InvalidRequest("OCI image manifest has no config descriptor".into())
    })?;
    require_oci_descriptor_media_type(config, &[OCI_IMAGE_CONFIG_MEDIA_TYPE], "image config")?;
    referenced_blobs.insert(oci_descriptor_digest(config)?.to_owned());
    let config_bytes = verify_oci_descriptor(tree_path, config, 16 * 1024 * 1024)?;
    let config: Value = serde_json::from_slice(&config_bytes)
        .map_err(|_| AppError::InvalidRequest("OCI image config is not valid JSON".into()))?;
    validate_oci_platform(&config)?;
    let layers = manifest
        .get("layers")
        .and_then(Value::as_array)
        .filter(|layers| layers.len() <= OCI_MAX_LAYERS)
        .ok_or_else(|| {
            AppError::InvalidRequest("OCI image layer inventory is invalid or unbounded".into())
        })?;
    let diff_ids = config
        .get("rootfs")
        .and_then(Value::as_object)
        .filter(|rootfs| rootfs.get("type").and_then(Value::as_str) == Some("layers"))
        .and_then(|rootfs| rootfs.get("diff_ids"))
        .and_then(Value::as_array)
        .filter(|diff_ids| diff_ids.len() == layers.len())
        .ok_or_else(|| {
            AppError::InvalidRequest(
                "OCI image config rootfs diff_ids do not match its layer inventory".into(),
            )
        })?;
    let mut tar_entries = 0_usize;
    for (layer, diff_id) in layers.iter().zip(diff_ids) {
        let media_type = require_oci_descriptor_media_type(
            layer,
            &[
                OCI_IMAGE_LAYER_TAR_MEDIA_TYPE,
                OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE,
            ],
            "image layer",
        )?;
        referenced_blobs.insert(oci_descriptor_digest(layer)?.to_owned());
        let bytes = verify_oci_descriptor(tree_path, layer, HARD_MAX_FILE_BYTES)?;
        let expected_diff_id = diff_id
            .as_str()
            .and_then(|digest| digest.strip_prefix("sha256:"))
            .filter(|digest| valid_sha256(digest))
            .ok_or_else(|| {
                AppError::InvalidRequest(
                    "OCI image config contains an invalid layer diff_id".into(),
                )
            })?;
        validate_oci_layer_tar(&bytes, media_type, expected_diff_id, &mut tar_entries)?;
    }
    validate_exact_oci_blob_inventory(tree_path, &referenced_blobs)?;
    Ok(())
}

fn require_oci_json_media_type<'a>(
    value: &'a Value,
    expected: &str,
    kind: &str,
) -> AppResult<&'a str> {
    value
        .get("mediaType")
        .and_then(Value::as_str)
        .filter(|media_type| *media_type == expected)
        .ok_or_else(|| AppError::InvalidRequest(format!("OCI {kind} mediaType is invalid")))
}

fn require_oci_descriptor_media_type<'a>(
    descriptor: &'a Value,
    allowed: &[&str],
    kind: &str,
) -> AppResult<&'a str> {
    descriptor
        .get("mediaType")
        .and_then(Value::as_str)
        .filter(|media_type| allowed.contains(media_type))
        .ok_or_else(|| {
            AppError::InvalidRequest(format!("OCI {kind} descriptor mediaType is invalid"))
        })
}

fn oci_descriptor_digest(descriptor: &Value) -> AppResult<&str> {
    descriptor
        .get("digest")
        .and_then(Value::as_str)
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .filter(|digest| valid_sha256(digest))
        .ok_or_else(|| AppError::InvalidRequest("OCI descriptor has an invalid digest".into()))
}

fn validate_oci_platform(config: &Value) -> AppResult<()> {
    for key in ["architecture", "os"] {
        let valid = config
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|value| {
                !value.is_empty()
                    && value.len() <= 64
                    && value.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'_' | b'.' | b'-')
                    })
            });
        if !valid {
            return Err(AppError::InvalidRequest(format!(
                "OCI image config {key} is invalid"
            )));
        }
    }
    Ok(())
}

fn validate_oci_layer_tar(
    bytes: &[u8],
    media_type: &str,
    expected_diff_id: &str,
    total_entries: &mut usize,
) -> AppResult<()> {
    if media_type == OCI_IMAGE_LAYER_TAR_MEDIA_TYPE {
        if sha256_bytes(bytes) != expected_diff_id {
            return Err(AppError::InvalidRequest(
                "OCI image layer does not match its config diff_id".into(),
            ));
        }
        inspect_oci_tar(Cursor::new(bytes), total_entries)?;
        return Ok(());
    }

    let reader =
        DigestingBoundedReader::new(MultiGzDecoder::new(bytes), OCI_MAX_UNCOMPRESSED_LAYER_BYTES);
    let reader = inspect_oci_tar(reader, total_entries)?;
    let (actual_diff_id, _) = reader.finish()?;
    if actual_diff_id != expected_diff_id {
        return Err(AppError::InvalidRequest(
            "OCI image layer does not match its config diff_id".into(),
        ));
    }
    Ok(())
}

fn inspect_oci_tar<R: Read>(reader: R, total_entries: &mut usize) -> AppResult<R> {
    let mut archive = tar::Archive::new(reader);
    let entries = archive.entries().map_err(|_| {
        AppError::InvalidRequest("OCI image layer is not a valid tar archive".into())
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|_| {
            AppError::InvalidRequest("OCI image layer contains an invalid tar entry".into())
        })?;
        *total_entries = total_entries.checked_add(1).ok_or_else(|| {
            AppError::InvalidRequest("OCI image layer entry count overflowed".into())
        })?;
        if *total_entries > OCI_MAX_TAR_ENTRIES || entry.size() > HARD_MAX_FILE_BYTES {
            return Err(AppError::InvalidRequest(
                "OCI image layer tar inventory exceeds its safety bound".into(),
            ));
        }
        let path = entry.path().map_err(|_| {
            AppError::InvalidRequest("OCI image layer contains an invalid tar path".into())
        })?;
        if path.as_os_str().is_empty()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(AppError::InvalidRequest(
                "OCI image layer contains a path outside its root".into(),
            ));
        }
        io::copy(&mut entry, &mut io::sink()).map_err(|_| {
            AppError::InvalidRequest("OCI image layer tar payload is invalid or unbounded".into())
        })?;
    }
    let mut reader = archive.into_inner();
    io::copy(&mut reader, &mut io::sink()).map_err(|_| {
        AppError::InvalidRequest("OCI image layer tar trailer is invalid or unbounded".into())
    })?;
    Ok(reader)
}

struct DigestingBoundedReader<R> {
    inner: R,
    digest: Sha256,
    bytes_read: u64,
    limit: u64,
}

impl<R> DigestingBoundedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
            bytes_read: 0,
            limit,
        }
    }

    fn finish(self) -> AppResult<(String, u64)> {
        Ok((hex::encode(self.digest.finalize()), self.bytes_read))
    }
}

impl<R: Read> Read for DigestingBoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let remaining = self.limit.saturating_sub(self.bytes_read);
        let request = buffer
            .len()
            .min(usize::try_from(remaining.saturating_add(1)).unwrap_or(buffer.len()));
        let read = self.inner.read(&mut buffer[..request])?;
        if u64::try_from(read).unwrap_or(u64::MAX) > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "OCI image layer exceeds its uncompressed byte limit",
            ));
        }
        self.digest.update(&buffer[..read]);
        self.bytes_read = self.bytes_read.saturating_add(read as u64);
        Ok(read)
    }
}

fn validate_exact_oci_blob_inventory(root: &Path, expected: &BTreeSet<String>) -> AppResult<()> {
    let blob_root = root.join("blobs").join("sha256");
    ensure_canonical_inside(&blob_root, root).map_err(|_| {
        AppError::InvalidRequest("OCI image blob directory is missing or unsafe".into())
    })?;
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(&blob_root).map_err(|_| {
        AppError::InvalidRequest("OCI image blob directory cannot be enumerated".into())
    })? {
        let entry = entry.map_err(|_| {
            AppError::InvalidRequest("OCI image blob directory contains an invalid entry".into())
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            AppError::InvalidRequest("OCI image blob name is not valid UTF-8".into())
        })?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| AppError::InvalidRequest("OCI image blob cannot be inspected".into()))?;
        if !valid_sha256(&name) || !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(AppError::InvalidRequest(
                "OCI image blob inventory contains an unsafe entry".into(),
            ));
        }
        actual.insert(name);
    }
    if &actual != expected {
        return Err(AppError::InvalidRequest(
            "OCI image layout contains missing or unreferenced blobs".into(),
        ));
    }
    Ok(())
}

fn read_bounded_json(root: &Path, relative_path: &str, max_bytes: u64) -> AppResult<Value> {
    let path = root.join(relative_path);
    ensure_canonical_inside(&path, root).map_err(|_| {
        AppError::InvalidRequest(format!(
            "local input is missing a safe regular {relative_path}"
        ))
    })?;
    let bytes = read_bounded_stable_file(&path, max_bytes).map_err(|_| {
        AppError::InvalidRequest(format!(
            "local input is missing a bounded regular {relative_path}"
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        AppError::InvalidRequest(format!("local input {relative_path} is not valid JSON"))
    })
}

fn verify_oci_descriptor(root: &Path, descriptor: &Value, max_bytes: u64) -> AppResult<Vec<u8>> {
    let digest = oci_descriptor_digest(descriptor)?;
    let expected_size = descriptor
        .get("size")
        .and_then(Value::as_u64)
        .filter(|size| *size > 0 && *size <= max_bytes)
        .ok_or_else(|| AppError::InvalidRequest("OCI descriptor has an invalid size".into()))?;
    let blob_path = root.join("blobs").join("sha256").join(digest);
    ensure_canonical_inside(&blob_path, root).map_err(|_| {
        AppError::InvalidRequest("OCI descriptor blob is missing or escaped the layout".into())
    })?;
    let bytes = read_bounded_stable_file(&blob_path, max_bytes).map_err(|_| {
        AppError::InvalidRequest("OCI descriptor blob is not a bounded regular file".into())
    })?;
    if bytes.len() as u64 != expected_size || sha256_bytes(&bytes) != digest {
        return Err(AppError::InvalidRequest(
            "OCI descriptor size or SHA-256 does not match its blob".into(),
        ));
    }
    Ok(bytes)
}

fn write_input_profile_marker(
    tree_path: &Path,
    input_profile: WorkspaceInputProfile,
    limits: WorkspaceSnapshotLimits,
    state: &mut CopyState,
) -> AppResult<()> {
    #[derive(Serialize)]
    struct Marker {
        schema_version: &'static str,
        input_profile: WorkspaceInputProfile,
    }

    let mut bytes = serde_json::to_vec(&Marker {
        schema_version: LOCAL_INPUT_PROFILE_SCHEMA,
        input_profile,
    })?;
    bytes.push(b'\n');
    let byte_length = u64::try_from(bytes.len())
        .map_err(|_| AppError::Runtime("local input profile marker length overflowed".into()))?;
    let total_bytes = state
        .total_bytes
        .checked_add(byte_length)
        .ok_or_else(|| AppError::Runtime("workspace snapshot byte count overflowed".into()))?;
    if state.files.len() >= limits.max_files || total_bytes > limits.max_total_bytes {
        return Err(AppError::InvalidRequest(
            "local input profile marker would exceed snapshot limits".into(),
        ));
    }
    write_private_readonly_file(&tree_path.join(LOCAL_INPUT_PROFILE_FILENAME), &bytes)?;
    state.files.push(WorkspaceSnapshotFile {
        relative_path: LOCAL_INPUT_PROFILE_FILENAME.into(),
        byte_length,
        sha256: sha256_bytes(&bytes),
    });
    state.total_bytes = total_bytes;
    Ok(())
}

fn snapshot_asset(
    source_id: &str,
    snapshot_id: &str,
    sha256: &str,
    input_profile: WorkspaceInputProfile,
) -> Asset {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "workspace_snapshot_id".into(),
        Value::String(snapshot_id.into()),
    );
    metadata.insert(
        "workspace_snapshot_sha256".into(),
        Value::String(sha256.into()),
    );
    if !input_profile.is_repository() {
        metadata.insert(
            "local_input_profile".into(),
            serde_json::to_value(input_profile).expect("local input profile serializes"),
        );
    }
    Asset {
        id: format!("{ASSET_ID_PREFIX}{source_id}"),
        kind: input_profile.asset_kind(),
        name: format!(
            "Local {} snapshot {}",
            input_profile.display_name(),
            &sha256[..12]
        ),
        provider: None,
        region: None,
        identifiers: vec![AssetIdentifier {
            namespace: "ai-security-scanner:workspace-snapshot-sha256".into(),
            value: sha256.into(),
        }],
        discovered_from: vec![source_id.into()],
        candidate: true,
        owner_confirmed: false,
        internet_exposed: None,
        contains_sensitive_data: None,
        metadata,
    }
}

fn prepare_existing_directory(path: &Path, label: &str) -> AppResult<PathBuf> {
    let canonical = inspect_existing_directory(path, label)?;
    set_private_directory(&canonical)?;
    Ok(canonical)
}

fn inspect_existing_directory(path: &Path, label: &str) -> AppResult<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::InvalidRequest(format!("{label} could not be inspected: {error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::InvalidRequest(format!(
            "{label} must be a real directory, not a symlink"
        )));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        AppError::InvalidRequest(format!("{label} could not be resolved: {error}"))
    })?;
    Ok(canonical)
}

fn prepare_selected_source(path: &Path) -> AppResult<PathBuf> {
    if !path.is_absolute()
        || path.to_str().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(AppError::InvalidRequest(
            "selected working-tree path must be an absolute normalized UTF-8 path".into(),
        ));
    }
    reject_symlink_path_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::InvalidRequest(format!(
            "selected working-tree directory could not be inspected: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::InvalidRequest(
            "selected working-tree path must be a real directory, not a symlink".into(),
        ));
    }
    fs::canonicalize(path).map_err(|error| {
        AppError::InvalidRequest(format!(
            "selected working-tree directory could not be resolved: {error}"
        ))
    })
}

fn reject_symlink_path_components(path: &Path) -> AppResult<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if !matches!(component, Component::Normal(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            AppError::InvalidRequest(format!(
                "selected working-tree path component could not be inspected: {error}"
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(AppError::InvalidRequest(
                "selected working-tree path may not contain symlink components".into(),
            ));
        }
    }
    Ok(())
}

fn ensure_private_child_directory(parent: &Path, name: &str) -> AppResult<PathBuf> {
    let child = parent.join(name);
    match fs::create_dir(&child) {
        Ok(()) => set_private_directory(&child)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&child)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AppError::Runtime(
                    "backend artifact directory was replaced by an unsafe entry".into(),
                ));
            }
            set_private_directory(&child)?;
        }
        Err(error) => return Err(error.into()),
    }
    let canonical = fs::canonicalize(&child)?;
    if canonical.parent() != Some(parent) {
        return Err(AppError::Runtime(
            "backend artifact directory escaped its expected parent".into(),
        ));
    }
    Ok(canonical)
}

fn create_private_generated_directory(parent: &Path, name: &str) -> AppResult<PathBuf> {
    let path = parent.join(name);
    fs::create_dir(&path).map_err(|error| {
        AppError::Runtime(format!(
            "backend-generated workspace artifact directory could not be reserved: {error}"
        ))
    })?;
    if let Err(error) = set_private_directory(&path) {
        let _ = fs::remove_dir(&path);
        return Err(error);
    }
    Ok(path)
}

fn create_private_directory(path: &Path) -> AppResult<()> {
    fs::create_dir(path).map_err(|error| {
        AppError::Runtime(format!(
            "private workspace snapshot directory could not be created: {error}"
        ))
    })?;
    set_private_directory(path)
}

fn resolve_real_child_directory(parent: &Path, name: &str) -> AppResult<PathBuf> {
    let path = parent.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        AppError::Runtime(format!(
            "workspace snapshot directory is unavailable: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::Runtime(
            "workspace snapshot path contains a symlink or non-directory".into(),
        ));
    }
    let canonical = fs::canonicalize(&path)?;
    if canonical.parent() != Some(parent) {
        return Err(AppError::Runtime(
            "workspace snapshot directory escaped its expected parent".into(),
        ));
    }
    Ok(canonical)
}

fn resolve_real_regular_file(parent: &Path, name: &str) -> AppResult<PathBuf> {
    let path = parent.join(name);
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::Runtime(
            "workspace snapshot manifest is not a regular file".into(),
        ));
    }
    ensure_canonical_inside(&path, parent)?;
    Ok(path)
}

fn sorted_directory_entries(
    directory: &Path,
    maximum_entries: usize,
) -> AppResult<Vec<(String, PathBuf)>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory)? {
        if entries.len() >= maximum_entries {
            return Err(AppError::InvalidRequest(
                "workspace snapshot directory contains more entries than its safety bounds allow"
                    .into(),
            ));
        }
        let entry = entry?;
        let name = validate_entry_name(&entry.file_name())?;
        entries.push((name, entry.path()));
    }
    entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    Ok(entries)
}

fn validate_entry_name(name: &std::ffi::OsStr) -> AppResult<String> {
    let Some(name) = name.to_str() else {
        return Err(AppError::InvalidRequest(
            "selected working tree contains a non-UTF-8 path".into(),
        ));
    };
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > MAX_COMPONENT_BYTES
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
    {
        return Err(AppError::InvalidRequest(
            "selected working tree contains an unsafe path component".into(),
        ));
    }
    Ok(name.into())
}

fn normalized_relative_path(components: &[String]) -> AppResult<String> {
    let path = components.join("/");
    if path.is_empty() || path.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(AppError::InvalidRequest(
            "selected working tree contains an empty or overlong relative path".into(),
        ));
    }
    Ok(path)
}

fn validate_normalized_relative_path(value: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > MAX_RELATIVE_PATH_BYTES
        || value.contains('\\')
        || Path::new(value).is_absolute()
        || value.split('/').any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || component.len() > MAX_COMPONENT_BYTES
                || component.chars().any(char::is_control)
        })
    {
        return Err(AppError::Runtime(
            "workspace snapshot manifest contains an unsafe relative path".into(),
        ));
    }
    Ok(())
}

fn inspect_real_directory(path: &Path, root: &Path) -> AppResult<FileFingerprint> {
    ensure_canonical_inside(path, root)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::InvalidRequest(
            "selected working tree contains a symlinked or invalid directory".into(),
        ));
    }
    Ok(FileFingerprint::from_metadata(&metadata))
}

fn ensure_canonical_inside(path: &Path, root: &Path) -> AppResult<()> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        AppError::Runtime(format!(
            "workspace snapshot path could not be resolved: {error}"
        ))
    })?;
    if !canonical.starts_with(root) {
        return Err(AppError::InvalidRequest(
            "selected working-tree entry resolved outside its selected root".into(),
        ));
    }
    Ok(())
}

fn create_private_new_file(path: &Path) -> AppResult<File> {
    #[cfg(windows)]
    {
        crate::managed_runtime::create_current_user_only_product_file(path).map_err(|error| {
            AppError::Runtime(format!(
                "private workspace snapshot file could not be created: {error}"
            ))
        })
    }
    #[cfg(not(windows))]
    let mut options = OpenOptions::new();
    #[cfg(not(windows))]
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_CLOEXEC);
    #[cfg(not(windows))]
    let file = options.open(path).map_err(|error| {
        AppError::Runtime(format!(
            "private workspace snapshot file could not be created: {error}"
        ))
    })?;
    #[cfg(unix)]
    set_private_file(path)?;
    #[cfg(not(windows))]
    Ok(file)
}

fn write_private_readonly_file(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let mut file = create_private_new_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    set_readonly_file(path)
}

fn open_readonly_nofollow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options.open(path)
}

fn read_bounded_stable_file(path: &Path, maximum_bytes: u64) -> AppResult<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(AppError::Runtime(
            "workspace snapshot contains a non-regular file".into(),
        ));
    }
    let mut file = open_readonly_nofollow(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(AppError::Runtime(
            "workspace snapshot contains a non-regular file".into(),
        ));
    }
    let before = FileFingerprint::from_metadata(&opened_metadata);
    if before != FileFingerprint::from_metadata(&path_metadata)
        || before.byte_length > maximum_bytes
    {
        return Err(AppError::Runtime(
            "workspace snapshot file changed or exceeds its byte limit".into(),
        ));
    }
    let capacity = usize::try_from(before.byte_length.min(1024 * 1024)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = FileFingerprint::from_metadata(&file.metadata()?);
    let final_path_metadata = fs::symlink_metadata(path)?;
    if bytes.len() as u64 > maximum_bytes
        || before.byte_length != bytes.len() as u64
        || before != after
        || after != FileFingerprint::from_metadata(&final_path_metadata)
    {
        return Err(AppError::Runtime(
            "workspace snapshot file changed while it was being verified".into(),
        ));
    }
    Ok(bytes)
}

fn hash_bounded_stable_file(path: &Path, maximum_bytes: u64) -> AppResult<(String, u64)> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(AppError::Runtime(
            "workspace snapshot contains a non-regular file".into(),
        ));
    }
    let mut file = open_readonly_nofollow(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Err(AppError::Runtime(
            "workspace snapshot contains a non-regular file".into(),
        ));
    }
    let before = FileFingerprint::from_metadata(&opened_metadata);
    if before != FileFingerprint::from_metadata(&path_metadata)
        || before.byte_length > maximum_bytes
    {
        return Err(AppError::Runtime(
            "workspace snapshot file changed or exceeds its byte limit".into(),
        ));
    }

    let mut first_digest = Sha256::new();
    let first_length = hash_reader_bounded(&mut file, maximum_bytes, &mut first_digest)?;
    let after_first = FileFingerprint::from_metadata(&file.metadata()?);
    file.seek(SeekFrom::Start(0))?;
    let before_second = FileFingerprint::from_metadata(&file.metadata()?);
    let mut second_digest = Sha256::new();
    let second_length = hash_reader_bounded(&mut file, maximum_bytes, &mut second_digest)?;
    let after_second = FileFingerprint::from_metadata(&file.metadata()?);
    let final_path_metadata = fs::symlink_metadata(path)?;
    let first_digest = first_digest.finalize();
    let second_digest = second_digest.finalize();
    if before != after_first
        || after_first != before_second
        || before_second != after_second
        || after_second != FileFingerprint::from_metadata(&final_path_metadata)
        || first_length != before.byte_length
        || second_length != first_length
        || first_digest != second_digest
    {
        return Err(AppError::Runtime(
            "workspace snapshot file changed while it was being verified".into(),
        ));
    }
    Ok((hex::encode(first_digest), first_length))
}

fn hash_reader_bounded(
    reader: &mut File,
    maximum_bytes: u64,
    digest: &mut Sha256,
) -> AppResult<u64> {
    let mut byte_length = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        byte_length = byte_length
            .checked_add(read as u64)
            .ok_or_else(|| AppError::Runtime("snapshot byte count overflowed".into()))?;
        if byte_length > maximum_bytes {
            return Err(AppError::Runtime(
                "workspace snapshot file exceeds its byte limit".into(),
            ));
        }
        digest.update(&buffer[..read]);
    }
    Ok(byte_length)
}

fn validate_safe_id(label: &str, value: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AppError::InvalidRequest(format!(
            "{label} contains unsafe path characters"
        )));
    }
    Ok(())
}

fn valid_storage_id(value: &str) -> bool {
    value.strip_prefix(STORAGE_ID_PREFIX).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn changed_file_error(relative_path: &str) -> AppError {
    AppError::Runtime(format!(
        "selected working-tree file changed while it was being copied at {relative_path}"
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    byte_length: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

impl FileFingerprint {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            byte_length: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            modified_seconds: metadata.mtime(),
            #[cfg(unix)]
            modified_nanoseconds: metadata.mtime_nsec(),
            #[cfg(unix)]
            changed_seconds: metadata.ctime(),
            #[cfg(unix)]
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

struct SnapshotCleanup {
    staging: Option<PathBuf>,
    final_container: Option<PathBuf>,
    armed: bool,
}

impl SnapshotCleanup {
    fn new(staging: PathBuf) -> Self {
        Self {
            staging: Some(staging),
            final_container: None,
            armed: true,
        }
    }

    fn track_final(&mut self, final_container: PathBuf) {
        self.final_container = Some(final_container);
    }

    fn staging_moved(&mut self) {
        self.staging = None;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SnapshotCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(path) = self.staging.as_deref() {
            remove_private_tree(path);
        }
        if let Some(path) = self.final_container.as_deref() {
            remove_private_tree(path);
        }
    }
}

fn remove_private_tree(path: &Path) {
    make_tree_deletable(path);
    let _ = fs::remove_dir_all(path);
}

pub(crate) fn make_tree_deletable(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return;
        }
    }
    if metadata.file_type().is_symlink() {
        return;
    }
    if metadata.is_dir() {
        let _ = set_private_directory(path);
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                make_tree_deletable(&entry.path());
            }
        }
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return;
            }
        }
        let _ = make_file_deletable(path);
    }
}

pub(crate) fn make_snapshot_tree_readonly(path: &Path) -> AppResult<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            make_snapshot_tree_readonly(&entry.path())?;
        } else if metadata.is_file() {
            set_readonly_file(&entry.path())?;
        } else {
            return Err(AppError::Runtime(
                "staged workspace snapshot contains an unsupported entry".into(),
            ));
        }
    }
    set_readonly_directory(path)
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> AppResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_readonly_directory(path: &Path) -> AppResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o500))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_readonly_directory(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> AppResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
fn make_file_deletable(path: &Path) -> AppResult<()> {
    let _single_link_guard = crate::case_archive_io::single_link_regular_file(path)?;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, GetFileAttributesW,
        INVALID_FILE_ATTRIBUTES, SetFileAttributesW,
    };

    let encoded = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: `encoded` is NUL-terminated and lives for the duration of each
    // Windows API call.
    let attributes = unsafe { GetFileAttributesW(encoded.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Err(std::io::Error::last_os_error().into());
    }
    if attributes & FILE_ATTRIBUTE_READONLY != 0 {
        let writable_attributes = match attributes & !FILE_ATTRIBUTE_READONLY {
            0 => FILE_ATTRIBUTE_NORMAL,
            remaining => remaining,
        };
        // SAFETY: `encoded` is a valid NUL-terminated path and the new
        // attribute mask preserves every bit except read-only.
        if unsafe { SetFileAttributesW(encoded.as_ptr(), writable_attributes) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn make_file_deletable(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn make_file_deletable(path: &Path) -> AppResult<()> {
    set_private_file(path)
}

#[cfg(unix)]
fn set_readonly_file(path: &Path) -> AppResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_readonly_file(path: &Path) -> AppResult<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> AppResult<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_two_node_facts_are_accepted_only_as_a_complete_exact_inventory() {
        let selected = crate::test_temp::tempdir().expect("node-facts source");
        let node = selected.path().join("node-snapshot");
        fs::create_dir(&node).expect("node-facts directory");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../engines/images/kube-bench/testdata/node-snapshot");
        for name in [
            "profile.json",
            "ca.crt",
            "kube-proxy.yaml",
            "kubelet-config.yaml",
            "kubelet.conf",
            "kubelet.service",
        ] {
            fs::copy(fixture.join(name), node.join(name)).expect("copy node-facts fixture");
        }
        let artifacts = crate::test_temp::tempdir().expect("node-facts artifacts");
        create_workspace_snapshot_with_profile(
            artifacts.path(),
            "case-node-facts",
            "source-node-facts",
            selected.path(),
            WorkspaceInputProfile::KubernetesNodeSnapshot,
            WorkspaceSnapshotLimits::default(),
        )
        .expect("complete schema-two node facts");

        let profile_path = node.join("profile.json");
        let mut profile: Value = serde_json::from_slice(&fs::read(&profile_path).unwrap()).unwrap();
        profile["processes"][0]["name"] = Value::String("unapproved-process".into());
        fs::write(&profile_path, serde_json::to_vec(&profile).unwrap()).unwrap();
        let rejected_artifacts =
            crate::test_temp::tempdir().expect("rejected node-facts artifacts");
        assert!(
            create_workspace_snapshot_with_profile(
                rejected_artifacts.path(),
                "case-invalid-node-facts",
                "source-invalid-node-facts",
                selected.path(),
                WorkspaceInputProfile::KubernetesNodeSnapshot,
                WorkspaceSnapshotLimits::default(),
            )
            .is_err(),
            "an unapproved process fact was accepted"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_fresh_workspace_file_has_an_exact_current_user_only_dacl() {
        let temporary = crate::test_temp::tempdir().expect("isolated Windows workspace parent");
        let product_root = temporary.path().join("isolated-product-data");
        let _guard =
            crate::managed_runtime::ensure_private_product_data_directory_for_isolated_test(
                &product_root,
            )
            .expect("isolated private product root");
        let snapshot = product_root.join("workspace-snapshot.json");
        let mut file = create_private_new_file(&snapshot).expect("private workspace file");
        file.write_all(b"private workspace snapshot")
            .expect("write workspace fixture");
        file.sync_all().expect("sync workspace fixture");
        drop(file);

        crate::managed_runtime::test_verify_current_user_only_product_file(&snapshot)
            .expect("fresh workspace file must have an exact private DACL");
    }

    #[test]
    fn case_insensitive_tracked_path_keys_protect_case_only_variants_and_ancestors() {
        let tracked = BTreeSet::from(["Secrets/API.KEY".to_owned()]);
        let (files, directories) = tracked_match_sets(&tracked, true);

        assert!(files.contains(&git_tracked_path_key("secrets/api.key", true)));
        assert!(directories.contains(&git_tracked_path_key("SECRETS", true)));
        assert!(directories.contains(""));
        let (case_sensitive_files, _) = tracked_match_sets(&tracked, false);
        assert!(!case_sensitive_files.contains(&git_tracked_path_key("secrets/api.key", false,)));
    }

    #[test]
    fn nested_git_inventory_probes_share_total_byte_runtime_and_count_budgets() {
        let initial = GitInventoryProbeBudget::default();
        let verification = GitInventoryProbeBudget::default();
        assert_eq!(
            initial.remaining_bytes + verification.remaining_bytes,
            (MAX_GIT_TRACKED_TOTAL_INVENTORY_BYTES / 2) * 2
        );
        assert_eq!(
            initial.remaining_runtime + verification.remaining_runtime,
            GIT_TRACKED_TOTAL_INVENTORY_RUNTIME
        );
        assert_eq!(
            initial.remaining_probes + verification.remaining_probes,
            MAX_GIT_TRACKED_INVENTORY_PROBES
        );
        let mut budget = GitInventoryProbeBudget {
            remaining_bytes: 10,
            remaining_runtime: Duration::from_millis(10),
            remaining_probes: 2,
        };
        assert_eq!(budget.reserve(), Some((10, Duration::from_millis(10))));
        budget.consume(Duration::from_millis(4), Some(6));
        assert_eq!(budget.reserve(), Some((4, Duration::from_millis(6))));
        budget.consume(Duration::from_millis(6), Some(4));
        assert_eq!(budget.reserve(), None);

        let mut hung_reader = GitInventoryProbeBudget {
            remaining_bytes: 10,
            remaining_runtime: Duration::from_secs(1),
            remaining_probes: 2,
        };
        let _ = hung_reader.reserve().unwrap();
        hung_reader.consume(Duration::from_millis(1), None);
        assert_eq!(hung_reader.reserve(), None);
    }

    #[cfg(unix)]
    #[test]
    fn inherited_stdout_pipe_cannot_outlive_the_probe_deadline() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "(/bin/sleep 2) & printf ok"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let child = command.spawn().expect("spawn inherited-pipe fixture");
        let started = Instant::now();

        assert!(collect_bounded_child_output(child, 64, Duration::from_millis(50)).is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn product_git_inventory_never_uses_a_bare_path_lookup() {
        if let Some(binary) = trusted_git_binary() {
            assert!(binary.is_absolute());
            assert_ne!(binary, Path::new("git"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn trusted_git_child_receives_only_the_fixed_environment() {
        // `env` stands in for Git and prints exactly what the child was given.
        let output = trusted_git_command(Path::new("/usr/bin/env"))
            .stdin(Stdio::null())
            .output()
            .expect("run the environment fixture");
        assert!(output.status.success());
        let mut variables = String::from_utf8(output.stdout)
            .expect("environment is UTF-8")
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        variables.sort();
        assert_eq!(
            variables,
            [
                "GIT_ALLOW_PROTOCOL=",
                "GIT_CONFIG_GLOBAL=/dev/null",
                "GIT_CONFIG_NOSYSTEM=1",
                "GIT_LITERAL_PATHSPECS=1",
                "GIT_NO_LAZY_FETCH=1",
                "GIT_OPTIONAL_LOCKS=0",
                "GIT_PAGER=",
                "GIT_TERMINAL_PROMPT=0",
                "LC_ALL=C",
            ]
        );
    }

    #[test]
    fn audit_memory_is_charged_before_records_are_retained() {
        let mut state = CopyState::default();
        let limits = WorkspaceSnapshotLimits {
            max_files: HARD_MAX_FILES,
            max_directories: HARD_MAX_DIRECTORIES,
            max_total_bytes: HARD_MAX_TOTAL_BYTES,
            max_file_bytes: HARD_MAX_FILE_BYTES,
            max_depth: HARD_MAX_DEPTH,
        };
        let mut charges = 0;
        while charge_snapshot_audit(&mut state, limits, MAX_RELATIVE_PATH_BYTES).is_ok() {
            charges += 1;
        }
        assert!(charges > 0);
        assert!(state.audit_bytes <= MAX_WORKSPACE_SNAPSHOT_AUDIT_BYTES);
        assert!(state.exclusions.is_empty());
        assert!(state.ignore_rule_sources.is_empty());
    }
}

#[cfg(test)]
#[test]
fn secret_name_classifier_golden_requires_version_bump() {
    let names = [
        ".env",
        ".ENV",
        ".env.local",
        ".ENV.LOCAL",
        ".envrc",
        ".ENVRC",
        ".npmrc",
        ".NPMRC",
        ".yarnrc",
        ".YARNRC",
        ".pypirc",
        ".PYPIRC",
        ".netrc",
        ".NETRC",
        ".pgpass",
        ".PGPASS",
        ".my.cnf",
        ".MY.CNF",
        ".git-credentials",
        ".GIT-CREDENTIALS",
        ".htpasswd",
        ".HTPASSWD",
        "id_rsa",
        "ID_RSA",
        "id_dsa",
        "ID_DSA",
        "id_ecdsa",
        "ID_ECDSA",
        "id_ed25519",
        "ID_ED25519",
        "terraform.tfstate",
        "TERRAFORM.TFSTATE",
        "terraform.tfstate.backup",
        "TERRAFORM.TFSTATE.BACKUP",
        "application_default_credentials.json",
        "APPLICATION_DEFAULT_CREDENTIALS.JSON",
        "a.tfvars",
        "A.TFVARS",
        "a.tfvars.json",
        "A.TFVARS.JSON",
        "a.pem",
        "A.PEM",
        "a.key",
        "A.KEY",
        "secret",
        "SECRET",
        "secrets",
        "SECRETS",
        "credential",
        "CREDENTIAL",
        "credentials",
        "CREDENTIALS",
        "secret.txt",
        "SECRET.TXT",
        "credentials.json",
        "CREDENTIALS.JSON",
        "env",
        "ENV",
        ".envrc.local",
        ".ENVRC.LOCAL",
        ".environment",
        ".ENVIRONMENT",
        "x.env",
        "X.ENV",
        ".npmrcx",
        ".NPMRCX",
        "a.tfstate",
        "A.TFSTATE",
        "id_rsa.pub",
        "ID_RSA.PUB",
        "a.pem.txt",
        "A.PEM.TXT",
        "key",
        "KEY",
        "secretary",
        "SECRETARY",
        "mysecret",
        "MYSECRET",
        "secret-key",
        "SECRET-KEY",
        "credentials_backup",
        "CREDENTIALS_BACKUP",
        "secrets/x",
        "SECRETS/X",
        "README.md",
        "README.MD",
    ];
    let observed = names
        .into_iter()
        .map(|name| (name, likely_secret_config_file_name(name)))
        .collect::<Vec<_>>();
    assert_eq!(
        (
            SECRET_NAME_CLASSIFIER_VERSION,
            sha256_bytes(&serde_json::to_vec(&observed).unwrap())
        ),
        (
            1,
            "7aaf7edc54262dbb16ca8b7c548454020f7efeaf9c78569568d909d414c58d4c".into()
        )
    );
}

#[cfg(unix)]
#[test]
fn unsealing_owned_trees_does_not_change_external_link_permissions() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = tempfile::tempdir().unwrap();
    let tree = root.path().join("tree");
    fs::create_dir(&tree).unwrap();
    let outside = root.path().join("outside");
    fs::write(&outside, b"synthetic external file").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o400)).unwrap();
    fs::hard_link(&outside, tree.join("hardlink")).unwrap();
    symlink(&outside, tree.join("symlink")).unwrap();
    fs::set_permissions(&tree, fs::Permissions::from_mode(0o500)).unwrap();
    make_tree_deletable(&tree);
    assert_eq!(
        fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
        0o400
    );
    fs::remove_dir_all(&tree).unwrap();
    assert_eq!(fs::read(&outside).unwrap(), b"synthetic external file");
}
