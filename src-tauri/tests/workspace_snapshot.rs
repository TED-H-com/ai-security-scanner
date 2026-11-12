use ai_security_scanner_lib::domain::AssetKind;
use ai_security_scanner_lib::mcp_armor_input::{
    MCP_CONFIGURATION_CANDIDATES_METADATA_KEY, MCP_CONFIGURATION_DISCOVERY_COMPLETE_METADATA_KEY,
};
use ai_security_scanner_lib::workspace_snapshot::{
    LOCAL_INPUT_PROFILE_FILENAME, WorkspaceInputProfile, WorkspaceSnapshotExclusionPolicy,
    WorkspaceSnapshotExclusionReason, WorkspaceSnapshotLimits, WorkspaceSnapshotReference,
    create_workspace_snapshot, create_workspace_snapshot_with_profile, inspect_workspace_snapshot,
    resolve_workspace_snapshot,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::{Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};

fn roots() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().expect("temporary directory");
    let artifact_root = temp.path().join("private-artifacts");
    let source = temp.path().join("TOP_SECRET_HOST_WORKTREE");
    fs::create_dir(&artifact_root).expect("artifact root");
    fs::create_dir(&source).expect("source root");
    (temp, artifact_root, source)
}

fn small_limits() -> WorkspaceSnapshotLimits {
    WorkspaceSnapshotLimits {
        max_files: 20,
        max_directories: 20,
        max_total_bytes: 2 * 1024 * 1024,
        max_file_bytes: 1024 * 1024,
        max_depth: 8,
    }
}

fn initialize_git_repository(path: &Path) {
    let status = Command::new("git")
        .args(["init", "--quiet"])
        .arg(path)
        .status()
        .expect("Git is required by the repository snapshot tests");
    assert!(status.success(), "Git repository initialization failed");
}

fn git_add(path: &Path, entries: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["add", "--force", "--"])
        .args(entries)
        .status()
        .expect("Git is required by the repository snapshot tests");
    assert!(status.success(), "Git tracked-file staging failed");
}

fn snapshot_entries(artifact_root: &Path, case_id: &str) -> Vec<String> {
    let path = artifact_root.join(case_id).join("workspace-snapshots");
    if !path.exists() {
        return Vec::new();
    }
    let mut names = fs::read_dir(path)
        .expect("read snapshot directory")
        .map(|entry| {
            entry
                .expect("snapshot entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn make_test_file_writable(path: &Path) {
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(permissions.mode() | 0o200);
        fs::set_permissions(path, permissions).unwrap();
    }
    #[cfg(windows)]
    {
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
        // SAFETY: `encoded` is NUL-terminated and lives for both API calls.
        let attributes = unsafe { GetFileAttributesW(encoded.as_ptr()) };
        assert_ne!(
            attributes,
            INVALID_FILE_ATTRIBUTES,
            "inspect test file attributes: {}",
            std::io::Error::last_os_error()
        );
        if attributes & FILE_ATTRIBUTE_READONLY != 0 {
            let writable_attributes = match attributes & !FILE_ATTRIBUTE_READONLY {
                0 => FILE_ATTRIBUTE_NORMAL,
                remaining => remaining,
            };
            // SAFETY: `encoded` remains valid and the new mask preserves every
            // attribute except read-only.
            let status = unsafe { SetFileAttributesW(encoded.as_ptr(), writable_attributes) };
            assert_ne!(
                status,
                0,
                "make test file writable: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
    }
}

fn deterministic_tar(path: &str, contents: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(contents.len() as u64);
    header.set_path(path).unwrap();
    header.set_cksum();
    builder.append(&header, Cursor::new(contents)).unwrap();
    builder.finish().unwrap();
    builder.into_inner().unwrap()
}

fn write_single_image_oci_layout(root: &Path) {
    let blobs = root.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    fs::write(
        root.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    let layer = deterministic_tar("app/package-lock.json", br#"{"lockfileVersion":3}"#);
    let layer_digest = digest(&layer);
    let config = serde_json::to_vec(&serde_json::json!({
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": [format!("sha256:{layer_digest}")]},
        "config": {}
    }))
    .unwrap();
    let config_digest = digest(&config);
    fs::write(blobs.join(&config_digest), &config).unwrap();
    fs::write(blobs.join(&layer_digest), &layer).unwrap();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": format!("sha256:{config_digest}"),
            "size": config.len()
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": format!("sha256:{layer_digest}"),
            "size": layer.len()
        }]
    }))
    .unwrap();
    let manifest_digest = digest(&manifest);
    fs::write(blobs.join(&manifest_digest), &manifest).unwrap();
    let index = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": format!("sha256:{manifest_digest}"),
            "size": manifest.len()
        }]
    }))
    .unwrap();
    fs::write(root.join("index.json"), index).unwrap();
}

fn descriptor_digest(descriptor: &serde_json::Value) -> String {
    descriptor["digest"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap()
        .to_owned()
}

fn rewrite_manifest(root: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
    let mut index: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("index.json")).unwrap()).unwrap();
    let descriptor = &mut index["manifests"][0];
    let old_digest = descriptor_digest(descriptor);
    let old_path = root.join("blobs/sha256").join(&old_digest);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&old_path).unwrap()).unwrap();
    mutate(&mut manifest);
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let new_digest = digest(&bytes);
    fs::write(root.join("blobs/sha256").join(&new_digest), &bytes).unwrap();
    if new_digest != old_digest {
        fs::remove_file(old_path).unwrap();
    }
    descriptor["digest"] = serde_json::Value::String(format!("sha256:{new_digest}"));
    descriptor["size"] = serde_json::json!(bytes.len());
    fs::write(root.join("index.json"), serde_json::to_vec(&index).unwrap()).unwrap();
}

fn rewrite_config(root: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
    rewrite_manifest(root, |manifest| {
        let descriptor = &mut manifest["config"];
        let old_digest = descriptor_digest(descriptor);
        let old_path = root.join("blobs/sha256").join(&old_digest);
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&old_path).unwrap()).unwrap();
        mutate(&mut config);
        let bytes = serde_json::to_vec(&config).unwrap();
        let new_digest = digest(&bytes);
        fs::write(root.join("blobs/sha256").join(&new_digest), &bytes).unwrap();
        if new_digest != old_digest {
            fs::remove_file(old_path).unwrap();
        }
        descriptor["digest"] = serde_json::Value::String(format!("sha256:{new_digest}"));
        descriptor["size"] = serde_json::json!(bytes.len());
    });
}

fn expect_invalid_oci(mutator: impl FnOnce(&Path), message: &str) {
    let (_temp, artifact_root, source) = roots();
    write_single_image_oci_layout(&source);
    mutator(&source);
    let error = create_workspace_snapshot_with_profile(
        &artifact_root,
        "case-invalid-oci",
        "source-invalid-oci",
        &source,
        WorkspaceInputProfile::ContainerImageOciLayout,
        small_limits(),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains(message),
        "unexpected OCI validation error: {error}"
    );
}

#[test]
fn snapshot_is_deterministic_private_source_grounded_and_working_tree_only() {
    let (_temp, artifact_root, source) = roots();
    fs::create_dir(source.join("src")).unwrap();
    fs::write(source.join("README.md"), b"# safe working tree\n").unwrap();
    fs::write(source.join("src/main.rs"), b"fn main() {}\n").unwrap();
    fs::create_dir(source.join("empty-directory")).unwrap();
    fs::create_dir(source.join(".git")).unwrap();
    fs::write(
        source.join(".git/config"),
        b"credential = must-never-be-copied\n",
    )
    .unwrap();

    let first = create_workspace_snapshot(
        &artifact_root,
        "case-123",
        "source-456",
        &source,
        small_limits(),
    )
    .expect("first snapshot");
    let second = create_workspace_snapshot(
        &artifact_root,
        "case-123",
        "source-456",
        &source,
        small_limits(),
    )
    .expect("second snapshot");

    assert_eq!(first.reference.sha256, second.reference.sha256);
    assert_eq!(first.reference.snapshot_id, second.reference.snapshot_id);
    assert_eq!(first.manifest, second.manifest);
    assert_eq!(first.asset.id, second.asset.id);
    assert_ne!(first.reference.storage_id, second.reference.storage_id);
    assert_eq!(first.asset.discovered_from, ["source-456"]);
    assert!(first.asset.candidate);
    assert!(!first.asset.owner_confirmed);
    assert_eq!(
        first
            .asset
            .metadata
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            MCP_CONFIGURATION_CANDIDATES_METADATA_KEY,
            MCP_CONFIGURATION_DISCOVERY_COMPLETE_METADATA_KEY,
            "workspace_snapshot_id",
            "workspace_snapshot_sha256"
        ]
    );
    assert_eq!(
        first.asset.metadata[MCP_CONFIGURATION_CANDIDATES_METADATA_KEY],
        serde_json::json!([])
    );
    assert_eq!(
        first.asset.metadata[MCP_CONFIGURATION_DISCOVERY_COMPLETE_METADATA_KEY],
        serde_json::json!(true)
    );

    let same_content_different_repository = create_workspace_snapshot(
        &artifact_root,
        "case-123",
        "source-789",
        &source,
        small_limits(),
    )
    .expect("same content selected as another repository");
    assert_eq!(
        first.reference.sha256,
        same_content_different_repository.reference.sha256
    );
    assert_ne!(first.asset.id, same_content_different_repository.asset.id);
    assert_eq!(first.manifest.excluded_entries, [".git"]);
    assert_eq!(
        first.manifest.exclusion_policy,
        Some(WorkspaceSnapshotExclusionPolicy::RepositoryTrackedGitignoreV2)
    );
    assert_eq!(first.manifest.exclusions.len(), 1);
    assert_eq!(first.manifest.exclusions[0].relative_path, ".git");
    assert_eq!(
        first.manifest.exclusions[0].reason,
        WorkspaceSnapshotExclusionReason::GitMetadata
    );
    assert_eq!(first.manifest.directory_count, 2);
    assert_eq!(first.manifest.file_count, 2);
    assert!(
        first
            .manifest
            .files
            .iter()
            .all(|file| !file.relative_path.starts_with(".git"))
    );

    let persisted = serde_json::to_string(&(first.reference.clone(), first.asset.clone())).unwrap();
    assert!(!persisted.contains("TOP_SECRET_HOST_WORKTREE"));
    assert!(!persisted.contains(source.to_string_lossy().as_ref()));
    assert!(!persisted.contains("must-never-be-copied"));

    let resolved = resolve_workspace_snapshot(&artifact_root, "case-123", &first.reference)
        .expect("snapshot resolves after full verification");
    assert_eq!(
        fs::read(resolved.tree_path.join("README.md")).unwrap(),
        b"# safe working tree\n"
    );
    assert!(!resolved.tree_path.join(".git").exists());
    assert_eq!(resolved.manifest, first.manifest);

    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(&resolved.tree_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o500
        );
        assert_eq!(
            fs::metadata(resolved.tree_path.join("README.md"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        assert_eq!(
            fs::metadata(&resolved.manifest_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
    }
}

#[test]
fn repository_snapshot_respects_nested_gitignore_negation_and_build_output_rules() {
    let (_temp, artifact_root, source) = roots();
    initialize_git_repository(&source);
    fs::write(
        source.join(".gitignore"),
        b"node_modules/\ntarget/\n*.log\n!important.log\nscratch/*\n!scratch/keep.txt\n",
    )
    .unwrap();
    fs::create_dir_all(source.join("node_modules/dependency")).unwrap();
    fs::create_dir_all(source.join("target/debug/incremental")).unwrap();
    for index in 0..30 {
        fs::write(
            source.join(format!("node_modules/dependency/{index}.js")),
            b"generated dependency",
        )
        .unwrap();
        fs::write(
            source.join(format!("target/debug/incremental/{index}.o")),
            b"generated build output",
        )
        .unwrap();
    }
    fs::write(source.join("ignored.log"), b"ignored log").unwrap();
    fs::write(source.join("important.log"), b"kept by root negation").unwrap();
    fs::create_dir(source.join("scratch")).unwrap();
    fs::write(source.join("scratch/drop.txt"), b"ignored scratch").unwrap();
    fs::write(source.join("scratch/keep.txt"), b"kept scratch").unwrap();
    fs::create_dir_all(source.join("packages/app")).unwrap();
    fs::write(
        source.join("packages/app/.gitignore"),
        b"*.tmp\n!keep.tmp\n!keep.log\n",
    )
    .unwrap();
    fs::write(source.join("packages/app/drop.tmp"), b"ignored temp").unwrap();
    fs::write(source.join("packages/app/keep.tmp"), b"kept temp").unwrap();
    fs::write(source.join("packages/app/keep.log"), b"nested override").unwrap();
    fs::write(source.join("src.rs"), b"fn main() {}\n").unwrap();

    let limits = WorkspaceSnapshotLimits {
        max_files: if cfg!(unix) { 8 } else { 100 },
        max_directories: if cfg!(unix) { 8 } else { 20 },
        ..small_limits()
    };
    let snapshot = create_workspace_snapshot(
        &artifact_root,
        "case-gitignore",
        "source-gitignore",
        &source,
        limits,
    )
    .expect("ignored dependency and build trees do not consume snapshot bounds");
    let paths = snapshot
        .manifest
        .files
        .iter()
        .map(|file| file.relative_path.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        snapshot.manifest.exclusion_policy,
        Some(WorkspaceSnapshotExclusionPolicy::RepositoryTrackedGitignoreV2)
    );
    assert!(paths.contains(&".gitignore"));
    assert!(paths.contains(&"important.log"));
    assert!(paths.contains(&"scratch/keep.txt"));
    assert!(paths.contains(&"packages/app/.gitignore"));
    assert!(paths.contains(&"packages/app/keep.tmp"));
    assert!(paths.contains(&"packages/app/keep.log"));
    assert!(paths.contains(&"src.rs"));
    #[cfg(unix)]
    {
        assert!(!paths.iter().any(|path| path.starts_with("node_modules/")));
        assert!(!paths.iter().any(|path| path.starts_with("target/")));
        assert!(!paths.contains(&"ignored.log"));
        assert!(!paths.contains(&"scratch/drop.txt"));
        assert!(!paths.contains(&"packages/app/drop.tmp"));
    }
    #[cfg(not(unix))]
    {
        assert!(paths.contains(&"node_modules/dependency/0.js"));
        assert!(paths.contains(&"target/debug/incremental/0.o"));
        assert!(paths.contains(&"ignored.log"));
        assert!(paths.contains(&"scratch/drop.txt"));
        assert!(paths.contains(&"packages/app/drop.tmp"));
    }
    assert_eq!(snapshot.manifest.ignore_rule_sources.len(), 2);
    assert_eq!(
        snapshot.manifest.exclusions.iter().any(|exclusion| {
            exclusion.relative_path == "node_modules"
                && exclusion.reason
                    == WorkspaceSnapshotExclusionReason::RepositoryGitignoreUntracked
        }),
        cfg!(unix)
    );
}

#[test]
fn repository_snapshot_keeps_ignored_secret_candidates_without_opening_generated_trees() {
    let (_temp, artifact_root, source) = roots();
    initialize_git_repository(&source);
    fs::write(
        source.join(".gitignore"),
        b".env\n.env.*\n.npmrc\n*.tfvars\nignored.txt\nnode_modules/\nbuild/\n",
    )
    .unwrap();
    git_add(&source, &[".gitignore"]);

    fs::write(source.join(".env"), b"EXAMPLE_TOKEN=fixture-only\n").unwrap();
    fs::write(source.join(".env.local"), b"EXAMPLE_LOCAL=fixture-only\n").unwrap();
    fs::write(
        source.join(".npmrc"),
        b"//registry.example/:_authToken=fixture-only\n",
    )
    .unwrap();
    fs::create_dir(source.join("config")).unwrap();
    fs::write(
        source.join("config/.env.production"),
        b"EXAMPLE_PRODUCTION=fixture-only\n",
    )
    .unwrap();
    fs::create_dir(source.join("infrastructure")).unwrap();
    fs::write(
        source.join("infrastructure/private.tfvars"),
        b"example_password = \"fixture-only\"\n",
    )
    .unwrap();
    fs::write(source.join("ignored.txt"), b"ordinary ignored file").unwrap();

    fs::create_dir_all(source.join("node_modules/package")).unwrap();
    fs::write(
        source.join("node_modules/package/.env"),
        b"GENERATED_EXAMPLE=fixture-only\n",
    )
    .unwrap();
    fs::write(
        source.join("node_modules/package/index.js"),
        b"generated dependency",
    )
    .unwrap();
    fs::create_dir_all(source.join("build/cache")).unwrap();
    fs::write(
        source.join("build/.env.production"),
        b"GENERATED_BUILD_EXAMPLE=fixture-only\n",
    )
    .unwrap();
    fs::write(source.join("build/cache/bundle.js"), b"generated build").unwrap();

    let snapshot = create_workspace_snapshot(
        &artifact_root,
        "case-ignored-secret-candidates",
        "source-ignored-secret-candidates",
        &source,
        small_limits(),
    )
    .expect("ignored secret candidates remain available within snapshot limits");
    let paths = snapshot
        .manifest
        .files
        .iter()
        .map(|file| file.relative_path.as_str())
        .collect::<Vec<_>>();

    for expected in [
        ".env",
        ".env.local",
        ".npmrc",
        "config/.env.production",
        "infrastructure/private.tfvars",
    ] {
        assert!(
            paths.contains(&expected),
            "missing secret candidate {expected}"
        );
    }
    assert!(!paths.contains(&"ignored.txt"));
    assert!(!paths.iter().any(|path| path.starts_with("node_modules/")));
    assert!(!paths.iter().any(|path| path.starts_with("build/")));
    for excluded_directory in ["node_modules", "build"] {
        assert!(snapshot.manifest.exclusions.iter().any(|exclusion| {
            exclusion.relative_path == excluded_directory
                && exclusion.reason
                    == WorkspaceSnapshotExclusionReason::RepositoryGitignoreUntracked
        }));
    }

    let resolved = resolve_workspace_snapshot(
        &artifact_root,
        "case-ignored-secret-candidates",
        &snapshot.reference,
    )
    .expect("snapshot with ignored secret candidates remains verifiable");
    assert_eq!(
        fs::read(resolved.tree_path.join(".env")).unwrap(),
        b"EXAMPLE_TOKEN=fixture-only\n"
    );
}

#[test]
fn ignored_secret_candidate_still_obeys_snapshot_byte_limits() {
    let (_temp, artifact_root, source) = roots();
    initialize_git_repository(&source);
    fs::write(source.join(".gitignore"), b".env\n").unwrap();
    git_add(&source, &[".gitignore"]);
    fs::write(source.join(".env"), vec![b'x'; 65]).unwrap();

    let limits = WorkspaceSnapshotLimits {
        max_file_bytes: 64,
        ..small_limits()
    };
    let error = create_workspace_snapshot(
        &artifact_root,
        "case-ignored-secret-limit",
        "source-ignored-secret-limit",
        &source,
        limits,
    )
    .expect_err("an ignored secret candidate must not bypass the per-file limit");

    assert!(
        error.to_string().contains(".env"),
        "unexpected error: {error}"
    );
    assert!(snapshot_entries(&artifact_root, "case-ignored-secret-limit").is_empty());
}

#[test]
fn repository_gitignore_never_omits_git_tracked_files() {
    let (_temp, artifact_root, source) = roots();
    initialize_git_repository(&source);
    fs::write(source.join(".gitignore"), b".env\nignored/\n").unwrap();
    fs::write(source.join(".env"), b"TRACKED_SECRET=must-be-scanned\n").unwrap();
    fs::create_dir(source.join("ignored")).unwrap();
    fs::write(source.join("ignored/generated.txt"), b"untracked output").unwrap();
    git_add(&source, &[".gitignore", ".env"]);

    let snapshot = create_workspace_snapshot(
        &artifact_root,
        "case-tracked-ignore",
        "source-tracked-ignore",
        &source,
        small_limits(),
    )
    .expect("tracked ignored files remain scanner inputs");
    let paths = snapshot
        .manifest
        .files
        .iter()
        .map(|file| file.relative_path.as_str())
        .collect::<Vec<_>>();
    assert!(paths.contains(&".env"));
    assert_eq!(
        paths.iter().any(|path| path.starts_with("ignored/")),
        !cfg!(unix)
    );
    assert_eq!(
        snapshot.manifest.exclusions.iter().any(|exclusion| {
            exclusion.relative_path == "ignored"
                && exclusion.reason
                    == WorkspaceSnapshotExclusionReason::RepositoryGitignoreUntracked
        }),
        cfg!(unix)
    );
    assert_eq!(snapshot.manifest.ignore_rule_sources.len(), 1);
    assert_eq!(
        snapshot.manifest.ignore_rule_sources[0].relative_path,
        ".gitignore"
    );
}

#[test]
fn unavailable_git_inventory_fails_open_instead_of_omitting_inputs() {
    let (_temp, artifact_root, source) = roots();
    fs::create_dir(source.join(".git")).unwrap();
    fs::write(source.join(".gitignore"), b"hidden.txt\n").unwrap();
    fs::write(source.join("hidden.txt"), b"must remain visible").unwrap();

    let snapshot = create_workspace_snapshot(
        &artifact_root,
        "case-git-fail-open",
        "source-git-fail-open",
        &source,
        small_limits(),
    )
    .expect("an unprovable tracked inventory keeps all ordinary files");
    assert!(
        snapshot
            .manifest
            .files
            .iter()
            .any(|file| file.relative_path == "hidden.txt")
    );
    assert!(snapshot.manifest.exclusions.iter().all(|exclusion| {
        exclusion.reason != WorkspaceSnapshotExclusionReason::RepositoryGitignoreUntracked
    }));
}

#[test]
fn gitdir_indirection_is_not_followed_and_ignore_pruning_fails_open() {
    let (_temp, artifact_root, source) = roots();
    fs::write(source.join(".git"), b"gitdir: ../outside-repository/.git\n").unwrap();
    fs::write(source.join(".gitignore"), b"hidden.txt\n").unwrap();
    fs::write(source.join("hidden.txt"), b"must remain visible").unwrap();

    let snapshot = create_workspace_snapshot(
        &artifact_root,
        "case-gitdir-fail-open",
        "source-gitdir-fail-open",
        &source,
        small_limits(),
    )
    .expect("Git indirection never redirects tracked-file inventory");

    assert!(
        snapshot
            .manifest
            .files
            .iter()
            .any(|file| file.relative_path == "hidden.txt")
    );
    assert!(snapshot.manifest.exclusions.iter().all(|exclusion| {
        exclusion.reason != WorkspaceSnapshotExclusionReason::RepositoryGitignoreUntracked
    }));
}

#[test]
fn tracked_nested_repository_is_not_pruned_by_parent_ignore_rule() {
    let (_temp, artifact_root, source) = roots();
    initialize_git_repository(&source);
    fs::write(source.join(".gitignore"), b"vendor/\n").unwrap();
    git_add(&source, &[".gitignore"]);
    let nested = source.join("vendor");
    fs::create_dir(&nested).unwrap();
    initialize_git_repository(&nested);
    fs::write(nested.join("tracked.rs"), b"fn nested() {}\n").unwrap();
    git_add(&nested, &["tracked.rs"]);

    let snapshot = create_workspace_snapshot(
        &artifact_root,
        "case-nested-repository",
        "source-nested-repository",
        &source,
        small_limits(),
    )
    .expect("a nested repository proves its tracked files independently");

    assert!(
        snapshot
            .manifest
            .files
            .iter()
            .any(|file| file.relative_path == "vendor/tracked.rs")
    );
    assert!(!snapshot.manifest.exclusions.iter().any(|exclusion| {
        exclusion.relative_path == "vendor"
            && exclusion.reason == WorkspaceSnapshotExclusionReason::RepositoryGitignoreUntracked
    }));
}

#[test]
fn non_repository_profile_does_not_apply_gitignore_rules() {
    let (_temp, artifact_root, source) = roots();
    fs::write(source.join(".gitignore"), b"target/\n*.tf\n").unwrap();
    fs::write(
        source.join("main.tf"),
        b"resource \"null_resource\" \"test\" {}\n",
    )
    .unwrap();
    fs::create_dir(source.join("target")).unwrap();
    fs::write(source.join("target/generated.tf"), b"output \"kept\" {}\n").unwrap();

    let snapshot = create_workspace_snapshot_with_profile(
        &artifact_root,
        "case-iac-no-ignore",
        "source-iac-no-ignore",
        &source,
        WorkspaceInputProfile::IacWorkingTree,
        small_limits(),
    )
    .expect("explicit non-repository input remains unfiltered");
    let paths = snapshot
        .manifest
        .files
        .iter()
        .map(|file| file.relative_path.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        snapshot.manifest.exclusion_policy,
        Some(WorkspaceSnapshotExclusionPolicy::GitMetadataOnlyV2)
    );
    assert!(paths.contains(&".gitignore"));
    assert!(paths.contains(&"main.tf"));
    assert!(paths.contains(&"target/generated.tf"));
}

#[test]
fn self_ignored_gitignore_cannot_bypass_total_byte_safety_limit() {
    let (_temp, artifact_root, source) = roots();
    fs::write(
        source.join(".gitignore"),
        b".gitignore\n# deliberately larger than the total snapshot limit\n",
    )
    .unwrap();
    fs::write(source.join("kept.rs"), b"x").unwrap();
    let limits = WorkspaceSnapshotLimits {
        max_files: 2,
        max_directories: 1,
        max_total_bytes: 16,
        max_file_bytes: 1024,
        max_depth: 1,
    };

    let error = create_workspace_snapshot(
        &artifact_root,
        "case-ignore-byte-limit",
        "source-ignore-byte-limit",
        &source,
        limits,
    )
    .expect_err("ignore sources remain subject to bounded input processing");
    assert!(error.to_string().contains("ignore rules"));
    assert!(error.to_string().contains("total-byte safety limit"));
    assert!(snapshot_entries(&artifact_root, "case-ignore-byte-limit").is_empty());
}

#[cfg(unix)]
#[test]
fn ignored_directory_is_pruned_before_symlink_and_resource_limit_checks() {
    let (_temp, artifact_root, source) = roots();
    initialize_git_repository(&source);
    fs::write(source.join(".gitignore"), b"ignored/\n").unwrap();
    fs::write(source.join("kept.rs"), b"fn kept() {}\n").unwrap();
    fs::create_dir(source.join("ignored")).unwrap();
    let outside = source.parent().unwrap().join("outside-ignore-secret");
    fs::write(&outside, b"must not be opened").unwrap();
    symlink(&outside, source.join("ignored/linked-secret")).unwrap();
    for index in 0..30 {
        fs::write(
            source.join(format!("ignored/generated-{index}.bin")),
            b"ignored",
        )
        .unwrap();
    }
    let limits = WorkspaceSnapshotLimits {
        max_files: 2,
        max_directories: 1,
        ..small_limits()
    };

    let snapshot = create_workspace_snapshot(
        &artifact_root,
        "case-ignore-pruning",
        "source-ignore-pruning",
        &source,
        limits,
    )
    .expect("ignored tree is neither opened nor charged to snapshot limits");
    assert_eq!(snapshot.manifest.file_count, 2);
    assert!(
        snapshot
            .manifest
            .files
            .iter()
            .all(|file| !file.relative_path.starts_with("ignored/"))
    );
}

#[test]
fn legacy_v1_snapshot_manifest_without_policy_remains_verifiable() {
    let (_temp, artifact_root, source) = roots();
    fs::write(source.join("code.rs"), b"fn legacy() {}\n").unwrap();
    let snapshot = create_workspace_snapshot(
        &artifact_root,
        "case-legacy-v1",
        "source-legacy-v1",
        &source,
        small_limits(),
    )
    .unwrap();
    let resolved =
        resolve_workspace_snapshot(&artifact_root, "case-legacy-v1", &snapshot.reference).unwrap();
    let manifest_path = resolved.manifest_path;
    make_test_file_writable(&manifest_path);
    let mut legacy: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    legacy["schema_version"] =
        serde_json::Value::String("ai-security-scanner.workspace-snapshot/v1".into());
    legacy.as_object_mut().unwrap().remove("exclusion_policy");
    let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
    fs::write(&manifest_path, &legacy_bytes).unwrap();
    let mut legacy_reference = snapshot.reference;
    legacy_reference.sha256 = digest(&legacy_bytes);
    legacy_reference.snapshot_id = format!("workspace-snapshot-sha256-{}", legacy_reference.sha256);

    let verified = resolve_workspace_snapshot(&artifact_root, "case-legacy-v1", &legacy_reference)
        .expect("legacy v1 snapshot remains verifiable");
    assert!(verified.manifest.exclusion_policy.is_none());
}

#[test]
fn legacy_v2_gitignore_manifest_without_audit_fields_remains_verifiable() {
    let (_temp, artifact_root, source) = roots();
    fs::write(source.join("code.rs"), b"fn legacy_v2() {}\n").unwrap();
    let snapshot = create_workspace_snapshot(
        &artifact_root,
        "case-legacy-v2",
        "source-legacy-v2",
        &source,
        small_limits(),
    )
    .unwrap();
    let resolved =
        resolve_workspace_snapshot(&artifact_root, "case-legacy-v2", &snapshot.reference).unwrap();
    let manifest_path = resolved.manifest_path;
    make_test_file_writable(&manifest_path);
    let mut legacy: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    legacy["schema_version"] =
        serde_json::Value::String("ai-security-scanner.workspace-snapshot/v2".into());
    legacy["exclusion_policy"] = serde_json::Value::String("repository_gitignore_v1".into());
    legacy.as_object_mut().unwrap().remove("exclusions");
    legacy
        .as_object_mut()
        .unwrap()
        .remove("ignore_rule_sources");
    let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
    fs::write(&manifest_path, &legacy_bytes).unwrap();
    let mut legacy_reference = snapshot.reference;
    legacy_reference.sha256 = digest(&legacy_bytes);
    legacy_reference.snapshot_id = format!("workspace-snapshot-sha256-{}", legacy_reference.sha256);

    let verified = resolve_workspace_snapshot(&artifact_root, "case-legacy-v2", &legacy_reference)
        .expect("legacy v2 snapshot remains verifiable");
    assert_eq!(
        verified.manifest.exclusion_policy,
        Some(WorkspaceSnapshotExclusionPolicy::RepositoryGitignoreV1)
    );
    assert!(verified.manifest.exclusions.is_empty());
    assert!(verified.manifest.ignore_rule_sources.is_empty());
}

#[test]
fn typed_oci_layout_becomes_a_verified_container_asset_with_backend_marker() {
    let (_temp, artifact_root, source) = roots();
    write_single_image_oci_layout(&source);

    let snapshot = create_workspace_snapshot_with_profile(
        &artifact_root,
        "case-oci",
        "source-oci",
        &source,
        WorkspaceInputProfile::ContainerImageOciLayout,
        small_limits(),
    )
    .expect("valid OCI layout snapshot");

    assert_eq!(snapshot.asset.kind, AssetKind::ContainerImage);
    assert_eq!(
        snapshot.reference.input_profile,
        WorkspaceInputProfile::ContainerImageOciLayout
    );
    assert_eq!(
        snapshot.manifest.input_profile,
        snapshot.reference.input_profile
    );
    assert!(
        snapshot
            .manifest
            .files
            .iter()
            .any(|file| file.relative_path == LOCAL_INPUT_PROFILE_FILENAME)
    );
    assert!(!source.join(LOCAL_INPUT_PROFILE_FILENAME).exists());

    let resolved = resolve_workspace_snapshot(&artifact_root, "case-oci", &snapshot.reference)
        .expect("typed snapshot resolves");
    let marker = fs::read_to_string(resolved.tree_path.join(LOCAL_INPUT_PROFILE_FILENAME)).unwrap();
    assert!(marker.contains("container_image_oci_layout"));
}

#[test]
fn typed_input_rejects_reserved_markers_wrong_profiles_and_tampered_oci_blobs() {
    let (_temp, artifact_root, source) = roots();
    fs::write(
        source.join(LOCAL_INPUT_PROFILE_FILENAME),
        b"attacker supplied",
    )
    .unwrap();
    let reserved = create_workspace_snapshot_with_profile(
        &artifact_root,
        "case-reserved",
        "source-reserved",
        &source,
        WorkspaceInputProfile::RepositoryWorkingTree,
        small_limits(),
    )
    .unwrap_err();
    assert!(reserved.to_string().contains("reserved backend marker"));

    fs::remove_file(source.join(LOCAL_INPUT_PROFILE_FILENAME)).unwrap();
    fs::write(source.join("README.txt"), b"not infrastructure as code").unwrap();
    let wrong_profile = create_workspace_snapshot_with_profile(
        &artifact_root,
        "case-wrong-profile",
        "source-wrong-profile",
        &source,
        WorkspaceInputProfile::IacWorkingTree,
        small_limits(),
    )
    .unwrap_err();
    assert!(wrong_profile.to_string().contains("contains no"));

    fs::remove_file(source.join("README.txt")).unwrap();
    write_single_image_oci_layout(&source);
    let layer = fs::read_dir(source.join("blobs/sha256"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            fs::read(path).ok().is_some_and(|bytes| {
                bytes
                    .windows(b"package-lock.json".len())
                    .any(|window| window == b"package-lock.json")
            })
        })
        .unwrap();
    fs::write(layer, b"changed after digest").unwrap();
    let tampered = create_workspace_snapshot_with_profile(
        &artifact_root,
        "case-tampered-oci",
        "source-tampered-oci",
        &source,
        WorkspaceInputProfile::ContainerImageOciLayout,
        small_limits(),
    )
    .unwrap_err();
    assert!(tampered.to_string().contains("does not match its blob"));
}

#[test]
fn typed_oci_layout_rejects_media_rootfs_layer_tar_and_unreferenced_blob_drift() {
    expect_invalid_oci(
        |root| {
            let mut index: serde_json::Value =
                serde_json::from_slice(&fs::read(root.join("index.json")).unwrap()).unwrap();
            index["manifests"][0]["mediaType"] =
                serde_json::Value::String("application/octet-stream".into());
            fs::write(root.join("index.json"), serde_json::to_vec(&index).unwrap()).unwrap();
        },
        "manifest descriptor mediaType",
    );

    expect_invalid_oci(
        |root| {
            rewrite_config(root, |config| {
                config["rootfs"]["diff_ids"] = serde_json::json!([])
            })
        },
        "rootfs diff_ids",
    );

    expect_invalid_oci(
        |root| {
            rewrite_config(root, |config| {
                config["rootfs"]["diff_ids"][0] =
                    serde_json::Value::String(format!("sha256:{}", "0".repeat(64)));
            });
        },
        "does not match its config diff_id",
    );

    expect_invalid_oci(
        |root| {
            rewrite_manifest(root, |manifest| {
                let invalid_tar = b"not a tar archive";
                let layer_descriptor = &mut manifest["layers"][0];
                let old_layer_digest = descriptor_digest(layer_descriptor);
                let new_layer_digest = digest(invalid_tar);
                fs::write(
                    root.join("blobs/sha256").join(&new_layer_digest),
                    invalid_tar,
                )
                .unwrap();
                fs::remove_file(root.join("blobs/sha256").join(old_layer_digest)).unwrap();
                layer_descriptor["digest"] =
                    serde_json::Value::String(format!("sha256:{new_layer_digest}"));
                layer_descriptor["size"] = serde_json::json!(invalid_tar.len());

                let config_descriptor = &mut manifest["config"];
                let old_config_digest = descriptor_digest(config_descriptor);
                let old_config_path = root.join("blobs/sha256").join(&old_config_digest);
                let mut config: serde_json::Value =
                    serde_json::from_slice(&fs::read(&old_config_path).unwrap()).unwrap();
                config["rootfs"]["diff_ids"][0] =
                    serde_json::Value::String(format!("sha256:{new_layer_digest}"));
                let config_bytes = serde_json::to_vec(&config).unwrap();
                let new_config_digest = digest(&config_bytes);
                fs::write(
                    root.join("blobs/sha256").join(&new_config_digest),
                    &config_bytes,
                )
                .unwrap();
                fs::remove_file(old_config_path).unwrap();
                config_descriptor["digest"] =
                    serde_json::Value::String(format!("sha256:{new_config_digest}"));
                config_descriptor["size"] = serde_json::json!(config_bytes.len());
            });
        },
        "tar",
    );

    expect_invalid_oci(
        |root| {
            let bytes = b"unreferenced";
            fs::write(root.join("blobs/sha256").join(digest(bytes)), bytes).unwrap();
        },
        "unreferenced blobs",
    );
}

#[cfg(unix)]
#[test]
fn symlink_is_rejected_without_following_and_staging_is_rolled_back() {
    let (_temp, artifact_root, source) = roots();
    let outside = source.parent().unwrap().join("outside-secret.txt");
    fs::write(&outside, b"outside secret").unwrap();
    symlink(&outside, source.join("linked-secret")).unwrap();

    let error = create_workspace_snapshot(
        &artifact_root,
        "case-symlink",
        "source-safe",
        &source,
        small_limits(),
    )
    .expect_err("symlink must fail closed");

    assert!(error.to_string().contains("symlink"));
    assert!(snapshot_entries(&artifact_root, "case-symlink").is_empty());
}

#[test]
fn byte_limits_fail_closed_and_remove_partial_staging() {
    let (_temp, artifact_root, source) = roots();
    fs::write(source.join("a-small.txt"), b"copied before the error").unwrap();
    fs::write(source.join("z-too-large.bin"), vec![7_u8; 65]).unwrap();
    let limits = WorkspaceSnapshotLimits {
        max_files: 10,
        max_directories: 10,
        max_total_bytes: 128,
        max_file_bytes: 64,
        max_depth: 4,
    };

    let error = create_workspace_snapshot(
        &artifact_root,
        "case-oversize",
        "source-safe",
        &source,
        limits,
    )
    .expect_err("oversize file rejected");

    assert!(error.to_string().contains("byte limit"));
    assert!(snapshot_entries(&artifact_root, "case-oversize").is_empty());
}

#[test]
fn file_count_depth_and_zero_limits_are_enforced() {
    let (_temp, artifact_root, source) = roots();
    fs::write(source.join("one.txt"), b"one").unwrap();
    fs::write(source.join("two.txt"), b"two").unwrap();
    let one_file = WorkspaceSnapshotLimits {
        max_files: 1,
        ..small_limits()
    };
    let count_error = create_workspace_snapshot(
        &artifact_root,
        "case-count",
        "source-safe",
        &source,
        one_file,
    )
    .expect_err("file-count bound enforced");
    assert!(count_error.to_string().contains("file-count"));
    assert!(snapshot_entries(&artifact_root, "case-count").is_empty());

    let (_other_temp, other_artifact_root, other_source) = roots();
    fs::create_dir(other_source.join("nested")).unwrap();
    fs::write(other_source.join("nested/file.txt"), b"nested").unwrap();
    let flat_only = WorkspaceSnapshotLimits {
        max_depth: 0,
        ..small_limits()
    };
    let depth_error = create_workspace_snapshot(
        &other_artifact_root,
        "case-depth",
        "source-safe",
        &other_source,
        flat_only,
    )
    .expect_err("depth bound enforced");
    assert!(depth_error.to_string().contains("directory depth"));
    assert!(snapshot_entries(&other_artifact_root, "case-depth").is_empty());

    let invalid_limits = WorkspaceSnapshotLimits {
        max_files: 0,
        ..small_limits()
    };
    let limit_error = create_workspace_snapshot(
        &other_artifact_root,
        "case-invalid-limit",
        "source-safe",
        &other_source,
        invalid_limits,
    )
    .expect_err("zero safety bound rejected");
    assert!(limit_error.to_string().contains("built-in safety ceiling"));
}

#[cfg(unix)]
#[test]
fn socket_entry_is_rejected_without_opening_it() {
    use std::os::unix::net::UnixListener;

    let (_temp, artifact_root, source) = roots();
    let _listener = UnixListener::bind(source.join("scanner.sock")).unwrap();
    let error = create_workspace_snapshot(
        &artifact_root,
        "case-socket",
        "source-safe",
        &source,
        small_limits(),
    )
    .expect_err("socket rejected");

    assert!(error.to_string().contains("device, FIFO, or socket"));
    assert!(snapshot_entries(&artifact_root, "case-socket").is_empty());
}

#[cfg(unix)]
#[test]
fn non_utf8_entry_is_rejected_and_rolled_back() {
    let (_temp, artifact_root, source) = roots();
    let invalid_name = OsString::from_vec(vec![b'i', b'n', b'v', b'a', b'l', b'i', b'd', 0xff]);
    fs::write(source.join(invalid_name), b"not representable").unwrap();

    let error = create_workspace_snapshot(
        &artifact_root,
        "case-non-utf8",
        "source-safe",
        &source,
        small_limits(),
    )
    .expect_err("non-UTF-8 path rejected");

    assert!(error.to_string().contains("non-UTF-8"));
    assert!(snapshot_entries(&artifact_root, "case-non-utf8").is_empty());
}

#[test]
fn unsafe_ids_non_directory_sources_and_overlapping_roots_are_rejected() {
    let (_temp, artifact_root, source) = roots();
    fs::write(source.join("file.txt"), b"content").unwrap();

    let traversal = create_workspace_snapshot(
        &artifact_root,
        "../escape",
        "source-safe",
        &source,
        small_limits(),
    )
    .expect_err("traversal id rejected");
    assert!(traversal.to_string().contains("unsafe path"));
    assert!(!artifact_root.parent().unwrap().join("escape").exists());

    let selected_file = source.join("file.txt");
    let not_directory = create_workspace_snapshot(
        &artifact_root,
        "case-safe",
        "source-safe",
        &selected_file,
        small_limits(),
    )
    .expect_err("file cannot be selected as a tree");
    assert!(not_directory.to_string().contains("real directory"));

    let nested_artifact_root = source.join("artifact-child");
    fs::create_dir(&nested_artifact_root).unwrap();
    let overlap = create_workspace_snapshot(
        &nested_artifact_root,
        "case-safe",
        "source-safe",
        &source,
        small_limits(),
    )
    .expect_err("artifact/source overlap rejected");
    assert!(overlap.to_string().contains("must not overlap"));
}

#[cfg(unix)]
#[test]
fn a_symlinked_selected_root_is_rejected() {
    let (temp, artifact_root, source) = roots();
    let selected_link = temp.path().join("selected-link");
    symlink(&source, &selected_link).unwrap();

    let error = create_workspace_snapshot(
        &artifact_root,
        "case-link-root",
        "source-safe",
        &selected_link,
        small_limits(),
    )
    .expect_err("symlink root rejected");
    assert!(error.to_string().contains("symlink"));
}

#[test]
fn resolver_rejects_tampered_content_and_injected_storage_ids() {
    let (_temp, artifact_root, source) = roots();
    fs::write(source.join("code.rs"), b"fn original() {}\n").unwrap();
    let snapshot = create_workspace_snapshot(
        &artifact_root,
        "case-tamper",
        "source-safe",
        &source,
        small_limits(),
    )
    .unwrap();
    let resolved = resolve_workspace_snapshot(&artifact_root, "case-tamper", &snapshot.reference)
        .expect("initial verification");
    let copied = resolved.tree_path.join("code.rs");
    make_test_file_writable(&copied);
    fs::write(&copied, b"fn tampered() {}\n").unwrap();

    let tampered = resolve_workspace_snapshot(&artifact_root, "case-tamper", &snapshot.reference)
        .expect_err("content tampering rejected");
    assert!(tampered.to_string().contains("immutable manifest"));

    let mut injected: WorkspaceSnapshotReference = snapshot.reference;
    injected.storage_id = "../../outside".into();
    let injection = resolve_workspace_snapshot(&artifact_root, "case-tamper", &injected)
        .expect_err("injected storage path rejected");
    assert!(injection.to_string().contains("reference is invalid"));
}

#[test]
fn preflight_inspector_is_read_only_and_rejects_missing_or_tampered_snapshots() {
    let (_temp, artifact_root, source) = roots();
    fs::write(source.join("code.rs"), b"fn original() {}\n").unwrap();
    let snapshot = create_workspace_snapshot(
        &artifact_root,
        "case-inspect",
        "source-safe",
        &source,
        small_limits(),
    )
    .unwrap();

    #[cfg(unix)]
    fs::set_permissions(&artifact_root, fs::Permissions::from_mode(0o755)).unwrap();
    #[cfg(unix)]
    let root_mode_before = fs::metadata(&artifact_root).unwrap().permissions().mode() & 0o777;

    let inspected = inspect_workspace_snapshot(&artifact_root, "case-inspect", &snapshot.reference)
        .expect("read-only snapshot inspection");

    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&artifact_root).unwrap().permissions().mode() & 0o777,
        root_mode_before,
        "preflight inspection must not chmod the artifact root"
    );

    let mut missing = snapshot.reference.clone();
    missing.storage_id = format!("workspace-artifact-{}", "0".repeat(32));
    let missing_path = artifact_root
        .join("case-inspect/workspace-snapshots")
        .join(&missing.storage_id);
    let error = inspect_workspace_snapshot(&artifact_root, "case-inspect", &missing)
        .expect_err("missing snapshot rejected");
    assert!(error.to_string().contains("directory is unavailable"));
    assert!(
        !missing_path.exists(),
        "inspection must not create a missing snapshot directory"
    );

    let copied = inspected.tree_path.join("code.rs");
    make_test_file_writable(&copied);
    fs::write(&copied, b"fn tampered() {}\n").unwrap();

    let error = inspect_workspace_snapshot(&artifact_root, "case-inspect", &snapshot.reference)
        .expect_err("tampered snapshot rejected");
    assert!(error.to_string().contains("immutable manifest"));
}

#[cfg(unix)]
#[test]
fn concurrent_file_mutation_is_detected_and_failed_staging_is_removed() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let (_temp, artifact_root, source) = roots();
    let changing = source.join("changing.bin");
    let file = FileBuilder::sized(&changing, 16 * 1024 * 1024);
    drop(file);
    let stop = Arc::new(AtomicBool::new(false));
    let mutations = Arc::new(AtomicUsize::new(0));
    let thread_stop = Arc::clone(&stop);
    let thread_mutations = Arc::clone(&mutations);
    let thread_path = changing.clone();
    let writer = std::thread::spawn(move || {
        let mut value = 0_u8;
        while !thread_stop.load(Ordering::Acquire) {
            let mut file = OpenOptions::new().write(true).open(&thread_path).unwrap();
            let offset = (thread_mutations.load(Ordering::Relaxed) % (1024 * 1024)) as u64;
            file.seek(SeekFrom::Start(offset)).unwrap();
            value = value.wrapping_add(1);
            file.write_all(&[value]).unwrap();
            file.sync_data().unwrap();
            thread_mutations.fetch_add(1, Ordering::Release);
        }
    });
    while mutations.load(Ordering::Acquire) < 4 {
        std::thread::yield_now();
    }

    let limits = WorkspaceSnapshotLimits {
        max_files: 2,
        max_directories: 1,
        max_total_bytes: 32 * 1024 * 1024,
        max_file_bytes: 32 * 1024 * 1024,
        max_depth: 1,
    };
    let mut detected = false;
    for _ in 0..3 {
        match create_workspace_snapshot(
            &artifact_root,
            "case-changing",
            "source-safe",
            &source,
            limits,
        ) {
            Err(error) if error.to_string().contains("changed while") => {
                detected = true;
                break;
            }
            Err(error) => panic!("unexpected mutation failure: {error}"),
            Ok(_) => {}
        }
    }
    stop.store(true, Ordering::Release);
    writer.join().unwrap();

    assert!(detected, "continuous content mutation must be detected");
    assert!(
        snapshot_entries(&artifact_root, "case-changing")
            .iter()
            .all(|name| !name.starts_with(".workspace-staging-"))
    );
}

#[cfg(unix)]
struct FileBuilder;

#[cfg(unix)]
impl FileBuilder {
    fn sized(path: &Path, bytes: u64) -> fs::File {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.set_len(bytes).unwrap();
        file
    }
}
