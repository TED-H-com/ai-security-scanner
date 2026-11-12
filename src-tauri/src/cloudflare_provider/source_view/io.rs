use super::super::{bundle::verified_read, bundle_io::BundleRoot};
use super::*;
use crate::case_archive_io::{
    guard_archive_parent, make_private, move_preserving_root_permissions, private_tempdir_in,
    publish_directory_no_replace, require_sealed_directory_root, seal_directory_contents,
    seal_directory_root,
};
use crate::workspace_snapshot::{
    WORKSPACE_SNAPSHOT_REFERENCE_SCHEMA, WORKSPACE_SNAPSHOT_SCHEMA, WorkspaceSnapshotReference,
    validate_manifest,
};
use policy::{MIB, Policy};
use std::fs::{self, OpenOptions};
use std::io::Write;

// Snapshot creation permits files + directories + one root audit record.
// A view can additionally exclude each captured file and directory once.
const CANONICAL_AUDIT_RECORDS: usize = 200_000 + 100_000 + 1;
const VIEW_EXCLUSION_RECORDS: usize = CANONICAL_AUDIT_RECORDS + 200_000 + 100_000;

#[derive(Debug, Serialize)]
pub struct SourceViewInspection {
    pub schema_version: &'static str,
    pub manifest_sha256: String,
    pub manifest_byte_length: u64,
    pub source: SourceView,
    pub policy_check: &'static str,
    pub integrity_verified: bool,
    pub expected_identity_verified: bool,
    pub producer_authenticated: bool,
    pub analysis_performed: bool,
}

fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> AppResult<T> {
    let limits = Policy::new(vec![".".into()]).limits;
    if bytes.len() as u64 > limits.manifest_bytes {
        return Err(invalid("metadata byte bound exceeded"));
    }
    serde_json::from_slice(bytes).map_err(|_| invalid("unknown or malformed source-view metadata"))
}
pub(super) fn canonical_manifest(bytes: &[u8]) -> AppResult<WorkspaceSnapshotManifest> {
    if bytes.len() as u64 > 64 * MIB {
        return Err(invalid("canonical manifest exceeds 64 MiB"));
    }
    let manifest: WorkspaceSnapshotManifest = parse(bytes)?;
    // Canonical hard limits are 200,000 files and 100,000 directories.
    if manifest.schema_version != WORKSPACE_SNAPSHOT_SCHEMA
        || !manifest.input_profile.is_repository()
        || manifest.files.len() > 200_000
        || manifest.directories.len() > 100_000
        || manifest
            .exclusions
            .len()
            .saturating_add(manifest.ignore_rule_sources.len())
            > CANONICAL_AUDIT_RECORDS
        || manifest.total_bytes > 10 * 1024 * MIB
    {
        return Err(invalid(
            "unsupported canonical snapshot schema, profile or bounds",
        ));
    }
    let reference = WorkspaceSnapshotReference {
        schema_version: WORKSPACE_SNAPSHOT_REFERENCE_SCHEMA.into(),
        input_profile: manifest.input_profile,
        storage_id: String::new(),
        snapshot_id: format!("workspace-snapshot-sha256-{}", digest(bytes)),
        sha256: digest(bytes),
        file_count: manifest.file_count,
        directory_count: manifest.directory_count,
        total_bytes: manifest.total_bytes,
        working_tree_only: true,
    };
    validate_manifest(&manifest, &reference)
        .map_err(|_| invalid("inconsistent canonical manifest"))?;
    // Structural partition needs a complete, non-overlapping directory index.
    let dirs = manifest
        .directories
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for path in manifest
        .directories
        .iter()
        .map(String::as_str)
        .chain(manifest.files.iter().map(|f| f.relative_path.as_str()))
    {
        if path.split('/').count() > 65
            || path
                .match_indices('/')
                .any(|(i, _)| !dirs.contains(&path[..i]))
        {
            return Err(invalid("incomplete canonical parent inventory"));
        }
    }
    if manifest
        .files
        .iter()
        .any(|f| dirs.contains(f.relative_path.as_str()))
    {
        return Err(invalid("canonical file/directory overlap"));
    }
    Ok(manifest)
}
fn write(root: &Path, relative: &str, bytes: &[u8]) -> AppResult<()> {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().ok_or_else(|| invalid("missing parent"))?)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    make_private(&path, false)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
#[cfg(unix)]
fn sync_dirs(path: &Path) -> AppResult<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_dirs(&entry.path())?;
        }
    }
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn check_index_bounds(view: &ViewManifest) -> AppResult<()> {
    let limits = Policy::new(vec![".".into()]).limits;
    if view.exclusions.len() > VIEW_EXCLUSION_RECORDS {
        return Err(invalid("exclusion audit exceeds canonical bounds"));
    }
    if view.source.files.len() > limits.files
        || view.included_file_count > limits.files
        || view.included_bytes > limits.total_bytes
    {
        return Err(invalid("source index exceeds aggregate bounds"));
    }
    let mut total = 0u64;
    for file in &view.source.files {
        total = total
            .checked_add(file.byte_length)
            .ok_or_else(|| invalid("source index byte overflow"))?;
        if file.byte_length > limits.file_bytes || total > limits.total_bytes {
            return Err(invalid("source index exceeds byte bounds"));
        }
    }
    Ok(())
}

pub fn inspect_source_view(
    input: &Path,
    expected: Option<&str>,
    canonical_payload: Option<&Path>,
) -> AppResult<SourceViewInspection> {
    let mut root = BundleRoot::open(input)?;
    let mut top = BTreeSet::from(["view.json", "canonical-manifest.json", "tree"]);
    root.enumerate("", |name| {
        if !top.remove(name) {
            return Err(invalid("unexpected view root member"));
        }
        Ok(())
    })?;
    if !top.is_empty() {
        return Err(invalid("incomplete view root inventory"));
    }
    let bytes = root.read("view.json", 128 * MIB)?;
    let sha = digest(&bytes);
    if expected.is_some_and(|e| !valid_hash(e) || e != sha) {
        return Err(invalid("manifest digest mismatch"));
    }
    let view: ViewManifest = parse(&bytes)?;
    check_index_bounds(&view)?;
    // Typed parsing plus exact canonical bytes rejects ambiguous encodings before use.
    if canonical_bytes(&view)? != bytes {
        return Err(invalid("non-canonical view encoding"));
    }
    let normalized = policy::normalize_scope(&view.policy.scope)?;
    if view.policy != Policy::new(normalized)
        || view.lineage.capture_record != CaptureIdentity::NotRecorded
    {
        return Err(invalid("unknown policy or lineage"));
    }
    let canonical = root.read("canonical-manifest.json", 64 * MIB)?;
    let manifest = canonical_manifest(&canonical)?;
    let mut tree = BundleRoot::open(&input.join("tree"))?;
    let indexed = view
        .source
        .files
        .iter()
        .map(|f| (f.path.as_str(), f))
        .collect::<BTreeMap<_, _>>();
    let excluded = view
        .exclusions
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect::<BTreeMap<_, _>>();
    let partition = partition::partition(&manifest, &view.policy, |file| {
        if let Some(entry) = indexed.get(file.relative_path.as_str()) {
            if entry.sha256 != file.sha256 || entry.byte_length != file.byte_length {
                return Err(invalid("index differs from canonical membership"));
            }
            let content = verified_read(&mut tree, entry)?;
            if policy::content_reason(&content).is_some() {
                return Err(invalid("included file violates policy"));
            }
            Ok(None)
        } else {
            let reason = excluded.get(file.relative_path.as_str()).map(|e| e.reason);
            if !matches!(
                reason,
                Some(
                    ExclusionReason::NonUtf8Text
                        | ExclusionReason::BinaryControlBytes
                        | ExclusionReason::PrivateKeyMarker
                )
            ) {
                return Err(invalid("canonical file is not accounted for exactly once"));
            }
            Ok(reason)
        }
    })?;
    let rebuilt = partition::assemble(&canonical, &manifest, view.policy.clone(), partition)?
        .map_err(|_| invalid("view exceeds aggregate bounds or is empty"))?;
    // Exact equality also checks order, duplicate records, counts, schema,
    // identity, lineage, policy digest and the unchanged SourceView shape.
    if canonical_bytes(&rebuilt)? != bytes {
        return Err(invalid(
            "view manifest is not the canonical partition/identity",
        ));
    }
    let expected_files = rebuilt
        .source
        .files
        .iter()
        .map(|f| f.path.clone())
        .collect();
    tree.check_inventory(&expected_files)?;
    if let Some(payload) = canonical_payload {
        let mut original = BundleRoot::open(payload)?;
        if original.read("manifest.json", 64 * MIB)? != canonical {
            return Err(invalid("replay canonical manifest mismatch"));
        }
        let mut source = BundleRoot::open(&payload.join("tree"))?;
        let replay = partition::partition(&manifest, &view.policy, |file| {
            let bytes = verified_read(
                &mut source,
                &BundleFile {
                    path: file.relative_path.clone(),
                    sha256: file.sha256.clone(),
                    byte_length: file.byte_length,
                },
            )?;
            Ok(policy::content_reason(&bytes))
        })?;
        let replay = partition::assemble(&canonical, &manifest, view.policy.clone(), replay)?
            .map_err(|_| invalid("policy replay blocked"))?;
        if canonical_bytes(&replay)? != bytes {
            return Err(invalid("excluded content failed policy replay"));
        }
        source.verify_unchanged()?;
        original.verify_unchanged()?;
    }
    tree.verify_unchanged()?;
    root.verify_unchanged()?;
    Ok(SourceViewInspection {
        schema_version: "ai-security-scanner.source-view-inspection/v1",
        manifest_sha256: sha,
        manifest_byte_length: bytes.len() as u64,
        source: rebuilt.source,
        policy_check: if canonical_payload.is_some() {
            "replayed"
        } else {
            "included_files_only"
        },
        integrity_verified: true,
        expected_identity_verified: expected.is_some(),
        producer_authenticated: false,
        analysis_performed: false,
    })
}

fn build_staged(
    staging: &Path,
    payload: &Path,
    expected_snapshot: &str,
    policy: Policy,
    checkpoint: &dyn Fn() -> AppResult<()>,
) -> AppResult<Result<ViewManifest, Blocker>> {
    let blocked = |code| Ok(Err(Blocker::new(code, "canonical_input")));
    let mut canonical_root = match BundleRoot::open(payload) {
        Ok(root) => root,
        Err(_) => return blocked(BlockerCode::SafeIoUnavailable),
    };
    let canonical = match canonical_root.read("manifest.json", 64 * MIB) {
        Ok(bytes) => bytes,
        Err(_) => return blocked(BlockerCode::SourceReadFailed),
    };
    if digest(&canonical) != expected_snapshot {
        return Ok(Err(Blocker::new(
            BlockerCode::SnapshotIntegrityFailed,
            "canonical_input",
        )));
    }
    let manifest = match canonical_manifest(&canonical) {
        Ok(manifest) => manifest,
        Err(_) => return blocked(BlockerCode::SnapshotIntegrityFailed),
    };
    fs::create_dir(staging.join("tree"))?;
    let mut source = match BundleRoot::open(&payload.join("tree")) {
        Ok(root) => root,
        Err(_) => return blocked(BlockerCode::SafeIoUnavailable),
    };
    let mut included_bytes = 0u64;
    let mut included_files = 0usize;
    let mut read_failed = false;
    let partition = partition::partition(&manifest, &policy, |file| {
        checkpoint()?;
        let bytes = verified_read(
            &mut source,
            &BundleFile {
                path: file.relative_path.clone(),
                sha256: file.sha256.clone(),
                byte_length: file.byte_length,
            },
        )
        .inspect_err(|_| {
            read_failed = true;
        })?;
        let reason = policy::content_reason(&bytes);
        if reason.is_none() {
            included_bytes += file.byte_length;
            included_files += 1;
            if included_bytes <= policy.limits.total_bytes && included_files <= policy.limits.files
            {
                write(&staging.join("tree"), &file.relative_path, &bytes)?;
            }
        }
        Ok(reason)
    });
    if read_failed {
        return blocked(BlockerCode::SourceReadFailed);
    }
    let partition = partition?;
    let view = match partition::assemble(&canonical, &manifest, policy, partition)? {
        Ok(view) => view,
        Err(blocker) => return Ok(Err(blocker)),
    };
    if source.verify_unchanged().is_err() || canonical_root.verify_unchanged().is_err() {
        return blocked(BlockerCode::SnapshotIntegrityFailed);
    }
    let bytes = canonical_bytes(&view)?;
    let sha = digest(&bytes);
    write(staging, "view.json", &bytes)?;
    write(staging, "canonical-manifest.json", &canonical)?;
    inspect_source_view(staging, Some(&sha), None)?;
    Ok(Ok(view))
}

pub(super) fn publish(
    parent: &Path,
    payload: &Path,
    expected_snapshot: &str,
    policy: Policy,
    checkpoint: &dyn Fn() -> AppResult<()>,
    authorized: &dyn Fn() -> bool,
) -> AppResult<Result<PreparationResult, Blocker>> {
    let guard = guard_archive_parent(parent)?;
    let staging = private_tempdir_in(guard.path(), ".source-view-staging-")?;
    struct UnsealOnDrop<'a>(&'a Path);
    impl Drop for UnsealOnDrop<'_> {
        fn drop(&mut self) {
            crate::workspace_snapshot::make_tree_deletable(self.0);
        }
    }
    let _cleanup = UnsealOnDrop(staging.path());
    let view = match build_staged(
        staging.path(),
        payload,
        expected_snapshot,
        policy,
        checkpoint,
    )? {
        Ok(view) => view,
        Err(blocker) => return Ok(Err(blocker)),
    };
    let bytes = canonical_bytes(&view)?;
    let sha = digest(&bytes);
    #[cfg(unix)]
    sync_dirs(staging.path())?;
    checkpoint()?;
    let destination = guard.path().join(&view.source.view_id);
    if !authorized() {
        return Ok(Err(Blocker::new(
            BlockerCode::SourceAuthorizationExpired,
            "publication",
        )));
    }
    let exists = match fs::symlink_metadata(&destination) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    let reuse = exists
        && require_sealed_directory_root(&destination).is_ok()
        && inspect_source_view(&destination, Some(&sha), None).is_ok();
    if !reuse {
        seal_directory_contents(staging.path())?;
    }
    // Verification and sealing can be lengthy; recheck immediately before publication.
    if !authorized() {
        crate::workspace_snapshot::make_tree_deletable(staging.path());
        return Ok(Err(Blocker::new(
            BlockerCode::SourceAuthorizationExpired,
            "publication",
        )));
    }
    if let Err(error) = checkpoint() {
        crate::workspace_snapshot::make_tree_deletable(staging.path());
        return Err(error);
    }
    if !reuse {
        if exists {
            let aside = private_tempdir_in(guard.path(), ".source-view-damaged-")?;
            let retained = aside.path().with_extension("retained");
            // Only the root is temporarily writable. Retained damaged bytes keep
            // their original seal, including when subsequent publication fails.
            move_preserving_root_permissions(&destination, &retained)?;
        }
        if !authorized() {
            return Ok(Err(Blocker::new(
                BlockerCode::SourceAuthorizationExpired,
                "publication",
            )));
        }
        if let Err(error) = publish_directory_no_replace(staging.path(), &destination) {
            crate::workspace_snapshot::make_tree_deletable(staging.path());
            return Err(error);
        }
        seal_directory_root(&destination)?;
        #[cfg(unix)]
        fs::File::open(guard.path())?.sync_all()?;
    }
    Ok(Ok(PreparationResult::Ready {
        view_id: view.source.view_id,
        manifest_sha256: sha,
        manifest_byte_length: bytes.len() as u64,
        view_sha256: view.source.view_sha256,
        relative_path: String::new(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_snapshot::{WorkspaceSnapshotLimits, create_workspace_snapshot};
    #[test]
    fn surplus_root_inventory_is_rejected_before_metadata_reads() {
        let temp = tempfile::tempdir().unwrap();
        let root = crate::internal_paths::canonicalize(temp.path()).unwrap();
        for i in 0..1000 {
            fs::write(root.join(format!("extra-{i}")), b"").unwrap();
        }
        let error = inspect_source_view(&root, None, None).unwrap_err();
        assert!(error.to_string().contains("unexpected view root member"));
        let mut reader = BundleRoot::open(&root).unwrap();
        let mut calls = 0;
        assert!(
            reader
                .enumerate("", |_| {
                    calls += 1;
                    Err(invalid("stop"))
                })
                .is_err()
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn captured_stage_inspects_replays_moves_and_rejects_tampering_without_publication() {
        let temp = tempfile::tempdir().unwrap();
        let root = crate::internal_paths::canonicalize(temp.path()).unwrap();
        let source = root.join("source");
        let artifacts = root.join("artifacts");
        fs::create_dir_all(source.join("credentials")).unwrap();
        fs::create_dir(&artifacts).unwrap();
        fs::write(source.join("safe.rs"), b"safe\r\nline2").unwrap();
        fs::write(source.join("credentials/fake"), b"obviously fake").unwrap();
        fs::write(source.join("binary"), b"a\0b").unwrap();
        let snapshot = create_workspace_snapshot(
            &artifacts,
            "case-test",
            "source-test",
            &source,
            WorkspaceSnapshotLimits::default(),
        )
        .unwrap();
        let payload = artifacts
            .join("case-test/workspace-snapshots")
            .join(snapshot.reference.storage_id)
            .join("payload");
        let stage = root.join("stage");
        fs::create_dir(&stage).unwrap();
        let view = build_staged(
            &stage,
            &payload,
            &snapshot.reference.sha256,
            Policy::new(vec![".".into()]),
            &|| Ok(()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(view.source.files.len(), 1);
        assert_eq!(view.omitted_file_count, 2);
        let expected = digest(&fs::read(stage.join("view.json")).unwrap());
        assert_eq!(
            inspect_source_view(&stage, Some(&expected), Some(&payload))
                .unwrap()
                .policy_check,
            "replayed"
        );
        fs::write(source.join("safe.rs"), b"post capture changes").unwrap();
        let second = root.join("second");
        fs::create_dir(&second).unwrap();
        build_staged(
            &second,
            &payload,
            &snapshot.reference.sha256,
            Policy::new(vec![".".into()]),
            &|| Ok(()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            fs::read(stage.join("view.json")).unwrap(),
            fs::read(second.join("view.json")).unwrap()
        );
        let moved = root.join("moved");
        crate::case_archive_io::rename_entry_no_replace(&stage, &moved).unwrap();
        assert_eq!(
            inspect_source_view(&moved, Some(&expected), None)
                .unwrap()
                .policy_check,
            "included_files_only"
        );
        fs::write(moved.join("tree/safe.rs"), b"tampered").unwrap();
        assert!(inspect_source_view(&moved, None, None).is_err());
        fs::write(moved.join("tree/safe.rs"), b"safe\r\nline2").unwrap();
        let original = fs::read(moved.join("view.json")).unwrap();
        for mutation in [
            "removed",
            "duplicate",
            "subtree",
            "reason",
            "empty_descendants",
            "included_secret",
            "count",
            "bytes",
        ] {
            let mut changed: ViewManifest = serde_json::from_slice(&original).unwrap();
            let sensitive = changed
                .exclusions
                .iter()
                .position(|e| e.reason == ExclusionReason::SensitiveName)
                .unwrap();
            match mutation {
                "removed" => {
                    changed.exclusions.remove(sensitive);
                }
                "duplicate" => changed
                    .exclusions
                    .push(changed.exclusions[sensitive].clone()),
                "subtree" => changed.exclusions[sensitive].covers_subtree = false,
                "reason" => changed.exclusions[sensitive].reason = ExclusionReason::OutsideScope,
                "empty_descendants" => {
                    changed.exclusions[sensitive].reason = ExclusionReason::NoIncludedDescendants;
                    changed.exclusions[sensitive].covers_subtree = false;
                }
                "included_secret" => {
                    changed.exclusions.remove(sensitive);
                    let content = b"obviously fake";
                    changed.included_file_count += 1;
                    changed.omitted_file_count -= 1;
                    changed.included_bytes += content.len() as u64;
                    changed.source.files.push(BundleFile {
                        path: "credentials/fake".into(),
                        sha256: digest(content),
                        byte_length: content.len() as u64,
                    });
                    fs::create_dir(moved.join("tree/credentials")).unwrap();
                    fs::write(moved.join("tree/credentials/fake"), content).unwrap();
                }
                "count" => changed.included_file_count += 1,
                _ => changed.included_bytes += 1,
            }
            changed.source.files.sort_by(|a, b| a.path.cmp(&b.path));
            changed.source.view_sha256 = file_index_digest(&changed.source.files).unwrap();
            changed.source.view_id = changed.identity().unwrap();
            fs::write(moved.join("view.json"), canonical_bytes(&changed).unwrap()).unwrap();
            assert!(
                inspect_source_view(&moved, None, None).is_err(),
                "{mutation}"
            );
            if mutation == "included_secret" {
                fs::remove_dir_all(moved.join("tree/credentials")).unwrap();
            }
        }
        let text = String::from_utf8(original.clone()).unwrap();
        for encoding in [
            text.replacen('{', "{\"line_mapping\":\"identity\",", 1),
            // Move the first canonical key to the end while retaining exactly the same values.
            {
                let mut fields: serde_json::Map<String, serde_json::Value> =
                    serde_json::from_slice(&original).unwrap();
                let key = fields.keys().next().unwrap().clone();
                let value = fields.remove(&key).unwrap();
                let remaining = serde_json::to_string(&fields).unwrap();
                format!(
                    "{},{}:{}}}",
                    &remaining[..remaining.len() - 1],
                    serde_json::to_string(&key).unwrap(),
                    value
                )
            },
        ] {
            fs::write(moved.join("view.json"), encoding).unwrap();
            assert!(inspect_source_view(&moved, None, None).is_err());
        }
        // Remove content to prove declared bounds fail before any indexed file read.
        fs::remove_file(moved.join("tree/safe.rs")).unwrap();
        for bound in ["file_count", "file_bytes", "total_bytes", "declared_bytes"] {
            let mut changed: ViewManifest = serde_json::from_slice(&original).unwrap();
            match bound {
                "file_count" => {
                    changed.source.files = vec![changed.source.files[0].clone(); 10_001]
                }
                "file_bytes" => changed.source.files[0].byte_length = 8 * MIB + 1,
                "total_bytes" => {
                    changed.source.files[0].byte_length = 8 * MIB;
                    changed.source.files = vec![changed.source.files[0].clone(); 17];
                }
                _ => changed.included_bytes = 128 * MIB + 1,
            }
            // Inflated document limits and noncanonical whitespace must not defer rejection.
            changed.policy.limits.files = usize::MAX;
            changed.policy.limits.file_bytes = u64::MAX;
            changed.policy.limits.total_bytes = u64::MAX;
            fs::write(
                moved.join("view.json"),
                serde_json::to_vec_pretty(&changed).unwrap(),
            )
            .unwrap();
            let error = inspect_source_view(&moved, None, None).unwrap_err();
            assert!(matches!(error, AppError::InvalidRequest(_)));
            assert!(
                error.to_string().contains("source index exceeds"),
                "{bound}: {error}"
            );
        }
        crate::workspace_snapshot::make_tree_deletable(&artifacts);
    }
}
