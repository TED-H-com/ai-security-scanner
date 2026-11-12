use super::*;
use crate::case_archive_io::validate_path;
use crate::workspace_snapshot::{WorkspaceSnapshotExclusionReason, WorkspaceSnapshotFile};
use policy::{Policy, beneath, sensitive};

pub(super) struct Partition {
    pub files: Vec<BundleFile>,
    pub exclusions: Vec<Exclusion>,
}
fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/').map(|(i, _)| &path[..i])
}
fn covered(path: &str, pruned: &BTreeSet<String>) -> bool {
    pruned.contains(path) || ancestors(path).any(|p| pruned.contains(p))
}
pub(super) fn check_scope(manifest: &WorkspaceSnapshotManifest, scope: &[String]) -> AppResult<()> {
    for path in scope {
        if path != "."
            && !manifest.directories.contains(path)
            && !manifest.files.iter().any(|f| f.relative_path == *path)
        {
            return Err(invalid(
                "scope selector is absent from the canonical manifest (case aliases are not accepted)",
            ));
        }
    }
    Ok(())
}

/// The only content-dependent decision is supplied by the verified reader.
/// Offline inspection may supply the recorded reason for excluded content;
/// it still reconstructs and compares the entire structural partition.
pub(super) fn partition(
    manifest: &WorkspaceSnapshotManifest,
    policy: &Policy,
    mut content: impl FnMut(&WorkspaceSnapshotFile) -> AppResult<Option<ExclusionReason>>,
) -> AppResult<Partition> {
    check_scope(manifest, &policy.scope)?;
    let mut exclusions = manifest
        .exclusions
        .iter()
        .map(|e| Exclusion {
            path: e.relative_path.clone(),
            entry_kind: e.entry_kind,
            covers_subtree: e.entry_kind == EntryKind::Directory,
            reason: match e.reason {
                WorkspaceSnapshotExclusionReason::GitMetadata => {
                    ExclusionReason::CanonicalGitMetadata
                }
                WorkspaceSnapshotExclusionReason::RepositoryGitignoreUntracked => {
                    ExclusionReason::CanonicalRepositoryGitignoreUntracked
                }
            },
        })
        .collect::<Vec<_>>();
    let mut pruned = BTreeSet::new();
    for path in &manifest.directories {
        if covered(path, &pruned) {
            continue;
        }
        let reason = if !policy
            .scope
            .iter()
            .any(|s| beneath(path, s) || beneath(s, path))
        {
            Some(ExclusionReason::OutsideScope)
        } else if sensitive(path) {
            Some(ExclusionReason::SensitiveName)
        } else {
            None
        };
        if let Some(reason) = reason {
            pruned.insert(path.clone());
            exclusions.push(Exclusion {
                path: path.clone(),
                reason,
                entry_kind: EntryKind::Directory,
                covers_subtree: true,
            });
        }
    }
    // Check every component, including directory aliases and file/directory
    // aliases. Exclude every file below either spelling, independent of order.
    let mut spellings: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for path in manifest
        .directories
        .iter()
        .map(String::as_str)
        .chain(manifest.files.iter().map(|f| f.relative_path.as_str()))
    {
        for prefix in ancestors(path).chain(std::iter::once(path)) {
            spellings
                .entry(prefix.to_lowercase())
                .or_default()
                .insert(prefix.into());
        }
    }
    let collisions = spellings
        .into_values()
        .filter(|s| s.len() > 1)
        .flatten()
        .collect::<BTreeSet<_>>();
    let mut files = Vec::new();
    let mut included_parents = BTreeSet::new();
    for file in &manifest.files {
        let path = &file.relative_path;
        if covered(path, &pruned) {
            continue;
        }
        let reason = if !policy.scope.iter().any(|s| beneath(path, s)) {
            Some(ExclusionReason::OutsideScope)
        } else if sensitive(path) {
            Some(ExclusionReason::SensitiveName)
        } else if validate_path(path).is_err()
            || path.split('/').count() > policy.limits.path_components
            || covered(path, &collisions)
        {
            Some(ExclusionReason::UnsupportedPath)
        } else if file.byte_length > policy.limits.file_bytes {
            Some(ExclusionReason::OversizeFile)
        } else {
            content(file)?
        };
        if let Some(reason) = reason {
            exclusions.push(Exclusion {
                path: path.clone(),
                reason,
                entry_kind: EntryKind::File,
                covers_subtree: false,
            });
        } else {
            included_parents.extend(ancestors(path).map(String::from));
            files.push(BundleFile {
                path: path.clone(),
                sha256: file.sha256.clone(),
                byte_length: file.byte_length,
            });
        }
    }
    for path in &manifest.directories {
        if !covered(path, &pruned) && !included_parents.contains(path) {
            exclusions.push(Exclusion {
                path: path.clone(),
                reason: ExclusionReason::NoIncludedDescendants,
                entry_kind: EntryKind::Directory,
                covers_subtree: false,
            });
        }
    }
    exclusions.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Partition { files, exclusions })
}

pub(super) fn assemble(
    canonical_bytes: &[u8],
    manifest: &WorkspaceSnapshotManifest,
    policy: Policy,
    partition: Partition,
) -> AppResult<Result<ViewManifest, Blocker>> {
    let total = partition.files.iter().map(|f| f.byte_length).sum::<u64>();
    for (name, limit, observed) in [
        (
            "included_files",
            policy.limits.files as u64,
            partition.files.len() as u64,
        ),
        ("included_bytes", policy.limits.total_bytes, total),
    ] {
        if observed > limit {
            return Ok(Err(Blocker::limit(name, limit, observed)));
        }
    }
    if partition.files.is_empty() {
        return Ok(Err(Blocker::new(BlockerCode::ViewEmpty, "partition")));
    }
    let sha = digest(canonical_bytes);
    let snapshot_id = format!("workspace-snapshot-sha256-{sha}");
    let source_ref = format!("snapshot:{snapshot_id};git:not_recorded");
    let source = SourceView {
        canonical_snapshot_id: Some(snapshot_id.clone()),
        canonical_snapshot_sha256: Some(sha.clone()),
        view_id: String::new(),
        view_sha256: file_index_digest(&partition.files)?,
        source_ref,
        policy_id: policy.id.clone(),
        files: partition.files,
    };
    let mut view = ViewManifest {
        schema_version: VIEW_SCHEMA.into(),
        identity_recipe: "ai-security-scanner.ai-source-view-identity/v1".into(),
        included_file_count: source.files.len(),
        omitted_file_count: manifest.files.len() - source.files.len(),
        included_bytes: total,
        source,
        policy_sha256: policy.sha256()?,
        policy,
        lineage: Lineage {
            canonical_snapshot_id: snapshot_id,
            canonical_manifest_sha256: sha,
            canonical_manifest_byte_length: canonical_bytes.len() as u64,
            capture_record: CaptureIdentity::NotRecorded,
        },
        exclusions: partition.exclusions,
        line_mapping: "identity".into(),
    };
    view.source.view_id = view.identity()?;
    let source_len = canonical_bytes_len(&view.source)?;
    let manifest_len = canonical_bytes_len(&view)?;
    for (name, limit, observed) in [
        (
            "source_metadata_bytes",
            view.policy.limits.source_bytes,
            source_len,
        ),
        (
            "manifest_bytes",
            view.policy.limits.manifest_bytes,
            manifest_len,
        ),
    ] {
        if observed > limit {
            return Ok(Err(Blocker::limit(name, limit, observed)));
        }
    }
    Ok(Ok(view))
}
fn canonical_bytes_len(value: &impl Serialize) -> AppResult<u64> {
    Ok(canonical_bytes(value)?.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_snapshot::{
        WORKSPACE_SNAPSHOT_SCHEMA, WorkspaceSnapshotExclusion, WorkspaceSnapshotExclusionPolicy,
    };
    fn manifest() -> WorkspaceSnapshotManifest {
        WorkspaceSnapshotManifest {
            schema_version: WORKSPACE_SNAPSHOT_SCHEMA.into(),
            content_semantics: "working_tree_only".into(),
            input_profile: Default::default(),
            exclusion_policy: Some(WorkspaceSnapshotExclusionPolicy::RepositoryTrackedGitignoreV2),
            excluded_entries: vec![".git".into()],
            exclusions: vec![],
            ignore_rule_sources: vec![],
            directories: vec![],
            files: vec![],
            directory_count: 0,
            file_count: 0,
            total_bytes: 0,
        }
    }
    #[test]
    fn copied_canonical_exclusions_and_pruned_subtrees_account_for_every_file() {
        let mut m = manifest();
        m.directories = vec!["outside".into(), "src".into(), "src/credentials".into()];
        m.files = [
            "outside/a",
            "outside/b",
            "src/credentials/a",
            "src/credentials/b",
            "src/ok",
        ]
        .map(|p| WorkspaceSnapshotFile {
            relative_path: p.into(),
            byte_length: 1,
            sha256: "a".repeat(64),
        })
        .into();
        m.exclusions.push(WorkspaceSnapshotExclusion {
            relative_path: "generated".into(),
            entry_kind: EntryKind::Directory,
            reason: WorkspaceSnapshotExclusionReason::RepositoryGitignoreUntracked,
        });
        let p = partition(&m, &Policy::new(vec!["src".into()]), |_| Ok(None)).unwrap();
        assert_eq!(p.files.len(), 1);
        assert_eq!(p.exclusions.len(), 3);
        assert!(p.exclusions.iter().all(|e| e.covers_subtree));
        assert_eq!(
            p.exclusions[0].reason,
            ExclusionReason::CanonicalRepositoryGitignoreUntracked
        );
        for file in &m.files {
            assert_eq!(
                p.files
                    .iter()
                    .filter(|f| f.path == file.relative_path)
                    .count()
                    + p.exclusions
                        .iter()
                        .filter(|e| beneath(&file.relative_path, &e.path))
                        .count(),
                1
            );
        }
    }
    #[test]
    fn rule_precedence_and_synthetic_case_collisions() {
        for (path, scope, limit, bytes, expected) in [
            (
                ".env",
                "src",
                0,
                b"\xff\0-----BEGIN PRIVATE KEY-----".as_slice(),
                ExclusionReason::OutsideScope,
            ),
            (
                ".env",
                ".",
                0,
                b"\xff\0-----BEGIN PRIVATE KEY-----".as_slice(),
                ExclusionReason::SensitiveName,
            ),
            (
                "CON",
                ".",
                0,
                b"\xff\0-----BEGIN PRIVATE KEY-----".as_slice(),
                ExclusionReason::UnsupportedPath,
            ),
            (
                "file",
                ".",
                0,
                b"\xff\0-----BEGIN PRIVATE KEY-----".as_slice(),
                ExclusionReason::OversizeFile,
            ),
            (
                "file",
                ".",
                1024,
                b"\xff\0-----BEGIN PRIVATE KEY-----".as_slice(),
                ExclusionReason::NonUtf8Text,
            ),
            (
                "file",
                ".",
                1024,
                b"\0-----BEGIN PRIVATE KEY-----".as_slice(),
                ExclusionReason::BinaryControlBytes,
            ),
            (
                "file",
                ".",
                1024,
                b"-----BEGIN PRIVATE KEY-----".as_slice(),
                ExclusionReason::PrivateKeyMarker,
            ),
        ] {
            let mut m = manifest();
            m.directories.push("src".into());
            m.files.push(WorkspaceSnapshotFile {
                relative_path: path.into(),
                sha256: digest(bytes),
                byte_length: bytes.len() as u64,
            });
            let mut p = Policy::new(vec![scope.into()]);
            p.limits.file_bytes = limit;
            let result = partition(&m, &p, |_| Ok(policy::content_reason(bytes))).unwrap();
            assert_eq!(
                result
                    .exclusions
                    .iter()
                    .find(|e| e.path == path)
                    .unwrap()
                    .reason,
                expected
            );
        }
        let mut m = manifest();
        m.directories = ["A", "a"].map(String::from).into();
        m.files = ["A/x", "SAME", "a/y", "same", "safe"]
            .map(|path| WorkspaceSnapshotFile {
                relative_path: path.into(),
                sha256: "a".repeat(64),
                byte_length: 1,
            })
            .into();
        let result = partition(&m, &Policy::new(vec![".".into()]), |_| Ok(None)).unwrap();
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "safe");
        for path in ["A/x", "a/y", "same", "SAME"] {
            assert_eq!(
                result
                    .exclusions
                    .iter()
                    .find(|e| e.path == path)
                    .unwrap()
                    .reason,
                ExclusionReason::UnsupportedPath
            );
        }
        let view = assemble(b"synthetic", &m, Policy::new(vec![".".into()]), result)
            .unwrap()
            .unwrap();
        assert_eq!(
            view.source.source_ref,
            format!(
                "snapshot:workspace-snapshot-sha256-{};git:not_recorded",
                digest(b"synthetic")
            )
        );
    }

    #[test]
    fn every_aggregate_limit_blocks_without_truncation() {
        let mut m = manifest();
        m.files.push(WorkspaceSnapshotFile {
            relative_path: "a".into(),
            sha256: "a".repeat(64),
            byte_length: 1,
        });
        for bound in [
            "included_files",
            "included_bytes",
            "source_metadata_bytes",
            "manifest_bytes",
        ] {
            let mut policy = Policy::new(vec![".".into()]);
            match bound {
                "included_files" => policy.limits.files = 0,
                "included_bytes" => policy.limits.total_bytes = 0,
                "source_metadata_bytes" => policy.limits.source_bytes = 0,
                _ => policy.limits.manifest_bytes = 0,
            }
            let partition = partition(&m, &policy, |_| Ok(None)).unwrap();
            let blocker = assemble(b"synthetic", &m, policy, partition)
                .unwrap()
                .unwrap_err();
            assert_eq!(blocker.bound.as_deref(), Some(bound));
        }
    }
}
