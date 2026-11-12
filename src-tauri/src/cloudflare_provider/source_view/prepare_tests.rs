use super::*;
use crate::domain::{AssessmentCase, DataSource, OrganizationProfile};
use crate::workspace_snapshot::{WorkspaceSnapshotLimits, create_workspace_snapshot};
use serde_json::json;
use std::path::PathBuf;

struct Fixture {
    _temp: tempfile::TempDir,
    data: PathBuf,
    storage: Storage,
    lease: DataDirectoryExclusiveLease,
    request: PrepareSourceViewRequest,
}
impl Fixture {
    fn new() -> Self {
        Self::with_source(|source| {
            fs::create_dir_all(source.join("src")).unwrap();
            for path in ["src/safe", "!file", "-x"] {
                fs::write(source.join(path), b"safe").unwrap();
            }
        })
    }
    fn with_source(configure: impl FnOnce(&Path)) -> Self {
        let builder = tempfile::Builder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::PermissionsExt;
            let mut builder = builder;
            builder.permissions(fs::Permissions::from_mode(0o700));
            builder
        };
        let temp = builder.tempdir().unwrap();
        let data = crate::internal_paths::canonicalize(temp.path())
            .unwrap()
            .join("data");
        let source = data.join("source");
        fs::create_dir_all(&source).unwrap();
        configure(&source);
        fs::create_dir_all(data.join("artifacts")).unwrap();
        let mut case = AssessmentCase::new(
            "Synthetic".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "1-10".into(),
                data_classes: vec![],
                notes: None,
            },
        );
        let snapshot = create_workspace_snapshot(
            data.join("artifacts"),
            &case.id,
            "source",
            &source,
            WorkspaceSnapshotLimits::default(),
        )
        .unwrap();
        let reference = snapshot.reference;
        let mut asset = snapshot.asset;
        asset.owner_confirmed = true;
        asset.candidate = false;
        case.data_sources.push(DataSource {
            id: "source".into(),
            kind: reference.input_profile.source_kind(),
            label: "Synthetic".into(),
            status: SourceConnectionStatus::Connected,
            connected_at: Some(Utc::now()),
            last_discovered_at: None,
            read_only: true,
            metadata: [(
                WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY.into(),
                json!(reference),
            )]
            .into(),
        });
        case.scope_grants.push(ScopeGrant {
            id: "grant".into(),
            asset_id: asset.id.clone(),
            permission: ScanPermission::LocalArtifactRead,
            confirmed_by: "owner".into(),
            confirmed_at: Utc::now() - chrono::Duration::seconds(60),
            expires_at: None,
            authorization_reference: None,
            notes: None,
            external_scope: None,
        });
        let request = PrepareSourceViewRequest {
            case_id: case.id.clone(),
            asset_id: asset.id.clone(),
            expected_snapshot_sha256: reference.sha256,
            scope_paths: vec![".".into()],
            request_id: "request".into(),
            acknowledge_model_processing: true,
            confirmed_by: "owner".into(),
            declared_host_id: "declared".into(),
        };
        case.assets.push(asset);
        let storage = Storage::open(data.join("casework.db")).unwrap();
        storage.save_case(&mut case, "fixture.created").unwrap();
        let lease = DataDirectoryExclusiveLease::acquire(&data).unwrap();
        Self {
            _temp: temp,
            data,
            storage,
            lease,
            request,
        }
    }
    fn context(&self) -> OwnedContext<'_> {
        OwnedContext {
            storage: &self.storage,
            data_dir: &self.data,
            lease: &self.lease,
            cancelled: None,
        }
    }
    fn change(&self, change: impl FnOnce(&mut AssessmentCase)) {
        let mut case = self.storage.get_case(&self.request.case_id).unwrap();
        change(&mut case);
        self.storage
            .save_case(&mut case, "fixture.changed")
            .unwrap();
    }
    fn prepare(&self) -> PreparationOutcome {
        prepare_source_view(&self.context(), &self.request).unwrap()
    }
    fn path(&self, receipt: &SourceViewPreparationReceipt) -> PathBuf {
        let PreparationResult::Ready { relative_path, .. } = &receipt.result else {
            panic!("not ready")
        };
        self.data.join("artifacts").join(relative_path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        crate::workspace_snapshot::make_tree_deletable(&self.data);
    }
}
fn committed(outcome: PreparationOutcome) -> SourceViewPreparationReceipt {
    let PreparationOutcome::Committed(receipt) = outcome else {
        panic!("expected committed, got {outcome:?}")
    };
    receipt
}
fn blocker(receipt: &SourceViewPreparationReceipt) -> BlockerCode {
    let PreparationResult::Blocked { blockers } = &receipt.result else {
        panic!("expected blocked")
    };
    blockers[0].code
}

#[test]
fn replay_rechecks_removed_expired_changed_grants_and_replaced_snapshot() {
    for mutation in ["removed", "expired", "grant_changed", "snapshot"] {
        let f = Fixture::new();
        let first = committed(f.prepare());
        f.change(|case| match mutation {
            "removed" => case.scope_grants.clear(),
            "expired" => {
                case.scope_grants[0].expires_at = Some(Utc::now() - chrono::Duration::seconds(1))
            }
            "grant_changed" => case.scope_grants[0].confirmed_by = "another-owner".into(),
            _ => {
                let source = f.data.join("replacement");
                fs::create_dir(&source).unwrap();
                fs::write(source.join("other"), b"different snapshot").unwrap();
                let snapshot = create_workspace_snapshot(
                    f.data.join("artifacts"),
                    &case.id,
                    "source",
                    &source,
                    WorkspaceSnapshotLimits::default(),
                )
                .unwrap();
                case.data_sources[0].metadata.insert(
                    WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY.into(),
                    json!(snapshot.reference),
                );
            }
        });
        let before = f
            .storage
            .list_case_events(&f.request.case_id)
            .unwrap()
            .len();
        let PreparationOutcome::SavedNotCurrent(reason) = f.prepare() else {
            panic!("stale replay accepted: {mutation}")
        };
        assert_eq!(
            json!(reason),
            match mutation {
                "removed" => "source_authorization_missing",
                "expired" => "source_authorization_expired",
                "grant_changed" => "grant_changed",
                _ => "source_binding_mismatch",
            }
        );
        assert_eq!(
            f.storage
                .list_case_events(&f.request.case_id)
                .unwrap()
                .len(),
            before
        );
        assert_eq!(
            f.storage
                .source_view_receipt(&f.request.case_id, &f.request.request_id)
                .unwrap()
                .unwrap()
                .digest,
            first.digest
        );
    }
}

#[test]
fn replay_republishes_missing_and_quarantines_damaged_views() {
    for mutation in ["missing", "removed_file", "changed_byte"] {
        let f = Fixture::new();
        let first = committed(f.prepare());
        let path = f.path(&first);
        crate::workspace_snapshot::make_tree_deletable(&path);
        match mutation {
            "missing" => fs::remove_dir_all(&path).unwrap(),
            "removed_file" => fs::remove_file(path.join("tree/src/safe")).unwrap(),
            _ => fs::write(path.join("tree/src/safe"), b"evil").unwrap(),
        }
        if mutation != "missing" {
            crate::workspace_snapshot::make_snapshot_tree_readonly(&path).unwrap();
        }
        let PreparationOutcome::Replayed(replay) = f.prepare() else {
            panic!("not replayed")
        };
        assert_eq!(json!(first), json!(replay));
        inspect_source_view(&path, None, None).unwrap();
        let damaged = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| {
                let e = e.unwrap();
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".source-view-damaged-")
                    .then(|| e.path())
            })
            .collect::<Vec<_>>();
        assert_eq!(damaged.len(), usize::from(mutation != "missing"));
        for aside in damaged {
            assert!(inspect_source_view(&aside, None, None).is_err());
            if mutation == "changed_byte" {
                assert_eq!(fs::read(aside.join("tree/src/safe")).unwrap(), b"evil");
            }
            if mutation == "removed_file" {
                assert!(!aside.join("tree/src/safe").exists());
            }
        }
    }
}

#[test]
fn authorization_gates_are_independent_and_effective_grants_are_deterministic() {
    for gate in [
        "none",
        "candidate",
        "owner",
        "future",
        "blank",
        "expired_first",
        "no_expiry",
        "non_repository",
        "latest",
        "id",
    ] {
        let f = Fixture::new();
        f.change(|case| match gate {
            "non_repository" => case.assets[0].kind = AssetKind::Host,
            "none" => case.scope_grants.clear(),
            "candidate" => case.assets[0].candidate = true,
            "owner" => case.assets[0].owner_confirmed = false,
            "future" => case.scope_grants[0].confirmed_at = Utc::now() + chrono::Duration::hours(1),
            "blank" => case.scope_grants[0].confirmed_by = " \t ".into(),
            _ => {
                let mut second = case.scope_grants[0].clone();
                second.id = "a-preferred".into();
                if gate == "expired_first" {
                    case.scope_grants[0].expires_at =
                        Some(Utc::now() - chrono::Duration::seconds(1));
                }
                if gate == "no_expiry" {
                    case.scope_grants[0].expires_at = Some(Utc::now() + chrono::Duration::hours(1));
                }
                if gate == "latest" {
                    case.scope_grants[0].expires_at = Some(Utc::now() + chrono::Duration::hours(1));
                    second.expires_at = Some(Utc::now() + chrono::Duration::hours(2));
                }
                case.scope_grants.push(second);
            }
        });
        let receipt = committed(f.prepare());
        if ["expired_first", "no_expiry", "latest", "id"].contains(&gate) {
            assert!(matches!(receipt.result, PreparationResult::Ready { .. }));
            assert_eq!(receipt.grant.unwrap().id, "a-preferred");
        } else {
            assert_eq!(
                blocker(&receipt),
                if gate == "future" {
                    BlockerCode::SourceAuthorizationExpired
                } else if gate == "non_repository" {
                    BlockerCode::InputProfileUnsupported
                } else {
                    BlockerCode::SourceAuthorizationMissing
                }
            );
            assert!(receipt.grant.is_none());
        }
    }
}

#[test]
fn clock_lapse_before_publication_and_commit_never_records_ready() {
    for lapse_at in [2, 3, 4, 5, 6] {
        let f = Fixture::new();
        let now = Utc::now();
        f.change(|case| {
            case.scope_grants[0].expires_at = Some(now + chrono::Duration::seconds(10))
        });
        let calls = std::cell::Cell::new(0);
        let clock = || {
            calls.set(calls.get() + 1);
            if calls.get() >= lapse_at {
                now + chrono::Duration::seconds(11)
            } else {
                now
            }
        };
        let receipt = committed(prepare_with_clock(&f.context(), &f.request, &clock).unwrap());
        assert_eq!(blocker(&receipt), BlockerCode::SourceAuthorizationExpired);
        let PreparationResult::Blocked { blockers } = &receipt.result else {
            unreachable!()
        };
        assert_eq!(
            blockers[0].stage,
            if lapse_at >= 5 {
                "commit"
            } else {
                "publication"
            }
        );

        let views = f
            .data
            .join("artifacts")
            .join(&f.request.case_id)
            .join("source-views");
        let entries = fs::read_dir(views).unwrap().count();
        assert_eq!(entries, usize::from(lapse_at >= 5));
        assert_eq!(
            f.storage
                .source_view_receipt(&f.request.case_id, &f.request.request_id)
                .unwrap()
                .unwrap()
                .digest,
            receipt.digest
        );
    }
}

#[test]
fn signal_after_last_checkpoint_keeps_committed_outcome() {
    let f = Fixture::new();
    let signal = std::sync::atomic::AtomicU8::new(0);
    let calls = std::cell::Cell::new(0);
    let clock = || {
        calls.set(calls.get() + 1);
        if calls.get() == 6 {
            signal.store(130, std::sync::atomic::Ordering::Release);
        }
        Utc::now()
    };
    let mut context = f.context();
    context.cancelled = Some(&signal);
    let receipt = committed(prepare_with_clock(&context, &f.request, &clock).unwrap());
    assert!(matches!(receipt.result, PreparationResult::Ready { .. }));
    assert_eq!(signal.load(std::sync::atomic::Ordering::Acquire), 130);
}

#[test]
fn redundant_scope_is_validated_before_normalization_and_replay() {
    let mut f = Fixture::new();
    for paths in [
        [".", "!file", "-x"],
        ["-x", ".", "!file"],
        ["!file", "-x", "."],
        [".", "-x", "!file"],
        ["!file", ".", "-x"],
        ["-x", "!file", "."],
    ] {
        f.request.scope_paths = paths.map(String::from).into();
        let outcome = f.prepare();
        assert!(matches!(
            outcome,
            PreparationOutcome::Committed(_) | PreparationOutcome::Replayed(_)
        ));
    }
    f.request.scope_paths = vec!["src".into(), "src/safe".into(), "src".into()];
    f.request.request_id = "src".into();
    committed(f.prepare());
    f.request.scope_paths = vec!["src".into(), "src".into()];
    assert!(matches!(f.prepare(), PreparationOutcome::Replayed(_)));
    for path in ["src/missing", "SRC", "src/", ""] {
        f.request.scope_paths = vec![".".into(), path.into()];
        f.request.request_id = "invalid".into();
        assert!(
            matches!(
                prepare_source_view(&f.context(), &f.request),
                Err(AppError::InvalidRequest(_))
            ),
            "{path}"
        );
        assert!(
            f.storage
                .source_view_receipt(&f.request.case_id, "invalid")
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn receipt_reader_checks_acknowledgement_and_grant_digests_independently() {
    for field in ["acknowledgement_sha256", "grant_sha256"] {
        let f = Fixture::new();
        let receipt = committed(f.prepare());
        let mut value = json!(receipt);
        value[field] = json!("0".repeat(64));
        let mut changed: SourceViewPreparationReceipt = serde_json::from_value(value).unwrap();
        // Recompute the enclosing digest so this pins the inner digest checks.
        changed.digest = changed.content_digest().unwrap();
        rusqlite::Connection::open(f.data.join("casework.db"))
            .unwrap()
            .execute(
                "UPDATE case_events SET payload_json=?1 WHERE event_type=?2",
                rusqlite::params![serde_json::to_string(&changed).unwrap(), RECEIPT_EVENT],
            )
            .unwrap();
        assert!(
            f.storage
                .source_view_receipt(&f.request.case_id, &f.request.request_id)
                .is_err()
        );
    }
}

#[test]
fn real_git_snapshot_prepares_only_ordinary_selected_source() {
    use std::process::Command;
    let mut f = Fixture::with_source(|source| {
        let status = Command::new("git")
            .args(["init", "--quiet"])
            .arg(source)
            .status()
            .expect("Git is required by repository snapshot tests");
        assert!(status.success());
        fs::create_dir(source.join("src")).unwrap();
        fs::write(source.join(".gitignore"), b"src/ignored.txt\nsrc/.env\n").unwrap();
        fs::write(source.join("src/.env"), b"SYNTHETIC_ONLY=yes\n").unwrap();
        fs::write(source.join("src/ignored.txt"), b"generated\0binary").unwrap();
        fs::write(
            source.join("src/private.txt"),
            b"-----BEGIN PRIVATE KEY-----\nOBVIOUSLY_FAKE\n",
        )
        .unwrap();
        fs::write(source.join("src/ordinary.rs"), b"fn ordinary() {}\n").unwrap();
        let status = Command::new("git")
            .arg("-C")
            .arg(source)
            .args(["add", "--force", "--", ".gitignore", "src/.env"])
            .status()
            .unwrap();
        assert!(status.success());
    });
    f.request.scope_paths = vec!["src".into()];
    let receipt = committed(f.prepare());
    let path = f.path(&receipt);
    let view: ViewManifest =
        serde_json::from_slice(&fs::read(path.join("view.json")).unwrap()).unwrap();
    assert_eq!(view.source.files.len(), 1);
    assert_eq!(view.source.files[0].path, "src/ordinary.rs");
    let exclusions = view
        .exclusions
        .iter()
        .map(|e| (e.path.as_str(), e.reason))
        .collect::<BTreeMap<_, _>>();
    for (path, reason) in [
        (".git", ExclusionReason::CanonicalGitMetadata),
        (".gitignore", ExclusionReason::OutsideScope),
        ("src/.env", ExclusionReason::SensitiveName),
        ("src/private.txt", ExclusionReason::PrivateKeyMarker),
        (
            "src/ignored.txt",
            if cfg!(unix) {
                ExclusionReason::CanonicalRepositoryGitignoreUntracked
            } else {
                ExclusionReason::BinaryControlBytes
            },
        ),
    ] {
        assert_eq!(exclusions[path], reason, "{path}");
    }
    let canonical: WorkspaceSnapshotManifest =
        serde_json::from_slice(&fs::read(path.join("canonical-manifest.json")).unwrap()).unwrap();
    for file in canonical.files {
        assert_eq!(
            view.source
                .files
                .iter()
                .filter(|f| f.path == file.relative_path)
                .count()
                + view
                    .exclusions
                    .iter()
                    .filter(|e| e.path == file.relative_path
                        || (e.covers_subtree && policy::beneath(&file.relative_path, &e.path)))
                    .count(),
            1
        );
    }
}

#[tokio::test]
async fn actually_prepared_view_keeps_reported_bundle_untrusted() {
    fn copy_tree(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &to.join(entry.file_name()));
            } else {
                fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
            }
        }
    }
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/cloudflare");
    let f = Fixture::with_source(|source| copy_tree(&fixtures.join("source-view"), source));
    let receipt = committed(f.prepare());
    let path = f.path(&receipt);
    let view: ViewManifest =
        serde_json::from_slice(&fs::read(path.join("view.json")).unwrap()).unwrap();
    let bundle = f.data.join("reported-bundle");
    copy_tree(&fixtures.join("bundle"), &bundle);
    let manifest_path = bundle.join("provider-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    // Same source bytes as the bundle fixture, but all product identities are real.
    assert_eq!(manifest["source"]["view_sha256"], view.source.view_sha256);
    manifest["source"] = json!(view.source);
    let metadata_path = bundle.join("run-metadata.json");
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(&metadata_path).unwrap()).unwrap();
    metadata["source_ref"] = json!(view.source.source_ref);
    let bytes = serde_json::to_vec(&metadata).unwrap();
    fs::write(metadata_path, &bytes).unwrap();
    let entry = manifest["files"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e["path"] == "run-metadata.json")
        .unwrap();
    entry["sha256"] = json!(digest(&bytes));
    entry["byte_length"] = json!(bytes.len());
    fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let validation =
        crate::cloudflare_provider::bundle::validate_bundle(&bundle, &path.join("tree"))
            .await
            .unwrap();
    let validation = json!(validation);
    assert_eq!(validation["provenance"], "reported_only");
    for flag in [
        "canonical_snapshot_binding_verified",
        "source_authorization_verified",
        "audit_performed",
        "admission_ready",
    ] {
        assert_eq!(validation[flag], false, "{flag}");
    }
}

#[test]
fn cancellation_before_publication_removes_staging_without_receipt() {
    let f = Fixture::new();
    let signal = std::sync::atomic::AtomicU8::new(0);
    let calls = std::cell::Cell::new(0);
    let clock = || {
        calls.set(calls.get() + 1);
        if calls.get() == 2 {
            signal.store(130, std::sync::atomic::Ordering::Release);
        }
        Utc::now()
    };
    let mut context = f.context();
    context.cancelled = Some(&signal);
    assert!(matches!(
        prepare_with_clock(&context, &f.request, &clock).unwrap(),
        PreparationOutcome::Interrupted
    ));
    assert!(
        f.storage
            .source_view_receipt(&f.request.case_id, &f.request.request_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fs::read_dir(
            f.data
                .join("artifacts")
                .join(&f.request.case_id)
                .join("source-views")
        )
        .unwrap()
        .count(),
        0
    );
}

#[test]
fn expiry_after_set_aside_never_publishes_or_records_ready() {
    let mut f = Fixture::new();
    let first = committed(f.prepare());
    let path = f.path(&first);
    crate::workspace_snapshot::make_tree_deletable(&path);
    fs::write(path.join("tree/src/safe"), b"damaged").unwrap();
    f.request.request_id = "expired-replacement".into();
    let now = Utc::now();
    f.change(|case| case.scope_grants[0].expires_at = Some(now + chrono::Duration::seconds(10)));
    let clock = || {
        let set_aside = fs::read_dir(path.parent().unwrap()).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".source-view-damaged-")
        });
        if set_aside {
            now + chrono::Duration::seconds(11)
        } else {
            now
        }
    };
    let receipt = committed(prepare_with_clock(&f.context(), &f.request, &clock).unwrap());
    assert_eq!(blocker(&receipt), BlockerCode::SourceAuthorizationExpired);
    let PreparationResult::Blocked { blockers } = receipt.result else {
        unreachable!()
    };
    assert_eq!(blockers[0].stage, "publication");
    assert!(!path.exists());
    let entries = fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        fs::read(entries[0].join("tree/src/safe")).unwrap(),
        b"damaged"
    );
}

#[test]
fn cloudflare_audit_authorization_lapses_at_transaction_clock() {
    use crate::cloudflare_provider::audit;
    let f = Fixture::new();
    let now = Utc::now();
    f.change(|c| c.scope_grants[0].expires_at = Some(now + chrono::Duration::hours(1)));
    let view = committed(f.prepare());
    let host = f.data.parent().unwrap().join("host");
    fs::create_dir(&host).unwrap();
    let request: audit::PrepareRequest = serde_json::from_value(json!({
        "schema_version":audit::REQUEST_SCHEMA,"request_id":"audit", "case_id":f.request.case_id,
        "asset_id":f.request.asset_id,"source_view_request_id":view.request_id,
        "expected_source_view_receipt_sha256":view.digest,"profile":"quick","invocation_budget":null,
        "host":{"host_id":"declared","delegation":"available"},"run_directory":host
    })).unwrap();
    let calls = std::cell::Cell::new(0);
    let result = audit::prepare::prepare_with_clock(&f.context(), &request, &|| {
        let n = calls.get();
        calls.set(n + 1);
        if n == 0 {
            now
        } else {
            now + chrono::Duration::hours(2)
        }
    })
    .unwrap();
    let audit::PreparationOutcome::Saved { receipt, .. } = result else {
        panic!("not committed")
    };
    assert_eq!(calls.get(), 2);
    assert!(receipt.session_id().is_none());
    let audit::PreparationResult::Blocked { blockers, .. } = receipt.result else {
        panic!("prepared after expiry")
    };
    assert_eq!(
        blockers[0].code,
        audit::BlockerCode::SourceAuthorizationExpired
    );
    assert_eq!(blockers[0].stage, "commit");
    assert!(
        !f.data
            .join("artifacts")
            .join(&f.request.case_id)
            .join("cloudflare-sessions")
            .exists()
    );
}

#[test]
fn cloudflare_audit_replay_rechecks_authority_after_inspection() {
    use crate::cloudflare_provider::audit;
    let f = Fixture::new();
    let now = Utc::now();
    f.change(|c| c.scope_grants[0].expires_at = Some(now + chrono::Duration::hours(1)));
    let view = committed(f.prepare());
    let host = f.data.parent().unwrap().join("host");
    fs::create_dir(&host).unwrap();
    let request: audit::PrepareRequest = serde_json::from_value(json!({
        "schema_version":audit::REQUEST_SCHEMA,"request_id":"audit", "case_id":f.request.case_id,
        "asset_id":f.request.asset_id,"source_view_request_id":view.request_id,
        "expected_source_view_receipt_sha256":view.digest,"profile":"quick","invocation_budget":null,
        "host":{"host_id":"declared","delegation":"available"},"run_directory":host
    })).unwrap();
    let audit::PreparationOutcome::Saved { receipt, .. } =
        audit::prepare::prepare_with_clock(&f.context(), &request, &|| now).unwrap()
    else {
        panic!("not prepared")
    };
    let path = f
        .data
        .join("artifacts")
        .join(&f.request.case_id)
        .join("cloudflare-sessions")
        .join(receipt.session_id().unwrap())
        .join("session.json");
    fs::remove_file(&path).unwrap();
    let calls = std::cell::Cell::new(0);
    let outcome = audit::prepare::prepare_with_clock(&f.context(), &request, &|| {
        let n = calls.get();
        calls.set(n + 1);
        if n == 0 {
            now
        } else {
            now + chrono::Duration::hours(2)
        }
    })
    .unwrap();
    assert!(matches!(
        outcome,
        audit::PreparationOutcome::SavedNotCurrent(audit::BlockerCode::SourceAuthorizationExpired)
    ));
    assert!(!path.exists());
    assert_eq!(
        f.storage
            .cloudflare_audit_receipt(&f.request.case_id, "audit", false)
            .unwrap()
            .unwrap()
            .receipt_sha256,
        receipt.receipt_sha256
    );
}

#[test]
fn cloudflare_checkpoint_authority_expires_immediately_before_insert_and_on_replay() {
    use crate::cloudflare_provider::audit::{self, record::*};
    let f = Fixture::new();
    let now = Utc::now();
    f.change(|c| c.scope_grants[0].expires_at = Some(now + chrono::Duration::hours(1)));
    let view = committed(f.prepare());
    let host = f.data.parent().unwrap().join("host");
    fs::create_dir(&host).unwrap();
    let request: audit::PrepareRequest = serde_json::from_value(json!({
        "schema_version":audit::REQUEST_SCHEMA,"request_id":"audit", "case_id":f.request.case_id,
        "asset_id":f.request.asset_id,"source_view_request_id":view.request_id,
        "expected_source_view_receipt_sha256":view.digest,"profile":"quick","invocation_budget":null,
        "host":{"host_id":"declared","delegation":"available"},"run_directory":host
    })).unwrap();
    let audit::PreparationOutcome::Saved { receipt, .. } =
        audit::prepare::prepare_with_clock(&f.context(), &request, &|| now).unwrap()
    else {
        panic!()
    };
    let request: CheckpointRequest = serde_json::from_value(json!({"schema_version":CHECKPOINT_SCHEMA,
        "request_id":"issue","case_id":receipt.case_id,"session_id":receipt.session_id(),
        "expected_head_sha256":receipt.receipt_sha256,"action":{"type":"issue","assignments":[{"role":"reconnaissance_baseline"}]}
    })).unwrap();
    let observer = rusqlite::Connection::open(f.storage.path()).unwrap();
    observer.busy_timeout(std::time::Duration::ZERO).unwrap();
    let calls = std::cell::Cell::new(0);
    let outcome = audit::checkpoint::checkpoint_with_clock(&f.context(), &request, &|| {
        let call = calls.get();
        calls.set(call + 1);
        if call >= 2 {
            assert_eq!(
                observer
                    .execute_batch("BEGIN IMMEDIATE")
                    .unwrap_err()
                    .sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy)
            );
        }
        if call >= 5 {
            now + chrono::Duration::hours(2)
        } else {
            now
        }
    })
    .unwrap();
    assert!(matches!(
        outcome,
        CheckpointOutcome::Rejected {
            error_code: Refusal::SavedReceiptNotCurrent,
            reason: Some(audit::BlockerCode::SourceAuthorizationExpired)
        }
    ));
    assert!(
        f.storage
            .cloudflare_audit_record(&receipt)
            .unwrap()
            .entries
            .is_empty()
    );
    assert_eq!(
        f.storage
            .get_case(&receipt.case_id)
            .unwrap()
            .storage_revision,
        receipt.case_revision
    );
    let saved = audit::checkpoint::checkpoint_with_clock(&f.context(), &request, &|| now).unwrap();
    assert!(matches!(
        saved,
        CheckpointOutcome::Saved {
            replayed: false,
            ..
        }
    ));
    let outcome = audit::checkpoint::checkpoint_with_clock(&f.context(), &request, &|| {
        now + chrono::Duration::hours(2)
    })
    .unwrap();
    assert!(matches!(
        outcome,
        CheckpointOutcome::Rejected {
            error_code: Refusal::SavedReceiptNotCurrent,
            ..
        }
    ));
    assert_eq!(
        f.storage
            .cloudflare_audit_record(&receipt)
            .unwrap()
            .entries
            .len(),
        1
    );
    // Cancellation before the transaction records nothing; a retry can reuse published objects.
    let mut documents = request.clone();
    documents.request_id = "cancelled-documents".into();
    documents.expected_head_sha256 = f
        .storage
        .cloudflare_audit_record(&receipt)
        .unwrap()
        .head(&receipt)
        .1
        .into();
    documents.action = Action::SubmitDocuments {
        documents: vec![audit::documents::DocumentSpec {
            name: "REPORT.md".into(),
            sha256: None,
            byte_length: None,
        }],
    };
    fs::write(host.join("REPORT.md"), b"synthetic report").unwrap();
    let stopped = std::sync::atomic::AtomicU8::new(130);
    let mut context = f.context();
    context.cancelled = Some(&stopped);
    assert!(matches!(
        audit::checkpoint(&context, &documents).unwrap(),
        CheckpointOutcome::Interrupted
    ));
    assert_eq!(
        f.storage
            .cloudflare_audit_record(&receipt)
            .unwrap()
            .entries
            .len(),
        1
    );
    assert!(matches!(
        audit::checkpoint(&f.context(), &documents).unwrap(),
        CheckpointOutcome::Saved {
            replayed: false,
            ..
        }
    ));
}

#[cfg(unix)]
#[test]
fn interrupted_root_seal_is_refused_and_republished() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let first = committed(f.prepare());
    let path = f.path(&first);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let case = f.storage.get_case(&f.request.case_id).unwrap();
    assert!(
        super::currency::current_view(&f.data, &case, &first, Utc::now())
            .unwrap()
            .is_err()
    );
    let PreparationOutcome::Replayed(replay) = f.prepare() else {
        panic!("not replayed")
    };
    assert_eq!(json!(first), json!(replay));
    crate::case_archive_io::require_sealed_directory_root(&path).unwrap();
    inspect_source_view(&path, None, None).unwrap();
}
