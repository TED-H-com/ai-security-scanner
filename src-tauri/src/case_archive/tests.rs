use super::*;
use crate::domain::OrganizationProfile;

struct Fixture {
    _directory: tempfile::TempDir,
    archive: PathBuf,
    restore_parent: PathBuf,
    destination: PathBuf,
    case: AssessmentCase,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        transport::make_private(directory.path(), true).unwrap();
        let source = directory.path().join("source");
        fs::create_dir(&source).unwrap();
        let mut case = AssessmentCase::new(
            "Synthetic archive interruption fixture".into(),
            OrganizationProfile {
                organization_name: "Archive test organization".into(),
                employee_range: "1-10".into(),
                data_classes: Vec::new(),
                notes: None,
            },
        );
        let storage = Storage::open(source.join("casework.db")).unwrap();
        storage.save_case(&mut case, "fixture.created").unwrap();
        case.profile.notes = Some("Retained without scanning or network access".into());
        storage.save_case(&mut case, "fixture.updated").unwrap();
        drop(storage);
        assert_eq!(case.storage_revision, 2);

        let archive = directory.path().join("case.tar.gz");
        create_archive(&source, &case.id, &archive, &ArchiveOptions::default()).unwrap();
        // Restoring and retrying must depend only on the saved package.
        fs::remove_dir_all(source).unwrap();
        let restore_parent = directory.path().join("restores");
        fs::create_dir(&restore_parent).unwrap();
        transport::make_private(&restore_parent, true).unwrap();
        let destination = restore_parent.join("restored");
        Self {
            _directory: directory,
            archive,
            restore_parent,
            destination,
            case,
        }
    }

    fn assert_no_staging_leftovers(&self, published: bool) {
        let children: BTreeSet<_> = fs::read_dir(&self.restore_parent)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let expected = if published {
            BTreeSet::from([self.destination.file_name().unwrap().to_owned()])
        } else {
            BTreeSet::new()
        };
        assert_eq!(
            children, expected,
            "restore left a private staging directory"
        );
    }

    fn saved_receipt(&self) -> RestoreReceipt {
        serde_json::from_slice(&fs::read(self.destination.join(RECEIPT_FILE)).unwrap()).unwrap()
    }

    fn assert_complete_destination(&self, receipt: &RestoreReceipt) {
        assert_eq!(receipt.case_id, self.case.id);
        assert_eq!(receipt.source_case_revision, 2);
        assert_eq!(receipt.local_case_revision, 1);
        assert!(!receipt.restores_scan_authority);
        assert_eq!(
            receipt.destination,
            fs::canonicalize(&self.destination).unwrap()
        );
        let verified = transport::read_archive(&self.archive).unwrap();
        assert_eq!(receipt.archive_id, verified.manifest.archive_id);
        assert_eq!(receipt.archive_sha256, verified.archive_sha256);
        assert_eq!(receipt.files.len(), verified.manifest.entries.len() + 1);
        for entry in &verified.manifest.entries {
            let actual = fs::read(self.destination.join(&entry.path)).unwrap();
            assert_eq!(
                actual,
                fs::read(verified.entry_path(&entry.path).unwrap()).unwrap()
            );
            assert_eq!(receipt.files.get(&entry.path), Some(&digest(&actual)));
        }
        let database = fs::read(self.destination.join("casework.db")).unwrap();
        assert!(!database.is_empty());
        assert_eq!(receipt.files.get("casework.db"), Some(&digest(&database)));
        assert!(self.destination.join("restore-intent.json").is_file());
        self.assert_no_staging_leftovers(true);
    }

    fn assert_database_reopens(&self) {
        let storage = Storage::open_read_only(self.destination.join("casework.db")).unwrap();
        let case = storage.get_case(&self.case.id).unwrap();
        assert_eq!(case.storage_revision, 1);
        assert_eq!(case.title, self.case.title);
        assert_eq!(case.profile.notes, self.case.profile.notes);
        assert!(case.scope_grants.is_empty());
        assert!(case.scan_runs.is_empty());
    }
}

// Compare observable bytes independently of the restore receipt's inventory.
fn workspace_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                pending.push(entry.path());
            } else {
                assert!(metadata.is_file());
                files.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    files
}

#[test]
fn failure_before_publish_removes_staging_and_retry_restores_complete_workspace() {
    let fixture = Fixture::new();
    let error = restore_impl(
        &fixture.archive,
        &fixture.destination,
        RestoreFault::BeforePublish,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected failure before publish")
    );
    assert!(!fixture.destination.exists());
    fixture.assert_no_staging_leftovers(false);

    let receipt = restore_archive(&fixture.archive, &fixture.destination).unwrap();
    fixture.assert_complete_destination(&receipt);
    assert_eq!(
        serde_json::to_value(&receipt).unwrap(),
        serde_json::to_value(fixture.saved_receipt()).unwrap()
    );
    fixture.assert_database_reopens();
}

#[test]
fn failure_after_publish_preserves_complete_workspace_and_exact_retry_receipt() {
    let fixture = Fixture::new();
    let error = restore_impl(
        &fixture.archive,
        &fixture.destination,
        RestoreFault::AfterPublish,
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected failure after publish"));
    let published_receipt = fixture.saved_receipt();
    fixture.assert_complete_destination(&published_receipt);
    let published_bytes = workspace_bytes(&fixture.destination);

    let retried_receipt = restore_archive(&fixture.archive, &fixture.destination).unwrap();
    assert_eq!(
        serde_json::to_value(&retried_receipt).unwrap(),
        serde_json::to_value(&published_receipt).unwrap(),
        "retry must retain the original workspace identity and restore time"
    );
    assert_eq!(workspace_bytes(&fixture.destination), published_bytes);
    fixture.assert_no_staging_leftovers(true);
    fixture.assert_database_reopens();
}

#[test]
fn modified_restore_intent_rejects_retry_without_repairing_or_overwriting_workspace() {
    let fixture = Fixture::new();
    restore_impl(
        &fixture.archive,
        &fixture.destination,
        RestoreFault::AfterPublish,
    )
    .unwrap_err();
    let receipt = fixture.saved_receipt();
    let intent_path = fixture.destination.join("restore-intent.json");
    let original_intent: serde_json::Value =
        serde_json::from_slice(&fs::read(&intent_path).unwrap()).unwrap();

    for (field, replacement) in [
        ("workspace_id", serde_json::json!("different-workspace")),
        ("archive_sha256", serde_json::json!("0".repeat(64))),
        ("destination", serde_json::json!("different-destination")),
        ("state", serde_json::json!("not-ready")),
    ] {
        let mut intent = original_intent.clone();
        intent[field] = replacement;
        fs::write(&intent_path, serde_json::to_vec(&intent).unwrap()).unwrap();
        let modified_bytes = workspace_bytes(&fixture.destination);

        let error = restore_archive(&fixture.archive, &fixture.destination).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("restore intent does not match its receipt"),
            "modified {field} was not rejected as an inconsistent intent: {error}"
        );
        assert_eq!(workspace_bytes(&fixture.destination), modified_bytes);
        assert_eq!(
            serde_json::to_value(fixture.saved_receipt()).unwrap(),
            serde_json::to_value(&receipt).unwrap()
        );
        fixture.assert_no_staging_leftovers(true);
    }
}

#[test]
fn staging_budget_refuses_excess_before_creating_payload_or_parent_directories() {
    let mut builder = Builder::new().unwrap();
    builder.add("retained.json", b"existing payload").unwrap();
    let maximum = transport::MAX_ARCHIVE_DECOMPRESSED_BYTES;
    let payload = b"fits exactly";
    let cost = payload.len() as u64 + 6 * 1024;
    // Simulate the boundary without creating a multi-gigabyte fixture.
    builder.staged_bytes = maximum - cost;
    builder.add("at-limit/payload.json", payload).unwrap();
    assert_eq!(builder.staged_bytes, maximum);
    let before = workspace_bytes(builder.directory.path());
    let files_before = builder.files.clone();
    let entries_before = serde_json::to_value(&builder.entries).unwrap();

    let error = builder.add("excess/nested/payload.json", b"x").unwrap_err();
    assert!(error.to_string().contains("bounded staging budget"));
    assert!(!builder.directory.path().join("excess").exists());
    assert_eq!(workspace_bytes(builder.directory.path()), before);
    assert_eq!(builder.files, files_before);
    assert_eq!(
        serde_json::to_value(&builder.entries).unwrap(),
        entries_before
    );
    assert_eq!(builder.staged_bytes, maximum);

    // An identical retained reference needs no additional staged bytes.
    builder.add("at-limit/payload.json", payload).unwrap();
    assert_eq!(builder.staged_bytes, maximum);
    assert_eq!(workspace_bytes(builder.directory.path()), before);
}

thread_local! { static LEGACY_PIN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
const PIN_TIME: &str = "2026-11-11T00:00:00Z";

pub(super) fn fixed_manifest(mut manifest: ArchiveManifest) -> ArchiveManifest {
    if LEGACY_PIN.get() {
        manifest.archive_id = "legacy-pin-archive".into();
        manifest.created_at = PIN_TIME.parse().unwrap();
        manifest.producer_version = "fixed-test-version".into();
    }
    manifest
}
pub(super) fn fixed_report(report: ReportSnapshot) -> ReportSnapshot {
    if !LEGACY_PIN.get() {
        return report;
    }
    let mut value = serde_json::to_value(report).unwrap();
    value["snapshot_id"] = format!("fixed-{}", value["run_id"].as_str().unwrap()).into();
    value["created_at"] = PIN_TIME.into();
    value["renderer"]["source_sha256"] = "0".repeat(64).into();
    value["renderer"]["product_version"] = "fixed-test-version".into();
    serde_json::from_value(value).unwrap()
}

#[test]
fn legacy_archive_fixed_bytes() {
    let _version = crate::product_version::pin("0.6.0");
    // Normalize synthetic UUIDs and times before saving; never normalize the archive.
    fn normalize(value: &mut serde_json::Value, ids: &mut BTreeMap<String, String>) {
        match value {
            serde_json::Value::Object(map) => {
                for v in map.values_mut() {
                    normalize(v, ids);
                }
            }
            serde_json::Value::Array(items) => {
                for v in items {
                    normalize(v, ids);
                }
            }
            serde_json::Value::String(s) => {
                if s.len() == 36 && uuid::Uuid::parse_str(s).is_ok() {
                    let next = format!("fixture-id-{}", ids.len());
                    *s = ids.entry(s.clone()).or_insert(next).clone();
                } else if DateTime::parse_from_rfc3339(s).is_ok() {
                    *s = PIN_TIME.into();
                }
            }
            _ => {}
        }
    }
    let directory = tempfile::tempdir().unwrap();
    transport::make_private(directory.path(), true).unwrap();
    let data = directory.path().join("data");
    let mut value = serde_json::to_value(crate::demo::build_demo_case()).unwrap();
    normalize(&mut value, &mut BTreeMap::new());
    let mut case: AssessmentCase = serde_json::from_value(value).unwrap();
    for raw in &mut case.raw_artifacts {
        raw.relative_path = format!(
            "{}/{}/{}/{}.json",
            case.id, raw.run_id, raw.engine_run_id, raw.id
        );
        let bytes = b"synthetic raw evidence";
        raw.sha256 = digest(bytes);
        raw.byte_length = bytes.len() as u64;
        let path = data.join("artifacts").join(&raw.relative_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    for finding in &mut case.findings {
        for evidence in &mut finding.evidence {
            evidence.artifact_sha256 = digest(b"synthetic raw evidence");
        }
    }
    for observation in &mut case.finding_observations {
        observation.evidence_hashes =
            vec![digest(b"synthetic raw evidence"); observation.evidence_hashes.len()];
        if let Some(finding) = &mut observation.finding_snapshot {
            for evidence in &mut finding.evidence {
                evidence.artifact_sha256 = digest(b"synthetic raw evidence");
            }
        }
    }
    let storage = Storage::open(data.join("casework.db")).unwrap();
    storage.save_case(&mut case, "fixture.created").unwrap();
    case.created_at = PIN_TIME.parse().unwrap();
    case.updated_at = PIN_TIME.parse().unwrap();
    let db = rusqlite::Connection::open(data.join("casework.db")).unwrap();
    db.execute(
        "UPDATE cases SET document_json = ?1",
        [serde_json::to_string(&case).unwrap()],
    )
    .unwrap();
    db.execute(
        "UPDATE case_events SET occurred_at = ?1, event_type = ?2, payload_json = ?3",
        [
            PIN_TIME,
            crate::cloudflare_provider::audit::RECEIPT_EVENT,
            r#"{"synthetic_preparation":true}"#,
        ],
    )
    .unwrap();
    LEGACY_PIN.set(true);
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            LEGACY_PIN.set(false);
        }
    }
    let _reset = Reset;
    let archive = directory.path().join("legacy.tar.gz");
    create_archive(&data, &case.id, &archive, &ArchiveOptions::default()).unwrap();
    let inspected = inspect_archive(&archive).unwrap();
    assert!(inspected.raw_artifact_count > 0);
    assert!(inspected.report_snapshot_count > 0);
    assert!(
        inspected
            .omissions
            .iter()
            .any(|s| s.starts_with("Cloudflare audit records are not included"))
    );
    assert_eq!(
        hash_file(&archive).unwrap(),
        "3af717bdfe35a3515315f326ebf466b86a607380b3a7412da67d0c1a626fb4a0"
    );
}

#[test]
fn staged_byte_mismatch_publishes_nothing_and_retry_succeeds() {
    let fixture = Fixture::new();
    let error = restore_impl(
        &fixture.archive,
        &fixture.destination,
        RestoreFault::StagedMismatch,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        AppError::ArchiveProvider {
            code: "archive_content_mismatch",
            ..
        }
    ));
    assert!(!fixture.destination.exists());
    fixture.assert_no_staging_leftovers(false);
    let receipt = restore_archive(&fixture.archive, &fixture.destination).unwrap();
    fixture.assert_complete_destination(&receipt);
}
