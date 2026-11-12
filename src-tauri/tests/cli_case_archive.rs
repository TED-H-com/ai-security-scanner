#![cfg(feature = "cli")]

#[allow(dead_code)]
#[path = "../src/test_temp.rs"]
mod test_temp;

use ai_security_scanner_lib::adapters::builtin_adapter_registry;
use ai_security_scanner_lib::case_service::CaseService;
use ai_security_scanner_lib::connectors::SnapshotArtifactReference;
use ai_security_scanner_lib::demo::build_demo_case;
use ai_security_scanner_lib::domain::{
    AssessmentCase, CaseExport, EngineRunStatus, FindingStatus, FindingWorkflowEvent,
    InventoryObservation, InventoryObservationKind, ReportAssetDisposition, ReportAssetSnapshot,
    SourceConnectionStatus,
};
use ai_security_scanner_lib::process_lease::DataDirectoryExclusiveLease;
use ai_security_scanner_lib::registry::EngineRegistry;
use ai_security_scanner_lib::storage::{CaseEvent, Storage};
use ai_security_scanner_lib::workspace_snapshot::{
    WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY, WorkspaceSnapshotLimits, WorkspaceSnapshotReference,
    create_workspace_snapshot, inspect_workspace_snapshot,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use flate2::{Compression, GzBuilder, read::GzDecoder};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SOURCE_BYTES: &[u8] = b"// Synthetic preserved source; no scanner executes this file.\n";
const EXPORT_BYTES: &[u8] = b"<!doctype html><p>Synthetic historical export</p>\n";
const COVERAGE_BYTES: &[u8] = b"{\"synthetic\":true,\"coverage\":\"partial\"}\n";

struct Fixture {
    data_dir: PathBuf,
    selected_source: PathBuf,
    case: AssessmentCase,
    document_json: String,
    events: Vec<CaseEvent>,
    revision: i64,
    raw_files: BTreeMap<String, Vec<u8>>,
    source_reference: WorkspaceSnapshotReference,
}

fn test_directory() -> test_temp::TempDir {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    builder.tempdir().map(test_temp::TempDir::from).unwrap()
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn fixture(root: &Path) -> Fixture {
    let data_dir = root.join("original-data");
    let artifact_root = data_dir.join("artifacts");
    let selected_source = root.join("selected-source");
    fs::create_dir_all(&artifact_root).unwrap();
    fs::create_dir_all(selected_source.join("empty-directory")).unwrap();
    fs::write(selected_source.join("source.rs"), SOURCE_BYTES).unwrap();

    // The demo supplies a nontrivial graph with partial coverage, frozen
    // findings, groups and grants. Replace its metadata-only raw artifacts
    // with actual synthetic files and update every evidence hash binding.
    let mut case = build_demo_case();
    case.is_demo = false;
    case.title = "Archive integration fixture: synthetic evidence".into();
    let mut raw_files = BTreeMap::new();
    for artifact in &mut case.raw_artifacts {
        let bytes = serde_json::to_vec(&json!({
            "synthetic": true,
            "check": "preserved-fixture-check",
            "status": "INCOMPLETE",
            "artifact_id": artifact.id,
        }))
        .unwrap();
        artifact.relative_path = format!(
            "{}/{}/{}/{}.json",
            case.id, artifact.run_id, artifact.engine_run_id, artifact.id
        );
        artifact.sha256 = digest(&bytes);
        artifact.byte_length = bytes.len() as u64;
        let path = artifact_root.join(&artifact.relative_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, &bytes).unwrap();
        raw_files.insert(artifact.relative_path.clone(), bytes);
    }
    for finding in &mut case.findings {
        for evidence in &mut finding.evidence {
            evidence.artifact_sha256 = case
                .raw_artifacts
                .iter()
                .find(|artifact| artifact.id == evidence.artifact_id)
                .unwrap()
                .sha256
                .clone();
        }
    }
    for observation in &mut case.finding_observations {
        let finding = case
            .findings
            .iter()
            .find(|finding| finding.id == observation.finding_id)
            .unwrap();
        observation.evidence_hashes = finding
            .evidence
            .iter()
            .map(|evidence| evidence.artifact_sha256.clone())
            .collect();
        observation.finding_snapshot = Some(finding.clone());
    }
    let run = &case.scan_runs[0];
    let task = &run.engine_runs[0];
    let artifact = case
        .raw_artifacts
        .iter()
        .find(|artifact| artifact.engine_run_id == task.id)
        .unwrap();
    case.inventory_observations.push(InventoryObservation {
        id: "fixture-inventory".into(),
        case_id: case.id.clone(),
        run_id: run.id.clone(),
        engine_run_id: task.id.clone(),
        asset_id: task.asset_ids[0].clone(),
        engine_id: task.engine_id.clone(),
        kind: InventoryObservationKind::CloudResource {
            resource_type: "synthetic-storage".into(),
            native_id: Some("fixture-resource".into()),
            display_name: Some("Preserved inventory".into()),
        },
        artifact_id: artifact.id.clone(),
        artifact_sha256: artifact.sha256.clone(),
        pointer: "/check".into(),
        observed_at: artifact.created_at,
    });
    let storage = Storage::open(data_dir.join("casework.db")).unwrap();
    storage.save_case(&mut case, "fixture.created").unwrap();
    let snapshot = create_workspace_snapshot(
        &artifact_root,
        &case.id,
        "fixture-workspace-source",
        &selected_source,
        WorkspaceSnapshotLimits::default(),
    )
    .unwrap();
    let source_reference = snapshot.reference.clone();
    let engines = EngineRegistry::load_builtin().unwrap();
    let adapters = builtin_adapter_registry().unwrap();
    let service = CaseService::new(
        &storage,
        &engines,
        &adapters,
        &artifact_root,
        data_dir.join("integrity-signing-key"),
    );
    case = service
        .attach_workspace_snapshot(&case.id, "Synthetic retained source", snapshot)
        .unwrap();

    // Live authority/path context must become inert on restore, while the
    // original portable document and unrelated source metadata survive.
    case.data_sources[0]
        .metadata
        .insert("path".into(), json!(selected_source));
    case.data_sources[0]
        .metadata
        .insert("provider_profile".into(), json!("synthetic-profile"));
    case.data_sources[0]
        .metadata
        .insert("historical_note".into(), json!("Keep this source detail"));
    case.assets[0]
        .metadata
        .insert("path".into(), json!(selected_source));
    case.assets[0]
        .metadata
        .insert("historical_note".into(), json!("Keep this asset detail"));

    let finding = &mut case.findings[0];
    let from_status = finding.status.clone();
    finding.status = FindingStatus::Confirmed;
    case.finding_workflow_events.push(FindingWorkflowEvent {
        id: "fixture-triage-event".into(),
        case_id: case.id.clone(),
        finding_id: finding.id.clone(),
        from_status,
        to_status: FindingStatus::Confirmed,
        decided_by: "synthetic-reviewer".into(),
        decided_at: chrono::Utc::now(),
        reason: "Retain human review separately from frozen scanner evidence".into(),
        expires_at: None,
    });
    let export_path = data_dir.join("historical.html");
    let coverage_path = data_dir.join("historical.coverage.json");
    fs::write(&export_path, EXPORT_BYTES).unwrap();
    fs::write(&coverage_path, COVERAGE_BYTES).unwrap();
    case.exports.push(CaseExport {
        report_snapshot: None,
        id: "fixture-export".into(),
        case_id: case.id.clone(),
        run_id: case.scan_runs[0].id.clone(),
        created_at: chrono::Utc::now(),
        format: Some("html".into()),
        path: export_path.to_string_lossy().into_owned(),
        sha256: digest(EXPORT_BYTES),
        coverage_manifest_path: Some(coverage_path.to_string_lossy().into_owned()),
        coverage_manifest_sha256: Some(digest(COVERAGE_BYTES)),
        signature: Some("historical-synthetic-signature".into()),
        public_key: Some("historical-synthetic-public-key".into()),
        redaction_profile: "standard".into(),
        raw_artifacts_included: Some(0),
        raw_artifacts_omitted: Some(case.raw_artifacts.len()),
        integrity_only_notice: "Synthetic integrity history; not an authenticity claim".into(),
    });
    storage.save_case(&mut case, "fixture.reviewed").unwrap();
    storage.set_selected_case(Some(&case.id)).unwrap();
    // These synthetic local files represent state that must never be copied.
    fs::write(
        data_dir.join("integrity-signing-key"),
        b"synthetic excluded key",
    )
    .unwrap();
    fs::create_dir(data_dir.join("runtime")).unwrap();
    fs::write(
        data_dir.join("runtime/worker-marker"),
        b"synthetic excluded worker",
    )
    .unwrap();
    let saved = storage.snapshot_case_for_archive(&case.id).unwrap();
    Fixture {
        data_dir,
        selected_source,
        case: saved.case,
        document_json: saved.document_json,
        events: saved.events,
        revision: saved.revision,
        raw_files,
        source_reference,
    }
}

fn cli(data_dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ai-security-scanner-cli"));
    command.arg("--data-dir").arg(data_dir).arg("--json");
    // No external scanner, container runtime, package manager or bootstrap can
    // be resolved by these child processes.
    command.env("PATH", "");
    command
}

fn create(fixture: &Fixture, destination: &Path) -> Command {
    let mut command = cli(&fixture.data_dir);
    command
        .args(["archive", "create", "--case-id", &fixture.case.id])
        .arg("--destination")
        .arg(destination)
        .arg("--acknowledge-sensitive-data");
    command
}

fn archive_command(data_dir: &Path, operation: &str, archive: &Path) -> Command {
    let mut command = cli(data_dir);
    command
        .args(["archive", operation, "--archive"])
        .arg(archive);
    command
}

fn restore(data_dir: &Path, archive: &Path, destination: &Path) -> Output {
    archive_command(data_dir, "restore", archive)
        .arg("--destination")
        .arg(destination)
        .arg("--acknowledge-sensitive-data")
        .output()
        .unwrap()
}

fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).expect("one JSON result")
}

fn failure(output: Output) -> String {
    assert!(!output.status.success(), "unexpected CLI success");
    assert!(
        output.stdout.is_empty(),
        "failure emitted a success receipt"
    );
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(!error.trim().is_empty());
    error
}

fn entries(path: &Path) -> Vec<(String, Vec<u8>)> {
    let mut archive = tar::Archive::new(GzDecoder::new(fs::File::open(path).unwrap()));
    archive
        .entries()
        .unwrap()
        .map(|entry| {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            (path, bytes)
        })
        .collect()
}

fn write_entries(path: &Path, entries: &[(String, Vec<u8>)]) {
    let gzip = GzBuilder::new()
        .mtime(0)
        .write(fs::File::create(path).unwrap(), Compression::default());
    let mut archive = tar::Builder::new(gzip);
    for (name, bytes) in entries {
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o600);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        archive
            .append_data(&mut header, name, bytes.as_slice())
            .unwrap();
    }
    archive.into_inner().unwrap().finish().unwrap();
}

fn assert_preserved_case(original: &AssessmentCase, restored: &AssessmentCase, destination: &Path) {
    let mut expected = original.clone();
    expected.scope_grants.clear();
    for source in &mut expected.data_sources {
        if source.status != SourceConnectionStatus::NotApplicable {
            source.status = SourceConnectionStatus::NotConnected;
        }
        source.connected_at = None;
        for key in [
            "path",
            "provider_profile",
            WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY,
        ] {
            source.metadata.remove(key);
        }
    }
    for asset in &mut expected.assets {
        asset.owner_confirmed = false;
        for key in [
            "path",
            "provider_profile",
            WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY,
        ] {
            asset.metadata.remove(key);
        }
    }
    for run in &mut expected.scan_runs {
        for task in &mut run.engine_runs {
            task.resume_token = None;
        }
    }
    expected.exports[0].path = destination
        .join("exports/0/report.html")
        .to_string_lossy()
        .into_owned();
    expected.exports[0].coverage_manifest_path = Some(
        destination
            .join("exports/0/coverage.json")
            .to_string_lossy()
            .into_owned(),
    );
    assert_eq!(
        serde_json::to_value(restored).unwrap(),
        serde_json::to_value(expected).unwrap(),
        "every persisted field must survive except the explicit authority/path transformations"
    );
}

#[test]
fn archive_round_trip_preserves_case_evidence_sources_and_saved_reports_without_original_workspace()
{
    let directory = test_directory();
    let fixture = fixture(directory.path());
    let report_path = directory.path().join("historical-report.json");
    success(
        cli(&fixture.data_dir)
            .args([
                "report",
                "snapshot",
                "--case-id",
                &fixture.case.id,
                "--run-id",
            ])
            .arg(&fixture.case.scan_runs[0].id)
            .arg("--destination")
            .arg(&report_path)
            .args([
                "--acknowledge-private-context",
                "--locale",
                "en",
                "--redaction",
                "none",
                "--include-raw-artifacts",
                "--acknowledge-sensitive-raw-artifacts",
            ])
            .output()
            .unwrap(),
    );
    let report_bytes = fs::read(&report_path).unwrap();
    let report: Value = serde_json::from_slice(&report_bytes).unwrap();
    let original_html = BASE64
        .decode(report["original_html"]["bytes"].as_str().unwrap())
        .unwrap();
    let archive_path = directory.path().join("complete.archive.tar.gz");
    let created = {
        // A live writer's lease and connection must not block the read-only
        // export path or cause recovery/selection/revision writes.
        let _lease = DataDirectoryExclusiveLease::acquire(&fixture.data_dir).unwrap();
        let writer = Storage::open(fixture.data_dir.join("casework.db")).unwrap();
        let receipt = success(
            create(&fixture, &archive_path)
                .args([
                    "--include-source-snapshots",
                    "--include-export-files",
                    "--report-snapshot",
                ])
                .arg(&report_path)
                .arg("--report-snapshot")
                .arg(&report_path)
                .output()
                .unwrap(),
        );
        let saved = writer.snapshot_case_for_archive(&fixture.case.id).unwrap();
        assert_eq!(saved.revision, fixture.revision);
        assert_eq!(saved.document_json, fixture.document_json);
        assert_eq!(saved.events, fixture.events);
        assert_eq!(
            writer.selected_case_id().unwrap().as_deref(),
            Some(fixture.case.id.as_str())
        );
        receipt
    };
    assert_eq!(created["sha256"], digest(&fs::read(&archive_path).unwrap()));
    assert_eq!(created["case_id"], fixture.case.id);
    let original_entries = entries(&archive_path)
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        original_entries["original-case.json"],
        fixture.document_json.as_bytes()
    );
    let portable: Value = serde_json::from_slice(&original_entries["case.json"]).unwrap();
    assert_eq!(
        portable["case"],
        serde_json::to_value(&fixture.case).unwrap()
    );
    assert_eq!(
        portable["historical_events"],
        serde_json::to_value(&fixture.events).unwrap()
    );

    // Old absolute export paths, raw artifacts and source trees are now gone.
    fs::rename(
        &fixture.data_dir,
        directory.path().join("moved-original-data"),
    )
    .unwrap();
    fs::rename(
        &fixture.selected_source,
        directory.path().join("moved-original-source"),
    )
    .unwrap();
    fs::remove_file(&report_path).unwrap();
    let no_data = directory.path().join("never-initialized").join("data");
    let inspection = success(
        archive_command(&no_data, "verify", &archive_path)
            .output()
            .unwrap(),
    );
    assert_eq!(inspection["integrity_valid"], true);
    assert_eq!(inspection["case_data_restore_available"], true);
    assert_eq!(inspection["restores_scan_authority"], false);
    assert_eq!(inspection["source_snapshots_included"], true);
    assert_eq!(inspection["raw_artifact_count"], fixture.raw_files.len());
    assert_eq!(
        inspection["inventory_count"],
        fixture.case.inventory_observations.len()
    );
    assert!(inspection["report_snapshot_count"].as_u64().unwrap() >= 2);
    let destination = directory.path().join("restored");
    let preview = success(
        archive_command(&no_data, "restore-preview", &archive_path)
            .arg("--destination")
            .arg(&destination)
            .output()
            .unwrap(),
    );
    assert_eq!(preview["destination_available"], true);
    assert!(
        !destination.exists(),
        "preview must not publish a workspace"
    );
    let receipt = success(restore(&no_data, &archive_path, &destination));
    assert_eq!(
        receipt["schema_version"],
        "ai-security-scanner.restore-receipt/v1"
    );
    assert_eq!(receipt["archive_id"], created["archive_id"]);
    assert_eq!(receipt["source_case_revision"], fixture.revision);
    assert_eq!(receipt["local_case_revision"], 1);
    assert_eq!(receipt["restores_scan_authority"], false);
    assert_eq!(
        success(restore(&no_data, &archive_path, &destination)),
        receipt
    );
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(destination.join("restore-receipt.json")).unwrap()
        )
        .unwrap(),
        receipt
    );
    assert!(!no_data.parent().unwrap().exists());
    assert!(!fixture.data_dir.exists());
    for excluded in [
        "integrity-signing-key",
        "runtime",
        ".exclusive-process.lock",
    ] {
        assert!(
            !destination.join(excluded).exists(),
            "must not restore {excluded}"
        );
    }

    let storage = Storage::open_read_only(destination.join("casework.db")).unwrap();
    let saved = storage.snapshot_case_for_archive(&fixture.case.id).unwrap();
    assert_eq!(saved.revision, 1);
    assert_eq!(storage.selected_case_id().unwrap(), None);
    assert_preserved_case(
        &fixture.case,
        &saved.case,
        &fs::canonicalize(&destination).unwrap(),
    );
    assert_eq!(
        &saved.events[..fixture.events.len()],
        fixture.events.as_slice()
    );
    assert_eq!(saved.events.len(), fixture.events.len() + 1);
    let restored_event = saved.events.last().unwrap();
    assert_eq!(restored_event.event_type, "case.restored");
    assert!(restored_event.sequence > fixture.events.last().unwrap().sequence);
    assert_eq!(
        serde_json::from_str::<Value>(&restored_event.payload_json).unwrap()["archive_id"],
        created["archive_id"]
    );
    assert_eq!(
        fs::read(destination.join("original-case.json")).unwrap(),
        fixture.document_json.as_bytes()
    );
    for (name, bytes) in &fixture.raw_files {
        assert_eq!(
            fs::read(destination.join("artifacts").join(name)).unwrap(),
            *bytes
        );
    }
    let retained_source = inspect_workspace_snapshot(
        destination.join("artifacts"),
        &fixture.case.id,
        &fixture.source_reference,
    )
    .unwrap();
    assert_eq!(
        fs::read(retained_source.tree_path.join("source.rs")).unwrap(),
        SOURCE_BYTES
    );
    assert!(retained_source.tree_path.join("empty-directory").is_dir());
    assert_eq!(fs::read(&saved.case.exports[0].path).unwrap(), EXPORT_BYTES);
    assert_eq!(
        fs::read(
            saved.case.exports[0]
                .coverage_manifest_path
                .as_ref()
                .unwrap()
        )
        .unwrap(),
        COVERAGE_BYTES
    );

    let retained_report = destination
        .join("report-snapshots")
        .join(format!("{}.json", digest(&report_bytes)));
    assert_eq!(fs::read(&retained_report).unwrap(), report_bytes);
    let inspected_report = success(
        cli(&no_data)
            .args(["report", "inspect", "--snapshot"])
            .arg(&retained_report)
            .output()
            .unwrap(),
    );
    assert_eq!(inspected_report["integrity_valid"], true);
    assert_eq!(inspected_report["case_restore_available"], false);
    let html_path = directory.path().join("retrieved.html");
    success(
        cli(&no_data)
            .args(["report", "retrieve", "--snapshot"])
            .arg(&retained_report)
            .args(["--format", "html", "--destination"])
            .arg(&html_path)
            .output()
            .unwrap(),
    );
    assert_eq!(fs::read(html_path).unwrap(), original_html);
    assert!(!no_data.parent().unwrap().exists());
}

#[test]
fn default_archive_records_omissions_and_restore_never_overwrites_existing_workspaces() {
    let directory = test_directory();
    let fixture = fixture(directory.path());
    let archive_path = directory.path().join("without-optional-files.tar.gz");
    success(create(&fixture, &archive_path).output().unwrap());
    let no_data = directory.path().join("unused-data");
    let inspection = success(
        archive_command(&no_data, "verify", &archive_path)
            .output()
            .unwrap(),
    );
    assert_eq!(inspection["source_snapshots_included"], false);
    let omissions = inspection["omissions"].as_array().unwrap();
    assert!(omissions.iter().any(|value| {
        value
            .as_str()
            .unwrap()
            .contains("Source snapshots were not selected")
    }));
    assert!(omissions.iter().any(|value| {
        value
            .as_str()
            .unwrap()
            .contains("Prior exported files were not selected")
    }));
    let names = entries(&archive_path)
        .into_iter()
        .map(|entry| entry.0)
        .collect::<Vec<_>>();
    assert!(
        !names
            .iter()
            .any(|name| name.starts_with("exports/") || name.contains("/workspace-snapshots/"))
    );

    let occupied = directory.path().join("occupied");
    fs::create_dir(&occupied).unwrap();
    fs::write(occupied.join("keep.txt"), b"existing user data").unwrap();
    failure(restore(&no_data, &archive_path, &occupied));
    assert_eq!(
        fs::read(occupied.join("keep.txt")).unwrap(),
        b"existing user data"
    );
    assert_eq!(fs::read_dir(&occupied).unwrap().count(), 1);
    let empty = directory.path().join("existing-empty");
    fs::create_dir(&empty).unwrap();
    failure(restore(&no_data, &archive_path, &empty));
    assert_eq!(fs::read_dir(empty).unwrap().count(), 0);

    let destination = directory.path().join("restored");
    let receipt = success(restore(&no_data, &archive_path, &destination));
    assert!(!destination.join("exports").exists());
    assert!(
        !destination
            .join("artifacts")
            .join(&fixture.case.id)
            .join("workspace-snapshots")
            .exists()
    );
    {
        let storage = Storage::open_read_only(destination.join("casework.db")).unwrap();
        let restored = storage
            .snapshot_case_for_archive(&fixture.case.id)
            .unwrap()
            .case;
        assert_eq!(restored.exports[0].sha256, fixture.case.exports[0].sha256);
        assert_eq!(
            restored.exports[0].signature,
            fixture.case.exports[0].signature
        );
        assert!(restored.exports[0].path.is_empty());
        assert!(restored.exports[0].coverage_manifest_path.is_none());
    }
    assert_eq!(
        success(restore(&no_data, &archive_path, &destination)),
        receipt
    );
    let other_archive = directory.path().join("different-archive.tar.gz");
    success(create(&fixture, &other_archive).output().unwrap());
    let database_bytes = fs::read(destination.join("casework.db")).unwrap();
    failure(restore(&no_data, &other_archive, &destination));
    assert_eq!(
        fs::read(destination.join("casework.db")).unwrap(),
        database_bytes
    );
    let untracked = destination.join("new-local-work.txt");
    fs::write(&untracked, b"new work after the published restore").unwrap();
    failure(restore(&no_data, &archive_path, &destination));
    assert_eq!(
        fs::read(&untracked).unwrap(),
        b"new work after the published restore"
    );
    fs::remove_file(untracked).unwrap();
    assert_eq!(
        success(restore(&no_data, &archive_path, &destination)),
        receipt
    );
    let changed_artifact = destination
        .join("artifacts")
        .join(fixture.raw_files.keys().next().unwrap());
    fs::write(&changed_artifact, b"local edit after restore").unwrap();
    failure(restore(&no_data, &archive_path, &destination));
    assert_eq!(
        fs::read(changed_artifact).unwrap(),
        b"local edit after restore"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(destination.join("restore-receipt.json")).unwrap()
        )
        .unwrap(),
        receipt
    );
    assert!(!no_data.exists());
}

#[test]
fn invalid_archive_payloads_fail_verify_preview_and_restore_before_publication() {
    let directory = test_directory();
    let fixture = fixture(directory.path());
    let archive_path = directory.path().join("valid.tar.gz");
    success(create(&fixture, &archive_path).output().unwrap());
    let original = entries(&archive_path);
    let raw_index = original
        .iter()
        .position(|(name, _)| name.starts_with("artifacts/"))
        .unwrap();
    let no_data = directory.path().join("never-initialized");
    for corruption in [
        "missing",
        "changed",
        "extra",
        "unreferenced",
        "duplicate",
        "schema",
        "unknown-case-field",
    ] {
        let mut changed = original.clone();
        match corruption {
            "missing" => {
                changed.remove(raw_index);
            }
            "changed" => {
                changed[raw_index].1[0] ^= 1;
            }
            "extra" | "unreferenced" => {
                let bytes = b"not part of the saved case".to_vec();
                if corruption == "unreferenced" {
                    let mut manifest: Value = serde_json::from_slice(&changed[0].1).unwrap();
                    manifest["entries"].as_array_mut().unwrap().push(json!({
                        "path": "extra.txt", "sha256": digest(&bytes), "byte_length": bytes.len(),
                    }));
                    changed[0].1 = serde_json::to_vec(&manifest).unwrap();
                }
                changed.push(("extra.txt".into(), bytes));
            }
            "duplicate" => {
                changed.push(changed[raw_index].clone());
            }
            "schema" => {
                let mut manifest: Value = serde_json::from_slice(&changed[0].1).unwrap();
                manifest["schema_version"] = json!("ai-security-scanner.archive/v999");
                changed[0].1 = serde_json::to_vec(&manifest).unwrap();
            }
            "unknown-case-field" => {
                // The transport and case digests are valid. A current reader
                // must still refuse data it would silently discard while
                // decoding the portable case, even though original-case.json
                // remains a perfectly valid, unchanged current-version DTO.
                let case_index = changed
                    .iter()
                    .position(|(name, _)| name == "case.json")
                    .unwrap();
                let mut portable: Value = serde_json::from_slice(&changed[case_index].1).unwrap();
                portable["case"]["scan_runs"][0]["engine_runs"][0]["future_execution_semantics"] =
                    json!({"must_be_preserved": true});
                changed[case_index].1 = serde_json::to_vec(&portable).unwrap();
                let hash = digest(&changed[case_index].1);
                let mut manifest: Value = serde_json::from_slice(&changed[0].1).unwrap();
                manifest["case_document_sha256"] = json!(hash);
                let case_entry = manifest["entries"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|entry| entry["path"] == "case.json")
                    .unwrap();
                case_entry["sha256"] = json!(hash);
                case_entry["byte_length"] = json!(changed[case_index].1.len());
                changed[0].1 = serde_json::to_vec(&manifest).unwrap();
                assert_eq!(
                    changed
                        .iter()
                        .find(|(name, _)| name == "original-case.json"),
                    original
                        .iter()
                        .find(|(name, _)| name == "original-case.json")
                );
            }
            _ => unreachable!(),
        }
        let invalid = directory.path().join(format!("{corruption}.tar.gz"));
        write_entries(&invalid, &changed);
        failure(
            archive_command(&no_data, "verify", &invalid)
                .output()
                .unwrap(),
        );
        let destination = directory.path().join(format!("restore-{corruption}"));
        failure(
            archive_command(&no_data, "restore-preview", &invalid)
                .arg("--destination")
                .arg(&destination)
                .output()
                .unwrap(),
        );
        failure(restore(&no_data, &invalid, &destination));
        assert!(!destination.exists(), "{corruption} published a workspace");
        assert!(!no_data.exists());
    }
    assert!(!fs::read_dir(directory.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".scanner-restore-")
    }));
}

#[test]
fn selecting_source_snapshots_refuses_historical_identity_without_a_retained_reference() {
    let directory = test_directory();
    let fixture = fixture(directory.path());
    {
        let storage = Storage::open(fixture.data_dir.join("casework.db")).unwrap();
        let mut case = storage
            .snapshot_case_for_archive(&fixture.case.id)
            .unwrap()
            .case;
        // Model a source refresh: the current source reference is still valid,
        // but a frozen run records a different older snapshot's hash and ID.
        // Keeping only the latest source must not be called complete source
        // preservation for this history.
        let mut historical = case
            .assets
            .iter()
            .find(|asset| asset.metadata.contains_key("workspace_snapshot_sha256"))
            .unwrap()
            .clone();
        let historical_hash = digest(b"historical source bytes no longer retained");
        historical.metadata.insert(
            "workspace_snapshot_id".into(),
            json!(format!("workspace-snapshot-sha256-{historical_hash}")),
        );
        historical
            .metadata
            .insert("workspace_snapshot_sha256".into(), json!(historical_hash));
        historical
            .metadata
            .remove(WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY);
        case.scan_runs[0]
            .report_asset_snapshots
            .push(ReportAssetSnapshot {
                asset: historical,
                disposition: ReportAssetDisposition::NoSupportedProfile,
            });
        storage
            .save_case(&mut case, "fixture.historical_source")
            .unwrap();
    }
    let without_sources = directory
        .path()
        .join("historical-case-without-sources.tar.gz");
    success(create(&fixture, &without_sources).output().unwrap());
    let no_data = directory.path().join("unused-data");
    let inspection = success(
        archive_command(&no_data, "verify", &without_sources)
            .output()
            .unwrap(),
    );
    assert_eq!(inspection["case_data_restore_available"], true);
    assert_eq!(inspection["source_snapshots_included"], false);
    let complete_parent = directory.path().join("must-not-publish-incomplete-source");
    let with_sources = complete_parent.join("archive.tar.gz");
    let error = failure(
        create(&fixture, &with_sources)
            .arg("--include-source-snapshots")
            .output()
            .unwrap(),
    );
    assert!(
        error.contains("historical") && error.contains("reference"),
        "{error}"
    );
    assert!(!complete_parent.exists());
    assert!(!no_data.exists());
}

#[test]
fn connector_capture_history_requires_complete_references_only_when_sources_are_selected() {
    for history_location in ["current", "frozen", "observed-values"] {
        let directory = test_directory();
        let fixture = fixture(directory.path());
        let capture_bytes =
            br#"{"Accounts":[{"Id":"111122223333","Name":"Synthetic retained account"}]}"#;
        let connector_root = fixture
            .data_dir
            .join("artifacts")
            .join(&fixture.case.id)
            .join("connector-snapshots");
        fs::create_dir_all(&connector_root).unwrap();
        fs::write(connector_root.join("synthetic-current.json"), capture_bytes).unwrap();
        let current = SnapshotArtifactReference::new(
            "synthetic-current.json",
            "current-connector-capture",
            "aws-organizations-list-accounts",
            fixture.case.created_at,
            Some(digest(capture_bytes)),
        );
        let storage = Storage::open(fixture.data_dir.join("casework.db")).unwrap();
        let mut case = storage
            .snapshot_case_for_archive(&fixture.case.id)
            .unwrap()
            .case;
        current
            .clone()
            .insert_into(&mut case.data_sources[0])
            .unwrap();
        case.assets[0]
            .metadata
            .insert("source_artifact_id".into(), json!(current.artifact_id));
        // Relation evidence also legitimately names scanner raw files and
        // normalized finding evidence; neither needs a connector reference.
        case.asset_relations[0].evidence_ids = vec![
            current.artifact_id.clone(),
            case.raw_artifacts[0].id.clone(),
            case.findings[0].evidence[0].id.clone(),
        ];
        storage
            .save_case(&mut case, "fixture.connector_capture")
            .unwrap();
        if history_location == "current" {
            // Repeated captures of the same bytes may have distinct times;
            // preserve both histories while retaining a single verified blob.
            let mut duplicate_source = case.data_sources[0].clone();
            duplicate_source.id = "fixture-shared-capture-source".into();
            let mut later_capture = current.clone();
            later_capture.observed_at += chrono::Duration::seconds(1);
            later_capture.insert_into(&mut duplicate_source).unwrap();
            case.data_sources.push(duplicate_source);
            storage
                .save_case(&mut case, "fixture.shared_capture")
                .unwrap();
            let complete = directory.path().join("complete-current-capture.tar.gz");
            success(
                create(&fixture, &complete)
                    .arg("--include-source-snapshots")
                    .output()
                    .unwrap(),
            );
            let no_data = directory.path().join("unused-data");
            success(
                archive_command(&no_data, "verify", &complete)
                    .output()
                    .unwrap(),
            );
            let capture_entry = format!(
                "artifacts/{}/connector-snapshots/synthetic-current.json",
                case.id
            );
            let saved = entries(&complete);
            assert_eq!(
                saved
                    .iter()
                    .filter(|(name, _)| name == &capture_entry)
                    .count(),
                1
            );
            assert_eq!(
                saved
                    .iter()
                    .find(|(name, _)| name == &capture_entry)
                    .unwrap()
                    .1,
                capture_bytes
            );
            let portable: Value = serde_json::from_slice(
                &saved
                    .iter()
                    .find(|(name, _)| name == "case.json")
                    .unwrap()
                    .1,
            )
            .unwrap();
            assert_eq!(
                portable["case"]["data_sources"],
                serde_json::to_value(&case.data_sources).unwrap()
            );
        }
        let missing = "historical-connector-capture-without-reference";
        match history_location {
            "current" => {
                case.assets[0]
                    .metadata
                    .insert("source_artifact_id".into(), json!(missing));
            }
            "frozen" => {
                case.scan_runs[0].report_asset_snapshots[0]
                    .asset
                    .metadata
                    .insert("source_artifact_id".into(), json!(missing));
            }
            "observed-values" => {
                case.assets[0].metadata.insert(
                    "ai_security_scanner.observed_values".into(),
                    json!({
                        "source_artifact_id": [current.artifact_id, missing],
                        "region": ["synthetic-old-region", "synthetic-new-region"],
                    }),
                );
            }
            _ => unreachable!(),
        }
        storage
            .save_case(&mut case, "fixture.historical_connector_capture")
            .unwrap();
        drop(storage);
        let without_sources = directory
            .path()
            .join("historical-case-without-sources.tar.gz");
        success(create(&fixture, &without_sources).output().unwrap());
        let no_data = directory.path().join("unused-data");
        let inspection = success(
            archive_command(&no_data, "verify", &without_sources)
                .output()
                .unwrap(),
        );
        assert_eq!(inspection["case_data_restore_available"], true);
        assert_eq!(inspection["source_snapshots_included"], false);
        let destination_parent = directory.path().join("incomplete-must-not-publish");
        let error = failure(
            create(&fixture, &destination_parent.join("archive.tar.gz"))
                .arg("--include-source-snapshots")
                .output()
                .unwrap(),
        );
        assert!(
            error.contains("historical connector") && error.contains("reference"),
            "{history_location}: {error}"
        );
        assert!(!destination_parent.exists());
        assert!(!no_data.exists());
    }
}

#[test]
fn create_refuses_missing_evidence_active_runs_and_existing_output_without_publication() {
    let directory = test_directory();
    let fixture = fixture(directory.path());
    let (name, bytes) = fixture.raw_files.iter().next().unwrap();
    let artifact_path = fixture.data_dir.join("artifacts").join(name);
    fs::remove_file(&artifact_path).unwrap();
    let failed_parent = directory.path().join("must-not-be-created");
    let output = failed_parent.join("archive.tar.gz");
    failure(create(&fixture, &output).output().unwrap());
    assert!(!failed_parent.exists());
    fs::write(artifact_path, bytes).unwrap();

    let existing = directory.path().join("existing.tar.gz");
    fs::write(&existing, b"existing archive bytes").unwrap();
    failure(create(&fixture, &existing).output().unwrap());
    assert_eq!(fs::read(existing).unwrap(), b"existing archive bytes");
    let storage = Storage::open(fixture.data_dir.join("casework.db")).unwrap();
    let mut active = storage.get_case(&fixture.case.id).unwrap();
    active.scan_runs[0].completed_at = None;
    active.scan_runs[0].engine_runs[0].status = EngineRunStatus::Running;
    storage.save_case(&mut active, "fixture.active").unwrap();
    failure(create(&fixture, &output).output().unwrap());
    assert!(!failed_parent.exists());
    assert!(
        storage.get_case(&fixture.case.id).unwrap().scan_runs[0]
            .completed_at
            .is_none()
    );
}

#[test]
fn archive_commands_do_not_initialize_a_missing_data_directory_or_bypass_acknowledgement() {
    let directory = test_directory();
    let no_data = directory.path().join("uninitialized-parent").join("data");
    let archive = directory.path().join("must-not-exist.tar.gz");
    for acknowledge in [false, true] {
        let mut command = cli(&no_data);
        command
            .args([
                "archive",
                "create",
                "--case-id",
                "missing-case",
                "--destination",
            ])
            .arg(&archive);
        if acknowledge {
            command.arg("--acknowledge-sensitive-data");
        }
        failure(command.output().unwrap());
        assert!(!archive.exists());
        assert!(!no_data.parent().unwrap().exists());
    }
    let destination = directory.path().join("must-not-publish");
    failure(
        archive_command(&no_data, "restore", &archive)
            .arg("--destination")
            .arg(&destination)
            .output()
            .unwrap(),
    );
    assert!(!destination.exists());
    assert!(!no_data.parent().unwrap().exists());
}

#[test]
fn archives_automatically_preserve_export_snapshots_and_reopen_them_after_restore() {
    let directory = test_directory();
    let fixture = fixture(directory.path());
    let mut originals = Vec::new();
    for format in ["html", "json"] {
        let destination = directory.path().join(format!("shared.{format}"));
        let mut command = cli(&fixture.data_dir);
        command
            .args([
                "export",
                "create",
                "--case-id",
                &fixture.case.id,
                "--run-id",
                &fixture.case.scan_runs[0].id,
                "--format",
                format,
                "--locale",
                "zh-Hant",
                "--redaction",
                "none",
                "--destination",
            ])
            .arg(&destination);
        if format == "html" {
            command.args([
                "--include-raw-artifacts",
                "--acknowledge-sensitive-raw-artifacts",
            ]);
        }
        let export = success(command.output().unwrap());
        let reference = export["report_snapshot"].clone();
        let source = fixture
            .data_dir
            .join("artifacts")
            .join(reference["relative_path"].as_str().unwrap());
        let snapshot = fs::read(&source).unwrap();
        let original = fs::read(&destination).unwrap();
        originals.push((format, reference, snapshot, original));
        fs::remove_file(destination).unwrap();
        let storage = Storage::open(fixture.data_dir.join("casework.db")).unwrap();
        let mut changed = storage.get_case(&fixture.case.id).unwrap();
        changed.title = format!("Case changed after {format} was shared");
        storage
            .save_case(&mut changed, "fixture.after_export")
            .unwrap();
    }
    let archive = directory.path().join("preserved.tar.gz");
    // No explicit snapshot paths and no external export-file selection.
    success(create(&fixture, &archive).output().unwrap());
    let archived = entries(&archive);
    assert!(
        !archived
            .iter()
            .any(|(name, _)| name.starts_with("exports/"))
    );
    for (_, reference, snapshot, _) in &originals {
        let name = format!("artifacts/{}", reference["relative_path"].as_str().unwrap());
        assert_eq!(
            &archived.iter().find(|(entry, _)| entry == &name).unwrap().1,
            snapshot
        );
    }
    fs::rename(
        &fixture.data_dir,
        directory.path().join("moved-original-data"),
    )
    .unwrap();
    fs::rename(
        &fixture.selected_source,
        directory.path().join("moved-original-source"),
    )
    .unwrap();
    let destination = directory.path().join("restored");
    success(restore(
        &directory.path().join("unused-data"),
        &archive,
        &destination,
    ));
    let restored = Storage::open_read_only(destination.join("casework.db"))
        .unwrap()
        .get_case(&fixture.case.id)
        .unwrap();
    assert!(restored.scope_grants.is_empty());
    assert!(restored.exports.iter().all(|export| export.path.is_empty()));
    for (format, reference, snapshot, original) in &originals {
        let path = destination
            .join("artifacts")
            .join(reference["relative_path"].as_str().unwrap());
        assert_eq!(&fs::read(&path).unwrap(), snapshot);
        assert!(
            restored
                .exports
                .iter()
                .any(|export| serde_json::to_value(&export.report_snapshot).unwrap() == *reference)
        );
        for operation in ["retrieve", "replay"] {
            let output = directory.path().join(format!("{operation}.{format}"));
            success(
                cli(&destination)
                    .args(["report", operation, "--snapshot"])
                    .arg(&path)
                    .args(["--format", format, "--destination"])
                    .arg(&output)
                    .output()
                    .unwrap(),
            );
            assert_eq!(&fs::read(output).unwrap(), original);
        }
    }
    // Restored relative references remain usable for a second portable archive.
    success(
        cli(&destination)
            .args([
                "archive",
                "create",
                "--case-id",
                &fixture.case.id,
                "--acknowledge-sensitive-data",
                "--destination",
            ])
            .arg(directory.path().join("second-archive.tar.gz"))
            .output()
            .unwrap(),
    );
}

#[test]
fn recorded_export_snapshots_cannot_be_omitted_or_substituted_in_archives() {
    let directory = test_directory();
    let fixture = fixture(directory.path());
    let export = success(
        cli(&fixture.data_dir)
            .args([
                "export",
                "create",
                "--case-id",
                &fixture.case.id,
                "--run-id",
                &fixture.case.scan_runs[0].id,
                "--format",
                "html",
                "--destination",
            ])
            .arg(directory.path().join("shared.html"))
            .output()
            .unwrap(),
    );
    let relative = export["report_snapshot"]["relative_path"].as_str().unwrap();
    let snapshot_path = fixture.data_dir.join("artifacts").join(relative);
    let snapshot = fs::read(&snapshot_path).unwrap();
    let archive = directory.path().join("complete.tar.gz");
    success(create(&fixture, &archive).output().unwrap());
    let mut stripped = entries(&archive);
    let name = format!("artifacts/{relative}");
    stripped.retain(|(path, _)| path != &name);
    let (_, index_bytes) = stripped
        .iter_mut()
        .find(|(path, _)| path == "archive-index.json")
        .unwrap();
    let mut index: Value = serde_json::from_slice(index_bytes).unwrap();
    index["reports"]
        .as_array_mut()
        .unwrap()
        .retain(|path| path != &name);
    *index_bytes = serde_json::to_vec(&index).unwrap();
    let mut manifest: Value = serde_json::from_slice(&stripped[0].1).unwrap();
    manifest["entries"] = json!(
        stripped
            .iter()
            .skip(1)
            .map(|(path, bytes)| json!({
                "path": path, "sha256": digest(bytes), "byte_length": bytes.len(),
            }))
            .collect::<Vec<_>>()
    );
    stripped[0].1 = serde_json::to_vec(&manifest).unwrap();
    let missing = directory.path().join("missing-historical-report.tar.gz");
    write_entries(&missing, &stripped);
    assert!(
        failure(
            archive_command(&fixture.data_dir, "verify", &missing)
                .output()
                .unwrap()
        )
        .contains("recorded export snapshot is missing")
    );
    let destination = directory.path().join("must-not-restore");
    failure(restore(&fixture.data_dir, &missing, &destination));
    assert!(!destination.exists());
    for corrupt in [true, false] {
        if corrupt {
            let mut changed = snapshot.clone();
            changed[0] ^= 1;
            fs::write(&snapshot_path, changed).unwrap();
        } else {
            fs::remove_file(&snapshot_path).unwrap();
        }
        let incomplete = directory
            .path()
            .join(format!("must-not-exist-{corrupt}.tar.gz"));
        failure(create(&fixture, &incomplete).output().unwrap());
        assert!(!incomplete.exists());
    }
}

#[test]
fn terminal_snapshots_survive_archive_restore_and_cannot_be_omitted() {
    let directory = test_directory();
    let fixture = fixture(directory.path());
    let storage = Storage::open(fixture.data_dir.join("casework.db")).unwrap();
    let mut case = storage.get_case(&fixture.case.id).unwrap();
    for task in &mut case.scan_runs[0].engine_runs {
        task.phase = "completed".into();
        task.cleanup_removed = Some(true);
        task.resume_token = None;
    }
    storage
        .save_case(&mut case, "fixture.clean_terminal")
        .unwrap();
    let engines = EngineRegistry::load_builtin().unwrap();
    let adapters = builtin_adapter_registry().unwrap();
    let service = CaseService::new(
        &storage,
        &engines,
        &adapters,
        fixture.data_dir.join("artifacts"),
        fixture.data_dir.join("key"),
    );
    let case = service
        .retain_terminal_report_snapshot(&case.id, &case.scan_runs[0].id)
        .unwrap();
    let record = &case.run_report_snapshots[0];
    let original = fs::read(
        fixture
            .data_dir
            .join("artifacts")
            .join(&record.snapshot.relative_path),
    )
    .unwrap();
    let archive = directory.path().join("terminal.tar.gz");
    success(create(&fixture, &archive).output().unwrap());
    let mut stripped = entries(&archive);
    let name = format!("artifacts/{}", record.snapshot.relative_path);
    assert_eq!(
        stripped.iter().find(|(path, _)| path == &name).unwrap().1,
        original
    );
    stripped.retain(|(path, _)| path != &name);
    let (_, index_bytes) = stripped
        .iter_mut()
        .find(|(path, _)| path == "archive-index.json")
        .unwrap();
    let mut index: Value = serde_json::from_slice(index_bytes).unwrap();
    index["reports"]
        .as_array_mut()
        .unwrap()
        .retain(|path| path != &name);
    *index_bytes = serde_json::to_vec(&index).unwrap();
    let mut manifest: Value = serde_json::from_slice(&stripped[0].1).unwrap();
    manifest["entries"] = json!(
        stripped
            .iter()
            .skip(1)
            .map(|(path, bytes)| json!({
                "path": path, "sha256": digest(bytes), "byte_length": bytes.len(),
            }))
            .collect::<Vec<_>>()
    );
    stripped[0].1 = serde_json::to_vec(&manifest).unwrap();
    let missing = directory.path().join("missing-terminal.tar.gz");
    write_entries(&missing, &stripped);
    assert!(
        failure(
            archive_command(&fixture.data_dir, "verify", &missing)
                .output()
                .unwrap()
        )
        .contains("recorded terminal snapshot is missing")
    );
    let rejected = directory.path().join("must-not-restore-terminal");
    failure(restore(&fixture.data_dir, &missing, &rejected));
    assert!(!rejected.exists());
    drop(storage);
    fs::rename(
        &fixture.data_dir,
        directory.path().join("moved-terminal-data"),
    )
    .unwrap();
    fs::rename(
        &fixture.selected_source,
        directory.path().join("moved-terminal-source"),
    )
    .unwrap();
    let destination = directory.path().join("restored-terminal");
    success(restore(
        &directory.path().join("unused-data"),
        &archive,
        &destination,
    ));
    let restored = Storage::open_read_only(destination.join("casework.db"))
        .unwrap()
        .get_case(&case.id)
        .unwrap();
    assert_eq!(
        json!(restored.run_report_snapshots),
        json!(case.run_report_snapshots)
    );
    let path = destination
        .join("artifacts")
        .join(&record.snapshot.relative_path);
    assert_eq!(fs::read(&path).unwrap(), original);
    for format in ["html", "json"] {
        let retrieved = directory.path().join(format!("terminal.{format}"));
        let replayed = directory.path().join(format!("replayed-terminal.{format}"));
        for (operation, target) in [("retrieve", &retrieved), ("replay", &replayed)] {
            success(
                cli(&destination)
                    .args(["report", operation, "--snapshot"])
                    .arg(&path)
                    .args(["--format", format, "--destination"])
                    .arg(target)
                    .output()
                    .unwrap(),
            );
        }
        assert_eq!(fs::read(retrieved).unwrap(), fs::read(replayed).unwrap());
    }
}

#[test]
fn combined_export_snapshots_and_selected_files_restore_with_portable_history() {
    use ai_security_scanner_lib::domain::{ScanRequestOutcome, ScanRequestOutcomeCode, new_id};
    for include_files in [false, true] {
        let directory = test_directory();
        let fixture = fixture(directory.path());
        let storage = Storage::open(fixture.data_dir.join("casework.db")).unwrap();
        let mut case = storage.get_case(&fixture.case.id).unwrap();
        let mut run = case.scan_runs[0].clone();
        run.id = new_id();
        run.sequence = case.scan_runs.iter().map(|run| run.sequence).max().unwrap() + 1;
        run.engine_runs.clear();
        run.verification_baseline_run_id = None;
        run.request_outcome = Some(
            ScanRequestOutcome::no_checks_completed(
                ScanRequestOutcomeCode::NoApplicableChecks,
                vec![],
                vec![],
                "Synthetic no-check source",
            )
            .unwrap(),
        );
        case.scan_runs.push(run);
        storage
            .save_case(&mut case, "fixture.combined_source")
            .unwrap();
        drop(storage);
        let ids: Vec<_> = case
            .scan_runs
            .iter()
            .rev()
            .map(|run| run.id.clone())
            .collect();
        let destination = directory.path().join("combined.html");
        let export = success(
            cli(&fixture.data_dir)
                .args([
                    "export",
                    "combine",
                    "--case-id",
                    &case.id,
                    "--run-id",
                    &ids.join(","),
                    "--format",
                    "html",
                    "--locale",
                    "zh-Hant",
                    "--destination",
                ])
                .arg(&destination)
                .output()
                .unwrap(),
        );
        let relative = export["report_snapshot"]["relative_path"].as_str().unwrap();
        let snapshot = fs::read(fixture.data_dir.join("artifacts").join(relative)).unwrap();
        let html = fs::read(&destination).unwrap();
        let archive = directory.path().join("combined.tar.gz");
        let mut command = create(&fixture, &archive);
        if include_files {
            command.arg("--include-export-files");
        }
        success(command.output().unwrap());
        let payloads = entries(&archive);
        let name = format!("artifacts/{relative}");
        assert_eq!(
            payloads.iter().find(|(path, _)| path == &name).unwrap().1,
            snapshot
        );
        // Transport hashes alone cannot make omission of a recorded original valid.
        let mut stripped = payloads;
        stripped.retain(|(path, _)| path != &name);
        let (_, index_bytes) = stripped
            .iter_mut()
            .find(|(path, _)| path == "archive-index.json")
            .unwrap();
        let mut index: Value = serde_json::from_slice(index_bytes).unwrap();
        index["reports"]
            .as_array_mut()
            .unwrap()
            .retain(|path| path != &name);
        *index_bytes = serde_json::to_vec(&index).unwrap();
        let mut manifest: Value = serde_json::from_slice(&stripped[0].1).unwrap();
        manifest["entries"] = json!(
            stripped
                .iter()
                .skip(1)
                .map(|(path, bytes)| json!({
                    "path": path, "sha256": digest(bytes), "byte_length": bytes.len(),
                }))
                .collect::<Vec<_>>()
        );
        stripped[0].1 = serde_json::to_vec(&manifest).unwrap();
        let missing = directory.path().join("missing-combined.tar.gz");
        write_entries(&missing, &stripped);
        assert!(
            failure(
                archive_command(&fixture.data_dir, "verify", &missing)
                    .output()
                    .unwrap()
            )
            .contains("recorded combined snapshot is missing")
        );
        let rejected = directory.path().join("must-not-restore-combined");
        failure(restore(&fixture.data_dir, &missing, &rejected));
        assert!(!rejected.exists());
        fs::remove_file(&destination).unwrap();
        fs::rename(
            &fixture.data_dir,
            directory.path().join("moved-combined-data"),
        )
        .unwrap();
        fs::rename(
            &fixture.selected_source,
            directory.path().join("moved-combined-source"),
        )
        .unwrap();
        let restored_root = directory.path().join("restored-combined");
        success(restore(
            &directory.path().join("unused"),
            &archive,
            &restored_root,
        ));
        let restored = Storage::open_read_only(restored_root.join("casework.db"))
            .unwrap()
            .get_case(&case.id)
            .unwrap();
        assert_eq!(restored.combined_exports.len(), 1);
        let record = &restored.combined_exports[0];
        assert_eq!(record.selected_run_ids, ids);
        assert_eq!(json!(record.report_snapshot), export["report_snapshot"]);
        if include_files {
            assert_eq!(fs::read(&record.path).unwrap(), html);
        } else {
            assert!(record.path.is_empty());
        }
        let path = restored_root.join("artifacts").join(relative);
        assert_eq!(fs::read(&path).unwrap(), snapshot);
        for operation in ["retrieve", "replay"] {
            let output = directory.path().join(format!("combined-{operation}.html"));
            success(
                cli(&restored_root)
                    .args(["report", operation, "--snapshot"])
                    .arg(&path)
                    .args(["--format", "html", "--destination"])
                    .arg(&output)
                    .output()
                    .unwrap(),
            );
            assert_eq!(fs::read(output).unwrap(), html);
        }
        let mut second = cli(&restored_root);
        second
            .args([
                "archive",
                "create",
                "--case-id",
                &case.id,
                "--acknowledge-sensitive-data",
                "--destination",
            ])
            .arg(directory.path().join("second-combined.tar.gz"));
        if include_files {
            second.arg("--include-export-files");
        }
        success(second.output().unwrap());
    }
}

fn originals_fixture(root: &Path) -> Fixture {
    use ai_security_scanner_lib::external_scanner_import::{
        ExternalScannerImportRequest, import_external_scanner_reports,
        preview_external_scanner_import,
    };
    let mut fixture = fixture(root);
    let report = root.join("upstream.json");
    fs::write(
        &report,
        include_bytes!("../../tests/fixtures/external-scanners/strix-vulnerabilities.json"),
    )
    .unwrap();
    let storage = Storage::open(fixture.data_dir.join("casework.db")).unwrap();
    fixture.case = import_external_scanner_reports(
        &storage,
        &fixture.data_dir.join("artifacts"),
        &fixture.case.id,
        &[ExternalScannerImportRequest {
            report_path: report.clone(),
            asset_id: fixture.case.assets[0].id.clone(),
            upstream_target: "/workspace/app".into(),
            source_sha256: preview_external_scanner_import(&report)
                .unwrap()
                .source_sha256,
        }],
    )
    .unwrap();
    fixture
}

fn export_with_originals(fixture: &Fixture, destination: &Path, redaction: &str) -> Output {
    let ids = fixture
        .case
        .scan_runs
        .iter()
        .map(|run| run.id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    cli(&fixture.data_dir)
        .args([
            "export",
            "combine",
            "--case-id",
            &fixture.case.id,
            "--run-id",
            &ids,
            "--format",
            "html",
            "--include-raw-artifacts",
            "--acknowledge-sensitive-raw-artifacts",
            "--acknowledge-sensitive-data",
            "--redaction",
            redaction,
            "--destination",
        ])
        .arg(destination)
        .output()
        .unwrap()
}

#[test]
fn combined_originals_preserve_source_task_namespaces_redaction_and_replay() {
    for redaction in ["none", "standard"] {
        let directory = test_directory();
        let fixture = originals_fixture(directory.path());
        let output = directory.path().join("with-originals.html");
        let receipt = success(export_with_originals(&fixture, &output, redaction));
        assert!(receipt.get("attachment_archive").is_none());
        assert_eq!(receipt["original_files"]["omitted_files"], 0);
        let expected = fixture
            .case
            .raw_artifacts
            .iter()
            .filter(|raw| redaction == "none" || !raw.contains_sensitive_data)
            .count();
        assert_eq!(receipt["original_files"]["included_files"], expected);
        assert_eq!(
            receipt["original_files"]["sensitive_files_excluded"],
            fixture.case.raw_artifacts.len() - expected
        );
        let path = fixture.data_dir.join("artifacts").join(
            receipt["report_snapshot"]["relative_path"]
                .as_str()
                .unwrap(),
        );
        let snapshot: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let inputs: Value = serde_json::from_slice(
            &BASE64
                .decode(snapshot["inputs"]["bytes"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let mut seen = std::collections::BTreeSet::new();
        let mut count = 0;
        for entry in inputs["combined_attachments"].as_array().unwrap() {
            let run = entry["run_id"].as_str().unwrap();
            let task = entry["attachment"]["engine_run_id"].as_str().unwrap();
            assert!(seen.insert((run, task)));
            let bytes = BASE64
                .decode(entry["attachment"]["bytes"].as_str().unwrap())
                .unwrap();
            assert_eq!(digest(&bytes), entry["attachment"]["sha256"]);
            let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
            let mut manifest = Vec::new();
            zip.by_name("manifest.json")
                .unwrap()
                .read_to_end(&mut manifest)
                .unwrap();
            let manifest: Value = serde_json::from_slice(&manifest).unwrap();
            assert_eq!(manifest["run_id"], run);
            assert_eq!(manifest["engine_run_id"], task);
            for file in manifest["files"].as_array().unwrap() {
                let mut original = Vec::new();
                zip.by_name(file["path"].as_str().unwrap())
                    .unwrap()
                    .read_to_end(&mut original)
                    .unwrap();
                assert_eq!(digest(&original), file["sha256"]);
                let raw = fixture
                    .case
                    .raw_artifacts
                    .iter()
                    .find(|raw| raw.id == file["artifact_id"].as_str().unwrap())
                    .unwrap();
                assert_eq!(raw.run_id, run);
                assert_eq!(raw.engine_run_id, task);
                assert_eq!(
                    original,
                    fs::read(fixture.data_dir.join("artifacts").join(&raw.relative_path)).unwrap()
                );
                count += 1;
            }
        }
        assert_eq!(count, expected);
        let html = fs::read(&output).unwrap();
        assert!(!String::from_utf8_lossy(&html).contains("<script>"));
        let archive = directory.path().join("originals.tar.gz");
        success(create(&fixture, &archive).output().unwrap());
        fs::rename(&fixture.data_dir, directory.path().join("moved-data")).unwrap();
        let restored = directory.path().join("restored");
        success(restore(
            &directory.path().join("unused"),
            &archive,
            &restored,
        ));
        let restored_snapshot = restored.join("artifacts").join(
            receipt["report_snapshot"]["relative_path"]
                .as_str()
                .unwrap(),
        );
        let replayed = directory.path().join("replayed.html");
        success(
            cli(&restored)
                .args(["report", "replay", "--snapshot"])
                .arg(restored_snapshot)
                .args(["--format", "html", "--destination"])
                .arg(&replayed)
                .output()
                .unwrap(),
        );
        assert_eq!(fs::read(replayed).unwrap(), html);
    }
}

#[test]
fn oversized_combined_originals_keep_readable_html_and_a_verified_full_archive() {
    for document_overflow in [false, true] {
        let directory = test_directory();
        let mut fixture = originals_fixture(directory.path());
        let bytes = if document_overflow {
            let mut state = 0x1278ab9345u64;
            (0..48 * 1024 * 1024)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect::<Vec<_>>()
        } else {
            vec![7u8; 65 * 1024 * 1024]
        };
        let mut raw = fixture.case.raw_artifacts[0].clone();
        raw.id = ai_security_scanner_lib::domain::new_id();
        raw.relative_path = format!(
            "{}/{}/{}/large.bin",
            raw.case_id, raw.run_id, raw.engine_run_id
        );
        raw.sha256 = digest(&bytes);
        raw.byte_length = bytes.len() as u64;
        raw.contains_sensitive_data = false;
        fs::write(
            fixture.data_dir.join("artifacts").join(&raw.relative_path),
            &bytes,
        )
        .unwrap();
        let task = fixture
            .case
            .scan_runs
            .iter_mut()
            .flat_map(|run| &mut run.engine_runs)
            .find(|task| task.id == raw.engine_run_id)
            .unwrap();
        task.raw_artifact_ids.push(raw.id.clone());
        fixture.case.raw_artifacts.push(raw.clone());
        Storage::open(fixture.data_dir.join("casework.db"))
            .unwrap()
            .save_case(&mut fixture.case, "fixture.large_original")
            .unwrap();
        let destination = directory.path().join("readable.html");
        if !document_overflow {
            let connection =
                rusqlite::Connection::open(fixture.data_dir.join("casework.db")).unwrap();
            connection.execute_batch("CREATE TRIGGER refuse_originals_history BEFORE INSERT ON case_events
                WHEN NEW.event_type = 'export.combined_created' BEGIN SELECT RAISE(ABORT, 'synthetic history failure'); END;").unwrap();
            failure(export_with_originals(&fixture, &destination, "none"));
            assert!(!destination.exists());
            assert!(!fs::read_dir(directory.path()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("report-originals-")
            }));
            assert_eq!(
                fs::read_dir(
                    fixture
                        .data_dir
                        .join("artifacts")
                        .join(&fixture.case.id)
                        .join("report-snapshots")
                )
                .unwrap()
                .count(),
                0
            );
            connection
                .execute_batch("DROP TRIGGER refuse_originals_history")
                .unwrap();
        }
        let receipt = success(export_with_originals(&fixture, &destination, "none"));
        assert_eq!(receipt["original_files"]["included_files"], 0);
        assert_eq!(
            receipt["original_files"]["omitted_files"],
            fixture.case.raw_artifacts.len()
        );
        assert_eq!(
            receipt["original_files"]["omission_reason"],
            if document_overflow {
                "combined_document_limit"
            } else {
                "original_file_limit"
            }
        );
        assert!(fs::metadata(&destination).unwrap().len() < 1024 * 1024);
        let archive = Path::new(receipt["attachment_archive"]["path"].as_str().unwrap());
        assert_eq!(
            digest(&fs::read(archive).unwrap()),
            receipt["attachment_archive"]["sha256"]
        );
        assert!(
            fs::read_to_string(&destination)
                .unwrap()
                .contains(archive.file_name().unwrap().to_str().unwrap())
        );
        success(
            archive_command(&fixture.data_dir, "verify", archive)
                .output()
                .unwrap(),
        );
        let restored = directory.path().join("restored-full-case");
        success(restore(&fixture.data_dir, archive, &restored));
        assert_eq!(
            fs::read(restored.join("artifacts").join(&raw.relative_path)).unwrap(),
            bytes
        );
        // Selecting external exports carries the fallback archive with its history.
        let outer = directory.path().join("outer.tar.gz");
        success(
            create(&fixture, &outer)
                .arg("--include-export-files")
                .output()
                .unwrap(),
        );
        let outer_restored = directory.path().join("outer-restored");
        success(restore(&fixture.data_dir, &outer, &outer_restored));
        let case = Storage::open_read_only(outer_restored.join("casework.db"))
            .unwrap()
            .get_case(&fixture.case.id)
            .unwrap();
        let retained = case
            .combined_exports
            .last()
            .unwrap()
            .attachment_archive
            .as_ref()
            .unwrap();
        assert_eq!(
            digest(&fs::read(&retained.path).unwrap()),
            receipt["attachment_archive"]["sha256"]
        );
    }
}

#[test]
fn combined_originals_require_explicit_choices_and_reject_corrupt_source_bytes() {
    let directory = test_directory();
    let fixture = originals_fixture(directory.path());
    let ids = fixture
        .case
        .scan_runs
        .iter()
        .map(|run| run.id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let missing = directory.path().join("must-not-initialize");
    failure(
        cli(&missing)
            .args([
                "export",
                "combine",
                "--case-id",
                &fixture.case.id,
                "--run-id",
                &ids,
                "--format",
                "html",
                "--include-raw-artifacts",
                "--destination",
            ])
            .arg(directory.path().join("missing-consent.html"))
            .output()
            .unwrap(),
    );
    assert!(!missing.exists());
    let raw = &fixture.case.raw_artifacts[0];
    fs::write(
        fixture.data_dir.join("artifacts").join(&raw.relative_path),
        b"changed original",
    )
    .unwrap();
    let destination = directory.path().join("must-not-publish.html");
    failure(export_with_originals(&fixture, &destination, "none"));
    assert!(!destination.exists());
    let saved = Storage::open_read_only(fixture.data_dir.join("casework.db"))
        .unwrap()
        .get_case(&fixture.case.id)
        .unwrap();
    assert!(saved.combined_exports.is_empty());
}
