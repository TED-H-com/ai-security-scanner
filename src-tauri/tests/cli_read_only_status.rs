#![cfg(feature = "cli")]

use ai_security_scanner_lib::domain::{AssessmentCase, CaseStatus, OrganizationProfile};
use ai_security_scanner_lib::process_lease::DataDirectoryExclusiveLease;
use ai_security_scanner_lib::storage::Storage;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn status(data_directory: &Path, case_id: &str, run_id: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ai-security-scanner-cli"));
    command.arg("--data-dir").arg(data_directory).args([
        "--json",
        "scan",
        "status",
        "--case-id",
        case_id,
    ]);
    if let Some(run_id) = run_id {
        command.args(["--run-id", run_id]);
    }
    command.output().expect("status subprocess")
}

fn successful_status(output: Output) -> Value {
    assert!(
        output.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).expect("one JSON result")
}

fn saved_revision(storage: &Storage, case_id: &str) -> i64 {
    Connection::open_with_flags(storage.path(), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap()
        .query_row(
            "SELECT revision FROM cases WHERE id = ?1",
            [case_id],
            |row| row.get(0),
        )
        .unwrap()
}

fn live_case(storage: &Storage) -> AssessmentCase {
    let mut case = AssessmentCase::new(
        "Read-only inspection fixture".into(),
        OrganizationProfile {
            organization_name: "Example".into(),
            employee_range: "1-10".into(),
            data_classes: Vec::new(),
            notes: None,
        },
    );
    case.status = CaseStatus::Scanning;
    case.scan_runs.push(
        serde_json::from_value(json!({
            "id": "live-run",
            "case_id": case.id,
            "sequence": 1,
            "created_at": case.created_at,
            "knowledge_cutoff": case.created_at,
            "scope_grant_ids": [],
            "engine_runs": [{
                "id": "live-engine",
                "scan_run_id": "live-run",
                "engine_id": "gitleaks",
                "asset_ids": [],
                "status": "running",
                "progress_percent": 42,
                "phase": "running",
                "started_at": case.created_at,
                "adapter_version": "fixture",
                "raw_artifact_ids": []
            }]
        }))
        .expect("saved live-run fixture"),
    );
    storage.save_case(&mut case, "fixture.created").unwrap();
    case
}

fn directory_files(path: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let name = entry.file_name().to_str().unwrap().to_owned();
            // SQLite's WAL reader coordinates through the shared-memory index.
            // Database and committed WAL bytes must remain unchanged.
            let bytes = if name.ends_with("-shm") {
                Vec::new()
            } else {
                fs::read(entry.path()).unwrap()
            };
            (name, bytes)
        })
        .collect()
}

#[test]
fn status_reads_live_owner_wal_without_recovery_or_a_second_writer_lease() {
    let directory = tempfile::tempdir().unwrap();
    let _owner = DataDirectoryExclusiveLease::acquire(directory.path()).unwrap();
    let storage = Storage::open(directory.path().join("casework.db")).unwrap();
    let mut case = live_case(&storage);
    let before = directory_files(directory.path());

    let result = successful_status(status(directory.path(), &case.id, Some("live-run")));
    assert_eq!(result["case_status"], "scanning");
    assert_eq!(result["runs"][0]["engine_runs"][0]["status"], "running");
    assert_eq!(result["runs"][0]["engine_runs"][0]["progress_percent"], 42);
    assert_eq!(directory_files(directory.path()), before);
    assert_eq!(saved_revision(&storage, &case.id), 1);
    assert_eq!(storage.list_case_events(&case.id).unwrap().len(), 1);

    // This update remains in the owner's WAL. An immutable=1 shortcut would
    // miss it and could misreport the state of an actively running assessment.
    case.scan_runs[0].engine_runs[0].progress_percent = 73;
    storage.save_case(&mut case, "fixture.checkpoint").unwrap();
    let result = successful_status(status(directory.path(), &case.id, None));
    assert_eq!(result["runs"][0]["engine_runs"][0]["progress_percent"], 73);
    assert_eq!(saved_revision(&storage, &case.id), 2);
    assert_eq!(storage.list_case_events(&case.id).unwrap().len(), 2);
}

#[test]
fn missing_data_directory_or_database_is_not_created() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing").join("nested");
    for data_directory in [missing.as_path(), directory.path()] {
        let output = status(data_directory, "missing-case", None);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("existing case database"));
    }
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn unknown_case_and_run_fail_without_changing_saved_data() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(directory.path().join("casework.db")).unwrap();
    let case = live_case(&storage);
    let before = directory_files(directory.path());
    for (case_id, run_id) in [
        ("unknown-case", None),
        (case.id.as_str(), Some("unknown-run")),
    ] {
        let output = status(directory.path(), case_id, run_id);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("not found"));
    }
    assert_eq!(directory_files(directory.path()), before);
    assert_eq!(storage.list_cases().unwrap().len(), 1);
    assert_eq!(saved_revision(&storage, &case.id), 1);
}

#[test]
fn legacy_and_unknown_schema_are_refused_without_migration() {
    for version in [1, 3] {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("casework.db");
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
                 CREATE TABLE cases (id TEXT PRIMARY KEY, document_json TEXT NOT NULL);",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, 'fixture')",
                [version],
            )
            .unwrap();
        drop(connection);
        let before = directory_files(directory.path());

        let output = status(directory.path(), "unused-case", None);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("schema"));
        assert_eq!(directory_files(directory.path()), before);
    }
}

#[test]
fn read_only_storage_rejects_writes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("casework.db");
    let storage = Storage::open(&path).unwrap();
    let case = live_case(&storage);
    let reader = Storage::open_read_only(&path).unwrap();
    let mut loaded = reader.get_case(&case.id).unwrap();
    loaded.title = "Cannot persist from a reader".into();
    assert!(reader.save_case(&mut loaded, "forbidden").is_err());
    assert!(reader.set_selected_case(Some(&case.id)).is_err());
    assert_eq!(storage.get_case(&case.id).unwrap().title, case.title);
    assert_eq!(saved_revision(&storage, &case.id), 1);
}

#[cfg(unix)]
#[test]
fn status_reads_os_read_only_database_without_changing_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(directory.path().join("casework.db")).unwrap();
    let case = live_case(&storage);
    let paths = fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    // Keep the owner's WAL and SHM readable, including the uncheckpointed case.
    // SQLite cannot read a WAL database on read-only media without its sidecars.
    for path in &paths {
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let before = directory_files(directory.path());
    let output = status(directory.path(), &case.id, None);
    let after = directory_files(directory.path());
    let modes = paths
        .iter()
        .map(|path| fs::metadata(path).unwrap().permissions().mode() & 0o777)
        .collect::<Vec<_>>();
    let directory_mode = fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777;
    // Restore test-owned permissions even if a subsequent assertion fails.
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    for path in &paths {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let result = successful_status(output);
    assert_eq!(result["runs"][0]["engine_runs"][0]["progress_percent"], 42);
    assert_eq!(before, after);
    assert_eq!(directory_mode, 0o500);
    assert!(modes.into_iter().all(|mode| mode == 0o400));
}
