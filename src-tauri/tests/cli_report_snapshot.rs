#![cfg(feature = "cli")]

#[allow(dead_code)]
#[path = "../src/test_temp.rs"]
mod test_temp;

#[path = "support/report_version.rs"]
mod report_version;

use ai_security_scanner_lib::domain::{AssessmentCase, FindingStatus, FindingWorkflowEvent};
use ai_security_scanner_lib::storage::Storage;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use flate2::read::GzDecoder;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/fixtures/report-fidelity/all-detectors")
        .join(name);
    let mut bytes = Vec::new();
    GzDecoder::new(fs::File::open(path).unwrap())
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}

fn saved_case(data_dir: &Path) -> AssessmentCase {
    fs::create_dir_all(data_dir).unwrap();
    let mut case: AssessmentCase = serde_json::from_slice(&fixture_bytes("case.json.gz")).unwrap();
    let storage = Storage::open(data_dir.join("casework.db")).unwrap();
    storage
        .save_case(&mut case, "fixture.report_snapshot")
        .unwrap();
    // These directories model the original runtime/source workspace. No real
    // source, scan target, credential or external scanner is used by this test.
    fs::create_dir_all(data_dir.join("artifacts")).unwrap();
    fs::create_dir_all(data_dir.join("workspace")).unwrap();
    case
}

fn cli(data_dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ai-security-scanner-cli"));
    command.arg("--data-dir").arg(data_dir).arg("--json");
    // The CLI executable is an absolute Cargo-provided path. Any accidental
    // attempt to find a scanner/runtime command through PATH must fail.
    command.env("PATH", data_dir.join("no-external-commands"));
    command
}

fn snapshot(
    data_dir: &Path,
    case: &AssessmentCase,
    destination: &Path,
    locale: &str,
    redaction: &str,
) -> Output {
    cli(data_dir)
        .args(["report", "snapshot", "--case-id", &case.id, "--run-id"])
        .arg(&case.scan_runs.last().unwrap().id)
        .arg("--destination")
        .arg(destination)
        .args([
            "--acknowledge-private-context",
            "--locale",
            locale,
            "--redaction",
            redaction,
        ])
        .output()
        .unwrap()
}

fn inspect(data_dir: &Path, snapshot: &Path) -> Output {
    cli(data_dir)
        .args(["report", "inspect", "--snapshot"])
        .arg(snapshot)
        .output()
        .unwrap()
}

fn saved_document(
    data_dir: &Path,
    operation: &str,
    snapshot: &Path,
    format: &str,
    destination: &Path,
) -> Output {
    cli(data_dir)
        .args(["report", operation, "--snapshot"])
        .arg(snapshot)
        .args(["--format", format, "--destination"])
        .arg(destination)
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
        "failure must not emit a success receipt"
    );
    String::from_utf8(output.stderr).unwrap()
}

fn snapshot_value(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn original(snapshot: &Value, format: &str) -> Vec<u8> {
    BASE64
        .decode(
            snapshot[format!("original_{format}")]["bytes"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
}

fn assert_receipt(receipt: &Value, operation: &str, path: &Path, expected: &[u8]) {
    assert_eq!(
        receipt["schema_version"],
        "ai-security-scanner.report-snapshot-receipt/v1"
    );
    assert_eq!(receipt["operation"], operation);
    assert_eq!(receipt["sha256"], sha256(expected));
    assert_eq!(receipt["byte_length"], expected.len() as u64);
    assert_eq!(
        PathBuf::from(receipt["path"].as_str().unwrap()),
        fs::canonicalize(path).unwrap()
    );
    assert_eq!(fs::read(path).unwrap(), expected);
}

#[test]
fn saved_reports_replay_and_retrieve_after_original_case_and_workspace_are_removed() {
    for (locale, redaction, disclosure) in
        [("en", "none", "full"), ("zh-Hant", "standard", "standard")]
    {
        let directory = test_temp::tempdir().unwrap();
        let data_dir = directory.path().join("original-workspace");
        let case = saved_case(&data_dir);
        let path = directory.path().join("saved-report.json");
        let receipt = success(snapshot(&data_dir, &case, &path, locale, redaction));
        assert_receipt(&receipt, "snapshot", &path, &fs::read(&path).unwrap());
        let frozen = snapshot_value(&path);
        let snapshot_id = frozen["snapshot_id"].clone();
        for format in ["html", "json"] {
            assert_eq!(
                report_version::normalize(
                    &format!("{locale}-{disclosure}.{format}"),
                    &original(&frozen, format),
                    &report_version::baseline_version(),
                ),
                fixture_bytes(&format!("{locale}-{disclosure}.{format}.gz")),
                "CLI must preserve the reviewed production {locale}/{format} output"
            );
        }

        // Mutate both current presentation context and human triage, then show
        // that a new snapshot captures them while the first remains immutable.
        {
            let storage = Storage::open(data_dir.join("casework.db")).unwrap();
            let mut changed = storage.get_case(&case.id).unwrap();
            changed.title = "Changed after the original snapshot".into();
            changed.profile.organization_name = "Later organization".into();
            let finding = changed.findings.first_mut().unwrap();
            let from_status = finding.status.clone();
            finding.status = FindingStatus::FalsePositive;
            changed.finding_workflow_events.push(FindingWorkflowEvent {
                id: "later-triage-event".into(),
                case_id: changed.id.clone(),
                finding_id: finding.id.clone(),
                from_status,
                to_status: FindingStatus::FalsePositive,
                decided_by: "fixture-reviewer".into(),
                decided_at: chrono::Utc::now(),
                reason: "Synthetic post-snapshot triage mutation".into(),
                expires_at: None,
            });
            storage
                .save_case(&mut changed, "fixture.after_snapshot")
                .unwrap();
        }
        let later_path = directory.path().join("later-report.json");
        success(snapshot(&data_dir, &case, &later_path, locale, redaction));
        let later = snapshot_value(&later_path);
        assert_ne!(later["snapshot_id"], snapshot_id);
        assert_ne!(later["inputs"]["sha256"], frozen["inputs"]["sha256"]);
        let later_inputs: Value = serde_json::from_slice(
            &BASE64
                .decode(later["inputs"]["bytes"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            later_inputs["case"]["title"],
            "Changed after the original snapshot"
        );
        assert_eq!(
            later_inputs["case"]["finding_workflow_events"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()["to_status"],
            "false_positive"
        );
        if redaction == "none" {
            assert_ne!(original(&later, "html"), original(&frozen, "html"));
        }
        fs::remove_dir_all(&data_dir).unwrap();
        let missing_data = directory.path().join("never-created").join("data");
        let inspection = success(inspect(&missing_data, &path));
        assert_eq!(inspection["integrity_valid"], true);
        assert_eq!(inspection["replay_available"], true);
        assert_eq!(inspection["contains_sensitive_context"], true);
        assert_eq!(inspection["case_restore_available"], false);
        assert_eq!(inspection["locale"], locale);
        assert_eq!(inspection["redaction"], redaction);
        assert_eq!(inspection["snapshot_id"], snapshot_id);
        for operation in ["replay", "retrieve"] {
            for format in ["html", "json"] {
                let destination = directory.path().join(format!("{operation}.{format}"));
                let expected = original(&frozen, format);
                let receipt = success(saved_document(
                    &missing_data,
                    operation,
                    &path,
                    format,
                    &destination,
                ));
                assert_receipt(&receipt, operation, &destination, &expected);
                assert_eq!(receipt["snapshot_id"], snapshot_id);
                assert_eq!(
                    inspection[format!("original_{format}_sha256")],
                    sha256(&expected)
                );
            }
        }
        assert!(
            !data_dir.exists(),
            "original database/artifact workspace was recreated"
        );
        assert!(
            !missing_data.parent().unwrap().exists(),
            "offline report operations created a data root"
        );
        assert_eq!(
            snapshot_value(&path),
            frozen,
            "original snapshot was rewritten"
        );
    }
}

#[test]
fn unavailable_renderer_is_retrieve_only_and_does_not_create_a_workspace() {
    let directory = test_temp::tempdir().unwrap();
    let data_dir = directory.path().join("source");
    let case = saved_case(&data_dir);
    let path = directory.path().join("future-renderer.json");
    success(snapshot(&data_dir, &case, &path, "en", "none"));
    let mut frozen = snapshot_value(&path);
    frozen["renderer"]["recipe"] = "future-incompatible-recipe".into();
    fs::write(&path, serde_json::to_vec(&frozen).unwrap()).unwrap();
    fs::remove_dir_all(&data_dir).unwrap();
    let missing_data = directory.path().join("absent");
    let inspection = success(inspect(&missing_data, &path));
    assert_eq!(inspection["integrity_valid"], true);
    assert_eq!(inspection["replay_available"], false);
    assert!(
        inspection["replay_unavailable_reason"]
            .as_str()
            .unwrap()
            .contains("original files can be retrieved")
    );
    for format in ["html", "json"] {
        let replay = directory
            .path()
            .join("rejected-replay")
            .join(format!("report.{format}"));
        assert!(
            failure(saved_document(
                &missing_data,
                "replay",
                &path,
                format,
                &replay
            ))
            .contains("compatible report renderer unavailable")
        );
        assert!(!replay.parent().unwrap().exists());
        let destination = directory.path().join(format!("retrieved.{format}"));
        let receipt = success(saved_document(
            &missing_data,
            "retrieve",
            &path,
            format,
            &destination,
        ));
        assert_receipt(
            &receipt,
            "retrieve",
            &destination,
            &original(&frozen, format),
        );
    }
    assert!(!missing_data.exists());
}

#[test]
fn corrupt_snapshot_hashes_fail_inspection_replay_and_retrieval_without_output() {
    let directory = test_temp::tempdir().unwrap();
    let data_dir = directory.path().join("source");
    let case = saved_case(&data_dir);
    let original_path = directory.path().join("valid.json");
    success(snapshot(&data_dir, &case, &original_path, "en", "standard"));
    let frozen = snapshot_value(&original_path);
    fs::remove_dir_all(&data_dir).unwrap();
    for field in ["inputs", "original_html", "original_json"] {
        let mut corrupted = frozen.clone();
        corrupted[field]["sha256"] = "0".repeat(64).into();
        let path = directory.path().join(format!("corrupt-{field}.json"));
        fs::write(&path, serde_json::to_vec(&corrupted).unwrap()).unwrap();
        assert!(failure(inspect(&data_dir, &path)).contains("digest does not match"));
        for operation in ["replay", "retrieve"] {
            for format in ["html", "json"] {
                let destination = directory
                    .path()
                    .join("must-not-be-created")
                    .join(format!("{field}-{operation}.{format}"));
                assert!(
                    failure(saved_document(
                        &data_dir,
                        operation,
                        &path,
                        format,
                        &destination
                    ))
                    .contains("digest does not match")
                );
                assert!(!destination.parent().unwrap().exists());
            }
        }
    }
    assert!(!data_dir.exists());
}

#[test]
fn snapshot_replay_and_retrieve_refuse_to_overwrite_selected_destinations() {
    let directory = test_temp::tempdir().unwrap();
    let data_dir = directory.path().join("source");
    let case = saved_case(&data_dir);
    let path = directory.path().join("report.json");
    success(snapshot(&data_dir, &case, &path, "en", "standard"));
    let before = fs::read(&path).unwrap();
    assert!(
        failure(snapshot(&data_dir, &case, &path, "en", "standard")).contains("already exists")
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    fs::remove_dir_all(&data_dir).unwrap();
    for operation in ["replay", "retrieve"] {
        for format in ["html", "json"] {
            let destination = directory
                .path()
                .join(format!("existing-{operation}.{format}"));
            fs::write(&destination, b"existing user document").unwrap();
            assert!(
                failure(saved_document(
                    &data_dir,
                    operation,
                    &path,
                    format,
                    &destination
                ))
                .contains("already exists")
            );
            assert_eq!(fs::read(&destination).unwrap(), b"existing user document");
        }
    }
    assert!(!data_dir.exists());
}

#[test]
fn private_context_acknowledgement_is_required_before_accessing_or_creating_data() {
    let directory = test_temp::tempdir().unwrap();
    let data_dir = directory.path().join("missing-workspace");
    let destination = directory.path().join("output").join("snapshot.json");
    let output = cli(&data_dir)
        .args([
            "report",
            "snapshot",
            "--case-id",
            "absent",
            "--run-id",
            "absent",
            "--destination",
        ])
        .arg(&destination)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "missing acknowledgement must be a parser error"
    );
    assert!(failure(output).contains("--acknowledge-private-context"));
    assert!(!data_dir.exists());
    assert!(!destination.parent().unwrap().exists());
}

fn export_document(
    data: &Path,
    case: &AssessmentCase,
    format: &str,
    locale: &str,
    redaction: &str,
    destination: &Path,
) -> Output {
    cli(data)
        .args([
            "export",
            "create",
            "--case-id",
            &case.id,
            "--run-id",
            &case.scan_runs.last().unwrap().id,
            "--format",
            format,
            "--locale",
            locale,
            "--redaction",
            redaction,
            "--destination",
        ])
        .arg(destination)
        .output()
        .unwrap()
}

#[test]
fn ordinary_exports_keep_private_snapshots_of_the_exact_shared_documents() {
    for (format, locale, redaction, disclosure) in [
        ("html", "zh-Hant", "standard", "standard"),
        ("json", "en", "none", "full"),
    ] {
        let directory = test_temp::tempdir().unwrap();
        let data = directory.path().join("data");
        let case = saved_case(&data);
        let destination = directory.path().join(format!("shared.{format}"));
        let receipt = success(export_document(
            &data,
            &case,
            format,
            locale,
            redaction,
            &destination,
        ));
        let reference = &receipt["report_snapshot"];
        let path = data
            .join("artifacts")
            .join(reference["relative_path"].as_str().unwrap());
        let bytes = fs::read(&path).unwrap();
        assert_eq!(reference["sha256"], sha256(&bytes));
        assert_eq!(reference["byte_length"], bytes.len() as u64);
        let inspection = success(inspect(&data, &path));
        assert_eq!(inspection["snapshot_id"], reference["snapshot_id"]);
        assert_eq!(inspection["locale"], locale);
        assert_eq!(inspection["redaction"], redaction);
        assert_eq!(inspection["contains_sensitive_context"], true);
        assert_eq!(
            report_version::normalize(
                &format!("{locale}-{disclosure}.{format}"),
                &fs::read(&destination).unwrap(),
                &report_version::baseline_version(),
            ),
            fixture_bytes(&format!("{locale}-{disclosure}.{format}.gz"))
        );
        assert_eq!(
            original(&snapshot_value(&path), format),
            fs::read(&destination).unwrap()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }
        {
            let storage = Storage::open(data.join("casework.db")).unwrap();
            let mut changed = storage.get_case(&case.id).unwrap();
            assert_eq!(
                serde_json::to_value(&changed.exports.last().unwrap().report_snapshot).unwrap(),
                *reference
            );
            changed.title = "Changed after sharing the report".into();
            changed.profile.organization_name = "Later organization".into();
            let finding = changed.findings.first_mut().unwrap();
            let from_status = finding.status.clone();
            finding.status = FindingStatus::FalsePositive;
            changed.finding_workflow_events.push(FindingWorkflowEvent {
                id: "post-export-triage".into(),
                case_id: changed.id.clone(),
                finding_id: finding.id.clone(),
                from_status,
                to_status: FindingStatus::FalsePositive,
                decided_by: "fixture-reviewer".into(),
                decided_at: chrono::Utc::now(),
                reason: "Synthetic post-export review".into(),
                expires_at: None,
            });
            storage.save_case(&mut changed, "fixture.updated").unwrap();
        }
        let newer = success(export_document(
            &data,
            &case,
            format,
            locale,
            redaction,
            &directory.path().join(format!("newer.{format}")),
        ));
        assert_ne!(
            newer["report_snapshot"]["snapshot_id"],
            reference["snapshot_id"]
        );
        let newer_path = data
            .join("artifacts")
            .join(newer["report_snapshot"]["relative_path"].as_str().unwrap());
        let newer_snapshot = snapshot_value(&newer_path);
        assert_ne!(
            newer_snapshot["inputs"]["sha256"],
            snapshot_value(&path)["inputs"]["sha256"]
        );
        let newer_inputs: Value = serde_json::from_slice(
            &BASE64
                .decode(newer_snapshot["inputs"]["bytes"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            newer_inputs["case"]["title"],
            "Changed after sharing the report"
        );
        assert_eq!(
            newer_inputs["case"]["finding_workflow_events"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()["to_status"],
            "false_positive"
        );
        fs::remove_file(&destination).unwrap();
        let retrieved = directory.path().join(format!("reopened.{format}"));
        success(saved_document(&data, "retrieve", &path, format, &retrieved));
        assert_eq!(sha256(&fs::read(retrieved).unwrap()), receipt["sha256"]);
        assert_eq!(
            fs::read(path).unwrap(),
            bytes,
            "a later export cannot rewrite the earlier presentation"
        );
    }
}

#[test]
fn export_failures_roll_back_new_documents_and_private_snapshots() {
    for fault in [
        "occupied_destination",
        "history_write",
        "snapshot_directory",
    ] {
        let directory = test_temp::tempdir().unwrap();
        let data = directory.path().join("data");
        let case = saved_case(&data);
        let destination = directory.path().join("shared.html");
        let snapshot_dir = data
            .join("artifacts")
            .join(&case.id)
            .join("report-snapshots");
        match fault {
            "occupied_destination" => fs::write(&destination, b"existing user document").unwrap(),
            "history_write" => rusqlite::Connection::open(data.join("casework.db"))
                .unwrap()
                .execute_batch(
                    "CREATE TRIGGER refuse_export_history BEFORE INSERT ON case_events
                 WHEN NEW.event_type = 'export.schema_created'
                 BEGIN SELECT RAISE(ABORT, 'fixture refuses export history'); END;",
                )
                .unwrap(),
            "snapshot_directory" => {
                fs::create_dir_all(snapshot_dir.parent().unwrap()).unwrap();
                fs::write(&snapshot_dir, b"existing user file").unwrap();
            }
            _ => unreachable!(),
        }
        failure(export_document(
            &data,
            &case,
            "html",
            "en",
            "standard",
            &destination,
        ));
        if fault == "occupied_destination" {
            assert_eq!(fs::read(&destination).unwrap(), b"existing user document");
        } else {
            assert!(!destination.exists());
        }
        if snapshot_dir.is_dir() {
            assert_eq!(
                fs::read_dir(&snapshot_dir).unwrap().count(),
                0,
                "failed export left private context behind"
            );
        } else {
            assert_eq!(fs::read(snapshot_dir).unwrap(), b"existing user file");
        }
        let saved = Storage::open_read_only(data.join("casework.db"))
            .unwrap()
            .get_case(&case.id)
            .unwrap();
        assert_eq!(saved.exports.len(), case.exports.len());
        assert_eq!(saved.storage_revision(), case.storage_revision());
    }
}

fn ready_terminal_case(data: &Path) -> AssessmentCase {
    let mut case = saved_case(data);
    case.is_demo = false;
    let run = case.scan_runs.last_mut().unwrap();
    for task in &mut run.engine_runs {
        task.status = ai_security_scanner_lib::domain::EngineRunStatus::Completed;
        task.phase = "completed".into();
        task.resume_token = None;
        task.cleanup_removed = Some(true);
    }
    Storage::open(data.join("casework.db"))
        .unwrap()
        .save_case(&mut case, "fixture.clean_terminal")
        .unwrap();
    case
}

fn retain_terminal(
    data: &Path,
    case: &AssessmentCase,
) -> ai_security_scanner_lib::error::AppResult<AssessmentCase> {
    use ai_security_scanner_lib::{
        adapters::builtin_adapter_registry, case_service::CaseService, registry::EngineRegistry,
    };
    let storage = Storage::open(data.join("casework.db"))?;
    let engines = EngineRegistry::load_builtin()?;
    let adapters = builtin_adapter_registry()?;
    CaseService::new(
        &storage,
        &engines,
        &adapters,
        data.join("artifacts"),
        data.join("key"),
    )
    .retain_terminal_report_snapshot(&case.id, &case.scan_runs.last().unwrap().id)
}

#[test]
fn terminal_snapshots_are_idempotent_after_triage_and_preserve_changed_run_outcomes() {
    let directory = test_temp::tempdir().unwrap();
    let data = directory.path().join("data");
    let case = ready_terminal_case(&data);
    let first = retain_terminal(&data, &case).unwrap();
    assert_eq!(first.run_report_snapshots.len(), 1);
    let record = &first.run_report_snapshots[0];
    let path = data.join("artifacts").join(&record.snapshot.relative_path);
    let bytes = fs::read(&path).unwrap();
    let same = retain_terminal(&data, &case).unwrap();
    assert_eq!(first.storage_revision(), same.storage_revision());
    let storage = Storage::open(data.join("casework.db")).unwrap();
    let mut changed = same;
    changed.title = "Edited after completion".into();
    changed.findings[0].status = FindingStatus::Confirmed;
    storage.save_case(&mut changed, "fixture.triaged").unwrap();
    let retried = retain_terminal(&data, &case).unwrap();
    assert_eq!(retried.storage_revision(), changed.storage_revision());
    assert_eq!(retried.run_report_snapshots.len(), 1);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    // Recovery can settle a different outcome on the same run. Retain both.
    let task = &mut changed.scan_runs.last_mut().unwrap().engine_runs[0];
    task.status = ai_security_scanner_lib::domain::EngineRunStatus::Failed;
    task.error_code = Some("fixture_failed".into());
    storage
        .save_case(&mut changed, "fixture.new_outcome")
        .unwrap();
    let newer = retain_terminal(&data, &case).unwrap();
    assert_eq!(newer.run_report_snapshots.len(), 2);
    assert_ne!(
        newer.run_report_snapshots[0].snapshot.snapshot_id,
        newer.run_report_snapshots[1].snapshot.snapshot_id
    );
    assert_eq!(fs::read(path).unwrap(), bytes);
    let current_path = data
        .join("artifacts")
        .join(&newer.run_report_snapshots[1].snapshot.relative_path);
    fs::write(&current_path, b"corrupted saved original").unwrap();
    assert!(
        retain_terminal(&data, &case).is_err(),
        "never silently regenerate a recorded original"
    );
    assert_eq!(fs::read(current_path).unwrap(), b"corrupted saved original");
    assert_eq!(
        storage.get_case(&case.id).unwrap().storage_revision(),
        newer.storage_revision()
    );
}

#[test]
fn terminal_snapshot_history_failure_rolls_back_private_file_and_retries() {
    let directory = test_temp::tempdir().unwrap();
    let data = directory.path().join("data");
    let case = ready_terminal_case(&data);
    let connection = rusqlite::Connection::open(data.join("casework.db")).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER refuse_terminal_snapshot BEFORE INSERT ON case_events
        WHEN NEW.event_type = 'report.terminal_snapshot_saved'
        BEGIN SELECT RAISE(ABORT, 'synthetic persistence failure'); END;",
        )
        .unwrap();
    assert!(retain_terminal(&data, &case).is_err());
    let current = Storage::open_read_only(data.join("casework.db"))
        .unwrap()
        .get_case(&case.id)
        .unwrap();
    assert_eq!(current.storage_revision(), case.storage_revision());
    assert!(current.run_report_snapshots.is_empty());
    assert_eq!(
        fs::read_dir(
            data.join("artifacts")
                .join(&case.id)
                .join("report-snapshots")
        )
        .unwrap()
        .count(),
        0
    );
    connection
        .execute_batch("DROP TRIGGER refuse_terminal_snapshot")
        .unwrap();
    assert_eq!(
        retain_terminal(&data, &case)
            .unwrap()
            .run_report_snapshots
            .len(),
        1
    );
}

#[test]
fn active_cleanup_and_unverified_checkpoints_do_not_create_terminal_reports() {
    use ai_security_scanner_lib::domain::EngineRunStatus;
    for (status, phase, checkpoint) in [
        (EngineRunStatus::Running, "running", None),
        (EngineRunStatus::PartiallyCompleted, "cleanup_pending", None),
        (
            EngineRunStatus::Failed,
            "failed",
            Some("invalid-checkpoint"),
        ),
    ] {
        let directory = test_temp::tempdir().unwrap();
        let data = directory.path().join("data");
        let mut case = ready_terminal_case(&data);
        let task = &mut case.scan_runs.last_mut().unwrap().engine_runs[0];
        task.status = status;
        task.phase = phase.into();
        task.resume_token = checkpoint.map(str::to_owned);
        Storage::open(data.join("casework.db"))
            .unwrap()
            .save_case(&mut case, "fixture.pending")
            .unwrap();
        let unchanged = retain_terminal(&data, &case).unwrap();
        assert_eq!(unchanged.storage_revision(), case.storage_revision());
        assert!(unchanged.run_report_snapshots.is_empty());
        assert!(
            !data
                .join("artifacts")
                .join(&case.id)
                .join("report-snapshots")
                .exists()
        );
    }
}

fn combined_case(data: &Path) -> AssessmentCase {
    use ai_security_scanner_lib::domain::{ScanRequestOutcome, ScanRequestOutcomeCode, new_id};
    let mut case = saved_case(data);
    let mut run = case.scan_runs[0].clone();
    run.id = new_id();
    run.sequence = case.scan_runs.iter().map(|run| run.sequence).max().unwrap() + 1;
    run.created_at += chrono::Duration::minutes(1);
    run.completed_at = Some(run.created_at);
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
    Storage::open(data.join("casework.db"))
        .unwrap()
        .save_case(&mut case, "fixture.combined")
        .unwrap();
    case
}

fn combined_export(
    data: &Path,
    case: &AssessmentCase,
    ids: &[String],
    format: &str,
    locale: &str,
    destination: &Path,
) -> Output {
    cli(data)
        .args([
            "export",
            "combine",
            "--case-id",
            &case.id,
            "--run-id",
            &ids.join(","),
            "--format",
            format,
            "--locale",
            locale,
            "--destination",
        ])
        .arg(destination)
        .output()
        .unwrap()
}

#[test]
fn combined_exports_freeze_ordered_sources_and_replay_without_the_original_workspace() {
    for (format, locale) in [("html", "zh-Hant"), ("json", "en")] {
        let directory = test_temp::tempdir().unwrap();
        let data = directory.path().join("data");
        let case = combined_case(&data);
        let ids: Vec<_> = case
            .scan_runs
            .iter()
            .rev()
            .map(|run| run.id.clone())
            .collect();
        let shared = directory.path().join(format!("combined.{format}"));
        let export = success(combined_export(&data, &case, &ids, format, locale, &shared));
        assert_eq!(export["selected_run_ids"], serde_json::json!(ids));
        let reference = &export["report_snapshot"];
        let path = data
            .join("artifacts")
            .join(reference["relative_path"].as_str().unwrap());
        let bytes = fs::read(&shared).unwrap();
        let snapshot = snapshot_value(&path);
        assert_eq!(
            snapshot["schema_version"],
            "ai-security-scanner.report-snapshot/v2"
        );
        assert!(snapshot.get("run_id").is_none());
        assert_eq!(snapshot["selected_run_ids"], serde_json::json!(ids));
        assert_eq!(original(&snapshot, format), bytes);
        let projection: Value = serde_json::from_slice(&original(&snapshot, "json")).unwrap();
        assert_eq!(projection["sources"][0]["origin"], "no_checks");
        assert_eq!(projection["sources"][0]["run_id"], ids[0]);
        assert_eq!(projection["sources"][1]["run_id"], ids[1]);
        assert_eq!(projection["generated_at"], export["created_at"]);
        let storage = Storage::open(data.join("casework.db")).unwrap();
        let mut changed = storage.get_case(&case.id).unwrap();
        assert_eq!(
            serde_json::to_value(&changed.combined_exports[0]).unwrap(),
            export
        );
        changed.title = "Later title must not replace the saved combined report".into();
        changed.findings[0].status = FindingStatus::FalsePositive;
        storage
            .save_case(&mut changed, "fixture.later_triage")
            .unwrap();
        drop(storage);
        let reversed: Vec<_> = ids.iter().rev().cloned().collect();
        let newer = success(combined_export(
            &data,
            &case,
            &reversed,
            format,
            locale,
            &directory.path().join(format!("newer.{format}")),
        ));
        assert_ne!(
            newer["report_snapshot"]["snapshot_id"],
            reference["snapshot_id"]
        );
        let retained = directory.path().join("retained-combined.json");
        fs::copy(&path, &retained).unwrap();
        fs::remove_file(shared).unwrap();
        fs::rename(&data, directory.path().join("unavailable-original")).unwrap();
        for output_format in ["html", "json"] {
            for operation in ["retrieve", "replay"] {
                let destination = directory
                    .path()
                    .join(format!("{operation}.{output_format}"));
                success(saved_document(
                    &data,
                    operation,
                    &retained,
                    output_format,
                    &destination,
                ));
                assert_eq!(
                    fs::read(destination).unwrap(),
                    original(&snapshot, output_format)
                );
            }
        }
        assert!(
            !data.exists(),
            "offline report operations must not create a workspace"
        );
    }
}

#[test]
fn combined_manual_snapshots_validate_sources_and_preserve_retrieve_only_compatibility() {
    let directory = test_temp::tempdir().unwrap();
    let data = directory.path().join("data");
    let case = combined_case(&data);
    let ids: Vec<_> = case.scan_runs.iter().map(|run| run.id.clone()).collect();
    let path = directory.path().join("manual-combined.json");
    success(
        cli(&data)
            .args([
                "report",
                "snapshot",
                "--case-id",
                &case.id,
                "--run-id",
                &ids[0],
                "--run-id",
                &ids[1],
                "--acknowledge-private-context",
                "--destination",
            ])
            .arg(&path)
            .output()
            .unwrap(),
    );
    let saved = Storage::open_read_only(data.join("casework.db"))
        .unwrap()
        .get_case(&case.id)
        .unwrap();
    assert_eq!(saved.storage_revision(), case.storage_revision());
    assert!(saved.combined_exports.is_empty());
    let inspection = success(
        cli(&data)
            .args(["report", "inspect", "--snapshot"])
            .arg(&path)
            .output()
            .unwrap(),
    );
    assert_eq!(inspection["selected_run_ids"], serde_json::json!(ids));
    let mut snapshot = snapshot_value(&path);
    let original_json = original(&snapshot, "json");
    snapshot["renderer"]["source_sha256"] = Value::String("f".repeat(64));
    let mut future_inputs: Value = serde_json::from_slice(
        &BASE64
            .decode(snapshot["inputs"]["bytes"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    future_inputs["case"]["scan_runs"][0]["engine_runs"][0]["status"] =
        "future-terminal-variant".into();
    let future_bytes = serde_json::to_vec(&future_inputs).unwrap();
    snapshot["inputs"]["bytes"] = BASE64.encode(&future_bytes).into();
    snapshot["inputs"]["sha256"] = sha256(&future_bytes).into();
    snapshot["inputs"]["byte_length"] = (future_bytes.len() as u64).into();
    fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let future = success(
        cli(&data)
            .args(["report", "inspect", "--snapshot"])
            .arg(&path)
            .output()
            .unwrap(),
    );
    assert_eq!(future["replay_available"], false);
    let destination = directory.path().join("future.json");
    failure(saved_document(&data, "replay", &path, "json", &destination));
    assert!(!destination.exists());
    success(saved_document(
        &data,
        "retrieve",
        &path,
        "json",
        &destination,
    ));
    assert_eq!(fs::read(destination).unwrap(), original_json);
    // A foreign ordered source list cannot masquerade as the saved document.
    snapshot["selected_run_ids"]
        .as_array_mut()
        .unwrap()
        .reverse();
    fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    failure(
        cli(&data)
            .args(["report", "inspect", "--snapshot"])
            .arg(&path)
            .output()
            .unwrap(),
    );
    for invalid in [
        vec![ids[0].clone(), ids[0].clone()],
        vec![ids[0].clone(), "missing".into()],
    ] {
        let output = directory.path().join("invalid.html");
        failure(combined_export(
            &data, &case, &invalid, "html", "en", &output,
        ));
        assert!(!output.exists());
    }
}

#[test]
fn combined_export_publication_failure_preserves_destinations_and_history() {
    for fault in ["history", "occupied", "snapshot_directory"] {
        let directory = test_temp::tempdir().unwrap();
        let data = directory.path().join("data");
        let case = combined_case(&data);
        let ids: Vec<_> = case.scan_runs.iter().map(|run| run.id.clone()).collect();
        let destination = directory.path().join("combined.html");
        let snapshots = data
            .join("artifacts")
            .join(&case.id)
            .join("report-snapshots");
        match fault {
            "history" => {
                rusqlite::Connection::open(data.join("casework.db")).unwrap().execute_batch(
                "CREATE TRIGGER refuse_combined BEFORE INSERT ON case_events WHEN NEW.event_type = 'export.combined_created'
                 BEGIN SELECT RAISE(ABORT, 'synthetic history failure'); END;").unwrap();
            }
            "occupied" => fs::write(&destination, b"existing report").unwrap(),
            "snapshot_directory" => {
                fs::create_dir_all(snapshots.parent().unwrap()).unwrap();
                fs::write(&snapshots, b"existing file").unwrap();
            }
            _ => unreachable!(),
        }
        failure(combined_export(
            &data,
            &case,
            &ids,
            "html",
            "en",
            &destination,
        ));
        if fault == "occupied" {
            assert_eq!(fs::read(destination).unwrap(), b"existing report");
        } else {
            assert!(!destination.exists());
        }
        if snapshots.is_dir() {
            assert_eq!(fs::read_dir(snapshots).unwrap().count(), 0);
        }
        let saved = Storage::open_read_only(data.join("casework.db"))
            .unwrap()
            .get_case(&case.id)
            .unwrap();
        assert_eq!(saved.storage_revision(), case.storage_revision());
        assert!(saved.combined_exports.is_empty());
    }
}
