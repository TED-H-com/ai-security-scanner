use super::{finalize, fixture::*};
use ai_security_scanner_lib::{
    agent_audit_admission::ADMITTED_EVENT,
    artifact_store::inspect_raw_artifacts,
    cloudflare_provider::audit::sealed::verify,
    domain::{CaseStatus, EngineRunStatus, FindingStatus},
};

pub(super) fn sealed(profile: &str) -> (RunFixture, Value) {
    let run = if profile == "quick" {
        RunFixture::with_records("quick", &[], |records, ledger, metadata| {
            *records = json!([records[1].clone()]);
            ledger[0]["result_fingerprints"] = json!([records[0]["fingerprint"], "unresolved-one"]);
            ledger[0]["unresolved"] = json!(["source work unfinished"]);
            metadata["run_status"] = json!("incomplete");
            metadata["incomplete_reason"] = json!("Host stopped after source review");
        })
    } else {
        RunFixture::new(profile)
    };
    finalize::finalize(&run, &finalize::request(&run), 0);
    let storage = run.f.storage();
    let v = verify(
        &run.f.data,
        &storage,
        &run.f.case_id,
        run.prepared["session_id"].as_str().unwrap(),
    )
    .unwrap();
    let request = json!({
        "schema_version":"ai-security-scanner.cloudflare-audit-admit-request/v1",
        "request_id":"admit-one", "case_id":run.f.case_id,
        "session_id":run.prepared["session_id"],
        "expected_sealed_entry_sha256":v.digests.sealed_entry_sha256,
        "expected_bundle_sha256":v.digests.bundle_sha256,
        "expected_projection_sha256":v.digests.projection_sha256,
    });
    drop(v);
    drop(storage);
    (run, request)
}
fn command(run: &RunFixture, request: &Value) -> Command {
    let path = run.f.data.with_file_name("admit.json");
    fs::write(&path, serde_json::to_vec(request).unwrap()).unwrap();
    let mut c = run.f.command();
    // Fixture commands have an empty PATH: Node and all validators are unavailable.
    c.args(["provider", "cloudflare", "admit", "--request"])
        .arg(path);
    c
}
pub(super) fn admit(run: &RunFixture, request: &Value, code: i32) -> Value {
    terminal(command(run, request).output().unwrap(), code)
}
pub(super) fn case(run: &RunFixture) -> AssessmentCase {
    run.f.storage().get_case(&run.f.case_id).unwrap()
}
fn events(run: &RunFixture) -> Vec<ai_security_scanner_lib::storage::CaseEvent> {
    run.f
        .storage()
        .list_case_events(&run.f.case_id)
        .unwrap()
        .into_iter()
        .filter(|e| e.event_type == ADMITTED_EVENT)
        .collect()
}
pub(super) fn status(run: &RunFixture) -> Value {
    run.f.audit_status("audit-one", false, 0)["result"].clone()
}
fn assert_no_publication_temporaries(directory: &std::path::Path) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            assert_no_publication_temporaries(&entry.path());
        } else {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(
                !(name.starts_with(".admission-") && name.ends_with(".tmp")),
                "leftover publication temporary: {:?}",
                entry.path()
            );
        }
    }
}
#[test]
fn stale_partial_publication_is_removed_and_admission_succeeds() {
    let (run, request) = sealed("standard");
    let storage = run.f.storage();
    let v = verify(
        &run.f.data,
        &storage,
        &run.f.case_id,
        request["session_id"].as_str().unwrap(),
    )
    .unwrap();
    let parent = run
        .f
        .data
        .join("artifacts")
        .join(&run.f.case_id)
        .join(&v.identities.run_id)
        .join(&v.identities.task_id)
        .join("retained/bundle");
    fs::create_dir_all(&parent).unwrap();
    let stale = parent.join(".admission-interrupted.tmp");
    fs::write(&stale, b"partial original").unwrap();
    drop(v);
    drop(storage);
    admit(&run, &request, 0);
    assert!(!stale.exists());
    assert_no_publication_temporaries(&run.f.data.join("artifacts"));
    inspect_raw_artifacts(&run.f.data.join("artifacts"), &case(&run).raw_artifacts).unwrap();
}
#[test]
fn newer_case_format_is_checked_before_request_replay() {
    let (run, request) = sealed("standard");
    admit(&run, &request, 0);
    let mut c = case(&run);
    c.format_requirements.insert("future/v1".into());
    // A newer format may change the admission representation or digest.
    c.agent_audit_admissions[0].counts.confirmed += 1;
    let db = rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap();
    db.execute(
        "UPDATE cases SET document_json=?1 WHERE id=?2",
        rusqlite::params![serde_json::to_string(&c).unwrap(), run.f.case_id],
    )
    .unwrap();
    let rejected = admit(&run, &request, 2);
    assert_eq!(rejected["error_code"], "not_available");
    assert_eq!(rejected["retryable"], false);
    assert!(
        rejected["error"]
            .as_str()
            .unwrap()
            .contains("requires a newer version")
    );
    assert_eq!(
        serde_json::to_value(case(&run)).unwrap(),
        serde_json::to_value(c).unwrap()
    );
    assert_eq!(events(&run).len(), 1);
}
#[test]
fn complete_and_incomplete_admit_without_node_preserve_custody_and_status() {
    for profile in ["standard", "quick"] {
        let (run, request) = sealed(profile);
        let before = status(&run);
        assert_eq!(before["admission_state"], "not_admitted");
        assert_eq!(before["next_operation"], "admit");
        let revision = case(&run).storage_revision();
        let saved = admit(&run, &request, 0);
        assert_eq!(saved["operation"], "provider.cloudflare.admit");
        assert_eq!(saved["command_outcome"], "committed");
        assert_eq!(saved["case_revision"], revision + 1);
        assert_eq!(saved["result"]["validators_reexecuted"], false);
        assert_eq!(saved["result"]["provenance"], "workflow_recorded");
        assert_eq!(
            saved["result"]["native_outcome"],
            if profile == "quick" {
                "incomplete"
            } else {
                "complete"
            }
        );
        assert_no_publication_temporaries(&run.f.data.join("artifacts"));
        let case = case(&run);
        assert_eq!(case.agent_audit_admissions.len(), 1);
        assert!(
            case.format_requirements
                .contains("cloudflare_audit_admission/v1")
        );
        assert_eq!(case.scan_runs.len(), 1);
        let audit = &case.agent_audit_admissions[0];
        assert_eq!(saved["run_id"], audit.identities.run_id);
        assert_eq!(saved["task_id"], audit.identities.task_id);
        assert_eq!(events(&run).len(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(&events(&run)[0].payload_json).unwrap(),
            saved["receipt"]
        );
        inspect_raw_artifacts(&run.f.data.join("artifacts"), &case.raw_artifacts).unwrap();
        let storage = run.f.storage();
        let mut v = verify(
            &run.f.data,
            &storage,
            &run.f.case_id,
            run.prepared["session_id"].as_str().unwrap(),
        )
        .unwrap();
        for binding in &audit.artifacts {
            let raw = case
                .raw_artifacts
                .iter()
                .find(|r| r.id == binding.artifact_id)
                .unwrap();
            assert_eq!(
                fs::read(run.f.data.join("artifacts").join(&raw.relative_path)).unwrap(),
                v.read_member(&binding.member_path).unwrap()
            );
        }
        let task = &case.scan_runs[0].engine_runs[0];
        if profile == "standard" {
            assert_eq!(case.findings.len(), 1);
            assert_eq!(case.finding_observations.len(), 1);
            assert_eq!(task.status, EngineRunStatus::Completed);
        } else {
            assert!(case.findings.is_empty());
            assert_eq!(task.status, EngineRunStatus::PartiallyCompleted);
            assert_eq!(
                task.error_message.as_deref(),
                Some("Host stopped after source review")
            );
        }
        let after = status(&run);
        assert_eq!(after["entries"], before["entries"]);
        assert_eq!(after["record_head"], before["record_head"]);
        assert_eq!(after["sealed"]["projection"]["admission_ready"], false);
        assert_eq!(after["admission_state"], "admitted");
        assert_eq!(
            after["admission"]["admission_id"],
            saved["result"]["admission_id"]
        );
        assert_eq!(after["next_operation"], "retrieve_report");
        assert_eq!(saved["result"]["report_snapshot_state"], "retained");
        assert_eq!(after["report_snapshot"], saved["result"]["report_snapshot"]);
        let inspected = terminal(
            run.f
                .command()
                .args([
                    "provider",
                    "cloudflare",
                    "inspect-sealed",
                    "--case-id",
                    &run.f.case_id,
                    "--session-id",
                    request["session_id"].as_str().unwrap(),
                ])
                .output()
                .unwrap(),
            0,
        );
        assert_eq!(inspected["result"]["admission"], after["admission"]);
        assert_eq!(inspected["result"]["next_operation"], "retrieve_report");
    }
}
#[test]
fn replay_preserves_human_triage_and_original_receipt_after_asset_removal() {
    let (run, request) = sealed("standard");
    let saved = admit(&run, &request, 0);
    run.f.change_case(|c| {
        c.findings[0].status = FindingStatus::Confirmed;
        c.assets.clear();
        c.data_sources.clear();
    });
    let revision = case(&run).storage_revision();
    let replay = admit(&run, &request, 0);
    assert_eq!(replay["command_outcome"], "replayed");
    assert_eq!(replay["receipt"], saved["receipt"]);
    assert_eq!(replay["result"]["replayed"], true);
    assert_eq!(case(&run).storage_revision(), revision);
    assert_eq!(case(&run).findings[0].status, FindingStatus::Confirmed);
    assert_eq!(events(&run).len(), 1);
    assert_eq!(run.f.storage().list_cases().unwrap().len(), 1);
    let mut changed = request.clone();
    changed["expected_bundle_sha256"] = json!("0".repeat(64));
    assert_eq!(admit(&run, &changed, 3)["error_code"], "request_conflict");
    changed["request_id"] = json!("another");
    assert_eq!(
        admit(&run, &changed, 2)["error_code"],
        "session_already_admitted"
    );
    let raw = &case(&run).raw_artifacts[0];
    let path = run.f.data.join("artifacts").join(&raw.relative_path);
    let original = fs::read(&path).unwrap();
    fs::write(&path, b"tamper").unwrap();
    assert_eq!(admit(&run, &request, 2)["error_code"], "admission_mismatch");
    assert_eq!(case(&run).storage_revision(), revision);
    fs::write(&path, original).unwrap();
    let mut tampered = case(&run);
    tampered.agent_audit_admissions[0].counts.confirmed += 1;
    let db = rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap();
    db.execute(
        "UPDATE cases SET document_json=?1 WHERE id=?2",
        rusqlite::params![serde_json::to_string(&tampered).unwrap(), run.f.case_id],
    )
    .unwrap();
    assert_eq!(admit(&run, &request, 2)["error_code"], "admission_mismatch");
}
#[test]
fn expected_digests_strict_request_and_busy_refuse_without_admission() {
    let (run, request) = sealed("quick");
    let revision = case(&run).storage_revision();
    for field in [
        "expected_bundle_sha256",
        "expected_sealed_entry_sha256",
        "expected_projection_sha256",
    ] {
        let mut changed = request.clone();
        changed[field] = json!("0".repeat(64));
        assert_eq!(
            admit(&run, &changed, 2)["error_code"],
            "expected_digest_mismatch"
        );
    }
    let mut changed = request.clone();
    changed["asset_id"] = json!("caller-cannot-bind");
    assert_eq!(admit(&run, &changed, 2)["error_code"], "invalid_request");
    let lease = DataDirectoryExclusiveLease::acquire(&run.f.data).unwrap();
    let busy = admit(&run, &request, 3);
    assert_eq!(busy["error_code"], "data_directory_busy");
    assert_eq!(busy["retryable"], true);
    drop(lease);
    assert_eq!(case(&run).storage_revision(), revision);
    assert!(case(&run).agent_audit_admissions.is_empty());
    assert!(events(&run).is_empty());
    let storage = run.f.storage();
    let v = verify(
        &run.f.data,
        &storage,
        &run.f.case_id,
        request["session_id"].as_str().unwrap(),
    )
    .unwrap();
    run.f.change_case(|c| {
        let mut collision = ai_security_scanner_lib::demo::build_demo_case()
            .scan_runs
            .remove(0);
        collision.id = v.identities.run_id.clone();
        collision.case_id = c.id.clone();
        c.scan_runs.push(collision);
    });
    assert_eq!(admit(&run, &request, 3)["error_code"], "identity_conflict");
}
#[test]
fn eligibility_and_binding_refusals_leave_no_case_data() {
    for change in ["archived", "active", "asset", "source", "binding", "format"] {
        let (run, request) = sealed("quick");
        if change == "format" {
            let mut c = case(&run);
            c.format_requirements.insert("future/v1".into());
            let db = rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap();
            db.execute(
                "UPDATE cases SET document_json=?1 WHERE id=?2",
                rusqlite::params![serde_json::to_string(&c).unwrap(), run.f.case_id],
            )
            .unwrap();
        } else {
            run.f.change_case(|c| match change {
                "archived" => c.status = CaseStatus::Archived,
                "asset" => c.assets.clear(),
                "source" => c.data_sources.clear(),
                "binding" => {
                    c.assets[0]
                        .metadata
                        .insert("workspace_snapshot_sha256".into(), json!("0".repeat(64)));
                }
                "active" => {
                    let mut demo = ai_security_scanner_lib::demo::build_demo_case()
                        .scan_runs
                        .remove(0);
                    demo.completed_at = None;
                    c.scan_runs.push(demo);
                }
                _ => unreachable!(),
            });
        }
        let revision = case(&run).storage_revision();
        let rejected = admit(&run, &request, if change == "active" { 3 } else { 2 });
        assert_eq!(rejected["retryable"], change == "active");
        assert_eq!(
            rejected["error_code"],
            match change {
                "archived" => "case_archived",
                "active" => "active_scan",
                "format" => "not_available",
                _ => "binding_not_provable",
            },
            "{change}: {rejected}"
        );
        if change == "format" {
            assert!(
                rejected["error"]
                    .as_str()
                    .unwrap()
                    .contains("requires a newer version")
            );
        }
        assert_eq!(case(&run).storage_revision(), revision);
        assert!(events(&run).is_empty());
        assert!(case(&run).agent_audit_admissions.is_empty());
    }
}
#[test]
fn publication_survives_transaction_failure_and_reuses_only_exact_orphans() {
    for conflict in [false, true] {
        let (run, request) = sealed("standard");
        let before = case(&run);
        let db = rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap();
        db.execute_batch("CREATE TRIGGER injected_admission_failure BEFORE INSERT ON case_events WHEN NEW.event_type='cloudflare_audit.admitted' BEGIN SELECT RAISE(ABORT, 'injected transaction failure'); END;").unwrap();
        assert_eq!(admit(&run, &request, 4)["error_code"], "storage_failed");
        assert_no_publication_temporaries(&run.f.data.join("artifacts"));
        assert_eq!(
            serde_json::to_value(case(&run)).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
        assert_eq!(case(&run).storage_revision(), before.storage_revision());
        assert!(events(&run).is_empty());
        let storage = run.f.storage();
        let v = verify(
            &run.f.data,
            &storage,
            &run.f.case_id,
            request["session_id"].as_str().unwrap(),
        )
        .unwrap();
        let path = run
            .f
            .data
            .join("artifacts")
            .join(&run.f.case_id)
            .join(&v.identities.run_id)
            .join(&v.identities.task_id)
            .join("workflow.json");
        assert!(path.exists());
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        db.execute_batch("DROP TRIGGER injected_admission_failure")
            .unwrap();
        if conflict {
            fs::write(&path, b"planted bytes").unwrap();
            let failed = admit(&run, &request, 4);
            assert_eq!(failed["error_code"], "artifact_conflict");
            assert_eq!(failed["retryable"], false);
            assert!(events(&run).is_empty());
            assert_eq!(case(&run).storage_revision(), before.storage_revision());
        } else {
            admit(&run, &request, 0);
            assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), modified);
            assert_eq!(events(&run).len(), 1);
        }
        assert_no_publication_temporaries(&run.f.data.join("artifacts"));
    }
}

#[test]
fn unsealed_and_tampered_packages_refuse_before_publishing() {
    let run = RunFixture::new("quick");
    let request = json!({
        "schema_version":"ai-security-scanner.cloudflare-audit-admit-request/v1",
        "request_id":"admit-one", "case_id":run.f.case_id, "session_id":run.prepared["session_id"],
        "expected_sealed_entry_sha256":"a".repeat(64), "expected_bundle_sha256":"a".repeat(64),
        "expected_projection_sha256":"a".repeat(64),
    });
    assert_eq!(admit(&run, &request, 2)["error_code"], "run_not_sealed");
    let (run, request) = sealed("standard");
    let storage = run.f.storage();
    let v = verify(
        &run.f.data,
        &storage,
        &run.f.case_id,
        request["session_id"].as_str().unwrap(),
    )
    .unwrap();
    let copy_root = run
        .f
        .data
        .join("artifacts")
        .join(&run.f.case_id)
        .join(&v.identities.run_id);
    let path = run
        .directory()
        .join("sealed")
        .join(&v.digests.bundle_sha256)
        .join("retained/bundle/findings.json");
    writable(&path);
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 1;
    fs::write(&path, bytes).unwrap();
    let before = serde_json::to_value(case(&run)).unwrap();
    let before_status = status(&run);
    assert_eq!(before_status["sealed_state"], "verified");
    assert_eq!(before_status["next_operation"], "admit");
    assert_eq!(
        admit(&run, &request, 2)["error_code"],
        "sealed_package_mismatch"
    );
    assert!(!copy_root.exists());
    assert_eq!(serde_json::to_value(case(&run)).unwrap(), before);
    assert_eq!(status(&run), before_status);
    assert!(events(&run).is_empty());
}
#[test]
fn revision_cas_fault_after_publication_is_retryable_and_commits_nothing() {
    let (run, request) = sealed("quick");
    let before = case(&run);
    let db = rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap();
    // Inject a lost CAS at the actual case UPDATE, after the sealed verifier and publication.
    db.execute_batch("CREATE TRIGGER lose_admission_cas BEFORE UPDATE ON cases WHEN instr(NEW.document_json, 'agent_audit_admissions') > 0 BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    let failed = admit(&run, &request, 3);
    assert_eq!(failed["error_code"], "case_changed");
    assert_eq!(failed["retryable"], true);
    assert_eq!(case(&run).storage_revision(), before.storage_revision());
    assert!(events(&run).is_empty());
    db.execute_batch("DROP TRIGGER lose_admission_cas").unwrap();
    admit(&run, &request, 0);
    assert_eq!(events(&run).len(), 1);
}
#[test]
fn archive_creation_preserves_revision_and_check_fixes_stays_refused() {
    let (run, request) = sealed("standard");
    let saved = admit(&run, &request, 0);
    let run_id = saved["run_id"].as_str().unwrap();
    let dest = run.f.data.with_file_name("must-not-exist");
    let dest = dest.to_str().unwrap();
    let revision = case(&run).storage_revision();
    let output = run
        .f
        .command()
        .args([
            "archive",
            "create",
            "--case-id",
            &run.f.case_id,
            "--destination",
            dest,
            "--acknowledge-sensitive-data",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Path::new(dest).exists());
    let output = run
        .f
        .command()
        .args([
            "scan",
            "rescan-plan",
            "--case-id",
            &run.f.case_id,
            "--baseline-run-id",
            run_id,
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("An admitted source audit cannot authorize a Check fixes scan")
    );
    assert_eq!(case(&run).storage_revision(), revision);
    assert_eq!(case(&run).scan_runs.len(), 1);
    assert_eq!(case(&run).run_report_snapshots.len(), 1);
    let copied: Vec<_> = case(&run)
        .raw_artifacts
        .iter()
        .map(|a| run.f.data.join("artifacts").join(&a.relative_path))
        .collect();
    assert!(!copied.is_empty());
    let plan: Value = serde_json::from_slice(
        &run.f
            .command()
            .args(["case", "delete-plan", &run.f.case_id])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let deleted = run
        .f
        .command()
        .args([
            "case",
            "delete",
            &run.f.case_id,
            "--confirm-case-id",
            &run.f.case_id,
        ])
        .output()
        .unwrap();
    assert!(
        deleted.status.success(),
        "{}",
        String::from_utf8_lossy(&deleted.stderr)
    );
    let deleted = run
        .f
        .command()
        .args([
            "case",
            "delete-artifacts",
            &run.f.case_id,
            "--exact-path",
            plan["artifacts"]["exact_path"].as_str().unwrap(),
            "--confirmation",
            &format!("DELETE {}", run.f.case_id),
        ])
        .output()
        .unwrap();
    assert!(
        deleted.status.success(),
        "{}",
        String::from_utf8_lossy(&deleted.stderr)
    );
    assert!(copied.iter().all(|p| !p.exists()));
}
