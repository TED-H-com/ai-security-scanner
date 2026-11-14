use super::fixture::*;
pub(super) fn request(run: &RunFixture) -> Value {
    let v = run.validate(0);
    json!({"schema_version":"ai-security-scanner.cloudflare-audit-finalize-request/v1",
        "request_id":"seal-one","case_id":run.f.case_id,"session_id":run.prepared["session_id"],
        "expected_head_sha256":run.head,"expected_bundle_sha256":v["result"]["bundle_sha256"]})
}
fn command(run: &RunFixture, request: &Value) -> Command {
    let path = run.f.data.with_file_name("finalize.json");
    fs::write(&path, serde_json::to_vec(request).unwrap()).unwrap();
    let mut c = run.f.command();
    c.env("PATH", std::env::var_os("PATH").unwrap())
        .args(["provider", "cloudflare", "finalize", "--request"])
        .arg(path);
    c
}
pub(super) fn finalize(run: &RunFixture, request: &Value, code: i32) -> Value {
    terminal(command(run, request).output().unwrap(), code)
}
fn status(run: &RunFixture) -> Value {
    run.f.audit_status("audit-one", false, 0)["result"].clone()
}
pub(super) fn path(run: &RunFixture, request: &Value) -> PathBuf {
    run.directory()
        .join("sealed")
        .join(request["expected_bundle_sha256"].as_str().unwrap())
}
fn read(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn no_temporary(run: &RunFixture) {
    if run.directory().join("sealed").exists() {
        assert!(
            fs::read_dir(run.directory().join("sealed"))
                .unwrap()
                .all(|e| !e.unwrap().file_name().to_string_lossy().starts_with('.'))
        );
    }
    assert!(
        fs::read_dir(run.directory()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.'))
    );
}
fn assert_unsealed(run: &RunFixture, before: &Value) {
    assert_eq!(&status(run), before);
    assert!(!run.directory().join("sealed").exists());
    no_temporary(run);
}
#[test]
fn record_without_seal_headroom_is_refused_before_publication() {
    use ai_security_scanner_lib::cloudflare_provider::audit::record::{
        MAX_ENTRY, MAX_RECORD, RECORD_EVENT,
    };

    let run = RunFixture::new("quick");
    let req = request(&run);
    let mut db = rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap();
    let tx = db.transaction().unwrap();
    let rows: Vec<(i64, String)> = {
        let mut statement = tx
            .prepare("SELECT sequence, payload_json FROM case_events WHERE case_id=?1 AND event_type=?2 ORDER BY sequence")
            .unwrap();
        statement
            .query_map(rusqlite::params![run.f.case_id, RECORD_EVENT], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let mut remaining = MAX_RECORD - 1 - rows.iter().map(|(_, p)| p.len()).sum::<usize>();
    for (sequence, mut payload) in rows {
        let padding = remaining.min(MAX_ENTRY - payload.len());
        payload.push_str(&" ".repeat(padding));
        tx.execute(
            "UPDATE case_events SET payload_json=?1 WHERE sequence=?2",
            rusqlite::params![payload, sequence],
        )
        .unwrap();
        remaining -= padding;
    }
    assert_eq!(remaining, 0);
    tx.commit().unwrap();

    let validation = run.validate(0);
    assert_eq!(validation["result"]["sealable"], false);
    assert!(
        validation["result"]["record_errors"]
            .as_array()
            .unwrap()
            .contains(&json!("record_bytes_limit"))
    );
    assert_eq!(finalize(&run, &req, 2)["error_code"], "record_bytes_limit");
    assert!(!run.directory().join("sealed").exists());
}

#[test]
fn oversized_unresolved_projection_is_refused_before_publication() {
    let run = RunFixture::with_records("quick", &[], |_, ledger, metadata| {
        let fingerprints = ledger[0]["result_fingerprints"].as_array_mut().unwrap();
        fingerprints.extend((0..995).map(|i| json!(format!("candidate-{i}-{}", "a".repeat(1200)))));
        ledger[0]["unresolved"] = json!(["Validation budget exhausted"]);
        metadata["run_status"] = json!("incomplete");
        metadata["incomplete_reason"] = json!("Validation budget exhausted");
    });
    let validation = run.validate(0);
    assert_eq!(validation["result"]["bundle_receipt"]["valid"], true);
    assert_eq!(validation["result"]["sealable"], false);
    assert!(
        validation["result"]["record_errors"]
            .as_array()
            .unwrap()
            .contains(&json!("entry_bytes_limit"))
    );
    let request = json!({"schema_version":"ai-security-scanner.cloudflare-audit-finalize-request/v1",
        "request_id":"seal-large","case_id":run.f.case_id,"session_id":run.prepared["session_id"],
        "expected_head_sha256":run.head,"expected_bundle_sha256":validation["result"]["bundle_sha256"]});
    assert_eq!(
        finalize(&run, &request, 2)["error_code"],
        "entry_bytes_limit"
    );
    assert!(!run.directory().join("sealed").exists());
}
#[test]
fn quick_and_standard_seal_custody_with_exact_record_projection_and_retention() {
    for profile in ["quick", "standard"] {
        let run = RunFixture::new(profile);
        let req = request(&run);
        let before = status(&run);
        fs::remove_dir_all(&run.host).unwrap();
        let saved = finalize(&run, &req, 0);
        let p = path(&run, &req);
        let mut names: Vec<_> = fs::read_dir(&p)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["retained", "workflow-projection.json", "workflow.json"]
        );
        let workflow = read(p.join("workflow.json"));
        assert_eq!(workflow["preparation_receipt"], before["receipt"]);
        assert_eq!(workflow["entries"], before["entries"]);
        assert_eq!(workflow["record_head"]["entry_sha256"], run.head);
        let projection = read(p.join("workflow-projection.json"));
        let retained = read(p.join("retained/projection.json"));
        assert_eq!(projection["provenance"], "workflow_recorded");
        assert_eq!(retained["provenance"], "reported_only");
        for flag in [
            "audit_performed",
            "canonical_snapshot_binding_verified",
            "source_authorization_verified",
        ] {
            assert_eq!(projection[flag], true);
        }
        for flag in ["admission_ready", "target_execution_allowed"] {
            assert_eq!(projection[flag], false);
        }
        for field in [
            "reported_counts",
            "coverage_by_status",
            "unresolved_candidates",
        ] {
            assert_eq!(projection[field], retained[field]);
        }
        for field in ["counts_by_role", "counts_by_state", "budget"] {
            assert_eq!(projection[field], before[field]);
        }
        assert_eq!(projection["run_status"], "complete");
        assert_eq!(projection["profile"], profile);
        assert_eq!(
            projection["issued_total"],
            before["assignments"].as_array().unwrap().len()
        );
        assert_eq!(
            saved["result"]["entry"]["content"]["seal"]["projection"],
            projection
        );
        let inspection = run
            .f
            .command()
            .args(["provider", "cloudflare", "inspect-retained", "--input"])
            .arg(p.join("retained"))
            .output()
            .unwrap();
        assert!(
            inspection.status.success(),
            "{}",
            String::from_utf8_lossy(&inspection.stderr)
        );
        let inspection: Value = serde_json::from_slice(&inspection.stdout).unwrap();
        assert_eq!(inspection["provenance"], "reported_only");
        assert_eq!(inspection["audit_performed"], false);
        assert_eq!(inspection["admission_ready"], false);
        let after = status(&run);
        assert_eq!(after["sealed_state"], "verified");
        assert_eq!(after["sealed_verification_scope"], "committed_files");
        assert_eq!(after["next_operation"], "admit");
        assert_eq!(after["package_path"], p.to_str().unwrap());
        #[cfg(unix)]
        assert!(fs::metadata(&p).unwrap().permissions().readonly());
        no_temporary(&run);
    }
}
#[test]
fn replay_is_authority_free_and_all_subsequent_mutations_are_terminal() {
    let run = RunFixture::new("quick");
    let req = request(&run);
    let saved = finalize(&run, &req, 0);
    let m = fs::metadata(path(&run, &req)).unwrap().modified().unwrap();
    run.f.change_case(|c| {
        c.scope_grants[0].expires_at = Some(Utc::now() - chrono::Duration::seconds(1))
    });
    fs::remove_dir_all(&run.host).unwrap();
    let replay = finalize(&run, &req, 0);
    assert_eq!(replay["result"]["entry"], saved["result"]["entry"]);
    assert_eq!(replay["result"]["replayed"], true);
    assert_eq!(
        m,
        fs::metadata(path(&run, &req)).unwrap().modified().unwrap()
    );
    assert_eq!(
        fs::read_dir(run.directory().join("sealed"))
            .unwrap()
            .count(),
        1
    );
    let mut other = req.clone();
    other["request_id"] = json!("seal-two");
    assert_eq!(finalize(&run, &other, 2)["error_code"], "run_sealed");
    other = req.clone();
    other["expected_bundle_sha256"] = json!("a".repeat(64));
    assert_eq!(finalize(&run, &other, 2)["error_code"], "run_sealed");
    rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap().execute(
        "UPDATE case_events SET payload_json='{}' WHERE event_type='source_view.preparation_terminal'", []).unwrap();
    assert_eq!(finalize(&run, &req, 0)["result"]["replayed"], true);
    assert_eq!(run.validate(2)["error_code"], "run_sealed");
    for action in [
        json!({"type":"issue","assignments":[{"role":"hunter","wave":2}]}),
        json!({"type":"interrupt","assignment_id":"absent","reason":"abandoned"}),
        json!({"type":"submit_documents","documents":[{"name":"REPORT.md"}]}),
        json!({"type":"submit_output","assignment_id":"absent","output":{"path":"absent"}}),
    ] {
        let cp = run.f.checkpoint_request(&run.prepared, action);
        assert_eq!(run.f.checkpoint(&cp, 2)["error_code"], "run_sealed");
    }
    let mut old_checkpoint = run.f.checkpoint_request(
        &run.prepared,
        json!({"type":"issue","assignments":[{"role":"reconnaissance_baseline"}]}),
    );
    old_checkpoint["request_id"] = json!("fixture-1");
    assert_eq!(
        run.f.checkpoint(&old_checkpoint, 2)["error_code"],
        "run_sealed"
    );
    no_temporary(&run);
}
#[test]
fn stale_bundle_unsealable_and_strict_requests_leave_no_record_or_package() {
    let run = RunFixture::new("quick");
    let req = request(&run);
    let before = status(&run);
    for field in ["expected_head_sha256", "expected_bundle_sha256"] {
        let mut wrong = req.clone();
        wrong[field] = json!("a".repeat(64));
        assert_eq!(
            finalize(&run, &wrong, 3)["error_code"],
            if field == "expected_head_sha256" {
                "stale_head"
            } else {
                "bundle_mismatch"
            }
        );
        assert_unsealed(&run, &before);
        wrong = req.clone();
        wrong.as_object_mut().unwrap().remove(field);
        assert_eq!(finalize(&run, &wrong, 2)["error_code"], "invalid_request");
    }
    let mut wrong = req.clone();
    wrong["unknown"] = json!(true);
    assert_eq!(finalize(&run, &wrong, 2)["error_code"], "invalid_request");
    let run = RunFixture::without("standard", &["clean"]);
    let expected = run.validate(0)["result"].clone();
    let before = status(&run);
    let result = finalize(&run, &request(&run), 2);
    assert_eq!(result["error_code"], "not_sealable");
    assert_eq!(result["result"], expected);
    assert_unsealed(&run, &before);
}
#[test]
fn incomplete_without_closed_hunter_does_not_claim_audit_performed() {
    for closed in [false, true] {
        let mut run = RunFixture::without(
            "quick",
            if closed {
                &[]
            } else {
                &["hunter", "candidate"]
            },
        );
        run.metadata["run_status"] = json!("incomplete");
        run.metadata["incomplete_reason"] = json!("Host stopped before source review finished");
        if !closed {
            run.findings = json!([]);
            run.ledger[0]["status"] = json!("deferred");
            run.ledger[0]["agent_id"] = Value::Null;
            run.ledger[0]["reviewed_paths"] = json!([]);
            run.ledger[0]["local_checks"] = json!([]);
            run.ledger[0]["result_fingerprints"] = json!([]);
            run.ledger[0]["unresolved"] = json!(["Source review interrupted"]);
        }
        run.documents(&["run-metadata.json", "findings.json", "coverage-ledger.json"]);
        let req = request(&run);
        let saved = finalize(&run, &req, 0);
        let projection = &saved["result"]["entry"]["content"]["seal"]["projection"];
        assert_eq!(projection["audit_performed"], closed);
        assert_eq!(projection["run_status"], "incomplete");
        assert_eq!(
            projection["incomplete_reason"],
            run.metadata["incomplete_reason"]
        );
    }
}
// Simulate durable publication followed by process loss before the commit by
// restoring only the database to its pre-commit revision. No production fault hook.
fn undo_terminal(run: &RunFixture, saved: &Value) {
    let mut connection = rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap();
    let tx = connection.transaction().unwrap();
    tx.execute("DELETE FROM case_events WHERE event_type='cloudflare_audit.record_entry' AND json_extract(payload_json,'$.entry_sha256')=?1", [saved["result"]["entry"]["entry_sha256"].as_str().unwrap()]).unwrap();
    tx.execute(
        "UPDATE cases SET revision=revision-1 WHERE id=?1",
        [&run.f.case_id],
    )
    .unwrap();
    tx.commit().unwrap();
}
#[test]
fn orphan_publication_is_reused_only_when_all_committed_files_match() {
    for (index, changed) in [
        None,
        None,
        Some("retained/retention.json"),
        Some("workflow.json"),
        Some("workflow-projection.json"),
    ]
    .into_iter()
    .enumerate()
    {
        let run = RunFixture::new("quick");
        let mut req = request(&run);
        let saved = finalize(&run, &req, 0);
        let p = path(&run, &req);
        let time = fs::metadata(&p).unwrap().modified().unwrap();
        undo_terminal(&run, &saved);
        if index == 1 {
            // Process stopped after rename but before sealing the published root.
            writable(&p);
        }
        if index != 0 {
            req["request_id"] = json!("recovery-request");
        }
        let before = status(&run);
        assert!(before.get("sealed_state").is_none());
        if let Some(file) = changed {
            writable(&p.join(file));
            fs::write(p.join(file), b"different bytes").unwrap();
            assert_eq!(finalize(&run, &req, 4)["error_code"], "storage_failed");
            assert_eq!(fs::read(p.join(file)).unwrap(), b"different bytes");
            assert_eq!(status(&run), before);
        } else {
            assert_eq!(finalize(&run, &req, 0)["result"]["replayed"], false);
            assert_eq!(status(&run)["sealed_state"], "verified");
            #[cfg(unix)]
            assert!(fs::metadata(&p).unwrap().permissions().readonly());
        }
        assert_eq!(time, fs::metadata(&p).unwrap().modified().unwrap());
        no_temporary(&run);
    }
}
#[test]
fn authority_integrity_and_writer_lease_refusals_do_not_seal() {
    for change in ["grant", "view", "snapshot", "lease"] {
        let run = RunFixture::new("quick");
        let req = request(&run);
        let mut lease = None;
        match change {
            "grant" => run.f.change_case(|c| {
                c.scope_grants[0].expires_at = Some(Utc::now() - chrono::Duration::seconds(1))
            }),
            "lease" => lease = Some(DataDirectoryExclusiveLease::acquire(&run.f.data).unwrap()),
            _ => {
                let file = if change == "view" {
                    run.f.view_root().join("tree/src/a.rs")
                } else {
                    run.f
                        .data
                        .join("artifacts")
                        .join(&run.f.case_id)
                        .join("workspace-snapshots")
                        .join(&run.f.reference.storage_id)
                        .join("payload/tree/src/a.rs")
                };
                writable(&file);
                fs::write(file, "modified source").unwrap();
            }
        }
        let before = status(&run);
        assert_eq!(
            finalize(&run, &req, 3)["error_code"],
            if change == "lease" {
                "data_directory_busy"
            } else {
                "saved_receipt_not_current"
            }
        );
        assert_unsealed(&run, &before);
        drop(lease);
    }
}
#[test]
fn cheap_status_and_replay_detect_missing_and_mismatched_committed_files() {
    let run = RunFixture::new("quick");
    let req = request(&run);
    finalize(&run, &req, 0);
    let p = path(&run, &req);
    assert_eq!(status(&run)["sealed_state"], "verified");
    move_directory(&p, p.with_extension("removed"));
    assert_eq!(status(&run)["sealed_state"], "missing");
    assert_eq!(finalize(&run, &req, 4)["error_code"], "storage_failed");
    move_directory(p.with_extension("removed"), &p);
    // Payload corruption is outside the cheap status contract.
    let payload = p.join("retained/bundle/REPORT.md");
    writable(&payload);
    fs::write(payload, "changed report").unwrap();
    assert_eq!(status(&run)["sealed_state"], "verified");
    for file in [
        "retained/retention.json",
        "workflow.json",
        "workflow-projection.json",
    ] {
        let member = p.join(file);
        let bytes = fs::read(&member).unwrap();
        writable(&member);
        fs::write(&member, "changed recorded file").unwrap();
        assert_eq!(status(&run)["sealed_state"], "mismatch");
        assert_eq!(finalize(&run, &req, 4)["error_code"], "storage_failed");
        fs::write(&member, bytes).unwrap();
    }
}
#[cfg(unix)]
#[test]
fn lost_output_is_exit_four_and_status_recovers_the_committed_result() {
    use std::process::Stdio;
    let run = RunFixture::new("quick");
    let req = request(&run);
    let mut child = command(&run, &req)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    assert_eq!(child.wait().unwrap().code(), Some(4));
    assert_eq!(status(&run)["sealed_state"], "verified");
    assert_eq!(finalize(&run, &req, 0)["result"]["replayed"], true);
}
fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
fn archive_omits_package_restore_keeps_terminal_history_and_confirmed_deletion_removes_readonly_tree()
 {
    let mut run = RunFixture::new("quick");
    let req = request(&run);
    let saved = finalize(&run, &req, 0);
    let package = path(&run, &req);
    let archive = run.f.data.with_file_name("sealed-case.tar.gz");
    success(
        run.f
            .command()
            .args([
                "archive",
                "create",
                "--case-id",
                &run.f.case_id,
                "--acknowledge-sensitive-data",
                "--include-source-snapshots",
                "--destination",
            ])
            .arg(&archive)
            .output()
            .unwrap(),
    );
    let verified = success(
        run.f
            .command()
            .args(["archive", "verify", "--archive"])
            .arg(&archive)
            .output()
            .unwrap(),
    );
    assert_eq!(
        verified["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| s
                .as_str()
                .unwrap()
                .contains("audit records are not included"))
            .count(),
        1
    );
    let restored = run.f.data.with_file_name("restored");
    success(
        run.f
            .command()
            .args(["archive", "restore", "--archive"])
            .arg(&archive)
            .args(["--acknowledge-sensitive-data", "--destination"])
            .arg(&restored)
            .output()
            .unwrap(),
    );
    let original = std::mem::replace(&mut run.f.data, restored);
    let restored_status = status(&run);
    assert_eq!(restored_status["sealed_state"], "missing");
    assert_eq!(
        restored_status["sealed_verification_scope"],
        "committed_files"
    );
    assert!(restored_status.get("sealed_failed_check").is_none());
    assert_eq!(
        restored_status["entries"]
            .as_array()
            .unwrap()
            .last()
            .unwrap(),
        &saved["result"]["entry"]
    );
    assert!(restored_status["next_operation"].is_null());
    assert!(!run.f.audit_root().exists());
    assert_eq!(
        finalize(&run, &req, 2)["error_code"],
        "restored_session_inert"
    );
    assert_eq!(run.validate(2)["error_code"], "restored_session_inert");
    run.f.data = original;
    let plan = success(
        run.f
            .command()
            .args(["case", "delete-plan", &run.f.case_id])
            .output()
            .unwrap(),
    );
    success(
        run.f
            .command()
            .args([
                "case",
                "delete",
                &run.f.case_id,
                "--confirm-case-id",
                &run.f.case_id,
            ])
            .output()
            .unwrap(),
    );
    assert!(package.exists());
    success(
        run.f
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
            .unwrap(),
    );
    assert!(!run.f.audit_root().exists());
}
#[test]
fn externally_supplied_sealed_payload_never_gains_workflow_provenance() {
    let run = RunFixture::new("quick");
    let req = request(&run);
    finalize(&run, &req, 0);
    let p = path(&run, &req).join("retained");
    let bundle = success(
        run.f
            .command()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .args(["provider", "cloudflare", "validate-bundle", "--bundle"])
            .arg(p.join("bundle"))
            .arg("--source-view")
            .arg(p.join("source-view"))
            .output()
            .unwrap(),
    );
    assert_eq!(bundle["provenance"], "reported_only");
    assert_eq!(bundle["projection"]["provenance"], "reported_only");
    for flag in [
        "audit_performed",
        "admission_ready",
        "canonical_snapshot_binding_verified",
        "source_authorization_verified",
    ] {
        assert_eq!(bundle[flag], false);
    }
    let external = run.f.data.with_file_name("external-retained");
    let retained = success(
        run.f
            .command()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .args(["provider", "cloudflare", "retain-bundle", "--bundle"])
            .arg(p.join("bundle"))
            .arg("--source-view")
            .arg(p.join("source-view"))
            .arg("--expected-bundle-sha256")
            .arg(req["expected_bundle_sha256"].as_str().unwrap())
            .arg("--destination")
            .arg(&external)
            .output()
            .unwrap(),
    );
    let hash = retained["inspection"]["retention_sha256"].as_str().unwrap();
    let inspected = success(
        run.f
            .command()
            .args(["provider", "cloudflare", "inspect-retained", "--input"])
            .arg(&external)
            .arg("--expected-retention-sha256")
            .arg(hash)
            .output()
            .unwrap(),
    );
    assert_eq!(inspected["provenance"], "reported_only");
    assert_eq!(inspected["audit_performed"], false);
    assert_eq!(inspected["admission_ready"], false);
    let retrieved = run.f.data.with_file_name("retrieved-validation.json");
    success(
        run.f
            .command()
            .args(["provider", "cloudflare", "retrieve-retained", "--input"])
            .arg(&external)
            .arg("--expected-retention-sha256")
            .arg(hash)
            .args(["--member", "validation.json", "--destination"])
            .arg(&retrieved)
            .output()
            .unwrap(),
    );
    assert_eq!(read(retrieved), bundle);
    let mut spoofed = read(external.join("retention.json"));
    spoofed["provenance"] = json!("workflow_recorded");
    fs::write(
        external.join("retention.json"),
        serde_json::to_vec(&spoofed).unwrap(),
    )
    .unwrap();
    let output = run
        .f
        .command()
        .args(["provider", "cloudflare", "inspect-retained", "--input"])
        .arg(&external)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported retention contract"));
}
