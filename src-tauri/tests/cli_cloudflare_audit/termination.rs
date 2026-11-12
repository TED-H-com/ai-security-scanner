use super::fixture::*;

pub(super) fn request(f: &Fixture, prepared: &Value, head: &Value, reason: &str) -> Value {
    json!({"schema_version":"ai-security-scanner.cloudflare-audit-terminate-request/v1",
        "request_id":"terminate-one","case_id":f.case_id,"session_id":prepared["session_id"],
        "expected_head_sha256":head,"reason":reason})
}
pub(super) fn command(f: &Fixture, operation: &str, request: &Value) -> Command {
    let path = f.data.with_file_name("terminal-request.json");
    fs::write(&path, serde_json::to_vec(request).unwrap()).unwrap();
    let mut c = f.command();
    c.args(["provider", "cloudflare", operation, "--request"])
        .arg(path);
    c
}
pub(super) fn terminate(f: &Fixture, request: &Value, code: i32) -> Value {
    terminal(command(f, "terminate", request).output().unwrap(), code)
}
#[test]
fn empty_every_reason_replay_conflict_stale_busy_and_finality() {
    for reason in [
        "host_cancelled",
        "host_interrupted",
        "budget_exhausted",
        "authorization_unavailable",
        "required_artifacts_unavailable",
        "workflow_failed",
    ] {
        let (f, prep) = Fixture::setup(true);
        let prepared = f.audit(&prep, 0);
        let request = request(&f, &prepared, &prepared["receipt"]["sha256"], reason);
        let mut stale = request.clone();
        stale["expected_head_sha256"] = json!("0".repeat(64));
        let refused = terminate(&f, &stale, 3);
        assert_eq!(refused["error_code"], "stale_head");
        assert_eq!(refused["retryable"], true);
        let lease = DataDirectoryExclusiveLease::acquire(&f.data).unwrap();
        assert_eq!(
            terminate(&f, &request, 3)["error_code"],
            "data_directory_busy"
        );
        drop(lease);
        let before = f.storage().snapshot_case_for_archive(&f.case_id).unwrap();
        let saved = terminate(&f, &request, 0);
        assert_eq!(saved["operation"], "provider.cloudflare.terminate");
        assert_eq!(
            saved["result"]["entry"]["content"],
            json!({"type":"terminated","reason":reason})
        );
        assert_eq!(saved["case_revision"], before.revision + 1);
        super::failure_rows::assert_row(&f, &saved, false);
        let replay = terminate(&f, &request, 0);
        assert_eq!(replay["result"]["entry"], saved["result"]["entry"]);
        assert_eq!(replay["result"]["replayed"], true);
        assert_eq!(terminate(&f, &stale, 3)["error_code"], "request_conflict");
        let mut different = request.clone();
        different["request_id"] = json!("another-end");
        assert_eq!(terminate(&f, &different, 2)["error_code"], "run_terminated");
        assert_eq!(f.record_events(), 1);
    }
}
#[test]
fn strict_requests_blocked_unknown_and_corrupt_chain() {
    let (f, prep) = Fixture::setup(true);
    let prepared = f.audit(&prep, 0);
    let request = request(
        &f,
        &prepared,
        &prepared["receipt"]["sha256"],
        "workflow_failed",
    );
    for field in ["prose", "occurred_at", "path", "assets", "outcome"] {
        let mut invalid = request.clone();
        invalid[field] = json!("caller supplied");
        assert_eq!(terminate(&f, &invalid, 2)["error_code"], "invalid_request");
    }
    for value in [json!("inactive"), Value::Null, json!(123)] {
        let mut invalid = request.clone();
        invalid["reason"] = value;
        assert_eq!(terminate(&f, &invalid, 2)["error_code"], "invalid_request");
    }
    let mut missing = request.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("expected_head_sha256");
    assert_eq!(terminate(&f, &missing, 2)["error_code"], "invalid_request");
    let mut unknown = request.clone();
    unknown["session_id"] = json!("unknown");
    assert_eq!(
        terminate(&f, &unknown, 2)["error_code"],
        "unknown_preparation"
    );
    let mut blocked = prep.clone();
    blocked["request_id"] = json!("blocked");
    blocked["host"]["delegation"] = json!("unavailable");
    f.audit(&blocked, 0);
    unknown["session_id"] = json!("blocked");
    assert_eq!(
        terminate(&f, &unknown, 2)["error_code"],
        "blocked_preparation"
    );
    terminate(&f, &request, 0);
    let db = rusqlite::Connection::open(f.data.join("casework.db")).unwrap();
    db.execute("UPDATE case_events SET payload_json=replace(payload_json,'workflow_failed','host_cancelled') WHERE event_type='cloudflare_audit.record_entry'", []).unwrap();
    assert_eq!(terminate(&f, &request, 4)["command_outcome"], "failed");
}
#[test]
fn expired_authorization_and_missing_directories_do_not_prevent_termination() {
    for remove in [false, true] {
        let (f, prep) = Fixture::setup(true);
        let prepared = f.audit(&prep, 0);
        let host = Path::new(prep["run_directory"].as_str().unwrap());
        fs::write(host.join("sentinel"), b"unchanged").unwrap();
        let directory = f
            .audit_root()
            .join(prepared["session_id"].as_str().unwrap());
        let descriptor = fs::read(directory.join("session.json")).ok();
        if remove {
            fs::remove_dir_all(host).unwrap();
            fs::remove_dir_all(&directory).unwrap();
        }
        f.change_case(|case| {
            for grant in &mut case.scope_grants {
                grant.expires_at = Some(Utc::now() - chrono::Duration::days(1));
            }
        });
        terminate(
            &f,
            &request(
                &f,
                &prepared,
                &prepared["receipt"]["sha256"],
                "authorization_unavailable",
            ),
            0,
        );
        if remove {
            assert!(!host.exists());
            assert!(!directory.exists());
        } else {
            assert_eq!(fs::read(host.join("sentinel")).unwrap(), b"unchanged");
            assert_eq!(fs::read(directory.join("session.json")).ok(), descriptor);
        }
    }
}

#[test]
fn populated_custody_survives_and_all_mutations_including_replays_refuse() {
    let mut run = RunFixture::new("quick");
    let discarded =
        run.issue(json!({"role":"candidate_verifier","fingerprint":"discarded-candidate"}));
    run.submit(&discarded, b"not json");
    let interrupted = run.issue(json!({"role":"reconnaissance_focused"}));
    run.action(json!({"type":"interrupt","assignment_id":interrupted["assignment_id"],"reason":"host stopped"}));
    run.issue(json!({"role":"reconnaissance_focused"}));
    run.documents(&["REPORT.md"]);
    let before = run.f.audit_status("audit-one", false, 0)["result"].clone();
    let end = request(&run.f, &run.prepared, &run.head, "host_interrupted");
    let saved = terminate(&run.f, &end, 0);
    let after = run.f.audit_status("audit-one", false, 0)["result"].clone();
    for key in [
        "assignments",
        "documents",
        "counts_by_state",
        "counts_by_role",
        "captured_bytes",
        "budget",
    ] {
        assert_eq!(before[key], after[key], "{key}");
    }
    assert_eq!(
        after["terminated"],
        json!({"reason":"host_interrupted","occurred_at":saved["result"]["entry"]["occurred_at"],"entry_sha256":saved["result"]["entry"]["entry_sha256"]})
    );
    assert!(after["next_operation"].is_null());
    let case = run.f.storage().get_case(&run.f.case_id).unwrap();
    let failure = json!(&case.scan_runs[0].engine_runs[0].task_kind);
    assert_eq!(
        failure["outcome"]["assignment_count"],
        before["assignments"].as_array().unwrap().len()
    );
    let snapshot = run
        .f
        .storage()
        .cloudflare_captured_snapshot(&run.f.case_id, run.prepared["session_id"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        failure["outcome"]["capture_count"],
        ai_security_scanner_lib::cloudflare_provider::audit::captured::enumerate(&snapshot.record)
            .unwrap()
            .len()
    );
    for key in [
        "checkpoint",
        "sealing",
        "document_capture",
        "assignment_output_capture",
    ] {
        assert_eq!(after[key]["available"], false, "{key}");
    }
    let custody = tree(&run.directory());
    let host = tree(&run.host);
    let snapshot = run
        .f
        .storage()
        .snapshot_case_for_archive(&run.f.case_id)
        .unwrap();
    for entry in before["entries"].as_array().unwrap() {
        let content = &entry["content"];
        let action = match content["type"].as_str().unwrap() {
            "issue" => {
                json!({"type":"issue","assignments":content["assignments"].as_array().unwrap().iter().map(|a|a["spec"].clone()).collect::<Vec<_>>()})
            }
            "submit_output" => {
                json!({"type":"submit_output","assignment_id":content["assignment_id"],"output":content["requested_output"]})
            }
            "submit_documents" => {
                json!({"type":"submit_documents","documents":content["requested_documents"]})
            }
            _ => content.clone(),
        };
        let mut replay = run.f.checkpoint_request(&run.prepared, action);
        replay["request_id"] = entry["request_id"].clone();
        replay["expected_head_sha256"] = entry["predecessor_sha256"].clone();
        for fresh in [false, true] {
            if fresh {
                replay["request_id"] = json!("fresh");
            }
            assert_eq!(run.f.checkpoint(&replay, 2)["error_code"], "run_terminated");
        }
    }
    assert_eq!(run.validate(2)["error_code"], "run_terminated");
    for operation in ["finalize", "admit"] {
        let mut r = json!({"schema_version":format!("ai-security-scanner.cloudflare-audit-{operation}-request/v1"),"request_id":"fixture-1","case_id":run.f.case_id,"session_id":run.prepared["session_id"],"expected_bundle_sha256":"0".repeat(64)});
        if operation == "finalize" {
            r["expected_head_sha256"] = run.head.clone();
        } else {
            r["expected_sealed_entry_sha256"] = run.head.clone();
            r["expected_projection_sha256"] = json!("0".repeat(64));
        }
        assert_eq!(
            terminal(command(&run.f, operation, &r).output().unwrap(), 2)["error_code"],
            "run_terminated"
        );
    }
    assert_eq!(
        snapshot.events,
        run.f
            .storage()
            .snapshot_case_for_archive(&run.f.case_id)
            .unwrap()
            .events
    );
    assert_eq!(custody, tree(&run.directory()));
    assert_eq!(host, tree(&run.host));
    // Recover every accepted document revision and assignment, including superseded bytes.
    let storage = run.f.storage();
    let snap = storage
        .cloudflare_captured_snapshot(&run.f.case_id, run.prepared["session_id"].as_str().unwrap())
        .unwrap();
    let captures =
        ai_security_scanner_lib::cloudflare_provider::audit::captured::enumerate(&snap.record)
            .unwrap();
    assert!(captures.iter().any(|c| !c.available));
    for (index, capture) in captures.iter().filter(|c| c.available).enumerate() {
        use ai_security_scanner_lib::cloudflare_provider::audit::captured::Selector;
        let destination = run.f.data.with_file_name(format!("recovered-{index}"));
        let mut c = run.f.command();
        c.args([
            "provider",
            "cloudflare",
            "retrieve-captured",
            "--case-id",
            &run.f.case_id,
            "--session-id",
            run.prepared["session_id"].as_str().unwrap(),
            "--destination",
        ])
        .arg(&destination);
        match &capture.selector {
            Selector::Document { name, revision } => {
                c.args(["--document", name, "--revision", &revision.to_string()]);
            }
            Selector::Assignment { assignment_id } => {
                c.args(["--assignment-id", assignment_id]);
            }
        }
        terminal(c.output().unwrap(), 0);
        assert_eq!(
            fs::read(destination).unwrap(),
            fs::read(
                run.directory()
                    .join(capture.object_reference.as_ref().unwrap())
            )
            .unwrap()
        );
    }
}
fn tree(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, path: &Path, result: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
        for e in fs::read_dir(path).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                walk(root, &e.path(), result);
            } else {
                result.insert(
                    e.path().strip_prefix(root).unwrap().to_owned(),
                    fs::read(e.path()).unwrap(),
                );
            }
        }
    }
    let mut result = Default::default();
    walk(root, root, &mut result);
    result
}

#[test]
fn sealed_audit_refuses_termination() {
    let (run, _) = super::admit::sealed("quick");
    let head =
        run.f.audit_status("audit-one", false, 0)["result"]["record_head"]["entry_sha256"].clone();
    assert_eq!(
        terminate(
            &run.f,
            &request(&run.f, &run.prepared, &head, "host_cancelled"),
            2
        )["error_code"],
        "run_sealed"
    );
}

#[test]
fn legacy_live_and_terminated_restore_refuse_termination_even_replay() {
    use ai_security_scanner_lib::case_archive::{self, ArchiveOptions};
    for ended in [false, true] {
        let (mut f, prep) = Fixture::setup(true);
        let prepared = f.audit(&prep, 0);
        let end = request(
            &f,
            &prepared,
            &prepared["receipt"]["sha256"],
            "host_cancelled",
        );
        if ended {
            terminate(&f, &end, 0);
        }
        let path = f.data.with_file_name("legacy.tar.gz");
        case_archive::create_archive(&f.data, &f.case_id, &path, &ArchiveOptions::default())
            .unwrap();
        let files = super::archives::unpack(&path);
        assert_eq!(files.contains_key("provider-history.json"), ended);
        let manifest: Value = serde_json::from_slice(&files["archive-manifest.json"]).unwrap();
        assert_eq!(manifest.get("required_capabilities").is_some(), ended);
        let destination = f.data.with_file_name("restored");
        case_archive::restore_archive(&path, &destination).unwrap();
        f.data = destination;
        let before = f.storage().snapshot_case_for_archive(&f.case_id).unwrap();
        assert_eq!(
            terminate(&f, &end, 2)["error_code"],
            "restored_session_inert"
        );
        let mut fresh = end.clone();
        fresh["request_id"] = json!("fresh-end");
        assert_eq!(
            terminate(&f, &fresh, 2)["error_code"],
            "restored_session_inert"
        );
        assert_eq!(
            before.events,
            f.storage()
                .snapshot_case_for_archive(&f.case_id)
                .unwrap()
                .events
        );
    }
}

#[test]
fn full_entry_and_byte_records_terminate_through_cli_and_captured_reader() {
    use ai_security_scanner_lib::cloudflare_provider::audit::{
        documents::{DocumentRevision, DocumentSpec},
        record::*,
    };
    for byte_full in [false, true] {
        let (f, prep) = Fixture::setup(true);
        let prepared = f.audit(&prep, 0);
        let storage = f.storage();
        let receipt = storage
            .cloudflare_audit_receipt(&f.case_id, "audit-one", false)
            .unwrap()
            .unwrap();
        let mut record = Record::default();
        let count = if byte_full { 4 } else { 4096 };
        let mut db = rusqlite::Connection::open(f.data.join("casework.db")).unwrap();
        let tx = db.transaction().unwrap();
        for revision in 1..=count {
            let mut entry = Entry {
                schema_version: ENTRY_SCHEMA.into(),
                case_id: f.case_id.clone(),
                session_id: prepared["session_id"].as_str().unwrap().into(),
                request_id: format!("full-{revision}"),
                request_sha256: String::new(),
                case_revision: receipt.case_revision + revision as i64,
                sequence: revision,
                predecessor_sha256: record.head(&receipt).1.into(),
                occurred_at: receipt.occurred_at.clone(),
                entry_sha256: String::new(),
                content: Content::SubmitDocuments {
                    requested_documents: vec![DocumentSpec {
                        name: "REPORT.md".into(),
                        sha256: None,
                        byte_length: None,
                    }],
                    documents: vec![DocumentRevision {
                        name: "REPORT.md".into(),
                        revision,
                        sha256: "a".repeat(64),
                        byte_length: 0,
                        validator_resources_sha256: None,
                        valid: None,
                    }],
                },
            };
            entry.request_sha256 = entry.request_digest().unwrap();
            entry.entry_sha256 = entry.content_digest().unwrap();
            let mut payload = serde_json::to_string(&entry).unwrap();
            if byte_full {
                payload.push_str(&" ".repeat(MAX_ENTRY - payload.len()));
            }
            tx.execute("INSERT INTO case_events(case_id,event_type,occurred_at,payload_json) VALUES (?1,?2,?3,?4)", rusqlite::params![f.case_id, RECORD_EVENT, entry.occurred_at, payload]).unwrap();
            record.push(&receipt, entry, payload.len()).unwrap();
        }
        tx.execute(
            "UPDATE cases SET revision=?1 WHERE id=?2",
            rusqlite::params![receipt.case_revision + count as i64, f.case_id],
        )
        .unwrap();
        tx.commit().unwrap();
        let end = request(
            &f,
            &prepared,
            &json!(record.head(&receipt).1),
            "budget_exhausted",
        );
        terminate(&f, &end, 0);
        assert_eq!(terminate(&f, &end, 0)["result"]["replayed"], true);
        let snapshot = storage
            .cloudflare_captured_snapshot(&f.case_id, receipt.session_id().unwrap())
            .unwrap();
        assert_eq!(snapshot.record.entries.len(), count as usize + 1);
        assert!(snapshot.record.terminated().is_some());
        if byte_full {
            assert!(snapshot.record.bytes > MAX_RECORD);
        }
    }
}

#[test]
fn lost_delivery_replays_durable_termination_and_persistence_failure_does_not_append() {
    let (f, prep) = Fixture::setup(true);
    let prepared = f.audit(&prep, 0);
    let end = request(
        &f,
        &prepared,
        &prepared["receipt"]["sha256"],
        "workflow_failed",
    );
    let db = rusqlite::Connection::open(f.data.join("casework.db")).unwrap();
    db.execute_batch("CREATE TRIGGER reject_terminal BEFORE INSERT ON case_events WHEN NEW.event_type='cloudflare_audit.record_entry' BEGIN SELECT RAISE(ABORT, 'synthetic persistence failure'); END;").unwrap();
    let before = f.storage().snapshot_case_for_archive(&f.case_id).unwrap();
    assert_eq!(terminate(&f, &end, 4)["error_code"], "storage_failed");
    let after = f.storage().snapshot_case_for_archive(&f.case_id).unwrap();
    assert_eq!(before.revision, after.revision);
    assert_eq!(before.events, after.events);
    db.execute_batch("DROP TRIGGER reject_terminal;").unwrap();
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let output = command(&f, "terminate", &end)
        .stdout(writer)
        .stderr(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(f.record_events(), 1);
    assert_eq!(terminate(&f, &end, 0)["result"]["replayed"], true);
}
