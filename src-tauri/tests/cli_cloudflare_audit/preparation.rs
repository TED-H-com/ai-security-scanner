use super::fixture::*;

#[test]
fn prepared_replay_conflict_status_and_independent_runs() {
    let (f, mut request) = Fixture::setup(true);
    let first = f.audit(&request, 0);
    assert_eq!(receipt(&first)["result"]["status"], "prepared");
    assert_eq!(facts(&first)["target_execution_allowed"], false);
    assert_eq!(receipt(&first)["sequence"], 0);
    assert!(receipt(&first)["predecessor_sha256"].is_null());
    for field in ["run_id", "task_id"] {
        assert!(first[field].is_null());
    }
    let session = facts(&first)["session_id"].as_str().unwrap();
    assert_eq!(first["session_id"], session);
    let descriptor = f.audit_root().join(session).join("session.json");
    let bytes = fs::read(&descriptor).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        *facts(&first)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&descriptor).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    for by_session in [false, true] {
        let status = f.audit_status(
            if by_session { session } else { "audit-one" },
            by_session,
            0,
        );
        assert_eq!(receipt(&status), receipt(&first));
        assert_eq!(status["session_id"], session);
        assert!(status["run_id"].is_null());
        assert!(status["task_id"].is_null());
        assert_eq!(status["result"]["descriptor_state"], "verified");
        assert_eq!(
            status["result"]["record_head"]["receipt_sha256"],
            receipt(&first)["receipt_sha256"]
        );
        assert_eq!(status["result"]["next_operation"]["available"], true);
    }
    let again = f.audit(&request, 0);
    assert_eq!(again["session_id"], session);
    assert!(again["run_id"].is_null());
    assert!(again["task_id"].is_null());
    assert_eq!(receipt(&again), receipt(&first));
    assert_eq!(f.events(), 1);
    assert_eq!(again["result"]["replayed"], true);
    request["profile"] = json!("standard");
    f.audit(&request, 3);
    assert_eq!(f.events(), 1);
    request["request_id"] = json!("audit-two");
    let second = f.audit(&request, 0);
    assert_ne!(facts(&first)["session_id"], facts(&second)["session_id"]);
    assert_eq!(f.events(), 2);
    assert!(
        f.storage()
            .get_case(&f.case_id)
            .unwrap()
            .scan_runs
            .is_empty()
    );
    let descriptor = f
        .audit_root()
        .join(facts(&second)["session_id"].as_str().unwrap())
        .join("session.json");
    fs::remove_file(&descriptor).unwrap();
    rusqlite::Connection::open(f.data.join("casework.db"))
        .unwrap()
        .execute(
            "DELETE FROM case_events WHERE event_type='source_view.preparation_terminal'",
            [],
        )
        .unwrap();
    assert_eq!(
        f.audit(&request, 3)["error_code"],
        "saved_receipt_not_current"
    );
    assert!(!descriptor.exists());
    assert_eq!(
        fs::read_dir(request["run_directory"].as_str().unwrap())
            .unwrap()
            .count(),
        0
    );
}
#[test]
fn budgets_host_delegation_and_blocked_source_receipt() {
    for (profile, budget, delegation, host, approve, code) in [
        (
            "quick",
            Some(5),
            "available",
            "declared-test-host",
            true,
            Some("budget_cannot_fund_reconnaissance_and_reserves"),
        ),
        (
            "quick",
            Some(6),
            "available",
            "declared-test-host",
            true,
            None,
        ),
        (
            "standard",
            Some(6),
            "available",
            "declared-test-host",
            true,
            Some("budget_cannot_fund_reconnaissance_and_reserves"),
        ),
        (
            "standard",
            Some(7),
            "available",
            "declared-test-host",
            true,
            None,
        ),
        (
            "deep",
            Some(6),
            "available",
            "declared-test-host",
            true,
            Some("budget_cannot_fund_reconnaissance_and_reserves"),
        ),
        (
            "deep",
            Some(7),
            "available",
            "declared-test-host",
            true,
            None,
        ),
        (
            "quick",
            None,
            "unavailable",
            "declared-test-host",
            true,
            Some("delegation_unavailable"),
        ),
        (
            "quick",
            None,
            "unknown",
            "declared-test-host",
            true,
            Some("delegation_unavailable"),
        ),
        (
            "quick",
            None,
            "available",
            "different",
            true,
            Some("host_mismatch"),
        ),
        (
            "quick",
            None,
            "available",
            "declared-test-host",
            false,
            Some("source_view_not_ready"),
        ),
    ] {
        let (f, mut r) = Fixture::setup(approve);
        let before = f
            .storage()
            .source_view_receipt(&f.case_id, "view-request")
            .unwrap()
            .unwrap()
            .digest;
        r["profile"] = json!(profile);
        r["invocation_budget"] = json!(budget);
        r["host"]["delegation"] = json!(delegation);
        r["host"]["host_id"] = json!(host);
        r["host"]["model"] = json!("declared model");
        let v = f.audit(&r, 0);
        if let Some(code) = code {
            assert_eq!(receipt(&v)["result"]["blockers"][0]["code"], code);
            assert_eq!(receipt(&v)["result"]["request"], r);
            assert!(facts(&v).is_null());
            assert!(v["session_id"].is_null());
            let status = f.audit_status("audit-one", false, 0);
            assert_eq!(receipt(&status), receipt(&v));
            assert!(status["session_id"].is_null());
            assert!(status["result"]["descriptor_state"].is_null());
            assert!(!f.audit_root().exists());
            assert_eq!(receipt(&f.audit(&r, 0)), receipt(&v));
            assert_eq!(f.events(), 1);
        } else {
            assert_eq!(receipt(&v)["result"]["status"], "prepared");
        }
        assert_eq!(
            f.storage()
                .source_view_receipt(&f.case_id, "view-request")
                .unwrap()
                .unwrap()
                .digest,
            before
        );
    }
}
#[test]
fn grant_snapshot_and_view_failures_block_without_repair() {
    for change in [
        "expired", "removed", "replaced", "binding", "tampered", "missing", "snapshot",
    ] {
        for replay in [false, true] {
            let (f, r) = Fixture::setup(true);
            let prepared = replay.then(|| f.audit(&r, 0));
            let view = f.view_root();
            let manifest = fs::read(view.join("view.json")).unwrap();
            match change {
                "expired" => f.change_case(|c| {
                    c.scope_grants[0].expires_at = Some(Utc::now() - chrono::Duration::seconds(1))
                }),
                "removed" => f.change_case(|c| c.scope_grants.clear()),
                "replaced" => f.change_case(|c| c.scope_grants[0].id = "replacement".into()),
                "binding" => f.change_case(|c| {
                    c.assets[0].metadata.remove("workspace_snapshot_id");
                }),
                "snapshot" => {
                    let file = f
                        .data
                        .join("artifacts")
                        .join(&f.case_id)
                        .join("workspace-snapshots")
                        .join(&f.reference.storage_id)
                        .join("payload/tree/src/a.rs");
                    writable(&file);
                    fs::write(file, b"damaged canonical bytes").unwrap();
                }
                "tampered" => {
                    let file = view.join("tree/src/a.rs");
                    writable(&file);
                    fs::write(file, b"tampered").unwrap();
                }
                "missing" => {
                    writable(&view);
                    move_directory(&view, view.with_extension("removed"));
                }
                _ => unreachable!(),
            }
            let expected = match change {
                "expired" => "source_authorization_expired",
                "removed" => "source_authorization_missing",
                "replaced" => "grant_changed",
                "binding" => "source_binding_mismatch",
                "tampered" => "view_integrity_failed",
                "snapshot" => "snapshot_integrity_failed",
                _ => "view_missing",
            };
            let v = f.audit(&r, if replay { 3 } else { 0 });
            if replay {
                assert_eq!(v["error_code"], "saved_receipt_not_current");
                assert_eq!(v["reason"], expected);
                assert_eq!(
                    receipt(&f.audit_status("audit-one", false, 0)),
                    receipt(prepared.as_ref().unwrap())
                );
            } else {
                assert_eq!(receipt(&v)["result"]["blockers"][0]["code"], expected);
                assert!(facts(&v).is_null());
                assert!(!f.audit_root().exists());
            }
            assert_eq!(f.events(), 1);
            if change != "missing" {
                assert_eq!(fs::read(view.join("view.json")).unwrap(), manifest);
            } else {
                assert!(!view.exists());
            }
        }
    }
}

#[test]
fn invalid_request_files_and_run_directories_record_nothing() {
    let (f, original) = Fixture::setup(true);
    for (key, value) in [
        ("schema_version", json!("unknown")),
        ("case_id", json!("unknown")),
        ("asset_id", json!("unknown")),
        ("source_view_request_id", json!("unknown")),
        ("expected_source_view_receipt_sha256", json!("0".repeat(64))),
        ("profile", json!("unknown")),
        ("invocation_budget", json!(-1)),
        ("invocation_budget", json!(1.5)),
        ("request_id", json!("x".repeat(129))),
        ("prompt", json!("not supported")),
        ("session_id", json!("caller supplied")),
        ("run_directory", json!("relative")),
        ("run_directory", json!(f.data)),
        ("run_directory", json!(f.data.parent().unwrap())),
        ("run_directory", json!(f.view_root())),
        ("run_directory", json!(f.view_root().join("tree"))),
        (
            "run_directory",
            json!(f.data.parent().unwrap().join("absent")),
        ),
        ("run_directory", json!(f.data.join("casework.db"))),
        (
            "run_directory",
            json!(format!(
                "{}/../host",
                original["run_directory"].as_str().unwrap()
            )),
        ),
        (
            "run_directory",
            json!(format!("{}/.", original["run_directory"].as_str().unwrap())),
        ),
    ] {
        let mut r = original.clone();
        r[key] = value;
        f.audit(&r, 2);
        assert_eq!(f.events(), 0, "{key}");
        assert!(!f.audit_root().exists());
    }
    let mut missing_budget = original.clone();
    missing_budget
        .as_object_mut()
        .unwrap()
        .remove("invocation_budget");
    f.audit(&missing_budget, 2);
    assert_eq!(f.events(), 0);
    for host in [
        json!({"host_id":"declared-test-host","delegation":"bogus"}),
        json!({"host_id":"declared-test-host","delegation":"available","model":"x".repeat(201)}),
        json!({"host_id":"declared-test-host","delegation":"available","credential":"secret"}),
    ] {
        let mut r = original.clone();
        r["host"] = host;
        f.audit(&r, 2);
        assert_eq!(f.events(), 0);
    }
    let path = f.data.parent().unwrap().join("invalid.json");
    for bytes in [
        b"{".to_vec(),
        vec![b' '; 1024 * 1024 + 1],
        serde_json::to_vec(&original)
            .unwrap()
            .into_iter()
            .rev()
            .collect(),
        format!(
            "{{\"request_id\":\"dup\",{}",
            &serde_json::to_string(&original).unwrap()[1..]
        )
        .into_bytes(),
    ] {
        fs::write(&path, bytes).unwrap();
        terminal(
            f.command()
                .args(["provider", "cloudflare", "prepare", "--request"])
                .arg(&path)
                .output()
                .unwrap(),
            2,
        );
        assert_eq!(f.events(), 0);
    }
    #[cfg(unix)]
    {
        let link = f.data.parent().unwrap().join("link");
        std::os::unix::fs::symlink(original["run_directory"].as_str().unwrap(), &link).unwrap();
        let mut r = original;
        r["run_directory"] = json!(link);
        f.audit(&r, 2);
        assert_eq!(f.events(), 0);
    }
}
#[test]
fn status_is_read_only_unknown_ids_and_writer_contention() {
    let (f, mut r) = Fixture::setup(true);
    let v = f.audit(&r, 0);
    f.audit_status("unknown", false, 2);
    f.audit_status("unknown", true, 2);
    let _owner = DataDirectoryExclusiveLease::acquire(&f.data).unwrap();
    assert_eq!(receipt(&f.audit_status("audit-one", false, 0)), receipt(&v));
    r["request_id"] = json!("busy");
    assert_eq!(f.audit(&r, 3)["error_code"], "data_directory_busy");
    assert_eq!(f.events(), 1);
    let absent = f.data.with_file_name("absent");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_ai-security-scanner-cli"))
            .arg("--data-dir")
            .arg(&absent)
            .args([
                "--json",
                "provider",
                "cloudflare",
                "status",
                "--case-id",
                "case",
                "--prepare-request-id",
                "request",
            ])
            .output()
            .unwrap()
    };
    assert!(!run().status.success());
    assert!(!absent.exists());
    fs::create_dir(&absent).unwrap();
    let db = absent.join("casework.db");
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch("PRAGMA user_version=999999; CREATE TABLE marker(value TEXT);")
        .unwrap();
    let before = fs::read(&db).unwrap();
    assert!(!run().status.success());
    assert_eq!(fs::read(&db).unwrap(), before);
    assert_eq!(fs::read_dir(absent).unwrap().count(), 1);
}
#[test]
fn committed_descriptor_publication_failure_recovers_without_new_identities() {
    let (f, r) = Fixture::setup(true);
    // A non-directory at the publication parent fails only after the event commit.
    fs::write(f.audit_root(), b"obstacle").unwrap();
    f.audit(&r, 4);
    let saved = f.audit_status("audit-one", false, 0);
    assert_eq!(saved["result"]["descriptor_state"], "mismatch");
    fs::remove_file(f.audit_root()).unwrap();
    let missing = f.audit_status("audit-one", false, 0);
    assert_eq!(missing["result"]["descriptor_state"], "missing");
    let recovered = f.audit(&r, 0);
    assert_eq!(receipt(&recovered), receipt(&saved));
    assert_eq!(f.events(), 1);
    let path = f
        .audit_root()
        .join(facts(&saved)["session_id"].as_str().unwrap())
        .join("session.json");
    let expected = fs::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    assert_eq!(
        f.audit_status("audit-one", false, 0)["result"]["descriptor_state"],
        "missing"
    );
    f.audit(&r, 0);
    assert_eq!(fs::read(&path).unwrap(), expected);
    fs::write(&path, b"different bytes").unwrap();
    assert_eq!(
        f.audit_status("audit-one", false, 0)["result"]["descriptor_state"],
        "mismatch"
    );
    f.audit(&r, 4);
    assert_eq!(fs::read(&path).unwrap(), b"different bytes");
    assert_eq!(f.events(), 1);
}
#[cfg(unix)]
#[test]
fn lost_output_recovers_and_descriptor_symlink_is_not_followed() {
    let (f, r) = Fixture::setup(true);
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let mut child = f
        .audit_command(&r)
        .stdout(writer)
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(4));
    let saved = f.audit_status("audit-one", false, 0);
    assert_eq!(receipt(&saved)["result"]["status"], "prepared");
    let path = f
        .audit_root()
        .join(facts(&saved)["session_id"].as_str().unwrap())
        .join("session.json");
    let external = f.data.with_file_name("external");
    fs::write(&external, fs::read(&path).unwrap()).unwrap();
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&external, &path).unwrap();
    assert_eq!(
        f.audit_status("audit-one", false, 0)["result"]["descriptor_state"],
        "mismatch"
    );
    f.audit(&r, 4);
    assert!(
        fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn archive_omission_restore_history_and_confirmed_deletion() {
    let (mut f, r) = Fixture::setup(true);
    let saved = f.audit(&r, 0);
    let checkpoint_request = f.checkpoint_request(
        &saved,
        json!({"type":"issue","assignments":[{"role":"reconnaissance_baseline"}]}),
    );
    let checkpoint = f.checkpoint(&checkpoint_request, 0);
    let archive = f.data.with_file_name("case.tar.gz");
    let created = f
        .command()
        .args([
            "archive",
            "create",
            "--case-id",
            &f.case_id,
            "--acknowledge-sensitive-data",
            "--include-source-snapshots",
            "--destination",
        ])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let verified = f
        .command()
        .args(["archive", "verify", "--archive"])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(verified.status.success());
    let v: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(
        v["omissions"]
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
    let restored = f.data.with_file_name("restored");
    let output = f
        .command()
        .args(["archive", "restore", "--archive"])
        .arg(&archive)
        .args(["--acknowledge-sensitive-data", "--destination"])
        .arg(&restored)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let original = f.data.clone();
    f.data = restored;
    let status = f.audit_status("audit-one", false, 0);
    assert_eq!(receipt(&status), receipt(&saved));
    assert_eq!(
        status["result"]["entries"][0],
        checkpoint["result"]["entry"]
    );
    assert_eq!(
        f.checkpoint(&checkpoint_request, 2)["error_code"],
        "restored_session_inert"
    );
    assert_eq!(status["result"]["descriptor_state"], "missing");
    assert_eq!(f.audit(&r, 2)["error_code"], "restored_session_inert");
    assert!(!f.audit_root().exists());
    f.data = original;
    let storage = f.storage();
    let engines = ai_security_scanner_lib::registry::EngineRegistry::load_builtin().unwrap();
    let adapters = ai_security_scanner_lib::adapters::builtin_adapter_registry().unwrap();
    let artifacts = f.data.join("artifacts");
    let service = ai_security_scanner_lib::case_service::CaseService::new(
        &storage,
        &engines,
        &adapters,
        &artifacts,
        f.data.join("signing-key"),
    );
    let deletion = service.delete_case(&f.case_id).unwrap();
    assert!(f.audit_root().exists());
    service
        .delete_case_artifacts(
            &f.case_id,
            &deletion.artifacts.exact_path,
            &format!("DELETE {}", f.case_id),
        )
        .unwrap();
    assert!(!f.audit_root().exists());
    assert_eq!(f.events(), 0);
}

#[cfg(unix)]
#[test]
fn committed_event_with_missing_descriptor_requires_current_view_before_republication() {
    use std::os::unix::fs::PermissionsExt;
    let (f, r) = Fixture::setup(true);
    fs::create_dir(f.audit_root()).unwrap();
    fs::set_permissions(f.audit_root(), fs::Permissions::from_mode(0o500)).unwrap();
    f.audit(&r, 4);
    let saved = f.audit_status("audit-one", false, 0);
    assert_eq!(saved["result"]["descriptor_state"], "missing");
    fs::set_permissions(f.audit_root(), fs::Permissions::from_mode(0o700)).unwrap();
    let view = f.view_root();
    move_directory(&view, view.with_extension("held"));
    assert_eq!(f.audit(&r, 3)["reason"], "view_missing");
    assert_eq!(fs::read_dir(f.audit_root()).unwrap().count(), 0);
    move_directory(view.with_extension("held"), &view);
    assert_eq!(receipt(&f.audit(&r, 0)), receipt(&saved));
    assert_eq!(
        f.audit_status("audit-one", false, 0)["result"]["descriptor_state"],
        "verified"
    );
    assert_eq!(f.events(), 1);
}

#[test]
fn unavailable_run_directory_rejects_new_request_and_marks_prepared_replay_stale() {
    let (f, request) = Fixture::setup(true);
    let host = Path::new(request["run_directory"].as_str().unwrap());
    fs::remove_dir(host).unwrap();
    f.audit(&request, 2);
    assert_eq!(f.events(), 0);
    assert!(!f.audit_root().exists());

    fs::create_dir(host).unwrap();
    let saved = f.audit(&request, 0);
    let descriptor = f
        .audit_root()
        .join(facts(&saved)["session_id"].as_str().unwrap())
        .join("session.json");
    fs::remove_file(&descriptor).unwrap();
    fs::remove_dir(host).unwrap();
    for replaced_with_file in [false, true] {
        if replaced_with_file {
            fs::write(host, b"not a directory").unwrap();
        }
        let replay = f.audit(&request, 3);
        assert_eq!(replay["error_code"], "saved_receipt_not_current");
        assert_eq!(replay["reason"], "run_directory_unavailable");
        assert_eq!(f.events(), 1);
        assert!(!descriptor.exists());
        assert_eq!(
            receipt(&f.audit_status("audit-one", false, 0)),
            receipt(&saved)
        );
    }
}

#[test]
fn tampered_blocked_request_in_stored_event_is_unreadable() {
    let (f, mut request) = Fixture::setup(true);
    request["invocation_budget"] = json!(5);
    let saved = f.audit(&request, 0);
    let mut tampered = receipt(&saved).clone();
    tampered["result"]["request"]["profile"] = json!("deep");
    rusqlite::Connection::open(f.data.join("casework.db"))
        .unwrap()
        .execute(
            "UPDATE case_events SET payload_json=?1 WHERE event_type='cloudflare_audit.preparation_terminal'",
            [serde_json::to_string(&tampered).unwrap()],
        )
        .unwrap();
    f.audit_status("audit-one", false, 4);
    f.audit(&request, 4);
    assert_eq!(f.events(), 1);
    assert!(!f.audit_root().exists());
}

#[cfg(unix)]
#[test]
fn preparation_refuses_linked_ancestor() {
    let (f, mut request) = Fixture::setup(true);
    let host = Path::new(request["run_directory"].as_str().unwrap());
    let link = host.with_file_name("linked-parent");
    std::os::unix::fs::symlink(host.parent().unwrap(), &link).unwrap();
    request["run_directory"] = json!(link.join("host"));
    f.audit(&request, 2);
    assert_eq!(f.events(), 0);
    assert!(!f.audit_root().exists());
}
