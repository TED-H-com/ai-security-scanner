use super::fixture::*;

#[test]
fn checkpoint_batch_identity_replay_conflict_and_head_retry() {
    let (f, r) = Fixture::setup(true);
    let prepared = f.audit(&r, 0);
    let descriptor = f
        .audit_root()
        .join(prepared["session_id"].as_str().unwrap())
        .join("session.json");
    let bytes = fs::read(&descriptor).unwrap();
    let mut request = f.checkpoint_request(
        &prepared,
        json!({"type":"issue","assignments":[
        {"role":"reconnaissance_baseline"},{"role":"hunter","wave":1}]}),
    );
    let first = f.checkpoint(&request, 0);
    let entry = &first["result"]["entry"];
    let assignments = entry["content"]["assignments"].as_array().unwrap();
    assert_eq!(assignments[0]["agent_id"], "a0001-recon");
    assert_eq!(assignments[1]["agent_id"], "a0002-hunter");
    assert_ne!(
        assignments[0]["assignment_id"],
        assignments[1]["assignment_id"]
    );
    assert_eq!(assignments[0]["ordinal"], 1);
    assert_eq!(assignments[1]["ordinal"], 2);
    assert_eq!(entry["sequence"], 1);
    assert_eq!(
        first["result"]["budget"],
        json!({"limit":null,"issued":2,"remaining":null})
    );
    let replay = f.checkpoint(&request, 0);
    assert_eq!(replay["result"]["entry"], *entry);
    assert_eq!(replay["result"]["replayed"], true);
    let before_refusal = f.storage().get_case(&f.case_id).unwrap().storage_revision();
    request["action"]["assignments"][0]["role"] = json!("reconnaissance_focused");
    assert_eq!(f.checkpoint(&request, 3)["error_code"], "request_conflict");
    request["request_id"] = json!("second");
    assert_eq!(f.checkpoint(&request, 3)["error_code"], "stale_head");
    assert_eq!(f.record_events(), 1);
    assert_eq!(
        f.storage().get_case(&f.case_id).unwrap().storage_revision(),
        before_refusal
    );
    request["expected_head_sha256"] = entry["entry_sha256"].clone();
    let second = f.checkpoint(&request, 0);
    assert_eq!(second["result"]["entry"]["sequence"], 2);
    assert_eq!(f.record_events(), 2);
    let mut another = r.clone();
    another["request_id"] = json!("another-run");
    let prepared_again = f.audit(&another, 0);
    let mut other_request = f.checkpoint_request(
        &prepared_again,
        json!({"type":"issue","assignments":[{"role":"reconnaissance_baseline"}]}),
    );
    let other = f.checkpoint(&other_request, 0);
    assert_eq!(
        other["result"]["entry"]["content"]["assignments"][0]["agent_id"],
        "a0001-recon"
    );
    other_request["request_id"] = json!("foreign-replacement");
    other_request["expected_head_sha256"] = other["result"]["entry"]["entry_sha256"].clone();
    other_request["action"]["assignments"][0]["replaces"] = assignments[0]["assignment_id"].clone();
    assert_eq!(
        f.checkpoint(&other_request, 2)["error_code"],
        "unknown_assignment"
    );
    for a in assignments {
        let agent = a["agent_id"].as_str().unwrap();
        assert!(
            agent.len() <= 64
                && agent
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
        );
    }
    assert_eq!(fs::read(descriptor).unwrap(), bytes);
    assert_eq!(
        fs::read_dir(r["run_directory"].as_str().unwrap())
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn checkpoint_role_fields_order_and_profile_rules() {
    for (profile, assignments, code) in [
        (
            "standard",
            json!([{ "role":"hunter" }]),
            "role_fields_invalid",
        ),
        (
            "standard",
            json!([{ "role":"post_wave_critic" }]),
            "role_fields_invalid",
        ),
        (
            "standard",
            json!([{ "role":"hunter","wave":0 }]),
            "role_fields_invalid",
        ),
        (
            "quick",
            json!([{ "role":"hunter","wave":2 }]),
            "quick_wave_limit",
        ),
        (
            "standard",
            json!([{ "role":"hunter","wave":2 }]),
            "wave_skipped",
        ),
        (
            "standard",
            json!([{ "role":"post_wave_critic","wave":1 }]),
            "critic_requires_hunters",
        ),
        (
            "quick",
            json!([{ "role":"final_clean_critic" }]),
            "quick_final_clean_unavailable",
        ),
        (
            "standard",
            json!([{ "role":"candidate_verifier" }]),
            "role_fields_invalid",
        ),
        (
            "standard",
            json!([{ "role":"candidate_verifier","fingerprint":"-invalid" }]),
            "fingerprint_invalid",
        ),
        (
            "standard",
            json!([{ "role":"candidate_verifier","fingerprint":"has spaces" }]),
            "fingerprint_invalid",
        ),
        (
            "standard",
            json!([{ "role":"candidate_verifier","fingerprint":"é" }]),
            "fingerprint_invalid",
        ),
        (
            "standard",
            json!([{ "role":"candidate_verifier","fingerprint":"a".repeat(4097) }]),
            "fingerprint_invalid",
        ),
        (
            "standard",
            json!([{ "role":"hunter","wave":1 },{"role":"post_wave_critic","wave":1},{"role":"hunter","wave":1}]),
            "wave_closed",
        ),
    ] {
        let (f, mut r) = Fixture::setup(true);
        r["profile"] = json!(profile);
        let prepared = f.audit(&r, 0);
        let request =
            f.checkpoint_request(&prepared, json!({"type":"issue","assignments":assignments}));
        assert_eq!(f.checkpoint(&request, 2)["error_code"], code);
        assert_eq!(f.record_events(), 0);
    }
    let (f, mut r) = Fixture::setup(true);
    r["profile"] = json!("standard");
    let prepared = f.audit(&r, 0);
    for role in [
        "reconnaissance_baseline",
        "reconnaissance_focused",
        "hunter",
        "post_wave_critic",
        "final_clean_critic",
        "candidate_verifier",
    ] {
        let mut spec = json!({"role":role});
        if ["hunter", "post_wave_critic"].contains(&role) {
            spec["wave"] = json!(1);
        }
        if role == "candidate_verifier" {
            spec["fingerprint"] = json!("valid");
        }
        let field = if ["hunter", "post_wave_critic"].contains(&role) {
            "fingerprint"
        } else {
            "wave"
        };
        spec[field] = if field == "wave" {
            json!(1)
        } else {
            json!("foreign")
        };
        let request = f.checkpoint_request(&prepared, json!({"type":"issue","assignments":[spec]}));
        assert_eq!(
            f.checkpoint(&request, 2)["error_code"],
            "role_fields_invalid",
            "{role}"
        );
    }
    let request = f.checkpoint_request(
        &prepared,
        json!({"type":"issue","assignments":[
        {"role":"hunter","wave":1},{"role":"post_wave_critic","wave":1},
        {"role":"hunter","wave":2},{"role":"final_clean_critic"},
        {"role":"candidate_verifier","fingerprint":"A._:/@+-9"}]}),
    );
    f.checkpoint(&request, 0);
    assert_eq!(f.record_events(), 1);
    let status = f.audit_status(prepared["session_id"].as_str().unwrap(), true, 0);
    assert_eq!(status["result"]["entry_count"], 1);
    assert_eq!(status["result"]["record_head"]["sequence"], 1);
    assert_eq!(status["result"]["counts_by_role"]["hunter"], 2);
    assert_eq!(status["result"]["assignments"][0]["role"], "hunter");
    assert_eq!(
        status["result"]["assignments"][4]["fingerprint"],
        "A._:/@+-9"
    );
    assert_eq!(status["result"]["assignments"][0]["state"], "open");
    assert_eq!(
        status["result"]["next_operation"]["actions"],
        json!(["issue", "interrupt", "submit_documents", "submit_output"])
    );
    assert_eq!(status["result"]["document_capture"]["available"], true);
}
#[test]
fn checkpoint_budget_examples_and_total_spend() {
    for (profile, budget, baselines, focused, code) in [
        ("quick", Some(6), 4, false, 2),
        ("quick", Some(7), 4, false, 0),
        ("standard", Some(7), 4, false, 2),
        ("standard", Some(8), 4, false, 0),
        ("quick", Some(6), 0, true, 2),
        ("quick", Some(7), 0, true, 0),
        ("quick", None, 4, false, 0),
    ] {
        let (f, mut r) = Fixture::setup(true);
        r["profile"] = json!(profile);
        r["invocation_budget"] = json!(budget);
        let prepared = f.audit(&r, 0);
        let mut request = f.checkpoint_request(&prepared, json!({"type":"issue","assignments":vec![json!({"role":"reconnaissance_baseline"});baselines]}));
        if baselines > 0 {
            let first = f.checkpoint(&request, 0);
            request["expected_head_sha256"] = first["result"]["entry"]["entry_sha256"].clone();
            request["request_id"] = json!("next");
        }
        request["action"]["assignments"] = if focused {
            json!([{"role":"reconnaissance_focused"}])
        } else {
            json!([{"role":"hunter","wave":1}])
        };
        let result = f.checkpoint(&request, code);
        if code == 2 {
            assert_eq!(
                result["error_code"],
                "budget_cannot_reserve_critics_and_validation"
            );
        }
    }
    let (f, mut r) = Fixture::setup(true);
    r["invocation_budget"] = json!(6);
    let prepared = f.audit(&r, 0);
    let request = f.checkpoint_request(
        &prepared,
        json!({"type":"issue","assignments":vec![json!({"role":"reconnaissance_baseline"});7]}),
    );
    assert_eq!(
        f.checkpoint(&request, 2)["error_code"],
        "invocation_budget_exhausted"
    );
    assert_eq!(f.record_events(), 0);
}

#[test]
fn checkpoint_interrupt_replacement_and_interrupted_budget_reserve() {
    let (f, mut r) = Fixture::setup(true);
    r["invocation_budget"] = json!(7);
    let prepared = f.audit(&r, 0);
    let mut specs = vec![json!({"role":"reconnaissance_baseline"}); 4];
    specs.push(json!({"role":"candidate_verifier","fingerprint":"CVE:synthetic"}));
    let mut request = f.checkpoint_request(&prepared, json!({"type":"issue","assignments":specs}));
    let issued = f.checkpoint(&request, 0);
    let id = issued["result"]["entry"]["content"]["assignments"][4]["assignment_id"].clone();
    request["expected_head_sha256"] = issued["result"]["entry"]["entry_sha256"].clone();
    request["request_id"] = json!("interrupt");
    request["action"] = json!({"type":"issue","assignments":[{"role":"candidate_verifier","fingerprint":"CVE:synthetic","replaces":id}]});
    assert_eq!(
        f.checkpoint(&request, 2)["error_code"],
        "replacement_not_interrupted"
    );
    request["action"] =
        json!({"type":"interrupt","assignment_id":"unknown","reason":"host cancelled"});
    assert_eq!(
        f.checkpoint(&request, 2)["error_code"],
        "unknown_assignment"
    );
    request["action"]["assignment_id"] = id.clone();
    for reason in [
        "".to_string(),
        "x".repeat(513),
        "newline\n".into(),
        "nul\0".into(),
        "é".repeat(257),
    ] {
        request["action"]["reason"] = json!(reason);
        assert_eq!(
            f.checkpoint(&request, 2)["error_code"],
            "interruption_reason_invalid"
        );
    }
    request["action"]["reason"] = json!("host cancelled");
    let interrupted = f.checkpoint(&request, 0);
    assert_eq!(
        f.checkpoint(&request, 0)["result"]["entry"],
        interrupted["result"]["entry"]
    );
    request["expected_head_sha256"] = interrupted["result"]["entry"]["entry_sha256"].clone();
    request["request_id"] = json!("next");
    assert_eq!(f.checkpoint(&request, 2)["error_code"], "assignment_closed");
    request["action"] = json!({"type":"issue","assignments":[{"role":"hunter","wave":1}]});
    assert_eq!(
        f.checkpoint(&request, 2)["error_code"],
        "budget_cannot_reserve_critics_and_validation"
    );
    for spec in [
        json!({"role":"reconnaissance_baseline","replaces":id}),
        json!({"role":"candidate_verifier","fingerprint":"different","replaces":id}),
    ] {
        request["action"]["assignments"] = json!([spec]);
        assert_eq!(
            f.checkpoint(&request, 2)["error_code"],
            "replacement_mismatch"
        );
    }
    request["action"]["assignments"] =
        json!([{"role":"candidate_verifier","fingerprint":"CVE:synthetic","replaces":id}]);
    let replaced = f.checkpoint(&request, 0);
    let replacement =
        replaced["result"]["entry"]["content"]["assignments"][0]["assignment_id"].clone();
    request["request_id"] = json!("again");
    request["expected_head_sha256"] = replaced["result"]["entry"]["entry_sha256"].clone();
    assert_eq!(
        f.checkpoint(&request, 2)["error_code"],
        "assignment_already_replaced"
    );
    let status = f.audit_status(prepared["session_id"].as_str().unwrap(), true, 0);
    assert_eq!(
        status["result"]["budget"],
        json!({"limit":7,"issued":6,"remaining":1})
    );
    assert_eq!(status["result"]["assignments"][4]["state"], "interrupted");
    assert_eq!(
        status["result"]["assignments"][4]["interruption_reason"],
        "host cancelled"
    );
    assert_eq!(
        status["result"]["assignments"][4]["replaced_by"],
        replacement
    );
    assert_eq!(status["result"]["assignments"][5]["replaces"], id);
    assert_eq!(f.record_events(), 3);
}
#[test]
fn checkpoint_authority_replay_lease_and_no_view_or_host_file_reads() {
    for change in ["expired", "removed", "replaced", "binding"] {
        for replay in [false, true] {
            let (f, r) = Fixture::setup(true);
            let prepared = f.audit(&r, 0);
            let request = f.checkpoint_request(
                &prepared,
                json!({"type":"issue","assignments":[{"role":"reconnaissance_baseline"}]}),
            );
            let first = replay.then(|| f.checkpoint(&request, 0));
            f.change_case(|c| match change {
                "expired" => {
                    c.scope_grants[0].expires_at = Some(Utc::now() - chrono::Duration::seconds(1))
                }
                "removed" => c.scope_grants.clear(),
                "replaced" => c.scope_grants[0].id = "other".into(),
                _ => {
                    c.assets[0].metadata.remove("workspace_snapshot_id");
                }
            });
            let rejected = f.checkpoint(&request, 3);
            assert_eq!(rejected["error_code"], "saved_receipt_not_current");
            assert_eq!(
                rejected["reason"],
                match change {
                    "expired" => "source_authorization_expired",
                    "removed" => "source_authorization_missing",
                    "replaced" => "grant_changed",
                    _ => "source_binding_mismatch",
                }
            );
            assert_eq!(f.record_events(), usize::from(replay));
            if let Some(first) = first {
                assert_eq!(
                    f.audit_status("audit-one", false, 0)["result"]["entries"][0],
                    first["result"]["entry"]
                );
            }
        }
    }
    let (f, r) = Fixture::setup(true);
    let prepared = f.audit(&r, 0);
    let request = f.checkpoint_request(
        &prepared,
        json!({"type":"issue","assignments":[{"role":"reconnaissance_baseline"}]}),
    );
    {
        let _lease = DataDirectoryExclusiveLease::acquire(&f.data).unwrap();
        assert_eq!(
            f.checkpoint(&request, 3)["error_code"],
            "data_directory_busy"
        );
        f.audit_status("audit-one", false, 0);
    }
    // Source-view files are not read by checkpoints; the run directory must still open.
    let view = f.view_root();
    writable(&view);
    move_directory(&view, view.with_extension("held"));
    f.checkpoint(&request, 0);
    fs::remove_dir(r["run_directory"].as_str().unwrap()).unwrap();
    assert_eq!(
        f.checkpoint(&request, 3)["reason"],
        "run_directory_unavailable"
    );
    f.audit_status("audit-one", false, 0);
    assert!(!view.exists());
    assert!(!Path::new(r["run_directory"].as_str().unwrap()).exists());
}
#[test]
fn checkpoint_strict_requests_unknown_and_blocked_preparations() {
    let (f, mut r) = Fixture::setup(true);
    r["invocation_budget"] = json!(5);
    let prepared = f.audit(&r, 0);
    let mut request = f.checkpoint_request(
        &prepared,
        json!({"type":"issue","assignments":[{"role":"reconnaissance_baseline"}]}),
    );
    request["session_id"] = json!("audit-one");
    assert_eq!(
        f.checkpoint(&request, 2)["error_code"],
        "blocked_preparation"
    );
    request["session_id"] = json!("unknown");
    assert_eq!(
        f.checkpoint(&request, 2)["error_code"],
        "unknown_preparation"
    );
    for spec in [
        json!({"role":"unknown_verifier"}),
        json!({"role":"reconnaissance_baseline","wave":null}),
        json!({"role":"reconnaissance_baseline","assignment_id":"supplied"}),
        json!({"role":"reconnaissance_baseline","agent_id":"supplied"}),
        json!({"role":"reconnaissance_baseline","issued_at":"supplied"}),
        json!({"role":"reconnaissance_baseline","ordinal":1}),
    ] {
        request["action"]["assignments"] = json!([spec]);
        assert_eq!(f.checkpoint(&request, 2)["error_code"], "invalid_request");
    }
    let path = f.data.parent().unwrap().join("invalid-checkpoint.json");
    for (bytes, code) in [
        (vec![b' '; 1024 * 1024 + 1], "request_file_limit"),
        (
            b"{\"request_id\":\"x\",\"request_id\":\"x\"}".to_vec(),
            "invalid_request",
        ),
    ] {
        fs::write(&path, bytes).unwrap();
        let value = terminal(
            f.command()
                .args(["provider", "cloudflare", "checkpoint", "--request"])
                .arg(&path)
                .output()
                .unwrap(),
            2,
        );
        assert_eq!(value["error_code"], code);
    }
    assert_eq!(f.record_events(), 0);
}
#[cfg(unix)]
#[test]
fn checkpoint_lost_output_commits_and_status_recovers_entry() {
    let (f, r) = Fixture::setup(true);
    let prepared = f.audit(&r, 0);
    let request = f.checkpoint_request(
        &prepared,
        json!({"type":"issue","assignments":[{"role":"reconnaissance_baseline"}]}),
    );
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let mut child = f
        .checkpoint_command(&request)
        .stdout(writer)
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(4));
    let status = f.audit_status("audit-one", false, 0);
    assert_eq!(status["result"]["entry_count"], 1);
    assert_eq!(
        f.checkpoint(&request, 0)["result"]["entry"],
        status["result"]["entries"][0]
    );
}
#[test]
fn checkpoint_and_status_fail_closed_on_tampering_deleted_middle_and_swapped_entries() {
    for mutation in ["tamper", "delete", "swap"] {
        let (f, r) = Fixture::setup(true);
        let prepared = f.audit(&r, 0);
        let mut request = f.checkpoint_request(
            &prepared,
            json!({"type":"issue","assignments":[{"role":"reconnaissance_baseline"}]}),
        );
        for n in 0..3 {
            request["request_id"] = json!(format!("entry{n}"));
            let saved = f.checkpoint(&request, 0);
            request["expected_head_sha256"] = saved["result"]["entry"]["entry_sha256"].clone();
        }
        let connection = rusqlite::Connection::open(f.data.join("casework.db")).unwrap();
        let rows: Vec<(i64,String)> = connection.prepare("SELECT sequence,payload_json FROM case_events WHERE event_type='cloudflare_audit.record_entry' ORDER BY sequence").unwrap()
            .query_map([],|r| Ok((r.get(0)?,r.get(1)?))).unwrap().map(Result::unwrap).collect();
        match mutation {
            "tamper" => {
                connection
                    .execute(
                        "UPDATE case_events SET payload_json=?1 WHERE sequence=?2",
                        rusqlite::params![
                            rows[0].1.replace("a0001-recon", "a0001-focus"),
                            rows[0].0
                        ],
                    )
                    .unwrap();
            }
            "delete" => {
                connection
                    .execute("DELETE FROM case_events WHERE sequence=?1", [rows[1].0])
                    .unwrap();
            }
            _ => {
                for (to, from) in [(0, 1), (1, 0)] {
                    connection
                        .execute(
                            "UPDATE case_events SET payload_json=?1 WHERE sequence=?2",
                            rusqlite::params![rows[from].1, rows[to].0],
                        )
                        .unwrap();
                }
            }
        }
        f.audit_status("audit-one", false, 4);
        f.checkpoint(&request, 4);
        assert_eq!(f.record_events(), if mutation == "delete" { 2 } else { 3 });
    }
}

#[test]
fn checkpoint_batch_run_and_total_byte_limits() {
    let (f, r) = Fixture::setup(true);
    let prepared = f.audit(&r, 0);
    let mut request = f.checkpoint_request(&prepared, json!({"type":"issue","assignments":[]}));
    for n in [0, 65] {
        request["action"]["assignments"] =
            json!(vec![json!({"role":"reconnaissance_baseline"}); n]);
        assert_eq!(
            f.checkpoint(&request, 2)["error_code"],
            "assignment_batch_limit"
        );
    }
    for n in 0..32 {
        request["request_id"] = json!(format!("batch{n}"));
        request["action"]["assignments"] = json!(vec![
            json!({"role":"reconnaissance_baseline"});
            if n == 31 { 16 } else { 64 }
        ]);
        let saved = f.checkpoint(&request, 0);
        request["expected_head_sha256"] = saved["result"]["entry"]["entry_sha256"].clone();
    }
    request["request_id"] = json!("over");
    request["action"]["assignments"] = json!([{"role":"reconnaissance_baseline"}]);
    assert_eq!(
        f.checkpoint(&request, 2)["error_code"],
        "assignment_run_limit"
    );
    assert_eq!(f.record_events(), 32);
    let (f, r) = Fixture::setup(true);
    let prepared = f.audit(&r, 0);
    let mut request = f.checkpoint_request(&prepared,json!({"type":"issue","assignments":vec![json!({"role":"candidate_verifier","fingerprint":"a".repeat(4096)});64]}));
    let mut count = 0;
    loop {
        request["request_id"] = json!(format!("bytes{count}"));
        let output = f.checkpoint_command(&request).output().unwrap();
        if output.status.code() == Some(2) {
            assert_eq!(terminal(output, 2)["error_code"], "record_bytes_limit");
            break;
        }
        let saved = terminal(output, 0);
        request["expected_head_sha256"] = saved["result"]["entry"]["entry_sha256"].clone();
        count += 1;
        assert!(count < 32);
    }
    assert!(count > 0);
    assert_eq!(f.record_events(), count);
}

#[test]
fn checkpoint_record_only_archive_still_lists_audit_omission() {
    let (f, r) = Fixture::setup(true);
    let prepared = f.audit(&r, 0);
    let request = f.checkpoint_request(
        &prepared,
        json!({"type":"issue","assignments":[{"role":"reconnaissance_baseline"}]}),
    );
    f.checkpoint(&request, 0);
    rusqlite::Connection::open(f.data.join("casework.db"))
        .unwrap()
        .execute(
            "DELETE FROM case_events WHERE event_type='cloudflare_audit.preparation_terminal'",
            [],
        )
        .unwrap();
    // Exercise the event-only omission path with neither preparation nor descriptor present.
    fs::remove_dir_all(f.audit_root()).unwrap();
    let archive = f.data.with_file_name("only-events.tar.gz");
    let output = f
        .command()
        .args([
            "archive",
            "create",
            "--case-id",
            &f.case_id,
            "--acknowledge-sensitive-data",
            "--destination",
        ])
        .arg(&archive)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verified = f
        .command()
        .args(["archive", "verify", "--archive"])
        .arg(archive)
        .output()
        .unwrap();
    assert!(verified.status.success());
    let v: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert!(v["omissions"].as_array().unwrap().iter().any(|s| {
        s.as_str()
            .unwrap()
            .contains("audit records are not included")
    }));
}

#[test]
fn checkpoint_wave_replacement_and_replay_use_current_head() {
    let (f, mut r) = Fixture::setup(true);
    r["profile"] = json!("standard");
    let prepared = f.audit(&r, 0);
    let mut request = f.checkpoint_request(
        &prepared,
        json!({"type":"issue","assignments":[{"role":"hunter","wave":1}]}),
    );
    let original = request.clone();
    let issued = f.checkpoint(&request, 0);
    let id = issued["result"]["entry"]["content"]["assignments"][0]["assignment_id"].clone();
    request["expected_head_sha256"] = issued["result"]["entry"]["entry_sha256"].clone();
    request["request_id"] = json!("interrupt");
    request["action"] = json!({"type":"interrupt","assignment_id":id,"reason":"abandoned"});
    let interrupted = f.checkpoint(&request, 0);
    request["expected_head_sha256"] = interrupted["result"]["entry"]["entry_sha256"].clone();
    request["request_id"] = json!("replacement");
    request["action"] =
        json!({"type":"issue","assignments":[{"role":"hunter","wave":2,"replaces":id}]});
    assert_eq!(
        f.checkpoint(&request, 2)["error_code"],
        "replacement_mismatch"
    );
    request["action"]["assignments"][0]["wave"] = json!(1);
    let replaced = f.checkpoint(&request, 0);
    let replayed = f.checkpoint(&original, 0);
    assert_eq!(replayed["result"]["entry"], issued["result"]["entry"]);
    assert_eq!(
        replayed["result"]["record_head"],
        replaced["result"]["record_head"]
    );
    assert_eq!(f.record_events(), 3);
}

#[test]
fn checkpoint_actions_require_available_run_directory_even_on_replay() {
    for kind in ["removed", "file", "link"] {
        if kind == "link" && !cfg!(unix) {
            continue;
        }
        let (f, request) = Fixture::setup(true);
        let prepared = f.audit(&request, 0);
        let issue = f.checkpoint_request(
            &prepared,
            json!({"type":"issue","assignments":[{"role":"reconnaissance_baseline"}]}),
        );
        let saved = f.checkpoint(&issue, 0);
        let mut interrupt = issue.clone();
        interrupt["request_id"] = json!("interrupt");
        interrupt["expected_head_sha256"] = saved["result"]["record_head"]["entry_sha256"].clone();
        interrupt["action"] = json!({"type":"interrupt","assignment_id":saved["result"]["entry"]["content"]["assignments"][0]["assignment_id"],"reason":"host stopped"});
        let host = Path::new(request["run_directory"].as_str().unwrap());
        fs::remove_dir(host).unwrap();
        if kind == "file" {
            fs::write(host, b"file").unwrap();
        }
        #[cfg(unix)]
        if kind == "link" {
            std::os::unix::fs::symlink(host.parent().unwrap(), host).unwrap();
        }
        for action in [&issue, &interrupt] {
            let rejected = f.checkpoint(action, 3);
            assert_eq!(rejected["error_code"], "saved_receipt_not_current");
            assert_eq!(rejected["reason"], "run_directory_unavailable");
        }
        assert_eq!(f.record_events(), 1);
    }
}
