use super::fixture::*;
use sha2::{Digest, Sha256};
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn host(prep: &Value) -> &Path {
    Path::new(prep["run_directory"].as_str().unwrap())
}
fn objects(f: &Fixture, prepared: &Value) -> PathBuf {
    f.audit_root()
        .join(prepared["session_id"].as_str().unwrap())
        .join("objects")
}
fn next(f: &Fixture, prepared: &Value, previous: &Value, id: &str, action: Value) -> Value {
    let mut r = f.checkpoint_request(prepared, action);
    r["request_id"] = json!(id);
    r["expected_head_sha256"] = previous["result"]["record_head"]["entry_sha256"].clone();
    r
}
fn issue(f: &Fixture, prepared: &Value, roles: Value) -> Value {
    f.checkpoint(
        &f.checkpoint_request(prepared, json!({"type":"issue","assignments":roles})),
        0,
    )
}
fn output(
    f: &Fixture,
    prep: &Value,
    prepared: &Value,
    issued: &Value,
    index: usize,
    bytes: &[u8],
) -> Value {
    let a = &issued["result"]["entry"]["content"]["assignments"][index];
    let path = format!(
        "agents/{}/artifacts/output.json",
        a["agent_id"].as_str().unwrap()
    );
    let file = host(prep).join(&path);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(file, bytes).unwrap();
    next(
        f,
        prepared,
        issued,
        "output",
        json!({"type":"submit_output","assignment_id":a["assignment_id"],"output":{"path":path}}),
    )
}
#[test]
fn reconnaissance_hunter_and_critics_close_once_and_store_exact_bytes() {
    for role in [
        "reconnaissance_baseline",
        "reconnaissance_focused",
        "hunter",
        "post_wave_critic",
        "final_clean_critic",
    ] {
        let (f, mut prep) = Fixture::setup(true);
        prep["profile"] = json!("standard");
        let prepared = f.audit(&prep, 0);
        let mut spec = json!({"role":role});
        if ["hunter", "post_wave_critic"].contains(&role) {
            spec["wave"] = json!(1);
        }
        let roles = if role == "post_wave_critic" {
            json!([{"role":"hunter","wave":1},spec])
        } else {
            json!([spec])
        };
        let index = roles.as_array().unwrap().len() - 1;
        let issued = issue(&f, &prepared, roles);
        let bytes = if role.starts_with("reconnaissance") {
            b"source map".as_slice()
        } else {
            b"{}"
        };
        let mut req = output(&f, &prep, &prepared, &issued, index, bytes);
        req["action"]["output"]["sha256"] = json!(hash(bytes));
        req["action"]["output"]["byte_length"] = json!(bytes.len());
        let saved = f.checkpoint(&req, 0);
        let out = &saved["result"]["entry"]["content"]["output"];
        assert_eq!(out["sha256"], hash(bytes));
        assert_eq!(out["byte_length"], bytes.len());
        assert_eq!(
            fs::read(objects(&f, &prepared).join(hash(bytes))).unwrap(),
            bytes
        );
        assert_eq!(
            f.audit_status("audit-one", false, 0)["result"]["assignments"][index]["state"],
            "closed"
        );
        let again = next(&f, &prepared, &saved, "again", req["action"].clone());
        assert_eq!(f.checkpoint(&again, 2)["error_code"], "assignment_closed");
        fs::remove_dir_all(host(&prep).join("agents")).unwrap();
        assert_eq!(
            f.checkpoint(&req, 0)["result"]["entry"],
            saved["result"]["entry"]
        );
    }
}

#[test]
fn bad_output_paths_declarations_and_unknown_fields_leave_assignment_open() {
    let (f, prep) = Fixture::setup(true);
    let prepared = f.audit(&prep, 0);
    let issued = issue(&f, &prepared, json!([{"role":"hunter","wave":1}]));
    let req = output(&f, &prep, &prepared, &issued, 0, b"{}");
    let agent = issued["result"]["entry"]["content"]["assignments"][0]["agent_id"]
        .as_str()
        .unwrap();
    for path in [
        "agents/a9999-hunter/artifacts/output.json".into(),
        "output.json".into(),
        format!("agents/{agent}/scratch/output.json"),
        format!("agents/{agent}/artifacts/sub/output.json"),
        format!("agents/{agent}/artifacts/../output.json"),
        host(&prep)
            .join(req["action"]["output"]["path"].as_str().unwrap())
            .to_str()
            .unwrap()
            .into(),
    ] {
        let mut bad = req.clone();
        bad["action"]["output"]["path"] = json!(path);
        assert_eq!(f.checkpoint(&bad, 2)["error_code"], "output_invalid");
    }
    for field in ["artifacts", "extra"] {
        let mut bad = req.clone();
        bad["action"][field] = json!([]);
        assert_eq!(f.checkpoint(&bad, 2)["error_code"], "invalid_request");
    }
    for (field, value) in [
        ("sha256", json!("a".repeat(64))),
        ("byte_length", json!(42)),
    ] {
        let mut bad = req.clone();
        bad["action"]["output"][field] = value;
        assert_eq!(f.checkpoint(&bad, 2)["error_code"], "output_mismatch");
    }
    let mut unknown = req.clone();
    unknown["action"]["assignment_id"] = json!("unknown");
    assert_eq!(
        f.checkpoint(&unknown, 2)["error_code"],
        "unknown_assignment"
    );
    assert_eq!(f.record_events(), 1);
    assert!(!objects(&f, &prepared).exists());
    let interrupted=f.checkpoint(&next(&f,&prepared,&issued,"interrupt",json!({"type":"interrupt","assignment_id":req["action"]["assignment_id"],"reason":"stopped"})),0);
    assert_eq!(
        f.checkpoint(
            &next(&f, &prepared, &interrupted, "after", req["action"].clone()),
            2
        )["error_code"],
        "assignment_closed"
    );
}

#[test]
fn output_capture_refusals_identify_the_output_without_a_document_field() {
    let (f, prep) = Fixture::setup(true);
    let prepared = f.audit(&prep, 0);
    let issued = issue(&f, &prepared, json!([{"role":"hunter","wave":1}]));
    let request = output(&f, &prep, &prepared, &issued, 0, b"{}");
    let path = request["action"]["output"]["path"].as_str().unwrap();
    let mut mismatch = request.clone();
    mismatch["action"]["output"]["sha256"] = json!("a".repeat(64));
    let mut unknown = request.clone();
    unknown["action"]["assignment_id"] = json!("unknown");
    let mut invalid = request.clone();
    invalid["action"]["output"]["path"] = json!("invalid");
    for (bad, code) in [
        (&mismatch, "output_mismatch"),
        (&unknown, "unknown_assignment"),
        (&invalid, "output_invalid"),
    ] {
        let result = f.checkpoint(bad, 2);
        assert_eq!(result["error_code"], code);
        assert_eq!(result["output"], bad["action"]["output"]["path"]);
        assert!(result.get("document").is_none(), "{result}");
    }
    fs::remove_file(host(&prep).join(path)).unwrap();
    let unreadable = f.checkpoint(&request, 2);
    assert_eq!(unreadable["error_code"], "output_unreadable");
    assert_eq!(unreadable["output"], path);
    assert!(unreadable.get("document").is_none());
    fs::write(host(&prep).join(path), b"{}").unwrap();
    let saved = f.checkpoint(&request, 0);
    let again = next(&f, &prepared, &saved, "again", request["action"].clone());
    let closed = f.checkpoint(&again, 2);
    assert_eq!(closed["error_code"], "assignment_closed");
    assert_eq!(closed["output"], path);
    assert!(closed.get("document").is_none());
}
#[test]
fn nonverifier_contract_failures_are_retryable_submissions() {
    for role in [
        "reconnaissance_baseline",
        "reconnaissance_focused",
        "hunter",
        "post_wave_critic",
        "final_clean_critic",
    ] {
        let (f, mut prep) = Fixture::setup(true);
        prep["profile"] = json!("standard");
        let prepared = f.audit(&prep, 0);
        let mut spec = json!({"role":role});
        if ["hunter", "post_wave_critic"].contains(&role) {
            spec["wave"] = json!(1);
        }
        let roles = if role == "post_wave_critic" {
            json!([{"role":"hunter","wave":1},spec])
        } else {
            json!([spec])
        };
        let index = roles.as_array().unwrap().len() - 1;
        let issued = issue(&f, &prepared, roles);
        let bad: Vec<&[u8]> = if role.starts_with("reconnaissance") {
            vec![b"", &[0xff]]
        } else {
            vec![
                b"[]",
                b"{\"x\":1,\"x\":2}",
                b"{} trailing",
                b"```json\n{}\n```",
                &[0xff],
            ]
        };
        for bytes in bad {
            let req = output(&f, &prep, &prepared, &issued, index, bytes);
            assert_eq!(f.checkpoint(&req, 2)["error_code"], "output_invalid");
            assert_eq!(
                f.audit_status("audit-one", false, 0)["result"]["assignments"][index]["state"],
                "open"
            );
            assert_eq!(f.record_events(), 1);
            assert!(!objects(&f, &prepared).exists());
        }
        f.checkpoint(&output(&f, &prep, &prepared, &issued, index, b"{}"), 0);
    }
}
#[test]
fn unsafe_files_and_size_limits_leave_output_unrecorded() {
    for role in ["hunter", "reconnaissance_baseline"] {
        let (f, prep) = Fixture::setup(true);
        let prepared = f.audit(&prep, 0);
        let spec = if role == "hunter" {
            json!({"role":role,"wave":1})
        } else {
            json!({"role":role})
        };
        let issued = issue(&f, &prepared, json!([spec]));
        for kind in [
            "directory",
            "oversized",
            "missing",
            "symlink",
            "hardlink",
            "fifo",
        ] {
            if ["symlink", "hardlink", "fifo"].contains(&kind) && !cfg!(unix) {
                continue;
            }
            let req = output(&f, &prep, &prepared, &issued, 0, b"{}");
            let path = host(&prep).join(req["action"]["output"]["path"].as_str().unwrap());
            fs::remove_file(&path).unwrap();
            let sibling = path.with_file_name("sibling");
            fs::write(&sibling, b"{}").unwrap();
            match kind {
                "directory" => fs::create_dir(&path).unwrap(),
                "oversized" => fs::File::create(&path)
                    .unwrap()
                    .set_len(if role == "hunter" {
                        5 * 1024 * 1024 + 1
                    } else {
                        1024 * 1024 + 1
                    })
                    .unwrap(),
                #[cfg(unix)]
                "symlink" => std::os::unix::fs::symlink(&sibling, &path).unwrap(),
                #[cfg(unix)]
                "hardlink" => fs::hard_link(&sibling, &path).unwrap(),
                #[cfg(unix)]
                "fifo" => {
                    let p = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                    // SAFETY: the terminated path belongs to this synthetic fixture.
                    assert_eq!(unsafe { libc::mkfifo(p.as_ptr(), 0o600) }, 0);
                }
                _ => {}
            }
            assert_eq!(f.checkpoint(&req, 2)["error_code"], "output_unreadable");
            assert_eq!(f.record_events(), 1);
            assert!(!objects(&f, &prepared).exists());
            fs::remove_dir_all(host(&prep).join("agents")).unwrap();
        }
    }
}

fn findings() -> Value {
    serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/cloudflare/findings.json"
    ))
    .unwrap()
}
fn with_node(f: &Fixture, req: &Value, code: i32) -> Value {
    terminal(
        f.checkpoint_command(req)
            .env("PATH", std::env::var_os("PATH").unwrap())
            .output()
            .unwrap(),
        code,
    )
}
#[test]
fn candidate_decisions_and_different_returned_fingerprint_are_recorded() {
    for record in findings().as_array().unwrap() {
        let (f, prep) = Fixture::setup(true);
        let prepared = f.audit(&prep, 0);
        let issued = issue(
            &f,
            &prepared,
            json!([{"role":"candidate_verifier","fingerprint":"assigned-fingerprint"}]),
        );
        let bytes =
            serde_json::to_vec(&json!({"decision":record["verdict"],"record":record})).unwrap();
        let req = output(&f, &prep, &prepared, &issued, 0, &bytes);
        assert_eq!(f.checkpoint(&req, 2)["error_code"], "not_available");
        assert_eq!(f.record_events(), 1);
        let saved = with_node(&f, &req, 0);
        let result = &saved["result"]["entry"]["content"]["output"];
        assert_eq!(result["decision"], record["verdict"]);
        assert_eq!(result["returned_fingerprint"], record["fingerprint"]);
        assert_eq!(
            result["record_sha256"],
            hash(&serde_json::to_vec(record).unwrap())
        );
        assert_eq!(result["disposition"], "accepted");
        assert_eq!(
            fs::read(objects(&f, &prepared).join(hash(&bytes))).unwrap(),
            bytes
        );
        let state = &f.audit_status("audit-one", false, 0)["result"]["assignments"][0];
        assert_eq!(state["state"], "closed");
        assert_eq!(state["fingerprint"], "assigned-fingerprint");
    }
}

#[cfg(unix)]
#[test]
fn verifier_validator_environment_failures_keep_assignment_open() {
    use std::os::unix::fs::PermissionsExt;
    let (f, prep) = Fixture::setup(true);
    let prepared = f.audit(&prep, 0);
    let issued = issue(
        &f,
        &prepared,
        json!([{"role":"candidate_verifier","fingerprint":"candidate"}]),
    );
    let record = &findings()[0];
    let req = output(
        &f,
        &prep,
        &prepared,
        &issued,
        0,
        &serde_json::to_vec(&json!({"decision":record["verdict"],"record":record})).unwrap(),
    );
    let runtime = host(&prep).join("runtime");
    fs::create_dir(&runtime).unwrap();
    let node = runtime.join("node");
    for script in [
        "#!/bin/sh\nexit 1\n",
        "#!/bin/sh\nexec /bin/sleep 30\n",
        "#!/bin/sh\nwhile :; do printf 'unbounded validator output'; done\n",
    ] {
        fs::write(&node, script).unwrap();
        fs::set_permissions(&node, fs::Permissions::from_mode(0o700)).unwrap();
        let result = terminal(
            f.checkpoint_command(&req)
                .env("PATH", &runtime)
                .output()
                .unwrap(),
            4,
        );
        assert_eq!(result["error_code"], "runtime_failed");
        assert_eq!(
            f.audit_status("audit-one", false, 0)["result"]["assignments"][0]["state"],
            "open"
        );
        assert_eq!(f.record_events(), 1);
        assert!(!objects(&f, &prepared).exists());
    }
    with_node(&f, &req, 0);
}

#[test]
fn malformed_candidate_outputs_are_permanently_discarded_and_replaced_at_budget_cost() {
    let record = &findings()[0];
    let valid = json!({"decision":record["verdict"],"record":record});
    let mut malformed = vec![
        b"prose {}".to_vec(),
        b"[]".to_vec(),
        vec![0xff],
        b"{\"decision\":1,\"decision\":2}".to_vec(),
    ];
    for kind in ["extra", "missing", "unknown", "mismatch", "invalid_record"] {
        let mut value = valid.clone();
        match kind {
            "extra" => value["extra"] = json!(true),
            "missing" => {
                value.as_object_mut().unwrap().remove("decision");
            }
            "unknown" => value["decision"] = json!("maybe"),
            "mismatch" => value["decision"] = json!("rejected"),
            _ => {
                value["record"].as_object_mut().unwrap().remove("title");
            }
        }
        malformed.push(serde_json::to_vec(&value).unwrap());
    }
    for bytes in malformed {
        let (f, prep) = Fixture::setup(true);
        let prepared = f.audit(&prep, 0);
        let spec = json!({"role":"candidate_verifier","fingerprint":"candidate"});
        let issued = issue(&f, &prepared, json!([spec]));
        let req = output(&f, &prep, &prepared, &issued, 0, &bytes);
        let saved = with_node(&f, &req, 0);
        let out = &saved["result"]["entry"]["content"]["output"];
        assert_eq!(out["disposition"], "discarded");
        assert_eq!(out["reason"], "output_invalid");
        assert_eq!(out["sha256"], hash(&bytes));
        assert_eq!(out["byte_length"], bytes.len());
        assert_eq!(saved["result"]["captured_bytes"]["used"], bytes.len());
        assert!(!objects(&f, &prepared).exists());
        assert_eq!(
            f.audit_status("audit-one", false, 0)["result"]["assignments"][0]["state"],
            "discarded"
        );
        let again = next(&f, &prepared, &saved, "again", req["action"].clone());
        assert_eq!(f.checkpoint(&again, 2)["error_code"], "assignment_closed");
        let mut replacement = spec.clone();
        replacement["replaces"] = req["action"]["assignment_id"].clone();
        let replaced = f.checkpoint(
            &next(
                &f,
                &prepared,
                &saved,
                "replacement",
                json!({"type":"issue","assignments":[replacement]}),
            ),
            0,
        );
        assert_eq!(replaced["result"]["budget"]["issued"], 2);
        assert_eq!(
            f.audit_status("audit-one", false, 0)["result"]["assignments"][0]["replaced_by"],
            replaced["result"]["entry"]["content"]["assignments"][0]["assignment_id"]
        );
        assert_eq!(
            f.checkpoint(&req, 0)["result"]["entry"],
            saved["result"]["entry"]
        );
    }
}

fn submit_findings(
    f: &Fixture,
    prep: &Value,
    prepared: &Value,
    previous: &Value,
    records: &Value,
    id: &str,
) -> Value {
    fs::write(
        host(prep).join("findings.json"),
        serde_json::to_vec(records).unwrap(),
    )
    .unwrap();
    with_node(
        f,
        &next(
            f,
            prepared,
            previous,
            id,
            json!({"type":"submit_documents","documents":[{"name":"findings.json"}]}),
        ),
        0,
    )
}
fn final_ready() -> (Fixture, Value, Value, Value) {
    let (f, mut prep) = Fixture::setup(true);
    prep["profile"] = json!("standard");
    let prepared = f.audit(&prep, 0);
    let record = &findings()[0];
    let issued = issue(
        &f,
        &prepared,
        json!([{"role":"candidate_verifier","fingerprint":"different-assigned-root"}]),
    );
    let saved = with_node(
        &f,
        &output(
            &f,
            &prep,
            &prepared,
            &issued,
            0,
            &serde_json::to_vec(&json!({"decision":record["verdict"],"record":record})).unwrap(),
        ),
        0,
    );
    let docs = submit_findings(&f, &prep, &prepared, &saved, &findings(), "findings");
    (f, prep, prepared, docs)
}
#[test]
fn final_issuance_requires_profile_findings_retained_verdict_and_candidate_output() {
    let (f, mut prep) = Fixture::setup(true);
    let prepared = f.audit(&prep, 0);
    let action = json!({"type":"issue","assignments":[{"role":"final_verifier","fingerprint":findings()[0]["fingerprint"]}]});
    assert_eq!(
        f.checkpoint(&f.checkpoint_request(&prepared, action.clone()), 2)["error_code"],
        "quick_final_verifier_unavailable"
    );
    prep["request_id"] = json!("standard");
    prep["profile"] = json!("standard");
    let prepared = f.audit(&prep, 0);
    assert_eq!(
        f.checkpoint(&f.checkpoint_request(&prepared, action.clone()), 2)["error_code"],
        "final_findings_required"
    );
    let issued = issue(
        &f,
        &prepared,
        json!([{"role":"candidate_verifier","fingerprint":findings()[0]["fingerprint"]}]),
    );
    let docs = submit_findings(&f, &prep, &prepared, &issued, &findings(), "findings");
    for (fp, code) in [
        (json!("unknown"), "final_record_ineligible"),
        (
            findings()[2]["fingerprint"].clone(),
            "final_record_ineligible",
        ),
        (
            findings()[0]["fingerprint"].clone(),
            "final_candidate_required",
        ),
    ] {
        let mut action = action.clone();
        action["assignments"][0]["fingerprint"] = fp;
        assert_eq!(
            f.checkpoint(&next(&f, &prepared, &docs, "final", action), 2)["error_code"],
            code
        );
    }
    assert_eq!(f.record_events(), 2);
}
#[test]
fn final_issuance_binds_product_object_revision_and_digest_and_rebinds_new_revision() {
    let (f, prep, prepared, docs) = final_ready();
    let records = findings();
    let record = &records[0];
    let action = json!({"type":"issue","assignments":[{"role":"final_verifier","fingerprint":record["fingerprint"]}]});
    fs::write(
        host(&prep).join("findings.json"),
        b"untrusted changed host file",
    )
    .unwrap();
    let req = next(&f, &prepared, &docs, "final", action.clone());
    let saved = f.checkpoint(&req, 0);
    let a = &saved["result"]["entry"]["content"]["assignments"][0];
    assert!(a["agent_id"].as_str().unwrap().ends_with("-final"));
    assert_eq!(a["findings_revision"], 1);
    assert_eq!(
        a["bound_record_sha256"],
        hash(&serde_json::to_vec(record).unwrap())
    );
    let mut changed = records.clone();
    changed[0]["title"] = json!("Revised title");
    let revision = submit_findings(&f, &prep, &prepared, &saved, &changed, "revised");
    let new = f.checkpoint(&next(&f, &prepared, &revision, "new-final", action), 0);
    let a = &new["result"]["entry"]["content"]["assignments"][0];
    assert_eq!(a["findings_revision"], 2);
    assert_eq!(
        a["bound_record_sha256"],
        hash(&serde_json::to_vec(&changed[0]).unwrap())
    );
    assert_ne!(
        a["bound_record_sha256"],
        saved["result"]["entry"]["content"]["assignments"][0]["bound_record_sha256"]
    );
    fs::remove_dir_all(objects(&f, &prepared)).unwrap();
    assert_eq!(
        f.checkpoint(&req, 0)["result"]["entry"],
        saved["result"]["entry"]
    );
}
#[test]
fn final_issuance_refuses_missing_corrupt_or_linked_product_objects() {
    for kind in ["missing", "corrupt", "link"] {
        if kind == "link" && !cfg!(unix) {
            continue;
        }
        let (f, prep, prepared, docs) = final_ready();
        // Only the Unix link case reads the host directory.
        #[cfg(not(unix))]
        let _ = &prep;
        let hash = docs["result"]["entry"]["content"]["documents"][0]["sha256"]
            .as_str()
            .unwrap();
        let path = objects(&f, &prepared).join(hash);
        match kind {
            "missing" => fs::remove_file(&path).unwrap(),
            "corrupt" => fs::write(&path, b"[]").unwrap(),
            #[cfg(unix)]
            "link" => {
                fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink(host(&prep).join("findings.json"), &path).unwrap();
            }
            _ => {}
        }
        let req = next(
            &f,
            &prepared,
            &docs,
            "final",
            json!({"type":"issue","assignments":[{"role":"final_verifier","fingerprint":findings()[0]["fingerprint"]}]}),
        );
        assert_eq!(f.checkpoint(&req, 4)["error_code"], "storage_failed");
        assert_eq!(f.record_events(), 3);
    }
}

fn issue_final(f: &Fixture, prepared: &Value, previous: &Value, id: &str) -> Value {
    f.checkpoint(&next(f,prepared,previous,id,json!({"type":"issue","assignments":[{"role":"final_verifier","fingerprint":findings()[0]["fingerprint"]}]})),0)
}
#[test]
fn final_verifier_verified_and_replacement_proposals_preserve_bound_and_returned_digests() {
    for decision in ["verified", "replace"] {
        let (f, prep, prepared, docs) = final_ready();
        let issued = issue_final(&f, &prepared, &docs, "final");
        let mut proposed = findings()[1].clone();
        proposed["title"] = json!("Proposed different record");
        let value = if decision == "verified" {
            json!({"decision":decision,"fingerprint":findings()[0]["fingerprint"]})
        } else {
            json!({"decision":decision,"reason":"Review proposes a different root cause","record":proposed})
        };
        let bytes = serde_json::to_vec(&value).unwrap();
        let mut req = output(&f, &prep, &prepared, &issued, 0, &bytes);
        req["request_id"] = json!("final-output");
        let saved = if decision == "verified" {
            f.checkpoint(&req, 0)
        } else {
            with_node(&f, &req, 0)
        };
        let out = &saved["result"]["entry"]["content"]["output"];
        assert_eq!(out["decision"], decision);
        assert_eq!(out["disposition"], "accepted");
        let record = if decision == "verified" {
            findings()[0].clone()
        } else {
            proposed
        };
        assert_eq!(out["returned_fingerprint"], record["fingerprint"]);
        assert_eq!(
            out["record_sha256"],
            hash(&serde_json::to_vec(&record).unwrap())
        );
        assert_eq!(
            fs::read(objects(&f, &prepared).join(hash(&bytes))).unwrap(),
            bytes
        );
        let status = f.audit_status("audit-one", false, 0);
        assert_eq!(status["result"]["assignments"][1]["state"], "closed");
        assert_eq!(
            status["result"]["assignments"][1]["bound_record_sha256"],
            hash(&serde_json::to_vec(&findings()[0]).unwrap())
        );
        assert_eq!(
            status["result"]["documents"]["findings.json"]["current"]["revision"],
            1
        );
    }
}
#[test]
fn malformed_final_verifier_outputs_are_discarded_without_objects() {
    let fp = findings()[0]["fingerprint"].clone();
    for value in [
        json!({"decision":"verified","fingerprint":"wrong"}),
        json!({"decision":"verified","fingerprint":fp,"extra":true}),
        json!({"decision":"replace","reason":" \n\t","record":findings()[0]}),
        json!({"decision":"replace","reason":"change","record":{}}),
        json!({"decision":"replace","reason":"change","record":findings()[0],"extra":true}),
    ] {
        let (f, prep, prepared, docs) = final_ready();
        let issued = issue_final(&f, &prepared, &docs, "final");
        let bytes = serde_json::to_vec(&value).unwrap();
        let mut req = output(&f, &prep, &prepared, &issued, 0, &bytes);
        req["request_id"] = json!("final-output");
        let saved = with_node(&f, &req, 0);
        assert_eq!(
            saved["result"]["entry"]["content"]["output"]["disposition"],
            "discarded"
        );
        assert!(!objects(&f, &prepared).join(hash(&bytes)).exists());
        assert_eq!(
            f.audit_status("audit-one", false, 0)["result"]["assignments"][1]["state"],
            "discarded"
        );
        assert_eq!(
            f.checkpoint(
                &next(&f, &prepared, &saved, "again", req["action"].clone()),
                2
            )["error_code"],
            "assignment_closed"
        );
    }
}

#[test]
fn output_replay_conflict_head_authority_and_directory_precede_capture() {
    for change in ["expired", "removed"] {
        let (f, prep) = Fixture::setup(true);
        let prepared = f.audit(&prep, 0);
        let issued = issue(&f, &prepared, json!([{"role":"hunter","wave":1}]));
        let req = output(&f, &prep, &prepared, &issued, 0, b"{}");
        let saved = f.checkpoint(&req, 0);
        fs::remove_dir_all(host(&prep).join("agents")).unwrap();
        assert_eq!(
            f.checkpoint(&req, 0)["result"]["entry"],
            saved["result"]["entry"]
        );
        let mut conflict = req.clone();
        conflict["action"]["output"]["byte_length"] = json!(2);
        assert_eq!(f.checkpoint(&conflict, 3)["error_code"], "request_conflict");
        conflict["request_id"] = json!("new");
        assert_eq!(f.checkpoint(&conflict, 3)["error_code"], "stale_head");
        if change == "expired" {
            f.change_case(|c| {
                c.scope_grants[0].expires_at = Some(Utc::now() - chrono::Duration::seconds(1))
            });
        } else {
            fs::remove_dir(host(&prep)).unwrap();
        }
        for request in [
            &req,
            &next(&f, &prepared, &saved, "new", req["action"].clone()),
        ] {
            let rejected = f.checkpoint(request, 3);
            assert_eq!(rejected["error_code"], "saved_receipt_not_current");
            assert_eq!(
                rejected["reason"],
                if change == "expired" {
                    "source_authorization_expired"
                } else {
                    "run_directory_unavailable"
                }
            );
        }
        assert_eq!(f.record_events(), 2);
    }
}
#[cfg(unix)]
#[test]
fn lost_output_delivery_commits_and_status_recovers() {
    use std::process::Stdio;
    let (f, prep) = Fixture::setup(true);
    let prepared = f.audit(&prep, 0);
    let issued = issue(&f, &prepared, json!([{"role":"hunter","wave":1}]));
    let req = output(&f, &prep, &prepared, &issued, 0, b"{}");
    let mut child = f
        .checkpoint_command(&req)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    assert_eq!(child.wait().unwrap().code(), Some(4));
    let status = f.audit_status("audit-one", false, 0);
    assert_eq!(status["result"]["assignments"][0]["state"], "closed");
    assert_eq!(
        status["result"]["entries"][1],
        f.checkpoint(&req, 0)["result"]["entry"]
    );
}

#[test]
fn status_and_checkpoint_show_output_state_times_metadata_and_counts_without_object_reads_or_lease()
{
    let (f, prep, prepared, docs) = final_ready();
    let final_issue = issue_final(&f, &prepared, &docs, "final");
    let mut req = output(&f, &prep, &prepared, &final_issue, 0, b"malformed");
    req["request_id"] = json!("discard");
    let discarded = f.checkpoint(&req, 0);
    assert_eq!(discarded["result"]["disposition"], "discarded");
    assert_eq!(discarded["result"]["assignment"]["state"], "discarded");
    assert_eq!(
        discarded["result"]["assignment"]["closed_at"],
        discarded["result"]["entry"]["occurred_at"]
    );
    let issued=f.checkpoint(&next(&f,&prepared,&discarded,"more",json!({"type":"issue","assignments":[{"role":"reconnaissance_baseline"},{"role":"reconnaissance_focused"}]})),0);
    let id = issued["result"]["entry"]["content"]["assignments"][0]["assignment_id"].clone();
    let interrupted = f.checkpoint(
        &next(
            &f,
            &prepared,
            &issued,
            "interrupt",
            json!({"type":"interrupt","assignment_id":id,"reason":"stopped"}),
        ),
        0,
    );
    assert_eq!(interrupted["result"]["assignment"]["state"], "interrupted");
    fs::remove_dir_all(objects(&f, &prepared)).unwrap();
    fs::remove_dir_all(host(&prep)).unwrap();
    let _lease = DataDirectoryExclusiveLease::acquire(&f.data).unwrap();
    let status = f.audit_status("audit-one", false, 0);
    assert_eq!(
        status["result"]["counts_by_state"],
        json!({"open":1,"closed":1,"interrupted":1,"discarded":1})
    );
    assert_eq!(
        status["result"]["assignments"][0]["output"]["decision"],
        "confirmed"
    );
    assert_eq!(status["result"]["assignments"][1]["findings_revision"], 1);
    assert_eq!(
        status["result"]["assignments"][1]["output"],
        discarded["result"]["entry"]["content"]["output"]
    );
    assert!(
        status["result"]["next_operation"]["actions"]
            .as_array()
            .unwrap()
            .contains(&json!("submit_output"))
    );
    assert_eq!(
        status["result"]["next_operation"]["sealing"]["available"],
        true
    );
}

#[test]
fn output_archive_omission_restore_history_and_confirmed_deletion() {
    let (mut f, prep, prepared, docs) = final_ready();
    let issued = issue_final(&f, &prepared, &docs, "final");
    let mut req = output(&f, &prep, &prepared, &issued, 0, b"malformed");
    req["request_id"] = json!("discard");
    f.checkpoint(&req, 0);
    let original_status = f.audit_status("audit-one", false, 0);
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
    let restored_output = f
        .command()
        .args(["archive", "restore", "--archive"])
        .arg(&archive)
        .args(["--acknowledge-sensitive-data", "--destination"])
        .arg(&restored)
        .output()
        .unwrap();
    assert!(
        restored_output.status.success(),
        "{}",
        String::from_utf8_lossy(&restored_output.stderr)
    );
    let original = f.data.clone();
    f.data = restored;
    let status = f.audit_status("audit-one", false, 0);
    for field in [
        "entries",
        "assignments",
        "counts_by_state",
        "captured_bytes",
        "record_head",
    ] {
        assert_eq!(status["result"][field], original_status["result"][field]);
    }
    assert_eq!(status["result"]["descriptor_state"], "missing");
    assert_eq!(
        f.checkpoint(&req, 2)["error_code"],
        "restored_session_inert"
    );
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
    assert!(objects(&f, &prepared).exists());
    service
        .delete_case_artifacts(
            &f.case_id,
            &deletion.artifacts.exact_path,
            &format!("DELETE {}", f.case_id),
        )
        .unwrap();
    assert!(!f.audit_root().exists());
    assert_eq!(f.record_events(), 0);
}

#[test]
fn final_verifier_accepts_needs_validation_binding_and_spends_budget_without_changing_reserves() {
    let (f, mut prep) = Fixture::setup(true);
    prep["profile"] = json!("standard");
    prep["invocation_budget"] = json!(7);
    let prepared = f.audit(&prep, 0);
    let records = findings();
    let record = &records[1];
    let issued = issue(
        &f,
        &prepared,
        json!([{"role":"candidate_verifier","fingerprint":record["fingerprint"]}]),
    );
    let saved = with_node(
        &f,
        &output(
            &f,
            &prep,
            &prepared,
            &issued,
            0,
            &serde_json::to_vec(&json!({"decision":"needs_validation","record":record})).unwrap(),
        ),
        0,
    );
    let docs = submit_findings(&f, &prep, &prepared, &saved, &records, "findings");
    let action = json!({"type":"issue","assignments":vec![json!({"role":"final_verifier","fingerprint":record["fingerprint"]});6]});
    let final_req = next(&f, &prepared, &docs, "final", action);
    let finals = f.checkpoint(&final_req, 0);
    assert_eq!(finals["result"]["budget"]["issued"], 7);
    assert_eq!(finals["result"]["budget"]["remaining"], 0);
    for a in finals["result"]["entry"]["content"]["assignments"]
        .as_array()
        .unwrap()
    {
        assert_eq!(
            a["bound_record_sha256"],
            hash(&serde_json::to_vec(record).unwrap())
        );
    }
    let action = json!({"type":"issue","assignments":[{"role":"final_verifier","fingerprint":record["fingerprint"]}]});
    assert_eq!(
        f.checkpoint(&next(&f, &prepared, &finals, "over-budget", action), 2)["error_code"],
        "invocation_budget_exhausted"
    );
}
