use super::fixture::*;
use sha2::{Digest, Sha256};

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn request(f: &Fixture, prepared: &Value, names: &[&str]) -> Value {
    f.checkpoint_request(prepared, json!({"type":"submit_documents","documents":names.iter().map(|name| json!({"name":name})).collect::<Vec<_>>()}))
}
fn objects(f: &Fixture, prepared: &Value) -> PathBuf {
    f.audit_root()
        .join(prepared["session_id"].as_str().unwrap())
        .join("objects")
}
fn host(preparation: &Value) -> &Path {
    Path::new(preparation["run_directory"].as_str().unwrap())
}

#[test]
fn markdown_batch_revisions_replay_and_status_are_record_derived() {
    let (f, preparation) = Fixture::setup(true);
    let prepared = f.audit(&preparation, 0);
    let names = [
        "architecture.md",
        "REPORT.md",
        "FINDINGS-DETAIL.md",
        "NEEDS-VALIDATION.md",
    ];
    for name in names {
        fs::write(host(&preparation).join(name), name).unwrap();
    }
    let mut req = request(&f, &prepared, &names);
    let saved = f.checkpoint(&req, 0);
    let docs = &saved["result"]["entry"]["content"]["documents"];
    assert_eq!(docs.as_array().unwrap().len(), 4);
    for (i, name) in names.iter().enumerate() {
        assert_eq!(docs[i]["name"], *name);
        assert_eq!(docs[i]["revision"], 1);
        assert_eq!(docs[i]["sha256"], hash(name.as_bytes()));
        assert_eq!(
            fs::read(objects(&f, &prepared).join(hash(name.as_bytes()))).unwrap(),
            name.as_bytes()
        );
    }
    assert_eq!(f.record_events(), 1);
    req["request_id"] = json!("revision-two");
    req["expected_head_sha256"] = saved["result"]["record_head"]["entry_sha256"].clone();
    req["action"]["documents"] = json!([{"name":"REPORT.md"}]);
    let second = f.checkpoint(&req, 0);
    assert_eq!(
        second["result"]["entry"]["content"]["documents"][0]["revision"],
        2
    );
    assert_eq!(fs::read_dir(objects(&f, &prepared)).unwrap().count(), 4);
    fs::remove_file(host(&preparation).join("REPORT.md")).unwrap();
    let replay = f.checkpoint(&req, 0);
    assert_eq!(replay["result"]["entry"], second["result"]["entry"]);
    fs::write(host(&preparation).join("REPORT.md"), b"changed").unwrap();
    assert_eq!(
        f.checkpoint(&req, 0)["result"]["entry"],
        second["result"]["entry"]
    );
    req["action"]["documents"][0]["byte_length"] = json!(9);
    assert_eq!(f.checkpoint(&req, 3)["error_code"], "request_conflict");
    req["request_id"] = json!("stale");
    assert_eq!(f.checkpoint(&req, 3)["error_code"], "stale_head");
    let status = f.audit_status("audit-one", false, 0);
    assert_eq!(
        status["result"]["documents"]["REPORT.md"]["revision_count"],
        2
    );
    assert_eq!(
        status["result"]["documents"]["architecture.md"]["current"]["revision"],
        1
    );
    assert_eq!(
        status["result"]["documents"]["REPORT.md"]["accepted_at"],
        second["result"]["entry"]["occurred_at"]
    );
    assert_eq!(
        status["result"]["captured_bytes"]["used"],
        names.iter().map(|n| n.len()).sum::<usize>() + "REPORT.md".len()
    );
    fs::remove_dir_all(objects(&f, &prepared)).unwrap();
    assert_eq!(f.audit_status("audit-one", false, 0), status);
}

#[test]
fn invalid_names_declarations_and_batches_keep_no_objects_or_entries() {
    let (f, preparation) = Fixture::setup(true);
    let prepared = f.audit(&preparation, 0);
    fs::write(host(&preparation).join("REPORT.md"), b"report").unwrap();
    for specs in [
        json!([]),
        json!([{"name":"extra.md"}]),
        json!([{"name":"sub/REPORT.md"}]),
        json!([{"name":"REPORT.md"},{"name":"REPORT.md"}]),
        json!([{"name":"REPORT.md","sha256":"a".repeat(64)}]),
        json!([{"name":"REPORT.md","byte_length":5}]),
        json!([{"name":"REPORT.md"},{"name":"architecture.md"}]),
    ] {
        let mut req = request(&f, &prepared, &[]);
        req["action"]["documents"] = specs;
        f.checkpoint(&req, 2);
        assert_eq!(f.record_events(), 0);
        assert!(!objects(&f, &prepared).exists());
    }
    let mut req = request(&f, &prepared, &["REPORT.md"]);
    req["action"]["documents"][0]["sha256"] = json!(hash(b"report"));
    req["action"]["documents"][0]["byte_length"] = json!(6);
    f.checkpoint(&req, 0);
}

#[test]
fn unreadable_oversized_and_non_utf8_documents_refuse_entire_batch() {
    for kind in [
        "missing",
        "directory",
        "oversized",
        "utf8",
        "symlink",
        "hardlink",
        "fifo",
    ] {
        if ["symlink", "hardlink", "fifo"].contains(&kind) && !cfg!(unix) {
            continue;
        }
        let (f, prep) = Fixture::setup(true);
        let prepared = f.audit(&prep, 0);
        let file = host(&prep).join("REPORT.md");
        fs::write(host(&prep).join("architecture.md"), b"valid").unwrap();
        match kind {
            "directory" => fs::create_dir(&file).unwrap(),
            "oversized" => fs::File::create(&file)
                .unwrap()
                .set_len(8 * 1024 * 1024 + 1)
                .unwrap(),
            "utf8" => fs::write(&file, [0xff]).unwrap(),
            #[cfg(unix)]
            "symlink" => {
                std::os::unix::fs::symlink(host(&prep).join("architecture.md"), &file).unwrap()
            }
            #[cfg(unix)]
            "hardlink" => fs::hard_link(host(&prep).join("architecture.md"), &file).unwrap(),
            #[cfg(unix)]
            "fifo" => {
                let path = std::ffi::CString::new(file.as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: the terminated string names a synthetic fixture entry.
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            _ => {}
        }
        let result = f.checkpoint(
            &request(&f, &prepared, &["architecture.md", "REPORT.md"]),
            2,
        );
        assert!(
            ["document_unreadable", "document_invalid"]
                .contains(&result["error_code"].as_str().unwrap())
        );
        assert_eq!(f.record_events(), 0);
        assert!(!objects(&f, &prepared).exists());
    }
}

#[test]
fn object_reuse_corruption_and_orphans_preserve_existing_bytes() {
    for corrupt in [false, true] {
        let (f, prep) = Fixture::setup(true);
        let prepared = f.audit(&prep, 0);
        fs::write(host(&prep).join("REPORT.md"), b"report").unwrap();
        fs::create_dir(objects(&f, &prepared)).unwrap();
        writable(&objects(&f, &prepared));
        let file = objects(&f, &prepared).join(hash(b"report"));
        let bytes = if corrupt { b"broken" } else { b"report" };
        fs::write(&file, bytes).unwrap();
        let before = fs::metadata(&file).unwrap().modified().unwrap();
        let result = f.checkpoint(
            &request(&f, &prepared, &["REPORT.md"]),
            if corrupt { 4 } else { 0 },
        );
        if corrupt {
            assert_eq!(result["error_code"], "storage_failed");
        }
        assert_eq!(f.record_events(), usize::from(!corrupt));
        assert_eq!(fs::read(&file).unwrap(), bytes);
        assert_eq!(fs::metadata(&file).unwrap().modified().unwrap(), before);
    }
}

#[test]
fn document_capture_obeys_directory_authority_and_writer_lease() {
    for change in ["removed", "file", "link", "expired", "lease"] {
        if change == "link" && !cfg!(unix) {
            continue;
        }
        let (f, prep) = Fixture::setup(true);
        let prepared = f.audit(&prep, 0);
        let req = request(&f, &prepared, &["REPORT.md"]);
        let mut lease = None;
        if ["removed", "file", "link"].contains(&change) {
            fs::remove_dir(host(&prep)).unwrap();
            if change == "file" {
                fs::write(host(&prep), b"file").unwrap();
            }
            #[cfg(unix)]
            if change == "link" {
                std::os::unix::fs::symlink(host(&prep).parent().unwrap(), host(&prep)).unwrap();
            }
        } else if change == "expired" {
            f.change_case(|c| {
                c.scope_grants[0].expires_at = Some(Utc::now() - chrono::Duration::seconds(1))
            });
        } else {
            lease = Some(DataDirectoryExclusiveLease::acquire(&f.data).unwrap());
        }
        let result = f.checkpoint(&req, 3);
        if ["removed", "file", "link"].contains(&change) {
            assert_eq!(result["reason"], "run_directory_unavailable");
        } else if change == "expired" {
            assert_eq!(result["reason"], "source_authorization_expired");
        } else {
            assert_eq!(result["error_code"], "data_directory_busy");
        }
        f.audit_status("audit-one", false, 0);
        assert_eq!(f.record_events(), 0);
        assert!(!objects(&f, &prepared).exists());
        drop(lease);
    }
}

#[cfg(unix)]
#[test]
fn lost_document_output_commits_and_status_recovers() {
    use std::process::Stdio;
    let (f, prep) = Fixture::setup(true);
    let prepared = f.audit(&prep, 0);
    fs::write(host(&prep).join("REPORT.md"), b"report").unwrap();
    let req = request(&f, &prepared, &["REPORT.md"]);
    let mut child = f
        .checkpoint_command(&req)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    assert_eq!(child.wait().unwrap().code(), Some(4));
    assert_eq!(f.record_events(), 1);
    let status = f.audit_status("audit-one", false, 0);
    assert_eq!(
        status["result"]["documents"]["REPORT.md"]["current"]["sha256"],
        hash(b"report")
    );
    assert_eq!(
        f.checkpoint(&req, 0)["result"]["entry"],
        status["result"]["entries"][0]
    );
}

fn checkpoint_with_node(f: &Fixture, req: &Value, code: i32) -> Value {
    terminal(
        f.checkpoint_command(req)
            .env("PATH", std::env::var_os("PATH").unwrap())
            .output()
            .unwrap(),
        code,
    )
}
#[test]
fn pinned_validators_capture_bytes_and_refuse_invalid_documents_with_diagnostics() {
    let (f, prep) = Fixture::setup(true);
    let prepared = f.audit(&prep, 0);
    let names = ["coverage-ledger.json", "findings.json"];
    let req = request(&f, &prepared, &names);
    for name in names {
        fs::write(host(&prep).join(name), b"{}").unwrap();
    }
    for name in names {
        let single = request(&f, &prepared, &[name]);
        let rejected = checkpoint_with_node(&f, &single, 2);
        assert_eq!(rejected["error_code"], "document_invalid");
        assert_eq!(rejected["document"], name);
        assert_eq!(rejected["validation"]["valid"], false);
        assert!(
            !rejected["validation"]["errors"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(!objects(&f, &prepared).exists());
        assert_eq!(f.record_events(), 0);
    }
    let ledger = include_bytes!("../../../tests/fixtures/cloudflare/coverage-ledger.json");
    let findings = include_bytes!("../../../tests/fixtures/cloudflare/findings.json");
    fs::write(host(&prep).join(names[0]), ledger).unwrap();
    checkpoint_with_node(&f, &req, 2);
    assert!(!objects(&f, &prepared).exists());
    fs::write(host(&prep).join(names[1]), findings).unwrap();
    assert_eq!(f.checkpoint(&req, 2)["error_code"], "not_available");
    assert_eq!(f.record_events(), 0);
    assert!(!objects(&f, &prepared).exists());
    let saved = checkpoint_with_node(&f, &req, 0);
    let documents = saved["result"]["entry"]["content"]["documents"]
        .as_array()
        .unwrap();
    for (doc, bytes) in documents
        .iter()
        .zip([ledger.as_slice(), findings.as_slice()])
    {
        assert_eq!(doc["valid"], true);
        assert_eq!(
            doc["validator_resources_sha256"],
            facts(&prepared)["validator_resources_sha256"]
        );
        assert_eq!(
            fs::read(objects(&f, &prepared).join(hash(bytes))).unwrap(),
            bytes
        );
    }
    for name in names {
        fs::remove_file(host(&prep).join(name)).unwrap();
    }
    assert_eq!(
        f.checkpoint(&req, 0)["result"]["entry"],
        saved["result"]["entry"]
    );
}

#[cfg(unix)]
#[test]
fn validator_runtime_failure_is_not_a_document_verdict() {
    use std::os::unix::fs::PermissionsExt;
    let (f, prep) = Fixture::setup(true);
    let prepared = f.audit(&prep, 0);
    fs::write(host(&prep).join("findings.json"), b"[]").unwrap();
    let runtime = host(&prep).join("runtime");
    fs::create_dir(&runtime).unwrap();
    let node = runtime.join("node");
    fs::write(&node, b"#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(node, fs::Permissions::from_mode(0o700)).unwrap();
    let result = terminal(
        f.checkpoint_command(&request(&f, &prepared, &["findings.json"]))
            .env("PATH", runtime)
            .output()
            .unwrap(),
        4,
    );
    assert_eq!(result["error_code"], "runtime_failed");
    assert!(result.get("validation").is_none());
    assert_eq!(f.record_events(), 0);
    assert!(!objects(&f, &prepared).exists());
}

fn metadata(prepared: &Value) -> Value {
    let facts = facts(prepared);
    json!({"run_id":facts["provider_run_id"],"profile":facts["profile"],"budget":facts["invocation_budget"],"source_ref":facts["source"]["source_ref"],"execution_policy":"sandboxed-source-and-local-only","run_status":"in_progress"})
}
#[test]
fn metadata_binds_each_prepared_field_but_allows_in_progress_and_unbounded_budget() {
    for budget in [Value::Null, json!(7)] {
        let (f, mut prep) = Fixture::setup(true);
        prep["invocation_budget"] = budget;
        let prepared = f.audit(&prep, 0);
        let req = request(&f, &prepared, &["architecture.md", "run-metadata.json"]);
        fs::write(host(&prep).join("architecture.md"), b"architecture").unwrap();
        let path = host(&prep).join("run-metadata.json");
        for (field, bad) in [
            ("run_id", json!("other")),
            ("profile", json!("deep")),
            ("budget", json!(6)),
            ("source_ref", json!("other")),
            ("execution_policy", json!("other")),
        ] {
            let mut value = metadata(&prepared);
            value[field] = bad;
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            let result = f.checkpoint(&req, 2);
            assert_eq!(result["error_code"], "metadata_binding_mismatch", "{field}");
            assert_eq!(result["document"], "run-metadata.json");
            assert_eq!(f.record_events(), 0);
            assert!(!objects(&f, &prepared).exists());
            value.as_object_mut().unwrap().remove(field);
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            assert_eq!(
                f.checkpoint(&req, 2)["error_code"],
                "metadata_binding_mismatch",
                "missing {field}"
            );
        }
        for bytes in [b"[]".as_slice(), b"{} {}", b"{\"run_id\":1,\"run_id\":2}"] {
            fs::write(&path, bytes).unwrap();
            assert_eq!(f.checkpoint(&req, 2)["error_code"], "document_invalid");
        }
        let bytes = serde_json::to_vec(&metadata(&prepared)).unwrap();
        fs::write(path, &bytes).unwrap();
        let saved = f.checkpoint(&req, 0);
        assert_eq!(
            saved["result"]["entry"]["content"]["documents"][1]["revision"],
            1
        );
        assert_eq!(
            fs::read(objects(&f, &prepared).join(hash(&bytes))).unwrap(),
            bytes
        );
    }
}

#[test]
fn all_seven_names_commit_together_and_each_bound_is_enforced() {
    let (f, prep) = Fixture::setup(true);
    let prepared = f.audit(&prep, 0);
    let names = [
        "run-metadata.json",
        "architecture.md",
        "coverage-ledger.json",
        "findings.json",
        "REPORT.md",
        "FINDINGS-DETAIL.md",
        "NEEDS-VALIDATION.md",
    ];
    for (name, bound) in [
        ("run-metadata.json", 1024 * 1024),
        ("coverage-ledger.json", 5 * 1024 * 1024),
        ("findings.json", 5 * 1024 * 1024),
    ] {
        let file = host(&prep).join(name);
        fs::File::create(&file).unwrap().set_len(bound + 1).unwrap();
        assert_eq!(
            f.checkpoint(&request(&f, &prepared, &[name]), 2)["error_code"],
            "document_unreadable"
        );
        fs::write(&file, [0xff]).unwrap();
        assert_eq!(
            f.checkpoint(&request(&f, &prepared, &[name]), 2)["error_code"],
            "document_invalid"
        );
        assert!(!objects(&f, &prepared).exists());
    }
    for name in names {
        fs::write(host(&prep).join(name), b"").unwrap();
    }
    fs::write(
        host(&prep).join("run-metadata.json"),
        serde_json::to_vec(&metadata(&prepared)).unwrap(),
    )
    .unwrap();
    fs::write(
        host(&prep).join("coverage-ledger.json"),
        include_bytes!("../../../tests/fixtures/cloudflare/coverage-ledger.json"),
    )
    .unwrap();
    fs::write(
        host(&prep).join("findings.json"),
        include_bytes!("../../../tests/fixtures/cloudflare/findings.json"),
    )
    .unwrap();
    let mut req = request(&f, &prepared, &names);
    req["action"]["documents"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"eighth.md"}));
    assert_eq!(f.checkpoint(&req, 2)["error_code"], "document_batch_limit");
    req["action"]["documents"].as_array_mut().unwrap().pop();
    let result = checkpoint_with_node(&f, &req, 0);
    let docs = result["result"]["entry"]["content"]["documents"]
        .as_array()
        .unwrap();
    assert_eq!(docs.len(), 7);
    assert_eq!(f.record_events(), 1);
    for doc in docs {
        let bytes = fs::read(host(&prep).join(doc["name"].as_str().unwrap())).unwrap();
        assert_eq!(doc["sha256"], hash(&bytes));
        assert_eq!(doc["byte_length"], bytes.len());
        assert_eq!(
            fs::read(objects(&f, &prepared).join(hash(&bytes))).unwrap(),
            bytes
        );
    }
}

#[test]
fn document_archive_omission_restore_history_and_confirmed_deletion() {
    let (mut f, r) = Fixture::setup(true);
    let saved = f.audit(&r, 0);
    fs::write(host(&r).join("REPORT.md"), b"private report").unwrap();
    let checkpoint_request = request(&f, &saved, &["REPORT.md"]);
    let checkpoint = f.checkpoint(&checkpoint_request, 0);
    assert!(objects(&f, &saved).join(hash(b"private report")).exists());
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
    assert_eq!(
        status["result"]["documents"]["REPORT.md"]["current"]["revision"],
        1
    );
    assert_eq!(
        status["result"]["captured_bytes"]["used"],
        b"private report".len()
    );
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
    assert!(objects(&f, &saved).join(hash(b"private report")).exists());
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

#[test]
fn document_replay_requires_current_directory_and_grant() {
    for change in ["removed", "file", "link", "expired"] {
        if change == "link" && !cfg!(unix) {
            continue;
        }
        let (f, prep) = Fixture::setup(true);
        let prepared = f.audit(&prep, 0);
        fs::write(host(&prep).join("REPORT.md"), b"saved report").unwrap();
        let req = request(&f, &prepared, &["REPORT.md"]);
        let saved = f.checkpoint(&req, 0);
        fs::remove_file(host(&prep).join("REPORT.md")).unwrap();
        if change == "expired" {
            f.change_case(|c| {
                c.scope_grants[0].expires_at = Some(Utc::now() - chrono::Duration::seconds(1))
            });
        } else {
            fs::remove_dir(host(&prep)).unwrap();
            if change == "file" {
                fs::write(host(&prep), b"file").unwrap();
            }
            #[cfg(unix)]
            if change == "link" {
                std::os::unix::fs::symlink(host(&prep).parent().unwrap(), host(&prep)).unwrap();
            }
        }
        let result = f.checkpoint(&req, 3);
        assert_eq!(result["error_code"], "saved_receipt_not_current");
        assert_eq!(
            result["reason"],
            if change == "expired" {
                "source_authorization_expired"
            } else {
                "run_directory_unavailable"
            }
        );
        assert_eq!(
            f.audit_status("audit-one", false, 0)["result"]["entries"][0],
            saved["result"]["entry"]
        );
        assert_eq!(f.record_events(), 1);
    }
}
