use super::{
    finalize::{finalize, path, request},
    fixture::*,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
fn command(run: &RunFixture) -> Command {
    let mut command = run.f.command();
    command.args([
        "provider",
        "cloudflare",
        "inspect-sealed",
        "--case-id",
        &run.f.case_id,
        "--session-id",
        run.prepared["session_id"].as_str().unwrap(),
    ]);
    command
}
fn inspect(run: &RunFixture, code: i32) -> Value {
    terminal(command(run).output().unwrap(), code)
}
fn tree(root: &Path) -> BTreeMap<String, String> {
    fn visit(base: &Path, at: &Path, entries: &mut BTreeMap<String, String>) {
        let metadata = fs::symlink_metadata(at).unwrap();
        let key = at.strip_prefix(base).unwrap().to_str().unwrap().to_owned();
        if metadata.file_type().is_symlink() {
            entries.insert(
                key,
                format!("link:{}", fs::read_link(at).unwrap().display()),
            );
        } else if metadata.is_dir() {
            entries.insert(key, "directory".into());
            for entry in fs::read_dir(at).unwrap() {
                visit(base, &entry.unwrap().path(), entries);
            }
        } else {
            entries.insert(key, hex::encode(Sha256::digest(fs::read(at).unwrap())));
        }
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries);
    entries
}
fn delete(root: &Path) {
    writable(root);
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            delete(&entry.path());
        } else {
            writable(&entry.path());
            fs::remove_file(entry.path()).unwrap();
        }
    }
    fs::remove_dir(root).unwrap();
}
fn refused_unchanged(run: &RunFixture, code: &str) -> Value {
    let _reader = Storage::open_read_only(run.f.data.join("casework.db")).unwrap();
    let before = tree(&run.f.data);
    let value = inspect(run, 2);
    assert_eq!(value["error_code"], code, "{value}");
    assert_eq!(value["retryable"], false);
    assert_eq!(before, tree(&run.f.data));
    value
}
#[test]
fn complete_and_incomplete_verify_exact_custody_offline_and_without_a_writer_lease() {
    for profile in ["standard", "quick"] {
        let mut run = RunFixture::new(profile);
        if profile == "standard" {
            // Existing sealing accepts this field; offline verification must preserve that contract.
            run.metadata["incomplete_reason"] = json!("Historical completion note");
            run.documents(&["run-metadata.json"]);
        }
        if profile == "quick" {
            run.metadata["run_status"] = json!("incomplete");
            run.metadata["incomplete_reason"] = json!("Host stopped after source review");
            run.documents(&["run-metadata.json"]);
        }
        let req = request(&run);
        let saved = finalize(&run, &req, 0);
        let package = path(&run, &req);
        let before_status = run.f.audit_status("audit-one", false, 0)["result"].clone();
        let view = serde_json::to_value(
            run.f
                .storage()
                .source_view_receipt(&run.f.case_id, "view-request")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        // Remove every original source artifact, keeping only the sealed audit custody tree.
        for entry in fs::read_dir(run.f.data.join("artifacts").join(&run.f.case_id)).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() != "cloudflare-sessions" {
                delete(&entry.path());
            }
        }
        delete(&run.host);
        delete(&run.f.data.parent().unwrap().join("source"));
        run.f.change_case(|c| c.scope_grants.clear());
        let _lease = DataDirectoryExclusiveLease::acquire(&run.f.data).unwrap();
        let _reader = Storage::open_read_only(run.f.data.join("casework.db")).unwrap();
        let before = tree(&run.f.data);
        // Fixture commands have an empty PATH: no Node or other executable is available.
        let value = inspect(&run, 0);
        assert_eq!(before, tree(&run.f.data));
        let v = &value["result"];
        assert_eq!(
            v["verification"],
            json!({"state":"verified","scope":"full_payload",
            "committed_files_verified":true,"full_payload_verified":true,"workflow_history_verified":true,
            "view_lineage_verified":true,"validators_reexecuted":false})
        );
        assert_eq!(v["identities"]["case_id"], run.f.case_id);
        assert_eq!(v["identities"]["session_id"], run.prepared["session_id"]);
        assert_eq!(v["preparation_request_id"], "audit-one");
        assert_eq!(v["source_view_request_id"], "view-request");
        assert_eq!(
            v["asset_binding"],
            json!({"asset_id":run.f.asset_id,"source_id":"synthetic-source","asset_present":true,"source_present":true})
        );
        assert_eq!(v["method"]["profile"], profile);
        assert_eq!(
            v["method"]["upstream_commit"],
            facts(&run.prepared)["upstream_commit"]
        );
        assert_eq!(
            v["method"]["validator_resources_sha256"],
            facts(&run.prepared)["validator_resources_sha256"]
        );
        assert_eq!(
            v["digests"]["preparation_receipt_sha256"],
            run.prepared["receipt"]["sha256"]
        );
        assert_eq!(v["digests"]["source_view_receipt_sha256"], view["digest"]);
        assert_eq!(
            v["digests"]["view_manifest_sha256"],
            view["result"]["manifest_sha256"]
        );
        assert_eq!(v["digests"]["view_sha256"], view["result"]["view_sha256"]);
        assert_eq!(
            v["digests"]["canonical_manifest_sha256"],
            view["acknowledgement"]["canonical_snapshot_sha256"]
        );
        assert_eq!(v["source"], facts(&run.prepared)["source"]);
        assert_eq!(v["method"]["budget"], before_status["budget"]);
        assert_eq!(v["counts_by_role"], before_status["counts_by_role"]);
        assert_eq!(v["counts_by_state"], before_status["counts_by_state"]);
        assert_eq!(v["outcome"]["state"], run.metadata["run_status"]);
        assert_eq!(
            v["outcome"]["incomplete_reason"],
            run.metadata["incomplete_reason"]
        );
        assert_eq!(v["outcome"]["audit_performed"], true);
        assert_eq!(v["provenance"], "workflow_recorded");
        let sealed = &saved["result"]["entry"];
        assert_eq!(v["sealed_entry_sequence"], sealed["sequence"]);
        assert_eq!(v["digests"]["sealed_entry_sha256"], sealed["entry_sha256"]);
        assert_eq!(v["digests"]["bundle_sha256"], req["expected_bundle_sha256"]);
        let members = v["package_members"].as_array().unwrap();
        assert_eq!(v["package_member_count"], members.len());
        let actual = tree(&package);
        let mut bytes = 0;
        for member in members {
            let name = member["path"].as_str().unwrap();
            assert_eq!(member["sha256"], actual[name]);
            let size = fs::metadata(package.join(name)).unwrap().len();
            assert_eq!(member["byte_length"], size);
            bytes += size;
        }
        assert_eq!(
            members.len(),
            actual.values().filter(|v| *v != "directory").count()
        );
        assert_eq!(v["package_bytes"], bytes);
        for (field, member) in [
            ("retention_sha256", "retained/retention.json"),
            ("workflow_sha256", "workflow.json"),
            ("projection_sha256", "workflow-projection.json"),
            ("retained_projection_sha256", "retained/projection.json"),
            ("manifest_sha256", "retained/bundle/provider-manifest.json"),
        ] {
            assert_eq!(v["digests"][field], actual[member]);
        }
    }
}
#[test]
fn missing_assets_and_sources_are_informational_and_recheck_detects_changed_bytes() {
    let run = RunFixture::new("quick");
    let req = request(&run);
    finalize(&run, &req, 0);
    run.f.change_case(|c| {
        c.assets.clear();
        c.data_sources.clear();
        c.scope_grants.clear();
    });
    let result = inspect(&run, 0);
    assert_eq!(result["result"]["asset_binding"]["asset_present"], false);
    assert_eq!(result["result"]["asset_binding"]["source_present"], false);
    let storage = Storage::open_read_only(run.f.data.join("casework.db")).unwrap();
    let verified = ai_security_scanner_lib::cloudflare_provider::audit::sealed::verify(
        &run.f.data,
        &storage,
        &run.f.case_id,
        run.prepared["session_id"].as_str().unwrap(),
    )
    .unwrap();
    verified.recheck_unchanged().unwrap();
    // A concurrent case change is retryable contention, not package corruption.
    run.f.change_case(|_| {});
    assert_eq!(
        verified.recheck_unchanged().unwrap_err().error_code,
        "case_changed"
    );
    let file = path(&run, &req).join("retained/bundle/REPORT.md");
    writable(&file);
    fs::write(file, b"changed").unwrap();
    let error = verified.recheck_unchanged().unwrap_err();
    assert_eq!(
        (error.error_code, error.failed_check),
        ("sealed_package_mismatch", "unchanged")
    );
}
#[test]
fn unsealed_unknown_and_wrong_case_are_refused_without_writes() {
    let run = RunFixture::new("quick");
    refused_unchanged(&run, "run_not_sealed");
    let _reader = Storage::open_read_only(run.f.data.join("casework.db")).unwrap();
    let before = tree(&run.f.data);
    for (case, session, error) in [
        (&*run.f.case_id, "unknown", "unknown_preparation"),
        (
            "wrong-case",
            run.prepared["session_id"].as_str().unwrap(),
            "case_not_found",
        ),
    ] {
        let result = terminal(
            run.f
                .command()
                .args([
                    "provider",
                    "cloudflare",
                    "inspect-sealed",
                    "--case-id",
                    case,
                    "--session-id",
                    session,
                ])
                .output()
                .unwrap(),
            2,
        );
        assert_eq!(result["error_code"], error);
    }
    assert_eq!(before, tree(&run.f.data));
}
#[test]
fn every_committed_and_retained_corruption_is_refused_without_writes() {
    let run = RunFixture::new("quick");
    let req = request(&run);
    finalize(&run, &req, 0);
    let package = path(&run, &req);
    for member in [
        "retained/retention.json",
        "workflow.json",
        "workflow-projection.json",
        "retained/bundle/REPORT.md",
        "retained/source-view/src/a.rs",
        "retained/validation.json",
        "retained/projection.json",
    ] {
        let file = package.join(member);
        let original = fs::read(&file).unwrap();
        writable(&file);
        let mut corrupted = original.clone();
        corrupted[0] ^= 1;
        fs::write(&file, corrupted).unwrap();
        refused_unchanged(&run, "sealed_package_mismatch");
        fs::write(&file, original).unwrap();
    }
    let member = package.join("workflow.json");
    writable(&package);
    let original = fs::read(&member).unwrap();
    fs::remove_file(&member).unwrap();
    refused_unchanged(&run, "sealed_package_mismatch");
    fs::write(&member, original).unwrap();
    fs::write(package.join("extra"), b"extra").unwrap();
    assert_eq!(
        refused_unchanged(&run, "sealed_package_mismatch")["failed_check"],
        "package_inventory"
    );
    fs::remove_file(package.join("extra")).unwrap();
    delete(&package);
    refused_unchanged(&run, "sealed_package_missing");
}
#[cfg(unix)]
#[test]
fn member_and_package_links_are_unsafe_even_when_dangling() {
    use std::os::unix::fs::symlink;
    let run = RunFixture::new("quick");
    let req = request(&run);
    finalize(&run, &req, 0);
    let package = path(&run, &req);
    let member = package.join("workflow.json");
    writable(&package);
    let original = fs::read(&member).unwrap();
    fs::remove_file(&member).unwrap();
    symlink("absent", &member).unwrap();
    refused_unchanged(&run, "unsafe_filesystem_entry");
    fs::remove_file(&member).unwrap();
    fs::write(&member, original).unwrap();
    let moved = package.with_file_name("moved");
    move_directory(&package, &moved);
    symlink(&moved, &package).unwrap();
    refused_unchanged(&run, "unsafe_filesystem_entry");
    fs::remove_file(&package).unwrap();
    symlink("absent", &package).unwrap();
    refused_unchanged(&run, "unsafe_filesystem_entry");
}
#[test]
fn invalid_record_is_rejected_before_missing_package() {
    let run = RunFixture::new("quick");
    let req = request(&run);
    finalize(&run, &req, 0);
    delete(&path(&run, &req));
    rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap().execute(
        "UPDATE case_events SET payload_json='{}' WHERE event_type='cloudflare_audit.record_entry'", []).unwrap();
    assert_eq!(
        refused_unchanged(&run, "sealed_package_mismatch")["failed_check"],
        "record_chain"
    );
}

#[cfg(unix)]
#[test]
fn unsafe_temporary_directory_is_nonretryable_and_records_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let run = RunFixture::new("quick");
    let req = request(&run);
    let ancestor = run.f.data.parent().unwrap().join("unsafe-temp");
    let temporary = ancestor.join("private");
    fs::create_dir_all(&temporary).unwrap();
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o770)).unwrap();
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700)).unwrap();
    let cp = json!({"schema_version":"ai-security-scanner.cloudflare-audit-checkpoint-request/v1",
        "request_id":"unsafe-checkpoint", "case_id":run.f.case_id,"session_id":run.prepared["session_id"],
        "expected_head_sha256":run.head,"action":{"type":"submit_documents","documents":[{"name":"findings.json"}]}});
    let cp_path = run.f.data.parent().unwrap().join("checkpoint-unsafe.json");
    fs::write(&cp_path, serde_json::to_vec(&cp).unwrap()).unwrap();
    let mut document = run.f.command();
    document
        .env("PATH", std::env::var_os("PATH").unwrap())
        .args([
            "provider",
            "cloudflare",
            "validate-document",
            "--document",
            "findings",
            "--input",
        ])
        .arg(run.host.join("findings.json"));
    let mut checkpoint = run.f.command();
    checkpoint
        .env("PATH", std::env::var_os("PATH").unwrap())
        .args(["provider", "cloudflare", "checkpoint", "--request"])
        .arg(cp_path);
    let final_path = run.f.data.parent().unwrap().join("final-unsafe.json");
    fs::write(&final_path, serde_json::to_vec(&req).unwrap()).unwrap();
    let mut seal = run.f.command();
    seal.env("PATH", std::env::var_os("PATH").unwrap())
        .args(["provider", "cloudflare", "finalize", "--request"])
        .arg(final_path);
    let before = run.f.audit_status("audit-one", false, 0);
    for mut c in [document, checkpoint, run.validate_command(), seal] {
        let value = terminal(c.env("TMPDIR", &temporary).output().unwrap(), 2);
        assert_eq!(value["error_code"], "unsafe_temporary_directory", "{value}");
        assert_eq!(value["retryable"], false);
        let message = value["error"].as_str().unwrap();
        assert!(
            message.contains("temporary directory")
                && message.contains("TMPDIR")
                && message.contains("private directory")
        );
        assert!(!message.contains("case archive"));
        assert_eq!(before, run.f.audit_status("audit-one", false, 0));
        assert_eq!(fs::read_dir(&temporary).unwrap().count(), 0);
    }
    // The same typed failure also survives the legacy standalone bundle commands.
    finalize(&run, &req, 0);
    let package = path(&run, &req);
    for operation in ["validate-bundle", "retain-bundle"] {
        let mut c = run.f.command();
        c.env("PATH", std::env::var_os("PATH").unwrap())
            .env("TMPDIR", &temporary)
            .args(["provider", "cloudflare", operation, "--bundle"])
            .arg(package.join("retained/bundle"))
            .arg("--source-view")
            .arg(package.join("retained/source-view"));
        let destination = run.f.data.parent().unwrap().join("retention-unsafe");
        if operation == "retain-bundle" {
            c.arg("--expected-bundle-sha256")
                .arg(req["expected_bundle_sha256"].as_str().unwrap())
                .arg("--destination")
                .arg(&destination);
        }
        let value = terminal(c.output().unwrap(), 2);
        assert_eq!(value["error_code"], "unsafe_temporary_directory");
        assert_eq!(value["retryable"], false);
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(&temporary).unwrap().count(), 0);
    }
}
