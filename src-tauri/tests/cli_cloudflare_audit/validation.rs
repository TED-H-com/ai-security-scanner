use super::fixture::*;
#[test]
fn terminal_fixture_captures_complete_quick_and_standard_runs() {
    for profile in ["quick", "standard"] {
        let run = RunFixture::new(profile);
        let status = run.f.audit_status("audit-one", false, 0);
        assert_eq!(status["result"]["counts_by_state"]["open"], 0);
        assert_eq!(
            status["result"]["counts_by_role"]["reconnaissance_baseline"],
            4
        );
        assert!(
            status["result"]["documents"]
                .as_object()
                .unwrap()
                .values()
                .all(|d| !d.is_null())
        );
    }
}

#[test]
fn complete_runs_validate_deterministically_from_custody_after_host_removal() {
    for profile in ["quick", "standard"] {
        let run = RunFixture::new(profile);
        let before = run.f.audit_status("audit-one", false, 0);
        let count = run.f.record_events();
        let first = run.validate(0);
        assert_eq!(first["result"]["sealable"], true, "{first}");
        let receipt = &first["result"]["bundle_receipt"];
        assert_eq!(receipt["valid"], true);
        assert_eq!(receipt["provenance"], "reported_only");
        for field in [
            "audit_performed",
            "admission_ready",
            "source_authorization_verified",
            "canonical_snapshot_binding_verified",
        ] {
            assert_eq!(receipt[field], false);
            assert!(first["result"].get(field).is_none());
        }
        fs::remove_dir_all(&run.host).unwrap();
        let second = run.validate(0);
        assert_eq!(first, second);
        assert_eq!(before, run.f.audit_status("audit-one", false, 0));
        assert_eq!(count, run.f.record_events());
        run.assert_no_temporary();
    }
}

#[test]
fn open_assignments_missing_documents_and_stale_heads_are_typed_refusals() {
    let mut run = RunFixture::without("quick", &["REPORT.md"]);
    assert_eq!(run.validate(2)["error_code"], "documents_required");
    run.documents(&["REPORT.md"]);
    let a = run.issue(json!({"role":"reconnaissance_focused"}));
    assert_eq!(run.validate(2)["error_code"], "assignments_open");
    run.action(json!({"type":"interrupt","assignment_id":a["assignment_id"],"reason":"abandoned"}));
    run.head = json!("a".repeat(64));
    assert_eq!(run.validate(3)["error_code"], "stale_head");
    run.assert_no_temporary();
}

#[test]
fn lapsed_authority_modified_view_and_modified_canonical_bytes_are_refused() {
    for change in ["grant", "view", "snapshot"] {
        let run = RunFixture::new("quick");
        match change {
            "grant" => run.f.change_case(|c| {
                c.scope_grants[0].expires_at = Some(Utc::now() - chrono::Duration::seconds(1))
            }),
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
                fs::write(file, "modified bytes").unwrap();
            }
        }
        let result = run.validate(3);
        assert_eq!(result["error_code"], "saved_receipt_not_current");
        assert_eq!(
            result["reason"],
            match change {
                "grant" => "source_authorization_expired",
                "view" => "view_integrity_failed",
                _ => "snapshot_integrity_failed",
            }
        );
        run.assert_no_temporary();
    }
}

#[test]
fn missing_or_modified_captured_objects_fail_without_recording_or_temporary_leaks() {
    for kind in ["document", "output"] {
        for remove in [true, false] {
            let run = RunFixture::new("quick");
            let status = run.f.audit_status("audit-one", false, 0);
            let hash = if kind == "document" {
                &status["result"]["documents"]["REPORT.md"]["current"]["sha256"]
            } else {
                &status["result"]["assignments"][4]["output"]["sha256"]
            };
            let path = run.directory().join("objects").join(hash.as_str().unwrap());
            if remove {
                fs::remove_file(path).unwrap();
            } else {
                fs::write(path, "corrupted").unwrap();
            }
            assert_eq!(run.validate(4)["error_code"], "storage_failed");
            assert_eq!(status, run.f.audit_status("audit-one", false, 0));
            run.assert_no_temporary();
        }
    }
}

#[test]
fn strict_request_and_validator_failure_leave_no_record_or_staging() {
    let run = RunFixture::new("quick");
    let before = run.f.record_events();
    let command = run.validate_command();
    let path = run.f.data.parent().unwrap().join("validate.json");
    let original = fs::read_to_string(&path).unwrap();
    let mut without_head: Value = serde_json::from_str(&original).unwrap();
    without_head
        .as_object_mut()
        .unwrap()
        .remove("expected_head_sha256");
    fs::write(&path, serde_json::to_vec(&without_head).unwrap()).unwrap();
    let mut optional = run.f.command();
    let result = terminal(
        optional
            .env("PATH", std::env::var_os("PATH").unwrap())
            .args(["provider", "cloudflare", "validate", "--request"])
            .arg(&path)
            .output()
            .unwrap(),
        0,
    );
    assert_eq!(result["result"]["sealable"], true);
    for request in [
        original.replace("{", "{\"unknown\":true,"),
        original.replace("{", "{\"case_id\":\"duplicate\","),
        original.replace(run.head.as_str().unwrap(), "bad-digest"),
    ] {
        fs::write(&path, request).unwrap();
        let mut command = run.f.command();
        let output = command
            .args(["provider", "cloudflare", "validate", "--request"])
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(terminal(output, 2)["error_code"], "invalid_request");
    }
    drop(command);
    assert_eq!(
        terminal(run.validate_command().env("PATH", "").output().unwrap(), 2)["error_code"],
        "not_available"
    );
    assert_eq!(before, run.f.record_events());
    run.assert_no_temporary();
}

#[test]
fn current_findings_require_matching_candidate_and_final_receipts() {
    for (profile, omit) in [
        ("quick", "candidate"),
        ("quick", "same_fingerprint"),
        ("standard", "final"),
    ] {
        let run = RunFixture::without(profile, &[omit]);
        let result = run.validate(0);
        assert_eq!(result["result"]["sealable"], false, "{result}");
        assert!(
            result["result"]["record_errors"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            result["result"]["bundle_receipt"]["reference_errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v
                    .as_str()
                    .unwrap()
                    .contains("lacks required independent verifier receipts"))
        );
        run.assert_no_temporary();
    }
    for profile in ["quick", "standard"] {
        let mut run = RunFixture::new(profile);
        run.findings[0]["title"] = json!("Changed current record");
        run.documents(&["findings.json"]);
        let result = run.validate(0);
        assert_eq!(result["result"]["sealable"], false);
        let errors = result["result"]["bundle_receipt"]["reference_errors"].to_string();
        assert!(
            errors.contains(if profile == "quick" {
                "exact record"
            } else {
                "lacks required independent verifier receipts"
            }),
            "{result}"
        );
    }
}

#[test]
fn rejected_standard_record_needs_no_final_but_needs_validation_does() {
    let mut run = RunFixture::without("standard", &["final"]);
    let rejected = run.findings[2].clone();
    run.findings = json!([rejected]);
    run.ledger[0]["result_fingerprints"] = json!([rejected["fingerprint"]]);
    run.documents(&["findings.json", "coverage-ledger.json"]);
    assert_eq!(run.validate(0)["result"]["sealable"], true);
    let needs: Value = serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/cloudflare/bundle/findings.json"
    ))
    .unwrap();
    let mut needs = needs[1].clone();
    for field in ["trace", "evidence"] {
        for location in needs[field].as_array_mut().unwrap() {
            location["file"] = json!("src/a.rs");
            location["line"] = json!(1);
        }
    }
    run.findings = json!([needs]);
    run.ledger[0]["result_fingerprints"] = json!([needs["fingerprint"]]);
    run.documents(&["findings.json", "coverage-ledger.json"]);
    assert_eq!(run.validate(0)["result"]["sealable"], false);
}

#[test]
fn ledger_owners_must_be_issued_evidence_roles_and_evidence_must_be_closed() {
    for owner in ["unknown", "critic", "interrupted"] {
        let mut run = RunFixture::without(
            "quick",
            if owner == "interrupted" {
                &["hunter"]
            } else {
                &[]
            },
        );
        let id = if owner == "unknown" {
            json!("never-issued")
        } else if owner == "critic" {
            let status = run.f.audit_status("audit-one", false, 0);
            status["result"]["assignments"]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["role"] == "post_wave_critic")
                .unwrap()["agent_id"]
                .clone()
        } else {
            run.hunter["agent_id"].clone()
        };
        run.ledger[0]["agent_id"] = id.clone();
        run.ledger[0]["local_checks"][0]["agent_id"] = id;
        run.documents(&["coverage-ledger.json"]);
        let result = run.validate(0);
        assert_eq!(
            result["result"]["bundle_receipt"]["valid"], true,
            "{result}"
        );
        assert_eq!(result["result"]["sealable"], false);
        assert!(
            result["result"]["record_errors"]
                .to_string()
                .contains(match owner {
                    "unknown" => "not issued in this run",
                    "critic" => "not issued an evidence role",
                    _ => "not closed",
                }),
            "{result}"
        );
    }
}

#[test]
fn complete_run_obligations_do_not_apply_to_an_incomplete_run_with_reason() {
    for missing in ["baseline", "critic", "clean"] {
        let mut run = RunFixture::without("standard", &[missing]);
        let result = run.validate(0);
        assert_eq!(result["result"]["sealable"], false, "{result}");
        assert_eq!(
            result["result"]["record_errors"].as_array().unwrap().len(),
            1
        );
        run.metadata["run_status"] = json!("incomplete");
        run.metadata["incomplete_reason"] = json!("Host stopped before completing reserved work");
        run.documents(&["run-metadata.json"]);
        let result = run.validate(0);
        assert_eq!(result["result"]["sealable"], true, "{result}");
        assert_eq!(result["result"]["run_status"], "incomplete");
        assert_eq!(
            result["result"]["incomplete_reason"],
            run.metadata["incomplete_reason"]
        );
    }
}

// Independently assemble the known small fixture as an external bundle. Comparing
// its validation digest checks both inclusion and exclusion without exposing staging.
fn external_bundle(run: &RunFixture, excluded: &[Value]) -> Value {
    use ai_security_scanner_lib::cloudflare_provider::{
        UPSTREAM_COMMIT, source_view::inspect_source_view,
    };
    let source = inspect_source_view(&run.f.view_root(), None, None)
        .unwrap()
        .source;
    let directory = run.host.with_file_name("external-bundle");
    fs::create_dir(&directory).unwrap();
    let status = run.f.audit_status("audit-one", false, 0);
    let facts = facts(&run.prepared);
    let binding = json!({"case_id":run.f.case_id,"asset_id":run.f.asset_id,
        "run_id":facts["provider_run_id"],"task_id":facts["provider_task_id"],
        "session_id":facts["session_id"],"attempt_id":facts["attempt_id"]});
    let mut files = Vec::new();
    for d in status["result"]["documents"].as_object().unwrap().values() {
        files.push(json!({"path":d["current"]["name"],"sha256":d["current"]["sha256"],"byte_length":d["current"]["byte_length"]}));
    }
    let mut verifiers = Vec::new();
    for a in status["result"]["assignments"].as_array().unwrap() {
        if !["hunter", "candidate_verifier", "final_verifier"]
            .contains(&a["role"].as_str().unwrap())
            || excluded.contains(&a["assignment_id"])
        {
            continue;
        }
        let o = &a["output"];
        files.push(json!({"path":o["path"],"sha256":o["sha256"],"byte_length":o["byte_length"]}));
        if a["role"] != "hunter" {
            verifiers.push(json!({"assignment_id":a["assignment_id"],"binding":binding,"agent_id":a["agent_id"],
                "role":a["role"],"fingerprint":a["fingerprint"],"view_sha256":source.view_sha256,
                "record_sha256":o["record_sha256"],"output_path":o["path"],
                "started_at":a["issued_at"],"finished_at":a["closed_at"]}));
        }
    }
    files.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    verifiers.sort_by(|a, b| {
        (a["fingerprint"].as_str(), a["role"].as_str())
            .cmp(&(b["fingerprint"].as_str(), b["role"].as_str()))
    });
    for file in &files {
        let path = file["path"].as_str().unwrap();
        fs::create_dir_all(directory.join(path).parent().unwrap()).unwrap();
        fs::copy(run.host.join(path), directory.join(path)).unwrap();
    }
    let manifest = json!({"schema_version":"ai-security-scanner.cloudflare-bundle/v1","provider_id":"cloudflare-security-audit",
        "upstream_commit":UPSTREAM_COMMIT,"binding":binding,"source":source,"files":files,"verifier_assignments":verifiers,
        "reported_counts":{"confirmed":1,"needs_validation":1,"rejected":1,"reported_confirmed_by_severity":{"medium":1}}});
    let manifest: ai_security_scanner_lib::cloudflare_provider::bundle::BundleManifest =
        serde_json::from_value(manifest).unwrap();
    fs::write(
        directory.join("provider-manifest.json"),
        serde_json::to_vec(&serde_json::to_value(manifest).unwrap()).unwrap(),
    )
    .unwrap();
    let output = run
        .f
        .command()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .args(["provider", "cloudflare", "validate-bundle", "--bundle"])
        .arg(directory)
        .arg("--source-view")
        .arg(run.f.view_root().join("tree"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn generated_manifest_matches_external_validation_and_excludes_unselected_outputs() {
    for profile in ["quick", "standard"] {
        let mut run = RunFixture::new(profile);
        let status = run.f.audit_status("audit-one", false, 0);
        let old = status["result"]["assignments"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["role"] == "candidate_verifier")
            .unwrap()["assignment_id"]
            .clone();
        let record = run.findings[0].clone();
        let a = run.issue(json!({"role":"candidate_verifier","fingerprint":record["fingerprint"]}));
        run.submit(
            &a,
            &serde_json::to_vec(&json!({"decision":record["verdict"],"record":record})).unwrap(),
        );
        let mut excluded = vec![old];
        if profile != "quick" {
            excluded.push(
                status["result"]["assignments"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|a| a["role"] == "final_verifier")
                    .unwrap()["assignment_id"]
                    .clone(),
            );
            let a = run.issue(json!({"role":"final_verifier","fingerprint":record["fingerprint"]}));
            run.submit(
                &a,
                &serde_json::to_vec(
                    &json!({"decision":"verified","fingerprint":record["fingerprint"]}),
                )
                .unwrap(),
            );
        }
        let external = external_bundle(&run, &excluded);
        let result = run.validate(0);
        assert_eq!(result["result"]["sealable"], true, "{result}");
        for field in ["manifest_sha256", "bundle_sha256"] {
            assert_eq!(result["result"][field], external[field], "{field}");
        }
    }
}

#[test]
fn terminal_bundle_byte_limit_is_a_validation_result_and_cleans_staging() {
    let mut run = RunFixture::new("standard");
    let bytes = serde_json::to_vec(&json!({"padding":"x".repeat(5 * 1024 * 1024 - 100)})).unwrap();
    for _ in 0..13 {
        let a = run.issue(json!({"role":"hunter","wave":2}));
        run.submit(&a, &bytes);
        let mut check = run.ledger[0]["local_checks"][0].clone();
        check["agent_id"] = a["agent_id"].clone();
        run.ledger[0]["local_checks"]
            .as_array_mut()
            .unwrap()
            .push(check);
    }
    run.metadata["run_status"] = json!("incomplete");
    run.metadata["incomplete_reason"] = json!("Stopped before second-wave criticism");
    run.documents(&["coverage-ledger.json", "run-metadata.json"]);
    let before = run.f.record_events();
    let result = run.validate(0);
    assert_eq!(result["result"]["sealable"], false, "{result}");
    assert!(
        result["result"]["bundle_receipt"]["reference_errors"]
            .to_string()
            .contains("total byte limit")
    );
    assert_eq!(before, run.f.record_events());
    run.assert_no_temporary();
}

#[test]
fn historical_attempt_and_check_owners_are_checked_too() {
    let mut run = RunFixture::new("quick");
    // An archived attempt keeps exactly the upstream attempt fields.
    let unit = run.ledger[0].clone();
    let attempt = json!({"wave":1,"status":"blocked","agent_id":"unknown-archive",
        "reviewed_paths":["src/a.rs"],"local_checks":[{
            "agent_id":"unknown-check","reviewed_paths":["src/a.rs"],"invariant":"Synthetic invariant",
            "method":"source","result":"Synthetic observation","artifact":null}],
        "result_fingerprints":[],"unresolved":["Interrupted investigation"],"reassignment_reason":"Continued in next wave"});
    run.ledger[0]["wave"] = json!(2);
    run.ledger[0]["attempts"] = json!([attempt]);
    // Keep the live source observations and links unchanged.
    assert_eq!(run.ledger[0]["local_checks"], unit["local_checks"]);
    run.documents(&["coverage-ledger.json"]);
    let result = run.validate(0);
    let errors = result["result"]["record_errors"].to_string();
    assert!(errors.contains("unknown-archive"), "{result}");
    assert!(errors.contains("unknown-check"), "{result}");
    assert_eq!(result["result"]["sealable"], false);
}

#[test]
fn invalid_record_is_a_typed_refusal_and_validation_requires_the_writer_lease() {
    let run = RunFixture::new("quick");
    let lease = DataDirectoryExclusiveLease::acquire(&run.f.data).unwrap();
    assert_eq!(run.validate(3)["error_code"], "data_directory_busy");
    drop(lease);
    rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap().execute(
        "UPDATE case_events SET payload_json='{}' WHERE event_type='cloudflare_audit.record_entry'",[]).unwrap();
    assert_eq!(run.validate(2)["error_code"], "record_invalid");
    run.assert_no_temporary();
}
