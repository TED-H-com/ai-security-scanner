use super::{admit, fixture::*};
use ai_security_scanner_lib::case_archive::{self, ArchiveOptions};

#[test]
fn admitted_archive_creation_preserves_packages_captures_and_source_selection() {
    let (run, request) = admit::sealed("standard");
    admit::admit(&run, &request, 0);
    let orphan = run.directory().join("objects").join("f".repeat(64));
    fs::write(&orphan, b"not recorded").unwrap();
    for sources in [false, true] {
        let path = run
            .f
            .data
            .with_file_name(format!("archive-{sources}.tar.gz"));
        case_archive::create_archive(
            &run.f.data,
            &run.f.case_id,
            &path,
            &ArchiveOptions {
                include_source_snapshots: sources,
                ..Default::default()
            },
        )
        .unwrap();
        let files = unpack(&path);
        let manifest = document(&files, "archive-manifest.json");
        assert_eq!(
            manifest["required_capabilities"],
            json!([
                "cloudflare_audit_admission/v1",
                "provider_archive_history/v1"
            ])
        );
        let history = document(&files, "provider-history.json");
        validate_history_schema(&history);
        let p = &history["preparations"][0];
        assert_eq!(p["state"], "admitted");
        assert!(!p["package"].as_array().unwrap().is_empty());
        assert!(!p["captured"].as_array().unwrap().is_empty());
        assert_eq!(
            p["source_body_omissions"].as_array().unwrap().is_empty(),
            sources
        );
        for entry in manifest["entries"].as_array().unwrap() {
            let path = entry["path"].as_str().unwrap();
            assert!(!path.ends_with(&"f".repeat(64)));
            if path.contains("/sealed/") && path.contains("/source-view/") {
                assert!(sources);
            }
        }
        assert!(
            manifest["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .any(|s| s.contains("credential-vault") && s.contains("leases"))
        );
        assert!(
            !manifest["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .any(|s| s.starts_with("Cloudflare audit records are not included"))
        );
        assert_eq!(
            manifest["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .any(|s| s.starts_with("Source snapshots inside source-audit packages")),
            !sources
        );
        assert!(
            case_archive::inspect_archive(&path)
                .unwrap()
                .integrity_valid
        );
        assert!(serde_json::from_value::<LegacyManifest>(manifest).is_err());
        let case = admit::case(&run);
        let admission = &case.agent_audit_admissions[0];
        for binding in &admission.artifacts {
            let original = case
                .raw_artifacts
                .iter()
                .find(|r| r.id == binding.artifact_id)
                .unwrap();
            let task_path = format!("artifacts/{}", original.relative_path);
            let package_path = format!(
                "artifacts/{}/cloudflare-sessions/{}/sealed/{}/{}",
                case.id,
                admission.identities.session_id,
                admission.digests.bundle_sha256,
                binding.member_path
            );
            assert_eq!(files[&task_path], files[&package_path]);
            assert_eq!(
                files[&task_path],
                fs::read(run.f.data.join(&task_path)).unwrap()
            );
        }
    }
}

use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read};
type Files = BTreeMap<String, Vec<u8>>;
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub(super) fn unpack(path: &Path) -> Files {
    let mut archive =
        tar::Archive::new(flate2::read::GzDecoder::new(fs::File::open(path).unwrap()));
    archive
        .entries()
        .unwrap()
        .map(|e| {
            let mut e = e.unwrap();
            let path = e.path().unwrap().to_str().unwrap().to_owned();
            let mut bytes = Vec::new();
            e.read_to_end(&mut bytes).unwrap();
            (path, bytes)
        })
        .collect()
}
fn document(files: &Files, name: &str) -> Value {
    serde_json::from_slice(&files[name]).unwrap()
}
fn put(files: &mut Files, name: &str, value: &Value) {
    files.insert(name.into(), serde_json::to_vec(value).unwrap());
}
pub(super) fn repack(path: &Path, mut files: Files) {
    let mut manifest = document(&files, "archive-manifest.json");
    files.remove("archive-manifest.json");
    manifest["case_document_sha256"] = hash(&files["case.json"]).into();
    manifest["entries"] = files
        .iter()
        .map(|(path, bytes)| json!({"path":path,"sha256":hash(bytes),"byte_length":bytes.len()}))
        .collect();
    let mut tar = tar::Builder::new(flate2::GzBuilder::new().mtime(0).write(
        fs::File::create(path).unwrap(),
        flate2::Compression::default(),
    ));
    let add = |tar: &mut tar::Builder<_>, name: &str, bytes: &[u8]| {
        let header = |size: usize| {
            let mut h = tar::Header::new_ustar();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(0);
            h.set_mode(0o600);
            h.set_size(size as u64);
            h
        };
        let mut h = header(bytes.len());
        let name = if h.set_path(name).is_err() {
            let mut long = name.as_bytes().to_vec();
            long.push(0);
            let mut lh = header(long.len());
            lh.set_entry_type(tar::EntryType::GNULongName);
            let marker = b"././@LongLink";
            lh.as_mut_bytes()[..marker.len()].copy_from_slice(marker);
            lh.set_cksum();
            tar.append(&lh, long.as_slice()).unwrap();
            "__archive_long_path__"
        } else {
            name
        };
        h = header(bytes.len());
        h.set_path(name).unwrap();
        h.set_cksum();
        tar.append(&h, bytes).unwrap();
    };
    add(
        &mut tar,
        "archive-manifest.json",
        &serde_json::to_vec(&manifest).unwrap(),
    );
    for (name, bytes) in files {
        add(&mut tar, &name, &bytes);
    }
    tar.into_inner().unwrap().finish().unwrap();
}

fn archived(sources: bool) -> (RunFixture, PathBuf, Files) {
    let (run, request) = admit::sealed("standard");
    admit::admit(&run, &request, 0);
    let path = run.f.data.with_file_name("complete.tar.gz");
    case_archive::create_archive(
        &run.f.data,
        &run.f.case_id,
        &path,
        &ArchiveOptions {
            include_source_snapshots: sources,
            ..Default::default()
        },
    )
    .unwrap();
    let files = unpack(&path);
    (run, path, files)
}
fn change_case(files: &mut Files, change: impl FnOnce(&mut Value)) {
    let mut portable = document(files, "case.json");
    change(&mut portable["case"]);
    put(files, "original-case.json", &portable["case"]);
    portable["source_document_sha256"] = hash(&files["original-case.json"]).into();
    put(files, "case.json", &portable);
}
pub(super) fn rejected(run: &RunFixture, path: &Path, code: &str) {
    for operation in ["verify", "restore-preview", "restore"] {
        let destination = run.f.data.with_file_name("refused-restore");
        let mut command = run.f.command();
        command.args(["archive", operation, "--archive"]).arg(path);
        if operation != "verify" {
            command.arg("--destination").arg(&destination);
        }
        if operation == "restore" {
            command.arg("--acknowledge-sensitive-data");
        }
        let out = command.output().unwrap();
        assert_eq!(out.status.code(), Some(1));
        let value: Value = serde_json::from_slice(&out.stderr).unwrap();
        assert_eq!(value["error_code"], code, "{operation}: {value}");
        assert!(!destination.exists());
        assert!(
            !fs::read_dir(destination.parent().unwrap())
                .unwrap()
                .any(|e| e
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".scanner-restore-"))
        );
    }
}

#[test]
fn crafted_admission_graphs_have_stable_refusals() {
    let (run, path, original) = archived(false);
    let cases = [
        ("duplicate", "archive_duplicate_admission"),
        ("session", "archive_duplicate_admission"),
        ("missing", "archive_original_missing"),
        ("extra", "archive_original_extra"),
        ("length", "archive_content_mismatch"),
        ("case", "archive_admission_binding_mismatch"),
        ("run", "archive_admission_binding_mismatch"),
        ("task", "archive_admission_binding_mismatch"),
        ("path", "archive_admission_binding_mismatch"),
        ("task_asset", "archive_admission_binding_mismatch"),
        ("frozen_source", "archive_admission_binding_mismatch"),
        ("frozen_snapshot", "archive_admission_binding_mismatch"),
        ("sensitivity", "archive_admission_binding_mismatch"),
        ("provider", "archive_provider_unsupported"),
        ("schema", "archive_provider_unsupported"),
        ("evidence_index", "archive_evidence_mismatch"),
        ("evidence_digest", "archive_evidence_mismatch"),
        ("evidence_fingerprint", "archive_evidence_mismatch"),
        ("digest", "archive_content_mismatch"),
        ("projection", "archive_content_mismatch"),
        ("no_admission", "archive_history_mismatch"),
        ("task_admission", "archive_admission_binding_mismatch"),
    ];
    for (mutation, code) in cases {
        let mut files = original.clone();
        change_case(&mut files, |case| {
            let id = case["agent_audit_admissions"][0]["artifacts"][0]["artifact_id"].clone();
            let raw = case["raw_artifacts"]
                .as_array()
                .unwrap()
                .iter()
                .position(|r| r["id"] == id)
                .unwrap();
            match mutation {
                "duplicate" | "session" => {
                    let mut duplicate = case["agent_audit_admissions"][0].clone();
                    if mutation == "session" {
                        duplicate["admission_id"] = "other".into();
                    }
                    case["agent_audit_admissions"]
                        .as_array_mut()
                        .unwrap()
                        .push(duplicate);
                }
                "missing" => {
                    case["raw_artifacts"].as_array_mut().unwrap().remove(raw);
                }
                "extra" => {
                    let extra = case["raw_artifacts"][raw].clone();
                    case["raw_artifacts"].as_array_mut().unwrap().push(extra);
                }
                "length" => case["raw_artifacts"][raw]["byte_length"] = 0.into(),
                "case" | "run" | "task" => {
                    case["agent_audit_admissions"][0]["identities"][format!("{mutation}_id")] =
                        "other".into()
                }
                "path" => {
                    case["raw_artifacts"][raw]["relative_path"] = "different/member.json".into()
                }
                "task_asset" => {
                    case["scan_runs"][0]["engine_runs"][0]["asset_ids"] = json!(["other"])
                }
                "frozen_source" => {
                    case["scan_runs"][0]["report_asset_snapshots"][0]["asset"]["discovered_from"] =
                        json!(["other"])
                }
                "frozen_snapshot" => {
                    case["scan_runs"][0]["report_asset_snapshots"][0]["asset"]["metadata"]["workspace_snapshot_sha256"] =
                        "0".repeat(64).into()
                }
                "sensitivity" => {
                    case["raw_artifacts"][raw]["contains_sensitive_data"] = false.into()
                }
                "provider" => {
                    case["agent_audit_admissions"][0]["provider_id"] = "unsupported".into()
                }
                "schema" => {
                    case["agent_audit_admissions"][0]["retained_projection"]["schema_version"] =
                        "future/v2".into()
                }
                "evidence_index" | "evidence_digest" | "evidence_fingerprint" => {
                    let evidence = &mut case["findings"][0]["evidence"][0]["provider_record"];
                    match mutation {
                        "evidence_index" => evidence["native_record_index"] = 999.into(),
                        "evidence_digest" => {
                            evidence["native_record_sha256"] = "0".repeat(64).into()
                        }
                        _ => evidence["native_fingerprint"] = "other".into(),
                    }
                }
                "digest" => {
                    case["agent_audit_admissions"][0]["admission_sha256"] = "0".repeat(64).into()
                }
                "projection" => {
                    case["agent_audit_admissions"][0]["retained_projection"]["coverage_by_status"]
                        ["covered"] = 999.into()
                }
                "no_admission" => case["agent_audit_admissions"] = json!([]),
                "task_admission" => {
                    case["scan_runs"][0]["engine_runs"][0]["task_kind"]["admission_id"] =
                        "other".into()
                }
                _ => unreachable!(),
            }
        });
        repack(&path, files);
        rejected(&run, &path, code);
    }
}

#[test]
fn crafted_custody_inventory_omissions_and_capabilities_fail_closed() {
    let (run, path, original) = archived(false);
    for (mutation, code) in [
        ("missing_history", "archive_history_mismatch"),
        ("tampered_history", "archive_history_mismatch"),
        ("unknown_history_field", "archive_history_mismatch"),
        ("missing_capture", "archive_content_mismatch"),
        ("extra_member", "archive_history_mismatch"),
        ("event", "archive_history_mismatch"),
        ("package", "archive_history_mismatch"),
        ("missing_omission", "archive_omission_mismatch"),
        ("wrong_omission", "archive_omission_mismatch"),
        ("overlap", "archive_omission_mismatch"),
        ("capability", "archive_capability_unsupported"),
    ] {
        let mut files = original.clone();
        let mut history = document(&files, "provider-history.json");
        match mutation {
            "missing_history" => {
                files.remove("provider-history.json");
            }
            "tampered_history" => {
                history["preparations"][0]["recorded_head"]["sequence"] = 999.into();
                put(&mut files, "provider-history.json", &history);
            }
            "unknown_history_field" => {
                history["prose"] = "not inventory".into();
                put(&mut files, "provider-history.json", &history);
            }
            "missing_capture" => {
                files.remove(
                    history["preparations"][0]["captured"][0]["member"]
                        .as_str()
                        .unwrap(),
                );
            }
            "extra_member" => {
                let prefix = history["preparations"][0]["descriptor"]["path"]
                    .as_str()
                    .unwrap()
                    .trim_end_matches("session.json");
                files.insert(format!("{prefix}unrecorded.json"), b"extra".to_vec());
            }
            "event" => {
                let mut portable = document(&files, "case.json");
                let e = portable["historical_events"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|e| e["event_type"] == "cloudflare_audit.record_entry")
                    .unwrap();
                let mut payload: Value =
                    serde_json::from_str(e["payload_json"].as_str().unwrap()).unwrap();
                payload["predecessor_sha256"] = "0".repeat(64).into();
                e["payload_json"] = serde_json::to_string(&payload).unwrap().into();
                put(&mut files, "case.json", &portable);
            }
            "package" => {
                let name = history["preparations"][0]["package"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|e| e["path"].as_str().unwrap().ends_with("workflow.json"))
                    .unwrap()["path"]
                    .as_str()
                    .unwrap();
                files.insert(name.into(), b"{}".to_vec());
            }
            "missing_omission" => {
                history["preparations"][0]["source_body_omissions"] = json!([]);
                put(&mut files, "provider-history.json", &history);
            }
            "wrong_omission" => {
                history["preparations"][0]["source_body_omissions"][0]["sha256"] =
                    "0".repeat(64).into();
                put(&mut files, "provider-history.json", &history);
            }
            "overlap" => {
                history["preparations"][0]["source_body_omissions"][0] =
                    history["preparations"][0]["descriptor"].clone();
                put(&mut files, "provider-history.json", &history);
            }
            "capability" => {
                let mut m = document(&files, "archive-manifest.json");
                m["required_capabilities"]
                    .as_array_mut()
                    .unwrap()
                    .push("future/v9".into());
                put(&mut files, "archive-manifest.json", &m);
            }
            _ => unreachable!(),
        }
        repack(&path, files);
        rejected(&run, &path, code);
    }
}

#[test]
fn provider_restore_checks_history_before_destination_staging() {
    let (run, path, original) = archived(false);
    let destination = run
        .f
        .data
        .with_file_name("restore-parent-does-not-exist")
        .join("restored");
    // History validation must precede destination staging.
    let mut files = original;
    files.insert("provider-history.json".into(), b"invalid JSON".to_vec());
    repack(&path, files);
    for operation in ["restore-preview", "restore"] {
        let mut command = run.f.command();
        command
            .args(["archive", operation, "--archive"])
            .arg(&path)
            .arg("--destination")
            .arg(&destination);
        if operation == "restore" {
            command.arg("--acknowledge-sensitive-data");
        }
        let out = command.output().unwrap();
        assert_eq!(out.status.code(), Some(1));
        let value: Value = serde_json::from_slice(&out.stderr).unwrap();
        assert_eq!(value["error_code"], "archive_history_mismatch");
        assert_eq!(
            value["error"],
            "Source-audit archive data is missing or inconsistent."
        );
        assert!(!destination.parent().unwrap().exists());
    }
}

#[test]
fn invalid_live_admission_and_different_original_bytes_publish_nothing() {
    let (run, request) = admit::sealed("standard");
    admit::admit(&run, &request, 0);
    let case = admit::case(&run);
    let destination = run.f.data.with_file_name("refused.tar.gz");
    let db = rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap();
    let mut bad = case.clone();
    bad.agent_audit_admissions
        .push(bad.agent_audit_admissions[0].clone());
    db.execute(
        "UPDATE cases SET document_json=?1 WHERE id=?2",
        rusqlite::params![serde_json::to_string(&bad).unwrap(), case.id],
    )
    .unwrap();
    let error =
        case_archive::create_archive(&run.f.data, &case.id, &destination, &Default::default())
            .unwrap_err();
    assert_eq!(
        ai_security_scanner_lib::error::foreground_error_class(&error).1,
        "archive_duplicate_admission"
    );
    assert!(!destination.exists());
    db.execute(
        "UPDATE cases SET document_json=?1 WHERE id=?2",
        rusqlite::params![serde_json::to_string(&case).unwrap(), case.id],
    )
    .unwrap();
    let path = run
        .f
        .data
        .join("artifacts")
        .join(&case.raw_artifacts[0].relative_path);
    writable(&path);
    fs::write(&path, b"different original bytes").unwrap();
    let error =
        case_archive::create_archive(&run.f.data, &case.id, &destination, &Default::default())
            .unwrap_err();
    assert_eq!(
        ai_security_scanner_lib::error::foreground_error_class(&error).1,
        "archive_content_mismatch"
    );
    assert!(!destination.exists());
    fs::remove_file(path).unwrap();
    let error =
        case_archive::create_archive(&run.f.data, &case.id, &destination, &Default::default())
            .unwrap_err();
    assert_eq!(
        ai_security_scanner_lib::error::foreground_error_class(&error).1,
        "archive_original_missing"
    );
    assert!(!destination.exists());
}

#[test]
fn all_recorded_preparations_and_superseded_or_unselected_captures_travel_inertly() {
    use super::finalize;
    let mut run = RunFixture::new("standard");
    fs::write(run.host.join("REPORT.md"), b"second recorded report").unwrap();
    run.action(json!({"type":"submit_documents","documents":[{"name":"REPORT.md"}]}));
    let accepted = run.issue(json!({"role":"reconnaissance_baseline"}));
    run.submit(&accepted, b"unselected accepted original");
    let discarded = run.issue(json!({"role":"candidate_verifier","fingerprint":"not-a-result"}));
    run.submit(&discarded, b"invalid verifier output");
    finalize::finalize(&run, &finalize::request(&run), 0);
    let storage = run.f.storage();
    let v = ai_security_scanner_lib::cloudflare_provider::audit::sealed::verify(
        &run.f.data,
        &storage,
        &run.f.case_id,
        run.prepared["session_id"].as_str().unwrap(),
    )
    .unwrap();
    let request = json!({"schema_version":"ai-security-scanner.cloudflare-audit-admit-request/v1",
        "request_id":"admit-one","case_id":run.f.case_id,"session_id":run.prepared["session_id"],
        "expected_sealed_entry_sha256":v.digests.sealed_entry_sha256,"expected_bundle_sha256":v.digests.bundle_sha256,
        "expected_projection_sha256":v.digests.projection_sha256});
    drop(v);
    drop(storage);
    admit::admit(&run, &request, 0);
    let other_host = run.f.data.with_file_name("second-host");
    fs::create_dir(&other_host).unwrap();
    let mut prep = json!({"schema_version":"ai-security-scanner.cloudflare-audit-prepare-request/v1",
        "request_id":"second-audit","case_id":run.f.case_id,"asset_id":run.f.asset_id,
        "source_view_request_id":"view-request","expected_source_view_receipt_sha256":facts(&run.prepared)["source"]["source_view_receipt_sha256"],
        "profile":"quick","invocation_budget":null,"host":{"host_id":"declared-test-host","delegation":"available"},"run_directory":other_host});
    let prepared = run.f.audit(&prep, 0);
    let mut checkpoint = run.f.checkpoint_request(
        &prepared,
        json!({"type":"issue","assignments":[{"role":"reconnaissance_baseline"}]}),
    );
    let issued = run.f.checkpoint(&checkpoint, 0);
    checkpoint["request_id"] = "interrupted-audit".into();
    checkpoint["expected_head_sha256"] = issued["result"]["record_head"]["entry_sha256"].clone();
    checkpoint["action"] = json!({"type":"interrupt","assignment_id":issued["result"]["entry"]["content"]["assignments"][0]["assignment_id"],"reason":"host stopped"});
    run.f.checkpoint(&checkpoint, 0);
    prep["request_id"] = "blocked-audit".into();
    prep["host"]["delegation"] = "unavailable".into();
    run.f.audit(&prep, 0);
    let archive = run.f.data.with_file_name("all-history.tar.gz");
    case_archive::create_archive(&run.f.data, &run.f.case_id, &archive, &Default::default())
        .unwrap();
    let files = unpack(&archive);
    let history = document(&files, "provider-history.json");
    assert_eq!(history["preparations"].as_array().unwrap().len(), 3);
    let p = &history["preparations"][0];
    let captured = p["captured"].as_array().unwrap();
    let reports: Vec<_> = captured
        .iter()
        .filter(|c| c["selector"]["name"] == "REPORT.md")
        .collect();
    assert_eq!(reports.len(), 2);
    assert_ne!(reports[0]["sha256"], reports[1]["sha256"]);
    for report in reports {
        assert!(files.contains_key(report["member"].as_str().unwrap()));
    }
    let accepted = captured
        .iter()
        .find(|c| c["selector"]["assignment_id"] == accepted["assignment_id"])
        .unwrap();
    assert_eq!(
        files[accepted["member"].as_str().unwrap()],
        b"unselected accepted original"
    );
    let discarded = captured
        .iter()
        .find(|c| c["selector"]["assignment_id"] == discarded["assignment_id"])
        .unwrap();
    assert_eq!(discarded["available"], false);
    assert!(discarded["member"].is_null());
    assert_eq!(history["preparations"][1]["state"], "unsealed");
    assert_eq!(history["preparations"][1]["recorded_head"]["sequence"], 2);
    assert_eq!(history["preparations"][2]["state"], "blocked");
    assert!(history["preparations"][2]["descriptor"].is_null());
    // Delete the live provider root: verification must depend only on archived bytes.
    writable(&run.directory());
    assert!(
        case_archive::inspect_archive(&archive)
            .unwrap()
            .integrity_valid
    );
    validate_history_schema(&history);
    let included = run.f.data.with_file_name("all-history-included.tar.gz");
    case_archive::create_archive(
        &run.f.data,
        &run.f.case_id,
        &included,
        &ArchiveOptions {
            include_source_snapshots: true,
            ..Default::default()
        },
    )
    .unwrap();
    super::restored::remove(&run.f.data);
    super::restored::remove(&run.host);
    super::restored::remove(&other_host);
    for (ordinal, archive) in [archive, included].iter().enumerate() {
        let destination = run
            .f
            .data
            .with_file_name(format!("restored-captures-{ordinal}"));
        case_archive::restore_archive(archive, &destination).unwrap();
        run.f.data = destination;
        let before = super::captured::logical_database(&run.f);
        for (i, capture) in captured.iter().enumerate() {
            let destination = run.f.data.with_file_name(format!("capture-{ordinal}-{i}"));
            let mut command = run.f.command();
            command
                .args([
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
            let selector = &capture["selector"];
            if selector["type"] == "document" {
                command.args([
                    "--document",
                    selector["name"].as_str().unwrap(),
                    "--revision",
                    &selector["revision"].to_string(),
                ]);
            } else {
                command.args([
                    "--assignment-id",
                    selector["assignment_id"].as_str().unwrap(),
                ]);
            }
            let available = capture["available"] == true;
            terminal(command.output().unwrap(), if available { 0 } else { 2 });
            if available {
                assert_eq!(
                    fs::read(destination).unwrap(),
                    files[capture["member"].as_str().unwrap()]
                );
            } else {
                assert!(!destination.exists());
            }
        }
        for request in ["second-audit", "blocked-audit"] {
            let status = run.f.audit_status(request, false, 0);
            assert_eq!(status["result"]["restored"], true);
            if request == "blocked-audit" {
                assert!(status["result"]["next_operation"].is_null());
            } else {
                assert_eq!(status["result"]["next_operation"]["available"], false);
                assert_eq!(
                    status["result"]["next_operation"]["sealing"]["available"],
                    false
                );
            }
            assert!(status["result"].get("source_snapshot_notice").is_none());
        }
        assert_eq!(before, super::captured::logical_database(&run.f));
    }
}

// Validate every keyword used by the checked-in schema, independently of Rust DTOs.
fn validate_history_schema(value: &Value) {
    fn accepts(v: &Value, s: &Value, root: &Value) -> bool {
        if let Some(reference) = s["$ref"].as_str() {
            return accepts(
                v,
                root.pointer(reference.trim_start_matches('#')).unwrap(),
                root,
            );
        }
        for key in ["oneOf", "anyOf"] {
            if let Some(branches) = s[key].as_array() {
                let count = branches.iter().filter(|s| accepts(v, s, root)).count();
                return if key == "oneOf" {
                    count == 1
                } else {
                    count > 0
                };
            }
        }
        if s.get("const").is_some_and(|c| c != v)
            || s["enum"].as_array().is_some_and(|a| !a.contains(v))
        {
            return false;
        }
        match s["type"].as_str() {
            Some("object") => v.as_object().is_some_and(|o| {
                s["required"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|k| o.contains_key(k.as_str().unwrap()))
                    && o.iter()
                        .all(|(k, v)| s["properties"].get(k).is_some_and(|s| accepts(v, s, root)))
            }),
            Some("array") => v
                .as_array()
                .is_some_and(|a| a.iter().all(|v| accepts(v, &s["items"], root))),
            Some("string") => v.as_str().is_some_and(|v| {
                v.len() as u64 >= s["minLength"].as_u64().unwrap_or(0)
                    && (s.get("pattern").is_none() || {
                        assert_eq!(s["pattern"], "^[a-f0-9]{64}$");
                        v.len() == 64
                            && v.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
            }),
            Some("integer") => v
                .as_u64()
                .is_some_and(|v| v >= s["minimum"].as_u64().unwrap_or(0)),
            Some("boolean") => v.is_boolean(),
            Some("null") => v.is_null(),
            None => true,
            _ => panic!("unsupported schema keyword"),
        }
    }
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/provider-archive-history.schema.json"
    ))
    .unwrap();
    assert!(accepts(value, &schema, &schema));
    let mut invalid = value.clone();
    invalid["unexpected"] = true.into();
    assert!(!accepts(&invalid, &schema, &schema));
}

// The previous reader denied unknown fields; it must reject the new manifest.
#[allow(dead_code)]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyManifest {
    schema_version: Value,
    archive_id: Value,
    created_at: Value,
    producer_version: Value,
    case_id: Value,
    source_case_revision: Value,
    case_document_sha256: Value,
    raw_artifacts_included: Value,
    source_snapshots_included: Value,
    omissions: Value,
    entries: Value,
}

#[test]
fn admitted_and_terminated_archive_custody_capability_and_exact_inventory() {
    use super::termination;
    let (mut run, admission) = admit::sealed("quick");
    admit::admit(&run, &admission, 0);
    let host = run.f.data.with_file_name("second-host");
    fs::create_dir(&host).unwrap();
    let prep = json!({"schema_version":"ai-security-scanner.cloudflare-audit-prepare-request/v1",
        "request_id":"second-audit","case_id":run.f.case_id,"asset_id":run.f.asset_id,
        "source_view_request_id":"view-request","expected_source_view_receipt_sha256":facts(&run.prepared)["source"]["source_view_receipt_sha256"],
        "profile":"quick","invocation_budget":null,"host":{"host_id":"declared-test-host","delegation":"available"},"run_directory":host});
    let prepared = run.f.audit(&prep, 0);
    fs::write(host.join("REPORT.md"), b"retained draft").unwrap();
    let captured = run.f.checkpoint(
        &run.f.checkpoint_request(
            &prepared,
            json!({"type":"submit_documents","documents":[{"name":"REPORT.md"}]}),
        ),
        0,
    );
    let end = termination::request(
        &run.f,
        &prepared,
        &captured["result"]["record_head"]["entry_sha256"],
        "required_artifacts_unavailable",
    );
    let saved = termination::terminate(&run.f, &end, 0);
    let path = run.f.data.with_file_name("terminated.tar.gz");
    case_archive::create_archive(
        &run.f.data,
        &run.f.case_id,
        &path,
        &ArchiveOptions::default(),
    )
    .unwrap();
    let files = unpack(&path);
    let history = document(&files, "provider-history.json");
    validate_history_schema(&history);
    let p = history["preparations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["preparation_request_id"] == "second-audit")
        .unwrap();
    assert_eq!(p["state"], "unsealed");
    assert_eq!(
        p["termination"],
        json!({"entry_sha256":saved["result"]["entry"]["entry_sha256"],"occurred_at":saved["result"]["entry"]["occurred_at"],"reason":"required_artifacts_unavailable"})
    );
    assert_eq!(
        p["recorded_head"]["entry_sha256"],
        p["termination"]["entry_sha256"]
    );
    for field in ["seal_sha256", "admission_id", "admission_sha256"] {
        assert!(p[field].is_null());
    }
    assert_eq!(p["completeness"]["sealed_package"], false);
    assert_eq!(p["captured"].as_array().unwrap().len(), 1);
    assert_eq!(
        document(&files, "archive-manifest.json")["required_capabilities"],
        json!([
            "cloudflare_audit_admission/v1",
            "cloudflare_audit_terminal/v1",
            "provider_archive_history/v1"
        ])
    );
    assert!(
        case_archive::inspect_archive(&path)
            .unwrap()
            .integrity_valid
    );
    for kind in ["missing", "wrong", "extra", "null", "capability"] {
        let mut altered = files.clone();
        if kind == "capability" {
            let mut manifest = document(&altered, "archive-manifest.json");
            manifest["required_capabilities"]
                .as_array_mut()
                .unwrap()
                .retain(|c| c != "cloudflare_audit_terminal/v1");
            put(&mut altered, "archive-manifest.json", &manifest);
        } else {
            let mut history = history.clone();
            let p = history["preparations"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|p| p["preparation_request_id"] == "second-audit")
                .unwrap();
            match kind {
                "missing" => {
                    p.as_object_mut().unwrap().remove("termination");
                }
                "wrong" => p["termination"]["reason"] = json!("workflow_failed"),
                "null" => p["termination"] = Value::Null,
                _ => p["termination"]["prose"] = json!("invented"),
            }
            put(&mut altered, "provider-history.json", &history);
        }
        let bad = run.f.data.with_file_name(format!("bad-{kind}.tar.gz"));
        repack(&bad, altered);
        assert!(
            matches!(
                case_archive::inspect_archive(&bad),
                Err(ai_security_scanner_lib::error::AppError::ArchiveProvider {
                    code: "archive_history_mismatch",
                    ..
                })
            ),
            "{kind}"
        );
    }
    let destination = run.f.data.with_file_name("terminated-restored");
    case_archive::restore_archive(&path, &destination).unwrap();
    run.f.data = destination;
    assert_eq!(
        termination::terminate(&run.f, &end, 2)["error_code"],
        "restored_session_inert"
    );
    let status = run.f.audit_status("second-audit", false, 0);
    assert_eq!(
        status["result"]["terminated"]["reason"],
        "required_artifacts_unavailable"
    );
    assert!(status["result"]["next_operation"].is_null());
    let again = run.f.data.with_file_name("terminated-again.tar.gz");
    case_archive::create_archive(
        &run.f.data,
        &run.f.case_id,
        &again,
        &ArchiveOptions::default(),
    )
    .unwrap();
    assert_eq!(document(&unpack(&again), "provider-history.json"), history);
}
