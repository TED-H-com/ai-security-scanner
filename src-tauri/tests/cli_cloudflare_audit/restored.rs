use super::{admit, fixture::*};
use ai_security_scanner_lib::case_archive::{self, ArchiveOptions};

fn inert(value: Value) {
    assert_eq!(value["error_code"], "restored_session_inert");
    assert_eq!(value["retryable"], false);
    assert_eq!(
        value["error"],
        "This audit was restored from an archive and is read-only history. Start a new audit with current authorization."
    );
}
fn request(f: &Fixture, operation: &str, value: &Value) -> Value {
    let path = f.data.with_file_name("inert-request.json");
    fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    terminal(
        f.command()
            .args(["provider", "cloudflare", operation, "--request"])
            .arg(path)
            .output()
            .unwrap(),
        2,
    )
}
fn guards(f: &Fixture, prepare: &Value, saved: &Value, admission: Option<&Value>) {
    let host = Path::new(prepare["run_directory"].as_str().unwrap());
    let host_existed = host.exists();
    let provider_root = f.audit_root();
    let provider_before = tree_hashes(&provider_root);
    let before_db = super::captured::logical_database(f);
    let before = f.storage().snapshot_case_for_archive(&f.case_id).unwrap();
    inert(f.audit(prepare, 2));
    inert(terminal(
        f.prepare_command("view-request", ".").output().unwrap(),
        2,
    ));
    for action in [
        json!({"type":"issue","assignments":[]}),
        json!({"type":"interrupt","assignment_id":"old","reason":"stopped"}),
        json!({"type":"submit_documents","documents":[]}),
        json!({"type":"submit_output","assignment_id":"old","output":{"path":"missing.txt"}}),
    ] {
        inert(f.checkpoint(&f.checkpoint_request(saved, action), 2));
    }
    let validation = json!({
        "schema_version":"ai-security-scanner.cloudflare-audit-validate-request/v1",
        "case_id":f.case_id,"session_id":saved["session_id"]
    });
    inert(request(f, "validate", &validation));
    inert(request(
        f,
        "finalize",
        &json!({
            "schema_version":"ai-security-scanner.cloudflare-audit-finalize-request/v1",
            "request_id":"seal-one", "case_id":f.case_id,"session_id":saved["session_id"],
            "expected_head_sha256":"0".repeat(64),"expected_bundle_sha256":"0".repeat(64)
        }),
    ));
    let fresh = json!({
        "schema_version":"ai-security-scanner.cloudflare-audit-admit-request/v1",
        "request_id":"admit-new", "case_id":f.case_id,"session_id":saved["session_id"],
        "expected_sealed_entry_sha256":"0".repeat(64),"expected_bundle_sha256":"0".repeat(64),
        "expected_projection_sha256":"0".repeat(64)
    });
    inert(request(f, "admit", &fresh));
    if let Some(admission) = admission {
        inert(request(f, "admit", admission));
    }
    let mut replayed = std::collections::BTreeSet::new();
    for event in &before.events {
        if event.event_type != "cloudflare_audit.record_entry" {
            continue;
        }
        let entry: Value = serde_json::from_str(&event.payload_json).unwrap();
        let content = &entry["content"];
        let kind = content["type"].as_str().unwrap();
        if !replayed.insert(kind.to_owned()) {
            continue;
        }
        let mut r = json!({"schema_version":"ai-security-scanner.cloudflare-audit-checkpoint-request/v1", "case_id":entry["case_id"],"session_id":entry["session_id"],"request_id":entry["request_id"],"expected_head_sha256":entry["predecessor_sha256"]});
        if kind == "sealed" {
            r["schema_version"] = json!("ai-security-scanner.cloudflare-audit-finalize-request/v1");
            r["expected_bundle_sha256"] = content["seal"]["bundle_sha256"].clone();
            inert(request(f, "finalize", &r));
        } else {
            r["action"] = match kind {
                "issue" => {
                    json!({"type":kind,"assignments":content["assignments"].as_array().unwrap().iter().map(|a| a["spec"].clone()).collect::<Vec<_>>()})
                }
                "submit_output" => {
                    json!({"type":kind,"assignment_id":content["assignment_id"],"output":content["requested_output"]})
                }
                "submit_documents" => {
                    json!({"type":kind,"documents":content["requested_documents"]})
                }
                _ => content.clone(),
            };
            inert(f.checkpoint(&r, 2));
        }
    }
    // Exercise the library entry directly, without CLI routing or preflight.
    {
        let storage = f.storage();
        let lease = DataDirectoryExclusiveLease::acquire(&f.data).unwrap();
        let context = ai_security_scanner_lib::cloudflare_provider::source_view::OwnedContext {
            storage: &storage,
            data_dir: &f.data,
            lease: &lease,
            cancelled: None,
        };
        let mut validation = validation.clone();
        validation["schema_version"] = json!("invalid");
        assert!(matches!(
            ai_security_scanner_lib::cloudflare_provider::audit::validation::validate(
                &context,
                &serde_json::from_value(validation).unwrap()
            ),
            Err(ai_security_scanner_lib::error::AppError::RestoredSessionInert)
        ));
        let request = serde_json::from_value(prepare.clone()).unwrap();
        assert!(matches!(
            ai_security_scanner_lib::cloudflare_provider::audit::prepare(&context, &request),
            Err(ai_security_scanner_lib::error::AppError::RestoredSessionInert)
        ));
    }
    let after = f.storage().snapshot_case_for_archive(&f.case_id).unwrap();
    assert_eq!(before.document_json, after.document_json);
    assert_eq!(before.revision, after.revision);
    assert_eq!(before.events, after.events);
    assert_eq!(before_db, super::captured::logical_database(f));
    assert_eq!(provider_before, tree_hashes(&provider_root));
    assert_eq!(host.exists(), host_existed);
    if host_existed {
        assert_eq!(
            fs::read(host.join("sentinel")).unwrap(),
            b"preserve existing host"
        );
    }
    assert!(
        !f.data
            .join("artifacts")
            .join(&f.case_id)
            .join("source-views")
            .exists()
    );
}

#[test]
fn legacy_restored_preparations_refuse_every_write_even_with_fresh_grant() {
    let (mut f, prepare) = Fixture::setup(true);
    let saved = f.audit(&prepare, 0);
    assert_eq!(
        f.storage()
            .latest_case_restore_sequence(&f.case_id)
            .unwrap(),
        None
    );
    let archive = f.data.with_file_name("legacy.tar.gz");
    case_archive::create_archive(
        &f.data,
        &f.case_id,
        &archive,
        &ArchiveOptions {
            include_source_snapshots: true,
            ..Default::default()
        },
    )
    .unwrap();
    let destination = f.data.with_file_name("restored");
    let preview = case_archive::preview_restore(&archive, &destination).unwrap();
    assert_eq!(preview.disabled_on_restore.len(), 5);
    remove(&f.data);
    fs::remove_dir_all(prepare["run_directory"].as_str().unwrap()).unwrap();
    let receipt = case_archive::restore_archive(&archive, &destination).unwrap();
    assert_eq!(receipt.transformations, preview.disabled_on_restore);
    f.data = destination;
    guards(&f, &prepare, &saved, None);
    let events = f.storage().list_case_events(&f.case_id).unwrap();
    assert_eq!(
        f.storage()
            .latest_case_restore_sequence(&f.case_id)
            .unwrap(),
        Some(events.last().unwrap().sequence)
    );
    let payload: Value = serde_json::from_str(&events.last().unwrap().payload_json).unwrap();
    assert_eq!(payload.as_object().unwrap().len(), 4);
    f.change_case(|case| {
        case.assets[0].owner_confirmed = true;
        case.scope_grants.push(ScopeGrant {
            id: "fresh".into(),
            asset_id: f.asset_id.clone(),
            permission: ScanPermission::LocalArtifactRead,
            confirmed_by: "test-owner".into(),
            confirmed_at: Utc::now(),
            expires_at: None,
            authorization_reference: None,
            notes: None,
            external_scope: None,
        });
    });
    guards(&f, &prepare, &saved, None);
    let host = Path::new(prepare["run_directory"].as_str().unwrap());
    fs::create_dir(host).unwrap();
    fs::write(host.join("sentinel"), b"preserve existing host").unwrap();
    guards(&f, &prepare, &saved, None);
    remove(host);
    let mut fresh = prepare;
    fresh["request_id"] = json!("new-audit");
    let value = f.audit(&fresh, 2); // Missing old run directory, not the inert rule.
    assert_ne!(value["error_code"], "restored_session_inert");
    assert!(!f.audit_root().exists());
}

#[test]
fn admitted_restored_packages_preserve_identities_and_inert_history() {
    for sources in [true, false] {
        let (mut run, admission) = admit::sealed("standard");
        admit::admit(&run, &admission, 0);
        let original = admit::case(&run);
        let ungated = Storage::open(run.f.data.with_file_name("ungated.db")).unwrap();
        assert!(
            ungated
                .import_archived_case(&mut original.clone(), &[], "unverified")
                .is_err()
        );
        assert!(ungated.list_case_events(&original.id).unwrap().is_empty());
        let before_read = read_outputs(&run, &original, "before");
        let prepare: Value =
            serde_json::from_slice(&fs::read(run.f.data.with_file_name("request.json")).unwrap())
                .unwrap();
        let archive = run.f.data.with_file_name("provider.tar.gz");
        case_archive::create_archive(
            &run.f.data,
            &run.f.case_id,
            &archive,
            &ArchiveOptions {
                include_source_snapshots: sources,
                ..Default::default()
            },
        )
        .unwrap();
        let destination = run.f.data.with_file_name("restored");
        let preview = case_archive::preview_restore(&archive, &destination).unwrap();
        assert!(preview.archive.case_data_restore_available);
        assert_eq!(preview.disabled_on_restore.len(), 6);
        assert_eq!(
            preview.disabled_on_restore[5],
            "restored source audits kept as read-only history"
        );
        remove(&run.f.data);
        fs::remove_dir_all(&run.host).unwrap();
        let receipt = case_archive::restore_archive(&archive, &destination).unwrap();
        assert_eq!(receipt.transformations, preview.disabled_on_restore);
        assert_eq!(
            case_archive::restore_archive(&archive, &destination)
                .unwrap()
                .workspace_id,
            receipt.workspace_id
        );
        run.f.data = destination;
        let restored = admit::case(&run);
        assert_eq!(
            serde_json::to_value(&original.agent_audit_admissions).unwrap(),
            serde_json::to_value(&restored.agent_audit_admissions).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&original.findings).unwrap(),
            serde_json::to_value(&restored.findings).unwrap()
        );
        for raw in &original.raw_artifacts {
            assert_eq!(
                hex::encode(sha2::Sha256::digest(
                    fs::read(run.f.data.join("artifacts").join(&raw.relative_path)).unwrap()
                )),
                raw.sha256
            );
        }
        assert_eq!(before_read, read_outputs(&run, &restored, "after"));
        guards(&run.f, &prepare, &run.prepared, Some(&admission));
        let status = admit::status(&run);
        assert_eq!(status["restored"], true);
        assert_eq!(status["next_operation"], "retrieve_report");
        assert_eq!(
            status["sealed_verification_scope"],
            if sources {
                "full_payload"
            } else {
                "included_payload"
            }
        );
        assert_eq!(status.get("source_snapshot_notice").is_some(), !sources);
        let out = terminal(
            run.f
                .command()
                .args([
                    "provider",
                    "cloudflare",
                    "inspect-sealed",
                    "--case-id",
                    &run.f.case_id,
                    "--session-id",
                    run.prepared["session_id"].as_str().unwrap(),
                ])
                .output()
                .unwrap(),
            0,
        );
        assert_eq!(out["result"]["restored"], true);
        assert_eq!(
            out["result"]["verification"]["scope"],
            if sources {
                "full_payload"
            } else {
                "included_payload"
            }
        );
        let package = PathBuf::from(status["package_path"].as_str().unwrap()).join("retained");
        if !sources {
            use ai_security_scanner_lib::cloudflare_provider::retained;
            assert!(retained::inspect_retained(&package, None).is_err());
            let destination = run.f.data.with_file_name("retained-refused.md");
            assert!(
                retained::retrieve_retained(
                    &package,
                    &restored.agent_audit_admissions[0].digests.retention_sha256,
                    "bundle/REPORT.md",
                    &destination
                )
                .is_err()
            );
            assert!(!destination.exists());
        }
        let rearchive = run.f.data.with_file_name("rearchive.tar.gz");
        case_archive::create_archive(
            &run.f.data,
            &run.f.case_id,
            &rearchive,
            &ArchiveOptions {
                include_source_snapshots: true,
                ..Default::default()
            },
        )
        .unwrap();
        let first_files = super::archives::unpack(&archive);
        let next_files = super::archives::unpack(&rearchive);
        for (name, bytes) in first_files
            .iter()
            .filter(|(name, _)| name.contains("/sealed/"))
        {
            assert_eq!(next_files.get(name), Some(bytes), "{name}");
        }
        let checked = case_archive::inspect_archive(&rearchive).unwrap();
        assert_eq!(
            checked
                .omissions
                .iter()
                .filter(|s| s.starts_with("Source snapshots inside source-audit packages"))
                .count(),
            usize::from(!sources)
        );
        const INHERITED: &str = "Source snapshots that were not included in the archive this case was restored from are still missing; this archive does not preserve the full assessed source tree.";
        assert_eq!(
            checked
                .omissions
                .iter()
                .filter(|s| s.as_str() == INHERITED)
                .count(),
            usize::from(!sources)
        );
        for copies in if sources { vec![1] } else { vec![0, 2] } {
            let mut files = next_files.clone();
            let mut manifest: Value =
                serde_json::from_slice(&files["archive-manifest.json"]).unwrap();
            let omissions = manifest["omissions"].as_array_mut().unwrap();
            omissions.retain(|s| s != INHERITED);
            omissions.extend((0..copies).map(|_| json!(INHERITED)));
            files.insert(
                "archive-manifest.json".into(),
                serde_json::to_vec(&manifest).unwrap(),
            );
            let bad = run.f.data.with_file_name("bad-omission.tar.gz");
            super::archives::repack(&bad, files);
            super::archives::rejected(&run, &bad, "archive_omission_mismatch");
        }
        let again = run.f.data.with_file_name("restored-again");
        case_archive::restore_archive(&rearchive, &again).unwrap();
        run.f.data = again;
        guards(&run.f, &prepare, &run.prepared, Some(&admission));
        assert_eq!(
            admit::status(&run)["sealed_verification_scope"],
            if sources {
                "full_payload"
            } else {
                "included_payload"
            }
        );
        let newest = admit::case(&run);
        let snapshot = &newest.run_report_snapshots[0].snapshot;
        let snapshot_path = run.f.data.join("artifacts").join(&snapshot.relative_path);
        let snapshot_bytes = fs::read(&snapshot_path).unwrap();
        fs::remove_file(&snapshot_path).unwrap();
        assert!(admit::status(&run)["next_operation"].is_null());
        fs::write(&snapshot_path, snapshot_bytes).unwrap();
        assert_eq!(admit::status(&run)["next_operation"], "retrieve_report");
        if sources {
            let package = PathBuf::from(admit::status(&run)["package_path"].as_str().unwrap())
                .join("retained");
            let index: Value =
                serde_json::from_slice(&fs::read(package.join("retention.json")).unwrap()).unwrap();
            let path = index["source_files"][0]["path"].as_str().unwrap();
            fs::remove_file(package.join(path)).unwrap();
        } else {
            let db = rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap();
            let events = run.f.storage().list_case_events(&run.f.case_id).unwrap();
            let e = events.last().unwrap();
            let mut payload: Value = serde_json::from_str(&e.payload_json).unwrap();
            payload["provider_history"]["source_bodies_omitted_sessions"] = json!([]);
            db.execute(
                "UPDATE case_events SET payload_json=?1 WHERE sequence=?2",
                rusqlite::params![payload.to_string(), e.sequence],
            )
            .unwrap();
        }
        // Unlisted history is strict: missing source bytes cannot become an omission.
        let storage = run.f.storage();
        let failure = ai_security_scanner_lib::cloudflare_provider::audit::sealed::verify(
            &run.f.data,
            &storage,
            &run.f.case_id,
            run.prepared["session_id"].as_str().unwrap(),
        )
        .err()
        .unwrap();
        let status = run.f.audit_status("audit-one", false, 0);
        assert_eq!(status["session_id"], run.prepared["session_id"]);
        assert_eq!(status["request_id"], "audit-one");
        assert_eq!(status["result"]["sealed_state"], "mismatch");
        assert_eq!(
            status["result"]["sealed_failed_check"],
            failure.failed_check
        );
        assert_eq!(
            status["result"]["sealed_verification_scope"],
            "committed_files"
        );
        assert!(status["result"]["next_operation"].is_null());
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
                    run.prepared["session_id"].as_str().unwrap(),
                ])
                .output()
                .unwrap(),
            2,
        );
        assert_eq!(inspected["failed_check"], failure.failed_check);
    }
}
use sha2::Digest;

pub(super) fn remove(path: &Path) {
    writable(path);
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            remove(&entry.unwrap().path());
        }
        fs::remove_dir(path).unwrap();
    } else {
        fs::remove_file(path).unwrap();
    }
}

fn read_outputs(run: &RunFixture, case: &AssessmentCase, label: &str) -> Value {
    use ai_security_scanner_lib::{
        export::{self, ExportOptions, RedactionProfile},
        report_snapshot::{ReportDocumentFormat, ReportSnapshot},
    };
    let id = &case.agent_audit_admissions[0].identities.run_id;
    let options = ExportOptions {
        redaction: RedactionProfile::None,
        include_raw_artifacts: true,
        ..Default::default()
    };
    let root = run.f.data.join("artifacts");
    let snapshot = ReportSnapshot::capture(case, id, options.clone(), &root).unwrap();
    let html = run.f.data.with_file_name(format!("{label}.html"));
    snapshot
        .retrieve(ReportDocumentFormat::Html, &html)
        .unwrap();
    let html = fs::read_to_string(html).unwrap();
    let encoded = html
        .split("data:application/zip;base64,")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    use base64::Engine;
    let zip = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(zip)).unwrap();
    let mut originals = std::collections::BTreeMap::new();
    use std::io::Read;
    for i in 0..zip.len() {
        let mut file = zip.by_index(i).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        originals.insert(
            file.name().unwrap().into_owned(),
            hex::encode(sha2::Sha256::digest(bytes)),
        );
    }
    let bundle = run.f.data.with_file_name(format!("{label}.case.tar.gz"));
    export::create_case_bundle_at(
        case,
        id,
        &root,
        &bundle,
        run.f.data.join("key"),
        options.clone(),
        case.updated_at,
    )
    .unwrap();
    export::verify_case_bundle(&bundle).unwrap();
    let storage = run.f.storage();
    let engines = ai_security_scanner_lib::registry::EngineRegistry::empty();
    let adapters = ai_security_scanner_lib::adapter::AdapterRegistry::default();
    let service = ai_security_scanner_lib::case_service::CaseService::new(
        &storage,
        &engines,
        &adapters,
        &root,
        run.f.data.join("key"),
    );
    let export = run.f.data.with_file_name(format!("{label}.ocsf.json"));
    service
        .export_case(
            &case.id,
            id,
            ai_security_scanner_lib::case_service::CaseExportFormat::OcsfJson,
            &export,
            ExportOptions {
                include_raw_artifacts: false,
                ..options.clone()
            },
        )
        .unwrap();
    let shown = run
        .f
        .command()
        .args(["case", "show", &case.id])
        .output()
        .unwrap();
    assert!(shown.status.success());
    json!({"originals":originals,
        "report":serde_json::from_slice::<Value>(&ai_security_scanner_lib::report_renderer::render_canonical_json(case,id,&options).unwrap()).unwrap()["report"]["source_audits"],
        "export":serde_json::from_slice::<Value>(&ai_security_scanner_lib::exporters::export_ocsf_finding_events_bytes(case,id).unwrap()).unwrap()})
}

fn tree_hashes(root: &Path) -> std::collections::BTreeMap<PathBuf, String> {
    let mut files = std::collections::BTreeMap::new();
    if !root.exists() {
        return files;
    }
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(tree_hashes(&path));
        } else {
            files.insert(
                path.clone(),
                hex::encode(sha2::Sha256::digest(fs::read(path).unwrap())),
            );
        }
    }
    files
}
