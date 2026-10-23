// Included in case_service::tests to exercise the real save/preview/export path.

fn html_attachment_fixture() -> (Fixture, AssessmentCase, String) {
    let fixture = Fixture::new();
    let created = fixture.create();
    let (_, asset_id) = fixture.discovered_asset(&created.id, AssetKind::Repository);
    let service = fixture.service();
    service
        .approve_scope(
            &created.id,
            ScopeApprovalRequest {
                asset_id,
                permissions: vec![ScanPermission::LocalArtifactRead],
                confirmed_by: "Fixture owner".into(),
                expires_at: None,
                authorization_reference: None,
                notes: None,
                external_scope: None,
            },
        )
        .unwrap();
    let plan = service
        .plan_scan(
            &created.id,
            ScanPlanRequest {
                campaign_id: None,
                engine_ids: vec!["gitleaks".into()],
                engine_asset_routes: Vec::new(),
            },
        )
        .unwrap();
    let run_id = plan.scan_run.id;
    let mut case = service.show_case(&created.id).unwrap();
    let now = Utc::now();
    case.status = CaseStatus::NeedsAttention;
    let run = &mut case.scan_runs[0];
    run.completed_at = Some(now);
    let task = &mut run.engine_runs[0];
    task.status = EngineRunStatus::PartiallyCompleted;
    task.started_at = Some(now);
    task.finished_at = Some(now);
    let mut failed = task.clone();
    failed.id = "failed-task".into();
    failed.engine_id = "semgrep".into();
    failed.status = EngineRunStatus::Failed;
    run.engine_runs.push(failed);
    let mut other = run.clone();
    other.id = "other-run".into();
    other.sequence += 1;
    other.engine_runs.truncate(1);
    other.engine_runs[0].id = "other-task".into();
    other.engine_runs[0].scan_run_id = other.id.clone();
    case.scan_runs.push(other);
    let task_id = case.scan_runs[0].engine_runs[0].id.clone();
    for (id, selected_run, engine, path, bytes) in [
        (
            "report",
            run_id.as_str(),
            task_id.as_str(),
            "attempt-1/output/upstream/report.html",
            b"<!doctype html><img src='images/logo.png'><script>TOP_SECRET_ORIGINAL();</script>"
                .as_slice(),
        ),
        (
            "image",
            run_id.as_str(),
            task_id.as_str(),
            "attempt-1/output/upstream/images/logo.png",
            b"\x89PNG\r\n\x1a\nfixture image".as_slice(),
        ),
        (
            "diagnostic",
            run_id.as_str(),
            "failed-task",
            "attempt-1/raw/stderr.log",
            b"Fixture check failed; preserved diagnostic".as_slice(),
        ),
        (
            "other",
            "other-run",
            "other-task",
            "attempt-1/output/other.json",
            b"OTHER_RUN_MUST_NOT_LEAK".as_slice(),
        ),
    ] {
        let relative_path = format!("{}/{selected_run}/{engine}/{path}", case.id);
        let source = fixture
            .directory
            .path()
            .join("artifacts")
            .join(&relative_path);
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(source, bytes).unwrap();
        case.raw_artifacts.push(RawArtifact {
            id: id.into(),
            case_id: case.id.clone(),
            run_id: selected_run.into(),
            engine_run_id: engine.into(),
            relative_path,
            media_type: "application/octet-stream".into(),
            sha256: sha256_bytes(bytes),
            byte_length: bytes.len() as u64,
            created_at: now,
            contains_sensitive_data: true,
        });
        case.scan_runs
            .iter_mut()
            .flat_map(|r| &mut r.engine_runs)
            .find(|task| task.id == engine)
            .unwrap()
            .raw_artifact_ids
            .push(id.into());
    }
    fixture
        .storage
        .save_case(&mut case, "test.attachment_fixture")
        .unwrap();
    (fixture, case, run_id)
}

fn html_attachment_options() -> ExportOptions {
    ExportOptions {
        redaction: RedactionProfile::None,
        include_raw_artifacts: true,
        locale: crate::export::ReportLocale::En,
    }
}

#[test]
fn html_attachments_round_trip_originals_and_only_the_selected_run() {
    use base64::Engine as _;
    use std::io::Read;
    let (fixture, case, run_id) = html_attachment_fixture();
    let service = fixture.service();
    for (locale, heading) in [
        (
            crate::export::ReportLocale::En,
            "Original report attachments",
        ),
        (crate::export::ReportLocale::ZhHant, "原始報告附件"),
    ] {
        let options = ExportOptions {
            locale,
            ..html_attachment_options()
        };
        let preview = service
            .preview_export(&case.id, &run_id, CaseExportFormat::Html, &options)
            .unwrap();
        assert_eq!(preview.raw_artifact_count, 3);
        assert_eq!(preview.raw_artifacts_included, 3);
        assert_eq!(preview.raw_artifacts_omitted, 0);
        let path = fixture
            .directory
            .path()
            .join(format!("report-{}.html", locale.as_str()));
        let exported = service
            .export_case(&case.id, &run_id, CaseExportFormat::Html, &path, options)
            .unwrap();
        assert_eq!(exported.raw_artifacts_included, Some(3));
        assert_eq!(exported.raw_artifacts_omitted, Some(0));
        assert!(
            service
                .verify_stored_export(&case.id, &exported.id)
                .unwrap()
                .valid
        );
        let html = fs::read_to_string(&path).unwrap();
        assert!(html.contains(heading));
        assert!(
            html.find("id=\"original-report-attachments\"").unwrap()
                < html.rfind("<footer>").unwrap()
        );
        assert!(html.contains("default-src 'none'"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("TOP_SECRET_ORIGINAL"));
        assert!(!html.contains("OTHER_RUN_MUST_NOT_LEAK"));
        let archives = html
            .split("href=\"data:application/zip;base64,")
            .skip(1)
            .map(|part| {
                base64::engine::general_purpose::STANDARD
                    .decode(part.split('"').next().unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(archives.len(), 2);
        let mut originals_seen = 0;
        for bytes in archives {
            let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
            let manifest: serde_json::Value =
                serde_json::from_reader(archive.by_name("manifest.json").unwrap()).unwrap();
            assert_eq!(manifest["run_id"], run_id);
            assert!(matches!(
                manifest["status"].as_str().unwrap(),
                "failed" | "partially_completed"
            ));
            for entry in manifest["files"].as_array().unwrap() {
                let original = case
                    .raw_artifacts
                    .iter()
                    .find(|a| a.id == entry["artifact_id"].as_str().unwrap())
                    .unwrap();
                assert_eq!(original.run_id, run_id);
                let mut recovered = Vec::new();
                archive
                    .by_name(entry["path"].as_str().unwrap())
                    .unwrap()
                    .read_to_end(&mut recovered)
                    .unwrap();
                let source = fs::read(
                    fixture
                        .directory
                        .path()
                        .join("artifacts")
                        .join(&original.relative_path),
                )
                .unwrap();
                assert_eq!(recovered, source);
                assert_eq!(sha256_bytes(&recovered), original.sha256);
                originals_seen += 1;
            }
        }
        assert_eq!(originals_seen, 3);
        assert!(
            service
                .export_case(
                    &case.id,
                    &run_id,
                    CaseExportFormat::Html,
                    &path,
                    html_attachment_options()
                )
                .is_err()
        );
    }
}

#[test]
fn html_attachments_obey_redaction_and_opt_out_without_reading_originals() {
    let (fixture, case, run_id) = html_attachment_fixture();
    for artifact in &case.raw_artifacts {
        fs::remove_file(
            fixture
                .directory
                .path()
                .join("artifacts")
                .join(&artifact.relative_path),
        )
        .unwrap();
    }
    for (name, options) in [
        (
            "standard",
            ExportOptions {
                redaction: RedactionProfile::Standard,
                ..html_attachment_options()
            },
        ),
        (
            "opt-out",
            ExportOptions {
                include_raw_artifacts: false,
                ..html_attachment_options()
            },
        ),
    ] {
        let preview = fixture
            .service()
            .preview_export(&case.id, &run_id, CaseExportFormat::Html, &options)
            .unwrap();
        assert_eq!(preview.raw_artifacts_included, 0);
        assert_eq!(preview.raw_artifacts_omitted, 3);
        let path = fixture.directory.path().join(format!("{name}.html"));
        let exported = fixture
            .service()
            .export_case(&case.id, &run_id, CaseExportFormat::Html, &path, options)
            .unwrap();
        assert_eq!(exported.raw_artifacts_included, Some(0));
        assert!(
            !fs::read_to_string(path)
                .unwrap()
                .contains("data:application/zip")
        );
    }
}

#[test]
fn html_attachments_reject_unverified_or_oversized_sources_without_an_export() {
    for problem in [
        "missing",
        "tampered",
        "same-length-tampered",
        "traversal",
        "other-task",
        "oversized",
        "duplicate",
        "reserved",
        "directory-collision",
    ] {
        let (fixture, mut case, run_id) = html_attachment_fixture();
        let root = fixture.directory.path().join("artifacts");
        let path = root.join(&case.raw_artifacts[0].relative_path);
        match problem {
            "missing" => fs::remove_file(path).unwrap(),
            "tampered" => fs::write(path, b"changed after capture").unwrap(),
            "same-length-tampered" => {
                let mut bytes = fs::read(&path).unwrap();
                bytes[0] ^= 1;
                fs::write(path, bytes).unwrap();
            }
            "traversal" => case.raw_artifacts[0].relative_path = "../outside.html".into(),
            "other-task" => case.raw_artifacts[0].engine_run_id = "other-task".into(),
            "oversized" => case.raw_artifacts[0].byte_length = 64 * 1024 * 1024 + 1,
            "duplicate" => {
                case.raw_artifacts[1].relative_path = case.raw_artifacts[0]
                    .relative_path
                    .replace("report.html", "REPORT.HTML")
            }
            "reserved" => case.raw_artifacts[0].relative_path.push_str("/CON.txt"),
            "directory-collision" => {
                case.raw_artifacts[1].relative_path =
                    format!("{}/child.png", case.raw_artifacts[0].relative_path)
            }
            _ => unreachable!(),
        }
        fixture
            .storage
            .save_case(&mut case, "test.invalid_attachment")
            .unwrap();
        let destination = fixture.directory.path().join("must-not-exist.html");
        assert!(
            fixture
                .service()
                .export_case(
                    &case.id,
                    &run_id,
                    CaseExportFormat::Html,
                    &destination,
                    html_attachment_options()
                )
                .is_err(),
            "{problem}"
        );
        assert!(!destination.exists(), "{problem}");
        assert!(
            fixture
                .service()
                .show_case(&case.id)
                .unwrap()
                .exports
                .is_empty()
        );
    }
}

#[test]
fn html_attachments_reject_active_runs_and_formats_without_attachments() {
    let (fixture, mut case, run_id) = html_attachment_fixture();
    let destination = fixture.directory.path().join("must-not-exist.html");
    assert!(
        fixture
            .service()
            .export_document(
                &case.id,
                &run_id,
                CaseExportFormat::CanonicalJson,
                &destination,
                html_attachment_options()
            )
            .is_err()
    );
    case.scan_runs[0].completed_at = None;
    case.scan_runs[0].engine_runs[0].status = EngineRunStatus::Running;
    case.scan_runs[0].engine_runs[0].finished_at = None;
    fixture
        .storage
        .save_case(&mut case, "test.active_attachment")
        .unwrap();
    assert!(
        fixture
            .service()
            .preview_export(
                &case.id,
                &run_id,
                CaseExportFormat::Html,
                &html_attachment_options()
            )
            .is_err()
    );
    assert!(
        fixture
            .service()
            .export_case(
                &case.id,
                &run_id,
                CaseExportFormat::Html,
                &destination,
                html_attachment_options()
            )
            .is_err()
    );
    assert!(!destination.exists());
}

#[cfg(unix)]
#[test]
fn html_attachments_reject_symlink_sources() {
    let (fixture, case, run_id) = html_attachment_fixture();
    let original = fixture
        .directory
        .path()
        .join("artifacts")
        .join(&case.raw_artifacts[0].relative_path);
    let moved = fixture.directory.path().join("outside.html");
    fs::rename(&original, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &original).unwrap();
    let destination = fixture.directory.path().join("must-not-exist.html");
    assert!(
        fixture
            .service()
            .export_case(
                &case.id,
                &run_id,
                CaseExportFormat::Html,
                &destination,
                html_attachment_options()
            )
            .is_err()
    );
    assert!(!destination.exists());
}
