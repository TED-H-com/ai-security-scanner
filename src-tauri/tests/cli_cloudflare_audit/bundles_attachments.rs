use super::{admit, exports, fixture::*};
use ai_security_scanner_lib::export::{self, ExportOptions, RedactionProfile};
use std::{collections::BTreeMap, io::Read};

fn members(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut archive =
        tar::Archive::new(flate2::read::GzDecoder::new(fs::File::open(path).unwrap()));
    archive
        .entries()
        .unwrap()
        .map(|entry| {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_str().unwrap().to_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            (name, bytes)
        })
        .collect()
}
fn document(files: &BTreeMap<String, Vec<u8>>, name: &str) -> Value {
    serde_json::from_slice(&files[name]).unwrap()
}

#[test]
fn bundle_admission_document_and_framework_share_the_chosen_profile() {
    let (run, request) = exports::sealed_export_fixture("standard");
    let saved = admit::admit(&run, &request, 0);
    let run_id = saved["run_id"].as_str().unwrap();
    let case = admit::case(&run);
    let native = &case.agent_audit_admissions[0].retained_projection;
    for (profile, raw) in [
        (RedactionProfile::Standard, false),
        (RedactionProfile::Standard, true),
        (RedactionProfile::None, false),
        (RedactionProfile::None, true),
    ] {
        let path = run
            .f
            .data
            .with_file_name(format!("{}-{raw}.case.tar.gz", profile.as_str()));
        export::create_case_bundle_at(
            &case,
            run_id,
            run.f.data.join("artifacts"),
            &path,
            run.f.data.join("key"),
            ExportOptions {
                redaction: profile,
                include_raw_artifacts: raw,
                ..Default::default()
            },
            case.updated_at,
        )
        .unwrap();
        let verified = export::verify_case_bundle(&path).unwrap();
        assert_eq!(verified.manifest.schemas["source_audit_admissions"], "1");
        let files = members(&path);
        let records = document(&files, "raw-artifacts.json");
        for artifact in &case.raw_artifacts {
            let record = records["raw_artifacts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == artifact.id)
                .unwrap();
            assert_eq!(record["included"], raw && profile == RedactionProfile::None);
            if record["included"] == true {
                let path = record["archive_path"].as_str().unwrap();
                let binding = case.agent_audit_admissions[0]
                    .artifacts
                    .iter()
                    .find(|b| b.artifact_id == artifact.id)
                    .unwrap();
                assert!(path.ends_with(&binding.member_path));
                assert_eq!(
                    files[path],
                    fs::read(run.f.data.join("artifacts").join(&artifact.relative_path)).unwrap()
                );
            }
        }
        let admissions = document(&files, "source-audit-admissions.json");
        assert_eq!(
            admissions["admissions"][0]["admission_sha256"],
            case.agent_audit_admissions[0].admission_sha256
        );
        assert_eq!(
            admissions["provider_tasks"][0]["method"],
            "Cloudflare source audit"
        );
        assert!(
            admissions["digest_scope"]
                .as_str()
                .unwrap()
                .contains("original material")
        );
        assert!(
            document(&files, "built-in-tasks.json")["built_in_tasks"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            document(&files, "engine-versions.json")["catalog_engine_runs"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let shared = document(&files, "exports/beginner-master-report.json");
        let framework = document(&files, "exports/master-framework-report.json");
        assert_eq!(
            framework["source_audits"],
            shared["report"]["source_audits"]
        );
        let text = admissions.to_string();
        assert_eq!(
            text.contains("PRIVATE-EXPORT-CODE"),
            profile == RedactionProfile::None
        );
        if profile == RedactionProfile::Standard {
            assert!(!text.contains("src/private-fix.rs"));
            for value in [
                native["records"][0]["native_record"]["description"].as_str(),
                native["records"][0]["fingerprint"].as_str(),
                native["records"][0]["coverage_ids"][0].as_str(),
            ]
            .into_iter()
            .flatten()
            {
                assert!(!value.is_empty());
                assert!(!text.contains(value), "provider value leaked: {value}");
            }
            assert!(text.contains("unit-") && text.contains("fp-"));
            assert!(
                admissions["admissions"][0]["retained_projection"]["withheld_code_fields"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
            assert!(
                framework["source_audits"][0]["withheld_code_fields"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
            assert!(
                framework["source_audits"][0]["withheld_text_fields"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
        }
    }
}

fn options(profile: RedactionProfile) -> ExportOptions {
    ExportOptions {
        redaction: profile,
        include_raw_artifacts: true,
        ..Default::default()
    }
}

#[test]
fn originals_zip_provenance_digests_and_offline_replay_preserve_exact_nested_bytes() {
    use ai_security_scanner_lib::report_snapshot::{ReportDocumentFormat, ReportSnapshot};
    use base64::Engine;
    use sha2::Digest;
    let (run, request) = exports::sealed_export_fixture("standard");
    let saved = admit::admit(&run, &request, 0);
    let run_id = saved["run_id"].as_str().unwrap();
    let case = admit::case(&run);
    let root = run.f.data.join("artifacts");
    let snapshot =
        ReportSnapshot::capture(&case, run_id, options(RedactionProfile::None), &root).unwrap();
    let output = run.f.data.with_file_name("original.html");
    snapshot
        .retrieve(ReportDocumentFormat::Html, &output)
        .unwrap();
    let html = fs::read_to_string(&output).unwrap();
    assert!(html.contains("Cloudflare source audit"));
    let encoded = html
        .split("data:application/zip;base64,")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    assert!(html.contains(&hex::encode(sha2::Sha256::digest(&bytes))));
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut manifest = String::new();
    zip.by_name("manifest.json")
        .unwrap()
        .read_to_string(&mut manifest)
        .unwrap();
    let manifest: Value = serde_json::from_str(&manifest).unwrap();
    let admission = &case.agent_audit_admissions[0];
    assert_eq!(
        manifest["source_audit"]["admission_id"],
        admission.admission_id
    );
    assert_eq!(
        manifest["source_audit"]["provider_id"],
        admission.provider_id
    );
    assert_eq!(
        manifest["source_audit"]["method"],
        "Cloudflare source audit"
    );
    assert_eq!(
        manifest["source_audit"]["original_digests"],
        json!(admission.digests)
    );
    let mut readme = String::new();
    zip.by_name("README.txt")
        .unwrap()
        .read_to_string(&mut readme)
        .unwrap();
    assert!(readme.contains("Cloudflare source audit"));
    for binding in &admission.artifacts {
        let mut bytes = Vec::new();
        let name = format!("files/{}", binding.member_path);
        zip.by_name(&name).unwrap().read_to_end(&mut bytes).unwrap();
        let artifact = case
            .raw_artifacts
            .iter()
            .find(|a| a.id == binding.artifact_id)
            .unwrap();
        assert_eq!(bytes, fs::read(root.join(&artifact.relative_path)).unwrap());
        assert_eq!(hex::encode(sha2::Sha256::digest(&bytes)), binding.sha256);
        let record = manifest["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["path"] == name)
            .unwrap();
        assert_eq!(record["sha256"], binding.sha256);
        assert_eq!(record["bytes"], bytes.len());
    }
    let artifact = &case.raw_artifacts[0];
    fs::write(
        root.join(&artifact.relative_path),
        vec![b'x'; artifact.byte_length as usize],
    )
    .unwrap();
    let refused = run.f.data.with_file_name("tampered-original.case.tar.gz");
    assert!(
        export::create_case_bundle_at(
            &case,
            run_id,
            &root,
            &refused,
            run.f.data.join("key"),
            options(RedactionProfile::None),
            case.updated_at
        )
        .is_err()
    );
    assert!(!refused.exists());
    assert!(
        ReportSnapshot::capture(&case, run_id, options(RedactionProfile::None), &root).is_err()
    );
    for artifact in &case.raw_artifacts {
        fs::remove_file(root.join(&artifact.relative_path)).unwrap();
    }
    let refused = run.f.data.with_file_name("missing-original.case.tar.gz");
    assert!(
        export::create_case_bundle_at(
            &case,
            run_id,
            &root,
            &refused,
            run.f.data.join("key"),
            options(RedactionProfile::None),
            case.updated_at
        )
        .is_err()
    );
    assert!(!refused.exists());
    assert!(
        ReportSnapshot::capture(&case, run_id, options(RedactionProfile::None), &root).is_err()
    );
    let standard =
        ReportSnapshot::capture(&case, run_id, options(RedactionProfile::Standard), &root).unwrap();
    assert_eq!(standard.verify().unwrap().attachment_count, 0);
    export::create_case_bundle_at(
        &case,
        run_id,
        &root,
        run.f.data.with_file_name("missing-standard.case.tar.gz"),
        run.f.data.join("key"),
        options(RedactionProfile::Standard),
        case.updated_at,
    )
    .unwrap();
    let replay = run.f.data.with_file_name("replay-original.html");
    snapshot
        .replay(ReportDocumentFormat::Html, &replay)
        .unwrap();
    assert_eq!(fs::read(replay).unwrap(), html.as_bytes());
}

pub(super) fn add_scanner(case: &mut AssessmentCase, root: &Path) -> String {
    use ai_security_scanner_lib::domain::EngineTaskKind;
    let mut run = case.scan_runs[0].clone();
    run.id = "scanner-run".into();
    run.sequence += 1;
    run.engine_runs.truncate(1);
    let task = &mut run.engine_runs[0];
    task.id = "scanner-task".into();
    task.scan_run_id = run.id.clone();
    task.engine_id = "trivy".into();
    task.task_kind = EngineTaskKind::CatalogEngine;
    let mut raw = case.raw_artifacts[0].clone();
    let bytes = fs::read(root.join(&raw.relative_path)).unwrap();
    raw.id = "scanner-original".into();
    raw.run_id = run.id.clone();
    raw.engine_run_id = task.id.clone();
    raw.contains_sensitive_data = false;
    raw.relative_path = format!(
        "{}/{}/{}/{}",
        case.id, run.id, task.id, case.agent_audit_admissions[0].artifacts[0].member_path
    );
    fs::create_dir_all(root.join(&raw.relative_path).parent().unwrap()).unwrap();
    fs::write(root.join(&raw.relative_path), bytes).unwrap();
    task.raw_artifact_ids = vec![raw.id.clone()];
    case.raw_artifacts.push(raw);
    let id = run.id.clone();
    case.scan_runs.push(run);
    id
}

#[test]
fn combined_scanner_and_audit_originals_have_namespaces_and_accurate_omissions() {
    use ai_security_scanner_lib::report_snapshot::{ReportDocumentFormat, ReportSnapshot};
    let (run, request) = exports::sealed_export_fixture("standard");
    let saved = admit::admit(&run, &request, 0);
    let audit_id = saved["run_id"].as_str().unwrap();
    let mut case = admit::case(&run);
    let root = run.f.data.join("artifacts");
    let scanner = add_scanner(&mut case, &root);
    let ids = vec![audit_id.into(), scanner.clone()];
    let mut frozen = Vec::new();
    for profile in [RedactionProfile::None, RedactionProfile::Standard] {
        let snapshot = ReportSnapshot::capture_combined_with_originals(
            &case,
            &ids,
            options(profile),
            &root,
            None,
        )
        .unwrap();
        let output = run
            .f
            .data
            .with_file_name(format!("combined-{}.html", profile.as_str()));
        snapshot
            .retrieve(ReportDocumentFormat::Html, &output)
            .unwrap();
        let html = fs::read_to_string(&output).unwrap();
        let json_path = run
            .f
            .data
            .with_file_name(format!("combined-{}.json", profile.as_str()));
        snapshot
            .retrieve(ReportDocumentFormat::Json, &json_path)
            .unwrap();
        let report: Value = serde_json::from_slice(&fs::read(json_path).unwrap()).unwrap();
        let summary: ai_security_scanner_lib::domain::CombinedOriginalFiles =
            serde_json::from_value(report["original_files"].clone()).unwrap();
        let audit_files = case.agent_audit_admissions[0].artifacts.len();
        assert_eq!(
            summary.included_files,
            if profile == RedactionProfile::None {
                audit_files + 1
            } else {
                1
            }
        );
        assert_eq!(
            summary.sensitive_files_excluded,
            if profile == RedactionProfile::None {
                0
            } else {
                audit_files
            }
        );
        assert_eq!(summary.omitted_files, 0);
        assert!(summary.archive_file_name.is_none());
        assert!(html.contains("scanner-run-scanner-task.zip"));
        assert_eq!(
            html.contains(&format!(
                "{audit_id}-{}.zip",
                case.agent_audit_admissions[0].identities.task_id
            )),
            profile == RedactionProfile::None
        );
        frozen.push((snapshot, html));
    }
    for raw in case.raw_artifacts.iter().filter(|a| a.run_id == audit_id) {
        fs::remove_file(root.join(&raw.relative_path)).unwrap();
    }
    for (index, (snapshot, html)) in frozen.iter().enumerate() {
        let replay = run
            .f
            .data
            .with_file_name(format!("combined-replayed-{index}.html"));
        snapshot
            .replay(ReportDocumentFormat::Html, &replay)
            .unwrap();
        assert_eq!(fs::read_to_string(replay).unwrap(), *html);
    }
    assert!(
        ReportSnapshot::capture_combined_with_originals(
            &case,
            &ids,
            options(RedactionProfile::Standard),
            &root,
            None
        )
        .is_ok()
    );
    let path = run.f.data.with_file_name("scanner-selected.case.tar.gz");
    export::create_case_bundle_at(
        &case,
        &scanner,
        &root,
        &path,
        run.f.data.join("key"),
        ExportOptions::default(),
        case.updated_at,
    )
    .unwrap();
    let files = members(&path);
    assert_eq!(
        document(&files, "source-audit-admissions.json")["admissions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        document(&files, "exports/master-framework-report.json")
            .get("source_audits")
            .is_none()
    );
}

#[test]
fn combined_overflow_with_invalid_originals_still_refuses_before_publication() {
    use ai_security_scanner_lib::{
        case_service::CaseService, domain::SelectedRunReportFormat, error::foreground_error_class,
    };
    let (run, request) = admit::sealed("standard");
    admit::admit(&run, &request, 0);
    let mut case = admit::case(&run);
    let root = run.f.data.join("artifacts");
    let scanner = add_scanner(&mut case, &root);
    let mut second = case.scan_runs.last().unwrap().clone();
    second.id = "scanner-two".into();
    second.sequence += 1;
    second.engine_runs[0].id = "scanner-two-task".into();
    second.engine_runs[0].scan_run_id = second.id.clone();
    let mut second_raw = case.raw_artifacts.last().unwrap().clone();
    second_raw.id = "second-scanner-original".into();
    second_raw.run_id = second.id.clone();
    second_raw.engine_run_id = second.engine_runs[0].id.clone();
    second_raw.relative_path = format!(
        "{}/{}/{}/original.txt",
        case.id, second.id, second_raw.engine_run_id
    );
    second.engine_runs[0].raw_artifact_ids = vec![second_raw.id.clone()];
    case.raw_artifacts.push(second_raw);
    case.scan_runs.push(second);
    let original = case.clone();
    let storage = run.f.storage();
    let engines = ai_security_scanner_lib::registry::EngineRegistry::empty();
    let adapters = ai_security_scanner_lib::adapter::AdapterRegistry::default();
    let service = CaseService::new(&storage, &engines, &adapters, &root, run.f.data.join("key"));
    let snapshots = fs::read_dir(root.join(&case.id).join("report-snapshots"))
        .unwrap()
        .count();
    for file_limit in [false, true] {
        case = original.clone();
        let template = case.raw_artifacts.last().unwrap().clone();
        if file_limit {
            for n in 0..10_001 {
                let mut raw = template.clone();
                raw.id = format!("extra-{n}");
                let task = &mut case.scan_runs[1 + n % 2].engine_runs[0];
                raw.run_id = task.scan_run_id.clone();
                raw.engine_run_id = task.id.clone();
                raw.relative_path = format!("{}/{}/{}/{n}.txt", case.id, raw.run_id, task.id);
                raw.byte_length = 1;
                task.raw_artifact_ids.push(raw.id.clone());
                case.raw_artifacts.push(raw);
            }
        } else {
            for raw in case
                .raw_artifacts
                .iter_mut()
                .filter(|r| r.engine_run_id.starts_with("scanner-"))
            {
                raw.byte_length = 40 * 1024 * 1024;
            }
        }
        let db = rusqlite::Connection::open(storage.path()).unwrap();
        db.execute(
            "UPDATE cases SET document_json=?1 WHERE id=?2",
            rusqlite::params![serde_json::to_string(&case).unwrap(), case.id],
        )
        .unwrap();
        let destination = run
            .f
            .data
            .with_file_name(format!("overflow-{file_limit}.html"));
        let error = service
            .export_selected_runs_with_archive(
                &case.id,
                &[scanner.clone(), "scanner-two".into()],
                SelectedRunReportFormat::Html,
                &destination,
                options(RedactionProfile::None),
                true,
            )
            .unwrap_err();
        assert_ne!(
            foreground_error_class(&error).1,
            "source_audit_attachment_overflow"
        );
        assert!(!destination.exists());
        let stored = storage.get_case(&case.id).unwrap();
        assert_eq!(stored.storage_revision(), case.storage_revision());
        assert_eq!(
            stored.combined_exports.len(),
            original.combined_exports.len()
        );
        assert_eq!(
            fs::read_dir(root.join(&case.id).join("report-snapshots"))
                .unwrap()
                .count(),
            snapshots
        );
    }
}

#[test]
fn single_audit_attachment_limits_and_portable_collisions_refuse_before_reads() {
    use ai_security_scanner_lib::report_snapshot::ReportSnapshot;
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let run_id = saved["run_id"].as_str().unwrap();
    let original = admit::case(&run);
    let root = run.f.data.join("artifacts");
    for kind in ["bytes", "files", "same", "case", "directory"] {
        let mut case = original.clone();
        let a = &mut case.agent_audit_admissions[0];
        let first_id = a.artifacts[0].artifact_id.clone();
        let raw = case
            .raw_artifacts
            .iter_mut()
            .find(|r| r.id == first_id)
            .unwrap();
        match kind {
            "bytes" => {
                raw.byte_length = 64 * 1024 * 1024 + 1;
                a.artifacts[0].byte_length = raw.byte_length;
            }
            "files" => {
                let template = raw.clone();
                for n in 0..10_001 {
                    let mut raw = template.clone();
                    raw.id = format!("extra-{n}");
                    raw.byte_length = 1;
                    let member = format!("extra/{n}.txt");
                    raw.relative_path =
                        format!("{}/{}/{}/{}", case.id, run_id, raw.engine_run_id, member);
                    let mut binding = a.artifacts[0].clone();
                    binding.artifact_id = raw.id.clone();
                    binding.member_path = member;
                    binding.byte_length = 1;
                    a.artifacts.push(binding);
                    case.scan_runs[0].engine_runs[0]
                        .raw_artifact_ids
                        .push(raw.id.clone());
                    case.raw_artifacts.push(raw);
                }
            }
            _ => {
                let second = &a.artifacts[1].member_path;
                let member = match kind {
                    "case" => second.to_uppercase(),
                    "directory" => format!("{second}/child"),
                    _ => second.clone(),
                };
                raw.relative_path =
                    format!("{}/{}/{}/{}", case.id, run_id, raw.engine_run_id, member);
                a.artifacts[0].member_path = member;
            }
        }
        let error = ReportSnapshot::capture(&case, run_id, options(RedactionProfile::None), &root)
            .expect_err(kind);
        assert!(
            error
                .to_string()
                .contains(if matches!(kind, "bytes" | "files") {
                    "attachment limit"
                } else {
                    "collide"
                }),
            "{kind}: {error}"
        );
    }
}

#[test]
fn bundle_verification_rejects_tampered_missing_and_extra_admission_documents() {
    use std::io::Write;
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let case = admit::case(&run);
    let path = run.f.data.with_file_name("verified.case.tar.gz");
    export::create_case_bundle_at(
        &case,
        saved["run_id"].as_str().unwrap(),
        run.f.data.join("artifacts"),
        &path,
        run.f.data.join("key"),
        ExportOptions::default(),
        case.updated_at,
    )
    .unwrap();
    let original = members(&path);
    for kind in ["tamper", "missing", "extra"] {
        let mut files = original.clone();
        match kind {
            "tamper" => {
                files
                    .get_mut("source-audit-admissions.json")
                    .unwrap()
                    .write_all(b" ")
                    .unwrap();
            }
            "missing" => {
                files.remove("source-audit-admissions.json");
            }
            _ => {
                files.insert(
                    "extra/source-audit-admissions.json".into(),
                    files["source-audit-admissions.json"].clone(),
                );
            }
        }
        let path = run.f.data.with_file_name(format!("{kind}.case.tar.gz"));
        let output = fs::File::create(&path).unwrap();
        let encoder = flate2::write::GzEncoder::new(output, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (name, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            archive
                .append_data(&mut header, &name, bytes.as_slice())
                .unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap();
        assert!(export::verify_case_bundle(path).is_err(), "{kind}");
    }
}

#[test]
fn preview_counts_source_audits_separately_and_omits_the_legacy_extension() {
    use ai_security_scanner_lib::case_service::{CaseExportFormat, CaseService};
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let audit = saved["run_id"].as_str().unwrap();
    let mut case = admit::case(&run);
    let root = run.f.data.join("artifacts");
    let scanner = add_scanner(&mut case, &root);
    let storage = run.f.storage();
    storage.save_case(&mut case, "synthetic.scanner").unwrap();
    let engines = ai_security_scanner_lib::registry::EngineRegistry::empty();
    let adapters = ai_security_scanner_lib::adapter::AdapterRegistry::default();
    let service = CaseService::new(&storage, &engines, &adapters, &root, run.f.data.join("key"));
    for format in [CaseExportFormat::Html, CaseExportFormat::CaseBundle] {
        let preview = service
            .preview_export(
                &case.id,
                audit,
                format.clone(),
                &options(RedactionProfile::Standard),
            )
            .unwrap();
        assert_eq!(preview.selected_source_audit_count, Some(1));
        assert_eq!(preview.selected_engine_run_count, 0);
        assert_eq!(
            preview.raw_artifacts_included,
            usize::from(format == CaseExportFormat::CaseBundle)
        );
        assert_eq!(
            preview.sensitive_raw_artifacts_omitted,
            case.agent_audit_admissions[0].artifacts.len()
        );
        let legacy = service
            .preview_export(&case.id, &scanner, format, &ExportOptions::default())
            .unwrap();
        assert_eq!(legacy.selected_engine_run_count, 1);
        assert!(json!(legacy).get("selected_source_audit_count").is_none());
    }
}

#[test]
fn combined_encoded_document_overflow_preserves_admitted_case_in_private_archive() {
    use ai_security_scanner_lib::{case_service::CaseService, domain::SelectedRunReportFormat};
    use sha2::Digest;
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let mut case = admit::case(&run);
    let root = run.f.data.join("artifacts");
    let scanner = add_scanner(&mut case, &root);
    // Incompressible bytes fit the raw budget but exceed it after ZIP/base64 encoding.
    let mut state = 7u32;
    let bytes: Vec<u8> = (0..49 * 1024 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let raw = case.raw_artifacts.last_mut().unwrap();
    raw.byte_length = bytes.len() as u64;
    raw.sha256 = hex::encode(sha2::Sha256::digest(&bytes));
    fs::write(root.join(&raw.relative_path), &bytes).unwrap();
    drop(bytes);
    let storage = run.f.storage();
    storage
        .save_case(&mut case, "synthetic.encoded_limit")
        .unwrap();
    let engines = ai_security_scanner_lib::registry::EngineRegistry::empty();
    let adapters = ai_security_scanner_lib::adapter::AdapterRegistry::default();
    let service = CaseService::new(&storage, &engines, &adapters, &root, run.f.data.join("key"));
    let destination = run.f.data.with_file_name("encoded-overflow.html");
    let saved = service
        .export_selected_runs_with_archive(
            &case.id,
            &[saved["run_id"].as_str().unwrap().into(), scanner],
            SelectedRunReportFormat::Html,
            &destination,
            options(RedactionProfile::None),
            true,
        )
        .unwrap();
    assert!(destination.exists());
    let html = fs::read_to_string(&destination).unwrap();
    assert!(html.contains("retrieve them from the private case archive"));
    let archive = saved.attachment_archive.as_ref().unwrap();
    assert!(
        ai_security_scanner_lib::case_archive::inspect_archive(Path::new(&archive.path))
            .unwrap()
            .case_data_restore_available
    );
    let stored = storage.get_case(&case.id).unwrap();
    assert_eq!(stored.combined_exports.len(), 1);
    assert_eq!(
        stored.agent_audit_admissions[0].admission_sha256,
        case.agent_audit_admissions[0].admission_sha256
    );
}
