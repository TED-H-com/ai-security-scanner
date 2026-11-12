use super::{admit, fixture::*};
use ai_security_scanner_lib::{
    case_service::{CaseExportFormat, CaseService},
    domain::EngineTaskKind,
    export::{ExportOptions, RedactionProfile},
    exporters::{
        export_master_framework_report_bytes, export_ocsf_finding_events_bytes,
        export_oscal_assessment_results_bytes,
    },
};
use sha2::Digest;

#[test]
fn admission_gate_refuses_tampered_bindings_before_publication() {
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let run_id = saved["run_id"].as_str().unwrap();
    let original = admit::case(&run);
    assert!(export_ocsf_finding_events_bytes(&original, run_id).is_ok());
    let task_id = original.agent_audit_admissions[0]
        .identities
        .task_id
        .clone();
    let storage = run.f.storage();
    let engines = ai_security_scanner_lib::registry::EngineRegistry::empty();
    let adapters = ai_security_scanner_lib::adapter::AdapterRegistry::default();
    let service = CaseService::new(
        &storage,
        &engines,
        &adapters,
        run.f.data.join("artifacts"),
        run.f.data.join("key"),
    );
    for change in 0..18 {
        let mut case = original.clone();
        match change {
            0 => case.agent_audit_admissions.clear(),
            1 => case
                .agent_audit_admissions
                .push(case.agent_audit_admissions[0].clone()),
            2 => case.agent_audit_admissions[0].identities.case_id = "other".into(),
            3 => case.agent_audit_admissions[0].identities.run_id = "other".into(),
            4 => case.agent_audit_admissions[0].identities.task_id = "other".into(),
            5 => case.agent_audit_admissions[0].provider_id = "other".into(),
            6 => {
                case.raw_artifacts
                    .iter_mut()
                    .find(|a| a.engine_run_id == task_id)
                    .unwrap()
                    .sha256 = "b".repeat(64)
            }
            7 => case
                .scan_runs
                .iter_mut()
                .find(|r| r.id == run_id)
                .unwrap()
                .engine_runs[0]
                .raw_artifact_ids
                .clear(),
            8 => {
                case.finding_observations
                    .iter_mut()
                    .find(|o| o.run_id == run_id)
                    .unwrap()
                    .finding_snapshot
                    .as_mut()
                    .unwrap()
                    .evidence[0]
                    .engine_run_id = Some("other".into())
            }
            9 => {
                case.finding_observations
                    .iter_mut()
                    .find(|o| o.run_id == run_id)
                    .unwrap()
                    .finding_snapshot
                    .as_mut()
                    .unwrap()
                    .evidence[0]
                    .provider_record
                    .as_mut()
                    .unwrap()
                    .native_record_sha256 = "b".repeat(64)
            }
            10 => {
                case.agent_audit_admissions[0].retained_projection["records"][0]["verdict"] =
                    json!("needs_validation")
            }
            11 => {
                case.scan_runs
                    .iter_mut()
                    .find(|r| r.id == run_id)
                    .unwrap()
                    .engine_runs[0]
                    .task_kind = EngineTaskKind::AgentAudit {
                    provider_id: "other".into(),
                    admission_id: case.agent_audit_admissions[0].admission_id.clone(),
                }
            }
            12 => {
                case.finding_observations
                    .iter_mut()
                    .find(|o| o.run_id == run_id)
                    .unwrap()
                    .finding_snapshot
                    .as_mut()
                    .unwrap()
                    .evidence[0]
                    .artifact_id = "other".into()
            }
            13 => case.raw_artifacts[0].contains_sensitive_data = false,
            14 => case.raw_artifacts[0].byte_length += 1,
            15 => {
                let task = case.scan_runs[0].engine_runs[0].clone();
                case.scan_runs[0].engine_runs.push(task);
            }
            16 => case.scan_runs.push(case.scan_runs[0].clone()),
            _ => {
                let mut raw = case.raw_artifacts[0].clone();
                raw.id = "unregistered-original".into();
                case.raw_artifacts.push(raw);
            }
        }
        for export in [
            export_master_framework_report_bytes,
            export_ocsf_finding_events_bytes,
            export_oscal_assessment_results_bytes,
        ] {
            assert!(export(&case, run_id).is_err(), "mutation {change}");
        }
        // Inject a damaged stored document without weakening normal storage checks.
        let db = rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap();
        db.execute(
            "UPDATE cases SET document_json=?1 WHERE id=?2",
            rusqlite::params![serde_json::to_string(&case).unwrap(), case.id],
        )
        .unwrap();
        for profile in [RedactionProfile::None, RedactionProfile::Standard] {
            let options = ExportOptions {
                redaction: profile,
                ..Default::default()
            };
            for format in [
                CaseExportFormat::CaseBundle,
                CaseExportFormat::Html,
                CaseExportFormat::FrameworkReport,
                CaseExportFormat::OcsfJson,
                CaseExportFormat::OscalJson,
            ] {
                let destination = run
                    .f
                    .data
                    .with_file_name(format!("refused-{change}-{}.case.tar.gz", format.as_str()));
                assert!(
                    service
                        .preview_export(&case.id, run_id, format.clone(), &options)
                        .is_err()
                );
                assert!(
                    service
                        .export_case(&case.id, run_id, format, &destination, options.clone())
                        .is_err()
                );
                assert!(!destination.exists());
                assert!(!run.f.data.join("key").exists());
            }
        }
    }
}

fn export_document(
    run: &RunFixture,
    run_id: &str,
    format: CaseExportFormat,
    profile: RedactionProfile,
    suffix: &str,
) -> (Value, std::path::PathBuf) {
    let storage = run.f.storage();
    let engines = ai_security_scanner_lib::registry::EngineRegistry::empty();
    let adapters = ai_security_scanner_lib::adapter::AdapterRegistry::default();
    let service = CaseService::new(
        &storage,
        &engines,
        &adapters,
        run.f.data.join("artifacts"),
        run.f.data.join("key"),
    );
    let path = run.f.data.with_file_name(format!(
        "{}-{}-{suffix}.json",
        format.as_str(),
        profile.as_str()
    ));
    service
        .export_case(
            &run.f.case_id,
            run_id,
            format,
            &path,
            ExportOptions {
                redaction: profile,
                ..Default::default()
            },
        )
        .unwrap();
    (
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap(),
        path,
    )
}

#[test]
fn ocsf_confirmed_identity_and_human_status_in_both_profiles() {
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let run_id = saved["run_id"].as_str().unwrap();
    let mut case = admit::case(&run);
    case.findings[0].status = ai_security_scanner_lib::domain::FindingStatus::ExpertReviewRequested;
    run.f
        .storage()
        .save_case(&mut case, "workflow.updated")
        .unwrap();
    for profile in [RedactionProfile::None, RedactionProfile::Standard] {
        let (events, _) = export_document(
            &run,
            run_id,
            CaseExportFormat::OcsfJson,
            profile,
            "identity",
        );
        assert_eq!(
            events.as_array().unwrap().len(),
            case.agent_audit_admissions[0].counts.confirmed
        );
        let event = &events[0];
        assert_eq!(event["class_uid"], 2004);
        assert_eq!(event["metadata"]["source"], "Source audit observation");
        let identity = &event["unmapped"]["ai_security_scanner"]["source_audit"];
        let admission = &case.agent_audit_admissions[0];
        let record = admission.retained_projection["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["verdict"] == "confirmed")
            .unwrap();
        assert_eq!(
            identity,
            &json!({"provider_id":admission.provider_id,"admission_id":admission.admission_id,
            "native_fingerprint": if profile == RedactionProfile::None { record["fingerprint"].clone() } else { json!(format!("fp-{}", &hex::encode(sha2::Sha256::digest(record["fingerprint"].as_str().unwrap().as_bytes()))[..12])) },"native_record_sha256":record["native_record_sha256"],
            "native_record_index":record["native_record_index"],"provider_verdict":"confirmed",
            "method":"Cloudflare source audit","upstream_commit":admission.method.upstream_commit})
        );
        assert_eq!(event["status"], "In Progress");
        if profile == RedactionProfile::Standard {
            assert!(
                identity["native_fingerprint"]
                    .as_str()
                    .unwrap()
                    .starts_with("fp-")
            );
        }
    }
}

#[test]
fn oscal_confirmed_identity_props_and_human_status_in_both_profiles() {
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let run_id = saved["run_id"].as_str().unwrap();
    let mut case = admit::case(&run);
    case.findings[0].status = ai_security_scanner_lib::domain::FindingStatus::FalsePositive;
    run.f
        .storage()
        .save_case(&mut case, "workflow.updated")
        .unwrap();
    for profile in [RedactionProfile::None, RedactionProfile::Standard] {
        let (ocsf, _) = export_document(
            &run,
            run_id,
            CaseExportFormat::OcsfJson,
            profile,
            "oscal-identity",
        );
        let (oscal, _) = export_document(
            &run,
            run_id,
            CaseExportFormat::OscalJson,
            profile,
            "identity",
        );
        let observations = oscal["assessment-results"]["results"][0]["observations"]
            .as_array()
            .unwrap();
        assert_eq!(observations.len(), 1);
        let observation = &observations[0];
        assert_eq!(observation["methods"], json!(["EXAMINE"]));
        let props = observation["props"].as_array().unwrap();
        assert!(
            props
                .iter()
                .any(|p| p["name"] == "finding-status" && p["value"] == "false_positive")
        );
        assert!(
            props
                .iter()
                .any(|p| p["name"] == "observation-source"
                    && p["value"] == "Source audit observation")
        );
        let identity = ocsf[0]["unmapped"]["ai_security_scanner"]["source_audit"]
            .as_object()
            .unwrap();
        for list in std::iter::once(props).chain(
            observation["relevant-evidence"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["props"].as_array().unwrap()),
        ) {
            for (key, value) in identity {
                let name = format!("source-audit-{}", key.replace('_', "-"));
                let text = value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string());
                assert!(
                    list.iter().any(|p| p["name"] == name
                        && p["value"] == text
                        && p["ns"] == "urn:ai-security-scanner:oscal:props"),
                    "{name}"
                );
            }
        }
        assert!(!oscal.to_string().contains("control-id-ref"));
    }
}

pub(super) fn sealed_export_fixture(profile: &str) -> (RunFixture, Value) {
    if profile == "quick" {
        return admit::sealed(profile);
    }
    let run = RunFixture::with_records(profile, &[], |records, _, _| {
        records[0]["remediation"]["code_changes"] = json!([{
            "file_name":"src/private-fix.rs", "fixed_code":"PRIVATE-EXPORT-CODE"}]);
    });
    super::finalize::finalize(&run, &super::finalize::request(&run), 0);
    let storage = run.f.storage();
    let verified = ai_security_scanner_lib::cloudflare_provider::audit::sealed::verify(
        &run.f.data,
        &storage,
        &run.f.case_id,
        run.prepared["session_id"].as_str().unwrap(),
    )
    .unwrap();
    let request = json!({
        "schema_version":"ai-security-scanner.cloudflare-audit-admit-request/v1",
        "request_id":"admit-export", "case_id":run.f.case_id, "session_id":run.prepared["session_id"],
        "expected_sealed_entry_sha256":verified.digests.sealed_entry_sha256,
        "expected_bundle_sha256":verified.digests.bundle_sha256,
        "expected_projection_sha256":verified.digests.projection_sha256,
    });
    drop(verified);
    drop(storage);
    (run, request)
}

#[test]
fn companions_keep_complete_and_zero_confirmed_audits_and_bind_main_bytes() {
    for audit_profile in ["standard", "quick"] {
        let (run, request) = sealed_export_fixture(audit_profile);
        let saved = admit::admit(&run, &request, 0);
        let run_id = saved["run_id"].as_str().unwrap();
        let case = admit::case(&run);
        for profile in [RedactionProfile::None, RedactionProfile::Standard] {
            for format in [CaseExportFormat::OcsfJson, CaseExportFormat::OscalJson] {
                let (document, path) =
                    export_document(&run, run_id, format.clone(), profile, "companion");
                let companion: Value = serde_json::from_slice(
                    &fs::read(path.with_file_name(format!(
                        "{}.coverage.json",
                        path.file_name().unwrap().to_str().unwrap()
                    )))
                    .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    companion["companion"]["sha256"],
                    hex::encode(sha2::Sha256::digest(fs::read(&path).unwrap()))
                );
                let canonical: Value = serde_json::from_slice(
                    &ai_security_scanner_lib::report_renderer::render_canonical_json(
                        &case,
                        run_id,
                        &ExportOptions {
                            redaction: profile,
                            ..Default::default()
                        },
                    )
                    .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    companion["report"]["source_audits"],
                    canonical["report"]["source_audits"]
                );
                let audit = &companion["report"]["source_audits"][0];
                assert_eq!(audit["to_validate"].as_array().unwrap().len(), 1);
                assert_eq!(audit["method"]["provider"], "cloudflare-security-audit");
                let events = if format == CaseExportFormat::OcsfJson {
                    &document
                } else {
                    &document["assessment-results"]["results"][0]["observations"]
                };
                assert_eq!(
                    events.as_array().unwrap().len(),
                    if audit_profile == "quick" { 0 } else { 1 }
                );
                if audit_profile == "quick" {
                    assert_eq!(audit["outcome"]["state"], "incomplete");
                    assert_eq!(audit["coverage_gaps"].as_array().unwrap().len(), 1);
                    assert_eq!(audit["unresolved_candidates"].as_array().unwrap().len(), 1);
                }
                if profile == RedactionProfile::Standard {
                    for text in [
                        "PRIVATE-EXPORT-CODE",
                        "src/private-fix.rs",
                        "src/a.rs",
                        "An attacker can reach an operation",
                        "A parsed size may reach",
                        "source work unfinished",
                        "Host stopped after source review",
                        "src-handler-missing-check",
                        "src-parser-size-hypothesis",
                    ] {
                        assert!(!document.to_string().contains(text), "main leaked {text}");
                        assert!(
                            !companion.to_string().contains(text),
                            "companion leaked {text}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn companion_publication_rolls_back_on_history_failure_and_preserves_existing_companion() {
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let run_id = saved["run_id"].as_str().unwrap();
    let storage = run.f.storage();
    let engines = ai_security_scanner_lib::registry::EngineRegistry::empty();
    let adapters = ai_security_scanner_lib::adapter::AdapterRegistry::default();
    let service = CaseService::new(
        &storage,
        &engines,
        &adapters,
        run.f.data.join("artifacts"),
        run.f.data.join("key"),
    );
    let db = rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_export BEFORE INSERT ON case_events WHEN NEW.event_type='export.schema_created' BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    let before = storage.get_case(&run.f.case_id).unwrap().exports.len();
    for profile in [RedactionProfile::None, RedactionProfile::Standard] {
        for format in [CaseExportFormat::OcsfJson, CaseExportFormat::OscalJson] {
            let path = run.f.data.with_file_name(format!(
                "rollback-{}-{}.json",
                format.as_str(),
                profile.as_str()
            ));
            let companion = path.with_file_name(format!(
                "{}.coverage.json",
                path.file_name().unwrap().to_str().unwrap()
            ));
            let options = ExportOptions {
                redaction: profile,
                ..Default::default()
            };
            assert!(
                service
                    .export_case(
                        &run.f.case_id,
                        run_id,
                        format.clone(),
                        &path,
                        options.clone()
                    )
                    .is_err()
            );
            assert!(!path.exists());
            assert!(!companion.exists());
            fs::write(&companion, b"existing companion").unwrap();
            assert!(
                service
                    .export_case(&run.f.case_id, run_id, format, &path, options)
                    .is_err()
            );
            assert!(!path.exists());
            assert_eq!(fs::read(companion).unwrap(), b"existing companion");
        }
    }
    assert_eq!(
        storage.get_case(&run.f.case_id).unwrap().exports.len(),
        before
    );
}

#[test]
fn framework_extension_uses_redacted_shared_report_and_declared_schema() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/master-framework-report.schema.json"
    ))
    .unwrap();
    for audit_profile in ["standard", "quick"] {
        let (run, request) = sealed_export_fixture(audit_profile);
        let saved = admit::admit(&run, &request, 0);
        let run_id = saved["run_id"].as_str().unwrap();
        let case = admit::case(&run);
        for profile in [RedactionProfile::None, RedactionProfile::Standard] {
            let (framework, _) = export_document(
                &run,
                run_id,
                CaseExportFormat::FrameworkReport,
                profile,
                "extension",
            );
            let canonical: Value = serde_json::from_slice(
                &ai_security_scanner_lib::report_renderer::render_canonical_json(
                    &case,
                    run_id,
                    &ExportOptions {
                        redaction: profile,
                        ..Default::default()
                    },
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                framework["source_audits"],
                canonical["report"]["source_audits"]
            );
            if audit_profile == "standard" {
                assert_eq!(
                    framework.to_string().contains("PRIVATE-EXPORT-CODE"),
                    profile == RedactionProfile::None
                );
                if profile == RedactionProfile::Standard {
                    assert!(!framework.to_string().contains("src/private-fix.rs"));
                    assert!(
                        !framework
                            .to_string()
                            .contains("An attacker can reach an operation")
                    );
                    assert!(
                        framework["source_audits"][0]["withheld_code_fields"]
                            .as_u64()
                            .unwrap()
                            > 0
                    );
                }
            }
            super::export_schema::validate(
                &schema,
                &schema["properties"]["source_audits"],
                &framework["source_audits"],
            )
            .unwrap();
            let mut invalid = framework["source_audits"].clone();
            invalid[0]["invented"] = json!(true);
            assert!(
                super::export_schema::validate(
                    &schema,
                    &schema["properties"]["source_audits"],
                    &invalid
                )
                .is_err()
            );
            invalid = framework["source_audits"].clone();
            invalid[0]["method"]["issued_invocations"] = json!("not a count");
            assert!(
                super::export_schema::validate(
                    &schema,
                    &schema["properties"]["source_audits"],
                    &invalid
                )
                .is_err()
            );
            for key in [
                "planned_engine_count",
                "completed_engine_count",
                "unfinished_engine_count",
                "not_executed_engine_count",
            ] {
                assert_eq!(framework["coverage"][key], 0, "{key}");
            }
            assert_eq!(framework["coverage"]["engine_states"], json!({}));
            assert_eq!(framework["coverage"]["state"], "incomplete_or_unknown");
            for observation in framework["observation_provenance"].as_array().unwrap() {
                assert_eq!(
                    observation["framework_mapping_state"],
                    "source_audit_not_mapped"
                );
                super::export_schema::validate(
                    &schema,
                    &schema["$defs"]["observationProvenance"],
                    observation,
                )
                .unwrap();
            }
            for block in framework["frameworks"].as_array().unwrap() {
                assert!(block["controls"].as_array().unwrap().is_empty());
            }
        }
    }
}

#[test]
fn mixed_scanner_and_audit_exports_preserve_scanner_provenance_and_counts() {
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let run_id = saved["run_id"].as_str().unwrap();
    let mut case = admit::case(&run);
    let scanner = ai_security_scanner_lib::demo::build_demo_case();
    let scanner_run_id = scanner.scan_runs[0].id.clone();
    fn rebind(value: &mut Value, case_id: &str, old_run: &str, new_run: &str) {
        match value {
            Value::Object(fields) => {
                for (key, child) in fields {
                    if key == "case_id" {
                        *child = json!(case_id);
                    } else {
                        rebind(child, case_id, old_run, new_run);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    rebind(item, case_id, old_run, new_run);
                }
            }
            Value::String(s) if s == old_run => *s = new_run.into(),
            _ => (),
        }
    }
    let mut scanner = json!(scanner);
    rebind(&mut scanner, &case.id, &scanner_run_id, run_id);
    let scanner: AssessmentCase = serde_json::from_value(scanner).unwrap();
    let scanner_tasks = scanner.scan_runs[0].engine_runs.len();
    let selected = case.scan_runs.iter_mut().find(|r| r.id == run_id).unwrap();
    selected
        .engine_runs
        .extend(scanner.scan_runs[0].engine_runs.clone());
    selected
        .report_asset_snapshots
        .extend(scanner.scan_runs[0].report_asset_snapshots.clone());
    case.assets.extend(scanner.assets);
    case.findings.extend(scanner.findings);
    case.finding_observations
        .extend(scanner.finding_observations);
    case.raw_artifacts.extend(scanner.raw_artifacts);
    run.f
        .storage()
        .save_case(&mut case, "fixture.mixed")
        .unwrap();
    let expected_events = case
        .finding_observations
        .iter()
        .filter(|o| o.run_id == run_id)
        .count();
    for profile in [RedactionProfile::None, RedactionProfile::Standard] {
        let (ocsf, _) = export_document(&run, run_id, CaseExportFormat::OcsfJson, profile, "mixed");
        let events = ocsf.as_array().unwrap();
        assert_eq!(events.len(), expected_events);
        assert_eq!(
            events
                .iter()
                .filter(|e| e["unmapped"]["ai_security_scanner"]["source_audit"].is_object())
                .count(),
            1
        );
        assert!(
            events
                .iter()
                .any(|e| e["metadata"]["source"] == "Canonical scanner observation")
        );
        let (oscal, _) =
            export_document(&run, run_id, CaseExportFormat::OscalJson, profile, "mixed");
        let observations = oscal["assessment-results"]["results"][0]["observations"]
            .as_array()
            .unwrap();
        assert_eq!(observations.len(), expected_events);
        assert_eq!(
            observations
                .iter()
                .filter(|o| o["props"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p["name"] == "source-audit-provider-verdict"))
                .count(),
            1
        );
        let (framework, _) = export_document(
            &run,
            run_id,
            CaseExportFormat::FrameworkReport,
            profile,
            "mixed",
        );
        assert_eq!(framework["coverage"]["planned_engine_count"], scanner_tasks);
        assert_eq!(framework["source_audits"].as_array().unwrap().len(), 1);
        assert_eq!(
            framework["observation_provenance"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|o| o["framework_mapping_state"] == "source_audit_not_mapped")
                .count(),
            1
        );
    }
}
