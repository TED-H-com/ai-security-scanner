use super::*;
#[test]
fn legacy_round_trip_and_unknown_task_discriminator() {
    let case = crate::demo::build_demo_case();
    let bytes = serde_json::to_vec(&case).unwrap();
    let decoded: AssessmentCase = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(bytes, serde_json::to_vec(&decoded).unwrap());
    let value = serde_json::to_value(&decoded).unwrap();
    assert!(value.get("agent_audit_admissions").is_none());
    assert!(value.get("format_requirements").is_none());
    assert!(
        serde_json::from_value::<crate::domain::EngineTaskKind>(
            serde_json::json!({"kind":"future_audit"})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<crate::domain::EngineTaskKind>(
            serde_json::json!({"kind":"agent_audit","provider_id":"provider"})
        )
        .is_err()
    );
}
#[test]
fn unknown_requirement_is_readable_but_cannot_be_saved_or_archived() {
    let temp = crate::test_temp::tempdir().unwrap();
    let path = temp.path().join("casework.db");
    let storage = crate::storage::Storage::open(&path).unwrap();
    let mut case = crate::demo::build_demo_case();
    storage.save_case(&mut case, "created").unwrap();
    case.format_requirements.insert("future/v1".into());
    let bytes = serde_json::to_string(&case).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE cases SET document_json = ?1 WHERE id = ?2",
        rusqlite::params![bytes, case.id],
    )
    .unwrap();
    let mut read = storage.get_case(&case.id).unwrap();
    assert_eq!(storage.list_cases().unwrap().len(), 1);
    assert!(
        storage
            .save_case(&mut read, "changed")
            .unwrap_err()
            .to_string()
            .contains("requires a newer version")
    );
    assert!(storage.snapshot_case_for_archive(&case.id).is_err());
    let after: String = db
        .query_row(
            "SELECT document_json FROM cases WHERE id = ?1",
            [&case.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(after, bytes);
    assert!(check_report(&read).is_err());
}

pub(crate) fn planned() -> (AssessmentCase, AdmissionPlan) {
    let case = crate::demo::build_demo_case();
    let b = serde_json::json!({"case_id":case.id,"asset_id":case.assets[0].id,"run_id":"audit-run","task_id":"audit-task","session_id":"session","attempt_id":"attempt"});
    let hashes = [
        "preparation_receipt_sha256",
        "source_view_receipt_sha256",
        "view_manifest_sha256",
        "view_sha256",
        "canonical_manifest_sha256",
        "sealed_entry_sha256",
        "bundle_sha256",
        "manifest_sha256",
        "retention_sha256",
        "workflow_sha256",
        "projection_sha256",
        "retained_projection_sha256",
    ];
    let digests: Value = hashes
        .iter()
        .map(|key| (key.to_string(), Value::String("a".repeat(64))))
        .collect::<serde_json::Map<_, _>>()
        .into();
    let admission: AgentAuditAdmission = serde_json::from_value(serde_json::json!({
        "admission_id":"admission", "request_id":"request", "request_sha256":"a".repeat(64), "admitted_at":case.updated_at,
        "provider_id":"cloudflare-security-audit", "provenance":"workflow_recorded", "identities":b,
        "preparation_request_id":"prepare", "source_id":"source", "source_view_request_id":"view-request",
        "source":{"source_view_request_id":"view-request", "source_view_receipt_sha256":"a".repeat(64), "view_id":"view", "view_sha256":"a".repeat(64), "canonical_snapshot_id":"snapshot", "canonical_snapshot_sha256":"a".repeat(64), "policy_id":"policy", "scope":["."], "source_ref":"source", "grant_sha256":"a".repeat(64), "acknowledgement_sha256":"a".repeat(64)},
        "digests":digests, "method":{"upstream_commit":"a".repeat(40), "validator_resources_sha256":"a".repeat(64), "profile":"quick", "budget":{"limit":7,"issued":6,"remaining":1}},
        "outcome":{"state":"complete", "incomplete_reason":null, "audit_performed":true}, "verification_scope":"full_payload", "validators_reexecuted":false,
        "counts_by_role":{},"counts_by_state":{},"counts":{"confirmed":0,"needs_validation":0,"rejected":0,"unresolved_candidates":0,"coverage_by_status":{}}, "artifacts":[], "retained_projection":{}, "admission_sha256":"a".repeat(64)
    })).unwrap();
    let mut run = case.scan_runs[0].clone();
    run.id = "audit-run".into();
    run.engine_runs.truncate(1);
    run.engine_runs[0].id = "audit-task".into();
    run.engine_runs[0].scan_run_id = run.id.clone();
    run.engine_runs[0].task_kind = crate::domain::EngineTaskKind::AgentAudit {
        provider_id: admission.provider_id.clone(),
        admission_id: admission.admission_id.clone(),
    };
    let plan = AdmissionPlan {
        admission,
        run,
        findings: vec![],
        observations: vec![],
        artifact_copies: vec![],
        format_requirement: FORMAT_REQUIREMENT.into(),
    };
    (case, plan)
}

#[test]
fn admission_and_whole_case_bounds_refuse_without_truncation() {
    use super::planner::{MAX_ADMISSION_BYTES, MAX_CASE_BYTES};
    let (case, mut plan) = planned();
    plan.admission.retained_projection = Value::String("x".repeat(MAX_ADMISSION_BYTES));
    assert!(
        plan.resulting_case(&case)
            .unwrap_err()
            .to_string()
            .contains("admission_too_large")
    );
    assert_eq!(
        plan.admission.retained_projection.as_str().unwrap().len(),
        MAX_ADMISSION_BYTES
    );
    plan.admission.retained_projection = Value::String("x".repeat(MAX_CASE_BYTES));
    assert!(
        plan.resulting_case(&case)
            .unwrap_err()
            .to_string()
            .contains("admission_too_large")
    );
    assert_eq!(
        plan.admission.retained_projection.as_str().unwrap().len(),
        MAX_CASE_BYTES
    );
}

#[test]
fn every_report_export_and_snapshot_entry_refuses_unsupported_cases_before_output() {
    use crate::{
        case_service::{CaseExportFormat, CaseService},
        export::ExportOptions,
        report_snapshot::{ReportDocumentFormat, ReportSnapshot},
        selected_run_report::{export_selected_run_report, preview_selected_run_report},
    };
    let temp = crate::test_temp::tempdir().unwrap();
    let (case, plan) = planned();
    let _admitted = plan.resulting_case(&case).unwrap();
    let mut unknown = case.clone();
    unknown.format_requirements.insert("future/v1".into());
    let engines = crate::registry::EngineRegistry::empty();
    let adapters = crate::adapters::builtin_adapter_registry().unwrap();
    for subject in [unknown] {
        let data = temp
            .path()
            .join(if subject.agent_audit_admissions.is_empty() {
                "unknown"
            } else {
                "admitted"
            });
        std::fs::create_dir(&data).unwrap();
        let storage = crate::storage::Storage::open(data.join("casework.db")).unwrap();
        let mut initial = case.clone();
        storage.save_case(&mut initial, "fixture").unwrap();
        let db = rusqlite::Connection::open(storage.path()).unwrap();
        let document = serde_json::to_string(&subject).unwrap();
        db.execute(
            "UPDATE cases SET document_json = ?1 WHERE id = ?2",
            rusqlite::params![document, subject.id],
        )
        .unwrap();
        let service = CaseService::new(
            &storage,
            &engines,
            &adapters,
            data.join("artifacts"),
            data.join("key"),
        );
        let dest = data.join("output");
        let run = &subject.scan_runs[0].id;
        let options = ExportOptions::default();
        fn unavailable<T>(result: AppResult<T>) {
            assert!(matches!(result, Err(AppError::NotAvailable(_))));
        }
        for format in [
            CaseExportFormat::CaseBundle,
            CaseExportFormat::CanonicalJson,
            CaseExportFormat::FrameworkReport,
            CaseExportFormat::Html,
            CaseExportFormat::OcsfJson,
            CaseExportFormat::OscalJson,
        ] {
            unavailable(service.preview_export(&subject.id, run, format.clone(), &options));
            unavailable(service.export_case(&subject.id, run, format, &dest, options.clone()));
            assert!(!dest.exists());
        }
        unavailable(crate::report_renderer::render_canonical_json(
            &subject, run, &options,
        ));
        unavailable(crate::report_renderer::render_html(
            &subject,
            run,
            &options,
            &[],
        ));
        assert!(matches!(
            crate::beginner_report::build_beginner_master_report(&subject, run),
            Err(crate::beginner_report::BeginnerReportError::NotAvailable { .. })
        ));
        unavailable(crate::exporters::export_master_framework_report_bytes(
            &subject, run,
        ));
        unavailable(crate::exporters::export_ocsf_finding_events_bytes(
            &subject, run,
        ));
        unavailable(crate::exporters::export_oscal_assessment_results_bytes(
            &subject, run,
        ));
        let runs = vec![run.clone(), "other-run".into()];
        unavailable(preview_selected_run_report(&subject, &runs, &options));
        for format in [
            crate::domain::SelectedRunReportFormat::Html,
            crate::domain::SelectedRunReportFormat::Json,
        ] {
            unavailable(export_selected_run_report(
                &subject, &runs, format, &dest, &options,
            ));
        }
        unavailable(ReportSnapshot::capture(
            &subject,
            run,
            options.clone(),
            temp.path(),
        ));
        unavailable(ReportSnapshot::capture_combined(
            &subject,
            &runs,
            options.clone(),
        ));
        unavailable(ReportSnapshot::capture_combined_with_originals(
            &subject,
            &runs,
            options.clone(),
            temp.path(),
            None,
        ));
        // Preserve a valid old envelope while replacing its frozen case with unsupported data.
        use base64::Engine;
        let snapshot =
            ReportSnapshot::capture(&case, &case.scan_runs[0].id, options, temp.path()).unwrap();
        let mut envelope = serde_json::to_value(snapshot).unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(envelope["inputs"]["bytes"].as_str().unwrap())
            .unwrap();
        let mut inputs: Value = serde_json::from_slice(&bytes).unwrap();
        inputs["case"] = serde_json::to_value(&subject).unwrap();
        let bytes = serde_json::to_vec(&inputs).unwrap();
        use sha2::Digest;
        envelope["inputs"] = serde_json::json!({"bytes":base64::engine::general_purpose::STANDARD.encode(&bytes),"byte_length":bytes.len(),"sha256":hex::encode(sha2::Sha256::digest(&bytes))});
        let snapshot: ReportSnapshot = serde_json::from_value(envelope).unwrap();
        // Integrity verification and original-file retrieval stay available;
        // only replay through this build's renderer is refused.
        assert!(!snapshot.verify().unwrap().replay_available);
        let retrieved = temp.path().join(format!(
            "{}-retrieved.json",
            data.file_name().unwrap().to_string_lossy()
        ));
        std::fs::remove_file(snapshot.save(&retrieved).unwrap().path).unwrap();
        for format in [ReportDocumentFormat::Html, ReportDocumentFormat::Json] {
            unavailable(snapshot.replay(format, &dest));
        }
        unavailable(crate::case_archive::create_archive(
            &data,
            &subject.id,
            &dest,
            &Default::default(),
        ));
        assert!(!dest.exists() && !data.join("key").exists() && !data.join("artifacts").exists());
        assert_eq!(storage.list_cases().unwrap().len(), 1);
        assert_eq!(storage.get_case(&subject.id).unwrap().id, subject.id);
        let after: String = db
            .query_row(
                "SELECT document_json FROM cases WHERE id = ?1",
                [&subject.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(after, document);
    }
}

#[test]
fn archive_inspection_preview_restore_and_import_refuse_unsupported_domain() {
    use crate::case_archive_io::{ARCHIVE_SCHEMA, ArchiveEntry, ArchiveManifest, write_archive};
    use crate::case_archive_model::{CASE_SNAPSHOT_SCHEMA, PortableCase};
    use sha2::{Digest, Sha256};
    let directory = crate::test_temp::tempdir().unwrap();
    crate::case_archive_io::make_private(directory.path(), true).unwrap();
    let (case, plan) = planned();
    let admitted = plan.resulting_case(&case).unwrap();
    let mut unknown = case.clone();
    unknown.format_requirements.insert("future/v1".into());
    for (i, mut subject) in [admitted, unknown].into_iter().enumerate() {
        let bytes = serde_json::to_vec(&PortableCase {
            schema_version: CASE_SNAPSHOT_SCHEMA.into(),
            case: subject.clone(),
            source_document_sha256: "a".repeat(64),
            historical_events: vec![],
        })
        .unwrap();
        let file = directory.path().join(format!("case-{i}.json"));
        std::fs::write(&file, &bytes).unwrap();
        let manifest = ArchiveManifest {
            required_capabilities: Vec::new(),
            schema_version: ARCHIVE_SCHEMA.into(),
            archive_id: format!("archive-{i}"),
            created_at: Utc::now(),
            producer_version: env!("CARGO_PKG_VERSION").into(),
            case_id: subject.id.clone(),
            source_case_revision: 1,
            case_document_sha256: hex::encode(Sha256::digest(&bytes)),
            raw_artifacts_included: true,
            source_snapshots_included: false,
            omissions: vec![],
            entries: vec![ArchiveEntry {
                path: "case.json".into(),
                sha256: hex::encode(Sha256::digest(&bytes)),
                byte_length: bytes.len() as u64,
            }],
        };
        let archive = directory.path().join(format!("archive-{i}.tar.gz"));
        write_archive(&manifest, &[("case.json".into(), file)].into(), &archive).unwrap();
        let destination = directory.path().join(format!("restore-{i}"));
        let expected = |error| {
            if i == 0 {
                matches!(
                    error,
                    AppError::ArchiveProvider {
                        code: "archive_history_mismatch",
                        ..
                    }
                )
            } else {
                matches!(error, AppError::NotAvailable(_))
            }
        };
        assert!(expected(
            crate::case_archive::inspect_archive(&archive).unwrap_err()
        ));
        assert!(expected(
            crate::case_archive::preview_restore(&archive, &destination).unwrap_err()
        ));
        assert!(expected(
            crate::case_archive::restore_archive(&archive, &destination).unwrap_err()
        ));
        assert!(!destination.exists());
        let storage =
            crate::storage::Storage::open(directory.path().join(format!("restore-{i}.db")))
                .unwrap();
        assert!(matches!(
            storage.import_archived_case(&mut subject, &[], "archive"),
            Err(AppError::NotAvailable(_))
        ));
        assert!(storage.list_cases().unwrap().is_empty());
    }
}

#[test]
fn admissions_are_immutable_and_confirmed_deletion_remains_available() {
    let directory = crate::test_temp::tempdir().unwrap();
    let storage = crate::storage::Storage::open(directory.path().join("casework.db")).unwrap();
    let (case, plan) = planned();
    let mut admitted = plan.resulting_case(&case).unwrap();
    storage.save_case(&mut admitted, "fixture").unwrap();
    let mut changed = admitted.clone();
    changed.agent_audit_admissions[0].retained_projection = serde_json::json!({"changed":true});
    assert!(
        storage
            .save_case(&mut changed, "changed")
            .unwrap_err()
            .to_string()
            .contains("immutable")
    );
    let mut downgraded = admitted.clone();
    downgraded.scan_runs.last_mut().unwrap().engine_runs[0].task_kind =
        crate::domain::EngineTaskKind::CatalogEngine;
    assert!(
        storage
            .save_case(&mut downgraded, "downgraded")
            .unwrap_err()
            .to_string()
            .contains("discriminator")
    );
    changed.agent_audit_admissions.clear();
    assert!(
        storage
            .save_case(&mut changed, "removed")
            .unwrap_err()
            .to_string()
            .contains("immutable")
    );
    assert_eq!(
        storage
            .get_case(&admitted.id)
            .unwrap()
            .agent_audit_admissions
            .len(),
        1
    );
    storage
        .delete_case(&admitted.id, admitted.storage_revision(), None)
        .unwrap();
    assert!(storage.list_cases().unwrap().is_empty());
}

#[test]
fn frozen_legacy_case_fixtures_reserialize_byte_identically() {
    use std::io::Read;
    for scenario in ["all-detectors", "mixed-terminal"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/fixtures/report-fidelity")
            .join(scenario)
            .join("case.json.gz");
        let compressed = std::fs::read(path).unwrap();
        let mut bytes = Vec::new();
        flate2::read::GzDecoder::new(compressed.as_slice())
            .read_to_end(&mut bytes)
            .unwrap();
        let case: AssessmentCase = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(bytes, serde_json::to_vec_pretty(&case).unwrap());
    }
}

#[test]
fn admission_transaction_shares_save_invariants_and_rolls_back_event_failure() {
    let temp = crate::test_temp::tempdir().unwrap();
    let storage = crate::storage::Storage::open(temp.path().join("casework.db")).unwrap();
    let (mut case, plan) = planned();
    storage.save_case(&mut case, "created").unwrap();
    let mut next = plan.resulting_case(&case).unwrap();
    let db = rusqlite::Connection::open(storage.path()).unwrap();
    db.execute_batch("CREATE TRIGGER reject_admission BEFORE INSERT ON case_events WHEN NEW.event_type = 'cloudflare_audit.admitted' BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
    assert!(
        storage
            .save_admitted_case(&mut next, &plan.admission)
            .is_err()
    );
    assert_eq!(
        storage.get_case(&case.id).unwrap().storage_revision,
        case.storage_revision
    );
    assert!(
        storage
            .get_case(&case.id)
            .unwrap()
            .agent_audit_admissions
            .is_empty()
    );
    assert_eq!(storage.list_case_events(&case.id).unwrap().len(), 1);
    db.execute_batch("DROP TRIGGER reject_admission").unwrap();
    storage
        .save_admitted_case(&mut next, &plan.admission)
        .unwrap();
    assert_eq!(next.storage_revision, case.storage_revision + 1);
    let events = storage.list_case_events(&case.id).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].event_type, ADMITTED_EVENT);
    assert_eq!(
        serde_json::from_str::<Value>(&events[1].payload_json).unwrap(),
        plan.admission.receipt(next.storage_revision)
    );
    let mut stale = plan.resulting_case(&case).unwrap();
    assert!(matches!(
        storage.save_admitted_case(&mut stale, &plan.admission),
        Err(AppError::Conflict(_))
    ));
    next.agent_audit_admissions[0].request_id = "tampered".into();
    assert!(storage.save_case(&mut next, "changed").is_err());
    // A concurrently changed format must still report a lost revision first.
    db.execute(r#"UPDATE cases SET revision=revision+1, document_json=json_set(document_json, '$.format_requirements', json('["future/v1"]')) WHERE id=?1"#, [&case.id]).unwrap();
    assert!(matches!(
        storage.save_case(&mut case, "changed"),
        Err(AppError::Conflict(_))
    ));
}

#[test]
fn agent_audit_baselines_and_comparisons_refuse_before_any_new_run() {
    use crate::case_service::{CaseService, ScanPlanRequest};
    let temp = crate::test_temp::tempdir().unwrap();
    let storage = crate::storage::Storage::open(temp.path().join("casework.db")).unwrap();
    let (case, plan) = planned();
    let mut admitted = plan.resulting_case(&case).unwrap();
    admitted.is_demo = false;
    storage.save_case(&mut admitted, "fixture").unwrap();
    let engines = crate::registry::EngineRegistry::empty();
    let adapters = crate::adapters::builtin_adapter_registry().unwrap();
    let service = CaseService::new(
        &storage,
        &engines,
        &adapters,
        temp.path().join("artifacts"),
        temp.path().join("key"),
    );
    let expected = "An admitted source audit cannot authorize a Check fixes scan; start a separately reviewed scan.";
    for result in [
        service.plan_rescan(&admitted.id, &plan.run.id, ScanPlanRequest::default()),
        service.plan_rescan_for_execution(&admitted.id, &plan.run.id, ScanPlanRequest::default()),
        service.persist_rescan_before_execution_preflight(
            &admitted.id,
            &plan.run.id,
            ScanPlanRequest::default(),
        ),
    ] {
        let error = result.unwrap_err().to_string();
        assert!(error.contains(expected), "{error}");
    }
    let other = &case.scan_runs[0].id;
    for (a, b) in [(&plan.run.id, other), (other, &plan.run.id)] {
        assert!(matches!(
            crate::diff::compare_case_runs(&admitted, a, b),
            Err(AppError::NotAvailable(_))
        ));
        assert!(matches!(
            service.compare_and_persist(&admitted.id, a, b),
            Err(AppError::NotAvailable(_))
        ));
    }
    assert_eq!(
        storage.get_case(&case.id).unwrap().storage_revision,
        admitted.storage_revision
    );
    assert_eq!(storage.list_case_events(&case.id).unwrap().len(), 1);
}

#[test]
fn surface_gates_bind_the_selected_run() {
    let (case, plan) = planned();
    let scanner_run = case.scan_runs[0].id.clone();
    let case = plan.resulting_case(&case).unwrap();
    assert!(check_format(&case).is_ok());
    assert!(check_run_export(&case, &scanner_run).is_ok());
    assert!(check_run_export(&case, "audit-run").is_err());
    assert!(check_report(&case).is_err());
}
