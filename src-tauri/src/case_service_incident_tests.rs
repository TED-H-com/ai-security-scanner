// Included in case_service::tests to reuse the real planner/storage fixtures.
#[test]
fn incident_focus_plan_reopen_export_and_rescan_preserve_campaign_and_scope() {
    let fixture = Fixture::new();
    let case = fixture.create();
    let (_, asset_id) = fixture.discovered_repository_with_files(
        &case.id, &[("requirements.txt", "requests==2.31.0\n")],
    );
    approve_local_asset(&fixture, &case.id, &asset_id);
    let service = fixture.service();
    let plan = service.plan_scan(&case.id, ScanPlanRequest {
        campaign_id: Some(crate::incident_focus::INCIDENT_FOCUS_ID.into()),
        engine_ids: Vec::new(),
        engine_asset_routes: vec![EngineAssetRoute { engine_id: "trivy".into(), asset_ids: vec![asset_id.clone()] }],
    }).unwrap();
    assert_eq!(plan.scan_run.campaign_id.as_deref(), Some("october-2026"));
    assert!(!plan.scan_run.engine_runs.is_empty());
    assert!(plan.scan_run.engine_runs.iter().all(|task|
        task.engine_id == "trivy" && task.asset_ids == vec![asset_id.clone()]));
    let mut stored = service.show_case(&case.id).unwrap();
    // Deliberately end without running a scanner: the exported campaign must
    // describe missing checks and must never manufacture a clean result.
    close_run_without_execution_for_report_fixture(&mut stored, &plan.scan_run.id);
    fixture.storage.save_case(&mut stored, "test.incident_no_execution").unwrap();
    let reopened_storage = Storage::open(fixture.directory.path().join("casework.db")).unwrap();
    let reopened = reopened_storage.get_case(&case.id).unwrap();
    let run = reopened.scan_runs.iter().find(|run| run.id == plan.scan_run.id).unwrap();
    assert_eq!(run.campaign_id.as_deref(), Some("october-2026"));
    let report = crate::beginner_report::build_beginner_master_report(&reopened, &run.id).unwrap();
    let focus = report.incident_focus.as_ref().unwrap();
    assert!(focus.issues.iter().any(|row| row.issue_id == "php2shell"
        && row.asset_id.as_deref() == Some(asset_id.as_str())
        && row.status == crate::incident_focus::IncidentCoverageStatus::NotTested));
    assert!(focus.issues.iter().all(|row| row.finding_ids.is_empty()));
    let export_path = fixture.directory.path().join("incident.html");
    service.export_case(&case.id, &plan.scan_run.id, CaseExportFormat::Html,
        &export_path, ExportOptions::default()).unwrap();
    let html = fs::read_to_string(export_path).unwrap();
    assert!(html.contains("PHP2Shell"));
    assert!(html.contains("Not tested"));
    assert!(html.contains("ConnMan"));
    assert!(html.contains("https://thephp.foundation/"));
    let rescan = service.plan_rescan(&case.id, &plan.scan_run.id, ScanPlanRequest::default()).unwrap();
    assert_eq!(rescan.plan.scan_run.campaign_id.as_deref(), Some("october-2026"));
    assert!(rescan.plan.scan_run.engine_runs.iter().all(|task|
        task.engine_id == "trivy" && task.asset_ids == vec![asset_id.clone()]));
}

#[test]
fn incident_focus_rejects_unlisted_routed_engine_before_persisting_work() {
    let fixture = Fixture::new();
    let case_id = repository_case_ready_for_execution(&fixture);
    let service = fixture.service();
    let before = service.show_case(&case_id).unwrap();
    let asset_id = before.assets[0].id.clone();
    let error = service.plan_scan(&case_id, ScanPlanRequest {
        campaign_id: Some(crate::incident_focus::INCIDENT_FOCUS_ID.into()),
        engine_ids: Vec::new(),
        engine_asset_routes: vec![EngineAssetRoute { engine_id: "gitleaks".into(), asset_ids: vec![asset_id] }],
    }).unwrap_err();
    assert!(error.to_string().contains("incident triage"));
    assert_eq!(service.show_case(&case_id).unwrap().scan_runs.len(), before.scan_runs.len());
}

#[test]
fn incident_focus_empty_or_generic_network_engines_cannot_fall_back_to_full_plan() {
    let fixture = Fixture::new();
    let case_id = repository_case_ready_for_execution(&fixture);
    let service = fixture.service();
    let before = service.show_case(&case_id).unwrap();
    for engine_ids in [vec![], vec!["nuclei".into()], vec!["greenbone".into()],
        vec!["trivy".into(), "nuclei".into()]] {
        let error = service.plan_scan(&case_id, ScanPlanRequest {
            campaign_id: Some(crate::incident_focus::INCIDENT_FOCUS_ID.into()),
            engine_ids,
            engine_asset_routes: vec![],
        }).unwrap_err();
        assert!(error.to_string().contains("explicit Trivy"));
        assert_eq!(service.show_case(&case_id).unwrap().scan_runs.len(), before.scan_runs.len());
    }
}
