use super::*;
use crate::cloudflare_provider::audit::{
    Blocker, Delegation, Host, PrepareRequest, Profile, RECEIPT_SCHEMA, REQUEST_SCHEMA,
};
use crate::storage::Storage;
#[test]
fn blocked_groups_multiple_reasons_strict_dto_custody_and_no_backfill() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("casework.db")).unwrap();
    let codes = [
        BlockerCode::SourceViewNotReady,
        BlockerCode::HostMismatch,
        BlockerCode::DelegationUnavailable,
        BlockerCode::BudgetCannotFundReconnaissanceAndReserves,
        BlockerCode::SourceAuthorizationMissing,
        BlockerCode::SourceAuthorizationExpired,
        BlockerCode::GrantChanged,
        BlockerCode::SourceBindingMismatch,
        BlockerCode::SnapshotIntegrityFailed,
        BlockerCode::ViewMissing,
        BlockerCode::ViewIntegrityFailed,
        BlockerCode::RunDirectoryUnavailable,
        BlockerCode::ValidatorResourcesChanged,
    ];
    for (i, code) in codes.iter().enumerate() {
        let mut case = AssessmentCase::new(
            "Synthetic".into(),
            OrganizationProfile {
                organization_name: "Fixture".into(),
                employee_range: "1".into(),
                data_classes: vec![],
                notes: None,
            },
        );
        storage.save_case(&mut case, "fixture").unwrap();
        let request = PrepareRequest {
            schema_version: REQUEST_SCHEMA.into(),
            request_id: format!("blocked-{i}"),
            case_id: case.id.clone(),
            asset_id: "removed-asset".into(),
            source_view_request_id: "view".into(),
            expected_source_view_receipt_sha256: "a".repeat(64),
            profile: Profile::Quick,
            invocation_budget: None,
            host: Host {
                host_id: "synthetic-host".into(),
                delegation: Delegation::Unavailable,
                model: None,
            },
            run_directory: temp.path().to_owned(),
        };
        let result = PreparationResult::Blocked {
            request: Box::new(request.clone()),
            blockers: vec![
                Blocker::new(code.clone(), "test"),
                Blocker::new(BlockerCode::GrantChanged, "test"),
            ],
        };
        let receipt = PreparationReceipt {
            schema_version: RECEIPT_SCHEMA.into(),
            request_id: request.request_id.clone(),
            request_sha256: request.content_digest().unwrap(),
            case_id: case.id.clone(),
            asset_id: request.asset_id.clone(),
            occurred_at: "2026-11-12T00:00:00Z".into(),
            case_revision: case.storage_revision(),
            sequence: 0,
            predecessor_sha256: None,
            result: result.clone(),
            receipt_sha256: String::new(),
        };
        let saved = storage
            .record_cloudflare_audit_receipt(receipt, || Ok(result))
            .unwrap();
        case = storage.get_case(&case.id).unwrap();
        let run = &case.scan_runs[0];
        let task = &run.engine_runs[0];
        let EngineTaskKind::AgentAuditFailure { outcome, .. } = &task.task_kind else {
            panic!()
        };
        assert_eq!(
            outcome.ending,
            Ending::Blocked {
                reasons: vec![code.clone(), BlockerCode::GrantChanged]
            }
        );
        assert!(outcome.session_id.is_none());
        assert_eq!(outcome.terminal_sha256, saved.receipt_sha256);
        assert_eq!(run.created_at, outcome.occurred_at);
        assert_eq!(task.status, EngineRunStatus::NotExecuted);
        assert_eq!(task.asset_ids, vec!["removed-asset"]);
        assert!(run.report_asset_snapshots.is_empty());
        let again = plan(&case, &saved, &Record::default()).unwrap().unwrap();
        assert_eq!(run.id, again.id);
        assert_eq!(task.id, again.engine_runs[0].id);
        let report = crate::beginner_report::build_beginner_master_report(&case, &run.id).unwrap();
        assert_eq!(report.actual.checks.len(), 1);
        assert_eq!(
            report
                .coverage_gaps
                .iter()
                .filter(|g| g.task_id.as_deref() == Some(&task.id))
                .count(),
            1
        );
        for sentence in [
            outcome.description().reason,
            outcome.description().next_action,
        ] {
            assert!(wording::translate(&sentence).is_some());
        }
        for locale in [
            crate::export::ReportLocale::En,
            crate::export::ReportLocale::ZhHant,
        ] {
            for redaction in [
                crate::export::RedactionProfile::None,
                crate::export::RedactionProfile::Standard,
            ] {
                let options = crate::export::ExportOptions {
                    locale,
                    redaction,
                    ..Default::default()
                };
                let html = String::from_utf8(
                    crate::report_renderer::render_html(&case, &run.id, &options, &[]).unwrap(),
                )
                .unwrap();
                let document: Value = serde_json::from_slice(
                    &crate::report_renderer::render_canonical_json(&case, &run.id, &options)
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    document["report"]["actual"]["checks"][0]["outcome"],
                    json!(outcome.description())
                );
                for sentence in [
                    outcome.description().summary,
                    outcome.description().reason,
                    outcome.description().next_action,
                    outcome.gap().into(),
                ] {
                    let expected = if locale == crate::export::ReportLocale::En {
                        sentence.as_str()
                    } else {
                        wording::translate(&sentence).unwrap()
                    };
                    assert!(
                        html.contains(&crate::report_renderer::html_escape(expected)),
                        "{code:?}: {expected}"
                    );
                }
            }
        }
        let events = storage.list_case_events(&case.id).unwrap();
        check_custody(&case, &events).unwrap();
        let mut forged = case.clone();
        let EngineTaskKind::AgentAuditFailure { outcome, .. } =
            &mut forged.scan_runs[0].engine_runs[0].task_kind
        else {
            panic!()
        };
        outcome.terminal_sha256 = "f".repeat(64);
        let mut extra = json!(outcome);
        assert!(check_custody(&forged, &events).is_err());
        extra["prose"] = json!("not allowed");
        assert!(serde_json::from_value::<Outcome>(extra).is_err());
        let mut historical = case.clone();
        historical.scan_runs.clear();
        historical.format_requirements.clear();
        let old_events: Vec<_> = events
            .into_iter()
            .filter(|e| e.event_type != EVENT)
            .collect();
        check_custody(&historical, &old_events).unwrap();
        assert!(historical.scan_runs.is_empty());
    }
}
