use super::{fixture::*, termination};
use ai_security_scanner_lib::{
    beginner_report::build_beginner_master_report,
    case_archive::{self, ArchiveOptions},
    domain::{EngineRunStatus, EngineTaskKind},
    export::{ExportOptions, RedactionProfile, ReportLocale},
    report_renderer::{render_canonical_json, render_html},
};

pub(super) fn assert_row(f: &Fixture, saved: &Value, blocked: bool) {
    let reference = &saved["result"]["outcome_run"];
    assert_eq!(reference["report_snapshot_state"], "retained", "{saved}");
    let case = f.storage().get_case(&f.case_id).unwrap();
    let run = case
        .scan_runs
        .iter()
        .find(|r| r.id == reference["run_id"])
        .unwrap();
    assert_eq!(run.engine_runs.len(), 1);
    let task = &run.engine_runs[0];
    assert_eq!(task.id, reference["task_id"]);
    assert_eq!(task.asset_ids, vec![f.asset_id.clone()]);
    assert_eq!(
        task.status,
        if blocked {
            EngineRunStatus::NotExecuted
        } else {
            EngineRunStatus::Failed
        }
    );
    assert!(task.started_at.is_none());
    assert_eq!(task.phase, if blocked { "not_executed" } else { "failed" });
    let EngineTaskKind::AgentAuditFailure { outcome, .. } = &task.task_kind else {
        panic!("wrong kind")
    };
    let wire = json!(outcome);
    assert_eq!(
        wire["ending"],
        if blocked { "blocked" } else { "terminated" }
    );
    assert_eq!(run.completed_at, Some(outcome.occurred_at));
    let mut extra = wire.clone();
    extra["prose"] = json!("unexpected");
    assert!(
        serde_json::from_value::<ai_security_scanner_lib::agent_audit_failure::Outcome>(extra)
            .is_err()
    );
    assert!(
        case.format_requirements
            .contains("cloudflare_audit_terminal/v1")
    );
    let report = build_beginner_master_report(&case, &run.id).unwrap();
    assert!(report.source_audits.is_empty());
    assert!(report.findings.is_empty());
    assert_eq!(report.actual.checks.len(), 1);
    assert!(report.actual.checks[0].tested_dimensions.is_empty());
    let gaps: Vec<_> = report
        .coverage_gaps
        .iter()
        .filter(|g| g.task_id.as_deref() == Some(&task.id))
        .collect();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].reason, outcome.gap());
    for locale in [ReportLocale::En, ReportLocale::ZhHant] {
        for redaction in [RedactionProfile::None, RedactionProfile::Standard] {
            let options = ExportOptions {
                locale,
                redaction,
                ..Default::default()
            };
            let html =
                String::from_utf8(render_html(&case, &run.id, &options, &[]).unwrap()).unwrap();
            let document: Value =
                serde_json::from_slice(&render_canonical_json(&case, &run.id, &options).unwrap())
                    .unwrap();
            assert_eq!(
                document["report"]["actual"]["checks"][0]["outcome"],
                json!(outcome.description())
            );
            let description = outcome.description();
            if wire["reason"] == "host_interrupted" {
                let expected = if locale == ReportLocale::En {
                    "<p>The Cloudflare source audit ended before completion. The audit was interrupted. Start a new source audit.</p>"
                } else {
                    "<p>Cloudflare 原始碼稽核未完成即結束。稽核流程中斷。開始新的原始碼稽核。</p>"
                };
                assert!(html.contains(expected), "missing exact row: {expected}");
            }
            for sentence in [
                &description.summary,
                &description.reason,
                &description.next_action,
            ] {
                let expected = if locale == ReportLocale::En {
                    sentence.as_str()
                } else {
                    ai_security_scanner_lib::agent_audit_failure::wording::translate(sentence)
                        .unwrap()
                };
                assert!(html.contains(expected), "missing {expected}");
            }
            let technical =
                document["report"]["technical_details"]["tasks"][0]["execution"].to_string();
            assert!(!technical.contains("request_id"));
            assert!(!technical.contains("host_id"));
            assert!(!technical.contains("run_directory"));
            let detail = html
                .split("<article><h3>")
                .find(|part| {
                    part.starts_with(&format!(
                        "{} <code>{}</code>",
                        if locale == ReportLocale::En {
                            "Task"
                        } else {
                            "工作"
                        },
                        task.id
                    ))
                })
                .unwrap()
                .split("</article>")
                .next()
                .unwrap();
            let labels = if locale == ReportLocale::En {
                [
                    if blocked {
                        "Source audit did not start"
                    } else {
                        "Source audit ended before completion"
                    },
                    "reason codes",
                    "recorded time",
                    "preparation receipt SHA-256",
                    "terminal record entry SHA-256",
                    "assignment count",
                    "capture count",
                ]
            } else {
                [
                    if blocked {
                        "原始碼稽核未開始"
                    } else {
                        "原始碼稽核未完成即結束"
                    },
                    "原因代碼",
                    "記錄時間",
                    "準備收據 SHA-256",
                    "終態紀錄項目 SHA-256",
                    "派工筆數",
                    "擷取筆數",
                ]
            };
            for label in &labels[..if blocked { 4 } else { 7 }] {
                assert!(detail.contains(label), "missing {label}: {detail}");
            }
            for digest in [
                &outcome.preparation_receipt_sha256,
                &outcome.terminal_sha256,
            ] {
                assert!(detail.contains(digest));
            }
            let time = outcome
                .occurred_at
                .format(if locale == ReportLocale::En {
                    "%Y-%m-%d %H:%M:%S UTC"
                } else {
                    "%Y年%m月%d日 %H:%M:%S UTC"
                })
                .to_string();
            assert!(detail.contains(&time), "missing {time}: {detail}");
            match &outcome.ending {
                ai_security_scanner_lib::agent_audit_failure::Ending::Blocked { reasons } => {
                    for reason in reasons {
                        assert!(detail.contains(json!(reason).as_str().unwrap()));
                    }
                    assert!(!detail.contains(labels[4]));
                    assert_eq!(detail.matches(labels[3]).count(), 1, "{detail}");
                    assert_eq!(
                        detail
                            .matches(outcome.preparation_receipt_sha256.as_str())
                            .count(),
                        1,
                        "{detail}"
                    );
                }
                ai_security_scanner_lib::agent_audit_failure::Ending::Terminated {
                    reason,
                    assignment_count,
                    capture_count,
                } => {
                    assert!(detail.contains(json!(reason).as_str().unwrap()));
                    assert!(detail.contains(&format!("{}: {assignment_count}", labels[5])));
                    assert!(detail.contains(&format!("{}: {capture_count}", labels[6])));
                }
            }
            for key in [
                "{",
                "}",
                "&quot;",
                "receipt_sha256",
                "terminal_sha256",
                "occurred_at",
                "assignment_count",
                "capture_count",
                "Source audit ended</",
                "<strong>Phase",
                "<strong>階段",
            ] {
                assert!(!detail.contains(key), "unexpected {key}: {detail}");
            }
            assert!(!html.contains("Continue the source audit from the listed paths."));
        }
    }
    assert!(task.raw_artifact_ids.is_empty());
    let events = f.storage().list_case_events(&f.case_id).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.event_type == "cloudflare_audit.outcome_recorded"
                && e.payload_json.contains(&run.id))
            .count(),
        1
    );
}

#[test]
fn ordinary_saves_cannot_introduce_failure_runs_or_read_custody() {
    for blocked in [false, true] {
        let (f, mut prep) = Fixture::setup(true);
        let saved = if blocked {
            prep["host"]["delegation"] = json!("unavailable");
            f.audit(&prep, 0)
        } else {
            let prepared = f.audit(&prep, 0);
            termination::terminate(
                &f,
                &termination::request(
                    &f,
                    &prepared,
                    &prepared["receipt"]["sha256"],
                    "host_interrupted",
                ),
                0,
            )
        };
        assert_row(&f, &saved, blocked);
        let storage = f.storage();
        let mut case = storage.get_case(&f.case_id).unwrap();
        let original = case.clone();
        let db = rusqlite::Connection::open(f.data.join("casework.db")).unwrap();
        // An unreadable event payload makes any accidental event read fail.
        db.execute(
            "UPDATE case_events SET payload_json=x'ff' WHERE case_id=?1",
            [&case.id],
        )
        .unwrap();
        storage.save_case(&mut case, "fixture.retained").unwrap();
        assert_eq!(json!(case.scan_runs), json!(original.scan_runs));
        assert_eq!(
            json!(case.run_report_snapshots),
            json!(original.run_report_snapshots)
        );
        let retained = case.clone();
        for previous_kind in 0..3 {
            let mut previous = retained.clone();
            previous.run_report_snapshots.clear();
            if previous_kind == 2 {
                // Reusing an ordinary run ID cannot authorize a failure task.
                previous.scan_runs[0].engine_runs[0].task_kind = EngineTaskKind::CatalogEngine;
            } else {
                previous.scan_runs.clear();
                if previous_kind == 0 {
                    previous.format_requirements.clear();
                }
            }
            db.execute(
                "UPDATE cases SET document_json=?1 WHERE id=?2",
                rusqlite::params![serde_json::to_string(&previous).unwrap(), case.id],
            )
            .unwrap();
            let error = storage.save_case(&mut case, "fixture.forged").unwrap_err();
            assert_eq!(
                error.to_string(),
                "invalid request: source audit failure does not match recorded custody"
            );
        }
        let mut new_case = AssessmentCase::new(retained.title.clone(), retained.profile.clone());
        new_case.scan_runs = retained.scan_runs.clone();
        new_case.format_requirements = retained.format_requirements.clone();
        assert_eq!(
            storage
                .save_case(&mut new_case, "fixture.forged")
                .unwrap_err()
                .to_string(),
            "invalid request: source audit failure does not match recorded custody"
        );
        // Ordinary cases need neither the old document decoded nor event payloads read.
        case.scan_runs.clear();
        case.run_report_snapshots.clear();
        case.format_requirements.clear();
        db.execute(
            "UPDATE cases SET document_json='synthetic undecodable document' WHERE id=?1",
            [&case.id],
        )
        .unwrap();
        storage.save_case(&mut case, "fixture.ordinary").unwrap();
    }
}

#[test]
fn failure_rows_atomicity_pending_snapshot_repair_replay_and_format() {
    for blocked in [false, true] {
        let (f, mut prep) = Fixture::setup(true);
        let prepared = if blocked {
            prep["host"]["delegation"] = json!("unavailable");
            None
        } else {
            Some(f.audit(&prep, 0))
        };
        let end = prepared
            .as_ref()
            .map(|p| termination::request(&f, p, &p["receipt"]["sha256"], "workflow_failed"));
        let invoke = |code| {
            if let Some(end) = &end {
                termination::terminate(&f, end, code)
            } else {
                f.audit(&prep, code)
            }
        };
        let db = rusqlite::Connection::open(f.data.join("casework.db")).unwrap();
        for trigger in [
            "CREATE TRIGGER fail_row BEFORE UPDATE OF document_json ON cases WHEN instr(NEW.document_json,'agent_audit_failure')>0 BEGIN SELECT RAISE(ABORT,'injected row failure'); END;",
            "CREATE TRIGGER fail_row BEFORE UPDATE OF document_json ON cases WHEN instr(NEW.document_json,'agent_audit_failure')>0 BEGIN SELECT RAISE(IGNORE); END;",
        ] {
            db.execute_batch(trigger).unwrap();
            let before = f.storage().snapshot_case_for_archive(&f.case_id).unwrap();
            invoke(if trigger.contains("IGNORE") { 3 } else { 4 });
            let after = f.storage().snapshot_case_for_archive(&f.case_id).unwrap();
            assert_eq!(before.events, after.events);
            assert_eq!(before.document_json, after.document_json);
            assert_eq!(before.revision, after.revision);
            db.execute_batch("DROP TRIGGER fail_row;").unwrap();
        }
        db.execute_batch("CREATE TRIGGER fail_snapshot BEFORE INSERT ON case_events WHEN NEW.event_type='report.terminal_snapshot_saved' BEGIN SELECT RAISE(ABORT,'injected snapshot failure'); END;").unwrap();
        let saved = invoke(0);
        assert_eq!(
            saved["result"]["outcome_run"]["report_snapshot_state"],
            "pending"
        );
        let status = f.audit_status("audit-one", false, 0);
        assert_eq!(
            status["result"]["next_operation"],
            if blocked {
                "prepare_replay"
            } else {
                "terminate_replay"
            }
        );
        let before = f.storage().snapshot_case_for_archive(&f.case_id).unwrap();
        assert_eq!(
            invoke(0)["result"]["outcome_run"],
            saved["result"]["outcome_run"]
        );
        assert_eq!(
            before.events,
            f.storage().list_case_events(&f.case_id).unwrap()
        );
        db.execute_batch("DROP TRIGGER fail_snapshot;").unwrap();
        let repaired = invoke(0);
        assert_row(&f, &repaired, blocked);
        let before = f.storage().snapshot_case_for_archive(&f.case_id).unwrap();
        assert_eq!(
            invoke(0)["result"]["outcome_run"],
            repaired["result"]["outcome_run"]
        );
        assert_eq!(
            before.events,
            f.storage().list_case_events(&f.case_id).unwrap()
        );
        assert!(f.audit_status("audit-one", false, 0)["result"]["next_operation"].is_null());
        for mutation in 0..4 {
            let mut case = before.case.clone();
            match mutation {
                0 => {
                    case.format_requirements.clear();
                }
                1 => {
                    case.format_requirements.insert("unknown/v1".into());
                }
                2 => case.scan_runs[0].engine_runs[0].asset_ids = vec!["different".into()],
                _ => case.scan_runs.clear(),
            }
            assert!(f.storage().save_case(&mut case, "tampered").is_err());
        }
    }
}

#[test]
fn failure_only_archives_restore_inert_and_inventory_is_exact() {
    use ai_security_scanner_lib::{
        case_service::{CaseExportFormat, CaseService},
        report_snapshot::{ReportDocumentFormat, ReportSnapshot, current_run_snapshot},
    };
    for blocked in [false, true] {
        let (mut f, mut prep) = Fixture::setup(true);
        let end;
        let saved = if blocked {
            prep["invocation_budget"] = json!(1);
            end = None;
            f.audit(&prep, 0)
        } else {
            let p = f.audit(&prep, 0);
            let request = termination::request(&f, &p, &p["receipt"]["sha256"], "host_cancelled");
            let saved = termination::terminate(&f, &request, 0);
            end = Some(request);
            saved
        };
        let reference = &saved["result"]["outcome_run"];
        let run_id = reference["run_id"].as_str().unwrap();
        let task_id = reference["task_id"].as_str().unwrap();
        let (ending, reason, heading) = if blocked {
            (
                "blocked",
                "The invocation budget was too small for this audit.",
                "Source audit did not start",
            )
        } else {
            (
                "terminated",
                "The audit was stopped before completion.",
                "Source audit ended before completion",
            )
        };
        let assert_report = |html: &[u8], json: &[u8]| {
            let document: Value = serde_json::from_slice(json).unwrap();
            assert!(
                document
                    .to_string()
                    .contains(&format!("\"ending\":\"{ending}\""))
            );
            assert_eq!(
                document["report"]["actual"]["checks"][0]["outcome"]["reason"],
                reason
            );
            let html = std::str::from_utf8(html).unwrap();
            assert!(html.contains(reason), "missing reason: {reason}");
            let disclosure = "<details class=\"technical\"><summary><strong>Technical details</strong></summary>";
            let (first_layer, technical) = html.split_once(disclosure).unwrap();
            let technical = technical.split("</details>").next().unwrap();
            let task_heading = format!("<article><h3>Task <code>{task_id}</code>");
            assert!(!first_layer.contains(&task_heading));
            let task = technical
                .split_once(&task_heading)
                .unwrap()
                .1
                .split("</article>")
                .next()
                .unwrap();
            assert!(task.contains(heading), "missing heading: {heading}");
            assert!(task.contains("reason codes"));
        };
        let retrieve = |f: &Fixture, stage: &str| {
            let case = f.storage().get_case(&f.case_id).unwrap();
            let record = current_run_snapshot(&case, run_id).unwrap().unwrap();
            let snapshot = ReportSnapshot::load(
                &f.data
                    .join("artifacts")
                    .join(&record.snapshot.relative_path),
            )
            .unwrap();
            let html = f.data.with_file_name(format!("{stage}-saved.html"));
            let json = f.data.with_file_name(format!("{stage}-saved.json"));
            snapshot
                .retrieve(ReportDocumentFormat::Html, &html)
                .unwrap();
            snapshot
                .retrieve(ReportDocumentFormat::Json, &json)
                .unwrap();
            (fs::read(html).unwrap(), fs::read(json).unwrap())
        };
        let export_current = |f: &Fixture, stage: &str| {
            let storage = f.storage();
            let engines = ai_security_scanner_lib::registry::EngineRegistry::empty();
            let adapters = ai_security_scanner_lib::adapter::AdapterRegistry::default();
            let service = CaseService::new(
                &storage,
                &engines,
                &adapters,
                f.data.join("artifacts"),
                f.data.join("key"),
            );
            let html = f.data.with_file_name(format!("{stage}-current.html"));
            let json = f.data.with_file_name(format!("{stage}-current.json"));
            for (format, path) in [
                (CaseExportFormat::Html, &html),
                (CaseExportFormat::CanonicalJson, &json),
            ] {
                service
                    .export_case(&f.case_id, run_id, format, path, ExportOptions::default())
                    .unwrap();
            }
            assert_report(&fs::read(html).unwrap(), &fs::read(json).unwrap());
        };
        let (before_html, before_json) = retrieve(&f, "before");
        assert_report(&before_html, &before_json);
        export_current(&f, "reopened");
        let original = f.storage().get_case(&f.case_id).unwrap();
        let path = f.data.with_file_name("failure.tar.gz");
        case_archive::create_archive(&f.data, &f.case_id, &path, &ArchiveOptions::default())
            .unwrap();
        case_archive::inspect_archive(&path).unwrap();
        let files = super::archives::unpack(&path);
        let manifest: Value = serde_json::from_slice(&files["archive-manifest.json"]).unwrap();
        assert_eq!(
            manifest["required_capabilities"],
            json!([
                "cloudflare_audit_terminal/v1",
                "provider_archive_history/v1"
            ])
        );
        let history: Value = serde_json::from_slice(&files["provider-history.json"]).unwrap();
        assert_eq!(
            history["preparations"][0]["outcome_run"]["run_id"],
            saved["result"]["outcome_run"]["run_id"]
        );
        let destination = f.data.with_file_name("restored-failure");
        case_archive::restore_archive(&path, &destination).unwrap();
        f.data = destination;
        let (restored_html, restored_json) = retrieve(&f, "restored");
        assert_eq!(restored_html, before_html);
        assert_eq!(restored_json, before_json);
        export_current(&f, "restored");
        assert_eq!(
            json!(original.scan_runs),
            json!(f.storage().get_case(&f.case_id).unwrap().scan_runs)
        );
        assert_row(&f, &saved, blocked);
        let before = f.storage().snapshot_case_for_archive(&f.case_id).unwrap();
        let refused = if let Some(end) = &end {
            termination::terminate(&f, end, 2)
        } else {
            f.audit(&prep, 2)
        };
        assert_eq!(refused["error_code"], "restored_session_inert");
        assert_eq!(
            before.events,
            f.storage().list_case_events(&f.case_id).unwrap()
        );
    }
}

#[test]
fn failure_rows_exports_combined_siblings_and_comparison_refusal() {
    use ai_security_scanner_lib::{
        case_service::{CaseExportFormat, CaseService},
        export, selected_run_report,
    };
    let (run, request) = super::admit::sealed("standard");
    super::admit::admit(&run, &request, 0);
    let f = &run.f;
    let storage = f.storage();
    let mut case = storage.get_case(&f.case_id).unwrap();
    let root = f.data.join("artifacts");
    let scanner = super::bundles_attachments::add_scanner(&mut case, &root);
    storage.save_case(&mut case, "fixture.scanner").unwrap();
    let originals: Vec<_> = case
        .raw_artifacts
        .iter()
        .map(|a| {
            (
                a.relative_path.clone(),
                fs::read(root.join(&a.relative_path)).unwrap(),
            )
        })
        .collect();
    let snapshots: Vec<_> = case
        .run_report_snapshots
        .iter()
        .map(|s| {
            (
                s.snapshot.relative_path.clone(),
                fs::read(root.join(&s.snapshot.relative_path)).unwrap(),
            )
        })
        .collect();
    let prior = json!([
        case.agent_audit_admissions,
        case.findings,
        case.raw_artifacts
    ]);
    let (_, mut prep) = Fixture::setup(true);
    // Use this fixture's recorded source view and source, never the donor's target.
    prep["case_id"] = json!(f.case_id);
    prep["asset_id"] = json!(f.asset_id);
    prep["request_id"] = json!("blocked-sibling");
    prep["expected_source_view_receipt_sha256"] = json!(
        storage
            .source_view_receipt(&f.case_id, "view-request")
            .unwrap()
            .unwrap()
            .digest
    );
    prep["run_directory"] = json!(run.host);
    prep["host"]["delegation"] = json!("unavailable");
    let blocked = f.audit(&prep, 0);
    prep["request_id"] = json!("terminated-sibling");
    prep["host"]["delegation"] = json!("available");
    let prepared = f.audit(&prep, 0);
    let end = termination::request(
        f,
        &prepared,
        &prepared["receipt"]["sha256"],
        "host_interrupted",
    );
    let ended = termination::terminate(f, &end, 0);
    let case = storage.get_case(&f.case_id).unwrap();
    assert_eq!(
        prior,
        json!([
            case.agent_audit_admissions,
            case.findings,
            case.raw_artifacts
        ])
    );
    for (path, bytes) in originals.into_iter().chain(snapshots) {
        assert_eq!(fs::read(root.join(path)).unwrap(), bytes);
    }
    let engines = ai_security_scanner_lib::registry::EngineRegistry::empty();
    let adapters = ai_security_scanner_lib::adapter::AdapterRegistry::default();
    let service = CaseService::new(&storage, &engines, &adapters, &root, f.data.join("key"));
    for saved in [&blocked, &ended] {
        let id = saved["result"]["outcome_run"]["run_id"].as_str().unwrap();
        assert_row(f, saved, std::ptr::eq(saved, &blocked));
        assert!(ai_security_scanner_lib::diff::compare_case_runs(&case, &scanner, id).is_err());
        assert!(service.resume_scan(&case.id, id).is_err());
        assert_eq!(
            service
                .plan_rescan(&case.id, id, Default::default())
                .unwrap_err()
                .to_string(),
            "invalid request: A source audit that did not finish cannot authorize a Check fixes scan; start a separately reviewed scan."
        );
        let before = storage.snapshot_case_for_archive(&case.id).unwrap();
        let recovery = terminal(
            f.command()
                .args([
                    "scan",
                    "recover",
                    "--case-id",
                    &case.id,
                    "--run-id",
                    id,
                    "--wait",
                ])
                .output()
                .unwrap(),
            2,
        );
        assert_eq!(recovery["error_code"], "not_available");
        assert_eq!(before.events, storage.list_case_events(&case.id).unwrap());
        assert!(
            service
                .persist_resume_before_execution_preflight(&case.id, id)
                .is_err()
        );
        assert!(
            service
                .persist_captured_recovery_before_execution_preflight(&case.id, id)
                .is_err()
        );
        let selected = selected_run_report::preview_selected_run_report(
            &case,
            &[scanner.clone(), id.into()],
            &ExportOptions::default(),
        )
        .unwrap();
        let selected_failure = selected.sources.iter().find(|s| s.run_id == id).unwrap();
        assert_eq!(
            selected_failure.origin,
            selected_run_report::SelectedRunOrigin::SourceAudit
        );
        assert_eq!(
            selected_failure.report.actual.checks[0].target_asset_ids,
            vec![f.asset_id.clone()]
        );
        for format in [
            CaseExportFormat::FrameworkReport,
            CaseExportFormat::OcsfJson,
            CaseExportFormat::OscalJson,
            CaseExportFormat::CaseBundle,
        ] {
            let options = ExportOptions::default();
            assert_eq!(
                service
                    .preview_export(&case.id, id, format.clone(), &options)
                    .unwrap()
                    .selected_engine_run_count,
                0
            );
            let path = f.data.with_file_name(format!(
                "{id}-{}.{}",
                format.as_str(),
                if format == CaseExportFormat::CaseBundle {
                    "case.tar.gz"
                } else {
                    "json"
                }
            ));
            service
                .export_case(&case.id, id, format.clone(), &path, options)
                .unwrap();
            if format == CaseExportFormat::CaseBundle {
                export::verify_case_bundle(&path).unwrap();
                let files = super::archives::unpack(&path);
                assert!(
                    String::from_utf8(files["scan-runs.json"].clone())
                        .unwrap()
                        .contains(id)
                );
                continue;
            }
            let document: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            match format {
                CaseExportFormat::FrameworkReport => {
                    assert_eq!(document["coverage"]["unfinished_engine_count"], 1);
                    assert_eq!(document["coverage"]["completed_engine_count"], 0);
                    assert_eq!(document["coverage"]["selected_run_finding_count"], 0);
                    assert_eq!(document["observation_provenance"], json!([]));
                }
                CaseExportFormat::OcsfJson | CaseExportFormat::OscalJson => {
                    let observations = if format == CaseExportFormat::OcsfJson {
                        &document
                    } else {
                        &document["assessment-results"]["results"][0]["observations"]
                    };
                    assert_eq!(observations, &json!([]));
                    let companion = path.with_file_name(format!(
                        "{}.coverage.json",
                        path.file_name().unwrap().to_str().unwrap()
                    ));
                    let coverage: Value =
                        serde_json::from_slice(&fs::read(companion).unwrap()).unwrap();
                    assert_eq!(
                        coverage["report"]["actual"]["checks"]
                            .as_array()
                            .unwrap()
                            .len(),
                        1
                    );
                }
                _ => unreachable!(),
            }
        }
    }
    let path = f.data.with_file_name("mixed.tar.gz");
    case_archive::create_archive(&f.data, &f.case_id, &path, &ArchiveOptions::default()).unwrap();
    case_archive::inspect_archive(&path).unwrap();
    let original = super::archives::unpack(&path);
    for kind in [
        "missing",
        "wrong",
        "extra",
        "null",
        "extra_binding",
        "digest",
        "capabilities",
    ] {
        let mut files = original.clone();
        let mut history: Value = serde_json::from_slice(&files["provider-history.json"]).unwrap();
        let p = history["preparations"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|p| p["preparation_request_id"] == "blocked-sibling")
            .unwrap();
        match kind {
            "missing" => {
                p.as_object_mut().unwrap().remove("outcome_run");
            }
            "wrong" => p["outcome_run"]["run_id"] = json!("wrong"),
            "null" => p["outcome_run"] = Value::Null,
            "extra" => p["outcome_run"]["prose"] = json!("extra"),
            "extra_binding" => {
                history["preparations"][0]["outcome_run"] =
                    blocked["result"]["outcome_run"].clone();
                history["preparations"][0]["outcome_run"]
                    .as_object_mut()
                    .unwrap()
                    .remove("report_snapshot_state");
            }
            "digest" => {
                let mut portable: Value = serde_json::from_slice(&files["case.json"]).unwrap();
                let event = portable["historical_events"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|e| e["event_type"] == "cloudflare_audit.outcome_recorded")
                    .unwrap();
                let mut payload: Value =
                    serde_json::from_str(event["payload_json"].as_str().unwrap()).unwrap();
                payload["outcome_sha256"] = json!("a".repeat(64));
                event["payload_json"] = json!(serde_json::to_string(&payload).unwrap());
                files.insert("case.json".into(), serde_json::to_vec(&portable).unwrap());
            }
            _ => {
                let mut manifest: Value =
                    serde_json::from_slice(&files["archive-manifest.json"]).unwrap();
                manifest["required_capabilities"] = json!([
                    "cloudflare_audit_admission/v1",
                    "provider_archive_history/v1"
                ]);
                files.insert(
                    "archive-manifest.json".into(),
                    serde_json::to_vec(&manifest).unwrap(),
                );
            }
        }
        files.insert(
            "provider-history.json".into(),
            serde_json::to_vec(&history).unwrap(),
        );
        super::archives::repack(&path, files);
        let error = case_archive::inspect_archive(&path).unwrap_err();
        assert!(
            matches!(
                error,
                ai_security_scanner_lib::error::AppError::ArchiveProvider {
                    code: "archive_history_mismatch",
                    ..
                }
            ),
            "{kind}: {error}"
        );
    }
}

#[test]
fn historical_custody_without_rows_is_never_backfilled_on_replay() {
    for blocked in [false, true] {
        let (f, mut prep) = Fixture::setup(true);
        let end = if blocked {
            prep["host"]["delegation"] = json!("unavailable");
            None
        } else {
            let p = f.audit(&prep, 0);
            Some(termination::request(
                &f,
                &p,
                &p["receipt"]["sha256"],
                "host_cancelled",
            ))
        };
        let invoke = || {
            if let Some(end) = &end {
                termination::terminate(&f, end, 0)
            } else {
                f.audit(&prep, 0)
            }
        };
        invoke();
        // Synthetic pre-B1 data: retain custody but remove B1 rows/events/snapshot references.
        let db = rusqlite::Connection::open(f.data.join("casework.db")).unwrap();
        let mut case = f.storage().get_case(&f.case_id).unwrap();
        case.scan_runs.clear();
        case.run_report_snapshots.clear();
        case.format_requirements.clear();
        db.execute(
            "UPDATE cases SET document_json=?1 WHERE id=?2",
            rusqlite::params![serde_json::to_string(&case).unwrap(), case.id],
        )
        .unwrap();
        db.execute("DELETE FROM case_events WHERE event_type IN ('cloudflare_audit.outcome_recorded','report.terminal_snapshot_saved')", []).unwrap();
        let before = f.storage().snapshot_case_for_archive(&case.id).unwrap();
        assert!(invoke()["result"].get("outcome_run").is_none());
        let after = f.storage().snapshot_case_for_archive(&case.id).unwrap();
        assert_eq!(before.events, after.events);
        assert_eq!(before.document_json, after.document_json);
        assert_eq!(before.revision, after.revision);
    }
}
