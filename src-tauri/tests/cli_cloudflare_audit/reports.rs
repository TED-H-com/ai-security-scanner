use super::{admit, finalize, fixture::*};
use ai_security_scanner_lib::{
    beginner_report::build_beginner_master_report,
    export::{ExportOptions, RedactionProfile, ReportLocale},
    report_renderer::{render_canonical_json, render_html},
    report_snapshot::{ReportDocumentFormat, ReportSnapshot},
};

fn options(locale: ReportLocale, redaction: RedactionProfile) -> ExportOptions {
    ExportOptions {
        locale,
        redaction,
        ..Default::default()
    }
}
fn render(case: &AssessmentCase, run: &str, options: &ExportOptions) -> (String, Value) {
    (
        String::from_utf8(render_html(case, run, options, &[]).unwrap()).unwrap(),
        serde_json::from_slice(&render_canonical_json(case, run, options).unwrap()).unwrap(),
    )
}
fn append_scanner_run(case: &mut AssessmentCase) -> String {
    fn bind(value: &mut Value, id: &str) {
        match value {
            Value::Object(fields) => {
                for (key, value) in fields {
                    if key == "case_id" {
                        *value = json!(id);
                    } else {
                        bind(value, id);
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    bind(value, id);
                }
            }
            _ => {}
        }
    }
    let mut scanner = json!(ai_security_scanner_lib::demo::build_demo_case());
    bind(&mut scanner, &case.id);
    let scanner: AssessmentCase = serde_json::from_value(scanner).unwrap();
    let run = scanner.scan_runs[0].id.clone();
    case.scan_runs.extend(scanner.scan_runs);
    case.assets.extend(scanner.assets);
    case.raw_artifacts.extend(scanner.raw_artifacts);
    case.findings.extend(scanner.findings);
    case.finding_observations
        .extend(scanner.finding_observations);
    run
}
fn assert_audit_continuation_step(case: &AssessmentCase, run_id: &str, path: &str) {
    use ai_security_scanner_lib::beginner_report::NextActionCode;
    let action = "Continue the source audit from the listed paths.";
    for locale in [ReportLocale::En, ReportLocale::ZhHant] {
        let (heading, not_tested, translated) = match locale {
            ReportLocale::En => ("What to do next", "What was not tested", action),
            ReportLocale::ZhHant => (
                "下一步怎麼做",
                "未測試項目",
                "請從列出的路徑繼續原始碼稽核。",
            ),
        };
        for redaction in [RedactionProfile::None, RedactionProfile::Standard] {
            let (html, document) = render(case, run_id, &options(locale, redaction));
            let report = &document["report"];
            let steps = report["next_steps"].as_array().unwrap();
            let audit_steps: Vec<_> = steps.iter().filter(|s| s["task_id"].is_string()).collect();
            assert_eq!(audit_steps.len(), 1);
            assert_eq!(audit_steps[0]["action"], action);
            assert_eq!(audit_steps[0]["code"], json!(NextActionCode::RetryCheck));
            for step in steps {
                let action = step["action"].as_str().unwrap();
                assert!(!action.contains(path));
                assert!(!action.contains("[redacted location]"));
                assert!(!step["reason"].as_str().unwrap().contains("out_of_scope"));
            }
            for gap in report["coverage_gaps"].as_array().unwrap() {
                if gap["kind"] == "excluded" {
                    assert_eq!(gap["next_action"], "");
                    assert_eq!(
                        gap["next_action_code"],
                        json!(NextActionCode::NoActionUnlessScopeChanges)
                    );
                } else {
                    assert_eq!(gap["next_action"], action);
                    assert_eq!(gap["next_action_code"], json!(NextActionCode::RetryCheck));
                }
            }
            let rendered_steps = html
                .split(&format!("<h2>{heading}</h2>"))
                .nth(1)
                .unwrap()
                .split("</section>")
                .next()
                .unwrap();
            assert_eq!(
                rendered_steps
                    .matches(&format!("<strong>{translated}</strong>"))
                    .count(),
                1
            );
            let has_validation = report["source_audits"]
                .as_array()
                .unwrap()
                .iter()
                .any(|audit| !audit["to_validate"].as_array().unwrap().is_empty());
            assert_eq!(
                rendered_steps.matches("<li>").count(),
                1 + usize::from(has_validation)
            );
            for action in rendered_steps.split("<strong>").skip(1) {
                let action = action.split("</strong>").next().unwrap();
                assert!(!action.contains(path));
                assert!(!action.contains("[redacted location]"));
            }
            let untested = html
                .split(&format!("<h3>{not_tested}</h3>"))
                .nth(1)
                .unwrap()
                .split("<details")
                .next()
                .unwrap();
            if redaction == RedactionProfile::None {
                assert!(untested.contains(path));
                assert!(
                    report["source_audits"][0]["technical_detail"]
                        .to_string()
                        .contains(path)
                );
            } else {
                assert!(!untested.contains(path));
                assert!(untested.contains(if locale == ReportLocale::En {
                    "[redacted location]"
                } else {
                    "（已遮蔽位置）"
                }));
            }
        }
    }
}

#[test]
fn quick_incomplete_audit_has_one_product_continuation_step_in_both_locales_and_profiles() {
    let (run, request) = admit::sealed("quick");
    let saved = admit::admit(&run, &request, 0);
    assert_audit_continuation_step(
        &admit::case(&run),
        saved["run_id"].as_str().unwrap(),
        "src/a.rs",
    );
}

#[test]
fn complete_audit_with_only_validation_records_has_validation_asset_action() {
    let run = RunFixture::with_records("standard", &[], |records, ledger, _| {
        *records = json!([records[1].clone()]);
        ledger[0]["result_fingerprints"] = json!([records[0]["fingerprint"]]);
        ledger[0]["excluded_blocks"] = json!([]);
    });
    finalize::finalize(&run, &finalize::request(&run), 0);
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
        "request_id":"admit-validation-only", "case_id":run.f.case_id,
        "session_id":run.prepared["session_id"],
        "expected_sealed_entry_sha256":verified.digests.sealed_entry_sha256,
        "expected_bundle_sha256":verified.digests.bundle_sha256,
        "expected_projection_sha256":verified.digests.projection_sha256,
    });
    drop(verified);
    drop(storage);
    let saved = admit::admit(&run, &request, 0);
    let case = admit::case(&run);
    let run_id = saved["run_id"].as_str().unwrap();
    let report = build_beginner_master_report(&case, run_id).unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.source_audits[0].to_validate.len(), 1);
    assert!(report.source_audits[0].unresolved_candidates.is_empty());
    assert!(report.source_audits[0].coverage_gaps.is_empty());
    assert!(report.coverage_gaps.is_empty());
    for (locale, action) in [
        (
            ReportLocale::En,
            "validate the listed source-audit items first",
        ),
        (ReportLocale::ZhHant, "請先驗證列出的原始碼稽核項目"),
    ] {
        let (html, _) = render(&case, run_id, &options(locale, RedactionProfile::None));
        let card = html
            .split("<tr class=\"asset-result asset-result--no-problems-completed\">")
            .nth(1)
            .unwrap()
            .split("</tr>")
            .next()
            .unwrap();
        assert!(card.contains(action));
    }
}

#[test]
fn admitted_reports_keep_native_sections_counts_and_localized_first_layer() {
    for profile in ["standard", "quick"] {
        let (run, request) = admit::sealed(profile);
        let saved = admit::admit(&run, &request, 0);
        assert_eq!(saved["result"]["report_snapshot_state"], "retained");
        let mut case = admit::case(&run);
        let run_id = saved["run_id"].as_str().unwrap();
        // No current authorization, source directory, or catalog is consulted.
        case.scope_grants.clear();
        case.data_sources.clear();
        let report = build_beginner_master_report(&case, run_id).unwrap();
        let a = &report.source_audits[0];
        let stored = &case.agent_audit_admissions[0];
        assert_eq!(a.method.counts_by_role, stored.counts_by_role);
        assert_eq!(a.method.counts_by_state, stored.counts_by_state);
        assert!(!a.method.counts_by_role.is_empty());
        assert_eq!(a.method.issued_invocations, stored.method.budget.issued);
        assert_eq!(
            a.method.declared_invocation_limit,
            stored.method.budget.limit
        );
        assert_eq!(
            a.method.remaining_invocations,
            stored.method.budget.remaining
        );
        assert_eq!(a.method.provenance, "workflow_recorded");
        assert!(!a.method.validators_reexecuted);
        assert_eq!(
            a.technical_detail.coverage_ledger,
            stored.retained_projection["native_coverage_ledger"]
        );
        assert_eq!(a.technical_detail.custody_digests, json!(stored.digests));
        assert_eq!(a.technical_detail.originals, json!(stored.artifacts));
        if profile == "quick" {
            assert_eq!(a.coverage_gaps[0].continuation_paths, vec!["src/a.rs"]);
        } else {
            assert!(a.coverage_gaps.is_empty());
        }
        assert_eq!(a.to_validate.len(), 1);
        assert!(!json!(a.to_validate).to_string().contains("severity"));
        assert_eq!(
            report.findings.len(),
            if profile == "quick" { 0 } else { 1 }
        );
        if profile == "standard" {
            assert_eq!(
                report.findings[0].possible_impact,
                run.findings[0]["severity"]["impact"]["reason"]
            );
            assert_eq!(
                report.findings[0].next_step,
                run.findings[0]["remediation"]["strategy"]
            );
            assert!(
                report
                    .next_steps
                    .iter()
                    .any(|s| s.action == report.findings[0].next_step)
            );
        }
        for (locale, validate, incomplete, zero) in [
            (
                ReportLocale::En,
                "To validate",
                "Source audit incomplete: 1 unit remains. Continue with the listed paths.",
                "No confirmed findings in the recorded checks.",
            ),
            (
                ReportLocale::ZhHant,
                "待驗證",
                "原始碼稽核未完成：尚有 1 個單元未完成。請從列出的路徑繼續。",
                "已記錄的檢查中未發現已確認問題。",
            ),
        ] {
            let (html, json) = render(&case, run_id, &options(locale, RedactionProfile::None));
            let first_layer = html.split("<details class=\"technical\">").next().unwrap();
            let expected = match (locale, profile) {
                (ReportLocale::En, "quick") => {
                    "Validate the 1 source-audit item under To validate first."
                }
                (ReportLocale::En, _) => "Also validate the 1 source-audit item under To validate.",
                (ReportLocale::ZhHant, "quick") => "請先驗證「待驗證」中的 1 個原始碼稽核項目。",
                (ReportLocale::ZhHant, _) => "另請驗證「待驗證」中的 1 個原始碼稽核項目。",
            };
            assert!(first_layer.contains(expected));
            if profile == "quick" {
                assert!(!first_layer.contains(if locale == ReportLocale::En {
                    "The first thing to do is:"
                } else {
                    "建議最先處理的是："
                }));
                assert!(first_layer.contains(if locale == ReportLocale::En {
                    "Then continue the source audit from the listed paths."
                } else {
                    "接著請從列出的路徑繼續原始碼稽核。"
                }));
            }
            let next_steps = html
                .split(if locale == ReportLocale::En {
                    "What to do next</h2>"
                } else {
                    "下一步怎麼做</h2>"
                })
                .nth(1)
                .unwrap()
                .split("</ol>")
                .next()
                .unwrap();
            assert!(next_steps.contains(if locale == ReportLocale::En {
                "Validate the 1 source-audit item under To validate."
            } else {
                "請驗證「待驗證」中的 1 個原始碼稽核項目。"
            }));
            if profile == "standard" {
                let first_action = if locale == ReportLocale::En {
                    "Start with “"
                } else {
                    "最先處理「"
                };
                assert!(
                    first_layer.find(first_action).unwrap() < first_layer.find(expected).unwrap()
                );
            }
            // Quick remains incomplete; standard has a confirmed problem.
            // Neither status is eligible for the clean-asset action override.
            assert!(html.contains(if profile == "quick" {
                "<tr class=\"asset-result asset-result--incomplete-failed\">"
            } else {
                "<tr class=\"asset-result asset-result--problems-found\">"
            }));
            assert!(!html.contains(if locale == ReportLocale::En {
                "validate the listed source-audit items first"
            } else {
                "請先驗證列出的原始碼稽核項目"
            }));
            assert!(html.contains(validate));
            assert!(html.contains("src/a.rs"));
            assert!(html.contains("<details class=\"technical\"><summary>"));
            assert_eq!(json["report"]["source_audits"][0], json!(a));
            if profile == "quick" {
                assert!(html.contains(incomplete));
                assert!(html.contains(zero));
                assert!(html.contains("Host stopped after source review"));
                assert_eq!(a.unresolved_candidates, vec!["unresolved-one"]);
            } else {
                assert!(
                    html.contains(
                        run.findings[0]["severity"]["impact"]["reason"]
                            .as_str()
                            .unwrap()
                    )
                );
                assert!(
                    html.contains(run.findings[0]["remediation"]["strategy"].as_str().unwrap())
                );
                assert!(html.contains(run.findings[2]["reason"].as_str().unwrap()));
            }
            let validation = html
                .split(&format!("<h3>{validate}</h3>"))
                .nth(1)
                .unwrap()
                .split("<details")
                .next()
                .unwrap();
            assert!(validation.contains(a.to_validate[0].native_record["title"].as_str().unwrap()));
            assert!(!validation.contains("pill--"));
        }
    }
}

#[test]
fn snapshots_replay_exact_bytes_and_combined_sources_keep_their_own_times() {
    use ai_security_scanner_lib::selected_run_report::{
        SelectedRunOrigin, preview_selected_run_report,
    };
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let mut case = admit::case(&run);
    let audit_run = saved["run_id"].as_str().unwrap().to_owned();
    fn bind_case(value: &mut Value, id: &str) {
        match value {
            Value::Object(fields) => {
                for (key, value) in fields {
                    if key == "case_id" {
                        *value = json!(id);
                    } else {
                        bind_case(value, id);
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    bind_case(value, id);
                }
            }
            _ => {}
        }
    }
    let mut scanner = json!(ai_security_scanner_lib::demo::build_demo_case());
    bind_case(&mut scanner, &case.id);
    let scanner: AssessmentCase = serde_json::from_value(scanner).unwrap();
    let scanner_run = scanner.scan_runs[0].id.clone();
    case.raw_artifacts.extend(scanner.raw_artifacts);
    case.scan_runs.extend(scanner.scan_runs);
    case.assets.extend(scanner.assets);
    case.findings.extend(scanner.findings);
    case.finding_observations
        .extend(scanner.finding_observations);
    for bytes in [
        ai_security_scanner_lib::exporters::export_master_framework_report_bytes(
            &case,
            &scanner_run,
        )
        .unwrap(),
        ai_security_scanner_lib::exporters::export_ocsf_finding_events_bytes(&case, &scanner_run)
            .unwrap(),
        ai_security_scanner_lib::exporters::export_oscal_assessment_results_bytes(
            &case,
            &scanner_run,
        )
        .unwrap(),
    ] {
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains(&case.agent_audit_admissions[0].admission_id));
        assert!(!text.contains(&case.agent_audit_admissions[0].provider_id));
    }
    let selected = vec![scanner_run, audit_run.clone()];
    let opts = options(ReportLocale::ZhHant, RedactionProfile::None);
    let combined = preview_selected_run_report(&case, &selected, &opts).unwrap();
    assert_eq!(
        combined.sources[0].origin,
        SelectedRunOrigin::RecordedChecks
    );
    assert_eq!(combined.sources[1].origin, SelectedRunOrigin::SourceAudit);
    assert_eq!(combined.sources[1].created_at, case.scan_runs[0].created_at);
    assert_eq!(combined.sources[1].report.findings.len(), 1);
    assert!(combined.sources[0].report.source_audits.is_empty());
    let single = ReportSnapshot::capture(
        &case,
        &audit_run,
        opts.clone(),
        &run.f.data.join("artifacts"),
    )
    .unwrap();
    let combined = ReportSnapshot::capture_combined(&case, &selected, opts).unwrap();
    for (index, snapshot) in [single, combined].iter().enumerate() {
        assert!(snapshot.verify().unwrap().replay_available);
        for (suffix, format) in [
            ("html", ReportDocumentFormat::Html),
            ("json", ReportDocumentFormat::Json),
        ] {
            let dest = run
                .f
                .data
                .with_file_name(format!("replay-{index}.{suffix}"));
            snapshot.replay(format, &dest).unwrap();
            let original = run
                .f
                .data
                .with_file_name(format!("original-{index}.{suffix}"));
            snapshot.retrieve(format, &original).unwrap();
            assert_eq!(fs::read(&dest).unwrap(), fs::read(original).unwrap());
            if suffix == "html" {
                assert!(
                    String::from_utf8(fs::read(dest).unwrap())
                        .unwrap()
                        .contains("原始碼稽核")
                );
            }
        }
    }
    assert!(
        ai_security_scanner_lib::diff::compare_case_runs(&case, &selected[0], &audit_run).is_err()
    );
}

#[test]
fn pending_snapshot_replay_preserves_receipt_and_recovery_never_starts_work() {
    for use_recovery in [false, true] {
        let (run, request) = admit::sealed("quick");
        let db = rusqlite::Connection::open(run.f.data.join("casework.db")).unwrap();
        db.execute_batch("CREATE TRIGGER fail_snapshot BEFORE INSERT ON case_events WHEN NEW.event_type='report.terminal_snapshot_saved' BEGIN SELECT RAISE(ABORT, 'injected snapshot failure'); END;").unwrap();
        let saved = admit::admit(&run, &request, 0);
        assert_eq!(saved["result"]["report_snapshot_state"], "pending");
        assert_eq!(saved["result"]["report_snapshot_retry_command"][2], "admit");
        assert_eq!(admit::status(&run)["next_operation"], "admit_replay");
        assert!(admit::case(&run).run_report_snapshots.is_empty());
        let directory = run
            .f
            .data
            .join("artifacts")
            .join(&run.f.case_id)
            .join("report-snapshots");
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        let run_id = saved["run_id"].as_str().unwrap();
        let recover = |expected| {
            terminal(
                run.f
                    .command()
                    .args([
                        "scan",
                        "recover",
                        "--case-id",
                        &run.f.case_id,
                        "--run-id",
                        run_id,
                        "--wait",
                    ])
                    .output()
                    .unwrap(),
                expected,
            )
        };
        assert_eq!(
            saved["result"]["report_snapshot_error_code"],
            "storage_failed"
        );
        assert_eq!(saved["result"]["report_snapshot_retryable"], true);
        let failed = recover(4);
        assert_eq!(failed["retryable"], true);
        assert_eq!(failed["error_code"], "storage_failed");
        assert_eq!(
            failed["result"]["report_snapshot_error_code"],
            "storage_failed"
        );
        assert_eq!(failed["result"]["report_snapshot_retryable"], true);
        let status = admit::status(&run);
        assert_eq!(status["report_snapshot_error_code"], "not_available");
        assert_eq!(status["report_snapshot_retryable"], false);
        db.execute_batch("DROP TRIGGER fail_snapshot").unwrap();
        let intact_case = admit::case(&run);
        let mut unavailable = intact_case.clone();
        unavailable.agent_audit_admissions.clear();
        db.execute(
            "UPDATE cases SET document_json=?1 WHERE id=?2",
            rusqlite::params![serde_json::to_string(&unavailable).unwrap(), run.f.case_id],
        )
        .unwrap();
        let failed = recover(2);
        assert_eq!(failed["retryable"], false);
        assert_eq!(failed["error_code"], "not_available");
        assert_eq!(
            failed["result"]["report_snapshot_error_code"],
            "not_available"
        );
        assert_eq!(failed["result"]["report_snapshot_retryable"], false);
        db.execute(
            "UPDATE cases SET document_json=?1 WHERE id=?2",
            rusqlite::params![serde_json::to_string(&intact_case).unwrap(), run.f.case_id],
        )
        .unwrap();
        if use_recovery {
            let recovered = recover(0);
            assert_eq!(recovered["result"]["report_snapshot_state"], "retained");
        }
        let replay = admit::admit(&run, &request, 0);
        assert_eq!(replay["receipt"], saved["receipt"]);
        assert_eq!(replay["result"]["report_snapshot_state"], "retained");
        assert_eq!(admit::status(&run)["next_operation"], "retrieve_report");
        let before = json!(admit::case(&run));
        let recovered = recover(0);
        assert_eq!(
            recovered["result"]["report_snapshot"],
            replay["result"]["report_snapshot"]
        );
        assert_eq!(json!(admit::case(&run)), before);
        assert_eq!(fs::read_dir(directory).unwrap().count(), 1);
        let path = run.f.data.join("artifacts").join(
            replay["result"]["report_snapshot"]["snapshot"]["relative_path"]
                .as_str()
                .unwrap(),
        );
        let original = fs::read(&path).unwrap();
        fs::write(&path, b"damaged saved report").unwrap();
        let damaged_status = admit::status(&run);
        assert_eq!(damaged_status["report_snapshot_state"], "pending");
        assert_eq!(
            damaged_status["report_snapshot"],
            replay["result"]["report_snapshot"]
        );
        assert_eq!(
            damaged_status["report_snapshot_error_code"],
            "invalid_request"
        );
        assert_eq!(damaged_status["report_snapshot_retryable"], false);
        assert_eq!(
            admit::admit(&run, &request, 0)["result"]["report_snapshot_state"],
            "pending"
        );
        let failed = recover(2);
        assert_eq!(failed["retryable"], false);
        assert_eq!(failed["result"]["report_snapshot_retryable"], false);
        assert_eq!(fs::read(&path).unwrap(), b"damaged saved report");
        fs::write(&path, original).unwrap();
        assert_eq!(admit::status(&run)["report_snapshot_state"], "retained");
    }
}

const HOSTILE: &str = "private-report-identifier [redacted location] </pre></script><script>alert(1)</script><svg onload=alert(2)><img src=x onerror=alert(3)> \" '& [link](javascript:alert(4)) ![image](data:text/html,x) file:///private/秘密.rs \u{0001}\u{202e} Unicode/資料.rs\n$(touch forbidden); `echo danger`  \n  ";
const CODE: &str = "PRIVATE-CODE-ONLY\n<script>code()</script>\n$(touch forbidden)  \n  ";
#[test]
fn hostile_native_text_is_inert_and_standard_withholds_code_in_all_copies() {
    let mut run = RunFixture::with_records("standard", &[], |records, ledger, _| {
        for r in records.as_array_mut().unwrap() {
            for key in [
                "title",
                "description",
                "root_cause",
                "claimed_root_cause",
                "intended_behavior",
                "reason",
            ] {
                if r.get(key).is_some() {
                    r[key] = json!(HOSTILE);
                }
            }
            for field in ["trace", "evidence"] {
                for loc in r[field].as_array_mut().unwrap() {
                    loc["description"] = json!(HOSTILE);
                    if loc.get("scope").is_some() {
                        loc["scope"] = json!(HOSTILE);
                    }
                }
            }
        }
        records[0]["conditions"] = json!([{"kind":"data_state","description":HOSTILE}]);
        for key in ["attacker_perspective", "observed_result"] {
            records[0]["execution"][key] = json!(HOSTILE);
        }
        records[0]["execution"]["payloads"] = json!([CODE]);
        records[0]["execution"]["instructions"] = json!([CODE]);
        records[0]["remediation"] = json!({"strategy":HOSTILE,"code_changes":[{"file_name":"Unicode/資料.rs","fixed_code":CODE}]});
        for kind in ["likelihood", "impact"] {
            records[0]["severity"][kind]["reason"] = json!(HOSTILE);
        }
        records[0]["confidence"]["reason"] = json!(HOSTILE);
        records[1]["blockers"] = json!([HOSTILE]);
        records[1]["validation_plan"] = json!({"local":HOSTILE,"deployment":HOSTILE});
        ledger[0]["local_checks"][0]["invariant"] = json!(HOSTILE.trim());
        ledger[0]["local_checks"][0]["result"] = json!(HOSTILE.trim());
        ledger[0]["excluded_blocks"][0]["reason"] = json!(HOSTILE.trim());
    });
    let first_check = run.ledger[0]["local_checks"][0].clone();
    let attempt = json!({"wave":1,"status":"blocked","agent_id":run.hunter["agent_id"],"reviewed_paths":["src/a.rs"],"local_checks":[first_check],"result_fingerprints":[],"unresolved":[HOSTILE.trim()],"reassignment_reason":HOSTILE.trim()});
    let mut second = attempt.clone();
    let owner = run.issue(json!({"role":"hunter","wave":2}));
    run.submit(&owner, b"{}");
    second["wave"] = json!(2);
    second["agent_id"] = owner["agent_id"].clone();
    second["local_checks"][0]["agent_id"] = owner["agent_id"].clone();
    second["reassignment_reason"] = json!("Second recorded attempt");
    let owner = run.issue(json!({"role":"hunter","wave":3}));
    run.submit(&owner, b"{}");
    run.ledger[0]["agent_id"] = owner["agent_id"].clone();
    run.ledger[0]["local_checks"][0]["agent_id"] = owner["agent_id"].clone();
    run.ledger[0]["wave"] = json!(3);
    run.ledger[0]["attempts"] = json!([attempt, second]);
    for wave in [2, 3] {
        let critic = run.issue(json!({"role":"post_wave_critic","wave":wave}));
        run.submit(&critic, b"{}");
    }
    run.documents(&["coverage-ledger.json"]);
    finalize::finalize(&run, &finalize::request(&run), 0);
    let storage = run.f.storage();
    let verified = ai_security_scanner_lib::cloudflare_provider::audit::sealed::verify(
        &run.f.data,
        &storage,
        &run.f.case_id,
        run.prepared["session_id"].as_str().unwrap(),
    )
    .unwrap();
    let req = json!({"schema_version":"ai-security-scanner.cloudflare-audit-admit-request/v1","request_id":"admit-hostile","case_id":run.f.case_id,"session_id":run.prepared["session_id"],
        "expected_sealed_entry_sha256":verified.digests.sealed_entry_sha256,"expected_bundle_sha256":verified.digests.bundle_sha256,"expected_projection_sha256":verified.digests.projection_sha256});
    drop(verified);
    drop(storage);
    let saved = admit::admit(&run, &req, 0);
    assert_eq!(saved["result"]["report_snapshot_state"], "retained");
    let mut case = admit::case(&run);
    case.title = "private-report-identifier".into();
    let run_id = saved["run_id"].as_str().unwrap();
    let hashes = json!(case.agent_audit_admissions[0].digests);
    let scanner_run = append_scanner_run(&mut case);
    for locale in [ReportLocale::En, ReportLocale::ZhHant] {
        for redaction in [RedactionProfile::None, RedactionProfile::Standard] {
            let opts = options(locale, redaction);
            let (html, document) = render(&case, run_id, &opts);
            for forbidden in [
                "<script>",
                "<svg onload",
                "<img src=x",
                "href=\"javascript:",
                "href=\"data:",
                "href=\"file:",
            ] {
                assert!(!html.contains(forbidden), "{forbidden}");
            }
            if redaction == RedactionProfile::None {
                assert!(html.contains("&lt;script&gt;"));
                assert!(html.contains("![image](data:text/html,x)"));
            } else {
                // The hostile string also occurs as an unresolved fingerprint;
                // its title occurrences therefore use the same pseudonym.
                assert!(!html.contains("alert(1)"));
            }
            let combined =
                ai_security_scanner_lib::selected_run_report::preview_selected_run_report(
                    &case,
                    &[run_id.to_owned(), scanner_run.clone()],
                    &opts,
                )
                .unwrap();
            let combined_json = json!(combined);
            let destination = run.f.data.with_file_name(format!(
                "combined-{}-{}.html",
                locale.as_str(),
                redaction.as_str()
            ));
            ai_security_scanner_lib::selected_run_report::export_selected_run_report(
                &case,
                &[run_id.to_owned(), scanner_run.clone()],
                ai_security_scanner_lib::selected_run_report::SelectedRunReportFormat::Html,
                &destination,
                &opts,
            )
            .unwrap();
            let combined_html = fs::read_to_string(destination).unwrap();
            if redaction == RedactionProfile::Standard {
                assert!(!combined_html.contains("PRIVATE-CODE-ONLY"));
                assert!(!combined_html.contains("private-report-identifier"));
                assert!(combined_html.contains(if locale == ReportLocale::En {
                    "Source code or credentials may permit unauthorized access"
                } else {
                    "原始碼或憑證可能導致未授權存取"
                }));
            } else {
                assert!(combined_html.contains("[redacted location]"));
            }
            assert_eq!(combined_json["sources"][0]["report"], document["report"]);
            let audit = &document["report"]["source_audits"][0];
            assert_eq!(audit["technical_detail"]["custody_digests"], hashes);
            assert_eq!(
                audit["technical_detail"]["coverage_ledger"][0]["attempts"][0]["wave"],
                1
            );
            assert_eq!(
                audit["technical_detail"]["coverage_ledger"][0]["attempts"][1]["wave"],
                2
            );
            assert_eq!(
                audit["technical_detail"]["admission_sha256"],
                case.agent_audit_admissions[0].admission_sha256
            );
            if redaction == RedactionProfile::None {
                assert!(html.contains("PRIVATE-CODE-ONLY"));
                assert!(html.contains("[redacted location]"));
                assert_eq!(
                    document["report"]["findings"][0]["plain_language_risk"],
                    HOSTILE
                );
                assert_eq!(
                    document["report"]["findings"][0]["possible_impact"],
                    HOSTILE
                );
                assert_eq!(document["report"]["findings"][0]["next_step"], HOSTILE);
                assert_eq!(
                    audit["technical_detail"]["confirmed"][0]["native_record"],
                    run.findings[0]
                );
            } else {
                assert!(!html.contains("PRIVATE-CODE-ONLY"));
                assert!(!document.to_string().contains("PRIVATE-CODE-ONLY"));
                assert!(!html.contains("private-report-identifier"));
                assert!(!document.to_string().contains("private-report-identifier"));
                assert_eq!(audit["withheld_code_fields"], 3);
                assert!(audit["withheld_text_fields"].as_u64().unwrap() > 40);
                let withheld = "[withheld provider text in the standard profile]";
                let confirmed = &audit["technical_detail"]["confirmed"][0]["native_record"];
                for pointer in [
                    "/description",
                    "/root_cause",
                    "/intended_behavior",
                    "/trace/0/description",
                    "/trace/0/scope",
                    "/evidence/0/description",
                    "/conditions/0/description",
                    "/execution/attacker_perspective",
                    "/execution/observed_result",
                    "/remediation/strategy",
                    "/severity/likelihood/reason",
                    "/severity/impact/reason",
                    "/confidence/reason",
                ] {
                    assert_eq!(confirmed.pointer(pointer).unwrap(), withheld, "{pointer}");
                }
                assert_eq!(confirmed["trace"][0]["file"], "[redacted location]");
                assert_eq!(
                    confirmed["remediation"]["code_changes"][0]["file_name"],
                    "[redacted location]"
                );
                assert_eq!(
                    confirmed["severity"]["overall_severity"],
                    run.findings[0]["severity"]["overall_severity"]
                );
                assert_eq!(
                    confirmed["trace"][0]["kind"],
                    run.findings[0]["trace"][0]["kind"]
                );
                let pending = &audit["to_validate"][0]["native_record"];
                for pointer in [
                    "/description",
                    "/claimed_root_cause",
                    "/blockers/0",
                    "/validation_plan/local",
                    "/validation_plan/deployment",
                ] {
                    assert_eq!(pending.pointer(pointer).unwrap(), withheld);
                }
                assert_eq!(
                    audit["technical_detail"]["rejected"][0]["native_record"]["reason"],
                    withheld
                );
                let ledger = &audit["technical_detail"]["coverage_ledger"][0];
                for pointer in [
                    "/local_checks/0/invariant",
                    "/local_checks/0/result",
                    "/excluded_blocks/0/reason",
                    "/attempts/0/reassignment_reason",
                ] {
                    assert_eq!(ledger.pointer(pointer).unwrap(), withheld, "{pointer}");
                }
                assert!(
                    ledger["attempts"][0]["unresolved"][0]
                        .as_str()
                        .unwrap()
                        .starts_with("fp-")
                );
                assert_eq!(ledger["starting_paths"][0], "[redacted location]");
                assert_eq!(ledger["excluded_blocks"][0]["block"], "[redacted location]");
                assert_eq!(ledger["canonical_refs"]["surface"], "[redacted location]");
                assert_eq!(
                    ledger["attempts"][0]["reviewed_paths"][0],
                    "[redacted location]"
                );
                assert_eq!(
                    audit["technical_detail"]["lineage"]["source"]["scope"][0],
                    "[redacted location]"
                );
                assert_eq!(
                    audit["technical_detail"]["lineage"]["source"]["source_ref"],
                    "[redacted location]"
                );
                let finding = &document["report"]["findings"][0];
                assert_eq!(
                    finding["plain_language_risk"],
                    "Cloudflare source audit reported a medium-severity condition on the assessed asset."
                );
                assert_eq!(
                    finding["possible_impact"],
                    "Source code or credentials may permit unauthorized access or unsafe application behavior."
                );
                assert!(
                    finding["next_step"]
                        .as_str()
                        .unwrap()
                        .starts_with("Change the code to remove the reported unsafe pattern")
                );
                for sentence in if locale == ReportLocale::En {
                    [
                        "reported a medium-severity condition on the assessed asset.",
                        "Source code or credentials may permit unauthorized access or unsafe application behavior.",
                        "Change the code to remove the reported unsafe pattern",
                    ]
                } else {
                    [
                        "在受評估的資產上回報了一項中等級的狀況。",
                        "原始碼或憑證可能導致未授權存取或不安全的程式行為。",
                        "修改程式碼以移除回報的不安全寫法",
                    ]
                } {
                    assert!(html.contains(sentence), "missing {sentence}");
                }
                if locale == ReportLocale::ZhHant {
                    assert!(html.contains("原始碼稽核涵蓋範圍"));
                    assert!(html.contains("已記錄的原始碼稽核"));
                }
                assert_eq!(
                    finding["evidence_references"][0]["scanner_details"]["description"],
                    withheld
                );
                assert_eq!(
                    finding["evidence_references"][0]["provider_record"]["source_locators"][0]["path"],
                    "[redacted location]"
                );
                assert_eq!(
                    document["report"]["actual"]["checks"][0]["tested_dimensions"][0]["value"],
                    "[redacted location]"
                );
                if locale == ReportLocale::ZhHant {
                    assert!(html.contains("（已遮蔽位置）"));
                }
                assert!(html.contains(if locale == ReportLocale::En {
                    "withheld in the standard profile"
                } else {
                    "已在標準設定檔中隱藏"
                }));
            }
        }
    }
    let mut hostile_case = case.clone();
    fn hostile_strings(value: &mut Value, key: &str) {
        match value {
            Value::Object(fields) => {
                for (key, value) in fields {
                    hostile_strings(value, key);
                }
            }
            Value::Array(values) => {
                for value in values {
                    hostile_strings(value, key);
                }
            }
            Value::String(text)
                if !key.ends_with("sha256")
                    && !matches!(key, "provenance" | "verdict" | "severity") =>
            {
                *text = HOSTILE.into()
            }
            _ => {}
        }
    }
    let a = &mut hostile_case.agent_audit_admissions[0];
    hostile_strings(&mut a.retained_projection, "");
    a.source.scope = vec![HOSTILE.into()];
    a.source.source_ref = HOSTILE.into();
    a.source.policy_id = HOSTILE.into();
    a.verification_scope = HOSTILE.into();
    for original in &mut a.artifacts {
        original.member_path = HOSTILE.into();
    }
    for locale in [ReportLocale::En, ReportLocale::ZhHant] {
        let (html, json) = render(
            &hostile_case,
            run_id,
            &options(locale, RedactionProfile::None),
        );
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<svg onload"));
        assert!(!html.contains("href=\"javascript:"));
        assert!(!html.contains("href=\"data:"));
        assert!(!html.contains("href=\"file:"));
        assert!(html.contains("&lt;script&gt;"));
        assert_eq!(
            json["report"]["source_audits"][0]["technical_detail"]["custody_digests"],
            hashes
        );
    }
    // Rendering never mutates the stored admission or raw artifact hashes.
    let stored = admit::case(&run);
    assert_eq!(
        stored.agent_audit_admissions[0].retained_projection["records"][0]["native_record"],
        run.findings[0]
    );
    ai_security_scanner_lib::artifact_store::inspect_raw_artifacts(
        &run.f.data.join("artifacts"),
        &stored.raw_artifacts,
    )
    .unwrap();
}

#[test]
fn report_cli_accepts_admitted_runs_bundles_attachments_and_complete_archives() {
    use ai_security_scanner_lib::{case_service::CaseExportFormat, case_service::CaseService};
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let run_id = saved["run_id"].as_str().unwrap();
    for format in ["html", "json", "framework-report", "ocsf", "oscal"] {
        let dest = run.f.data.with_file_name(format!("export.{format}"));
        let out = run
            .f
            .command()
            .args([
                "export",
                "create",
                "--case-id",
                &run.f.case_id,
                "--run-id",
                run_id,
                "--format",
                format,
                "--destination",
            ])
            .arg(&dest)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(dest.exists());
    }
    let snapshot = run.f.data.with_file_name("manual.snapshot.json");
    let out = run
        .f
        .command()
        .args([
            "report",
            "snapshot",
            "--case-id",
            &run.f.case_id,
            "--run-id",
            run_id,
            "--acknowledge-private-context",
            "--destination",
        ])
        .arg(&snapshot)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for operation in ["retrieve", "replay"] {
        let dest = run.f.data.with_file_name(format!("{operation}.html"));
        let out = run
            .f
            .command()
            .args(["report", operation, "--snapshot"])
            .arg(&snapshot)
            .args(["--format", "html", "--destination"])
            .arg(&dest)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert_eq!(
        fs::read(run.f.data.with_file_name("retrieve.html")).unwrap(),
        fs::read(run.f.data.with_file_name("replay.html")).unwrap()
    );
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
    let dest = run.f.data.with_file_name("admitted.case.tar.gz");
    {
        let format = CaseExportFormat::CaseBundle;
        assert!(
            service
                .preview_export(&run.f.case_id, run_id, format.clone(), &Default::default())
                .is_ok()
        );
        assert!(
            service
                .export_case(&run.f.case_id, run_id, format, &dest, Default::default())
                .is_ok()
        );
        assert!(dest.exists());
    }
    let mut combined_case = admit::case(&run);
    let scanner_run =
        super::bundles_attachments::add_scanner(&mut combined_case, &run.f.data.join("artifacts"));
    for redaction in [RedactionProfile::None, RedactionProfile::Standard] {
        let opts = ExportOptions {
            include_raw_artifacts: true,
            redaction,
            ..Default::default()
        };
        assert!(
            ReportSnapshot::capture(
                &admit::case(&run),
                run_id,
                opts.clone(),
                &run.f.data.join("artifacts")
            )
            .is_ok()
        );
        assert!(
            ReportSnapshot::capture_combined_with_originals(
                &combined_case,
                &[run_id.to_owned(), scanner_run.clone()],
                opts,
                &run.f.data.join("artifacts"),
                None
            )
            .is_ok()
        );
    }
    assert!(
        ai_security_scanner_lib::case_archive::create_archive(
            &run.f.data,
            &run.f.case_id,
            &run.f.data.with_file_name("complete-admitted.tar.gz"),
            &Default::default()
        )
        .is_ok()
    );
}

#[test]
fn ledger_statuses_incomplete_framing_and_empty_sections_follow_saved_projection() {
    use ai_security_scanner_lib::{
        cloudflare_provider::audit::sealed::TerminalState, provider_report::ProviderProvenance,
    };
    let (run, request) = admit::sealed("quick");
    let saved = admit::admit(&run, &request, 0);
    let mut case = admit::case(&run);
    let run_id = saved["run_id"].as_str().unwrap();
    let statuses = [
        "planned",
        "in_progress",
        "blocked",
        "deferred",
        "candidate",
        "out_of_scope",
        "not_applicable",
        "covered",
    ];
    let a = &mut case.agent_audit_admissions[0];
    a.provenance = ProviderProvenance::ReportedOnly;
    a.validators_reexecuted = true;
    a.retained_projection["native_coverage_ledger"] = json!(statuses.iter().map(|status| json!({"coverage_id":format!("private-unit-{status}"),"attack_class":"Access control","surface":"POST /users/:id","status":status,"starting_paths":["src/private.rs"],"result_fingerprints":["unresolved-one"],"unresolved":["private continuation reason"]})).chain(std::iter::once(json!({"coverage_id":"resolved","status":"candidate","starting_paths":["resolved.rs"],"result_fingerprints":["resolved-fingerprint"],"unresolved":[]}))).collect::<Vec<_>>());
    let report = build_beginner_master_report(&case, run_id).unwrap();
    let a = &report.source_audits[0];
    assert_eq!(a.method.provenance, "reported_only");
    assert!(a.method.validators_reexecuted);
    assert_eq!(report.coverage_gaps.len(), 2);
    assert_eq!(report.coverage_gaps[0].reason, "5 units remain.");
    assert_eq!(
        report.coverage_gaps[1].reason,
        "1 unit is outside the audit scope."
    );
    assert_eq!(a.coverage_gaps.len(), 6);
    assert_eq!(a.coverage_gaps.iter().filter(|g| g.remaining()).count(), 5);
    assert!(a.coverage_gaps[5].continuation_paths.is_empty());
    for gap in &report.coverage_gaps {
        assert_ne!(
            gap.next_action_code,
            ai_security_scanner_lib::beginner_report::NextActionCode::ReviewFinding
        );
        if gap.kind == ai_security_scanner_lib::beginner_report::CoverageGapKind::Excluded {
            assert!(gap.next_action.is_empty());
        }
    }
    for locale in [ReportLocale::En, ReportLocale::ZhHant] {
        let (html, _) = render(&case, run_id, &options(locale, RedactionProfile::None));
        assert!(html.contains(if locale == ReportLocale::En {
            "5 units remain"
        } else {
            "尚有 5 個單元"
        }));
        let first = html
            .split("<section class=\"source-audit report-card\">")
            .nth(1)
            .unwrap()
            .split("<details")
            .next()
            .unwrap();
        assert!(first.contains(if locale == ReportLocale::En {
            "Outside the audit scope"
        } else {
            "不在稽核範圍內"
        }));
        assert!(!first.contains("out_of_scope"));
        assert!(first.contains("Access control — POST /users/:id"));
        for label in if locale == ReportLocale::En {
            [
                "Not started",
                "In progress",
                "Blocked",
                "Deferred",
                "Unresolved candidate",
            ]
        } else {
            ["尚未開始", "進行中", "受阻", "已延後", "候選問題未解決"]
        } {
            assert!(first.contains(label), "{label}");
        }
        for copy in if locale == ReportLocale::En {
            ["5 units remain.", "1 unit is outside the audit scope."]
        } else {
            ["尚有 5 個單元未完成。", "有 1 個單元不在稽核範圍內。"]
        } {
            assert!(html.contains(copy), "{copy}");
        }
        assert!(!first.contains("not_applicable"));
        assert!(!first.contains("unresolved-one"));
        assert!(
            !html.contains("Framework sources and attribution are shown in the framework section.")
        );
        assert!(!html.contains("框架來源與出處聲明顯示於框架區塊。"));
    }
    let (_, standard) = render(
        &case,
        run_id,
        &options(ReportLocale::En, RedactionProfile::Standard),
    );
    for gap in standard["report"]["coverage_gaps"].as_array().unwrap() {
        if gap["kind"] == "excluded" {
            assert_eq!(gap["next_action"], "");
        } else {
            assert_eq!(
                gap["next_action"],
                "Continue the source audit from the listed paths."
            );
        }
    }
    for step in standard["report"]["next_steps"].as_array().unwrap() {
        if step["task_id"].is_string() {
            assert_eq!(
                step["action"],
                "Continue the source audit from the listed paths."
            );
        }
    }
    for gap in standard["report"]["source_audits"][0]["coverage_gaps"]
        .as_array()
        .unwrap()
    {
        assert_eq!(
            gap["unresolved"][0],
            standard["report"]["source_audits"][0]["technical_detail"]["coverage_ledger"][0]["unresolved"]
                [0]
        );
        assert!(gap["unresolved"][0].as_str().unwrap().starts_with("fp-"));
        if gap["status"] != "out_of_scope" {
            assert_eq!(gap["continuation_paths"][0], "[redacted location]");
        }
    }
    assert_audit_continuation_step(&case, run_id, "src/private.rs");
    // Out-of-scope units alone have no audit continuation step.
    case.agent_audit_admissions[0].retained_projection["native_coverage_ledger"]
        .as_array_mut()
        .unwrap()
        .retain(|unit| unit["status"] == "out_of_scope");
    for locale in [ReportLocale::En, ReportLocale::ZhHant] {
        for redaction in [RedactionProfile::None, RedactionProfile::Standard] {
            let (_, doc) = render(&case, run_id, &options(locale, redaction));
            assert!(
                doc["report"]["next_steps"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|step| step["task_id"].is_null())
            );
            assert_eq!(doc["report"]["coverage_gaps"][0]["next_action"], "");
        }
    }
    let ledger = case.agent_audit_admissions[0].retained_projection["native_coverage_ledger"]
        .as_array_mut()
        .unwrap();
    let mut second = ledger[0].clone();
    second["coverage_id"] = json!("second-excluded-unit");
    ledger.push(second);
    for locale in [ReportLocale::En, ReportLocale::ZhHant] {
        for redaction in [RedactionProfile::None, RedactionProfile::Standard] {
            let (html, doc) = render(&case, run_id, &options(locale, redaction));
            assert_eq!(doc["report"]["coverage_gaps"].as_array().unwrap().len(), 1);
            assert_eq!(
                doc["report"]["coverage_gaps"][0]["reason"],
                "2 units are outside the audit scope."
            );
            assert_eq!(doc["report"]["coverage_counts"]["excluded"], 1);
            assert!(html.contains(if locale == ReportLocale::En {
                "2 units are outside the audit scope."
            } else {
                "有 2 個單元不在稽核範圍內。"
            }));
        }
    }
    for candidates in [vec!["unresolved-one"], vec![]] {
        let a = &mut case.agent_audit_admissions[0];
        a.outcome.state = TerminalState::Incomplete;
        a.retained_projection["native_coverage_ledger"] = json!([]);
        a.retained_projection["records"] = json!([]);
        a.retained_projection["unresolved_candidates"] = json!(candidates);
        a.counts.unresolved_candidates = candidates.len();
        for locale in [ReportLocale::En, ReportLocale::ZhHant] {
            let (html, doc) = render(&case, run_id, &options(locale, RedactionProfile::Standard));
            let copy = match (locale, candidates.is_empty()) {
                (ReportLocale::En, true) => "Source audit incomplete.",
                (ReportLocale::ZhHant, true) => "原始碼稽核未完成。",
                (ReportLocale::En, false) => {
                    "Source audit incomplete: 1 candidate finding remains unresolved."
                }
                (ReportLocale::ZhHant, false) => "原始碼稽核未完成：尚有 1 個候選問題未解決。",
            };
            assert!(html.contains(copy));
            assert!(!html.contains("<h3>To validate</h3>"));
            assert!(!html.contains("<h3>待驗證</h3>"));
            assert!(!html.contains("<h3>What was not tested</h3>"));
            assert!(!html.contains("<h3>未測試項目</h3>"));
            assert_eq!(
                doc["report"]["source_audits"][0]["outcome"]["incomplete_reason"],
                "[withheld provider text in the standard profile]"
            );
        }
    }
}

fn first_layer(html: &str) -> String {
    let mut output = String::new();
    let mut depth = 0usize;
    for part in html.split_inclusive('>') {
        if part.contains("<details") {
            depth += 1;
        }
        if depth == 0 {
            output.push_str(part);
        }
        if part.contains("</details>") {
            depth -= 1;
        }
    }
    output
}

fn pseudonym(prefix: &str, original: &str) -> String {
    use sha2::Digest;
    format!(
        "{prefix}-{}",
        &hex::encode(sha2::Sha256::digest(original.as_bytes()))[..12]
    )
}

#[test]
fn provider_identifiers_are_pseudonymous_in_single_combined_and_replayed_reports() {
    for profile in ["quick", "standard"] {
        let (run, request) = admit::sealed(profile);
        let saved = admit::admit(&run, &request, 0);
        let mut case = admit::case(&run);
        let run_id = saved["run_id"].as_str().unwrap();
        let projection = &case.agent_audit_admissions[0].retained_projection;
        let mut identifiers = Vec::new();
        for unit in projection["native_coverage_ledger"].as_array().unwrap() {
            identifiers.push(("unit", unit["coverage_id"].as_str().unwrap().to_owned()));
            for fp in unit["result_fingerprints"].as_array().unwrap() {
                identifiers.push(("fp", fp.as_str().unwrap().to_owned()));
            }
        }
        for record in projection["records"].as_array().unwrap() {
            identifiers.push(("fp", record["fingerprint"].as_str().unwrap().to_owned()));
        }
        for finding in &case.findings {
            identifiers.push(("fp", finding.fingerprint.clone()));
        }
        // A provider may repeat a private identifier in a title as well as a typed field.
        let pending_index = if profile == "quick" { 0 } else { 1 };
        let repeated = case.agent_audit_admissions[0].retained_projection["records"][pending_index]
            ["fingerprint"]
            .as_str()
            .unwrap()
            .to_owned();
        case.agent_audit_admissions[0].retained_projection["records"][pending_index]["native_record"]
            ["title"] = json!(format!("Review {repeated}"));
        let scanner_run = append_scanner_run(&mut case);
        for locale in [ReportLocale::En, ReportLocale::ZhHant] {
            for redaction in [RedactionProfile::None, RedactionProfile::Standard] {
                let opts = options(locale, redaction);
                let (html, doc) = render(&case, run_id, &opts);
                let report = &doc["report"];
                let audit = &report["source_audits"][0];
                let native = &case.agent_audit_admissions[0].retained_projection;
                for (unit, original) in audit["technical_detail"]["coverage_ledger"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .zip(native["native_coverage_ledger"].as_array().unwrap())
                {
                    let id = original["coverage_id"].as_str().unwrap();
                    assert_eq!(
                        unit["coverage_id"],
                        if redaction == RedactionProfile::Standard {
                            pseudonym("unit", id)
                        } else {
                            id.to_owned()
                        }
                    );
                    for (fp, original) in unit["result_fingerprints"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .zip(original["result_fingerprints"].as_array().unwrap())
                    {
                        let original = original.as_str().unwrap();
                        assert_eq!(
                            fp,
                            &json!(if redaction == RedactionProfile::Standard {
                                pseudonym("fp", original)
                            } else {
                                original.to_owned()
                            })
                        );
                    }
                }
                let first = first_layer(&html);
                let method = if locale == ReportLocale::En {
                    "Cloudflare source audit"
                } else {
                    "Cloudflare 原始碼稽核"
                };
                assert!(first.contains(method));
                assert!(!first.contains("cloudflare-security-audit"));
                assert!(!first.contains("Cloudflare-security-audit"));
                let validation = html
                    .split(if locale == ReportLocale::En {
                        "<h3>To validate</h3>"
                    } else {
                        "<h3>待驗證</h3>"
                    })
                    .nth(1)
                    .unwrap()
                    .split("</article>")
                    .next()
                    .unwrap();
                for key in [
                    "claimed_root_cause",
                    "validation_plan",
                    "<dt>file</dt>",
                    "<dt>line</dt>",
                    "<dt>description</dt>",
                    "<dt>local</dt>",
                    "<dt>deployment</dt>",
                ] {
                    assert!(!validation.contains(key));
                }
                if redaction == RedactionProfile::Standard {
                    let guidance = if locale == ReportLocale::En {
                        "Ask the code owner to check whether this behavior can occur, using the claim and validation plan in the unredacted report or the app."
                    } else {
                        "請程式碼負責人依照未遮蔽報告或應用程式中的主張與驗證計畫，確認這個行為是否可能發生。"
                    };
                    assert_eq!(validation.matches(guidance).count(), 1);
                    let audit_first = first
                        .split("<section class=\"source-audit report-card\">")
                        .nth(1)
                        .unwrap()
                        .split("</section>")
                        .next()
                        .unwrap();
                    assert!(!audit_first.contains("[withheld provider text"));
                    assert!(!audit_first.contains("隱藏提供者文字"));
                    let count = audit["to_validate"][0]["native_record"]["evidence"]
                        .as_array()
                        .unwrap()
                        .len();
                    let count_line = if locale == ReportLocale::En {
                        format!(
                            "{count} evidence location{} (hidden in this profile)",
                            if count == 1 { "" } else { "s" }
                        )
                    } else {
                        format!("{count} 個證據位置（此設定下已隱藏）")
                    };
                    assert!(validation.contains(&count_line));
                } else {
                    assert!(validation.contains(if locale == ReportLocale::En {
                        "Local check"
                    } else {
                        "本機檢查"
                    }));
                    assert!(validation.contains(if locale == ReportLocale::En {
                        "Deployment check"
                    } else {
                        "部署環境檢查"
                    }));
                    assert!(validation.contains("src/a.rs:"));
                    assert!(validation.contains(" — "));
                    assert!(!validation.contains("<pre>"));
                }
                if profile == "quick" {
                    assert_eq!(report["coverage_counts"]["tested_partial"], 1);
                    assert_eq!(report["coverage_counts"]["not_tested"], 0);
                    assert_eq!(report["coverage_gaps"].as_array().unwrap().len(), 1);
                    assert_eq!(report["coverage_gaps"][0]["reason"], "1 unit remains.");
                    assert!(first.contains(if locale == ReportLocale::En {
                        "1 unit remains."
                    } else {
                        "尚有 1 個單元未完成。"
                    }));
                }
                assert_eq!(
                    html.matches(if locale == ReportLocale::En {
                        "<h3>Method</h3>"
                    } else {
                        "<h3>方法</h3>"
                    })
                    .count(),
                    1
                );
                let single = ReportSnapshot::capture(
                    &case,
                    run_id,
                    opts.clone(),
                    &run.f.data.join("artifacts"),
                )
                .unwrap();
                let combined = ReportSnapshot::capture_combined(
                    &case,
                    &[scanner_run.clone(), run_id.to_owned()],
                    opts,
                )
                .unwrap();
                for snapshot in [single, combined] {
                    for format in [ReportDocumentFormat::Html, ReportDocumentFormat::Json] {
                        let dest = run.f.data.with_file_name("masked-replay");
                        snapshot.replay(format, &dest).unwrap();
                        let replay = fs::read_to_string(&dest).unwrap();
                        let original = run.f.data.with_file_name("masked-original");
                        snapshot.retrieve(format, &original).unwrap();
                        assert_eq!(replay, fs::read_to_string(&original).unwrap());
                        fs::remove_file(original).unwrap();
                        fs::remove_file(dest).unwrap();
                        for (prefix, id) in &identifiers {
                            if redaction == RedactionProfile::Standard {
                                assert!(!replay.contains(id), "original {id}");
                                if format == ReportDocumentFormat::Json || id.len() != 64 {
                                    assert!(
                                        replay.contains(&pseudonym(prefix, id)),
                                        "pseudonym for {id}"
                                    );
                                }
                            } else if format == ReportDocumentFormat::Json || id.len() != 64 {
                                assert!(replay.contains(id), "original {id}");
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn incomplete_audit_asset_actions_distinguish_app_checks_and_count_audit_once() {
    use ai_security_scanner_lib::{
        cloudflare_provider::audit::sealed::TerminalState,
        domain::{EngineRunStatus, EngineTaskKind},
    };
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let mut case = admit::case(&run);
    let run_id = saved["run_id"].as_str().unwrap();
    let a = &mut case.agent_audit_admissions[0];
    a.outcome.state = TerminalState::Incomplete;
    a.retained_projection["native_coverage_ledger"][0]["status"] = json!("blocked");
    for other in [false, true] {
        if other {
            let mut check = case.scan_runs[0].engine_runs[0].clone();
            check.id = "incomplete-app-check".into();
            check.engine_id = "trivy".into();
            check.task_kind = EngineTaskKind::CatalogEngine;
            check.status = EngineRunStatus::PartiallyCompleted;
            case.scan_runs[0].engine_runs.push(check);
        }
        for locale in [ReportLocale::En, ReportLocale::ZhHant] {
            let (html, _) = render(&case, run_id, &options(locale, RedactionProfile::Standard));
            let first = first_layer(&html);
            let row = first
                .split("<tr")
                .skip(1)
                .find(|row| row.contains("problems-found"))
                .unwrap();
            assert!(row.contains(if locale == ReportLocale::En {
                "Continue the source audit from the listed paths."
            } else {
                "請從列出的路徑繼續原始碼稽核。"
            }));
            assert_eq!(
                row.contains(if locale == ReportLocale::En {
                    "Some checks are incomplete. Finish or retry them in the app."
                } else {
                    "另有檢查尚未完成；請在應用程式中完成或重試。"
                }),
                other
            );
        }
    }
    case.scan_runs[0].engine_runs.pop();
    case.agent_audit_admissions[0].outcome.audit_performed = false;
    let report = build_beginner_master_report(&case, run_id).unwrap();
    assert_eq!(report.coverage_counts.tested_partial, 0);
    assert_eq!(report.coverage_counts.not_tested, 1);
}

#[test]
fn validation_next_steps_in_combined_reports_and_zero_lead_regression() {
    let (run, request) = admit::sealed("quick");
    let saved = admit::admit(&run, &request, 0);
    let mut case = admit::case(&run);
    let audit_run = saved["run_id"].as_str().unwrap().to_owned();
    let scanner_run = append_scanner_run(&mut case);
    let mut second_scanner = case
        .scan_runs
        .iter()
        .find(|r| r.id == scanner_run)
        .unwrap()
        .clone();
    second_scanner.id = "scanner-without-audit".to_owned();
    let second_scanner_run = second_scanner.id.clone();
    case.scan_runs.push(second_scanner);
    for locale in [ReportLocale::En, ReportLocale::ZhHant] {
        for problems in [true, false] {
            let mut selected_case = case.clone();
            if !problems {
                selected_case.findings.clear();
                selected_case.finding_observations.clear();
            }
            for leads in [true, false] {
                let selected = if leads {
                    vec![scanner_run.clone(), audit_run.clone()]
                } else {
                    vec![scanner_run.clone(), second_scanner_run.clone()]
                };
                let snapshot = ReportSnapshot::capture_combined(
                    &selected_case,
                    &selected,
                    options(locale, RedactionProfile::None),
                )
                .unwrap();
                let dest = run.f.data.with_file_name("validation-priorities.html");
                snapshot.replay(ReportDocumentFormat::Html, &dest).unwrap();
                let html = fs::read_to_string(&dest).unwrap();
                fs::remove_file(dest).unwrap();
                let heading = if locale == ReportLocale::En {
                    "Priorities and next actions"
                } else {
                    "優先事項與下一步"
                };
                let priorities = html
                    .split(&format!("<h2>{heading}</h2>"))
                    .nth(1)
                    .unwrap()
                    .split("</section>")
                    .next()
                    .unwrap();
                let expected = match (locale, problems, leads) {
                    (ReportLocale::En, false, true) => {
                        "The selected reports contain no problem observations. Validate the 1 source-audit item under To validate first, then review each source&#39;s completed checks and coverage limits below."
                    }
                    (ReportLocale::ZhHant, false, true) => {
                        "所選報告沒有問題觀察紀錄；請先驗證「待驗證」中的 1 個原始碼稽核項目，再查看各來源完成的檢查與涵蓋限制。"
                    }
                    (ReportLocale::En, true, true) => {
                        "Also validate the 1 source-audit item under To validate."
                    }
                    (ReportLocale::ZhHant, true, true) => {
                        "另請驗證「待驗證」中的 1 個原始碼稽核項目。"
                    }
                    (ReportLocale::En, false, false) => {
                        "The selected reports contain no problem observations. Review each source's completed checks and coverage limits below."
                    }
                    (ReportLocale::ZhHant, false, false) => {
                        "所選報告沒有問題觀察紀錄；請查看下方各來源完成的檢查與涵蓋限制。"
                    }
                    (_, true, false) => "",
                };
                assert!(priorities.contains(expected), "{priorities}");
                if !leads {
                    assert!(!priorities.contains("source-audit item"));
                    assert!(!priorities.contains("原始碼稽核項目"));
                    let (single, _) = render(
                        &selected_case,
                        &scanner_run,
                        &options(locale, RedactionProfile::None),
                    );
                    assert!(!single.contains("source-audit item"));
                    assert!(!single.contains("原始碼稽核項目"));
                    if !problems {
                        assert!(single.contains(if locale == ReportLocale::En {
                            "The checks that completed reported no problems."
                        } else {
                            "已完成的檢查沒有發現問題。"
                        }));
                    }
                }
            }
        }
    }
}

#[test]
fn combined_sources_show_checks_and_coverage_gaps_before_details() {
    use ai_security_scanner_lib::beginner_report::CoverageDimensionStatus;
    use ai_security_scanner_lib::domain::EngineRunStatus;
    use ai_security_scanner_lib::selected_run_report::preview_selected_run_report;
    let (run, request) = admit::sealed("quick");
    let saved = admit::admit(&run, &request, 0);
    let mut case = admit::case(&run);
    let scanner_run = append_scanner_run(&mut case);
    let scanner = case
        .scan_runs
        .iter_mut()
        .find(|r| r.id == scanner_run)
        .unwrap();
    let mut secret_check = scanner.engine_runs[0].clone();
    secret_check.id = "synthetic-gitleaks-check".into();
    secret_check.engine_id = "gitleaks".into();
    secret_check.engine_version = Some("8.30.1".into());
    secret_check.reported_version = None;
    let mut failed_check = secret_check.clone();
    failed_check.id = "synthetic-failed-check".into();
    failed_check.engine_id = "semgrep".into();
    failed_check.status = EngineRunStatus::Failed;
    failed_check.progress_percent = 0;
    scanner.engine_runs.push(secret_check);
    scanner.engine_runs.push(failed_check);
    let selected = vec![scanner_run, saved["run_id"].as_str().unwrap().to_owned()];
    let opts = options(ReportLocale::En, RedactionProfile::None);
    let report = preview_selected_run_report(&case, &selected, &opts).unwrap();
    let snapshot = ReportSnapshot::capture_combined(&case, &selected, opts).unwrap();
    let dest = run.f.data.with_file_name("combined-source-coverage.html");
    snapshot.replay(ReportDocumentFormat::Html, &dest).unwrap();
    let html = fs::read_to_string(&dest).unwrap();
    fs::remove_file(dest).unwrap();
    let escape = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    };
    for (index, source) in report.sources.iter().enumerate() {
        let article = html
            .split(&format!(
                "<article class=\"source\" id=\"source-{}\">",
                index + 1
            ))
            .nth(1)
            .unwrap()
            .split("<details>")
            .next()
            .unwrap();
        for check in &source.report.actual.checks {
            let name = ai_security_scanner_lib::registry::builtin_display_name(&check.check_id)
                .unwrap_or(&check.check_id);
            assert!(article.contains(&escape(name)), "missing {name}: {article}");
            assert!(
                article
                    .split("</h3>")
                    .next()
                    .unwrap()
                    .contains(&escape(name))
            );
            let outcome = match check.status {
                CoverageDimensionStatus::TestedComplete => "Completed in source run",
                CoverageDimensionStatus::TestedPartial => "Partial",
                CoverageDimensionStatus::Failed => "Failed",
                CoverageDimensionStatus::TimedOut => "Timed out",
                CoverageDimensionStatus::Cancelled => "Cancelled",
                CoverageDimensionStatus::NotTested => "Not tested",
            };
            assert!(article.contains(outcome), "missing outcome: {article}");
        }
        for gap in &source.report.coverage_gaps {
            assert!(
                article.contains(&escape(&gap.reason)),
                "missing gap: {article}"
            );
        }
        assert!(article.contains("What was not tested"));
        assert!(!article.contains(&source.run_id));
        assert!(!article.contains(&source.created_at.to_rfc3339()));
    }
    let scanner_first = html
        .split("<article class=\"source\"")
        .nth(1)
        .unwrap()
        .split("<details>")
        .next()
        .unwrap();
    assert!(scanner_first.contains("Gitleaks / Version 8.30.1"));
    assert!(scanner_first.contains("Failed"));
    let zh = ReportSnapshot::capture_combined(
        &case,
        &selected,
        options(ReportLocale::ZhHant, RedactionProfile::None),
    )
    .unwrap();
    let dest = run
        .f
        .data
        .with_file_name("combined-source-coverage-zh.html");
    zh.replay(ReportDocumentFormat::Html, &dest).unwrap();
    let html = fs::read_to_string(&dest).unwrap();
    fs::remove_file(dest).unwrap();
    let audit_first = html
        .split("<article class=\"source\"")
        .nth(2)
        .unwrap()
        .split("<details>")
        .next()
        .unwrap();
    assert!(audit_first.contains("Cloudflare 原始碼稽核"));
    assert!(audit_first.contains("未測試的內容"));
    assert!(audit_first.contains("尚有 1 個單元未完成。"));
}

#[test]
fn combined_chinese_standard_localizes_redacted_case_title_in_html() {
    use ai_security_scanner_lib::selected_run_report::preview_selected_run_report;
    let (run, request) = admit::sealed("quick");
    let saved = admit::admit(&run, &request, 0);
    let mut case = admit::case(&run);
    let scanner_run = append_scanner_run(&mut case);
    let selected = vec![scanner_run, saved["run_id"].as_str().unwrap().to_owned()];
    let opts = options(ReportLocale::ZhHant, RedactionProfile::Standard);
    let report = preview_selected_run_report(&case, &selected, &opts).unwrap();
    assert_eq!(report.project_title, "Redacted assessment case");
    let snapshot = ReportSnapshot::capture_combined(&case, &selected, opts).unwrap();
    let dest = run.f.data.with_file_name("combined-zh-title.html");
    snapshot.replay(ReportDocumentFormat::Html, &dest).unwrap();
    let html = fs::read_to_string(&dest).unwrap();
    fs::remove_file(dest).unwrap();
    assert!(html.contains("<title>已遮蔽的評估案件</title>"));
    assert!(html.contains("<p>已遮蔽的評估案件</p>"));
    assert!(!html.contains(">Redacted assessment case<"));
}

#[test]
fn standard_validation_guidance_counts_hidden_evidence_in_single_and_combined_html() {
    let (run, request) = admit::sealed("quick");
    let saved = admit::admit(&run, &request, 0);
    let mut case = admit::case(&run);
    let run_id = saved["run_id"].as_str().unwrap().to_owned();
    let evidence = case.agent_audit_admissions[0].retained_projection["records"][0]
        ["native_record"]["evidence"].as_array_mut().unwrap();
    let location = evidence[0].clone();
    evidence.resize(7, location);
    let scanner_run = append_scanner_run(&mut case);
    for locale in [ReportLocale::En, ReportLocale::ZhHant] {
        let opts = options(locale, RedactionProfile::Standard);
        let (single, doc) = render(&case, &run_id, &opts);
        assert_eq!(
            doc["report"]["source_audits"][0]["to_validate"][0]["native_record"]["evidence"]
                .as_array()
                .unwrap()
                .len(),
            7
        );
        let snapshot =
            ReportSnapshot::capture_combined(&case, &[scanner_run.clone(), run_id.clone()], opts)
                .unwrap();
        let dest = run.f.data.with_file_name("hidden-validation-evidence.html");
        snapshot.replay(ReportDocumentFormat::Html, &dest).unwrap();
        let combined = fs::read_to_string(&dest).unwrap();
        fs::remove_file(dest).unwrap();
        for html in [single, combined] {
            let validation = html
                .split(if locale == ReportLocale::En {
                    "<h3>To validate</h3>"
                } else {
                    "<h3>待驗證</h3>"
                })
                .nth(1)
                .unwrap()
                .split("</article>")
                .next()
                .unwrap();
            assert!(validation.contains(if locale == ReportLocale::En {
                "Ask the code owner to check whether this behavior can occur, using the claim and validation plan in the unredacted report or the app."
            } else {
                "請程式碼負責人依照未遮蔽報告或應用程式中的主張與驗證計畫，確認這個行為是否可能發生。"
            }));
            assert!(validation.contains(if locale == ReportLocale::En {
                "7 evidence locations (hidden in this profile)"
            } else {
                "7 個證據位置（此設定下已隱藏）"
            }));
            assert!(!validation.contains("[redacted location]:"));
            if locale == ReportLocale::ZhHant {
                assert!(html.contains("（已遮蔽位置）"));
            }
        }
    }
}

#[test]
fn combined_visible_times_are_readable_and_keep_exact_datetime_values() {
    let (run, request) = admit::sealed("quick");
    let saved = admit::admit(&run, &request, 0);
    let mut case = admit::case(&run);
    let selected = vec![
        append_scanner_run(&mut case),
        saved["run_id"].as_str().unwrap().to_owned(),
    ];
    for locale in [ReportLocale::En, ReportLocale::ZhHant] {
        let snapshot = ReportSnapshot::capture_combined(
            &case,
            &selected,
            options(locale, RedactionProfile::None),
        )
        .unwrap();
        let html_path = run.f.data.with_file_name("combined-times.html");
        let json_path = run.f.data.with_file_name("combined-times.json");
        snapshot
            .replay(ReportDocumentFormat::Html, &html_path)
            .unwrap();
        snapshot
            .replay(ReportDocumentFormat::Json, &json_path)
            .unwrap();
        let html = fs::read_to_string(&html_path).unwrap();
        let doc: Value = serde_json::from_slice(&fs::read(&json_path).unwrap()).unwrap();
        fs::remove_file(html_path).unwrap();
        fs::remove_file(json_path).unwrap();
        let sources = doc["sources"].as_array().unwrap();
        for value in std::iter::once(&doc["generated_at"])
            .chain(
                sources
                    .iter()
                    .flat_map(|s| [&s["created_at"], &s["completed_at"]]),
            )
            .chain(sources.iter().flat_map(|s| {
                s["report"]["actual"]["checks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|check| check.get("finished_at").filter(|value| value.is_string()))
            }))
        {
            let exact = chrono::DateTime::parse_from_rfc3339(value.as_str().unwrap())
                .unwrap()
                .with_timezone(&chrono::Utc);
            assert!(html.contains(&format!(
                "<time datetime=\"{}\">{}</time>",
                exact.to_rfc3339(),
                exact.format("%Y-%m-%d %H:%M UTC")
            )));
        }
    }
}

#[test]
fn chinese_audit_technical_details_localize_phase_and_punctuation() {
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let case = admit::case(&run);
    let run_id = saved["run_id"].as_str().unwrap();
    let (html, _) = render(
        &case,
        run_id,
        &options(ReportLocale::ZhHant, RedactionProfile::Standard),
    );
    assert!(html.contains("階段：</strong>原始碼稽核已封存"));
    assert!(html.contains("已發出的呼叫次數："));
    assert!(html.contains("標準設定檔中隱藏的文字欄位："));
    assert!(html.contains("標準設定檔中隱藏的程式碼欄位："));
    assert!(html.contains("原始碼稽核：cloudflare-security-audit；納入紀錄："));
}

#[test]
fn chinese_standard_localizes_bare_redaction_in_demo_technical_detail() {
    let case = ai_security_scanner_lib::demo::build_demo_case();
    let run_id = &case.scan_runs[0].id;
    let (standard, _) = render(
        &case,
        run_id,
        &options(ReportLocale::ZhHant, RedactionProfile::Standard),
    );
    assert!(standard.contains("<strong>建立者：</strong>（已遮蔽）"));
    let (unredacted, _) = render(
        &case,
        run_id,
        &options(ReportLocale::ZhHant, RedactionProfile::None),
    );
    assert!(unredacted.contains("Synthetic demo builder"));
}

#[test]
fn audit_report_terms_exclude_unshown_framework_references() {
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let case = admit::case(&run);
    let run_id = saved["run_id"].as_str().unwrap();
    let scanner = ai_security_scanner_lib::demo::build_demo_case();
    for locale in [ReportLocale::En, ReportLocale::ZhHant] {
        let opts = options(locale, RedactionProfile::Standard);
        let (audit_html, _) = render(&case, run_id, &opts);
        let (scanner_html, _) = render(&scanner, &scanner.scan_runs[0].id, &opts);
        let terms = |html: &str| html.split("<footer><h2>").nth(1).unwrap().to_owned();
        let audit_terms = terms(&audit_html);
        let scanner_terms = terms(&scanner_html);
        let (framework, aidefend, disclaimer) = match locale {
            ReportLocale::En => (
                "Framework references are informational navigation.",
                "AIDEFEND references are an independent, unofficial mapping",
                "This report is not an audit, certification, compliance decision, security guarantee, or automatic remediation.",
            ),
            ReportLocale::ZhHant => (
                "框架參照只供資訊導航。",
                "AIDEFEND 參照屬於獨立、非官方的對照。",
                "本報告不是稽核、認證、合規判定、資安保證或自動修復。",
            ),
        };
        assert!(!audit_terms.contains(framework));
        assert!(!audit_terms.contains(aidefend));
        assert!(!audit_terms.to_ascii_lowercase().contains("framework"));
        assert!(!audit_terms.contains("框架"));
        assert!(audit_terms.contains(disclaimer));
        assert!(scanner_terms.contains(framework));
        assert!(scanner_terms.contains(aidefend));
        assert!(scanner_terms.contains(disclaimer));
    }
}

#[test]
fn standard_source_view_request_id_is_pseudonymous_in_single_and_combined_reports() {
    let (run, request) = admit::sealed("standard");
    let saved = admit::admit(&run, &request, 0);
    let mut case = admit::case(&run);
    let scanner_run = append_scanner_run(&mut case);
    let run_id = saved["run_id"].as_str().unwrap();
    for locale in [ReportLocale::En, ReportLocale::ZhHant] {
        for redaction in [RedactionProfile::Standard, RedactionProfile::None] {
            let opts = options(locale, redaction);
            let expected = if redaction == RedactionProfile::Standard {
                pseudonym("req", "view-request")
            } else {
                "view-request".to_owned()
            };
            let (html, doc) = render(&case, run_id, &opts);
            let lineage = &doc["report"]["source_audits"][0]["technical_detail"]["lineage"];
            assert_eq!(lineage["source_view_request_id"], expected);
            assert_eq!(lineage["source"]["source_view_request_id"], expected);
            assert!(html.contains(&expected));
            if redaction == RedactionProfile::Standard {
                assert!(!html.contains("view-request"));
                assert!(!doc.to_string().contains("view-request"));
            }

            let snapshot = ReportSnapshot::capture_combined(
                &case,
                &[scanner_run.clone(), run_id.to_owned()],
                opts,
            )
            .unwrap();
            for format in [ReportDocumentFormat::Html, ReportDocumentFormat::Json] {
                let dest = run.f.data.with_file_name("source-view-report");
                snapshot.replay(format, &dest).unwrap();
                let combined = fs::read_to_string(&dest).unwrap();
                fs::remove_file(dest).unwrap();
                assert!(combined.contains(&expected));
                if redaction == RedactionProfile::Standard {
                    assert!(!combined.contains("view-request"));
                }
            }
        }
    }
}

#[test]
fn empty_problem_section_reflects_completed_security_checks() {
    use ai_security_scanner_lib::beginner_report::{CheckResultKind, CoverageDimensionStatus};

    let scanner = ai_security_scanner_lib::demo::build_demo_case();
    let mut clean = scanner.clone();
    clean.findings.clear();
    clean.finding_observations.clear();
    clean.finding_groups.clear();
    clean.finding_group_events.clear();
    let clean_run = &clean.scan_runs[0].id;
    let complete = build_beginner_master_report(&clean, clean_run).unwrap();
    assert!(complete.findings.is_empty());
    assert!(complete.actual.checks.iter().any(|check| {
        check.effective_result_kind() == CheckResultKind::SecurityCheck
            && check.status == CoverageDimensionStatus::TestedComplete
    }));

    let (run, request) = admit::sealed("quick");
    let saved = admit::admit(&run, &request, 0);
    let incomplete = admit::case(&run);
    let incomplete_run = saved["run_id"].as_str().unwrap();
    let incomplete_report = build_beginner_master_report(&incomplete, incomplete_run).unwrap();
    assert!(incomplete_report.findings.is_empty());
    assert!(!incomplete_report.actual.checks.iter().any(|check| {
        check.effective_result_kind() == CheckResultKind::SecurityCheck
            && check.status == CoverageDimensionStatus::TestedComplete
    }));

    for locale in [ReportLocale::En, ReportLocale::ZhHant] {
        let (heading, completed_text, incomplete_text, explanation) = match locale {
            ReportLocale::En => (
                "Problems found",
                "No problems were found in the completed checks.",
                "No confirmed problems were recorded for this run.",
                "Problems follow the report order.",
            ),
            ReportLocale::ZhHant => (
                "發現的問題",
                "已完成的檢查沒有發現問題。",
                "本輪未記錄已確認的問題。",
                "問題依報告順序排列。",
            ),
        };
        for redaction in [RedactionProfile::Standard, RedactionProfile::None] {
            let opts = options(locale, redaction);
            for (case, run_id, expected) in [
                (&clean, clean_run.as_str(), completed_text),
                (&incomplete, incomplete_run, incomplete_text),
            ] {
                let (html, _) = render(case, run_id, &opts);
                let section = html
                    .split(&format!("<h2>{heading}</h2>"))
                    .nth(1)
                    .unwrap()
                    .split("<section")
                    .next()
                    .unwrap();
                assert!(section.contains(expected), "{section}");
                assert!(!section.contains(explanation));
            }
            let (html, _) = render(&scanner, &scanner.scan_runs[0].id, &opts);
            let section = html
                .split(&format!("<h2>{heading}</h2>"))
                .nth(1)
                .unwrap()
                .split("<section")
                .next()
                .unwrap();
            assert!(section.contains(explanation));
        }
    }
}
