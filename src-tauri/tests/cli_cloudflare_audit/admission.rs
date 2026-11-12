use super::{
    finalize::{finalize, request},
    fixture::*,
};
use ai_security_scanner_lib::{
    agent_audit_admission::{AdmissionRequestFacts, plan_admission},
    cloudflare_provider::audit::sealed::verify,
    domain::EngineTaskKind,
};

#[test]
fn sealed_run_and_original_copy_plan_are_deterministic_and_bound() {
    let run = RunFixture::new("standard");
    let req = request(&run);
    finalize(&run, &req, 0);
    let storage = run.f.storage();
    let mut verified = verify(
        &run.f.data,
        &storage,
        &run.f.case_id,
        run.prepared["session_id"].as_str().unwrap(),
    )
    .unwrap();
    let case = storage.get_case(&run.f.case_id).unwrap();
    let now = Utc::now();
    let facts = AdmissionRequestFacts {
        request_id: "admit-one".into(),
        request_sha256: "a".repeat(64),
    };
    let plan = || {
        let mut n = 0;
        plan_admission(&verified, &case, &facts, now, || {
            n += 1;
            format!("id-{n}")
        })
        .unwrap()
    };
    let a = plan();
    assert_eq!(
        serde_json::to_value(&a).unwrap(),
        serde_json::to_value(plan()).unwrap()
    );
    assert_eq!(a.run.id, verified.identities.run_id);
    assert_eq!(a.run.engine_runs[0].id, verified.identities.task_id);
    assert!(
        matches!(&a.run.engine_runs[0].task_kind, EngineTaskKind::AgentAudit { admission_id, .. } if admission_id == &a.admission.admission_id)
    );
    assert_eq!(a.run.report_asset_snapshots[0].asset.id, run.f.asset_id);
    assert!(a.run.scope_grant_ids.is_empty());
    assert!(a.run.scope_grant_snapshots.is_empty());
    assert_eq!(
        &a.admission.retained_projection,
        verified.retained_projection()
    );
    let expected: Vec<_> = verified
        .package_members
        .iter()
        .filter(|m| !m.path.starts_with("retained/source-view/"))
        .cloned()
        .collect();
    assert!(
        verified.package_members.len() > expected.len(),
        "the sealed package retains source-view files that the plan must not copy"
    );
    for required in [
        "workflow.json",
        "workflow-projection.json",
        "retained/bundle/findings.json",
    ] {
        assert!(
            a.artifact_copies.iter().any(|c| c.member_path == required),
            "{required} must be copied"
        );
    }
    assert_eq!(expected.len(), a.artifact_copies.len());
    for (m, c) in expected.iter().zip(&a.artifact_copies) {
        assert_eq!(m.path, c.member_path);
        assert_eq!(m.sha256, c.artifact.sha256);
        assert_eq!(m.byte_length, c.artifact.byte_length);
        let bytes = verified.read_member(&m.path).unwrap();
        assert_eq!(bytes.len() as u64, m.byte_length);
        assert!(c.artifact.contains_sensitive_data);
    }
    assert!(verified.read_member("not-indexed").is_err());
    verified.recheck_unchanged().unwrap();
}

#[test]
fn exact_confirmed_mapping_and_all_native_severity_confidence_values() {
    use ai_security_scanner_lib::domain::{Confidence, FindingFamily, FindingStatus};
    let title = format!(
        "漏洞 <script>unsafe()</script> {}  \n",
        "long title ".repeat(100)
    );
    let description = format!("說明 {}\n\t  ", "body ".repeat(1000));
    let code = "fn fixed() {\n    // 安全 <svg onload=alert(1)>  \n}\n  ";
    let run = RunFixture::with_records("standard", &[], |records, ledger, _| {
        let original = records[0].clone();
        let mut mapped = vec![];
        for severity in ["informational", "low", "medium", "high", "critical"] {
            for confidence in ["low", "medium", "high"] {
                let mut r = original.clone();
                r["fingerprint"] = json!(format!("record-{severity}-{confidence}"));
                r["title"] = json!(title);
                r["description"] = json!(description);
                r["severity"]["overall_severity"] = json!(severity);
                r["severity"]["impact"]["score"] = json!(severity);
                r["confidence"]["score"] = json!(confidence);
                r["remediation"]["strategy"] = json!("保持策略\n  ");
                r["remediation"]["code_changes"] =
                    json!([{"file_name":"src/a.rs","fixed_code":code}]);
                r["execution"]["payloads"] = json!(["$(echo unsafe)\n<script>測試</script>  "]);
                let mut second = r["evidence"][0].clone();
                second["description"] = json!("另一項證據\n  ");
                r["evidence"].as_array_mut().unwrap().push(second);
                mapped.push(r);
            }
        }
        mapped.extend(records.as_array().unwrap().iter().skip(1).cloned());
        mapped.sort_by(|a, b| a["fingerprint"].as_str().cmp(&b["fingerprint"].as_str()));
        ledger[0]["result_fingerprints"] = json!(
            mapped
                .iter()
                .map(|r| r["fingerprint"].clone())
                .collect::<Vec<_>>()
        );
        *records = json!(mapped);
    });
    finalize(&run, &request(&run), 0);
    let storage = run.f.storage();
    let verified = verify(
        &run.f.data,
        &storage,
        &run.f.case_id,
        run.prepared["session_id"].as_str().unwrap(),
    )
    .unwrap();
    let case = storage.get_case(&run.f.case_id).unwrap();
    let facts = AdmissionRequestFacts {
        request_id: "admit-fidelity".into(),
        request_sha256: "b".repeat(64),
    };
    let mut n = 0;
    let plan = plan_admission(&verified, &case, &facts, Utc::now(), || {
        n += 1;
        format!("id-{n}")
    })
    .unwrap();
    assert_eq!((plan.findings.len(), plan.observations.len()), (15, 15));
    assert_eq!(
        (
            plan.admission.counts.confirmed,
            plan.admission.counts.needs_validation,
            plan.admission.counts.rejected
        ),
        (15, 1, 1)
    );
    assert_eq!(plan.admission.counts.unresolved_candidates, 0);
    assert_eq!(plan.admission.counts.coverage_by_status["candidate"], 1);
    for (index, (finding, observation)) in plan.findings.iter().zip(&plan.observations).enumerate()
    {
        let native = &run.findings[index];
        assert_eq!(finding.title, title);
        assert_eq!(finding.plain_language_summary, description);
        assert_eq!(
            json!(finding.severity),
            native["severity"]["overall_severity"]
        );
        assert_eq!(json!(finding.confidence), native["confidence"]["score"]);
        assert_ne!(finding.confidence, Confidence::Confirmed);
        assert_eq!(finding.family, Some(FindingFamily::SourceCode));
        assert_eq!(finding.status, FindingStatus::Unreviewed);
        assert_eq!(json!(observation.finding_snapshot), json!(finding));
        assert_eq!(finding.evidence.len(), 2);
        assert!(finding.control_references.is_empty());
        for (i, evidence) in finding.evidence.iter().enumerate() {
            assert_eq!(evidence.pointer, Some(format!("/{index}/evidence/{i}")));
            let reference = evidence.provider_record.as_ref().unwrap();
            assert_eq!(reference.admission_id, plan.admission.admission_id);
            assert_eq!(reference.native_record_index, index);
            assert_eq!(
                reference.native_record_sha256,
                verified.retained_projection()["records"][index]["native_record_sha256"]
            );
            assert_eq!(reference.source_locators[0].path, "src/a.rs");
            let details = evidence.scanner_details.as_ref().unwrap();
            assert_eq!(details.description.as_deref(), Some(description.as_str()));
            assert_eq!(details.remediation.as_deref(), Some("保持策略\n  "));
            assert_eq!(
                details.remediation_code_changes.as_ref().unwrap()[0]["fixed_code"],
                code
            );
            assert!(details.cvss.is_empty() && details.cwe_ids.is_empty());
        }
        assert_eq!(
            plan.admission.retained_projection["records"][index]["native_record"],
            *native
        );
    }
    assert!(
        plan.resulting_case(&case)
            .unwrap()
            .finding_workflow_events
            .is_empty()
    );
}

#[test]
fn incomplete_lead_only_has_no_findings_and_preserves_reason_and_times() {
    use ai_security_scanner_lib::domain::EngineRunStatus;
    let reason = "尚待驗證\n  ";
    let run = RunFixture::with_records("quick", &[], |records, ledger, metadata| {
        *records = json!([records[1].clone()]);
        ledger[0]["result_fingerprints"] = json!([records[0]["fingerprint"], "unresolved-one"]);
        ledger[0]["unresolved"] = json!(["source work unfinished"]);
        metadata["run_status"] = json!("incomplete");
        metadata["incomplete_reason"] = json!(reason);
    });
    finalize(&run, &request(&run), 0);
    let storage = run.f.storage();
    let verified = verify(
        &run.f.data,
        &storage,
        &run.f.case_id,
        run.prepared["session_id"].as_str().unwrap(),
    )
    .unwrap();
    let mut case = storage.get_case(&run.f.case_id).unwrap();
    case.scope_grants.clear();
    let facts = AdmissionRequestFacts {
        request_id: "admit-incomplete".into(),
        request_sha256: "c".repeat(64),
    };
    let mut n = 0;
    let plan = plan_admission(&verified, &case, &facts, Utc::now(), || {
        n += 1;
        format!("id-{n}")
    })
    .unwrap();
    assert!(plan.findings.is_empty() && plan.observations.is_empty());
    assert_eq!(plan.admission.counts.needs_validation, 1);
    assert_eq!(plan.admission.counts.unresolved_candidates, 1);
    assert_eq!(
        plan.run.engine_runs[0].status,
        EngineRunStatus::PartiallyCompleted
    );
    assert_eq!(
        plan.run.engine_runs[0].error_message.as_deref(),
        Some(reason)
    );
    assert_eq!(
        plan.run.created_at,
        chrono::DateTime::parse_from_rfc3339(verified.prepared_at()).unwrap()
    );
    assert_eq!(
        plan.run.engine_runs[0].started_at,
        Some(plan.run.created_at)
    );
    assert_eq!(
        plan.run.completed_at.unwrap(),
        chrono::DateTime::parse_from_rfc3339(verified.sealed_at()).unwrap()
    );
    assert!(plan.run.engine_runs[0].runtime_provider.is_none());
    assert!(plan.run.engine_runs[0].image_digest.is_none());
    assert_eq!(
        plan.run.engine_runs[0].engine_version.as_ref(),
        Some(&verified.method.upstream_commit)
    );
    case.assets[0]
        .metadata
        .insert("workspace_snapshot_sha256".into(), json!("changed"));
    assert!(plan_admission(&verified, &case, &facts, Utc::now(), || "id".into()).is_err());
}

#[test]
fn independent_sealed_sessions_have_distinct_product_fingerprints() {
    let mut fingerprints = Vec::new();
    for _ in 0..2 {
        let run = RunFixture::new("quick");
        finalize(&run, &request(&run), 0);
        let storage = run.f.storage();
        let verified = verify(
            &run.f.data,
            &storage,
            &run.f.case_id,
            run.prepared["session_id"].as_str().unwrap(),
        )
        .unwrap();
        let case = storage.get_case(&run.f.case_id).unwrap();
        let facts = AdmissionRequestFacts {
            request_id: "admit".into(),
            request_sha256: "d".repeat(64),
        };
        let mut n = 0;
        let plan = plan_admission(&verified, &case, &facts, Utc::now(), || {
            n += 1;
            format!("id-{n}")
        })
        .unwrap();
        fingerprints.push(plan.findings[0].fingerprint.clone());
        assert_eq!(
            plan.run.engine_runs[0].status,
            ai_security_scanner_lib::domain::EngineRunStatus::Completed
        );
    }
    assert_ne!(fingerprints[0], fingerprints[1]);
}
