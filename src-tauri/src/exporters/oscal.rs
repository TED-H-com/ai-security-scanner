use crate::domain::{
    AssessmentCase, Confidence, Evidence, EvidenceKind, Finding, FindingObservation, FindingStatus,
    ScanRun, Severity,
};
use crate::error::AppResult;
use crate::exporters::terminal_run;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const OSCAL_VERSION: &str = "1.2.3";
pub const OSCAL_PROPERTY_NAMESPACE: &str = "urn:ai-security-scanner:oscal:props";
pub const OSCAL_EXPORT_NOTICE: &str = "This document contains preliminary scanner observations. It is not a formal assessment, audit, certification, attestation, or forensic conclusion. Related control references are navigation coordinates only and do not state that a control passed, failed, was assessed, or is compliant.";

/// Convert canonical observations for a run to an OSCAL Assessment Results JSON model.
///
/// OSCAL requires an assessment-plan import and reviewed-controls structure. Because
/// the product does not perform a formal control assessment, the exporter points to
/// an explicit placeholder plan and selects one clearly named local structural
/// sentinel instead of `include-all`. Canonical control mappings appear only as
/// namespaced observation properties.
pub fn export_oscal_assessment_results(case: &AssessmentCase, run_id: &str) -> AppResult<Value> {
    let run = terminal_run(case, run_id)?;

    let findings = case
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let mut canonical_observations = case
        .finding_observations
        .iter()
        .filter(|observation| observation.run_id == run_id)
        .collect::<Vec<_>>();
    canonical_observations.sort_by(|left, right| {
        left.fingerprint
            .cmp(&right.fingerprint)
            .then_with(|| left.id.cmp(&right.id))
    });

    let last_durable_activity = selected_run_last_durable_activity(run, &canonical_observations);
    let observations = canonical_observations
        .into_iter()
        .filter_map(|observation| {
            let canonical_finding = findings.get(observation.finding_id.as_str()).copied();
            let finding = observation
                .finding_snapshot
                .as_ref()
                .or(canonical_finding)?;
            let effective_status = canonical_finding
                .map(|canonical| &canonical.status)
                .unwrap_or(&finding.status);
            Some(oscal_observation(finding, effective_status, observation))
        })
        .collect::<Vec<_>>();

    let end = run.completed_at.unwrap_or(last_durable_activity);
    let result = json!({
        "uuid": stable_uuid(&format!("assessment-result:{}:{}", case.id, run_id)),
        "title": format!("Scanner run {} observations", run.sequence),
        "description": "Read-only and explicitly authorized scanner observations normalized by ai-security-scanner.",
        "start": run.created_at.to_rfc3339(),
        "end": end.to_rfc3339(),
        "props": [
            property("canonical-case-id", &case.id),
            property("canonical-run-id", run_id),
            property("export-kind", "preliminary-scanner-observations"),
            property("result-lifecycle", "final")
        ],
        "reviewed-controls": {
            "description": "No formal catalog controls were reviewed. The required OSCAL selection contains only a product-local structural sentinel; related framework coordinates appear only on observations.",
            "control-selections": [{
                "description": "Product-local structural sentinel only; this is not a NIST, ISO, CIS, or other catalog control and makes no control assessment claim.",
                "props": [property("selection-kind", "no-formal-controls-reviewed")],
                "include-controls": [{
                    "control-id": "ai-security-scanner-no-formal-controls-reviewed"
                }]
            }]
        },
        "observations": observations,
        "remarks": OSCAL_EXPORT_NOTICE
    });
    Ok(json!({
        "assessment-results": {
            "uuid": stable_uuid(&format!("assessment-results:{}:{}", case.id, run_id)),
            "metadata": {
                "title": format!("{} — preliminary scanner observations", case.title),
                "last-modified": last_durable_activity.to_rfc3339(),
                "version": env!("CARGO_PKG_VERSION"),
                "oscal-version": OSCAL_VERSION,
                "remarks": OSCAL_EXPORT_NOTICE
            },
            "import-ap": {
                "href": "urn:ai-security-scanner:placeholder:non-formal-assessment-plan",
                "remarks": "Structural placeholder required by the OSCAL Assessment Results model. No formal assessment plan was executed or imported."
            },
            "results": [result]
        }
    }))
}

fn selected_run_last_durable_activity(
    run: &ScanRun,
    observations: &[&FindingObservation],
) -> chrono::DateTime<chrono::Utc> {
    let mut latest = run.created_at;
    for task in &run.engine_runs {
        for timestamp in [task.started_at, task.finished_at].into_iter().flatten() {
            latest = latest.max(timestamp);
        }
        if let Some(observation) = task.localhost_tcp_observation.as_ref() {
            latest = latest.max(observation.observed_at);
        }
    }
    for observation in observations {
        latest = latest.max(observation.observed_at);
    }
    if let Some(completed_at) = run.completed_at {
        latest = latest.max(completed_at);
    }
    latest
}

pub fn export_oscal_assessment_results_bytes(
    case: &AssessmentCase,
    run_id: &str,
) -> AppResult<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(
        &export_oscal_assessment_results(case, run_id)?,
    )?)
}

fn oscal_observation(
    finding: &Finding,
    effective_status: &FindingStatus,
    observation: &FindingObservation,
) -> Value {
    let exposure_observation = finding
        .severity_basis_code
        .is_some_and(|code| code.is_exposure_observation());
    let mut props = vec![
        property("canonical-finding-id", &finding.id),
        property("canonical-fingerprint", &observation.fingerprint),
        property("canonical-severity", severity_name(&observation.severity)),
        property(
            "canonical-confidence",
            confidence_name(&observation.confidence),
        ),
        property(
            "record-kind",
            if exposure_observation {
                "service-inventory-observation"
            } else {
                "security-finding-observation"
            },
        ),
    ];
    if exposure_observation {
        let observation_kind = serde_json::to_value(finding.severity_basis_code)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "reachable_service".into());
        props.push(property("observation-kind", &observation_kind));
        for detail in finding.tags.iter().filter(|tag| {
            tag.starts_with("port:")
                || tag.starts_with("protocol:")
                || tag.starts_with("http-status:")
        }) {
            props.push(property("observed-service-detail", detail));
        }
    }

    let mut asset_ids = observation.asset_ids.clone();
    asset_ids.sort();
    asset_ids.dedup();
    for asset_id in asset_ids {
        props.push(property("canonical-asset-id", &asset_id));
    }

    let mut engine_ids = observation.engine_ids.clone();
    engine_ids.sort();
    engine_ids.dedup();
    for engine_id in engine_ids {
        props.push(property("source-engine-id", &engine_id));
    }

    if !exposure_observation {
        props.push(property("priority", &finding.priority.to_string()));
        props.push(property(
            "finding-status",
            &enum_value(effective_status, "unknown"),
        ));
        props.push(property(
            "recommended-expert-type",
            &finding.recommended_expert_type,
        ));
        props.push(property("possible-impact", &finding.possible_impact));
        props.push(property("recommendation", &finding.recommendation));
        props.push(property(
            "verification-guidance",
            &finding.verification_guidance,
        ));
        if let Some(family) = &finding.family {
            props.push(property("finding-family", &enum_value(family, "unknown")));
        }
        if let Some(basis) = &finding.severity_basis_code {
            props.push(property("severity-basis", &enum_value(basis, "unknown")));
        }
        if let Some(basis) = &finding.confidence_basis_code {
            props.push(property("confidence-basis", &enum_value(basis, "unknown")));
        }
        for factor in &finding.context_factors {
            props.push(property("context-factor", &enum_value(factor, "unknown")));
        }
        if let Some(rollback) = &finding.rollback_considerations {
            props.push(property("rollback-considerations", rollback));
        }
        for reference in &finding.official_references {
            props.push(property("official-reference", reference));
        }
    }

    for reference in &finding.control_references {
        props.push(json!({
            "name": "related-control-coordinate",
            "ns": OSCAL_PROPERTY_NAMESPACE,
            "value": format!(
                "{}@{}:{}",
                reference.framework, reference.framework_version, reference.control_id
            ),
            "remarks": format!(
                "Coordinate only; no assessment result. Title: {}. Relationship: {}. Rationale: {}. Mapping version: {}.",
                reference.title,
                reference.relationship,
                reference.rationale,
                reference.mapping_version
            )
        }));
    }

    let mut evidence = finding
        .evidence
        .iter()
        .filter(|evidence| evidence.run_id == observation.run_id)
        .collect::<Vec<_>>();
    evidence.sort_by(|left, right| left.id.cmp(&right.id));
    let relevant_evidence: Vec<Value> = if evidence.is_empty() {
        let mut hashes = observation.evidence_hashes.clone();
        hashes.sort();
        hashes.dedup();
        hashes
            .into_iter()
            .map(|hash| {
                json!({
                    "description": "Canonical evidence content hash; raw evidence may be omitted from this schema export.",
                    "props": [property("sha-256", &hash)]
                })
            })
            .collect()
    } else {
        evidence.into_iter().map(oscal_evidence).collect()
    };

    let (description, types, remarks) = if exposure_observation {
        (
            crate::finding_narrative::EXPOSURE_OBSERVATION_RISK.to_owned(),
            vec!["inventory", "service-discovery"],
            crate::finding_narrative::EXPOSURE_OBSERVATION_NEXT_STEP.to_owned(),
        )
    } else {
        (
            format!(
                "{} Possible impact: {}",
                finding.plain_language_summary, finding.possible_impact
            ),
            vec!["discovery"],
            format!(
                "Preliminary observation. Suggested next step: {} Verification guidance: {}",
                finding.recommendation, finding.verification_guidance
            ),
        )
    };

    json!({
        "uuid": stable_uuid(&format!(
            "observation:{}:{}:{}",
            observation.run_id, observation.id, observation.fingerprint
        )),
        "title": finding.title,
        "description": description,
        "props": props,
        "methods": ["EXAMINE"],
        "types": types,
        "relevant-evidence": relevant_evidence,
        "collected": observation.observed_at.to_rfc3339(),
        "remarks": remarks
    })
}

fn oscal_evidence(evidence: &Evidence) -> Value {
    let mut props = vec![
        property("canonical-evidence-id", &evidence.id),
        property("evidence-kind", evidence_kind_name(&evidence.kind)),
        property("source-engine-id", &evidence.engine_id),
        property("canonical-scan-run-id", &evidence.run_id),
        property("raw-artifact-id", &evidence.artifact_id),
        property("sha-256", &evidence.artifact_sha256),
        property("redacted", if evidence.redacted { "true" } else { "false" }),
    ];
    if let Some(engine_run_id) = &evidence.engine_run_id {
        props.push(property("canonical-engine-run-id", engine_run_id));
    } else {
        props.push(property(
            "canonical-engine-run-id-state",
            "legacy-not-recorded",
        ));
    }
    if let Some(source_rule) = &evidence.source_rule {
        props.push(property("source-rule-id", source_rule));
    }
    if let Some(result_pointer_sha256) = &evidence.result_pointer_sha256 {
        props.push(property("result-pointer-sha-256", result_pointer_sha256));
    }
    if let Some(location) = &evidence.location {
        props.push(property("evidence-location", location));
    }
    if let Some(pointer) = &evidence.pointer {
        props.push(property("result-pointer", pointer));
    }
    if let Some(details) = &evidence.scanner_details {
        props.push(property("scanner-provided-details-trust", "untrusted"));
        if let Some(description) = &details.description {
            props.push(property("scanner-provided-description", description));
        }
        if let Some(remediation) = &details.remediation {
            props.push(property("scanner-provided-remediation", remediation));
        }
        if let Some(installed_version) = &details.installed_version {
            props.push(property(
                "scanner-provided-installed-version",
                installed_version,
            ));
        }
        if let Some(fixed_version) = &details.fixed_version {
            props.push(property("scanner-provided-fixed-version", fixed_version));
        }
        if evidence.engine_id == "cloudsplaining"
            && let Some(iam) = &details.aws_iam_policy
        {
            let source = match iam.policy_source {
                crate::domain::AwsIamPolicySource::AwsManaged => "aws_managed",
                crate::domain::AwsIamPolicySource::CustomerManaged => "customer_managed",
                crate::domain::AwsIamPolicySource::Inline => "inline",
            };
            props.push(property("scanner-provided-aws-iam-policy-source", source));
            props.push(property(
                "scanner-provided-aws-iam-policy-name",
                &iam.policy_name,
            ));
            props.push(property(
                "scanner-provided-aws-iam-finding-identity",
                &iam.finding_identity,
            ));
            for action in &iam.actions {
                props.push(property("scanner-provided-aws-iam-action", action));
            }
            props.push(property(
                "scanner-provided-aws-iam-actions-complete",
                if iam.actions_complete {
                    "true"
                } else {
                    "false"
                },
            ));
            for role in &iam.attached_to.roles {
                props.push(property("scanner-provided-aws-iam-attached-role", role));
            }
            for group in &iam.attached_to.groups {
                props.push(property("scanner-provided-aws-iam-attached-group", group));
            }
            for user in &iam.attached_to.users {
                props.push(property("scanner-provided-aws-iam-attached-user", user));
            }
            props.push(property(
                "scanner-provided-aws-iam-attachments-complete",
                if iam.attached_to.complete {
                    "true"
                } else {
                    "false"
                },
            ));
        }
    }
    json!({
        "description": evidence.summary,
        "props": props
    })
}

fn property(name: &str, value: &str) -> Value {
    json!({
        "name": name,
        "ns": OSCAL_PROPERTY_NAMESPACE,
        "value": value
    })
}

fn enum_value<T: serde::Serialize>(value: &T, fallback: &str) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| fallback.to_owned())
}

fn evidence_kind_name(kind: &EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Configuration => "configuration",
        EvidenceKind::Observation => "observation",
        EvidenceKind::ExternalValidation => "external_validation",
        EvidenceKind::SourceCode => "source_code",
        EvidenceKind::PackageInventory => "package_inventory",
        EvidenceKind::UserDeclaration => "user_declaration",
        EvidenceKind::RawToolOutput => "raw_tool_output",
    }
}

fn stable_uuid(seed: &str) -> String {
    let digest = Sha256::digest(seed.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).to_string()
}

fn severity_name(severity: &Severity) -> &'static str {
    match severity {
        Severity::Unknown => "unknown",
        Severity::Informational => "informational",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn confidence_name(confidence: &Confidence) -> &'static str {
    match confidence {
        Confidence::Unknown => "unknown",
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
        Confidence::Confirmed => "confirmed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn oscal_export_preserves_unknown_ratings() {
        assert_eq!(severity_name(&Severity::Unknown), "unknown");
        assert_eq!(confidence_name(&Confidence::Unknown), "unknown");
    }

    fn fixture() -> AssessmentCase {
        let time = Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();
        let mut case = AssessmentCase::new(
            "Export".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "1-10".into(),
                data_classes: vec![DataClass::General],
                notes: None,
            },
        );
        case.id = "case-1".into();
        case.scan_runs.push(ScanRun {
            id: "run-1".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: time,
            completed_at: Some(time),
            request_outcome: None,
            report_asset_snapshots: Vec::new(),
            knowledge_cutoff: time,
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec![],
            scope_grant_snapshots: vec![],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![],
        });
        case.findings.push(Finding {
            family: None,
            severity_basis_code: None,
            confidence_basis_code: None,
            context_factors: Vec::new(),
            id: "finding-1".into(),
            case_id: case.id.clone(),
            first_seen_run_id: "run-1".into(),
            last_seen_run_id: "run-1".into(),
            fingerprint: "fp-1".into(),
            title: "Potential issue".into(),
            plain_language_summary: "A setting needs review.".into(),
            possible_impact: "Unexpected access".into(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            priority: 60,
            priority_reasons: vec![],
            asset_ids: vec!["asset-1".into()],
            evidence: vec![],
            control_references: vec![ControlReference {
                framework: "ISO/IEC 27001".into(),
                framework_version: "2022".into(),
                control_id: "A.8.3".into(),
                title: "Information access restriction".into(),
                relationship: "related".into(),
                rationale: "Possible relationship".into(),
                mapping_version: "1".into(),
                mapping_provenance: None,
            }],
            recommendation: "Have the system owner review it.".into(),
            verification_guidance: "Repeat the read-only inspection.".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Security engineer".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![],
        });
        case.finding_observations.push(FindingObservation {
            id: "observation-1".into(),
            run_id: "run-1".into(),
            finding_id: "finding-1".into(),
            fingerprint: "fp-1".into(),
            asset_ids: vec!["asset-1".into()],
            engine_ids: vec!["engine-1".into()],
            severity: Severity::Medium,
            confidence: Confidence::High,
            evidence_hashes: vec!["abc".into()],
            observed_at: time,
            finding_snapshot: None,
        });
        case
    }

    #[test]
    fn emits_observations_and_coordinate_only_control_properties() {
        let mut case = fixture();
        case.findings[0].family = Some(FindingFamily::CloudPosture);
        case.findings[0].severity_basis_code = Some(SeverityBasisCode::CloudControlQuery);
        case.findings[0].confidence_basis_code =
            Some(ConfidenceBasisCode::DeterministicPolicyEvaluation);
        case.findings[0].context_factors = vec![ContextFactor::SensitiveDataAsset];
        case.findings[0].rollback_considerations = Some("Keep the prior policy available.".into());
        case.findings[0].official_references = vec!["https://example.invalid/rule".into()];
        let value = export_oscal_assessment_results(&case, "run-1").unwrap();
        let root = &value["assessment-results"];
        assert_eq!(root["metadata"]["oscal-version"], OSCAL_VERSION);
        let result = &root["results"][0];
        assert!(result.get("findings").is_none());
        assert!(result.get("risks").is_none());
        assert!(result.get("attestations").is_none());
        assert!(
            result["reviewed-controls"]["control-selections"][0]
                .get("include-all")
                .is_none()
        );
        assert_eq!(
            result["reviewed-controls"]["control-selections"][0]["include-controls"][0]["control-id"],
            "ai-security-scanner-no-formal-controls-reviewed"
        );
        let props = result["observations"][0]["props"].as_array().unwrap();
        let coordinate = props
            .iter()
            .find(|prop| prop["name"] == "related-control-coordinate")
            .unwrap();
        assert_eq!(coordinate["value"], "ISO/IEC 27001@2022:A.8.3");
        assert!(
            coordinate["remarks"]
                .as_str()
                .unwrap()
                .contains("no assessment result")
        );
        let property_value = |name: &str| {
            props
                .iter()
                .find(|property| property["name"] == name)
                .map(|property| property["value"].clone())
        };
        assert_eq!(
            property_value("possible-impact"),
            Some(json!("Unexpected access"))
        );
        assert_eq!(
            property_value("recommendation"),
            Some(json!("Have the system owner review it."))
        );
        assert_eq!(
            property_value("finding-family"),
            Some(json!("cloud_posture"))
        );
        assert_eq!(
            property_value("severity-basis"),
            Some(json!("cloud_control_query"))
        );
        assert_eq!(
            property_value("confidence-basis"),
            Some(json!("deterministic_policy_evaluation"))
        );
        assert_eq!(
            property_value("context-factor"),
            Some(json!("sensitive_data_asset"))
        );
        assert_eq!(
            property_value("official-reference"),
            Some(json!("https://example.invalid/rule"))
        );
    }

    #[test]
    fn preserves_generic_upstream_evidence_identity_and_location() {
        let mut case = fixture();
        let evidence = Evidence {
            id: "evidence-1".into(),
            finding_id: "finding-1".into(),
            run_id: "run-1".into(),
            engine_run_id: Some("engine-run-1".into()),
            kind: EvidenceKind::Configuration,
            engine_id: "cloudsplaining".into(),
            scanner_details: Some(ScannerFindingDetails {
                description: Some("Upstream scanner explanation".into()),
                remediation: Some("Upstream scanner remediation".into()),
                installed_version: Some("1.2.3".into()),
                fixed_version: Some("1.2.4".into()),
                aws_iam_policy: Some(AwsIamPolicyFindingDetails {
                    policy_source: AwsIamPolicySource::CustomerManaged,
                    policy_name: "NarrowMe".into(),
                    finding_identity: "s3:GetObject".into(),
                    actions: vec!["s3:GetObject".into()],
                    actions_complete: true,
                    attached_to: AwsIamAttachedTo {
                        roles: vec!["ReadRole".into()],
                        groups: vec![],
                        users: vec!["Analyst".into()],
                        complete: false,
                    },
                }),
                cwe_ids: Vec::new(),
                cvss: Vec::new(),
                benchmarks: Vec::new(),
                advisory_aliases: Vec::new(),
            }),
            source_rule: Some("DataExfiltration".into()),
            result_pointer_sha256: Some("def".into()),
            observed_at: case.finding_observations[0].observed_at,
            summary: "Upstream evidence summary".into(),
            location: Some("config/policy.json:4".into()),
            artifact_id: "artifact-1".into(),
            artifact_sha256: "abc".into(),
            pointer: Some("/results/0".into()),
            redacted: false,
        };
        case.findings[0].evidence = vec![evidence];

        let value = export_oscal_assessment_results(&case, "run-1").unwrap();
        let relevant =
            &value["assessment-results"]["results"][0]["observations"][0]["relevant-evidence"][0];
        let props = relevant["props"].as_array().unwrap();
        let has = |name: &str, expected: &str| {
            props
                .iter()
                .any(|property| property["name"] == name && property["value"] == expected)
        };

        assert_eq!(relevant["description"], "Upstream evidence summary");
        assert!(has("evidence-kind", "configuration"));
        assert!(has("source-engine-id", "cloudsplaining"));
        assert!(has("source-rule-id", "DataExfiltration"));
        assert!(has("result-pointer-sha-256", "def"));
        assert!(has("evidence-location", "config/policy.json:4"));
        assert!(has("result-pointer", "/results/0"));
        assert!(has("scanner-provided-details-trust", "untrusted"));
        assert!(has(
            "scanner-provided-description",
            "Upstream scanner explanation"
        ));
        assert!(has(
            "scanner-provided-remediation",
            "Upstream scanner remediation"
        ));
        assert!(has("scanner-provided-installed-version", "1.2.3"));
        assert!(has("scanner-provided-fixed-version", "1.2.4"));
        assert!(has(
            "scanner-provided-aws-iam-policy-source",
            "customer_managed"
        ));
        assert!(has("scanner-provided-aws-iam-policy-name", "NarrowMe"));
        assert!(has(
            "scanner-provided-aws-iam-finding-identity",
            "s3:GetObject"
        ));
        assert!(has("scanner-provided-aws-iam-action", "s3:GetObject"));
        assert!(has("scanner-provided-aws-iam-actions-complete", "true"));
        assert!(has("scanner-provided-aws-iam-attached-role", "ReadRole"));
        assert!(has("scanner-provided-aws-iam-attached-user", "Analyst"));
        assert!(has(
            "scanner-provided-aws-iam-attachments-complete",
            "false"
        ));
        for name in [
            "scanner-provided-details-trust",
            "scanner-provided-description",
            "scanner-provided-remediation",
            "scanner-provided-installed-version",
            "scanner-provided-fixed-version",
            "scanner-provided-aws-iam-policy-source",
            "scanner-provided-aws-iam-policy-name",
            "scanner-provided-aws-iam-finding-identity",
            "scanner-provided-aws-iam-action",
            "scanner-provided-aws-iam-actions-complete",
            "scanner-provided-aws-iam-attached-role",
            "scanner-provided-aws-iam-attached-user",
            "scanner-provided-aws-iam-attachments-complete",
        ] {
            assert!(props.iter().any(|property| {
                property["name"] == name && property["ns"] == OSCAL_PROPERTY_NAMESPACE
            }));
        }
        let remarks = value["assessment-results"]["results"][0]["observations"][0]["remarks"]
            .as_str()
            .expect("product remarks");
        assert!(remarks.contains("Have the system owner review it."));
        assert!(!remarks.contains("Upstream scanner remediation"));
    }

    #[test]
    fn reachable_service_is_an_inventory_observation_without_vulnerability_remediation() {
        let mut case = fixture();
        let finding = &mut case.findings[0];
        finding.severity = Severity::Informational;
        finding.severity_basis_code = Some(SeverityBasisCode::ReachableHttpService);
        finding.plain_language_summary = "STALE_EXPOSURE_SUMMARY".into();
        finding.possible_impact = "STALE_EXPOSURE_IMPACT".into();
        finding.recommendation = "STALE_EXPOSURE_REMEDIATION".into();
        finding.verification_guidance = "STALE_EXPOSURE_VERIFICATION".into();
        finding.tags = vec!["http-status:200".into()];
        case.finding_observations[0].severity = Severity::Informational;

        let value = export_oscal_assessment_results(&case, "run-1").unwrap();
        let observation = &value["assessment-results"]["results"][0]["observations"][0];
        let props = observation["props"].as_array().unwrap();

        assert!(props.iter().any(|property| {
            property["name"] == "record-kind"
                && property["value"] == "service-inventory-observation"
        }));
        assert!(props.iter().any(|property| {
            property["name"] == "observation-kind" && property["value"] == "reachable_http_service"
        }));
        assert_eq!(
            observation["types"],
            json!(["inventory", "service-discovery"])
        );
        assert_eq!(
            observation["description"],
            crate::finding_narrative::EXPOSURE_OBSERVATION_RISK
        );
        assert_eq!(
            observation["remarks"],
            crate::finding_narrative::EXPOSURE_OBSERVATION_NEXT_STEP
        );
        let encoded = observation.to_string();
        assert!(!encoded.contains("STALE_EXPOSURE"));
        assert!(encoded.contains("Canonical evidence content hash"));
    }

    #[test]
    fn stable_uuid_is_repeatable_and_well_formed() {
        let first = stable_uuid("same input");
        assert_eq!(first, stable_uuid("same input"));
        assert!(Uuid::parse_str(&first).is_ok());
    }

    #[test]
    fn historical_export_uses_the_run_specific_finding_snapshot() {
        let mut case = fixture();
        let mut original = case.findings[0].clone();
        original.title = "Run one title".into();
        original.plain_language_summary = "Run one summary".into();
        original.status = FindingStatus::FalsePositive;
        case.finding_observations[0].finding_snapshot = Some(original);
        case.findings[0].title = "Later run title".into();
        case.findings[0].plain_language_summary = "Later run summary".into();
        case.findings[0].status = FindingStatus::Confirmed;

        let value =
            export_oscal_assessment_results(&case, "run-1").expect("historical OSCAL export");
        let observation = &value["assessment-results"]["results"][0]["observations"][0];

        assert_eq!(observation["title"], "Run one title");
        assert!(
            observation["description"]
                .as_str()
                .expect("description")
                .contains("Run one summary")
        );
        assert!(
            observation["props"]
                .as_array()
                .unwrap()
                .iter()
                .any(|property| {
                    property["name"] == "finding-status" && property["value"] == "confirmed"
                })
        );
        assert!(!observation.to_string().contains("Later run"));
    }

    #[test]
    fn active_run_cannot_be_exported() {
        let mut case = fixture();
        case.scan_runs[0].completed_at = None;

        let error = export_oscal_assessment_results(&case, "run-1").unwrap_err();
        assert!(
            matches!(error, crate::error::AppError::NotAvailable(message) if message == "scan is in progress")
        );
    }

    #[test]
    fn dangling_observation_does_not_suppress_valid_siblings() {
        let mut case = fixture();
        let mut dangling = case.finding_observations[0].clone();
        dangling.id = "observation-dangling".into();
        dangling.finding_id = "finding-missing".into();
        dangling.fingerprint = "fp-missing".into();
        dangling.finding_snapshot = None;
        case.finding_observations.push(dangling);

        let value = export_oscal_assessment_results(&case, "run-1").unwrap();
        let observations = value["assessment-results"]["results"][0]["observations"]
            .as_array()
            .unwrap();

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0]["title"], "Potential issue");
    }
}
