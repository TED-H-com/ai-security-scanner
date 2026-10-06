use crate::domain::{
    AssessmentCase, Asset, Confidence, Evidence, Finding, FindingObservation, FindingStatus,
    Severity,
};
use crate::error::AppResult;
use crate::exporters::terminal_run;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OCSF_SCHEMA_VERSION: &str = "1.10.0-dev";
pub const OCSF_EXPORT_NOTICE: &str = "Preliminary scanner observations only. Related control references are navigation coordinates, not compliance results. This export is not an audit or forensic conclusion.";

/// Convert canonical observations for one run into OCSF events.
///
/// Security problems use Detection Finding (class UID 2004). Naabu/httpx
/// reachability rows use Network Activity (class UID 4001) because a service
/// response is an inventory observation, not a detection finding.
pub fn export_ocsf_finding_events(case: &AssessmentCase, run_id: &str) -> AppResult<Vec<Value>> {
    terminal_run(case, run_id)?;

    let findings = case
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let assets = case
        .assets
        .iter()
        .map(|asset| (asset.id.as_str(), asset))
        .collect::<BTreeMap<_, _>>();

    let mut observations = case
        .finding_observations
        .iter()
        .filter(|observation| observation.run_id == run_id)
        .collect::<Vec<_>>();
    observations.sort_by(|left, right| {
        left.fingerprint
            .cmp(&right.fingerprint)
            .then_with(|| left.id.cmp(&right.id))
    });

    Ok(observations
        .into_iter()
        .filter_map(|observation| {
            let canonical_finding = findings.get(observation.finding_id.as_str()).copied();
            let finding = observation
                .finding_snapshot
                .as_ref()
                .or(canonical_finding)?;
            // Normalized evidence and prose are run-specific, while workflow
            // state is a current case projection (including expired temporary
            // suppressions). Never revive stale snapshot status in an export.
            let effective_status = canonical_finding
                .map(|canonical| &canonical.status)
                .unwrap_or(&finding.status);
            Some(to_event(
                case,
                run_id,
                finding,
                effective_status,
                observation,
                &assets,
            ))
        })
        .collect())
}

pub fn export_ocsf_finding_events_bytes(case: &AssessmentCase, run_id: &str) -> AppResult<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(&export_ocsf_finding_events(
        case, run_id,
    )?)?)
}

fn to_event(
    case: &AssessmentCase,
    run_id: &str,
    finding: &Finding,
    effective_status: &FindingStatus,
    observation: &FindingObservation,
    assets: &BTreeMap<&str, &Asset>,
) -> Value {
    let activity_id = if finding.first_seen_run_id == run_id {
        1
    } else {
        2
    };
    let activity_name = if activity_id == 1 { "Create" } else { "Update" };
    let (severity_id, severity) = ocsf_severity(&observation.severity);
    let (confidence_id, confidence) = ocsf_confidence(&observation.confidence);
    let (status_id, status) = ocsf_status(effective_status);

    let first_seen_time = case
        .scan_runs
        .iter()
        .find(|run| run.id == finding.first_seen_run_id)
        .map(|run| run.created_at.timestamp_millis())
        .unwrap_or_else(|| observation.observed_at.timestamp_millis());

    let mut asset_ids = observation.asset_ids.clone();
    asset_ids.sort();
    asset_ids.dedup();
    let resources = asset_ids
        .iter()
        .map(|asset_id| match assets.get(asset_id.as_str()) {
            Some(asset) => resource_value(asset),
            None => json!({
                "uid": asset_id,
                "name": "Unknown canonical asset",
                "role_id": 3,
                "role": "Affected"
            }),
        })
        .collect::<Vec<_>>();

    let mut evidence = finding
        .evidence
        .iter()
        .filter(|evidence| evidence.run_id == run_id)
        .collect::<Vec<_>>();
    evidence.sort_by(|left, right| left.id.cmp(&right.id));
    let evidences = if evidence.is_empty() {
        let mut hashes = observation.evidence_hashes.clone();
        hashes.sort();
        hashes.dedup();
        hashes
            .into_iter()
            .map(|sha256| {
                json!({
                    "name": "Canonical evidence hash",
                    "data": { "sha256": sha256 }
                })
            })
            .collect::<Vec<_>>()
    } else {
        evidence.into_iter().map(evidence_value).collect()
    };

    let control_coordinates = finding
        .control_references
        .iter()
        .map(|reference| {
            json!({
                "framework": reference.framework,
                "framework_version": reference.framework_version,
                "control_id": reference.control_id,
                "title": reference.title,
                "relationship": reference.relationship,
                "rationale": reference.rationale,
                "mapping_version": reference.mapping_version,
                "assertion": "related_coordinate_only"
            })
        })
        .collect::<Vec<_>>();

    let mut engines = observation.engine_ids.clone();
    engines.sort();
    engines.dedup();

    if finding
        .severity_basis_code
        .is_some_and(|code| code.is_exposure_observation())
    {
        let observation_kind = serde_json::to_value(finding.severity_basis_code)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "reachable_service".into());
        let observation_details = finding
            .tags
            .iter()
            .filter(|tag| {
                tag.starts_with("port:")
                    || tag.starts_with("protocol:")
                    || tag.starts_with("http-status:")
            })
            .cloned()
            .collect::<Vec<_>>();
        let destination = asset_ids
            .first()
            .map(|asset_id| match assets.get(asset_id.as_str()) {
                Some(asset) => json!({ "uid": asset.id, "name": asset.name }),
                None => json!({ "uid": asset_id, "name": "Unknown canonical asset" }),
            });
        let mut event = json!({
            "activity_id": 1,
            "activity_name": "Open",
            "category_uid": 4,
            "category_name": "Network Activity",
            "class_uid": 4001,
            "class_name": "Network Activity",
            "type_uid": 400101,
            "type_name": "Network Activity: Open",
            "time": observation.observed_at.timestamp_millis(),
            "severity_id": severity_id,
            "severity": severity,
            "message": crate::finding_narrative::EXPOSURE_OBSERVATION_RISK,
            "resources": resources,
            "metadata": {
                "uid": observation.id,
                "original_event_uid": observation.id,
                "correlation_uid": case.id,
                "version": OCSF_SCHEMA_VERSION,
                "product": {
                    "name": "ai-security-scanner",
                    "vendor_name": "ai-security-scanner",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "source": "Scanner service inventory observation"
            },
            "unmapped": {
                "ai_security_scanner": {
                    "record_kind": "service_inventory_observation",
                    "observation_kind": observation_kind,
                    "canonical_record_id": finding.id,
                    "canonical_fingerprint": observation.fingerprint,
                    "canonical_confidence": confidence_name(&observation.confidence),
                    "observation_details": observation_details,
                    "engine_ids": engines,
                    "run_id": run_id,
                    "evidences": evidences,
                    "export_notice": OCSF_EXPORT_NOTICE,
                    "omitted_canonical_areas": [
                        "case scope grants",
                        "coverage ledger",
                        "asset relationships",
                        "workflow history"
                    ]
                }
            }
        });
        if let Some(destination) = destination {
            event
                .as_object_mut()
                .expect("OCSF inventory event is an object")
                .insert("dst_endpoint".into(), destination);
        }
        return event;
    }

    let scanner_extension = json!({
        "record_kind": "security_finding",
        "canonical_fingerprint": observation.fingerprint,
        "canonical_confidence": confidence_name(&observation.confidence),
        "finding_family": finding.family,
        "severity_basis": finding.severity_basis_code,
        "confidence_basis": finding.confidence_basis_code,
        "context_factors": finding.context_factors,
        "priority": finding.priority,
        "priority_reasons": finding.priority_reasons,
        "possible_impact": finding.possible_impact,
        "recommendation": finding.recommendation,
        "verification_guidance": finding.verification_guidance,
        "rollback_considerations": finding.rollback_considerations,
        "official_references": finding.official_references,
        "recommended_expert_type": finding.recommended_expert_type,
        "engine_ids": engines,
        "run_id": run_id,
        "related_control_coordinates": control_coordinates,
        "control_mapping_notice": "References are navigation coordinates only; no control pass, failure, compliance, or audit conclusion is asserted.",
        "export_notice": OCSF_EXPORT_NOTICE,
        "omitted_canonical_areas": [
            "case scope grants",
            "coverage ledger",
            "asset relationships",
            "workflow history"
        ]
    });
    json!({
        "activity_id": activity_id,
        "activity_name": activity_name,
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "type_uid": 200400 + activity_id,
        "type_name": format!("Detection Finding: {activity_name}"),
        "time": observation.observed_at.timestamp_millis(),
        "severity_id": severity_id,
        "severity": severity,
        "confidence_id": confidence_id,
        "confidence": confidence,
        "status_id": status_id,
        "status": status,
        "message": finding.plain_language_summary,
        "metadata": {
            "uid": observation.id,
            "original_event_uid": observation.id,
            "correlation_uid": case.id,
            "version": OCSF_SCHEMA_VERSION,
            "product": {
                "name": "ai-security-scanner",
                "vendor_name": "ai-security-scanner",
                "version": env!("CARGO_PKG_VERSION")
            },
            "source": "Canonical scanner observation"
        },
        "finding_info": {
            "uid": finding.id,
            "uid_alt": finding.fingerprint,
            "title": finding.title,
            "desc": finding.plain_language_summary,
            "created_time": first_seen_time,
            "first_seen_time": first_seen_time,
            "last_seen_time": observation.observed_at.timestamp_millis(),
            "types": ["Preliminary scanner observation"],
            "tags": finding.tags
        },
        "resources": resources,
        "evidences": evidences,
        "unmapped": {
            "ai_security_scanner": scanner_extension
        }
    })
}

fn resource_value(asset: &Asset) -> Value {
    let mut resource = Map::new();
    resource.insert("uid".into(), json!(asset.id));
    resource.insert("name".into(), json!(asset.name));
    resource.insert("type".into(), json!(asset_kind_name(asset)));
    resource.insert("role_id".into(), json!(3));
    resource.insert("role".into(), json!("Affected"));
    if let Some(provider) = &asset.provider {
        resource.insert("provider".into(), json!(provider));
    }
    if let Some(region) = &asset.region {
        resource.insert("region".into(), json!(region));
    }
    Value::Object(resource)
}

fn asset_kind_name(asset: &Asset) -> String {
    serde_json::to_value(&asset.kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "other".into())
}

fn evidence_value(evidence: &Evidence) -> Value {
    let mut data = json!({
        "summary": evidence.summary,
        "engine_id": evidence.engine_id,
        "source_rule": evidence.source_rule,
        "scan_run_id": evidence.run_id,
        "engine_run_id": evidence.engine_run_id,
        "artifact_uid": evidence.artifact_id,
        "artifact_sha256": evidence.artifact_sha256,
        "result_pointer_sha256": evidence.result_pointer_sha256,
        "location": evidence.location,
        "pointer": evidence.pointer,
        "redacted": evidence.redacted,
        "observed_time": evidence.observed_at.timestamp_millis()
    });
    if let Some(details) = &evidence.scanner_details {
        data.as_object_mut()
            .expect("OCSF evidence data is an object")
            .insert(
                "ai_security_scanner".into(),
                json!({
                    "scanner_provided_details": {
                        "trust": "untrusted",
                        "description": details.description,
                        "remediation": details.remediation,
                        "installed_version": details.installed_version,
                        "fixed_version": details.fixed_version,
                        "aws_iam_policy": details
                            .aws_iam_policy
                            .as_ref()
                            .filter(|_| evidence.engine_id == "cloudsplaining")
                    }
                }),
            );
    }
    json!({
        "uid": evidence.id,
        "name": format!("{:?}", evidence.kind),
        "data": data
    })
}

fn ocsf_severity(severity: &Severity) -> (u8, &'static str) {
    match severity {
        Severity::Unknown => (0, "Unknown"),
        Severity::Informational => (1, "Informational"),
        Severity::Low => (2, "Low"),
        Severity::Medium => (3, "Medium"),
        Severity::High => (4, "High"),
        Severity::Critical => (5, "Critical"),
    }
}

fn ocsf_confidence(confidence: &Confidence) -> (u8, &'static str) {
    match confidence {
        Confidence::Unknown => (0, "Unknown"),
        Confidence::Low => (1, "Low"),
        Confidence::Medium => (2, "Medium"),
        Confidence::High | Confidence::Confirmed => (3, "High"),
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

fn ocsf_status(status: &FindingStatus) -> (u8, &'static str) {
    match status {
        FindingStatus::Unreviewed => (1, "New"),
        FindingStatus::ExpertReviewRequested
        | FindingStatus::Confirmed
        | FindingStatus::RemediationReported => (2, "In Progress"),
        FindingStatus::FalsePositive => (3, "Suppressed"),
        FindingStatus::VerifiedResolved => (4, "Resolved"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::*;
    use chrono::{TimeZone, Utc};
    use std::collections::BTreeMap;

    #[test]
    fn unknown_ratings_use_the_ocsf_unknown_identifiers() {
        assert_eq!(ocsf_severity(&Severity::Unknown), (0, "Unknown"));
        assert_eq!(ocsf_confidence(&Confidence::Unknown), (0, "Unknown"));
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
        case.assets.push(Asset {
            id: "asset-1".into(),
            kind: AssetKind::CloudAccount,
            name: "Account".into(),
            provider: Some("AWS".into()),
            region: Some("us-east-1".into()),
            identifiers: vec![],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: None,
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        });
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
            title: "Public bucket".into(),
            plain_language_summary: "A bucket may be public.".into(),
            possible_impact: "Data exposure".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            priority: 90,
            priority_reasons: vec!["Internet exposed".into()],
            asset_ids: vec!["asset-1".into()],
            evidence: vec![],
            control_references: vec![ControlReference {
                framework: "NIST CSF".into(),
                framework_version: "2.0".into(),
                control_id: "PR.DS-01".into(),
                title: "Data-at-rest protection".into(),
                relationship: "related".into(),
                rationale: "Possible relationship".into(),
                mapping_version: "1".into(),
                mapping_provenance: None,
            }],
            recommendation: "Ask the cloud owner to review access.".into(),
            verification_guidance: "Re-run the read-only check.".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Cloud security engineer".into(),
            status: FindingStatus::Unreviewed,
            tags: vec!["cloud".into()],
        });
        case.finding_observations.push(FindingObservation {
            id: "observation-1".into(),
            run_id: "run-1".into(),
            finding_id: "finding-1".into(),
            fingerprint: "fp-1".into(),
            asset_ids: vec!["asset-1".into()],
            engine_ids: vec!["prowler".into()],
            severity: Severity::High,
            confidence: Confidence::Confirmed,
            evidence_hashes: vec!["abc".into()],
            observed_at: time,
            finding_snapshot: None,
        });
        case
    }

    #[test]
    fn maps_to_detection_finding_without_compliance_assertions() {
        let mut case = fixture();
        case.findings[0].family = Some(FindingFamily::CloudPosture);
        case.findings[0].severity_basis_code = Some(SeverityBasisCode::CloudControlQuery);
        case.findings[0].confidence_basis_code =
            Some(ConfidenceBasisCode::DeterministicPolicyEvaluation);
        case.findings[0].context_factors = vec![ContextFactor::InternetExposedAsset];
        let events = export_ocsf_finding_events(&case, "run-1").unwrap();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event["class_uid"], 2004);
        assert_eq!(event["type_uid"], 200401);
        assert_eq!(event["severity_id"], 4);
        assert_eq!(event["confidence_id"], 3);
        assert_eq!(event["resources"][0]["uid"], "asset-1");
        assert_eq!(event["finding_info"]["uid"], "finding-1");
        assert!(event.get("compliance").is_none());
        let coordinates = &event["unmapped"]["ai_security_scanner"]["related_control_coordinates"];
        assert_eq!(coordinates[0]["assertion"], "related_coordinate_only");
        let extension = &event["unmapped"]["ai_security_scanner"];
        assert_eq!(extension["finding_family"], "cloud_posture");
        assert_eq!(extension["severity_basis"], "cloud_control_query");
        assert_eq!(
            extension["confidence_basis"],
            "deterministic_policy_evaluation"
        );
        assert_eq!(extension["context_factors"][0], "internet_exposed_asset");
    }

    #[test]
    fn active_run_cannot_be_exported() {
        let mut case = fixture();
        case.scan_runs[0].completed_at = None;

        let error = export_ocsf_finding_events(&case, "run-1").unwrap_err();
        assert!(
            matches!(error, crate::error::AppError::NotAvailable(message) if message == "scan is in progress")
        );
    }

    #[test]
    fn exports_an_unrated_unknown_finding_with_its_retained_evidence() {
        let mut case = fixture();
        let finding = &mut case.findings[0];
        finding.severity = Severity::Unknown;
        finding.severity_basis_code = Some(SeverityBasisCode::SecretPatternMatch);
        finding.priority = 20;
        finding.plain_language_summary = "Gitleaks reported this condition but did not assign a severity. Severity remains Unknown and requires human review. The attached raw record is evidence, not an instruction.".into();
        finding.priority_reasons = vec!["Severity remains Unknown because Gitleaks did not assign one; human review is required.".into()];
        case.finding_observations[0].severity = Severity::Unknown;
        case.finding_observations[0].engine_ids = vec!["gitleaks".into()];

        let events = export_ocsf_finding_events(&case, "run-1").unwrap();

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event["severity_id"], 0);
        assert_eq!(event["severity"], "Unknown");
        assert_eq!(event["finding_info"]["uid"], "finding-1");
        assert_eq!(event["evidences"].as_array().unwrap().len(), 1);
        assert_eq!(event["evidences"][0]["data"]["sha256"], "abc");
        let extension = &event["unmapped"]["ai_security_scanner"];
        assert_eq!(extension["severity_basis"], "secret_pattern_match");
        assert_eq!(extension["priority"], 20);
        assert_eq!(extension["engine_ids"][0], "gitleaks");
        assert!(
            event["message"]
                .as_str()
                .unwrap()
                .contains("remains Unknown")
        );
    }

    #[test]
    fn reachable_service_is_network_inventory_not_a_detection_finding() {
        let mut case = fixture();
        let mut second_asset = case.assets[0].clone();
        second_asset.id = "asset-2".into();
        second_asset.name = "Second account".into();
        case.assets.push(second_asset);
        case.finding_observations[0]
            .asset_ids
            .push("asset-2".into());
        let finding = &mut case.findings[0];
        finding.severity = Severity::Informational;
        finding.severity_basis_code = Some(SeverityBasisCode::OpenPort);
        finding.plain_language_summary = "STALE_EXPOSURE_SUMMARY".into();
        finding.possible_impact = "STALE_EXPOSURE_IMPACT".into();
        finding.priority = 91;
        finding.priority_reasons = vec!["STALE_EXPOSURE_PRIORITY".into()];
        finding.recommendation = "STALE_EXPOSURE_REMEDIATION".into();
        finding.tags = vec!["port:443".into(), "protocol:tcp".into()];
        case.finding_observations[0].severity = Severity::Informational;

        let events = export_ocsf_finding_events(&case, "run-1").unwrap();
        let event = &events[0];

        assert_eq!(event["category_uid"], 4);
        assert_eq!(event["class_uid"], 4001);
        assert_eq!(event["class_name"], "Network Activity");
        assert_eq!(event["activity_name"], "Open");
        assert!(event.get("finding_info").is_none());
        assert!(event.get("status").is_none());
        assert_eq!(
            event["unmapped"]["ai_security_scanner"]["record_kind"],
            "service_inventory_observation"
        );
        assert_eq!(
            event["unmapped"]["ai_security_scanner"]["observation_kind"],
            "open_port"
        );
        assert_eq!(event["dst_endpoint"]["uid"], "asset-1");
        assert_eq!(event["resources"].as_array().unwrap().len(), 2);
        assert_eq!(event["resources"][1]["uid"], "asset-2");
        let encoded = event.to_string();
        assert!(!encoded.contains("STALE_EXPOSURE"));
        assert!(!encoded.contains("priority"));
        assert!(!encoded.contains("recommendation"));
        assert!(encoded.contains("Canonical evidence hash"));
    }

    #[test]
    fn historical_export_uses_the_observation_snapshot_not_latest_projection() {
        let mut case = fixture();
        let mut original = case.findings[0].clone();
        original.title = "Run one title".into();
        original.plain_language_summary = "Run one summary".into();
        original.status = FindingStatus::FalsePositive;
        original.evidence.push(Evidence {
            id: "evidence-1".into(),
            finding_id: original.id.clone(),
            run_id: "run-1".into(),
            engine_run_id: None,
            kind: EvidenceKind::Configuration,
            engine_id: "cloudsplaining".into(),
            scanner_details: Some(ScannerFindingDetails {
                description: Some("Upstream scanner explanation".into()),
                remediation: Some("Upstream scanner remediation".into()),
                installed_version: Some("1.2.3".into()),
                fixed_version: Some("1.2.4".into()),
                aws_iam_policy: Some(AwsIamPolicyFindingDetails {
                    policy_source: AwsIamPolicySource::AwsManaged,
                    policy_name: "IAMFullAccess".into(),
                    finding_identity: "CreateAccessKey".into(),
                    actions: vec!["iam:createaccesskey".into()],
                    actions_complete: true,
                    attached_to: AwsIamAttachedTo {
                        roles: vec!["BuildRole".into()],
                        groups: vec!["AdminGroup".into()],
                        users: vec![],
                        complete: true,
                    },
                }),
                cwe_ids: Vec::new(),
                cvss: Vec::new(),
                benchmarks: Vec::new(),
                advisory_aliases: Vec::new(),
            }),
            source_rule: Some("PrivilegeEscalation".into()),
            result_pointer_sha256: Some("def".into()),
            observed_at: Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap(),
            summary: "Run one evidence".into(),
            location: Some("config/policy.json:4".into()),
            artifact_id: "artifact-1".into(),
            artifact_sha256: "abc".into(),
            pointer: None,
            redacted: false,
        });
        case.finding_observations[0].finding_snapshot = Some(original);
        case.findings[0].title = "Later run title".into();
        case.findings[0].plain_language_summary = "Later run summary".into();
        case.findings[0].severity = Severity::Unknown;
        case.findings[0].priority = 20;
        case.findings[0].evidence.clear();

        let events = export_ocsf_finding_events(&case, "run-1").expect("historical export");

        assert_eq!(events[0]["finding_info"]["title"], "Run one title");
        assert_eq!(events[0]["message"], "Run one summary");
        assert_eq!(events[0]["severity"], "High");
        assert_eq!(events[0]["unmapped"]["ai_security_scanner"]["priority"], 90);
        assert_eq!(events[0]["status"], "New");
        assert_eq!(
            events[0]["evidences"][0]["data"]["summary"],
            "Run one evidence"
        );
        assert_eq!(
            events[0]["evidences"][0]["data"]["engine_id"],
            "cloudsplaining"
        );
        assert_eq!(
            events[0]["evidences"][0]["data"]["source_rule"],
            "PrivilegeEscalation"
        );
        assert_eq!(
            events[0]["evidences"][0]["data"]["result_pointer_sha256"],
            "def"
        );
        assert_eq!(
            events[0]["evidences"][0]["data"]["location"],
            "config/policy.json:4"
        );
        let scanner_details =
            &events[0]["evidences"][0]["data"]["ai_security_scanner"]["scanner_provided_details"];
        assert_eq!(scanner_details["trust"], "untrusted");
        assert_eq!(
            scanner_details["description"],
            "Upstream scanner explanation"
        );
        assert_eq!(
            scanner_details["remediation"],
            "Upstream scanner remediation"
        );
        assert_eq!(scanner_details["installed_version"], "1.2.3");
        assert_eq!(scanner_details["fixed_version"], "1.2.4");
        assert_eq!(
            scanner_details["aws_iam_policy"]["policy_source"],
            "aws_managed"
        );
        assert_eq!(
            scanner_details["aws_iam_policy"]["policy_name"],
            "IAMFullAccess"
        );
        assert_eq!(
            scanner_details["aws_iam_policy"]["finding_identity"],
            "CreateAccessKey"
        );
        assert_eq!(
            scanner_details["aws_iam_policy"]["actions"],
            json!(["iam:createaccesskey"])
        );
        assert_eq!(scanner_details["aws_iam_policy"]["actions_complete"], true);
        assert_eq!(
            scanner_details["aws_iam_policy"]["attached_to"]["roles"],
            json!(["BuildRole"])
        );
        assert_eq!(
            events[0]["unmapped"]["ai_security_scanner"]["recommendation"],
            "Ask the cloud owner to review access."
        );
        assert!(!events[0].to_string().contains("Later run"));
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

        let events = export_ocsf_finding_events(&case, "run-1").unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["finding_info"]["title"], "Public bucket");
    }
}
