use crate::coverage::NOT_APPLICABLE_REASON_METADATA;
use crate::domain::*;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

fn artifact_hash(content: &str) -> String {
    hex::encode(Sha256::digest(content.as_bytes()))
}

pub fn build_demo_case() -> AssessmentCase {
    let now = Utc::now();
    let mut case = AssessmentCase::new(
        "Demo case: Northstar online services".into(),
        OrganizationProfile {
            organization_name: "Northstar Demo Co.".into(),
            employee_range: "11-50".into(),
            data_classes: vec![
                DataClass::PersonallyIdentifiableInformation,
                DataClass::CredentialsAndSecrets,
            ],
            notes: Some("This is synthetic demo data, not a real scan result.".into()),
        },
    );
    case.is_demo = true;
    case.status = CaseStatus::ReadyForHandoff;
    case.knowledge_cutoff = Some(now - Duration::days(2));
    case.requested_activities = vec![
        AssessmentActivity::ConfigurationAssessment,
        AssessmentActivity::LocalArtifactAnalysis,
        AssessmentActivity::LowImpactExternalChecks,
    ];

    let aws_source_id = new_id();
    let dns_source_id = new_id();
    let azure_source_id = new_id();
    let gcp_source_id = new_id();
    case.data_sources = vec![
        DataSource {
            id: aws_source_id.clone(),
            kind: SourceKind::AwsOrganization,
            label: "AWS Organization (read-only demo)".into(),
            status: SourceConnectionStatus::Connected,
            connected_at: Some(now - Duration::days(3)),
            last_discovered_at: Some(now - Duration::days(2)),
            read_only: true,
            metadata: BTreeMap::new(),
        },
        DataSource {
            id: dns_source_id.clone(),
            kind: SourceKind::Dns,
            label: "northstar.example DNS".into(),
            status: SourceConnectionStatus::Connected,
            connected_at: Some(now - Duration::days(3)),
            last_discovered_at: Some(now - Duration::days(2)),
            read_only: true,
            metadata: BTreeMap::new(),
        },
        DataSource {
            id: azure_source_id,
            kind: SourceKind::AzureTenant,
            label: "Azure Tenant".into(),
            status: SourceConnectionStatus::NotApplicable,
            connected_at: None,
            last_discovered_at: None,
            read_only: true,
            metadata: BTreeMap::from([(
                NOT_APPLICABLE_REASON_METADATA.into(),
                serde_json::Value::String(
                    "The synthetic questionnaire states that Azure is not used in this case."
                        .into(),
                ),
            )]),
        },
        DataSource {
            id: gcp_source_id,
            kind: SourceKind::GcpOrganization,
            label: "Google Cloud Organization".into(),
            status: SourceConnectionStatus::NotConnected,
            connected_at: None,
            last_discovered_at: None,
            read_only: true,
            metadata: BTreeMap::new(),
        },
    ];

    let account_id = new_id();
    let bucket_id = new_id();
    let domain_id = new_id();
    let unknown_host_id = new_id();
    case.assets = vec![
        Asset {
            id: account_id.clone(),
            kind: AssetKind::CloudAccount,
            name: "northstar-production".into(),
            provider: Some("aws".into()),
            region: Some("us-east-1".into()),
            identifiers: vec![AssetIdentifier {
                namespace: "aws_account_id".into(),
                value: "111122223333".into(),
            }],
            discovered_from: vec![aws_source_id.clone()],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(false),
            contains_sensitive_data: Some(true),
            metadata: BTreeMap::new(),
        },
        Asset {
            id: bucket_id.clone(),
            kind: AssetKind::CloudResource,
            name: "northstar-customer-exports".into(),
            provider: Some("aws".into()),
            region: Some("us-east-1".into()),
            identifiers: vec![AssetIdentifier {
                namespace: "aws_arn".into(),
                value: "arn:aws:s3:::northstar-customer-exports".into(),
            }],
            discovered_from: vec![aws_source_id.clone()],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(true),
            contains_sensitive_data: Some(true),
            metadata: BTreeMap::new(),
        },
        Asset {
            id: domain_id.clone(),
            kind: AssetKind::Domain,
            name: "portal.northstar.example".into(),
            provider: None,
            region: None,
            identifiers: vec![AssetIdentifier {
                namespace: "dns_name".into(),
                value: "portal.northstar.example".into(),
            }],
            discovered_from: vec![dns_source_id],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(true),
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        },
        Asset {
            id: unknown_host_id.clone(),
            kind: AssetKind::IpAddress,
            name: "198.51.100.24 (synthetic candidate)".into(),
            provider: None,
            region: None,
            identifiers: vec![AssetIdentifier {
                namespace: "ip".into(),
                value: "198.51.100.24".into(),
            }],
            discovered_from: vec![aws_source_id.clone()],
            candidate: true,
            owner_confirmed: false,
            internet_exposed: Some(true),
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        },
    ];

    case.asset_relations.push(AssetRelation {
        id: new_id(),
        from_asset_id: account_id.clone(),
        to_asset_id: bucket_id.clone(),
        kind: RelationKind::Contains,
        evidence_ids: Vec::new(),
    });

    let scope_id = new_id();
    case.scope_grants = vec![ScopeGrant {
        id: scope_id.clone(),
        asset_id: account_id.clone(),
        permission: ScanPermission::ConfigurationRead,
        confirmed_by: "Demo operator".into(),
        confirmed_at: now - Duration::days(2),
        expires_at: Some(now + Duration::hours(1)),
        authorization_reference: Some("SYNTHETIC-DEMO".into()),
        notes: Some("Synthetic demonstration only".into()),
        external_scope: None,
    }];

    let run_id = new_id();
    let prowler_run_id = new_id();
    let httpx_run_id = new_id();
    case.scan_runs.push(ScanRun {
        campaign_id: None,
        id: run_id.clone(),
        case_id: case.id.clone(),
        sequence: 1,
        created_at: now - Duration::days(2),
        completed_at: Some(now - Duration::days(2) + Duration::minutes(18)),
        request_outcome: None,
        report_asset_snapshots: Vec::new(),
        knowledge_cutoff: now - Duration::days(2),
        ai_system_applicable: false,
        ai_system_applicability: AiSystemApplicabilityAnswer::NotApplicable,
        ai_generated_artifact: Default::default(),
        verification_baseline_run_id: None,
        scope_grant_ids: vec![scope_id],
        scope_grant_snapshots: case.scope_grants.clone(),
        engine_admission_issues: Vec::new(),
        engine_runs: vec![
            EngineRun {
                id: prowler_run_id.clone(),
                scan_run_id: run_id.clone(),
                engine_id: "prowler".into(),
                task_kind: Default::default(),
                localhost_tcp_observation: None,
                asset_ids: vec![account_id.clone(), bucket_id.clone()],
                status: EngineRunStatus::Completed,
                progress_percent: 100,
                phase: "completed".into(),
                started_at: Some(now - Duration::days(2)),
                finished_at: Some(now - Duration::days(2) + Duration::minutes(14)),
                resume_token: None,
                last_execution_report_sha256: None,
                engine_version: Some("synthetic-demo".into()),
                reported_version: None,
                image_digest: Some("sha256:synthetic-demo-not-an-image".into()),
                rule_version: Some("synthetic-demo".into()),
                adapter_version: "0.1.2-demo".into(),
                manifest_schema_version: Some("synthetic-demo".into()),
                source_revision: Some("synthetic-demo".into()),
                repository_url: None,
                distribution_mode: None,
                image_repository: None,
                command_sha256: None,
                execution_timeout_seconds: None,
                knowledge_input: None,
                scope_contract_sha256: None,
                comparison_scope_sha256: None,
                execution_scope_grant_ids: None,
                naabu_work_plan: None,
                naabu_attempt_requests: Vec::new(),
                naabu_attempt_results: Vec::new(),
                mapping_version: None,
                mapping_provenance: None,
                fingerprint_schema_version: None,
                runtime_provider: None,
                runtime_version: None,
                runtime_security_options: None,
                exit_code: Some(0),
                cleanup_removed: Some(true),
                cleanup_detail: Some("Synthetic demonstration only".into()),
                gateway_refusals: None,
                warnings: vec!["Synthetic demonstration data; no scanner was executed.".into()],
                unattributed: Vec::new(),
                unevaluated_targets: Vec::new(),
                security_template_executions: Vec::new(),
                manual_review_controls: Vec::new(),
                raw_artifact_ids: Vec::new(),
                error_code: None,
                error_message: None,
            },
            EngineRun {
                id: httpx_run_id.clone(),
                scan_run_id: run_id.clone(),
                engine_id: "httpx".into(),
                task_kind: Default::default(),
                localhost_tcp_observation: None,
                asset_ids: vec![domain_id.clone()],
                status: EngineRunStatus::PartiallyCompleted,
                progress_percent: 72,
                phase: "failed".into(),
                started_at: Some(now - Duration::days(2) + Duration::minutes(3)),
                finished_at: Some(now - Duration::days(2) + Duration::minutes(18)),
                resume_token: None,
                last_execution_report_sha256: None,
                engine_version: Some("synthetic-demo".into()),
                reported_version: None,
                image_digest: None,
                rule_version: None,
                adapter_version: "0.1.2-demo".into(),
                manifest_schema_version: Some("synthetic-demo".into()),
                source_revision: Some("synthetic-demo".into()),
                repository_url: None,
                distribution_mode: None,
                image_repository: None,
                command_sha256: None,
                execution_timeout_seconds: None,
                knowledge_input: None,
                scope_contract_sha256: None,
                comparison_scope_sha256: None,
                execution_scope_grant_ids: None,
                naabu_work_plan: None,
                naabu_attempt_requests: Vec::new(),
                naabu_attempt_results: Vec::new(),
                mapping_version: None,
                mapping_provenance: None,
                fingerprint_schema_version: None,
                runtime_provider: None,
                runtime_version: None,
                runtime_security_options: None,
                exit_code: Some(2),
                cleanup_removed: Some(true),
                cleanup_detail: Some("Synthetic demonstration only".into()),
                gateway_refusals: None,
                warnings: vec!["Synthetic demonstration data; no scanner was executed.".into()],
                unattributed: Vec::new(),
                unevaluated_targets: Vec::new(),
                security_template_executions: Vec::new(),
                manual_review_controls: Vec::new(),
                raw_artifact_ids: Vec::new(),
                error_code: Some("TARGET_TIMEOUT".into()),
                error_message: Some("One synthetic target timed out.".into()),
            },
        ],
    });
    // Freeze the requested assets the way planning does for a real run, so
    // the example report labels its targets from the run.
    let requested_asset_ids = case.scan_runs[0]
        .engine_runs
        .iter()
        .flat_map(|engine_run| engine_run.asset_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    case.scan_runs[0].report_asset_snapshots = case
        .assets
        .iter()
        .filter(|asset| requested_asset_ids.contains(&asset.id))
        .map(|asset| ReportAssetSnapshot {
            asset: asset.clone(),
            disposition: ReportAssetDisposition::RequestedForScan,
        })
        .collect();

    case.coverage = vec![
        CoverageEntry {
            id: new_id(),
            scope_key: "aws:111122223333".into(),
            label: "AWS production account".into(),
            source_kind: SourceKind::AwsOrganization,
            asset_id: Some(account_id.clone()),
            status: CoverageStatus::DiscoveredAuthorizedScanned,
            explanation: "All 1 compatible engine run(s) planned for this asset completed. This state is independent of how many findings were reported.".into(),
            last_run_id: Some(run_id.clone()),
            observed_at: Some(now - Duration::days(2)),
        },
        CoverageEntry {
            id: new_id(),
            scope_key: "ip:198.51.100.24".into(),
            label: "Synthetic candidate external IP".into(),
            source_kind: SourceKind::AwsOrganization,
            asset_id: Some(unknown_host_id),
            status: CoverageStatus::DiscoveredNotAuthorized,
            explanation: "The discovered candidate has not had ownership and scope explicitly confirmed. Discovery never authorizes a target automatically.".into(),
            last_run_id: None,
            observed_at: Some(now - Duration::days(2)),
        },
        CoverageEntry {
            id: new_id(),
            scope_key: "dns:portal.northstar.example".into(),
            label: "Public demo portal".into(),
            source_kind: SourceKind::Dns,
            asset_id: Some(domain_id.clone()),
            status: CoverageStatus::AuthorizedScanIncomplete,
            explanation: "The authorized scan is incomplete: httpx=partially_completed. Only completed compatible catalog-engine runs or exact completed built-in tasks can produce scanned coverage.".into(),
            last_run_id: Some(run_id.clone()),
            observed_at: Some(now - Duration::days(2)),
        },
        CoverageEntry {
            id: new_id(),
            scope_key: "azure:tenant".into(),
            label: "Azure Tenant".into(),
            source_kind: SourceKind::AzureTenant,
            asset_id: None,
            status: CoverageStatus::NotApplicable,
            explanation: "The source area is explicitly outside this case: The synthetic questionnaire states that Azure is not used in this case. This is a scoped applicability statement, not a successful scan result.".into(),
            last_run_id: None,
            observed_at: None,
        },
        CoverageEntry {
            id: new_id(),
            scope_key: "gcp:organization".into(),
            label: "Google Cloud Organization".into(),
            source_kind: SourceKind::GcpOrganization,
            asset_id: None,
            status: CoverageStatus::SourceNotConnectedUnknown,
            explanation: "The source is not currently connected (status: not_connected). Its present coverage is unknown; 0 previously attributed asset(s) are retained but do not make the source green.".into(),
            last_run_id: None,
            observed_at: None,
        },
    ];

    let raw_content = r#"{"demo":true,"check":"s3_public_access","status":"FAIL"}"#;
    let artifact_id = new_id();
    let finding_id = new_id();
    case.raw_artifacts.push(RawArtifact {
        id: artifact_id.clone(),
        case_id: case.id.clone(),
        run_id: run_id.clone(),
        engine_run_id: prowler_run_id.clone(),
        relative_path: "raw/prowler/synthetic-demo.json".into(),
        media_type: "application/json".into(),
        sha256: artifact_hash(raw_content),
        byte_length: raw_content.len() as u64,
        created_at: now - Duration::days(2),
        contains_sensitive_data: true,
    });
    case.findings.push(Finding {
        id: finding_id.clone(),
        case_id: case.id.clone(),
        first_seen_run_id: run_id.clone(),
        last_seen_run_id: run_id.clone(),
        family: Some(FindingFamily::CloudPosture),
        severity_basis_code: None,
        confidence_basis_code: None,
        context_factors: Vec::new(),
        fingerprint: "demo:aws:s3:public-customer-export".into(),
        title: "Synthetic customer-export storage may allow public access".into(),
        plain_language_summary:
            "Prowler reported a critical-severity condition on the assessed asset.".into(),
        possible_impact:
            "Cloud resources or data may be accessed, changed, or used unexpectedly.".into(),
        severity: Severity::Critical,
        confidence: Confidence::High,
        priority: 96,
        priority_reasons: vec![
            "An affected asset is marked internet-exposed, and all retained source attribution for that asset is non-questionnaire.".into(),
            "An affected asset is marked sensitive, all retained source attribution for that asset is non-questionnaire, and the case questionnaire separately records sensitive-data context.".into(),
        ],
        asset_ids: vec![bucket_id.clone()],
        evidence: vec![Evidence {
            id: new_id(),
            finding_id: finding_id.clone(),
            run_id: run_id.clone(),
            engine_run_id: Some(prowler_run_id.clone()),
            kind: EvidenceKind::Configuration,
            engine_id: "prowler".into(),
            scanner_details: None,
            source_rule: None,
            result_pointer_sha256: None,
            observed_at: now - Duration::days(2),
            summary: "Synthetic policy observation for interface demonstration.".into(),
            location: Some("s3://customer-export".into()),
            artifact_id: artifact_id.clone(),
            artifact_sha256: artifact_hash(raw_content),
            pointer: Some("/check".into()),
            redacted: true,
        }],
        control_references: vec![
            ControlReference {
                framework: "NIST CSF".into(),
                framework_version: "2.0".into(),
                control_id: "PR.DS-01".into(),
                title: "Data-at-rest protection".into(),
                relationship: "related".into(),
                rationale: "Evidence that an object-storage resource permits public access is related to access policy, authorization review, and cloud service protection.".into(),
                mapping_version: "demo-0.1".into(),
                mapping_provenance: None,
            },
            ControlReference {
                framework: "ISO/IEC 27001".into(),
                framework_version: "2022".into(),
                control_id: "A.8.3".into(),
                title: "Information access restriction".into(),
                relationship: "related".into(),
                rationale: "Evidence that an object-storage resource permits public access is related to access policy, authorization review, and cloud service protection.".into(),
                mapping_version: "demo-0.1".into(),
                mapping_provenance: None,
            },
        ],
        recommendation: "Have a cloud security engineer review the synthetic bucket policy, Block Public Access settings, and demo dependencies. Do not apply an automatic fix.".into(),
        verification_guidance: "Rerun Prowler with the same scope after the change and confirm that source rule s3_public_access is no longer reported.".into(),
        rollback_considerations: Some("Capture the current configuration and test its restoration path before making the change.".into()),
        official_references: vec!["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html".into()],
        recommended_expert_type: "Cloud security engineer".into(),
        status: FindingStatus::ExpertReviewRequested,
        tags: vec!["synthetic-demo".into(), "data-exposure".into()],
    });

    let timeout_content =
        r#"{"demo":true,"check":"hsts","status":"INCOMPLETE","reason":"TARGET_TIMEOUT"}"#;
    let timeout_artifact_id = new_id();
    case.raw_artifacts.push(RawArtifact {
        id: timeout_artifact_id.clone(),
        case_id: case.id.clone(),
        run_id: run_id.clone(),
        engine_run_id: httpx_run_id.clone(),
        relative_path: "raw/httpx/synthetic-timeout.json".into(),
        media_type: "application/json".into(),
        sha256: artifact_hash(timeout_content),
        byte_length: timeout_content.len() as u64,
        created_at: now - Duration::days(2),
        contains_sensitive_data: false,
    });
    case.scan_runs[0].engine_runs[0]
        .raw_artifact_ids
        .push(artifact_id);
    case.scan_runs[0].engine_runs[1]
        .raw_artifact_ids
        .push(timeout_artifact_id.clone());

    let second_finding_id = new_id();
    case.findings.push(Finding {
        id: second_finding_id.clone(),
        case_id: case.id.clone(),
        first_seen_run_id: run_id.clone(),
        last_seen_run_id: run_id.clone(),
        family: Some(FindingFamily::NetworkExposure),
        severity_basis_code: None,
        confidence_basis_code: None,
        context_factors: Vec::new(),
        fingerprint: "demo:web:missing-hsts".into(),
        title: "The synthetic public site's HSTS status remains unconfirmed".into(),
        plain_language_summary:
            "httpx reported an informational-severity condition on the assessed asset.".into(),
        possible_impact: "An internet-reachable service may expose unexpected functionality or a known weakness.".into(),
        severity: Severity::Informational,
        confidence: Confidence::Medium,
        priority: 58,
        priority_reasons: vec![
            "An affected asset is marked internet-exposed, and all retained source attribution for that asset is non-questionnaire.".into(),
            "Direct scanner evidence is attached.".into(),
        ],
        asset_ids: vec![domain_id],
        evidence: vec![Evidence {
            id: new_id(),
            finding_id: second_finding_id.clone(),
            run_id: run_id.clone(),
            engine_run_id: Some(httpx_run_id),
            kind: EvidenceKind::Observation,
            engine_id: "httpx".into(),
            scanner_details: None,
            source_rule: None,
            result_pointer_sha256: None,
            observed_at: now - Duration::days(2),
            summary: "Synthetic timeout record proving the check was incomplete, not that HSTS was absent.".into(),
            location: Some("https://shop.example.test".into()),
            artifact_id: timeout_artifact_id,
            artifact_sha256: artifact_hash(timeout_content),
            pointer: Some("/status".into()),
            redacted: false,
        }],
        // No framework reference, and that is the faithful demonstration: the
        // pinned mapping catalog has no httpx entry, so a real HSTS observation
        // carries no control relationship either.
        control_references: Vec::new(),
        recommendation: "Have a network or system administrator review the synthetic reverse-proxy and CDN TLS/HSTS settings.".into(),
        verification_guidance: "Rerun httpx with the same scope after the change and confirm that source rule hsts is no longer reported.".into(),
        rollback_considerations: None,
        official_references: vec![
            "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security".into(),
        ],
        recommended_expert_type: "Network or system administrator".into(),
        status: FindingStatus::Unreviewed,
        tags: vec!["synthetic-demo".into(), "tls".into()],
    });

    let group_id = new_id();
    let group_title = "Synthetic external data-transfer observations for joint review".to_owned();
    let group_rationale = "Both synthetic observations concern public services and data protection. This demo-only group supports human handoff and does not merge findings, fingerprints, or evidence.".to_owned();
    let group_actor = "Synthetic demo builder".to_owned();
    let group_created_at = now - Duration::days(1);
    let grouped_finding_ids = vec![finding_id.clone(), second_finding_id.clone()];
    case.finding_groups.push(FindingGroup {
        id: group_id.clone(),
        case_id: case.id.clone(),
        title: group_title.clone(),
        finding_ids: grouped_finding_ids.clone(),
        rationale: group_rationale.clone(),
        grouped_by: group_actor.clone(),
        created_at: group_created_at,
    });
    case.finding_group_events.push(FindingGroupEvent {
        id: new_id(),
        case_id: case.id.clone(),
        group_id,
        action: FindingGroupAction::Created,
        title: group_title,
        finding_ids: grouped_finding_ids,
        rationale: group_rationale,
        actor: group_actor,
        occurred_at: group_created_at,
    });

    case.finding_observations = case
        .findings
        .iter()
        .map(|finding| FindingObservation {
            id: new_id(),
            run_id: run_id.clone(),
            finding_id: finding.id.clone(),
            fingerprint: finding.fingerprint.clone(),
            asset_ids: finding.asset_ids.clone(),
            engine_ids: finding
                .evidence
                .iter()
                .map(|evidence| evidence.engine_id.clone())
                .collect(),
            severity: finding.severity.clone(),
            confidence: finding.confidence.clone(),
            evidence_hashes: finding
                .evidence
                .iter()
                .map(|evidence| evidence.artifact_sha256.clone())
                .collect(),
            observed_at: now - Duration::days(2),
            finding_snapshot: Some(finding.clone()),
        })
        .collect();

    case.touch();
    case
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_han(character: char) -> bool {
        matches!(
            character,
            '\u{3400}'..='\u{4dbf}'
                | '\u{4e00}'..='\u{9fff}'
                | '\u{f900}'..='\u{faff}'
                | '\u{20000}'..='\u{2ffff}'
                | '\u{30000}'..='\u{323af}'
        )
    }

    fn string_values_with_han(value: &serde_json::Value) -> Vec<&str> {
        match value {
            serde_json::Value::String(value) if value.chars().any(is_han) => vec![value],
            serde_json::Value::Array(values) => {
                values.iter().flat_map(string_values_with_han).collect()
            }
            serde_json::Value::Object(values) => {
                values.values().flat_map(string_values_with_han).collect()
            }
            _ => Vec::new(),
        }
    }

    #[test]
    fn demo_case_stores_no_han_characters() {
        let demo = serde_json::to_value(build_demo_case()).expect("demo case should serialize");
        let offenders = string_values_with_han(&demo);

        assert!(
            offenders.is_empty(),
            "demo case contains Han characters in stored strings: {offenders:#?}"
        );
    }

    #[test]
    fn seeded_demo_case_stores_only_valid_resume_tokens() {
        let demo = build_demo_case();
        let httpx_run = demo
            .scan_runs
            .iter()
            .flat_map(|run| &run.engine_runs)
            .find(|engine_run| engine_run.engine_id == "httpx")
            .expect("demo case should contain an httpx run");

        assert_eq!(httpx_run.status, EngineRunStatus::PartiallyCompleted);
        assert_eq!(httpx_run.progress_percent, 72);
        assert_eq!(httpx_run.phase, "failed");
        assert!(httpx_run.resume_token.is_none());

        for engine_run in demo
            .scan_runs
            .iter()
            .flat_map(|run| &run.engine_runs)
            .filter(|engine_run| engine_run.resume_token.is_some())
        {
            crate::orchestrator::ExecutionCheckpoint::from_resume_token(
                engine_run.resume_token.as_deref().unwrap(),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "demo engine run {} stores an invalid resume token: {error}",
                    engine_run.id
                )
            });
        }
    }

    #[test]
    fn demo_report_labels_its_targets_from_the_run() {
        let demo = build_demo_case();
        let report =
            crate::beginner_report::build_beginner_master_report(&demo, &demo.scan_runs[0].id)
                .unwrap();

        assert_eq!(report.requested.targets.len(), 3);
        for target in &report.requested.targets {
            assert_eq!(
                target.label_availability,
                crate::beginner_report::DataAvailability::Recorded,
                "{target:?}"
            );
            assert_eq!(
                target.asset_kind_availability,
                crate::beginner_report::DataAvailability::Recorded,
                "{target:?}"
            );
        }
        assert!(
            !report
                .requested
                .unavailable_dimensions
                .iter()
                .any(|dimension| dimension.dimension == "run-frozen target label or type"),
            "the example report asked a reader to rerun a scan it cannot rerun"
        );
    }

    #[test]
    fn demo_coverage_explanations_use_the_shared_translation_path() {
        let demo = build_demo_case();
        let translations = demo
            .coverage
            .iter()
            .map(|entry| {
                crate::finding_narrative::coverage_record_detail_zh_hant(&entry.explanation)
                    .unwrap_or_else(|| {
                        panic!(
                            "demo coverage explanation is not recognized: {}",
                            entry.explanation
                        )
                    })
            })
            .collect::<Vec<_>>();

        assert_eq!(translations.len(), demo.coverage.len());
        assert!(
            translations
                .iter()
                .all(|translation| translation.chars().any(is_han)),
            "Traditional Chinese coverage translations were not rendered: {translations:#?}"
        );
    }

    #[test]
    fn demo_control_rationales_use_the_shared_translation_path() {
        let demo = build_demo_case();
        // Without this the loop below passes on a demo that stopped carrying
        // any control reference at all.
        assert!(
            demo.findings
                .iter()
                .flat_map(|finding| &finding.control_references)
                .count()
                >= 2
        );
        for rationale in demo
            .findings
            .iter()
            .flat_map(|finding| &finding.control_references)
            .map(|reference| &reference.rationale)
        {
            let translation =
                crate::finding_narrative::control_mapping_rationale_zh_hant(rationale)
                    .unwrap_or_else(|| {
                        panic!("demo control rationale is not recognized: {rationale}")
                    });
            assert!(translation.chars().any(is_han));
        }
    }
}
