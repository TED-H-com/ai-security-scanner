use ai_security_scanner_lib::coverage::{
    NOT_APPLICABLE_REASON_METADATA, assess_asset_coverage, compute_coverage_ledger,
};
use ai_security_scanner_lib::discovery::{
    ConnectorDiscovery, DiscoveredAsset, DiscoveredRelation, DiscoveryAssetRef, DiscoveryBatch,
    DiscoveryConnector, DiscoveryError, reconcile_discovery, run_connector,
};
use ai_security_scanner_lib::domain::*;
use ai_security_scanner_lib::external_scope::{
    CanonicalTarget, DirectNetworkTargetKind, ExternalActivity, ExternalScopeGrant, RatePolicy,
    TemplatePolicy, TransportProtocol,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

fn timestamp(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("valid test timestamp")
        .with_timezone(&Utc)
}

fn empty_case() -> AssessmentCase {
    AssessmentCase::new(
        "Discovery and coverage".into(),
        OrganizationProfile {
            organization_name: "Example".into(),
            employee_range: "1-10".into(),
            data_classes: vec![DataClass::General],
            notes: None,
        },
    )
}

fn source(id: &str, kind: SourceKind, status: SourceConnectionStatus) -> DataSource {
    DataSource {
        id: id.into(),
        kind,
        label: id.into(),
        status,
        connected_at: Some(timestamp("2026-01-01T00:00:00Z")),
        last_discovered_at: None,
        read_only: true,
        metadata: BTreeMap::new(),
    }
}

fn observation(key: &str, native_id: &str, name: &str) -> DiscoveredAsset {
    DiscoveredAsset {
        observation_key: key.into(),
        kind: AssetKind::CloudAccount,
        name: name.into(),
        provider: Some("aws".into()),
        region: Some("us-east-1".into()),
        stable_identifier: AssetIdentifier {
            namespace: "aws_account_id".into(),
            value: native_id.into(),
        },
        additional_identifiers: Vec::new(),
        internet_exposed: None,
        contains_sensitive_data: None,
        metadata: BTreeMap::new(),
    }
}

fn batch(source_id: &str, assets: Vec<DiscoveredAsset>) -> DiscoveryBatch {
    DiscoveryBatch {
        source_id: source_id.into(),
        source_kind: SourceKind::AwsOrganization,
        connector_id: "test.aws.inventory".into(),
        connector_version: "1.0.0".into(),
        observed_at: timestamp("2026-01-02T00:00:00Z"),
        assets,
        relations: Vec::new(),
        notices: Vec::new(),
    }
}

#[test]
fn discovery_creates_attributable_candidates_and_evidenced_relations() {
    let mut case = empty_case();
    case.data_sources.push(source(
        "aws-source",
        SourceKind::AwsOrganization,
        SourceConnectionStatus::Connected,
    ));
    let mut discovery = batch(
        "aws-source",
        vec![
            observation("organization", "111111111111", "Organization"),
            observation("workload", "222222222222", "Workload"),
        ],
    );
    discovery.relations.push(DiscoveredRelation {
        from: DiscoveryAssetRef::Observation("organization".into()),
        to: DiscoveryAssetRef::Observation("workload".into()),
        kind: RelationKind::Contains,
        evidence_ids: vec!["inventory-artifact-sha256".into()],
    });

    let report = reconcile_discovery(&mut case, &discovery).expect("batch reconciles");

    assert_eq!(report.created_asset_ids.len(), 2);
    assert_eq!(case.assets.len(), 2);
    assert!(case.assets.iter().all(|asset| asset.candidate));
    assert!(case.assets.iter().all(|asset| !asset.owner_confirmed));
    assert!(
        case.assets
            .iter()
            .all(|asset| asset.discovered_from == ["aws-source"])
    );
    assert!(
        case.scope_grants.is_empty(),
        "discovery must not grant scope"
    );
    assert_eq!(case.asset_relations.len(), 1);
    assert_eq!(
        case.asset_relations[0].evidence_ids,
        ["inventory-artifact-sha256"]
    );
    assert_eq!(
        case.data_sources[0].last_discovered_at,
        Some(timestamp("2026-01-02T00:00:00Z"))
    );

    let asset_ids = case
        .assets
        .iter()
        .map(|asset| asset.id.clone())
        .collect::<Vec<_>>();
    let relation_id = case.asset_relations[0].id.clone();
    reconcile_discovery(&mut case, &discovery).expect("same batch is idempotent");
    assert_eq!(case.assets.len(), 2);
    assert_eq!(
        case.assets
            .iter()
            .map(|asset| asset.id.clone())
            .collect::<Vec<_>>(),
        asset_ids
    );
    assert_eq!(case.asset_relations.len(), 1);
    assert_eq!(case.asset_relations[0].id, relation_id);
    assert_eq!(case.asset_relations[0].evidence_ids.len(), 1);

    case.data_sources.push(source(
        "aws-source-2",
        SourceKind::AwsOrganization,
        SourceConnectionStatus::Connected,
    ));
    let mut corroborating = discovery.clone();
    corroborating.source_id = "aws-source-2".into();
    corroborating.observed_at = timestamp("2026-01-03T00:00:00Z");
    reconcile_discovery(&mut case, &corroborating).expect("second source corroborates assets");
    assert_eq!(
        case.assets.len(),
        2,
        "stable identities merge across sources"
    );
    assert!(case.assets.iter().all(|asset| {
        asset
            .discovered_from
            .iter()
            .any(|source_id| source_id == "aws-source")
            && asset
                .discovered_from
                .iter()
                .any(|source_id| source_id == "aws-source-2")
    }));
}

#[test]
fn rediscovery_preserves_stable_identity_approval_history_and_unseen_assets() {
    let mut case = empty_case();
    case.data_sources.push(source(
        "aws-source",
        SourceKind::AwsOrganization,
        SourceConnectionStatus::Connected,
    ));
    let mut first_asset = observation("one", "111111111111", "Original name");
    first_asset
        .metadata
        .insert("environment".into(), json!("prod"));
    let first = batch(
        "aws-source",
        vec![first_asset, observation("two", "222222222222", "Retained")],
    );
    reconcile_discovery(&mut case, &first).expect("first discovery");
    let stable_id = case.assets[0].id.clone();
    let retained_id = case.assets[1].id.clone();
    case.assets[0].candidate = false;
    case.assets[0].owner_confirmed = true;

    let mut changed = observation("renamed", "111111111111", "Changed display name");
    changed
        .metadata
        .insert("environment".into(), json!("production"));
    changed.additional_identifiers.push(AssetIdentifier {
        namespace: "billing_account".into(),
        value: "payer-1".into(),
    });
    let mut second = batch("aws-source", vec![changed]);
    second.observed_at = timestamp("2026-01-03T00:00:00Z");

    let report = reconcile_discovery(&mut case, &second).expect("repeat discovery");
    let updated = case
        .assets
        .iter()
        .find(|asset| asset.id == stable_id)
        .expect("stable asset retained");

    assert_eq!(
        case.assets.len(),
        2,
        "absence is never destructive deletion"
    );
    assert_eq!(
        updated.name, "Original name",
        "old value remains reconstructable"
    );
    assert!(!updated.candidate, "discovery does not revoke approval");
    assert!(updated.owner_confirmed);
    assert!(
        updated
            .identifiers
            .iter()
            .any(|identifier| identifier.namespace == "billing_account")
    );
    let observations = updated.metadata["ai_security_scanner.observed_values"]
        .as_object()
        .expect("conflicts retained");
    assert!(observations.contains_key("display_name"));
    assert!(observations.contains_key("environment"));
    assert_eq!(report.retained_unseen_asset_ids, [retained_id]);

    let before_stale = serde_json::to_value(&case).expect("serialize current case");
    let stale = batch(
        "aws-source",
        vec![observation("stale", "333333333333", "Stale")],
    );
    assert!(matches!(
        reconcile_discovery(&mut case, &stale),
        Err(DiscoveryError::StaleBatch { .. })
    ));
    assert_eq!(serde_json::to_value(&case).unwrap(), before_stale);

    let mut empty_latest = batch("aws-source", Vec::new());
    empty_latest.observed_at = timestamp("2026-01-04T00:00:00Z");
    let empty_report =
        reconcile_discovery(&mut case, &empty_latest).expect("empty discovery reconciles");
    assert_eq!(empty_report.retained_unseen_asset_ids.len(), 2);
    assert_eq!(case.assets.len(), 2, "prior evidence remains retained");
    let ledger = compute_coverage_ledger(&case, &[manifest()], timestamp("2026-02-01T00:00:00Z"));
    assert!(ledger.iter().any(|entry| {
        entry.scope_key == "source:aws-source"
            && entry.status == CoverageStatus::SourceConnectedNothingDiscovered
    }));
}

#[test]
fn invalid_relation_is_atomic_and_does_not_mutate_case() {
    let mut case = empty_case();
    case.data_sources.push(source(
        "aws-source",
        SourceKind::AwsOrganization,
        SourceConnectionStatus::Connected,
    ));
    let before = serde_json::to_value(&case).expect("serialize before");
    let mut discovery = batch(
        "aws-source",
        vec![observation("known", "111111111111", "Known")],
    );
    discovery.relations.push(DiscoveredRelation {
        from: DiscoveryAssetRef::Observation("known".into()),
        to: DiscoveryAssetRef::Observation("missing".into()),
        kind: RelationKind::Related,
        evidence_ids: vec!["evidence-1".into()],
    });

    let error = reconcile_discovery(&mut case, &discovery).expect_err("invalid endpoint rejected");
    assert!(matches!(error, DiscoveryError::UnknownRelationEndpoint(_)));
    assert_eq!(serde_json::to_value(&case).unwrap(), before);
}

struct FixedConnector;

impl DiscoveryConnector for FixedConnector {
    fn connector_id(&self) -> &str {
        "fixed"
    }

    fn connector_version(&self) -> &str {
        "1"
    }

    fn source_kind(&self) -> SourceKind {
        SourceKind::AwsOrganization
    }

    fn discover(&self, _source: &DataSource) -> Result<ConnectorDiscovery, DiscoveryError> {
        Ok(ConnectorDiscovery {
            observed_at: timestamp("2026-01-02T00:00:00Z"),
            assets: vec![observation("one", "111111111111", "One")],
            relations: Vec::new(),
            notices: Vec::new(),
        })
    }
}

#[test]
fn connector_contract_enforces_connected_read_only_matching_source() {
    let connector = FixedConnector;
    let disconnected = source(
        "source",
        SourceKind::AwsOrganization,
        SourceConnectionStatus::NotConnected,
    );
    assert!(matches!(
        run_connector(&connector, &disconnected),
        Err(DiscoveryError::SourceNotConnected { .. })
    ));

    let mut writable = source(
        "source",
        SourceKind::AwsOrganization,
        SourceConnectionStatus::Connected,
    );
    writable.read_only = false;
    assert!(matches!(
        run_connector(&connector, &writable),
        Err(DiscoveryError::SourceNotReadOnly(_))
    ));

    let wrong_kind = source(
        "source",
        SourceKind::AzureTenant,
        SourceConnectionStatus::Connected,
    );
    assert!(matches!(
        run_connector(&connector, &wrong_kind),
        Err(DiscoveryError::SourceKindMismatch { .. })
    ));
}

fn asset(id: &str, source_id: &str, approved: bool) -> Asset {
    Asset {
        id: id.into(),
        kind: AssetKind::CloudAccount,
        name: id.into(),
        provider: Some("aws".into()),
        region: None,
        identifiers: vec![AssetIdentifier {
            namespace: "aws_account_id".into(),
            value: id.into(),
        }],
        discovered_from: vec![source_id.into()],
        candidate: !approved,
        owner_confirmed: approved,
        internet_exposed: None,
        contains_sensitive_data: None,
        metadata: BTreeMap::new(),
    }
}

fn grant(id: &str, asset_id: &str) -> ScopeGrant {
    ScopeGrant {
        id: id.into(),
        asset_id: asset_id.into(),
        permission: ScanPermission::InventoryRead,
        confirmed_by: "owner@example.test".into(),
        confirmed_at: timestamp("2026-01-01T00:00:00Z"),
        expires_at: Some(timestamp("2026-12-31T00:00:00Z")),
        authorization_reference: None,
        notes: None,
        external_scope: None,
    }
}

fn manifest() -> EngineManifest {
    EngineManifest {
        schema_version: "1".into(),
        id: "inventory".into(),
        display_name: "Inventory".into(),
        category: EngineCategory::CloudInventory,
        description: "test".into(),
        repository_url: "https://example.test/inventory".into(),
        homepage_url: None,
        license_spdx: "Apache-2.0".into(),
        distribution_mode: DistributionMode::ExternalExecutable,
        image: None,
        source_revision: Some("test".into()),
        engine_version: Some("1".into()),
        reported_version: None,
        rule_version: None,
        adapter_version: "1".into(),
        supported_providers: vec![],
        supported_asset_kinds: vec![AssetKind::CloudAccount],
        input_contracts: vec![],
        provider_execution_contracts: vec![],
        direct_network_contract: None,
        required_permissions: vec![ScanPermission::InventoryRead],
        active_external: false,
        default_enabled: true,
        estimated_memory_mb: 1,
        estimated_disk_mb: 1,
        network_destinations: Vec::new(),
        output_formats: vec!["json".into()],
        command: vec!["inventory".into()],
        status: ManifestStatus::Integrated,
        notices: Vec::new(),
        compatibility: EngineCompatibility {
            runnable: true,
            blocked_by: vec![],
            ..EngineCompatibility::default()
        },
        execution: None,
    }
}

fn engine_run(run_id: &str, asset_id: &str, status: EngineRunStatus) -> EngineRun {
    EngineRun {
        unattributed: Vec::new(),
        unevaluated_targets: Vec::new(),
        security_template_executions: Vec::new(),
        manual_review_controls: Vec::new(),
        id: format!("engine-{asset_id}"),
        scan_run_id: run_id.into(),
        engine_id: "inventory".into(),
        task_kind: Default::default(),
        localhost_tcp_observation: None,
        asset_ids: vec![asset_id.into()],
        status,
        progress_percent: 100,
        phase: "terminal".into(),
        started_at: Some(timestamp("2026-01-04T00:00:00Z")),
        finished_at: Some(timestamp("2026-01-04T00:01:00Z")),
        resume_token: None,
        last_execution_report_sha256: None,
        engine_version: Some("1".into()),
        reported_version: None,
        image_digest: None,
        rule_version: None,
        adapter_version: "1".into(),
        manifest_schema_version: None,
        source_revision: None,
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
        exit_code: None,
        cleanup_removed: None,
        cleanup_detail: None,
        gateway_refusals: None,
        warnings: vec![],
        raw_artifact_ids: Vec::new(),
        error_code: None,
        error_message: None,
    }
}

#[test]
fn ledger_represents_all_six_states_without_using_findings() {
    let as_of = timestamp("2026-02-01T00:00:00Z");
    let mut case = empty_case();
    let mut connected = source(
        "connected",
        SourceKind::AwsOrganization,
        SourceConnectionStatus::Connected,
    );
    connected.last_discovered_at = Some(timestamp("2026-01-02T00:00:00Z"));
    let mut not_applicable = source(
        "not-applicable",
        SourceKind::GcpOrganization,
        SourceConnectionStatus::NotApplicable,
    );
    not_applicable.metadata.insert(
        NOT_APPLICABLE_REASON_METADATA.into(),
        json!("The organization confirmed that it does not use Google Cloud."),
    );
    case.data_sources = vec![
        connected,
        source("empty", SourceKind::Dns, SourceConnectionStatus::Connected),
        source(
            "unknown",
            SourceKind::AzureTenant,
            SourceConnectionStatus::NotConnected,
        ),
        not_applicable,
    ];
    case.assets = vec![
        asset("candidate", "connected", false),
        asset("incomplete", "connected", true),
        asset("scanned", "connected", true),
    ];
    case.scope_grants = vec![
        grant("grant-candidate", "candidate"),
        grant("grant-incomplete", "incomplete"),
        grant("grant-scanned", "scanned"),
    ];
    let run_scope_snapshots = case.scope_grants[1..].to_vec();
    case.scan_runs.push(ScanRun {
        campaign_id: None,
        id: "run-1".into(),
        case_id: case.id.clone(),
        sequence: 1,
        created_at: timestamp("2026-01-04T00:00:00Z"),
        completed_at: Some(timestamp("2026-01-04T00:01:00Z")),
        request_outcome: None,
        report_asset_snapshots: Vec::new(),
        knowledge_cutoff: timestamp("2026-01-04T00:00:00Z"),
        ai_system_applicable: false,
        ai_system_applicability: Default::default(),
        ai_generated_artifact: Default::default(),
        verification_baseline_run_id: None,
        scope_grant_ids: vec!["grant-incomplete".into(), "grant-scanned".into()],
        scope_grant_snapshots: run_scope_snapshots,
        engine_admission_issues: Vec::new(),
        engine_runs: vec![engine_run("run-1", "scanned", EngineRunStatus::Completed)],
    });
    assert!(
        case.findings.is_empty(),
        "fixture has zero findings by design"
    );

    let ledger = compute_coverage_ledger(&case, &[manifest()], as_of);
    let statuses = ledger
        .iter()
        .map(|entry| (entry.scope_key.as_str(), entry.status.clone()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        statuses["asset:candidate"],
        CoverageStatus::DiscoveredNotAuthorized
    );
    assert_eq!(
        statuses["asset:incomplete"],
        CoverageStatus::AuthorizedScanIncomplete
    );
    assert_eq!(
        statuses["asset:scanned"],
        CoverageStatus::DiscoveredAuthorizedScanned,
        "a completed plan may be green even with zero findings"
    );
    assert_eq!(
        statuses["source:empty"],
        CoverageStatus::SourceConnectedNothingDiscovered
    );
    assert_eq!(
        statuses["source:unknown"],
        CoverageStatus::SourceNotConnectedUnknown
    );
    assert_eq!(
        statuses["source:not-applicable"],
        CoverageStatus::NotApplicable
    );
    assert_ne!(statuses["source:empty"], statuses["asset:scanned"]);
    assert_ne!(statuses["source:unknown"], statuses["asset:scanned"]);
    assert_ne!(
        statuses["source:not-applicable"], statuses["asset:scanned"],
        "an applicability declaration is never successful scan evidence"
    );

    let missing_manifest = assess_asset_coverage(&case, &case.assets[2], &[], as_of);
    assert_eq!(
        missing_manifest.status,
        CoverageStatus::AuthorizedScanIncomplete,
        "a completed process without its compatible manifest cannot establish coverage"
    );

    let second = compute_coverage_ledger(&case, &[manifest()], as_of);
    assert_eq!(
        ledger.iter().map(|entry| &entry.id).collect::<Vec<_>>(),
        second.iter().map(|entry| &entry.id).collect::<Vec<_>>(),
        "ledger identities and order are deterministic"
    );
}

#[test]
fn failed_partial_cancelled_and_not_executed_never_become_green() {
    let as_of = timestamp("2026-02-01T00:00:00Z");
    for status in [
        EngineRunStatus::NotExecuted,
        EngineRunStatus::Queued,
        EngineRunStatus::Preparing,
        EngineRunStatus::Running,
        EngineRunStatus::Paused,
        EngineRunStatus::PartiallyCompleted,
        EngineRunStatus::Failed,
        EngineRunStatus::Cancelled,
    ] {
        let mut case = empty_case();
        case.assets.push(asset("target", "source", true));
        case.scope_grants.push(grant("grant-target", "target"));
        let run_scope_snapshot = case.scope_grants[0].clone();
        case.scan_runs.push(ScanRun {
            campaign_id: None,
            id: "run".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: timestamp("2026-01-04T00:00:00Z"),
            completed_at: Some(timestamp("2026-01-04T00:01:00Z")),
            request_outcome: None,
            report_asset_snapshots: Vec::new(),
            knowledge_cutoff: timestamp("2026-01-04T00:00:00Z"),
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec!["grant-target".into()],
            scope_grant_snapshots: vec![run_scope_snapshot],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![engine_run("run", "target", status.clone())],
        });

        let result = assess_asset_coverage(&case, &case.assets[0], &[manifest()], as_of);
        assert_eq!(
            result.status,
            CoverageStatus::AuthorizedScanIncomplete,
            "{status:?} must remain non-green"
        );
    }
}

#[test]
fn built_in_localhost_coverage_uses_typed_outcomes_without_a_manifest() {
    let as_of = timestamp("2026-02-01T00:00:00Z");
    let mut case = empty_case();
    let mut endpoint = asset("localhost", "local-source", true);
    endpoint.kind = AssetKind::WebService;
    endpoint.name = "127.0.0.1:9001".into();
    endpoint.provider = None;
    endpoint.internet_exposed = Some(false);
    endpoint.identifiers = vec![AssetIdentifier {
        namespace: BUILT_IN_LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE.into(),
        value: "127.0.0.1:9001".into(),
    }];
    case.assets.push(endpoint);
    let mut localhost_grant = grant("grant-localhost", "localhost");
    localhost_grant.permission = ScanPermission::LowImpactExternalConnection;
    localhost_grant.authorization_reference =
        Some(BUILT_IN_LOCALHOST_TCP_AUTHORIZATION_REFERENCE.into());
    case.scope_grants.push(localhost_grant);
    let run_scope_snapshot = case.scope_grants[0].clone();
    let observed_at = timestamp("2026-01-04T00:00:03Z");
    let mut completed = engine_run("run", "localhost", EngineRunStatus::Completed);
    completed.engine_id = "built-in-localhost-tcp".into();
    completed.task_kind = EngineTaskKind::built_in_localhost_tcp(9_001);
    completed.localhost_tcp_observation = Some(LocalhostTcpObservation {
        outcome: LocalhostTcpOutcome::Reachable,
        observed_at,
    });
    completed.finished_at = Some(observed_at);
    case.scan_runs.push(ScanRun {
        campaign_id: None,
        id: "run".into(),
        case_id: case.id.clone(),
        sequence: 1,
        created_at: timestamp("2026-01-04T00:00:00Z"),
        completed_at: Some(observed_at),
        request_outcome: None,
        report_asset_snapshots: Vec::new(),
        knowledge_cutoff: timestamp("2026-01-04T00:00:00Z"),
        ai_system_applicable: false,
        ai_system_applicability: Default::default(),
        ai_generated_artifact: Default::default(),
        verification_baseline_run_id: None,
        scope_grant_ids: vec!["grant-localhost".into()],
        scope_grant_snapshots: vec![run_scope_snapshot],
        engine_admission_issues: Vec::new(),
        engine_runs: vec![completed],
    });

    let reachable = assess_asset_coverage(&case, &case.assets[0], &[], as_of);
    assert_eq!(
        reachable.status,
        CoverageStatus::DiscoveredAuthorizedScanned,
        "the product-owned exact task must not depend on a catalog manifest"
    );
    assert!(reachable.explanation.contains("127.0.0.1:9001=reachable"));
    assert!(reachable.explanation.contains("does not establish"));
    assert!(reachable.explanation.contains("secure"));
    assert!(!reachable.explanation.contains("manifest_missing"));

    case.scan_runs[0].engine_runs[0]
        .localhost_tcp_observation
        .as_mut()
        .unwrap()
        .outcome = LocalhostTcpOutcome::Closed;
    let closed = assess_asset_coverage(&case, &case.assets[0], &[], as_of);
    assert_eq!(closed.status, CoverageStatus::DiscoveredAuthorizedScanned);
    assert!(closed.explanation.contains("127.0.0.1:9001=closed"));
    assert!(closed.explanation.contains("does not establish"));

    case.scan_runs[0].engine_runs[0].status = EngineRunStatus::PartiallyCompleted;
    case.scan_runs[0].engine_runs[0]
        .localhost_tcp_observation
        .as_mut()
        .unwrap()
        .outcome = LocalhostTcpOutcome::TimedOut;
    let timed_out = assess_asset_coverage(&case, &case.assets[0], &[], as_of);
    assert_eq!(timed_out.status, CoverageStatus::AuthorizedScanIncomplete);
    assert!(timed_out.explanation.contains("timed_out"));

    case.scan_runs[0].engine_runs[0].status = EngineRunStatus::Failed;
    case.scan_runs[0].engine_runs[0].localhost_tcp_observation = None;
    let failed = assess_asset_coverage(&case, &case.assets[0], &[], as_of);
    assert_eq!(failed.status, CoverageStatus::AuthorizedScanIncomplete);
    assert!(failed.explanation.contains("observation_missing(failed)"));
}

#[test]
fn completed_provider_incompatible_run_never_becomes_green() {
    let as_of = timestamp("2026-02-01T00:00:00Z");
    let mut case = empty_case();
    let mut target = asset("target", "source", true);
    target.provider = Some("azure".into());
    case.assets.push(target);
    case.scope_grants.push(grant("grant-target", "target"));
    let run_scope_snapshot = case.scope_grants[0].clone();
    case.scan_runs.push(ScanRun {
        campaign_id: None,
        id: "run".into(),
        case_id: case.id.clone(),
        sequence: 1,
        created_at: timestamp("2026-01-04T00:00:00Z"),
        completed_at: Some(timestamp("2026-01-04T00:01:00Z")),
        request_outcome: None,
        report_asset_snapshots: Vec::new(),
        knowledge_cutoff: timestamp("2026-01-04T00:00:00Z"),
        ai_system_applicable: false,
        ai_system_applicability: Default::default(),
        ai_generated_artifact: Default::default(),
        verification_baseline_run_id: None,
        scope_grant_ids: vec!["grant-target".into()],
        scope_grant_snapshots: vec![run_scope_snapshot],
        engine_admission_issues: Vec::new(),
        engine_runs: vec![engine_run("run", "target", EngineRunStatus::Completed)],
    });
    let mut aws_manifest = manifest();
    aws_manifest.supported_providers = vec!["aws".into()];

    let incompatible =
        assess_asset_coverage(&case, &case.assets[0], &[aws_manifest.clone()], as_of);
    assert_eq!(
        incompatible.status,
        CoverageStatus::AuthorizedScanIncomplete
    );
    assert!(incompatible.explanation.contains("provider_incompatible"));

    case.assets[0].provider = None;
    let missing = assess_asset_coverage(&case, &case.assets[0], &[aws_manifest.clone()], as_of);
    assert_eq!(missing.status, CoverageStatus::AuthorizedScanIncomplete);
    assert!(missing.explanation.contains("provider_incompatible"));

    case.assets[0].provider = Some("aws".into());
    let compatible = assess_asset_coverage(&case, &case.assets[0], &[aws_manifest], as_of);
    assert_eq!(
        compatible.status,
        CoverageStatus::DiscoveredAuthorizedScanned
    );
}

#[test]
fn active_low_impact_engine_uses_its_declared_permission_for_coverage() {
    let as_of = timestamp("2026-01-10T00:00:00Z");
    let mut case = empty_case();
    let mut endpoint = asset("endpoint", "source", true);
    endpoint.kind = AssetKind::IpAddress;
    endpoint.provider = None;
    endpoint.identifiers = vec![AssetIdentifier {
        namespace: "ip_address".into(),
        value: "127.0.0.1".into(),
    }];
    case.assets.push(endpoint);

    let mut low_impact = grant("grant-endpoint", "endpoint");
    low_impact.permission = ScanPermission::LowImpactExternalConnection;
    low_impact.authorization_reference = Some("owner-confirmed endpoint QC".into());
    low_impact.external_scope = Some(ExternalScopeGrant {
        id: low_impact.id.clone(),
        case_id: case.id.clone(),
        asset_id: low_impact.asset_id.clone(),
        target: CanonicalTarget::parse("127.0.0.1").unwrap(),
        ports: BTreeSet::from([9001]),
        protocol: TransportProtocol::Http,
        activity: ExternalActivity::LowImpactExternal,
        rate_policy: RatePolicy {
            requests_per_second: 1,
            concurrency: 1,
            timeout_seconds: 60,
        },
        template_policy: TemplatePolicy::conservative("not_applicable", vec![]),
        asserted_authority: "owner-confirmed endpoint QC".into(),
        approved_by: "owner@example.test".into(),
        approved_at: timestamp("2026-01-01T00:00:00Z"),
        expires_at: timestamp("2026-01-31T00:00:00Z"),
        allow_sensitive_networks: true,
    });
    low_impact.expires_at = Some(timestamp("2026-01-31T00:00:00Z"));
    case.scope_grants.push(low_impact.clone());

    let mut completed = engine_run("run", "endpoint", EngineRunStatus::Completed);
    completed.engine_id = "httpx".into();
    case.scan_runs.push(ScanRun {
        campaign_id: None,
        id: "run".into(),
        case_id: case.id.clone(),
        sequence: 1,
        created_at: timestamp("2026-01-04T00:00:00Z"),
        completed_at: Some(timestamp("2026-01-04T00:01:00Z")),
        request_outcome: None,
        report_asset_snapshots: Vec::new(),
        knowledge_cutoff: timestamp("2026-01-04T00:00:00Z"),
        ai_system_applicable: false,
        ai_system_applicability: Default::default(),
        ai_generated_artifact: Default::default(),
        verification_baseline_run_id: None,
        scope_grant_ids: vec![low_impact.id.clone()],
        scope_grant_snapshots: vec![low_impact],
        engine_admission_issues: Vec::new(),
        engine_runs: vec![completed],
    });

    let mut httpx = manifest();
    httpx.id = "httpx".into();
    httpx.category = EngineCategory::ExternalAttackSurface;
    httpx.supported_asset_kinds = vec![AssetKind::IpAddress];
    httpx.direct_network_contract = Some(DirectNetworkExecutionContract {
        target_kinds: vec![DirectNetworkTargetKind::Address],
        protocols: vec![TransportProtocol::Http],
    });
    httpx.required_permissions = vec![ScanPermission::LowImpactExternalConnection];
    httpx.active_external = true;

    let compatible = assess_asset_coverage(&case, &case.assets[0], &[httpx.clone()], as_of);
    assert_eq!(
        compatible.status,
        CoverageStatus::DiscoveredAuthorizedScanned,
        "active execution must not invent an ActiveExternalTesting requirement"
    );

    case.scan_runs[0].scope_grant_snapshots[0].permission = ScanPermission::ActiveExternalTesting;
    let wrong_permission = assess_asset_coverage(&case, &case.assets[0], &[httpx], as_of);
    assert_eq!(
        wrong_permission.status,
        CoverageStatus::AuthorizedScanIncomplete
    );
    assert!(wrong_permission.explanation.contains("scope_incompatible"));
}

#[test]
fn coverage_uses_frozen_run_grants_and_never_backfills_legacy_runs() {
    let as_of = timestamp("2026-02-01T00:00:00Z");
    let mut case = empty_case();
    case.assets.push(asset("target", "source", true));
    case.scope_grants.push(grant("grant-target", "target"));
    case.scan_runs.push(ScanRun {
        campaign_id: None,
        id: "run".into(),
        case_id: case.id.clone(),
        sequence: 1,
        created_at: timestamp("2026-01-04T00:00:00Z"),
        completed_at: Some(timestamp("2026-01-04T00:01:00Z")),
        request_outcome: None,
        report_asset_snapshots: Vec::new(),
        knowledge_cutoff: timestamp("2026-01-04T00:00:00Z"),
        ai_system_applicable: false,
        ai_system_applicability: Default::default(),
        ai_generated_artifact: Default::default(),
        verification_baseline_run_id: None,
        scope_grant_ids: vec!["grant-target".into()],
        scope_grant_snapshots: vec![],
        engine_admission_issues: Vec::new(),
        engine_runs: vec![engine_run("run", "target", EngineRunStatus::Completed)],
    });

    let legacy = assess_asset_coverage(&case, &case.assets[0], &[manifest()], as_of);
    assert_eq!(legacy.status, CoverageStatus::AuthorizedScanIncomplete);
    assert!(
        legacy
            .explanation
            .contains("predates frozen scope-grant snapshots")
    );
    assert!(
        legacy
            .explanation
            .contains("Live grants are never substituted")
    );

    case.scan_runs[0].scope_grant_snapshots = vec![case.scope_grants[0].clone()];
    case.scope_grants[0].permission = ScanPermission::ConfigurationRead;
    let historical = assess_asset_coverage(&case, &case.assets[0], &[manifest()], as_of);
    assert_eq!(
        historical.status,
        CoverageStatus::DiscoveredAuthorizedScanned,
        "a later live-grant edit must not rewrite the permission frozen into a completed run"
    );

    case.scope_grants[0].permission = ScanPermission::InventoryRead;
    case.scan_runs[0].scope_grant_snapshots[0].permission = ScanPermission::ConfigurationRead;
    let incompatible = assess_asset_coverage(&case, &case.assets[0], &[manifest()], as_of);
    assert_eq!(
        incompatible.status,
        CoverageStatus::AuthorizedScanIncomplete
    );
    assert!(incompatible.explanation.contains("scope_incompatible"));
}

#[test]
fn expired_or_unsubstantiated_external_grants_do_not_authorize() {
    let as_of = timestamp("2026-02-01T00:00:00Z");
    let mut case = empty_case();
    case.assets.push(asset("target", "source", true));
    let mut external = grant("external", "target");
    external.permission = ScanPermission::ActiveExternalTesting;
    external.authorization_reference = None;
    case.scope_grants.push(external);

    let result = assess_asset_coverage(&case, &case.assets[0], &[], as_of);
    assert_eq!(result.status, CoverageStatus::DiscoveredNotAuthorized);

    case.scope_grants[0].authorization_reference = Some("contract-42".into());
    case.scope_grants[0].expires_at = Some(timestamp("2026-01-31T00:00:00Z"));
    let result = assess_asset_coverage(&case, &case.assets[0], &[], as_of);
    assert_eq!(result.status, CoverageStatus::DiscoveredNotAuthorized);
}
