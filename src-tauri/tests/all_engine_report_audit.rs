use ai_security_scanner_lib::adapter::AdapterRegistry;
use ai_security_scanner_lib::adapters::{BUILTIN_ENGINE_IDS, builtin_adapter_registry};
use ai_security_scanner_lib::artifact_store::ArtifactStore;
use ai_security_scanner_lib::beginner_report::{
    BeginnerInventoryItemKind, BeginnerMasterReport, CLOUD_SCOPE_LIMIT_DIMENSIONS,
    CoverageDimensionStatus, CoverageGapClass, CoverageGapKind, NextActionCode, TechnicalExecution,
    build_beginner_master_report,
};
use ai_security_scanner_lib::case_service::{
    CaseExportFormat, CaseService, DurableExecutionReport, EngineAssetRoute,
    NaabuLauncherV2CoverageApplyOutcome, PlannedEngineExecution, ScanPlanRequest,
    ScopeApprovalRequest, SourceMutation,
};
use ai_security_scanner_lib::connectors::{
    LIVE_PROVIDER_ARTIFACT_SET_SCHEMA, LiveProviderArtifactPage, LiveProviderArtifactSet,
    SnapshotConnectorRegistry,
};
use ai_security_scanner_lib::container_runtime::{
    CONTAINER_EXECUTION_TIMEOUT_ERROR, CancellationToken, FakeContainerRuntime, FakeRunBehavior,
    NetworkPolicy, ResourceLimits, RuntimeCommandProvenance, RuntimeProvider, ScannerCredentialSet,
};
use ai_security_scanner_lib::discovery::run_connector;
use ai_security_scanner_lib::domain::{
    AiGeneratedArtifactAnswer, AssessmentActivity, AssessmentCase, AssessmentIntent, AssetKind,
    CreateCaseRequest, DataClass, DeclaredAssetInput, DeclaredAssetKind, DeclaredHostScanInput,
    DeclaredHostScanProfile, DeclaredNetworkProtocol, DeclaredWebProtocol, DeclaredWebServiceInput,
    EngineRunStatus, NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION, NaabuAttemptRequest, ScanPermission,
    SourceConnectionStatus, SourceKind,
};
use ai_security_scanner_lib::export::{ExportOptions, RedactionProfile, ReportLocale};
use ai_security_scanner_lib::external_scope::{
    CanonicalTarget, ExternalActivity, ExternalScopeRequest, RatePolicy, TemplatePolicy,
    TransportProtocol, freeze_external_plan,
};
use ai_security_scanner_lib::managed_network::GatewayDestination;
use ai_security_scanner_lib::naabu_work_plan::{
    NaabuLauncherPlanDocument, NaabuWorkPlanIdentity, NaabuWorkPlanV1, build_naabu_work_plan,
};
use ai_security_scanner_lib::orchestrator::{
    EngineExecutionRequest, ExecutionCheckpoint, ExecutionReport, ExecutionStage, Orchestrator,
};
use ai_security_scanner_lib::registry::EngineRegistry;
use ai_security_scanner_lib::source_authorization::PROVIDER_RESOURCE_SCOPE_METADATA_KEY;
use ai_security_scanner_lib::storage::Storage;
use ai_security_scanner_lib::workspace_snapshot::{
    WorkspaceInputProfile, WorkspaceSnapshotLimits, WorkspaceSnapshotReference,
    create_workspace_snapshot_with_profile, resolve_workspace_snapshot,
};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

#[path = "support/public_sample_reports.rs"]
mod public_sample_reports;

/// Which shape of finished run the harness produces.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EngineOutcomes {
    /// One check per terminal state -- a failure, a host timeout, a
    /// cancellation, a partial run and an empty completion -- beside the
    /// checks that report. This is the run the coverage and next-step
    /// sections are written for.
    MixedTerminalStates,
    /// Every detector exits successfully and reports. The real kube-bench
    /// fixture still has WARN controls and must retain that coverage gap.
    /// Five packaged catalog entries
    /// belong to checks that only ever carry a terminal state in the mixed
    /// run, so nothing else proves their adapter can carry a finding through
    /// the report and onto its mapped control.
    EveryDetectorReports,
}

fn fixture(engine: &str, outcomes: EngineOutcomes) -> (&'static [u8], &'static str) {
    let reporting = outcomes == EngineOutcomes::EveryDetectorReports;
    match engine {
        "cloudquery" => (
            include_bytes!("fixtures/adapters/cloudquery.json"),
            "aws_iam_users.json",
        ),
        "steampipe" => (
            include_bytes!("fixtures/adapters/steampipe.json"),
            "steampipe.json",
        ),
        "prowler" => (
            include_bytes!("fixtures/adapters/prowler-ocsf.json"),
            "prowler-ocsf.json",
        ),
        "scoutsuite" => (
            include_bytes!("fixtures/adapters/scoutsuite.json"),
            "scoutsuite.json",
        ),
        "cloudsplaining" => (
            include_bytes!("fixtures/adapters/cloudsplaining.json"),
            "cloudsplaining.json",
        ),
        "scubagear" => (
            include_bytes!("fixtures/adapters/scubagear.json"),
            "scubagear.json",
        ),
        "maester" => (
            include_bytes!("fixtures/adapters/maester.json"),
            "maester.json",
        ),
        "naabu" => (
            include_bytes!("fixtures/adapters/naabu.jsonl"),
            "naabu.jsonl",
        ),
        "httpx" => (
            include_bytes!("fixtures/adapters/httpx.jsonl"),
            "httpx.jsonl",
        ),
        "zap" => (include_bytes!("fixtures/adapters/zap.json"), "zap.json"),
        "nuclei" if reporting => (
            include_bytes!("fixtures/adapters/nuclei.jsonl"),
            "nuclei.jsonl",
        ),
        "nuclei" => (
            include_bytes!("fixtures/adapters/malformed-nuclei.jsonl"),
            "nuclei.jsonl",
        ),
        "greenbone" if reporting => (
            include_bytes!("fixtures/adapters/greenbone.xml"),
            "greenbone.xml",
        ),
        "greenbone" => (
            include_bytes!("fixtures/adapters/greenbone-result-types.xml"),
            "greenbone.xml",
        ),
        "semgrep" if reporting => (
            include_bytes!("fixtures/adapters/semgrep.json"),
            "semgrep.json",
        ),
        "semgrep" => (
            include_bytes!("fixtures/adapters/semgrep-empty.json"),
            "semgrep.json",
        ),
        "gitleaks" => (
            include_bytes!("fixtures/adapters/gitleaks.json"),
            "gitleaks.json",
        ),
        "trufflehog" => (
            include_bytes!("fixtures/adapters/trufflehog.jsonl"),
            "trufflehog.jsonl",
        ),
        "checkov" => (
            include_bytes!("fixtures/adapters/checkov.json"),
            "checkov.json",
        ),
        "kics" => (include_bytes!("fixtures/adapters/kics.json"), "kics.json"),
        "trivy" => (include_bytes!("fixtures/adapters/trivy.json"), "trivy.json"),
        "grype" => (include_bytes!("fixtures/adapters/grype.json"), "grype.json"),
        "syft" => (include_bytes!("fixtures/adapters/syft.json"), "syft.json"),
        "kubescape" => (
            include_bytes!("fixtures/adapters/kubescape.json"),
            "kubescape.json",
        ),
        "kube-bench" => (
            include_bytes!("fixtures/adapters/kube-bench.json"),
            "kube-bench.json",
        ),
        "mcp-armor" => (
            include_bytes!("../../docs/research/fixtures/mcp-armor/config-findings.json"),
            "mcp-armor.json",
        ),
        "agentic-radar" => (
            include_bytes!("../../docs/research/fixtures/agentic-radar/n8n.json"),
            "agentic-radar.json",
        ),
        "garak" => (
            include_bytes!("fixtures/adapters/garak-0.17.0-native.jsonl"),
            "report.jsonl",
        ),
        other => panic!("missing fixture for {other}"),
    }
}

fn write_oci_layout(root: &Path) {
    let blobs = root.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    fs::write(
        root.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    let contents = b"all-engine report audit layer";
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(contents.len() as u64);
    header.set_path("app/fixture.txt").unwrap();
    header.set_cksum();
    builder.append(&header, Cursor::new(contents)).unwrap();
    builder.finish().unwrap();
    let layer = builder.into_inner().unwrap();
    let layer_digest = hex::encode(Sha256::digest(&layer));
    let config = serde_json::to_vec(&serde_json::json!({
        "architecture":"amd64", "os":"linux",
        "rootfs":{"type":"layers","diff_ids":[format!("sha256:{layer_digest}")]}, "config":{}
    }))
    .unwrap();
    let config_digest = hex::encode(Sha256::digest(&config));
    fs::write(blobs.join(&config_digest), &config).unwrap();
    fs::write(blobs.join(&layer_digest), &layer).unwrap();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion":2,
        "mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":format!("sha256:{config_digest}"),"size":config.len()},
        "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":format!("sha256:{layer_digest}"),"size":layer.len()}]
    })).unwrap();
    let manifest_digest = hex::encode(Sha256::digest(&manifest));
    fs::write(blobs.join(&manifest_digest), &manifest).unwrap();
    fs::write(root.join("index.json"), serde_json::to_vec(&serde_json::json!({
        "schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
        "manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":format!("sha256:{manifest_digest}"),"size":manifest.len()}]
    })).unwrap()).unwrap();
}

fn write_node_snapshot(root: &Path) {
    let node = root.join("node-snapshot");
    fs::create_dir_all(&node).unwrap();
    let config = b"kind: KubeletConfiguration\n";
    fs::write(node.join("kubelet-config.yaml"), config).unwrap();
    fs::write(node.join("profile.json"), serde_json::to_vec(&serde_json::json!({
        "schema_version":"1.0.0", "profile":"cis-kubernetes-node-config",
        "captured_at":"2026-08-24T12:00:00Z",
        "files":[{"path":"kubelet-config.yaml","sha256":format!("sha256:{}", hex::encode(Sha256::digest(config)))}]
    })).unwrap()).unwrap();
}

fn attach_provider_asset(
    service: &CaseService<'_>,
    registry: &SnapshotConnectorRegistry,
    case_id: &str,
    kind: SourceKind,
    profile: &str,
    raw: &[u8],
    expected_kind: AssetKind,
) -> String {
    let source = service
        .upsert_source(
            case_id,
            SourceMutation {
                id: None,
                kind: kind.clone(),
                label: format!("Fixture {kind:?}"),
                status: SourceConnectionStatus::Connected,
                read_only: true,
                metadata: BTreeMap::from([(
                    PROVIDER_RESOURCE_SCOPE_METADATA_KEY.into(),
                    serde_json::Value::String(if kind == SourceKind::AwsOrganization {
                        "aws-account:123456789012".into()
                    } else {
                        "microsoft365-tenant:22222222-2222-4222-8222-222222222222".into()
                    }),
                )]),
            },
        )
        .unwrap();
    let observed_at = Utc::now();
    let artifact = registry
        .ingest_provider_response(&kind, raw, profile, observed_at)
        .unwrap();
    let operation = if kind == SourceKind::AwsOrganization {
        "organizations:ListAccounts"
    } else {
        "microsoft-graph:DirectoryInventory"
    };
    service
        .attach_live_provider_capture(
            case_id,
            &source.id,
            LiveProviderArtifactSet {
                schema_version: LIVE_PROVIDER_ARTIFACT_SET_SCHEMA.into(),
                capture_id: format!("capture-{}", source.id),
                profile: profile.into(),
                operation: operation.into(),
                observed_at,
                complete: true,
                pages: vec![LiveProviderArtifactPage {
                    sequence: 1,
                    operation: operation.into(),
                    http_status: 200,
                    parser_eligible: true,
                    artifact,
                }],
            },
        )
        .unwrap();
    let captured = service
        .show_case(case_id)
        .unwrap()
        .data_sources
        .into_iter()
        .find(|item| item.id == source.id)
        .unwrap();
    let batch = run_connector(&registry.connector_for(&kind), &captured).unwrap();
    service.reconcile_discovery_batch(case_id, &batch).unwrap();
    service
        .show_case(case_id)
        .unwrap()
        .assets
        .into_iter()
        .find(|asset| asset.kind == expected_kind && asset.discovered_from.contains(&source.id))
        .unwrap()
        .id
}

fn substituted_fixture(
    engine: &str,
    asset_id: &str,
    grant_id: &str,
    outcomes: EngineOutcomes,
) -> (&'static str, Vec<u8>) {
    let (bytes, name) = fixture(engine, outcomes);
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    (
        name,
        text.replace("asset-1", asset_id)
            .replace("grant-1", grant_id)
            .replace("service.example.test", "portal.example.test")
            .replace("example.com", "portal.example.test")
            .replace(
                "portal.example.test",
                if engine == "zap" {
                    "passive.example.test"
                } else {
                    "portal.example.test"
                },
            )
            .into_bytes(),
    )
}

/// Everything one Naabu attempt needs before it may reach a target: the
/// immutable work plan the case service freezes, the launcher request recorded
/// against that plan, the private launcher document the container reads, its
/// exact digest, and the gateway those selected work units address.
struct NaabuAttempt {
    plan: NaabuWorkPlanV1,
    request: NaabuAttemptRequest,
    launcher: NaabuLauncherPlanDocument,
    launcher_sha256: String,
    gateway: Vec<GatewayDestination>,
}

/// Rebuilds the private launcher work the current Naabu launcher demands.
///
/// Naabu is the one engine the orchestrator refuses to start from its scope
/// grant alone: it wants the frozen work-unit document a real attempt saves
/// before any contact, and the digest of the exact bytes that document
/// serializes to. Building it here through the production builder keeps the
/// audit run on the path a real attempt takes instead of teaching the harness
/// its own idea of an authorized port sweep.
fn naabu_attempt(execution: &PlannedEngineExecution) -> NaabuAttempt {
    let external = execution.scope_grants[0]
        .external_scope
        .as_ref()
        .expect("the Naabu grant carries a structured external scope");
    let frozen_at = Utc::now();
    // The grant names a literal address, so freezing consults no resolver and
    // the empty candidate list below is never read.
    let resolved = freeze_external_plan(external, [], frozen_at).expect("frozen external plan");
    let identity = NaabuWorkPlanIdentity::new(
        &execution.case_id,
        &execution.scan_run_id,
        &execution.engine_run_id,
        frozen_at,
    );
    let plan = build_naabu_work_plan(identity, std::slice::from_ref(&resolved), None)
        .expect("Naabu work plan");
    let requested_unit_ids = plan
        .work_units
        .iter()
        .map(|unit| unit.unit_id.clone())
        .collect::<Vec<_>>();
    let selected = requested_unit_ids.iter().cloned().collect::<BTreeSet<_>>();
    let launcher = plan
        .launcher_plan_v3(execution.attempt, Some(&selected))
        .expect("Naabu launcher plan");
    let launcher_sha256 = hex::encode(Sha256::digest(
        serde_json::to_vec(&launcher).expect("launcher plan JSON"),
    ));
    // The orchestrator requires the attempt gateway to be exactly the endpoint
    // rectangles the selected work units address -- not the grant's whole
    // corpus -- so project it off the plan rather than restating it.
    let mut gateway = plan
        .resolved_plans_for_work_units(&requested_unit_ids)
        .expect("Naabu attempt gateway")
        .iter()
        .map(|resolved| GatewayDestination {
            hostname: match &resolved.target {
                CanonicalTarget::Hostname(hostname) => Some(hostname.clone()),
                CanonicalTarget::Address(_) | CanonicalTarget::Network(_) => None,
            },
            addresses: resolved.resolution.addresses.iter().copied().collect(),
            ports: resolved.ports.iter().copied().collect(),
            allow_sensitive_networks: resolved.allow_sensitive_networks,
        })
        .collect::<Vec<_>>();
    gateway.sort();
    gateway.dedup();
    NaabuAttempt {
        plan,
        request: NaabuAttemptRequest {
            schema_version: NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION,
            execution_attempt: execution.attempt,
            requested_unit_ids,
            launcher_plan_sha256: launcher_sha256.clone(),
        },
        launcher,
        launcher_sha256,
        gateway,
    }
}

fn execute(
    orchestrator: &Orchestrator<'_, FakeContainerRuntime>,
    runtime: &FakeContainerRuntime,
    execution: &PlannedEngineExecution,
    workspace: Option<&Path>,
    cancellation: &CancellationToken,
    outcomes: EngineOutcomes,
    naabu: Option<(&CaseService<'_>, &NaabuAttempt)>,
) -> ExecutionReport {
    let manifest = execution.manifest.clone();
    let (name, output) = substituted_fixture(
        &execution.manifest.id,
        &execution.assets[0].id,
        &execution.scope_grants[0].id,
        outcomes,
    );
    runtime.set_behavior(FakeRunBehavior {
        exit_code: if manifest.id == "checkov" && outcomes == EngineOutcomes::MixedTerminalStates {
            Some(9)
        } else {
            Some(0)
        },
        stdout: vec![],
        stderr: vec![],
        output_files: match naabu {
            Some((_, attempt)) => launcher_output(execution, attempt, output),
            None => BTreeMap::from([(name.into(), output)]),
        },
    });
    let gateway = naabu.map(|(_, attempt)| attempt.gateway.as_slice());
    let destinations = match execution.manifest.id.as_str() {
        "nuclei" | "httpx" => vec!["portal.example.test:443".into()],
        "zap" => vec!["passive.example.test:443".into()],
        "garak" => vec!["model.example.test:8443".into()],
        "greenbone" => vec!["203.0.113.10:443".into(), "203.0.113.10:8443".into()],
        "naabu" => gateway
            .expect("the Naabu run carries its prepared attempt")
            .iter()
            .flat_map(|destination| {
                destination.addresses.iter().flat_map(|address| {
                    destination
                        .ports
                        .iter()
                        .map(move |port| std::net::SocketAddr::new(*address, *port).to_string())
                })
            })
            .collect(),
        _ => manifest.network_destinations.clone(),
    };
    let network = if destinations.is_empty() {
        NetworkPolicy::Disabled
    } else {
        NetworkPolicy::managed(
            format!("audit-{}-network", execution.manifest.id),
            format!("audit-{}-policy", execution.manifest.id),
            destinations,
            "socks5h://172.29.0.1:1080",
        )
        .unwrap()
    };
    let resources = ResourceLimits {
        memory_mb: execution.manifest.estimated_memory_mb,
        tmpfs_mb: execution.manifest.estimated_disk_mb.clamp(16, 4096),
        ..Default::default()
    };
    let frozen = match execution.manifest.id.as_str() {
        "nuclei" | "httpx" => Some(vec![GatewayDestination {
            hostname: Some("portal.example.test".into()),
            addresses: BTreeSet::from(["203.0.113.20".parse().unwrap()]),
            ports: BTreeSet::from([443]),
            allow_sensitive_networks: false,
        }]),
        "naabu" => Some(
            gateway
                .expect("the Naabu run carries its prepared attempt")
                .to_vec(),
        ),
        _ => None,
    };
    let credentials = if execution.manifest.id == "garak" {
        let sessions = ai_security_scanner_lib::garak_input::ModelEndpointSessions::default();
        sessions
            .put(
                &execution.case_id,
                &execution.assets[0],
                zeroize::Zeroizing::new("synthetic-fixture-only-no-provider-access".into()),
                Utc::now(),
            )
            .unwrap();
        sessions
            .take(
                &execution.case_id,
                &execution.assets[0],
                &execution.scope_grants,
                Utc::now(),
            )
            .unwrap()
    } else {
        ScannerCredentialSet::default()
    };
    let request = EngineExecutionRequest {
        case_id: &execution.case_id,
        scan_run_id: &execution.scan_run_id,
        engine_run_id: &execution.engine_run_id,
        manifest: &manifest,
        ai_system_applicable: execution.ai_system_applicable,
        ai_generated_artifact_applicable: execution.ai_generated_artifact
            == AiGeneratedArtifactAnswer::Yes,
        assets: &execution.assets,
        scope_grants: &execution.scope_grants,
        frozen_destinations: frozen.as_deref(),
        naabu_launcher_plan: naabu.map(|(_, attempt)| &attempt.launcher),
        expected_naabu_launcher_plan_sha256: naabu
            .map(|(_, attempt)| attempt.launcher_sha256.as_str()),
        workspace,
        network_policy: &network,
        resource_limits: &resources,
        credentials: &credentials,
        attempt: execution.attempt,
    };
    let Some((service, attempt)) = naabu else {
        return orchestrator.execute(&request, cancellation).unwrap();
    };
    // The launcher is the one engine whose process exit is not the coverage
    // authority: the orchestrator hands back a captured attempt and the host
    // reads which work units were actually tested out of the journal, then
    // runs the adapter over the per-unit results. That is three calls, in this
    // order, and skipping any of them leaves the check reported as not tested.
    let report = stamped(orchestrator.execute(&request, cancellation).unwrap());
    let applied = service
        .apply_naabu_launcher_v2_execution_report(
            &execution.case_id,
            &DurableExecutionReport::from(&report),
        )
        .unwrap();
    assert!(
        matches!(
            applied.coverage,
            NaabuLauncherV2CoverageApplyOutcome::Persisted { .. }
        ),
        "the launcher attempt recorded no work-unit coverage: {:?}",
        applied.coverage
    );
    service
        .adapt_and_persist_naabu_attempt(
            &execution.case_id,
            &execution.scan_run_id,
            &execution.engine_run_id,
            attempt.request.execution_attempt,
        )
        .unwrap();
    service
        .finish_naabu_launcher_v2_normalization(
            &execution.case_id,
            &execution.scan_run_id,
            &execution.engine_run_id,
            false,
        )
        .unwrap();
    report
}

/// Writes what a finished launcher attempt leaves under `/output`: one result
/// file per requested work unit, and the append-only journal that says which
/// units the attempt actually tested.
///
/// The whole port corpus goes to the first unit's file and later units finish
/// empty, which is what a sweep of a small corpus produces: the division is by
/// endpoint rectangle, not by how many ports happen to answer.
fn launcher_output(
    execution: &PlannedEngineExecution,
    attempt: &NaabuAttempt,
    scanner_output: Vec<u8>,
) -> BTreeMap<String, Vec<u8>> {
    let units_by_id = attempt
        .plan
        .work_units
        .iter()
        .map(|unit| (unit.unit_id.as_str(), unit.scope_sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut files = BTreeMap::new();
    let mut journal = format!(
        "{}\n",
        serde_json::json!({
            "record_type": "header",
            "schema_version": 2,
            "engine_run_id": execution.engine_run_id,
            "execution_attempt": execution.attempt,
            "requested_work_units": attempt
                .request
                .requested_unit_ids
                .iter()
                .map(|unit_id| serde_json::json!({
                    "unit_id": unit_id,
                    "scope_sha256": units_by_id[unit_id.as_str()],
                }))
                .collect::<Vec<_>>(),
        })
    );
    for (ordinal, unit_id) in attempt.request.requested_unit_ids.iter().enumerate() {
        let bytes = if ordinal == 0 {
            scanner_output.clone()
        } else {
            Vec::new()
        };
        let relative_path = format!(
            "launcher-v2/units/unit-{ordinal:06}/attempt-{}.jsonl",
            execution.attempt
        );
        journal.push_str(&format!(
            "{}\n",
            serde_json::json!({
                "record_type": "attempt_finished",
                "unit_id": unit_id,
                "scope_sha256": units_by_id[unit_id.as_str()],
                "attempt": execution.attempt,
                "outcome": "tested_complete",
                "final_artifact": {
                    "engine_run_id": execution.engine_run_id,
                    "unit_id": unit_id,
                    "scope_sha256": units_by_id[unit_id.as_str()],
                    "attempt": execution.attempt,
                    "relative_path": relative_path,
                    "sha256": hex::encode(Sha256::digest(&bytes)),
                    "byte_length": bytes.len(),
                },
            })
        ));
        files.insert(relative_path, bytes);
    }
    files.insert("launcher-v2/journal.jsonl".into(), journal.into_bytes());
    files
}

/// Records which runtime produced one report, the way the desktop path records
/// it after its own preflight.
fn stamped(mut report: ExecutionReport) -> ExecutionReport {
    report.checkpoint.runtime_provider = Some(RuntimeProvider::Docker);
    report.checkpoint.runtime_command_provenance = Some(RuntimeCommandProvenance::Compatibility);
    report
}

/// One finished all-engine run, handed to the audit body by reference so the
/// service and the temporary tree it writes into outlive every check.
struct AllEngineRun<'a> {
    engines: &'a EngineRegistry,
    adapters: &'a AdapterRegistry,
    database: &'a Path,
    artifact_root: &'a Path,
    signing_key: &'a Path,
    case_id: &'a str,
    scan_run_id: &'a str,
    completed: AssessmentCase,
    report: BeginnerMasterReport,
}

/// Runs every integrated engine once against one fixture case and hands the
/// terminal report to `audit`.
///
/// The two case answers are parameters because they are the only inputs that
/// decide which framework families a report may reference: AIDEFEND
/// coordinates are withheld unless the case declares an AI system, and its
/// static-admission coordinate unless the case also declares an AI-generated
/// artifact. Everything else -- assets, grants, routes, fixture bytes and the
/// per-engine outcomes -- is identical between runs, so a difference between
/// two reports is a difference the answers caused.
fn all_engines_in_one_report<T>(
    intent: AssessmentIntent,
    ai_generated: AiGeneratedArtifactAnswer,
    outcomes: EngineOutcomes,
    audit: impl FnOnce(&AllEngineRun<'_>) -> T,
) -> T {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("casework.db");
    let artifact_root = temp.path().join("artifacts");
    let signing_key = temp.path().join("integrity-key");
    let storage = Storage::open(&database).unwrap();
    let engines = EngineRegistry::load_builtin().unwrap();
    let adapters = builtin_adapter_registry().unwrap();
    let artifacts = ArtifactStore::open(&artifact_root).unwrap();
    let service = CaseService::new(&storage, &engines, &adapters, &artifact_root, &signing_key);
    let case = service
        .create_case(&CreateCaseRequest {
            title: format!("All integrated engines, one report ({intent:?})"),
            organization_name: "Fixture organization".into(),
            employee_range: "1-10".into(),
            assessment_intent: Some(intent),
            ai_generated_artifact: ai_generated,
            data_classes: vec![DataClass::CredentialsAndSecrets],
            requested_activities: vec![AssessmentActivity::ActiveExternalVulnerabilityTests],
            source_kinds: vec![],
            not_applicable_source_kinds: vec![],
            notes: Some("FakeContainerRuntime only; no network target contact".into()),
            declared_assets: vec![
                DeclaredAssetInput {
                    kind: DeclaredAssetKind::ExternalTarget,
                    value: "portal.example.test".into(),
                    internet_exposed: Some(true),
                    web_service: Some(DeclaredWebServiceInput {
                        protocol: DeclaredWebProtocol::Https,
                        port: 443,
                        path: "/".into(),
                        scan_profile: None,
                    }),
                    network_service: None,
                    host_scan: None,
                },
                DeclaredAssetInput {
                    kind: DeclaredAssetKind::ExternalTarget,
                    value: "passive.example.test".into(),
                    internet_exposed: Some(true),
                    web_service: Some(DeclaredWebServiceInput {
                        protocol: DeclaredWebProtocol::Https,
                        port: 443,
                        path: "/".into(),
                        scan_profile: None,
                    }),
                    network_service: None,
                    host_scan: None,
                },
                DeclaredAssetInput {
                    kind: DeclaredAssetKind::ExternalTarget,
                    value: "203.0.113.10".into(),
                    internet_exposed: Some(false),
                    web_service: None,
                    network_service: None,
                    host_scan: Some(DeclaredHostScanInput {
                        protocol: DeclaredNetworkProtocol::Tcp,
                        ports: vec![443, 8443],
                        profile: DeclaredHostScanProfile::GreenboneRemoteSafeV1,
                    }),
                },
                DeclaredAssetInput {
                    kind: DeclaredAssetKind::ExternalTarget,
                    value: "203.0.113.11".into(),
                    internet_exposed: Some(false),
                    web_service: None,
                    network_service: None,
                    host_scan: None,
                },
            ],
        })
        .unwrap();
    let website = case
        .assets
        .iter()
        .find(|a| {
            a.kind == AssetKind::WebService
                && a.identifiers
                    .iter()
                    .any(|identifier| identifier.value == "portal.example.test")
        })
        .unwrap()
        .id
        .clone();
    let passive_website = case
        .assets
        .iter()
        .find(|asset| {
            asset
                .identifiers
                .iter()
                .any(|identifier| identifier.value == "passive.example.test")
        })
        .unwrap()
        .id
        .clone();
    let host = case
        .assets
        .iter()
        .find(|a| a.kind == AssetKind::Host)
        .unwrap()
        .id
        .clone();
    let naabu_host = case
        .assets
        .iter()
        .find(|asset| {
            asset
                .identifiers
                .iter()
                .any(|identifier| identifier.value == "203.0.113.11")
        })
        .unwrap()
        .id
        .clone();

    let selected = temp.path().join("selected");
    let inputs = [
        (
            "repo",
            "Repository",
            WorkspaceInputProfile::RepositoryWorkingTree,
        ),
        (
            "oci",
            "OCI image",
            WorkspaceInputProfile::ContainerImageOciLayout,
        ),
        (
            "manifests",
            "Kubernetes manifests",
            WorkspaceInputProfile::KubernetesManifests,
        ),
        (
            "node",
            "Kubernetes node",
            WorkspaceInputProfile::KubernetesNodeSnapshot,
        ),
    ];
    fs::create_dir_all(selected.join("repo")).unwrap();
    fs::write(
        selected.join("repo/main.tf"),
        b"resource \"fixture\" \"audit\" {}\n",
    )
    .unwrap();
    fs::write(
        selected.join("repo/mcp.json"),
        include_bytes!("../../engines/images/mcp-armor/testdata/workspace/mcp.json"),
    )
    .unwrap();
    write_oci_layout(&selected.join("oci"));
    fs::create_dir_all(selected.join("manifests")).unwrap();
    fs::write(
        selected.join("manifests/pod.yaml"),
        b"apiVersion: v1\nkind: Pod\nmetadata:\n  name: audit\n",
    )
    .unwrap();
    fs::create_dir_all(selected.join("node")).unwrap();
    write_node_snapshot(&selected.join("node"));
    let mut local_assets = BTreeMap::<String, (String, WorkspaceSnapshotReference)>::new();
    for (source_id, label, profile) in inputs {
        let snapshot = create_workspace_snapshot_with_profile(
            &artifact_root,
            &case.id,
            source_id,
            selected.join(source_id),
            profile,
            WorkspaceSnapshotLimits::default(),
        )
        .unwrap();
        local_assets.insert(
            source_id.into(),
            (snapshot.asset.id.clone(), snapshot.reference.clone()),
        );
        service
            .attach_workspace_snapshot(&case.id, label, snapshot)
            .unwrap();
    }
    let connector_root = temp.path().join("connector-artifacts");
    fs::create_dir(&connector_root).unwrap();
    let connectors = SnapshotConnectorRegistry::new(&connector_root).unwrap();
    let aws = attach_provider_asset(
        &service,
        &connectors,
        &case.id,
        SourceKind::AwsOrganization,
        "aws-organizations-list-accounts",
        br#"{"Accounts":[{"Arn":"arn:aws:organizations::123456789012:account/o-fixture/123456789012","Email":"audit@example.test","Id":"123456789012","JoinedMethod":"CREATED","JoinedTimestamp":1.7E9,"Name":"Audit account","State":"ACTIVE","Status":"ACTIVE"}]}"#,
        AssetKind::CloudAccount,
    );
    let m365 = attach_provider_asset(&service, &connectors, &case.id, SourceKind::Microsoft365Tenant, "microsoft-graph-directory-inventory", br#"{"value":[{"id":"22222222-2222-4222-8222-222222222222","displayName":"Audit tenant"}]}"#, AssetKind::Tenant);

    let repo = &local_assets["repo"].0;
    service
        .select_agentic_framework(
            &case.id,
            repo,
            &local_assets["repo"].1.sha256,
            Some(ai_security_scanner_lib::agentic_radar_input::AgenticFramework::N8n),
        )
        .unwrap();
    let oci = &local_assets["oci"].0;
    let manifests = &local_assets["manifests"].0;
    let node = &local_assets["node"].0;
    for (asset_id, permissions, external_scope) in [
        (repo, vec![ScanPermission::LocalArtifactRead], None),
        (oci, vec![ScanPermission::LocalArtifactRead], None),
        (manifests, vec![ScanPermission::LocalArtifactRead], None),
        (node, vec![ScanPermission::LocalArtifactRead], None),
        (
            &aws,
            vec![
                ScanPermission::InventoryRead,
                ScanPermission::ConfigurationRead,
            ],
            None,
        ),
        (
            &m365,
            vec![
                ScanPermission::InventoryRead,
                ScanPermission::ConfigurationRead,
            ],
            None,
        ),
    ] {
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id: asset_id.clone(),
                    permissions,
                    confirmed_by: "Fixture asset owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: Some("Fixture-only execution".into()),
                    external_scope,
                },
            )
            .unwrap();
    }
    let expires = Utc::now() + Duration::hours(1);
    let model_input = ai_security_scanner_lib::garak_input::ModelEndpointInput::validated(
        "https://model.example.test:8443/v1/chat/completions",
        "fixture/model",
    )
    .unwrap();
    let configured = service
        .configure_model_endpoint(&case.id, model_input.clone(), true)
        .unwrap();
    let model_asset = configured
        .assets
        .iter()
        .find(|asset| {
            ai_security_scanner_lib::garak_input::asset_input(asset)
                .ok()
                .as_ref()
                == Some(&model_input)
        })
        .unwrap()
        .id
        .clone();
    service
        .approve_scope(
            &case.id,
            ScopeApprovalRequest {
                asset_id: model_asset.clone(),
                permissions: vec![ScanPermission::ActiveExternalTesting],
                confirmed_by: "Fixture model owner".into(),
                expires_at: Some(Utc::now() + Duration::minutes(30)),
                authorization_reference: Some(
                    "Exact model fixture and stated inference charges".into(),
                ),
                notes: Some("Fake runtime only; no API key or endpoint contact".into()),
                external_scope: Some(ExternalScopeRequest {
                    target: "model.example.test".into(),
                    ports: BTreeSet::from([8443]),
                    protocol: TransportProtocol::Https,
                    activity: ExternalActivity::ActiveExternal,
                    rate_policy: RatePolicy {
                        requests_per_second: 1,
                        concurrency: 1,
                        timeout_seconds: 20,
                    },
                    template_policy: TemplatePolicy::conservative_profile(
                        ai_security_scanner_lib::garak_input::SOURCE_REVISION,
                        ai_security_scanner_lib::garak_input::PROFILE_ID,
                    ),
                    asserted_authority: "Exact model fixture and stated inference charges".into(),
                    allow_sensitive_networks: false,
                }),
            },
        )
        .unwrap();
    for (asset_id, target, ports, protocol, permission, activity, templates) in [
        (
            &website,
            "portal.example.test",
            BTreeSet::from([443]),
            TransportProtocol::Https,
            ScanPermission::LowImpactExternalConnection,
            ExternalActivity::LowImpactExternal,
            TemplatePolicy::conservative("not_applicable", vec![]),
        ),
        (
            &website,
            "portal.example.test",
            BTreeSet::from([443]),
            TransportProtocol::Https,
            ScanPermission::ActiveExternalTesting,
            ExternalActivity::ActiveExternal,
            TemplatePolicy::conservative_profile(
                format!(
                    "nuclei-templates@{}",
                    engines
                        .get("nuclei")
                        .unwrap()
                        .rule_version
                        .as_deref()
                        .unwrap()
                ),
                "nuclei_web_safe_v1",
            ),
        ),
        (
            &passive_website,
            "passive.example.test",
            BTreeSet::from([443]),
            TransportProtocol::Https,
            ScanPermission::ActiveExternalTesting,
            ExternalActivity::ActiveExternal,
            TemplatePolicy::conservative_profile(
                ai_security_scanner_lib::zap_work_plan::ZAP_PASSIVE_TEMPLATE_REVISION,
                ai_security_scanner_lib::zap_work_plan::ZAP_PASSIVE_PROFILE_ID,
            ),
        ),
        (
            &naabu_host,
            "203.0.113.11",
            BTreeSet::from([443, 8443]),
            TransportProtocol::Tcp,
            ScanPermission::LowImpactExternalConnection,
            ExternalActivity::LowImpactExternal,
            TemplatePolicy::conservative("not_applicable", vec![]),
        ),
        (
            &host,
            "203.0.113.10",
            BTreeSet::from([443, 8443]),
            TransportProtocol::Tcp,
            ScanPermission::ActiveExternalTesting,
            ExternalActivity::ActiveExternal,
            TemplatePolicy::conservative_profile(
                format!(
                    "greenbone-community-feed@{}",
                    engines
                        .get("greenbone")
                        .unwrap()
                        .rule_version
                        .as_deref()
                        .unwrap()
                ),
                "greenbone_remote_safe_v1",
            ),
        ),
    ] {
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id: asset_id.clone(),
                    permissions: vec![permission],
                    confirmed_by: "Fixture target owner".into(),
                    expires_at: Some(expires),
                    authorization_reference: Some("Exact fixture target".into()),
                    notes: Some("Fake runtime only".into()),
                    external_scope: Some(ExternalScopeRequest {
                        target: target.into(),
                        ports,
                        protocol,
                        activity,
                        rate_policy: RatePolicy {
                            requests_per_second: if target == "portal.example.test" {
                                10
                            } else if target == "passive.example.test" {
                                5
                            } else {
                                2
                            },
                            concurrency: if matches!(
                                target,
                                "portal.example.test" | "passive.example.test"
                            ) {
                                5
                            } else {
                                1
                            },
                            timeout_seconds: if matches!(
                                target,
                                "portal.example.test" | "passive.example.test"
                            ) {
                                10
                            } else {
                                15
                            },
                        },
                        template_policy: templates,
                        asserted_authority: "Exact fixture target approved".into(),
                        allow_sensitive_networks: !matches!(
                            target,
                            "portal.example.test" | "passive.example.test"
                        ),
                    }),
                },
            )
            .unwrap();
    }

    let mut routes: Vec<EngineAssetRoute> = [
        ("nuclei", &website),
        ("zap", &passive_website),
        ("httpx", &website),
        ("greenbone", &host),
        ("naabu", &naabu_host),
        ("gitleaks", repo),
        ("trufflehog", repo),
        ("semgrep", repo),
        ("checkov", repo),
        ("kics", repo),
        ("mcp-armor", repo),
        ("agentic-radar", repo),
        ("kubescape", manifests),
        ("kube-bench", node),
        ("cloudquery", &aws),
        ("steampipe", &aws),
        ("prowler", &aws),
        ("scoutsuite", &aws),
        ("cloudsplaining", &aws),
        ("scubagear", &m365),
        ("maester", &m365),
    ]
    .into_iter()
    .map(|(engine_id, asset_id)| EngineAssetRoute {
        engine_id: engine_id.into(),
        asset_ids: vec![asset_id.clone()],
    })
    .chain(
        ["trivy", "grype", "syft"]
            .into_iter()
            .map(|engine_id| EngineAssetRoute {
                engine_id: engine_id.into(),
                asset_ids: vec![repo.clone(), oci.clone()],
            }),
    )
    .collect();
    if dispatchable_engine_ids(&engines).contains("garak") {
        routes.push(EngineAssetRoute {
            engine_id: "garak".into(),
            asset_ids: vec![model_asset],
        });
    }
    let plan = service
        .plan_scan(
            &case.id,
            ScanPlanRequest {
                campaign_id: None,
                engine_ids: vec![],
                engine_asset_routes: routes,
            },
        )
        .unwrap();
    assert!(
        plan.not_executed.is_empty(),
        "unroutable engines: {:?}",
        plan.not_executed
    );
    assert_eq!(
        plan.executable.len(),
        dispatchable_engine_ids(&engines).len() + 3
    );
    assert!(
        plan.executable
            .iter()
            .all(|execution| execution.assets.len() == 1)
    );

    let runtime = FakeContainerRuntime::default();
    let orchestrator = Orchestrator::new(&runtime, &artifacts, &adapters);
    // Outcome carriers, on the mixed run: nuclei=partial;
    // semgrep=complete-empty; checkov=failed; kics=timed out on the host
    // deadline; trufflehog=cancelled; greenbone=unevaluated/dead host.
    // Syft, CloudQuery, Steampipe, Naabu and HTTPX are observation/inventory
    // only in either run: discovery prepares a target, it is not a result.
    let mixed = outcomes == EngineOutcomes::MixedTerminalStates;
    for execution in &plan.executable {
        let workspace = local_assets
            .values()
            .find(|(id, _)| id == &execution.assets[0].id)
            .map(|(_, reference)| {
                resolve_workspace_snapshot(&artifact_root, &case.id, reference)
                    .unwrap()
                    .tree_path
            });
        let mut report = match execution.manifest.id.as_str() {
            "naabu" if mixed => ExecutionReport {
                checkpoint: ExecutionCheckpoint {
                    case_id: execution.case_id.clone(),
                    scan_run_id: execution.scan_run_id.clone(),
                    engine_run_id: execution.engine_run_id.clone(),
                    engine_id: execution.manifest.id.clone(),
                    attempt: execution.attempt,
                    stage: ExecutionStage::Cancelled,
                    container_name: None,
                    scope_sha256: None,
                    zap_plan_sha256: None,
                    launcher_plan_sha256: None,
                    artifact_ids: vec![],
                    cleanup_completed: true,
                    last_error: None,
                    failure_code: None,
                    runtime_command_provenance: None,
                    runtime_provider: None,
                    managed_network: None,
                },
                runtime_preflight: None,
                cleanup: None,
                exit_code: None,
                raw_artifacts: vec![],
                findings: vec![],
                observations: vec![],
                warnings: vec![],
                unattributed: vec![],
                unevaluated_targets: vec![],
                security_template_executions: vec![],
                manual_review_controls: vec![],
                artifact_root: artifact_root.clone(),
                output_directory: artifact_root.join("naabu-cancelled"),
            },
            "trufflehog" if mixed => {
                let token = CancellationToken::default();
                token.cancel();
                execute(
                    &orchestrator,
                    &runtime,
                    execution,
                    workspace.as_deref(),
                    &token,
                    outcomes,
                    None,
                )
            }
            "naabu" => {
                // The launcher's own precondition: the exact work request is
                // durable before the attempt may contact anything.
                let attempt = naabu_attempt(execution);
                service
                    .persist_naabu_attempt_request(
                        &execution.case_id,
                        &execution.scan_run_id,
                        &execution.engine_run_id,
                        &attempt.plan,
                        &attempt.request,
                    )
                    .unwrap();
                execute(
                    &orchestrator,
                    &runtime,
                    execution,
                    workspace.as_deref(),
                    &CancellationToken::default(),
                    outcomes,
                    Some((&service, &attempt)),
                )
            }
            _ => execute(
                &orchestrator,
                &runtime,
                execution,
                workspace.as_deref(),
                &CancellationToken::default(),
                outcomes,
                None,
            ),
        };
        if mixed && execution.manifest.id == "kics" {
            // The product's own host deadline, recorded the way the runtime
            // records it. An invented marker here would have exercised a
            // shape no run produces and left the timed-out row untested.
            report.checkpoint.stage = ExecutionStage::Failed;
            report.checkpoint.last_error = Some(CONTAINER_EXECUTION_TIMEOUT_ERROR.into());
            report.exit_code = None;
            report.findings.clear();
        }
        // The launcher run already applied its own interim and terminal
        // reports, the second through the launcher-v2 path that reads
        // work-unit coverage. Everything else applies once, here.
        if mixed || execution.manifest.id != "naabu" {
            service
                .apply_execution_report(&case.id, &DurableExecutionReport::from(&report))
                .unwrap();
        }
    }

    let completed = service.show_case(&case.id).unwrap();
    let report = build_beginner_master_report(&completed, &plan.scan_run.id).unwrap();
    audit(&AllEngineRun {
        engines: &engines,
        adapters: &adapters,
        database: &database,
        artifact_root: &artifact_root,
        signing_key: &signing_key,
        case_id: &case.id,
        scan_run_id: &plan.scan_run.id,
        completed,
        report,
    })
}

/// Every paragraph in one export closes before a block element opens.
///
/// Forty-five cards shipped `<p>...<h4>...</h4><p>...</p></p>`: a heading
/// nested in a paragraph, which every parser recovers from by closing the
/// paragraph early, plus a stray end tag after it. No reader saw an error and
/// no assertion about the report's words could see it either.
fn assert_paragraphs_are_well_formed(html: &str, label: &str) {
    // `<p class="...">` counts too. Counting only the bare tag would let a
    // styled paragraph carry the next nested heading past this gate.
    let opens = |html: &str| {
        html.match_indices("<p")
            .filter(|(at, _)| matches!(html[at + "<p".len()..].chars().next(), Some('>' | ' ')))
            .map(|(at, _)| at)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        opens(html).len(),
        html.matches("</p>").count(),
        "{label} does not close every paragraph"
    );
    let mut cursor = 0usize;
    while let Some(at) = opens(&html[cursor..]).first().copied() {
        let start = cursor
            + at
            + html[cursor + at..]
                .find('>')
                .expect("a paragraph open tag ends")
            + 1;
        let end = html[start..]
            .find("</p>")
            .map_or(html.len(), |offset| start + offset);
        for block in [
            "<h1", "<h2", "<h3", "<h4", "<ul", "<ol", "<table", "<section", "<article", "<details",
        ] {
            assert!(
                !html[start..end].contains(block),
                "{label} opens {block} inside a paragraph: {}",
                &html[start..end.min(start + 200)]
            );
        }
        assert!(
            opens(&html[start..end]).is_empty(),
            "{label} opens a paragraph inside a paragraph: {}",
            &html[start..end.min(start + 200)]
        );
        cursor = end;
    }
}

/// The reader-visible text of one rendered report, markup and entities gone.
fn strip_markup(html: &str) -> String {
    let mut text = String::with_capacity(html.len());
    let mut inside_tag = false;
    for character in html.chars() {
        match character {
            '<' => inside_tag = true,
            '>' => inside_tag = false,
            _ if !inside_tag => text.push(character),
            _ => {}
        }
    }
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

/// The first place an ASCII sentence mark closes a Chinese clause, with the
/// words around it.
///
/// A mark inside a value -- the decimal point of a version, the comma between
/// two fixed releases -- is not a clause break, so only a mark followed by
/// whitespace, another Han character or the end of the text counts.
fn ascii_clause_break_after_han(text: &str) -> Option<String> {
    fn is_han(character: char) -> bool {
        ('\u{4e00}'..='\u{9fff}').contains(&character)
    }
    let characters = text.chars().collect::<Vec<_>>();
    characters.windows(3).enumerate().find_map(|(at, window)| {
        let [before, mark, after] = [window[0], window[1], window[2]];
        (is_han(before)
            && matches!(mark, '.' | ',' | ';' | '!' | '?')
            && (after.is_whitespace() || is_han(after)))
        .then(|| {
            characters[at.saturating_sub(30)..(at + 30).min(characters.len())]
                .iter()
                .collect::<String>()
        })
    })
}

#[test]
fn an_ascii_clause_break_is_only_reported_where_a_chinese_clause_ends() {
    assert!(ascii_clause_break_after_han("遮蔽設定：無. 完整性：未簽章的 HTML").is_some());
    assert!(ascii_clause_break_after_han("移除群組只會附加歷史,不會刪除成員").is_some());
    // A mark inside a value is not a clause break.
    assert!(ascii_clause_break_after_han("對照版本：2026-09-11.1 · 目錄 SHA-256").is_none());
    assert!(ascii_clause_break_after_han("掃描工具提供的修正版版本 1.1, 1.2").is_none());
    assert!(ascii_clause_break_after_han("移除群組只會附加歷史，不會刪除成員。").is_none());
}

/// The first place a Chinese run-in label sets its colon the English way: an
/// ASCII `:` immediately after Han text, or a full-width `：` immediately
/// followed by a space it was never meant to carry.
fn ascii_label_colon_in_chinese(text: &str) -> Option<String> {
    fn is_han(character: char) -> bool {
        ('\u{4e00}'..='\u{9fff}').contains(&character)
    }
    let characters = text.chars().collect::<Vec<_>>();
    characters.windows(2).enumerate().find_map(|(at, window)| {
        let [before, after] = [window[0], window[1]];
        ((is_han(before) && after == ':') || (before == '：' && after == ' ')).then(|| {
            characters[at.saturating_sub(30)..(at + 30).min(characters.len())]
                .iter()
                .collect::<String>()
        })
    })
}

#[test]
fn a_chinese_label_colon_is_full_width_without_a_space() {
    assert!(ascii_label_colon_in_chinese("嚴重程度: 高").is_some());
    assert!(ascii_label_colon_in_chinese("可能影響： 值").is_some());
    assert!(ascii_label_colon_in_chinese("嚴重程度：高").is_none());
    assert!(ascii_label_colon_in_chinese("觀察時間 2026年09月26日 00:21:05").is_none());
    assert!(ascii_label_colon_in_chinese("對照版本：2026-09-11.1").is_none());
    assert!(ascii_label_colon_in_chinese("package:pyyaml").is_none());
}

/// The first place an ASCII space follows full-width punctuation, with the
/// words around it.
///
/// Full-width sentence and clause marks -- "。！？；：」』）" -- already carry
/// their own spacing. An ASCII space right after one is an English habit left
/// in by prose or markup that joins two runs with a literal " ". A space
/// before the product's own " · " metadata separator is not this mistake and
/// is not flagged.
fn space_after_full_width_mark(text: &str) -> Option<String> {
    let characters = text.chars().collect::<Vec<_>>();
    characters.windows(2).enumerate().find_map(|(at, window)| {
        let [before, after] = [window[0], window[1]];
        ("。！？；：」』）".contains(before)
            && after == ' '
            && characters.get(at + 2) != Some(&'·'))
        .then(|| {
            characters[at.saturating_sub(30)..(at + 30).min(characters.len())]
                .iter()
                .collect::<String>()
        })
    })
}

#[test]
fn a_full_width_mark_is_not_followed_by_a_space() {
    assert!(space_after_full_width_mark("狀況。 可能影響：高").is_some());
    assert!(space_after_full_width_mark("狀況。可能影響：高").is_none());
    assert!(space_after_full_width_mark("（CVE-2020-1747） 的").is_some());
    assert!(space_after_full_width_mark("本整合。https://doi.org/x").is_none());
    assert!(space_after_full_width_mark("version 2.0. Next").is_none());
    assert!(space_after_full_width_mark("（軟體元件） · 版本").is_none());
}

/// The first appearance of "座標" in reader-facing report text, with the
/// words around it.
///
/// A framework mapping is "a framework reference" (「框架參考」) everywhere a
/// reader sees one, on Results and in this report alike. "座標" means
/// nothing to a reader who does not already know the code, so any return
/// here is a wording leak this report must not carry.
fn retired_coordinate_word(text: &str) -> Option<String> {
    let at = text.find("座標")?;
    let characters = text.chars().collect::<Vec<_>>();
    let char_at = text[..at].chars().count();
    Some(
        characters[char_at.saturating_sub(30)..(char_at + 30).min(characters.len())]
            .iter()
            .collect::<String>(),
    )
}

#[test]
fn the_retired_coordinate_word_is_found_by_its_own_two_characters() {
    assert!(retired_coordinate_word("已觀察到相關座標").is_some());
    assert!(retired_coordinate_word("已觀察到相關框架參考").is_none());
    assert!(retired_coordinate_word("座標").is_some());
    assert!(retired_coordinate_word("框架參考").is_none());
    assert!(retired_coordinate_word("").is_none());
}

/// Discovery engines prepare a target for a security check. Their output is
/// inventory, not a result, in either run.
const INVENTORY_ONLY_ENGINES: [&str; 6] = [
    "agentic-radar",
    "cloudquery",
    "httpx",
    "naabu",
    "steampipe",
    "syft",
];

/// The engines this build will actually run, read from the release contract
/// rather than listed here.
///
/// A packaged catalog coordinate is not the same thing as a dispatchable
/// engine: an entry that declares itself non-runnable exists so its adapter has
/// a reviewed manifest to be validated against, and the registry refuses to
/// plan it. Asking a report to account for one is asking it to report on a
/// check that never ran. Derived from `release_blocker` so a coordinate that
/// later becomes runnable is picked up here without anyone remembering to.
fn dispatchable_engine_ids(engines: &EngineRegistry) -> BTreeSet<&'static str> {
    BUILTIN_ENGINE_IDS
        .iter()
        .copied()
        .filter(|engine_id| {
            engines
                .get(engine_id)
                .is_some_and(|manifest| manifest.release_blocker().is_none())
        })
        .collect()
}

fn section_between<'a>(html: &'a str, start: &str, end: &str) -> &'a str {
    let start_at = html
        .find(start)
        .unwrap_or_else(|| panic!("missing {start}"));
    let rest = &html[start_at + start.len()..];
    let end_at = rest
        .find(end)
        .unwrap_or_else(|| panic!("missing {end} after {start}"));
    &rest[..end_at]
}

fn article_containing<'a>(html: &'a str, needle: &str) -> &'a str {
    let mut rest = html;
    while let Some(start) = rest.find("<article") {
        let item_rest = &rest[start..];
        let Some(end) = item_rest.find("</article>") else {
            break;
        };
        let item = &item_rest[..end + "</article>".len()];
        if item.contains(needle) {
            return item;
        }
        rest = &item_rest[end + "</article>".len()..];
    }
    panic!("no article contains {needle}");
}

fn list_item_containing<'a>(html: &'a str, needle: &str) -> &'a str {
    let mut rest = html;
    while let Some(start) = rest.find("<li>") {
        let item_rest = &rest[start..];
        let Some(end) = item_rest.find("</li>") else {
            break;
        };
        let item = &item_rest[..end + "</li>".len()];
        if item.contains(needle) {
            return item;
        }
        rest = &item_rest[end + "</li>".len()..];
    }
    panic!("no list item contains {needle}: {html}");
}

fn first_strong(item: &str) -> &str {
    let start = item.find("<strong>").expect("a step action") + "<strong>".len();
    let end = item[start..]
        .find("</strong>")
        .expect("a step action closes");
    &item[start..start + end]
}

fn assert_uppercase_password_rule_keeps_its_severity_and_explains_a_lower_order(
    english: &str,
    chinese: &str,
) {
    let title = "Password Policy Lacks Uppercase Requirement";
    let card = article_containing(english, title);
    assert!(
        card.contains(
            "<p class=\"finding-priority-basis\"><strong>Benchmark:</strong> CIS Amazon Web Services Foundations 1.2.0 item 1.5 (reported by ScoutSuite)<br><strong>Why this order:</strong> Placed lower than its severity suggests."
        ),
        "{card}"
    );
    assert_eq!(
        card.matches(ai_security_scanner_lib::finding_narrative::PASSWORD_COMPOSITION_ORDER_REASON)
            .count(),
        1,
        "{card}"
    );
    assert!(
        card.contains("<span class=\"pill pill--high\">Severity: High</span>"),
        "{card}"
    );
    // The reviewed mismatch: a password-policy card told the reader to apply
    // least privilege. Its next step names the setting instead.
    assert!(
        !card.contains("least privilege"),
        "the password-policy card must name the setting, not least privilege: {card}"
    );
    let card_zh = article_containing(chinese, title);
    assert!(
        !card_zh.contains("最小權限"),
        "the Chinese password-policy card must name the setting: {card_zh}"
    );
    assert!(
        card_zh.contains(
            "<p class=\"finding-priority-basis\"><strong>基準：</strong>CIS Amazon Web Services Foundations 1.2.0 第 1.5 項（ScoutSuite 回報）<br><strong>排序原因：</strong>處理順序比嚴重程度所示更後面。"
        ),
        "{card_zh}"
    );
    assert_eq!(
        card_zh
            .matches(
                ai_security_scanner_lib::finding_narrative::PASSWORD_COMPOSITION_ORDER_REASON_ZH_HANT
            )
            .count(),
        1,
        "{card_zh}"
    );
    assert!(
        card_zh.contains("<span class=\"pill pill--high\">嚴重程度：高</span>"),
        "{card_zh}"
    );
    let index = section_between(english, "<table class=\"finding-index\">", "</table>");
    let row_at = index
        .find(title)
        .expect("the uppercase password rule is in the problem index");
    let mut rest = index;
    while let Some(at) = rest.find("pill--medium") {
        let absolute = index.len() - rest.len() + at;
        assert!(
            absolute < row_at,
            "a Medium-severity row sorts after the uppercase password rule"
        );
        rest = &rest[at + "pill--medium".len()..];
    }
}

/// A family-level instruction repeated across different findings is the same
/// kind of change, not one fix. A typed IAM policy action is one fix. A
/// Microsoft 365 control is titled for the state it was checking, so a failed
/// control's heading says the requirement was not met.
fn assert_next_steps_distinguish_one_fix_from_the_same_kind_of_change(
    english: &str,
    chinese: &str,
) {
    let english_steps = section_between(
        english,
        "<h2>What to do next</h2>",
        "<h2>Problems found</h2>",
    );
    let chinese_steps = section_between(chinese, "<h2>下一步怎麼做</h2>", "<h2>發現的問題</h2>");
    for title in [
        "Resource limits",
        "Vulnerable package example-package (CVE-2025-0002)",
        "Attached IAM customer-managed policy allows &#39;*:*&#39; administrative privileges",
        "Content Security Policy (CSP) Header Not Set",
    ] {
        let step = list_item_containing(english_steps, title);
        assert!(
            step.contains("related problems call for this kind of change"),
            "{title} must say each problem needs its own fix: {step}"
        );
        assert!(
            !step.contains(&format!(
                "problems name this same fix. The first is {title}"
            )),
            "{title} must not be called one shared fix: {step}"
        );
        let zh = list_item_containing(chinese_steps, title);
        assert!(
            zh.contains("需要這類處理"),
            "{title} must say each problem needs its own fix in Chinese: {zh}"
        );
        assert!(
            !zh.contains("指向同一個修復方式"),
            "{title} must not be called one shared fix in Chinese: {zh}"
        );
    }

    for policy in [
        "IAMFullAccess",
        "InlinePolicyForAdminGroup",
        "InsecurePolicy",
    ] {
        let step = list_item_containing(english_steps, policy);
        assert!(
            step.contains("problems name this same fix"),
            "{policy} is one change and must stay one fix: {step}"
        );
        let zh = list_item_containing(chinese_steps, policy);
        assert!(
            zh.contains("指向同一個修復方式"),
            "{policy} is one change and must stay one fix in Chinese: {zh}"
        );
    }

    // Nine Kubernetes problems sit on three resources. Naming only the lead's
    // would read as where all nine are.
    let kubernetes = list_item_containing(english_steps, "Resource limits");
    assert!(
        kubernetes.contains(
            "<strong>Location:</strong> apps/v1/production/StatefulSet/ledger-db and 2 more"
        ),
        "a grouped step names the lead's place and counts the others: {kubernetes}"
    );
    let kubernetes_zh = list_item_containing(chinese_steps, "Resource limits");
    assert!(
        kubernetes_zh
            .contains("<strong>位置：</strong>apps/v1/production/StatefulSet/ledger-db，另有 2 處"),
        "a grouped step names the lead's place and counts the others in Chinese: {kubernetes_zh}"
    );

    let password = list_item_containing(
        english_steps,
        "Attached IAM customer-managed policy allows &#39;*:*&#39; administrative privileges",
    );
    assert!(
        !first_strong(password).contains("least privilege"),
        "the cloud-setting action must name the setting, not least privilege: {password}"
    );
    let password_zh = list_item_containing(
        chinese_steps,
        "Attached IAM customer-managed policy allows &#39;*:*&#39; administrative privileges",
    );
    assert!(
        !first_strong(password_zh).contains("最小權限"),
        "the Chinese cloud-setting action must name the setting: {password_zh}"
    );

    let semgrep = list_item_containing(
        english_steps,
        "A subprocess launched through a shell can allow command injection",
    );
    assert!(
        semgrep.contains("<strong>Location:</strong> "),
        "the Semgrep step must name a location: {semgrep}"
    );
    assert!(
        semgrep.contains("src/example.py") && semgrep.contains("line 7"),
        "the Semgrep location must name the file and the line: {semgrep}"
    );
    assert!(
        semgrep.contains("<strong>To confirm:</strong> ") && semgrep.contains("Semgrep"),
        "the Semgrep step must say how to confirm it, naming Semgrep: {semgrep}"
    );
    let semgrep_zh = list_item_containing(
        chinese_steps,
        "A subprocess launched through a shell can allow command injection",
    );
    assert!(
        semgrep_zh.contains("<strong>位置：</strong>") && semgrep_zh.contains("src/example.py"),
        "the Chinese Semgrep step must name a location: {semgrep_zh}"
    );
    assert!(
        semgrep_zh.contains("第 7 行"),
        "the Chinese Semgrep location must name the line: {semgrep_zh}"
    );
    assert!(
        semgrep_zh.contains("<strong>確認方式：</strong>") && semgrep_zh.contains("Semgrep"),
        "the Chinese Semgrep step must say how to confirm it, naming Semgrep: {semgrep_zh}"
    );

    let raw = "Legacy authentication is blocked";
    let framed = format!("Requirement not met: {raw}");
    let index = section_between(english, "<table class=\"finding-index\">", "</table>");
    assert!(
        index.contains(&format!("<td>{framed}</td>")),
        "the problems table must frame the failed control: {index}"
    );
    assert!(
        !index.contains(&format!("<td>{raw}</td>")),
        "the problems table must not print the unframed control name: {index}"
    );
    assert!(
        english.contains(&format!("<h3>{framed} <span class=\"finding-asset\">")),
        "the card heading must frame the failed control"
    );
    assert!(
        !english.contains(&format!("<h3>{raw} <span class=\"finding-asset\">")),
        "the card heading must not print the unframed control name"
    );
    let framed_zh = format!("未符合要求：{raw}");
    let index_zh = section_between(chinese, "<table class=\"finding-index\">", "</table>");
    assert!(
        index_zh.contains(&format!("<td>{framed_zh}</td>")),
        "the Chinese problems table must frame the failed control: {index_zh}"
    );
    assert!(
        !index_zh.contains(&format!("<td>{raw}</td>")),
        "the Chinese problems table must not print the unframed control name: {index_zh}"
    );
    assert!(
        chinese.contains(&format!("<h3>{framed_zh} <span class=\"finding-asset\">")),
        "the Chinese card heading must frame the failed control"
    );
    assert!(
        !chinese.contains(&format!("<h3>{raw} <span class=\"finding-asset\">")),
        "the Chinese card heading must not print the unframed control name"
    );
}

/// What the other run cannot show: every detector reporting at once.
///
/// The mixed run spends five checks on terminal states, so Checkov, KICS,
/// Semgrep, TruffleHog and Nuclei never carry a finding into a report there --
/// and each of those five has a packaged mapping-catalog entry that nothing
/// else exercises end to end. A detector that cannot place its own finding on
/// its own control is wired up in name only.
#[test]
fn every_detector_places_its_finding_on_its_mapped_control() {
    all_engines_in_one_report(
        AssessmentIntent::InternalItEnvironment,
        AiGeneratedArtifactAnswer::No,
        EngineOutcomes::EveryDetectorReports,
        |subject| {
            let &AllEngineRun {
                engines,
                adapters,
                database,
                artifact_root,
                signing_key,
                case_id,
                scan_run_id,
                ..
            } = subject;
            let report = &subject.report;
            let reporting = report
                .findings
                .iter()
                .flat_map(|finding| &finding.evidence_references)
                .map(|reference| reference.engine_id.as_str())
                .collect::<BTreeSet<_>>();
            let silent = dispatchable_engine_ids(engines)
                .into_iter()
                .filter(|engine| {
                    !INVENTORY_ONLY_ENGINES.contains(engine) && !reporting.contains(engine)
                })
                .collect::<Vec<_>>();
            assert!(
                silent.is_empty(),
                "these checks ran and reported nothing a reader can see: {silent:?}"
            );
            let unfinished = report
                .actual
                .checks
                .iter()
                .filter(|check| check.status != CoverageDimensionStatus::TestedComplete)
                .map(|check| (check.check_id.clone(), check.status))
                .collect::<Vec<_>>();
            assert_eq!(
                unfinished,
                [("kube-bench".into(), CoverageDimensionStatus::TestedPartial)],
                "a successful process must not hide the fixture's WARN controls"
            );
            // What is left is coverage data, not unfinished execution: a
            // control upstream evaluated but left for a person to rule on,
            // what a cloud or Microsoft 365 check's fixed profile leaves out,
            // and the controls an engine said it did not evaluate.
            let unfinished_gaps = report
                .coverage_gaps
                .iter()
                .filter(|gap| {
                    !matches!(gap.kind, CoverageGapKind::ManualReview)
                        && !CLOUD_SCOPE_LIMIT_DIMENSIONS.contains(&gap.dimension.as_str())
                        && !gap.dimension.ends_with(": controls not evaluated")
                })
                .collect::<Vec<_>>();
            assert_eq!(unfinished_gaps.len(), 1, "{unfinished_gaps:#?}");
            assert_eq!(
                unfinished_gaps[0].dimension,
                "kube-bench: remaining requested dimensions"
            );
            let benchmark_gap = report
                .coverage_gaps
                .iter()
                .find(|gap| gap.dimension == "kube-bench: controls not evaluated")
                .expect("WARN controls must reach the terminal report");
            assert_eq!(benchmark_gap.kind, CoverageGapKind::NotTested);
            assert!(
                benchmark_gap
                    .reason
                    .contains("5 left without an automated verdict")
            );
            assert_eq!(benchmark_gap.next_action, "Check these controls by hand.");
            let scope_limits = report
                .coverage_gaps
                .iter()
                .filter(|gap| CLOUD_SCOPE_LIMIT_DIMENSIONS.contains(&gap.dimension.as_str()))
                .map(|gap| gap.dimension.as_str())
                .collect::<BTreeSet<_>>();
            assert_eq!(
                scope_limits,
                BTreeSet::from([
                    "AWS services other than IAM",
                    "Microsoft 365 products other than Entra ID"
                ]),
                "a clean cloud account or tenant must say what its check left out"
            );

            // Discovery still reports inventory rather than problems. A port
            // that answers is a target for a security check, not a result.
            assert!(
                report.inventory.total > 0,
                "the discovery checks recorded nothing"
            );
            for engine in INVENTORY_ONLY_ENGINES {
                assert!(
                    !reporting.contains(engine),
                    "{engine} is a discovery check and must not raise a problem"
                );
            }

            // The five coordinates the mixed run cannot reach. What each one
            // should land on is read out of the packaged catalog rather than
            // repeated here: the claim under test is that the entry shipped
            // for an engine and rule is the control the reader is shown, so
            // restating the control would only test this file against itself.
            // AIDEFEND coordinates are withheld from a case that declares no
            // AI system, which is this case, so they are not expected.
            let catalog = serde_json::from_slice::<serde_json::Value>(
                &fs::read(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .parent()
                        .expect("the crate sits inside the repository")
                        .join("mappings/control-mappings.json"),
                )
                .unwrap(),
            )
            .unwrap();
            let control_by_key = catalog["controls"]
                .as_array()
                .unwrap()
                .iter()
                .map(|control| {
                    (
                        control["key"].as_str().unwrap().to_owned(),
                        (
                            control["framework"].as_str().unwrap().to_owned(),
                            control["control_id"].as_str().unwrap().to_owned(),
                        ),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let packaged = |engine: &str, rule: &str| -> BTreeSet<String> {
                catalog["entries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|entry| entry["engine_id"] == engine && entry["source_rule"] == rule)
                        .unwrap_or_else(|| panic!("no packaged catalog entry for {engine} {rule}"))
                        ["controls"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|key| &control_by_key[key.as_str().unwrap()])
                        // This case declares no AI system, so the frameworks
                        // that only describe one are correctly withheld and are
                        // not part of what every detector must reach here.
                        .filter(|(framework, _)| {
                            framework != "AIDEFEND"
                                && framework != "OWASP Top 10 for LLM Applications"
                        })
                        .map(|(framework, control_id)| format!("{framework}/{control_id}"))
                        .collect()
            };

            let placed = report
                .findings
                .iter()
                .flat_map(|finding| {
                    finding.evidence_references.iter().map(move |reference| {
                        (
                            reference.engine_id.clone(),
                            reference.source_rule.clone().unwrap_or_default(),
                            finding
                                .framework_references
                                .iter()
                                .map(|control| {
                                    format!("{}/{}", control.framework, control.control_id)
                                })
                                .collect::<BTreeSet<_>>(),
                        )
                    })
                })
                .collect::<Vec<_>>();
            for (engine, rule) in [
                ("checkov", "CKV_AWS_18"),
                ("kics", "5fb49a69-8d46-4495-a2f8-9c8c622b2b6e"),
                ("semgrep", "ai-security-scanner.python.shell-true"),
                ("nuclei", "phpmyadmin-panel"),
            ] {
                let reached = placed
                    .iter()
                    .filter(|(placed_engine, placed_rule, _)| {
                        placed_engine == engine && placed_rule == rule
                    })
                    .flat_map(|(_, _, controls)| controls)
                    .cloned()
                    .collect::<BTreeSet<_>>();
                let expected = packaged(engine, rule);
                assert!(
                    expected.is_subset(&reached),
                    "{engine} rule {rule} reached {reached:?}, missing {:?}",
                    expected.difference(&reached).collect::<Vec<_>>()
                );
            }
            // TruffleHog's catalog entry matches by prefix, so its rule is
            // whatever detector fired rather than a fixed string.
            let secrets = packaged("trufflehog", "trufflehog:");
            assert!(
                placed
                    .iter()
                    .any(|(engine, rule, controls)| engine == "trufflehog"
                        && rule.starts_with("trufflehog:")
                        && secrets.is_subset(controls)),
                "TruffleHog placed no finding on {secrets:?}: {placed:#?}"
            );

            let reopened_storage = Storage::open(database).unwrap();
            let reopened_service = CaseService::new(
                &reopened_storage,
                engines,
                adapters,
                artifact_root,
                signing_key,
            );
            let export = |format, name, locale| {
                let path = artifact_root.join(name);
                reopened_service
                    .export_case(
                        case_id,
                        scan_run_id,
                        format,
                        path.clone(),
                        ExportOptions {
                            redaction: RedactionProfile::None,
                            include_raw_artifacts: false,
                            locale,
                        },
                    )
                    .unwrap();
                fs::read_to_string(&path).unwrap()
            };
            let english = export(
                CaseExportFormat::Html,
                "every-detector-en.html",
                ReportLocale::En,
            );
            let chinese = export(
                CaseExportFormat::Html,
                "every-detector-zh.html",
                ReportLocale::ZhHant,
            );
            assert_paragraphs_are_well_formed(&english, "the English report");
            assert_paragraphs_are_well_formed(&chinese, "the Chinese report");
            if let Some(offence) = ascii_clause_break_after_han(&strip_markup(&chinese)) {
                panic!("the Chinese report ends a clause as English: {offence}");
            }
            if let Some(offence) = ascii_label_colon_in_chinese(&strip_markup(&chinese)) {
                panic!("the Chinese report sets a label with an ASCII colon: {offence}");
            }
            if let Some(offence) = space_after_full_width_mark(&strip_markup(&chinese)) {
                panic!("the Chinese report puts a space after full-width punctuation: {offence}");
            }
            if let Some(offence) = retired_coordinate_word(&strip_markup(&chinese)) {
                panic!(
                    "the Chinese report kept the retired word for a framework reference: {offence}"
                );
            }
            assert!(!chinese.contains(":</strong>"));
            assert!(!chinese.contains(":</em>"));
            // Successful process exits still expose the benchmark WARN checks
            // in the coverage and next-step sections.
            assert!(english.contains("What needs attention"));
            assert!(english.contains("What to do next"));
            assert_uppercase_password_rule_keeps_its_severity_and_explains_a_lower_order(
                &english, &chinese,
            );
            assert_next_steps_distinguish_one_fix_from_the_same_kind_of_change(&english, &chinese);

            // The node's remaining checks need an asset-specific step, so its
            // action column is useful even when every process exited zero.
            let board = &english[english
                .find("<table class=\"asset-result-table\"")
                .expect("the asset board")..];
            let board = &board[..board.find("</section>").expect("the board ends")];
            assert!(
                board.contains("<th scope=\"col\">What to do next</th>"),
                "the node's remaining checks lost their action column"
            );
            assert!(
                board.contains(
                    "<td>Some checks are incomplete. Finish or retry them in the app.</td>"
                ),
                "the node must have a direct continuation: {board}"
            );
            assert!(board.contains("class=\"asset-result-steps\""), "{board}");

            // A coverage row's third field is composed the same way its name
            // is, and was the one field left in English: a Chinese reader saw
            // the launcher's "2 of 2" and Greenbone's
            // "applicability-driven upstream profile on asset ... across ...".
            // The mixed run has neither row, so only this run can see it.
            let tested_zh = &chinese[chinese
                .find(">實際測試的內容</h2>")
                .expect("the Chinese tested section")..];
            let tested_zh = &tested_zh[..tested_zh
                .find(">需要留意的內容</h2>")
                .expect("the gaps section follows")];
            for english in [
                "2 of 2",
                "applicability-driven upstream profile",
                " approved TCP ports",
            ] {
                assert!(
                    !tested_zh.contains(english),
                    "a Chinese coverage row measured in English: {english}"
                );
            }
            for translated in ["2 個中的 2 個", "依適用性選擇的上游設定檔"] {
                assert!(
                    tested_zh.contains(translated),
                    "the Chinese coverage row lost: {translated}"
                );
            }

            if let Some(dump) = std::env::var_os("AI_SCANNER_REPORT_DUMP_DIR").map(PathBuf::from) {
                let dump = dump.join("every-detector");
                fs::create_dir_all(&dump).unwrap();
                fs::write(dump.join("report-en.html"), &english).unwrap();
                fs::write(dump.join("report-zh.html"), &chinese).unwrap();
                fs::write(
                    dump.join("framework.json"),
                    export(
                        CaseExportFormat::FrameworkReport,
                        "every-detector-framework.json",
                        ReportLocale::En,
                    ),
                )
                .unwrap();
                fs::write(
                    dump.join("beginner-report.json"),
                    serde_json::to_string_pretty(report).unwrap(),
                )
                .unwrap();
            }
        },
    );
}

#[test]
fn every_integrated_engine_lands_in_one_terminal_report() {
    all_engines_in_one_report(
        AssessmentIntent::InternalItEnvironment,
        AiGeneratedArtifactAnswer::No,
        EngineOutcomes::MixedTerminalStates,
        |subject| {
            let &AllEngineRun {
                engines,
                adapters,
                database,
                artifact_root,
                signing_key,
                case_id,
                scan_run_id,
                ..
            } = subject;
            let (completed, report) = (&subject.completed, &subject.report);
            assert_eq!(
                report
                    .actual
                    .checks
                    .iter()
                    .map(|check| check.check_id.as_str())
                    .collect::<BTreeSet<_>>(),
                dispatchable_engine_ids(engines)
            );
            assert_eq!(
                report
                    .requested
                    .targets
                    .iter()
                    .map(|target| &target.asset_id)
                    .collect::<BTreeSet<_>>()
                    .len(),
                completed.assets.len(),
                "requested: {:?}; case assets: {:?}",
                report
                    .requested
                    .targets
                    .iter()
                    .map(|target| (&target.asset_id, &target.label))
                    .collect::<Vec<_>>(),
                completed
                    .assets
                    .iter()
                    .map(|asset| (&asset.id, &asset.name, &asset.kind))
                    .collect::<Vec<_>>()
            );
            let model_target = report
                .requested
                .targets
                .iter()
                .find(|target| target.asset_kind == Some(AssetKind::AiModelEndpoint))
                .expect("the exact model target must remain in the saved report");
            assert_eq!(
                model_target.label.as_deref(),
                Some("fixture/model (https://model.example.test:8443/v1/chat/completions)")
            );
            let model_findings = report
                .findings
                .iter()
                .filter(|finding| {
                    finding
                        .evidence_references
                        .iter()
                        .any(|reference| reference.engine_id == "garak")
                })
                .collect::<Vec<_>>();
            assert_eq!(
                model_findings.len(),
                4,
                "all four native failing probe/detector pairs must survive"
            );
            assert!(
                model_findings
                    .iter()
                    .all(|finding| finding.target_asset_ids.as_slice()
                        == [model_target.asset_id.clone()])
            );
            assert!(
                !serde_json::to_string(completed)
                    .unwrap()
                    .contains("synthetic-fixture-only-no-provider-access")
            );
            for (engine, status) in [
                ("nuclei", CoverageDimensionStatus::TestedPartial),
                ("semgrep", CoverageDimensionStatus::TestedComplete),
                ("checkov", CoverageDimensionStatus::Failed),
                ("kics", CoverageDimensionStatus::TimedOut),
                ("trufflehog", CoverageDimensionStatus::Cancelled),
            ] {
                assert_eq!(
                    report
                        .actual
                        .checks
                        .iter()
                        .find(|check| check.check_id == engine)
                        .unwrap()
                        .status,
                    status
                );
            }
            let inventory = ["syft", "cloudquery", "steampipe", "naabu", "httpx"];
            assert!(
                completed
                    .findings
                    .iter()
                    .flat_map(|finding| &finding.evidence)
                    .all(|evidence| !inventory.contains(&evidence.engine_id.as_str()))
            );
            assert!(report.inventory.items.iter().any(|item| matches!(
                item.details,
                BeginnerInventoryItemKind::SoftwareComponent { .. }
            )));
            assert!(
                report
                    .actual
                    .checks
                    .iter()
                    .any(|check| check.check_id == "gitleaks"
                        && check.status == CoverageDimensionStatus::TestedComplete)
            );
            assert!(
                report
                    .actual
                    .checks
                    .iter()
                    .any(|check| check.check_id == "trivy"
                        && check.status == CoverageDimensionStatus::TestedComplete)
            );
            assert!(
                completed
                    .scan_runs
                    .iter()
                    .find(|run| run.id == scan_run_id)
                    .unwrap()
                    .engine_runs
                    .iter()
                    .any(|run| run.status == EngineRunStatus::Completed)
            );

            // One instruction is listed once, however many findings name it. Every
            // finding still reaches the reader through exactly one step: nothing is
            // dropped by the merge, and nothing is counted twice.
            let mut step_findings = report
                .next_steps
                .iter()
                .filter_map(|step| step.finding_id.clone().map(|lead| (lead, step)))
                .flat_map(|(lead, step)| {
                    std::iter::once(lead).chain(step.also_resolves.iter().cloned())
                })
                .collect::<Vec<_>>();
            let listed = step_findings.len();
            step_findings.sort();
            step_findings.dedup();
            assert_eq!(
                listed,
                step_findings.len(),
                "a finding must be named by exactly one next step"
            );
            let mut actionable = report
                .findings
                .iter()
                .filter(|finding| {
                    !finding
                        .severity_basis_code
                        .is_some_and(|code| code.is_exposure_observation())
                })
                .map(|finding| finding.finding_id.clone())
                .collect::<Vec<_>>();
            actionable.sort();
            assert_eq!(
                step_findings, actionable,
                "every actionable finding reaches the reader through a next step"
            );
            let repeated = report
                .next_steps
                .iter()
                .filter(|step| !step.also_resolves.is_empty())
                .count();
            assert!(
                repeated > 0,
                "this run has findings that share a fix; the merge must be exercised"
            );
            assert!(
                report.next_steps.len() < actionable.len(),
                "{} steps for {} findings is the findings list printed twice",
                report.next_steps.len(),
                actionable.len()
            );

            // Two findings whose stored instruction is the same string are still two
            // instructions when the reader is sent to a different specialist, and a
            // Cloudsplaining step is composed from its typed policy record rather than
            // from that string at all. Merging on the stored text alone would collapse
            // both of these into one wrong sentence. Greenbone on this mixed run did
            // not produce observations, so its Vulnerability manager step is
            // confirm-first rather than the family remedy; Nuclei did, and keeps it.
            let correct_service = report
                .next_steps
                .iter()
                .filter(|step| {
                    step.action == "Correct the service or configuration named by this check."
                })
                .map(|step| step.recommended_expert_type.clone())
                .collect::<Vec<_>>();
            assert_eq!(
                correct_service,
                [Some("Application security engineer".to_string())],
                "a confirmed network-exposure finding keeps the family remedy"
            );
            assert!(
                report.next_steps.iter().any(|step| {
                    step.code == NextActionCode::ConfirmFindingAfterIncompleteCheck
                        && step.recommended_expert_type.as_deref()
                            == Some("Vulnerability manager")
                        && step.action
                            == ai_security_scanner_lib::finding_narrative::INCOMPLETE_CHECK_CONFIRM_ACTION
                }),
                "an incomplete Greenbone check must not tell the reader to correct a service"
            );
            let iam_policies = [
                "IAMFullAccess",
                "InlinePolicyForAdminGroup",
                "InsecurePolicy",
            ];
            for policy in iam_policies {
                let named = report
                    .next_steps
                    .iter()
                    .filter(|step| step.action.contains(policy))
                    .collect::<Vec<_>>();
                assert_eq!(
                    named.len(),
                    1,
                    "one step per IAM policy the reader has to change; {policy} has {}",
                    named.len()
                );
                assert!(
                    !named[0].also_resolves.is_empty(),
                    "{policy} is named by more than one finding"
                );
            }

            // CloudQuery's catalog records a knowledge date years before this
            // run. That date is provenance on the technical execution. It does
            // not open a coverage gap.
            let cloudquery_knowledge_date = subject
                .completed
                .scan_runs
                .iter()
                .find(|run| run.id == scan_run_id)
                .expect("the audited run")
                .engine_runs
                .iter()
                .find(|run| run.engine_id == "cloudquery")
                .expect("CloudQuery ran")
                .knowledge_input
                .as_ref()
                .and_then(|input| input.knowledge_date.clone())
                .expect("the CloudQuery fixture records a knowledge date");
            assert!(
                report.coverage_gaps.iter().all(|gap| {
                    let text = format!("{} {}", gap.dimension, gap.reason).to_ascii_lowercase();
                    !text.contains("expired knowledge")
                        && !text.contains("expired detection knowledge")
                        && !text.contains("support ended")
                        && !text.contains("stale-knowledge")
                }),
                "scanner age became a coverage gap: {:#?}",
                report
                    .coverage_gaps
                    .iter()
                    .filter(|gap| {
                        let text = format!("{} {}", gap.dimension, gap.reason).to_ascii_lowercase();
                        text.contains("expired")
                            || text.contains("knowledge")
                            || text.contains("support ended")
                            || text.contains("stale-knowledge")
                    })
                    .collect::<Vec<_>>()
            );
            let cloudquery_execution = report
                .technical_details
                .tasks
                .iter()
                .find_map(|task| match &task.execution {
                    TechnicalExecution::CatalogEngine {
                        engine_id,
                        knowledge_date,
                        ..
                    } if engine_id == "cloudquery" => Some(knowledge_date),
                    _ => None,
                })
                .expect("CloudQuery technical execution");
            assert_eq!(
                cloudquery_execution.as_deref(),
                Some(cloudquery_knowledge_date.as_str())
            );
            // The check still ran and its inventory is still reported.
            assert_eq!(
                report
                    .actual
                    .checks
                    .iter()
                    .find(|check| check.check_id == "cloudquery")
                    .unwrap()
                    .status,
                CoverageDimensionStatus::TestedComplete
            );

            let reopened_storage = Storage::open(database).unwrap();
            let reopened = reopened_storage.get_case(case_id).unwrap();
            assert_eq!(
                &build_beginner_master_report(&reopened, scan_run_id).unwrap(),
                report
            );
            let reopened_service = CaseService::new(
                &reopened_storage,
                engines,
                adapters,
                artifact_root,
                signing_key,
            );
            // Two vulnerability scanners cover the same repository and the same
            // image, so this run is the shape cross-engine correlation exists for:
            // Trivy and Grype both name CVE-2024-2511 on openssl. The suggestion is
            // the product's offer to combine them; nothing is merged without the
            // reader accepting it, and an unfired suggestion here would mean the
            // reader is never offered the choice on a run that plainly needs it.
            let correlations = ai_security_scanner_lib::correlation::correlation_report(completed);
            let openssl = correlations
                .suggestions
                .iter()
                .filter(|suggestion| suggestion.vulnerability_id == "CVE-2024-2511")
                .collect::<Vec<_>>();
            assert_eq!(
                openssl.len(),
                2,
                "one suggestion per asset the two scanners agree on: {:#?}",
                correlations
            );
            for suggestion in openssl {
                assert_eq!(suggestion.package, "openssl");
                assert_eq!(suggestion.engine_ids, ["grype", "trivy"]);
                assert_eq!(suggestion.finding_ids.len(), 2);
            }
            assert_eq!(correlations.truncated_suggestions, 0);

            // The heading promises the assets that need attention, so the list is
            // read as an order. Before it was one, this run put the asset carrying a
            // single problem first, the asset carrying twenty-two third, and the host
            // whose check failed in the middle of the healthy ones.
            let ordered_html = artifact_root.join("asset-order.html");
            reopened_service
                .export_case(
                    case_id,
                    scan_run_id,
                    CaseExportFormat::Html,
                    ordered_html.clone(),
                    ExportOptions {
                        redaction: RedactionProfile::None,
                        include_raw_artifacts: false,
                        locale: ReportLocale::En,
                    },
                )
                .unwrap();
            let ordered_html = fs::read_to_string(&ordered_html).unwrap();
            assert_paragraphs_are_well_formed(&ordered_html, "the English report");
            // The inventory sample prints addresses, not quantities. Digit
            // grouping turned this run's 8080 into "8,080", which is not a
            // port anyone can paste back into a tool.
            assert!(ordered_html.contains("port 8080"));
            assert!(!ordered_html.contains("port 8,080"));
            let asset_board = &ordered_html[ordered_html
                .find("Which assets need attention")
                .expect("asset board")..];
            let asset_board = &asset_board[..asset_board.find("</section>").expect("board end")];
            let leading_finding = &report.findings[0];
            let leading_asset = report
                .requested
                .targets
                .iter()
                .find(|target| leading_finding.target_asset_ids.contains(&target.asset_id))
                .and_then(|target| target.label.clone())
                .expect("the report's first problem is on a requested asset");
            let first_row = asset_board
                .find("<tr class=\"asset-result")
                .expect("at least one asset row");
            assert!(
                asset_board[first_row..].starts_with(&format!(
                    "<tr class=\"asset-result asset-result--problems-found\">\
                     <th scope=\"row\" class=\"asset-result__identity\">\
                     <strong>{leading_asset}</strong>"
                )),
                "the asset carrying the report's first problem leads the board"
            );
            let last_problem = asset_board
                .rfind("asset-result--problems-found")
                .expect("a problems row");
            let first_incomplete = asset_board
                .find("asset-result--incomplete-failed")
                .expect("an incomplete row");
            assert!(
                last_problem < first_incomplete,
                "every asset with a found problem is read before the ones with none"
            );

            // What this product retained about how it knows is kept, and kept out of
            // the way. On this run those two blocks were 57% of everything printed
            // under "Problems found" -- artifact and engine-run identifiers, capture
            // hashes, and the same catalog rationale repeated once per reference --
            // read before the reader reached the next problem.
            let problems = &ordered_html[ordered_html
                .find(">Problems found</h2>")
                .expect("problems section")..];
            // Bounded before the inventory and framework context that follow the
            // problems, and before the run-level technical section, whose task
            // records are articles too.
            let problems_end = [
                "<section><h2>Inventory observations</h2>",
                "<section class=\"framework-coverage\"",
                "<details class=\"technical\">",
            ]
            .iter()
            .filter_map(|marker| problems.find(marker))
            .min()
            .expect("technical details follow the problems");
            let problems = &problems[..problems_end];
            // Every card is anchored so the index above can point at it.
            let cards = problems.match_indices("<article id=\"f").count();
            assert_eq!(cards, report.findings.len(), "one card per finding");
            assert_eq!(
                problems
                    .match_indices("<details class=\"technical finding-technical\">")
                    .count(),
                cards,
                "every card keeps its evidence and framework provenance collapsed"
            );
            // The report cites twenty-one third-party projects by name. Humanizing
            // their identifiers named five of them something their own documentation
            // does not use, and split one on its hyphen.
            let tested = &ordered_html[ordered_html
                .find(">What was actually tested</h2>")
                .expect("tested section")..];
            let tested = &tested[..tested
                .find(">What needs attention</h2>")
                .expect("gaps follow")];
            // Scoped to this section only for the coordinate wording. The
            // names themselves are checked across the whole report below,
            // because the coverage grid was title-casing its column headings
            // long after this section stopped.
            assert!(
                !tested.contains("Completed check To Target"),
                "the report humanized a coordinate identifier"
            );
            for wrong in [
                "Httpx",
                "Kics",
                "Kube Bench",
                "Scoutsuite",
                "Scubagear",
                "Trufflehog",
                "Cloudquery",
            ] {
                assert!(
                    !ordered_html.contains(wrong),
                    "the report printed a humanized identifier: {wrong}"
                );
            }
            for right in [
                "httpx",
                "KICS",
                "kube-bench",
                "ScoutSuite",
                "ScubaGear",
                "TruffleHog",
                "CloudQuery",
            ] {
                assert!(tested.contains(right), "the report lost a name: {right}");
            }

            // A completed check's coarse coordinate restated its own header line and
            // added a sentence about this product's record keeping. Eighteen of them
            // were a third of this section.
            for restated in [
                "check-to-target coordinate",
                "The durable task reached completed state for this target binding.",
            ] {
                assert!(
                    !tested.contains(restated),
                    "a completed check restates its header: {restated}"
                );
            }
            // Each run is one row now: the check names itself, the state and the
            // targets sit in their own columns, and the window is the last two.
            // The header also names the scanner version and its last-updated date.
            // A run that retained dimension detail keeps it in a row beneath.
            let syft_check = report
                .actual
                .checks
                .iter()
                .find(|check| check.check_id == "syft")
                .expect("Syft check");
            let (syft_version, syft_knowledge_date) = report
                .technical_details
                .tasks
                .iter()
                .find_map(|task| match &task.execution {
                    TechnicalExecution::CatalogEngine {
                        engine_version,
                        knowledge_date,
                        ..
                    } if task.task_id == syft_check.task_id => {
                        Some((engine_version.as_deref(), knowledge_date.as_deref()))
                    }
                    _ => None,
                })
                .expect("Syft technical execution");
            let (Some(syft_version), Some(syft_knowledge_date)) =
                (syft_version, syft_knowledge_date)
            else {
                panic!(
                    "Syft recorded version {syft_version:?} and knowledge date {syft_knowledge_date:?}"
                );
            };
            assert!(
                tested.contains(&format!(
                    "<tr><th scope=\"row\">Syft<br><small>Version {syft_version} · last updated {syft_knowledge_date}</small></th><td class=\"tested-state\">Completed</td>"
                )),
                "a completed run lost its row"
            );
            assert!(
                tested.contains("<tr class=\"tested-detail\"><td colspan=\"5\">"),
                "a run that proved dimensions of its own lost them"
            );
            // A scanner built from pinned source shows the release its binary
            // reports and a short commit here. The full source@ pin stays in
            // the technical detail.
            let source_scanners = [
                ("trufflehog", "TruffleHog"),
                ("kube-bench", "kube-bench"),
                ("semgrep", "Semgrep"),
            ];
            let mut source_rows = Vec::new();
            for (engine_id, display) in source_scanners {
                let manifest = engines.get(engine_id).expect("catalog source scanner");
                let reported = manifest
                    .reported_version
                    .as_deref()
                    .expect("reported version");
                let commit = manifest
                    .source_revision
                    .as_deref()
                    .expect("source revision");
                let check = report
                    .actual
                    .checks
                    .iter()
                    .find(|check| check.check_id == engine_id)
                    .unwrap_or_else(|| panic!("{display} check"));
                let (engine_version, reported_version, knowledge_date) = report
                    .technical_details
                    .tasks
                    .iter()
                    .find_map(|task| match &task.execution {
                        TechnicalExecution::CatalogEngine {
                            engine_version,
                            reported_version,
                            knowledge_date,
                            ..
                        } if task.task_id == check.task_id => {
                            Some((engine_version, reported_version, knowledge_date))
                        }
                        _ => None,
                    })
                    .unwrap_or_else(|| panic!("{display} technical execution"));
                let pinned = format!("source@{commit}");
                assert_eq!(
                    engine_version.as_deref(),
                    Some(pinned.as_str()),
                    "{display} engine version"
                );
                assert_eq!(
                    reported_version.as_deref(),
                    Some(reported),
                    "{display} reported version"
                );
                let knowledge_date = knowledge_date
                    .as_deref()
                    .unwrap_or_else(|| panic!("{display} knowledge date"));
                assert_eq!(
                    knowledge_date, manifest.compatibility.knowledge_date,
                    "{display} knowledge date"
                );
                let short_commit = &commit[..7];
                let short_en = format!("{reported} (source {short_commit})");
                let exact_en = format!("{reported} (source@{commit})");
                let row = format!(
                    "<tr><th scope=\"row\">{display}<br><small>Version {short_en} · last updated {knowledge_date}</small></th>"
                );
                assert!(
                    tested.contains(&row),
                    "{display} first-layer row lost the short source label: {row}"
                );
                assert!(
                    !tested.contains(&format!("Version source@{commit}")),
                    "{display} first-layer row still shows the raw source pin"
                );
                assert!(
                    ordered_html.contains(&format!("engine version {exact_en}")),
                    "{display} technical detail lost the exact source label"
                );
                source_rows.push((
                    display,
                    format!(
                        "<tr><th scope=\"row\">{display}<br><small>版本 {reported}（source {short_commit}） · 最後更新 {knowledge_date}</small></th>"
                    ),
                    format!("引擎版本 {reported}（source@{commit}）"),
                ));
            }

            // The same rule, in the one other place the report composes a name
            // around an identifier. This list named six scanners differently
            // from the "Requested checks" list two headings above it, and
            // title-cased the reader's own target into "Https://...".
            // To the close that balances the list, not the first </ul>: the
            // list nests one level now, so the first close is a source
            // group's, not its own.
            let limits = &ordered_html[ordered_html.find(">Limits</h3>").expect("limits")..];
            let mut nesting = limits
                .match_indices("<ul>")
                .map(|(at, _)| (at, 1i32))
                .chain(limits.match_indices("</ul>").map(|(at, _)| (at, -1i32)))
                .collect::<Vec<_>>();
            nesting.sort_by_key(|(at, _)| *at);
            let mut depth = 0i32;
            let limits_end = nesting
                .into_iter()
                .find_map(|(at, step)| {
                    depth += step;
                    (depth == 0).then_some(at + "</ul>".len())
                })
                .expect("the limits list closes");
            let limits = &limits[..limits_end];
            for wrong in [
                "Httpx",
                "Kics",
                "Kube Bench",
                "Scoutsuite",
                "Scubagear",
                "Trufflehog",
                "Cloudquery",
                "Https://",
            ] {
                assert!(
                    !limits.contains(wrong),
                    "the limits list humanized an identifier: {wrong}"
                );
            }
            // Twenty-two engines shared one execution timeout and the list
            // printed it once per engine. A limit is a policy and who it
            // covers: forty-one lines carried twelve distinct policies.
            for right in [
                "<strong>Execution timeout:</strong> 600 seconds",
                "<strong>Execution timeout:</strong> 900 seconds",
                "<strong>Execution timeout:</strong> 1800 seconds",
                "<strong>Execution timeout:</strong> 3600 seconds",
                "Checkov, CloudQuery, Cloudsplaining, Gitleaks, Grype, KICS, kube-bench",
                "<strong>Execution timeout:</strong> 7200 seconds",
                "Greenbone Community Edition, httpx, Nuclei",
                "<strong>Execution timeout:</strong> 14461 seconds",
                "<strong>Approved ports:</strong> 443,8443",
                "<strong>Approved ports:</strong> 443 \u{2014}",
            ] {
                assert!(limits.contains(right), "the limits list lost: {right}");
            }
            assert_eq!(
                limits.matches("Execution timeout:").count(),
                6,
                "one execution timeout per distinct value, not per engine"
            );
            // Where a limit came from is a property of the grant, and it was
            // printed on all twelve lines to say one of two things.
            for source in ["saved scope approval", "saved task settings"] {
                assert_eq!(
                    limits.matches(source).count(),
                    1,
                    "the limits list repeats where a limit came from"
                );
                assert!(
                    limits.contains(&format!("<strong>From the {source}</strong><ul>")),
                    "the limits under {source} are not gathered under it"
                );
            }
            // Grouped by policy but ordered by arrival, one asset's authorized
            // target sat past the request rates. Like policies read together,
            // inside the source they came from.
            let mut subjects_seen = 0usize;
            for group in limits.split("</strong><ul>").skip(1) {
                let group = &group[..group.find("</ul>").expect("a source group closes")];
                let subjects = group
                    .match_indices("</strong>")
                    .map(|(at, _)| group[..at].rfind("<strong>").expect("a label opens"))
                    .map(|at| {
                        group[at..]
                            .split_once("</strong>")
                            .expect("a label closes")
                            .0
                    })
                    .collect::<Vec<_>>();
                let mut seen: Vec<&str> = Vec::new();
                for subject in &subjects {
                    if seen.last() != Some(subject) {
                        assert!(
                            !seen.contains(subject),
                            "the limits list returns to {subject} after leaving it"
                        );
                        seen.push(subject);
                    }
                }
                subjects_seen += seen.len();
            }
            assert!(subjects_seen >= 5, "the audit lost the limit subjects");
            // ZAP and Garak each retain their distinct rate, port, profile and timeout bounds.
            assert!(
                limits.matches("<li>").count() - limits.matches("<strong>From the ").count() <= 21,
                "the limits list is repeating a policy per holder"
            );
            // A limit that names itself needs no holder after it.
            assert!(
                !limits.contains("203.0.113.11 \u{2014} 203.0.113.11"),
                "an authorized network target printed its own name twice"
            );

            // Every remediable finding carries the same product-authored safety
            // sentence, so the report printed the same 115 characters forty-five
            // times. It is advice about making any change, not about one finding.
            assert_eq!(ordered_html.matches("Before changing anything").count(), 1);

            // The coverage rows and the action list sit next to each other, and
            // every gap-derived step used to restate its row's own sentence --
            // a quarter of the section, and five of the nine said "this check"
            // without saying which. Each now names the coverage it closes.
            let steps = &ordered_html[ordered_html
                .find(">What to do next</h2>")
                .expect("next-step section")..];
            let steps = &steps[..steps.find(">Problems found</h2>").expect("problems follow")];
            for restated in [
                "This check failed, so it cannot be shown as tested.",
                "Host response unavailable. Vulnerability checks did not complete.",
                "The bounded check reached its time limit, so it cannot be treated as tested complete.",
                "This check was cancelled before completed coverage was recorded.",
                "This check did not reach a confirmed complete result.",
                "This run did not retain an exact reduction record.",
                "Maester evaluated this control but did not return a pass or fail verdict.",
            ] {
                assert!(
                    !steps.contains(restated),
                    "a step restates the coverage row above it: {restated}"
                );
            }
            for named in [
                "Retry this check.</strong> — Checkov · Repository</li>",
                "Confirm the host is powered on and reachable from this computer on the approved ports, then run this check again.</strong> — Greenbone Community Edition: target response",
                "Retry the timed-out work.</strong> — KICS · Repository <em>",
                "Retry this check for a confirmed result.</strong> — kube-bench: unfinished part · Kubernetes node; Nuclei: unfinished part · https://portal.example.test:443</li>",
                "Check these controls by hand.</strong> — kube-bench: controls not evaluated · Kubernetes node; Maester: controls not evaluated · Audit tenant</li>",
                // One step closes two rows, and says so rather than showing one
                // of the two reasons and dropping the other.
                "Retry this check to complete the missing coverage.</strong> — Naabu · 203.0.113.11; TruffleHog · Repository</li>",
                "Rerun the scan to create a fully frozen result.</strong> — Automatic scope reductions or truncations; Requested scan stage",
            ] {
                assert!(
                    steps.contains(named),
                    "a step lost its coverage name: {named}\n{steps}"
                );
            }
            for absent in ["expired knowledge", "Support ended", "stale-knowledge"] {
                assert!(
                    !ordered_html.contains(absent),
                    "the English report still treats scanner age as expiry: {absent}"
                );
            }
            assert!(
                ordered_html.contains(&format!("last updated {cloudquery_knowledge_date}")),
                "the English report omitted CloudQuery's last-updated date"
            );
            assert!(
                ordered_html.find("Before changing anything")
                    < ordered_html.find(">Problems found</h2>")
            );

            // One attached principal is the ordinary shape of a customer-managed
            // policy, and the sentence had been written only for a list.
            assert!(steps.contains(
                "Narrow customer-managed policy InsecurePolicy and verify that user ExampleUser retains only the permissions they need."
            ));

            // The Chinese report composes its coverage names from the engine's
            // id, so the same scanner was "Checkov" in the tested-checks list
            // and "checkov" in the limits, coverage rows and next steps two
            // sections below. A reader cannot tell whether that is one tool.
            let zh_path = artifact_root.join("asset-order-zh.html");
            reopened_service
                .export_case(
                    case_id,
                    scan_run_id,
                    CaseExportFormat::Html,
                    zh_path.clone(),
                    ExportOptions {
                        redaction: RedactionProfile::None,
                        include_raw_artifacts: false,
                        locale: ReportLocale::ZhHant,
                    },
                )
                .unwrap();
            let zh_html = fs::read_to_string(&zh_path).unwrap();
            assert_paragraphs_are_well_formed(&zh_html, "the Chinese report");
            for named in [
                "<strong>來自已保存的工作設定</strong><ul>",
                "<strong>檢查逾時限制：</strong>3600 秒；適用於 Checkov、CloudQuery",
                "<strong>檢查逾時限制：</strong>7200 秒；適用於 Greenbone Community Edition、httpx、Nuclei",
                "KICS、kube-bench",
                "ScoutSuite、ScubaGear",
                "Trivy、TruffleHog",
                "Checkov 檢查",
                "Greenbone Community Edition 的目標回應",
                "KICS 檢查",
                "Naabu 檢查",
                "TruffleHog 檢查",
                "Nuclei 未完成的部分",
                "Maester：未回傳判定的控制項 MT.1003",
            ] {
                assert!(
                    zh_html.contains(named),
                    "the Chinese report lost a scanner's name: {named}"
                );
            }
            for absent in [
                "expired knowledge",
                "Support ended",
                "stale-knowledge",
                "已過期的偵測知識",
                "過時知識",
                "支援結束日期",
            ] {
                assert!(
                    !zh_html.contains(absent),
                    "the Chinese report still treats scanner age as expiry: {absent}"
                );
            }
            assert!(
                zh_html.contains(&format!("最後更新 {cloudquery_knowledge_date}")),
                "the Chinese report omitted CloudQuery's last-updated date"
            );
            for (display, row, exact) in &source_rows {
                assert!(
                    zh_html.contains(row),
                    "{display} Chinese first-layer row lost the short source label: {row}"
                );
                assert!(
                    zh_html.contains(exact),
                    "{display} Chinese technical detail lost the exact source label: {exact}"
                );
            }
            // The deepest technical block is the report's provenance, not a
            // dumping ground: its headings were translated while the values
            // under them stayed in English. A Chinese reader saw "證據類型:
            // Configuration", "散布方式 Pull Pinned Image", a partly finished
            // run labelled "Partially Completed" beside "已完成" siblings, and
            // one English sentence between two translated ones.
            for translated in [
                "設定",
                "套件盤點",
                "外部驗證",
                "原始碼",
                "拉取已釘選映像",
                "部分完成",
                "本輪的診斷紀錄無法取得；已遮蔽的診斷匯出為獨立檔案。",
            ] {
                assert!(
                    zh_html.contains(translated),
                    "the Chinese report lost a technical value: {translated}"
                );
            }
            for stored_english in [
                "Configuration<",
                "Package Inventory",
                "External Validation",
                "Pull Pinned Image",
                "Partially Completed",
                "Run-bound diagnostic log",
                // The reason a framework reported nothing. The exporter pairs
                // this sentence with the state identifier and writes both to
                // the canonical JSON in English; the report has to translate
                // it like any other sentence it shows a reader.
                "so references to frameworks that only describe AI systems",
            ] {
                assert!(
                    !zh_html.contains(stored_english),
                    "the Chinese report printed a technical value in English: {stored_english}"
                );
            }
            // The same values stay in English where English is the report.
            for kept in [
                "Package Inventory",
                "Pull Pinned Image",
                "Partially Completed",
                "Run-bound diagnostic log: unavailable. Redacted diagnostic export: separate.",
            ] {
                assert!(
                    ordered_html.contains(kept),
                    "the English report lost: {kept}"
                );
            }

            // The state pill used to be followed by a sentence naming the
            // state again, and the only thing the sentence added was a count
            // the severity mix beside it already spells out.
            let board = &ordered_html[ordered_html
                .find("<table class=\"asset-result-table\"")
                .expect("the asset board")..];
            let board = &board[..board.find("</section>").expect("the board ends")];
            for twin in [
                "Problems found: ",
                "1 problem was found.",
                "No completed security check",
            ] {
                assert!(
                    !board.contains(twin),
                    "the asset board restated a pill it had already printed: {twin}"
                );
            }

            // The step a state implies is the same step on every row in that
            // state. It is said once, under the table, and only for the
            // states whose rows actually fell back to it: this run's failed
            // asset has a step of its own, so its state is not named here.
            let steps = board
                .split("class=\"asset-result-steps\">")
                .nth(1)
                .and_then(|rest| rest.split("</p>").next())
                .expect("the state steps");
            // This board has its own "What to do next" column, so the shared
            // line only speaks for the rows that left that column blank.
            assert!(
                steps.starts_with("For rows without their own next step: "),
                "{steps}"
            );
            assert!(steps.contains("Problems found"), "{steps}");
            assert!(
                !steps.contains("Incomplete or failed"),
                "a state whose rows all had their own step was named anyway: {steps}"
            );
            assert_eq!(
                board.matches("highest-priority problem first").count(),
                1,
                "the step a state implies was printed more than once"
            );

            // A row keeps what is its own: the step its coverage gap calls
            // for, and the note that some of its checks did not finish. The
            // column exists because those rows exist. The cancelled host's
            // recorded step names the missing coverage and the check it
            // retries; the action code does not replace it with one sentence
            // shared by every retry.
            assert!(
                board.contains("<th scope=\"col\">What to do next</th>"),
                "{board}"
            );
            assert!(
                board.contains(
                    "<td>Retry this check to complete the missing coverage (Naabu).</td>"
                ),
                "{board}"
            );
            assert!(!board.contains("Retry this check."));
            assert!(board.contains("Some checks are incomplete."));
            assert!(
                board.contains("Some checks are incomplete. Finish or retry them in the app."),
                "{board}"
            );
            let zh_board = &zh_html[zh_html
                .find("<table class=\"asset-result-table\"")
                .expect("the Chinese asset board")..];
            let zh_board = &zh_board[..zh_board.find("</section>").expect("the board ends")];
            assert!(
                zh_board.contains("<td>重新執行這項檢查以完成缺少的涵蓋範圍（Naabu 檢查）。</td>"),
                "{zh_board}"
            );
            assert!(!zh_board.contains("重試這項檢查。"));
            assert!(
                zh_board.contains("另有檢查尚未完成；請在應用程式中完成或重試。"),
                "{zh_board}"
            );
            for html in [&ordered_html, &zh_html] {
                assert!(
                    !html.contains("Review scanner status"),
                    "the exported report names a desktop-only control"
                );
                assert!(
                    !html.contains("查看掃描工具狀態"),
                    "the exported report names a desktop-only control"
                );
            }

            // Two frameworks put out of scope for the same reason share one
            // line. Given a bordered block each they printed the same sentence
            // twice in a row, under two headings that the overview table one
            // screen above had already named and scored.
            for html in [&ordered_html, &zh_html] {
                assert_eq!(
                    html.matches("class=\"framework-quiet\"").count(),
                    1,
                    "frameworks skipped for one reason did not share one line"
                );
            }
            for (html, both) in [
                (
                    &ordered_html,
                    [
                        "AIDEFEND version",
                        "OWASP Top 10 for LLM Applications version",
                    ],
                ),
                (
                    &zh_html,
                    ["AIDEFEND 版本", "OWASP Top 10 for LLM Applications 版本"],
                ),
            ] {
                let line = html
                    .split("class=\"framework-quiet\">")
                    .nth(1)
                    .and_then(|rest| rest.split("</p>").next())
                    .expect("a shared out-of-scope line");
                for named in both {
                    assert!(
                        line.contains(named),
                        "the shared line dropped {named}: {line}"
                    );
                }
            }

            // A scanner's name is the same string in both reports. The
            // coverage grid title-cased its column headings, so the Chinese
            // report named seven engines one way in the grid and another way
            // three sections later.
            for wrong in [
                "Httpx",
                "Kics",
                "Kube Bench",
                "Scoutsuite",
                "Scubagear",
                "Trufflehog",
                "Cloudquery",
            ] {
                assert!(
                    !zh_html.contains(wrong),
                    "the Chinese report printed a humanized identifier: {wrong}"
                );
            }
            for right in ["httpx", "KICS", "kube-bench", "ScoutSuite", "TruffleHog"] {
                assert!(
                    zh_html.contains(right),
                    "the Chinese report lost a scanner name: {right}"
                );
            }

            // Two kinds of name sit in the same column. The NIST and ISO rows
            // carry this project's own short names for a coordinate, not the
            // standards' wording, and those were printing in English beside
            // Chinese counts. The owners' published names, and the titles
            // kube-bench itself reports, stay as they were written.
            for translated in ["弱點的辨識與記錄", "技術性弱點的處理"] {
                assert!(
                    zh_html.contains(translated),
                    "the Chinese report kept a project-authored control name in English: \
                     {translated}"
                );
            }
            for owner_named in [
                "Vulnerable and Outdated Components",
                "Ensure that the --anonymous-auth argument is set to false",
            ] {
                assert!(
                    zh_html.contains(owner_named),
                    "the Chinese report translated a name its owner published: {owner_named}"
                );
            }

            // Attribution is four sentences per framework and they are not one
            // kind of sentence. The citation, the copyright line and the
            // licence name are the attribution of record and stay as the
            // licensor wrote them. What this product selected, changed, and is
            // not endorsed by are its own sentences, and a Chinese reader had
            // been getting all four in English.
            let zh_sources = zh_html
                .split("class=\"framework-block framework-sources\"")
                .nth(1)
                .and_then(|rest| rest.split("</article>").next())
                .expect("the Chinese framework sources block");
            for product_sentence in [
                "has not reviewed or endorsed this report or integration",
                "project-authored navigation metadata",
                "are referenced nominatively",
                "remains subject to",
                "is not affiliated with, approved, certified, sponsored, or endorsed",
                "as the pinned kube-bench image reports them",
                "publishes in its own CIS 3.0 compliance file",
            ] {
                assert!(
                    !zh_sources.contains(product_sentence),
                    "the Chinese attribution kept this product's own sentence in English: \
                     {product_sentence}"
                );
            }
            for of_record in [
                "NIST Cybersecurity Framework (CSF) 2.0, National Institute of Standards",
                "AIDEFEND AI Defense Framework, created by Edward Lee",
                "Creative Commons Attribution 4.0 International",
                "Creative Commons Attribution-ShareAlike 4.0 International",
                "Copyright (c) 2003-2025 The OWASP Foundation, Inc.",
            ] {
                assert!(
                    zh_sources.contains(of_record),
                    "the Chinese attribution translated the attribution of record: {of_record}"
                );
            }
            for translated in [
                "未審閱或背書本報告與本整合",
                "屬於導覽用的中繼資料",
                "以指名方式引用",
                "本報告不是該基準的複本",
            ] {
                assert!(
                    zh_sources.contains(translated),
                    "the Chinese attribution lost: {translated}"
                );
            }

            // A Chinese clause does not end with an ASCII full stop, comma or
            // semicolon. The footer set "遮蔽設定: 無." that way and joined the
            // next Chinese sentence with a space, beside a sibling clause
            // already using "：" and "；".
            if let Some(offence) = ascii_clause_break_after_han(&strip_markup(&zh_html)) {
                panic!("the Chinese report ends a clause as English: {offence}");
            }
            if let Some(offence) = ascii_label_colon_in_chinese(&strip_markup(&zh_html)) {
                panic!("the Chinese report sets a label with an ASCII colon: {offence}");
            }
            if let Some(offence) = space_after_full_width_mark(&strip_markup(&zh_html)) {
                panic!("the Chinese report puts a space after full-width punctuation: {offence}");
            }
            if let Some(offence) = retired_coordinate_word(&strip_markup(&zh_html)) {
                panic!(
                    "the Chinese report kept the retired word for a framework reference: {offence}"
                );
            }
            assert!(!zh_html.contains(":</strong>"));
            assert!(!zh_html.contains(":</em>"));

            for spelled_two_ways in [
                "（checkov）",
                "（cloudquery）",
                "（greenbone）",
                "（kics）",
                "（scoutsuite）",
                "（trufflehog）",
                "checkov 的",
                "greenbone 的",
                "kics 的",
                "naabu 的",
                "trufflehog 的",
                "cloudquery 的",
                "nuclei 的",
                "maester：",
            ] {
                assert!(
                    !zh_html.contains(spelled_two_ways),
                    "the Chinese report named a scanner by its id: {spelled_two_ways}"
                );
            }

            // The redacted export is the copy that leaves this machine. Every
            // value it removes has to say it was removed: a cloud resource
            // whose native ID was dropped to nothing printed one line reading
            // "Resource type aws_iam_users", which a recipient reads as an
            // observation that recorded nothing else.
            let redacted_path = artifact_root.join("asset-order-redacted.html");
            reopened_service
                .export_case(
                    case_id,
                    scan_run_id,
                    CaseExportFormat::Html,
                    redacted_path.clone(),
                    ExportOptions {
                        redaction: RedactionProfile::Standard,
                        include_raw_artifacts: false,
                        locale: ReportLocale::En,
                    },
                )
                .unwrap();
            let redacted_html = fs::read_to_string(&redacted_path).unwrap();
            for removed in [
                "192.0.2.11",
                "arn:aws:iam::123456789012:user/alice",
                "pkg:deb/debian/example-package@1.0",
                "example-user",
            ] {
                assert!(
                    ordered_html.contains(removed),
                    "the run no longer carries {removed}; this gate proves nothing"
                );
                assert!(
                    !redacted_html.contains(removed),
                    "the redacted report kept {removed}"
                );
            }
            for marker in [
                "[redacted service endpoint]",
                "[redacted software component]",
                "[redacted version]",
                "[redacted purl]",
                "[redacted native ID]",
                "[redacted display name]",
                "[redacted inventory pointer]",
            ] {
                assert!(
                    redacted_html.contains(marker),
                    "the redacted report dropped a value silently: {marker}"
                );
                assert!(
                    !ordered_html.contains(marker),
                    "the unredacted report marked a value redacted: {marker}"
                );
            }

            // A compliance reader scans a control list by its own numbering.
            // Ordering the identifiers as text put A.8.20 and A.8.24 between
            // A.8.2 and A.8.6.
            let framework_path = artifact_root.join("asset-order-framework.json");
            reopened_service
                .export_case(
                    case_id,
                    scan_run_id,
                    CaseExportFormat::FrameworkReport,
                    framework_path.clone(),
                    ExportOptions {
                        redaction: RedactionProfile::None,
                        include_raw_artifacts: false,
                        locale: ReportLocale::En,
                    },
                )
                .unwrap();
            let framework: serde_json::Value =
                serde_json::from_slice(&fs::read(&framework_path).unwrap()).unwrap();
            let iso = framework["frameworks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["framework"] == "ISO/IEC 27001")
                .expect("this run places findings on ISO/IEC 27001")
                .clone();
            let iso_controls = iso["controls"]
                .as_array()
                .unwrap()
                .iter()
                .map(|control| control["control_id"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                iso_controls,
                [
                    "A.5.15", "A.5.17", "A.5.18", "A.5.23", "A.8.2", "A.8.6", "A.8.8", "A.8.9",
                    "A.8.20", "A.8.24",
                ]
            );

            // Two scanners find the same CVE on the repository and on the image built
            // from it. The cards are titled identically by upstream, so with the asset
            // four items into the identifier line the reader sees the same heading
            // twice in a row and reads it as the report duplicating one problem.
            // Presentation groups can move originals into related-check
            // details. Verify every original by its durable anchor, rather
            // than treating group headings as additional scanner findings.
            let headings = report
                .findings
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    let anchor = format!("<article id=\"f{}\">", index + 1);
                    let card = &problems[problems.find(&anchor).expect("original finding card")..];
                    let rest = &card[card.find("<h3>").expect("original heading") + "<h3>".len()..];
                    rest[..rest.find("</h3>").expect("heading end")].to_owned()
                })
                .collect::<Vec<_>>();
            assert_eq!(headings.len(), cards);
            let mut by_heading = BTreeMap::new();
            for (heading, finding) in headings.iter().zip(&report.findings) {
                by_heading
                    .entry(heading)
                    .or_insert_with(Vec::new)
                    .push(finding);
            }
            for (heading, findings) in by_heading {
                if findings.len() < 2 {
                    continue;
                }
                // ZAP preserves each page affected by an upstream alert. A rule
                // can therefore have the same title and website asset, while
                // its retained page location distinguishes the original finding.
                let mut locations = BTreeSet::new();
                for finding in &findings {
                    assert_eq!(finding.evidence_references.len(), 1, "{heading}");
                    let evidence = &finding.evidence_references[0];
                    assert_eq!(evidence.engine_id, "zap", "{heading}");
                    assert!(evidence.source_rule.is_some(), "{heading}");
                    assert!(evidence.location.is_some(), "{heading}");
                    locations.insert((&evidence.source_rule, &evidence.location));
                }
                assert_eq!(locations.len(), findings.len(), "{heading}");
            }
            for (heading, finding) in headings.iter().zip(&report.findings) {
                assert!(
                    heading.contains("<span class=\"finding-asset\">"),
                    "every heading names the asset it is on: {heading}"
                );
                let (title, asset) = heading
                    .split_once(" <span class=\"finding-asset\">")
                    .expect("heading end");
                // A Microsoft 365 control is titled for the state it was
                // checking, so a failed one is framed as an unmet requirement.
                // Every heading keeps the whole upstream title.
                assert_eq!(
                    title
                        .replace("&amp;", "&")
                        .replace("&lt;", "<")
                        .replace("&gt;", ">")
                        .replace("&quot;", "\"")
                        .replace("&#39;", "'"),
                    ai_security_scanner_lib::finding_narrative::finding_headline_english(
                        &finding.title,
                        finding.family,
                    ),
                    "the upstream title still leads, unchanged apart from the Microsoft 365 frame"
                );
                assert!(asset.starts_with("— "), "{asset}");
            }

            let grype_impact =
                "Grype reported a critical-severity condition on the assessed asset.";
            let grype_impact_at = problems.find(grype_impact).expect("Grype finding impact");
            let grype_card_at = problems[..grype_impact_at]
                .rfind("<article id=\"f")
                .expect("Grype finding card");
            let grype_finding_index = problems[grype_card_at + "<article id=\"f".len()..]
                .split('"')
                .next()
                .expect("original finding ordinal")
                .parse::<usize>()
                .unwrap()
                - 1;
            let grype_finding = &report.findings[grype_finding_index];
            assert!(
                !grype_finding.target_asset_ids.is_empty()
                    && grype_finding.target_asset_ids.iter().all(|asset_id| {
                        completed.assets.iter().any(|asset| {
                            asset.id == *asset_id
                                && matches!(
                                    asset.kind,
                                    AssetKind::ContainerImage | AssetKind::ContainerRegistry
                                )
                        })
                    }),
                "this Grype card must belong to a container asset"
            );
            let grype_card = &problems[grype_card_at..];
            let grype_card = &grype_card[..grype_card.find("</article>").expect("card end")];
            let collapsed_at = grype_card
                .find("<details class=\"technical finding-technical\">")
                .expect("collapsed block");
            for open_text in [
                grype_impact,
                "Upgrade the affected component to a fixed version",
                "Container security engineer",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-0002",
            ] {
                let at = grype_card
                    .find(open_text)
                    .unwrap_or_else(|| panic!("card omitted {open_text}"));
                assert!(at < collapsed_at, "{open_text} must stay in the open");
            }
            for retained in [
                "Evidence SHA-256",
                "Related framework references",
                "ISO/IEC 27001",
            ] {
                let at = grype_card
                    .find(retained)
                    .unwrap_or_else(|| panic!("card dropped {retained}"));
                assert!(
                    at > collapsed_at,
                    "{retained} must stay available, collapsed"
                );
            }
            // A closed <details> prints its summary and nothing under it, so
            // the printed report carried sixty-two headings that led nowhere.
            // The two groups that cost no pages print regardless; the two that
            // cost sixty-six between them print only where a reader opened
            // them, and the terms say which is which.
            for (html, printed) in [
                (&ordered_html, "stay collapsed technical detail"),
                (&zh_html, "仍屬收合的技術細節"),
            ] {
                assert!(
                    html.contains(
                        ".source-provenance::details-content,.inventory-complete::details-content\
                         {content-visibility:visible}"
                    ),
                    "framework attribution and the inventory would not print"
                );
                assert!(
                    html.contains(
                        "details:not([open]):not(.source-provenance):not(.inventory-complete)\
                         {display:none}"
                    ),
                    "a closed detail would print a heading with nothing under it"
                );
                assert_eq!(
                    html.matches(printed).count(),
                    1,
                    "the terms do not say what a printed copy leaves behind"
                );
                // Severity, coverage and the asset board are each well under a
                // page. Giving each one a page of its own printed three of them
                // on three pages and cost six over the report.
                assert!(
                    !html.contains("h2{break-before:page"),
                    "a page per section leaves the short ones mostly blank"
                );
                assert!(
                    html.contains("h2{break-after:avoid"),
                    "nothing keeps a section heading with its section"
                );
            }

            // A column header says which column it heads. The coverage matrix
            // was the only table that said so; the report's own row headers
            // already do it, and ten tables did not.
            for html in [&ordered_html, &zh_html] {
                let heads = html
                    .match_indices("<thead>")
                    .map(|(at, _)| {
                        // Past the <thead> tag itself: it starts with "<th".
                        let rest = &html[at + "<thead>".len()..];
                        &rest[..rest.find("</thead>").expect("a header row closes")]
                    })
                    .collect::<Vec<_>>();
                assert!(heads.len() >= 10, "the audit lost the report's tables");
                for head in heads {
                    assert_eq!(
                        head.matches("<th").count(),
                        head.matches("scope=\"col\"").count(),
                        "a column header does not say which column it heads: {head}"
                    );
                }
            }

            // A column header names its column; nothing named the table. Read
            // out of order -- by a screen reader, or by a reader landing on a
            // page break -- eleven grids arrived with no idea what they list.
            for html in [&ordered_html, &zh_html] {
                let tables = html.match_indices("<table").count();
                assert!(tables >= 10, "the audit lost the report's tables");
                let mut captions = 0usize;
                for (at, _) in html.match_indices("<table") {
                    let rest = &html[at..];
                    let opened = rest.find('>').expect("a table tag closes") + 1;
                    let caption = "<caption class=\"visually-hidden\">";
                    assert!(
                        rest[opened..].starts_with(caption),
                        "a table opens with no caption: {}",
                        &rest[..opened + 60.min(rest.len() - opened)]
                    );
                    let said = &rest[opened + caption.len()..];
                    let said = &said[..said.find("</caption>").expect("a caption closes")];
                    assert!(!said.trim().is_empty(), "a table caption says nothing");
                    captions += 1;
                }
                assert_eq!(tables, captions, "a table went uncaptioned");
            }

            // The asset column and the index's asset cell are the two narrow
            // places a full URL is printed, and overflow-wrap was breaking it
            // mid-label. A reader cannot tell that seam from the name.
            for html in [&ordered_html, &zh_html] {
                assert!(
                    html.contains("https:<wbr>/<wbr>/<wbr>portal.<wbr>example.<wbr>test:<wbr>443"),
                    "a target identity offers no place to break but the middle of a label"
                );
                // Only where the column width is fixed. The tested table is
                // sized by what is in it, and letting a target wrap there cost
                // five pages across the four reports.
                let tested = &html[html.find("<table class=\"tested-table\"").expect("tested")..];
                let tested = &tested[..tested.find("</table>").expect("tested end")];
                assert!(
                    tested.contains("tested-time"),
                    "the audit lost the tested table"
                );
                assert!(
                    !tested.contains("<wbr>"),
                    "a content-sized column was given a reason to wrap"
                );
                let index = &html[html.find("<table class=\"finding-index\"").expect("index")..];
                let index = &index[..index.find("</table>").expect("index end")];
                assert!(
                    index.contains("<wbr>"),
                    "the index's fixed-width asset cell still breaks mid-label"
                );
            }

            // An evidence record answers with what the scanner reported. Two
            // fields answered with the report's own defaults instead:
            // "Redacted: No" on forty-eight of fifty-one records, and
            // "not provided" on thirty-six attachment rows the scanner had in
            // fact reported as empty.
            //
            // The summary row went the same way. This build's adapters compose
            // it from the check, the source rule and the location, and all
            // three are labelled rows in the same block -- so fifty-one
            // records restated themselves, in English, inside the Chinese
            // report.
            for (html, summary) in [
                (&ordered_html, "<dt>Evidence summary</dt>"),
                (&zh_html, "<dt>證據摘要</dt>"),
            ] {
                assert_eq!(
                    html.matches(summary).count(),
                    0,
                    "an evidence summary restates the rows beside it"
                );
                assert_eq!(
                    html.matches(" reported rule ").count(),
                    0,
                    "an adapter-composed sentence reached the report untranslated"
                );
            }
            for (html, records, redacted, unknown, roles, groups) in [
                (
                    &ordered_html,
                    "<dt>Source rule</dt>",
                    "<dt>Redacted</dt>",
                    "not provided",
                    "<dt>Attached roles</dt>",
                    "<dt>Attached groups</dt>",
                ),
                (
                    &zh_html,
                    "<dt>來源規則</dt>",
                    "<dt>已遮蔽</dt>",
                    "未提供",
                    "<dt>附加的角色</dt>",
                    "<dt>附加的群組</dt>",
                ),
            ] {
                let evidence_records = html.matches(records).count();
                assert!(evidence_records > 20, "the audit lost the evidence records");
                let redaction_rows = html.matches(redacted).count();
                assert!(
                    (1..evidence_records / 4).contains(&redaction_rows),
                    "redaction reported on records where it did not happen: {redaction_rows} rows over {evidence_records} records"
                );
                assert_eq!(
                    html.matches(&format!("<dd>{unknown}</dd>")).count(),
                    0,
                    "an evidence field answers with a placeholder"
                );
                assert_eq!(
                    html.matches(roles).count(),
                    0,
                    "an empty attachment list is printed as a missing one"
                );
                assert!(
                    html.matches(groups).count() > 0,
                    "an attachment the scanner did report was dropped with the empty ones"
                );
            }

            // Every evidence summary this build's adapters write ends with the
            // same sentence about how raw target text is kept. That is one
            // statement about the report, and it was stapled to fifty-one
            // records. Progress already drops it; the terms now carry it.
            for (html, lifted) in [
                (
                    &ordered_html,
                    "Target text quoted in an evidence summary is retained as untrusted input",
                ),
                (&zh_html, "證據摘要引用的目標文字"),
            ] {
                assert_eq!(
                    html.matches("Raw target text is retained only as untrusted evidence")
                        .count(),
                    0,
                    "the standing evidence caveat is repeated per record"
                );
                assert_eq!(html.matches(lifted).count(), 1);
                let terms = &html[html.rfind("<footer>").expect("report terms")..];
                assert!(terms.contains(lifted), "the caveat left the report terms");
            }

            // Whether this run's scanner log can be read back is one fact
            // about the run's export. Written into each task record it was
            // four identical lines twenty-four times over, and the records
            // stopped being about the tasks.
            for (html, availability, explanation, footnote) in [
                (
                    &ordered_html,
                    "Every task in this run recorded the same state.",
                    "Run-bound diagnostic log: unavailable.",
                    "Scanner messages are not included in this readable HTML report.",
                ),
                (
                    &zh_html,
                    "本輪每個工作記錄的狀態都相同。",
                    "本輪的診斷紀錄無法取得",
                    "這份好讀的 HTML 報告不包含掃描工具訊息。",
                ),
            ] {
                assert_eq!(html.matches(availability).count(), 1);
                assert_eq!(
                    html.matches(explanation).count(),
                    1,
                    "the diagnostic-log state is restated per task"
                );
                assert_eq!(html.matches(footnote).count(), 1);
            }

            // The artifact digest proves the retained file was not altered.
            // Without a pointer a reader still cannot find the one record the
            // finding was raised from inside it -- the inventory provenance
            // has printed one all along, and the finding evidence had not.
            for (html, records, pointer) in [
                (
                    &ordered_html,
                    "<dt>Source rule</dt>",
                    "<dt>Result pointer</dt><dd><code>",
                ),
                (&zh_html, "<dt>來源規則</dt>", "<dt>結果指標</dt><dd><code>"),
            ] {
                let evidence = html.matches(records).count();
                assert!(evidence > 20, "the audit lost the evidence records");
                assert_eq!(
                    html.matches(pointer).count(),
                    evidence,
                    "an evidence record cannot be traced into its artifact"
                );
                let named = html
                    .match_indices(pointer)
                    .map(|(at, _)| {
                        let value = &html[at + pointer.len()..];
                        &value[..value.find("</code>").expect("a pointer closes")]
                    })
                    .collect::<Vec<_>>();
                for into in &named {
                    assert!(!into.is_empty(), "an evidence record points nowhere");
                }
                // A pointer that is the same for every record locates nothing.
                let distinct = named.iter().collect::<std::collections::BTreeSet<_>>();
                assert!(
                    distinct.len() > evidence / 4,
                    "{} pointers over {evidence} records do not locate a record",
                    distinct.len()
                );
            }

            // The coverage tile and its sentence count the same list. The
            // separate final record-notes tile is deliberately not part of
            // either count.
            for html in [&ordered_html, &zh_html] {
                let row = &html[html.find("kpi-row").expect("the cover tiles")..];
                let row = &row[..row.find("</section>").expect("the tiles close")];
                let label_marker = "class=\"kpi__label\">";
                let (label_at, tile) = row
                    .match_indices(label_marker)
                    .map(|(at, _)| {
                        let label = &row[at + label_marker.len()..];
                        (
                            at,
                            &label[..label.find("</span>").expect("a tile label closes")],
                        )
                    })
                    .find(|(_, label)| {
                        label.contains("Unfinished checks") || label.contains("未完成的檢查")
                    })
                    .expect("a coverage tile");
                assert!(
                    tile.contains("Unfinished checks") || tile.contains("未完成的檢查"),
                    "the audit lost the no-verdict tile: {tile}"
                );
                let summary = &html[html
                    .find("executive-summary\">")
                    .expect("the executive summary")..];
                let summary = &summary[..summary.find("</section>").expect("the summary closes")];
                let counted = row[..label_at]
                    .rsplit_once("class=\"kpi__value\">")
                    .expect("a tile is counted")
                    .1;
                let counted = counted[..counted.find("</span>").expect("a count closes")]
                    .parse::<usize>()
                    .expect("a tile counts");
                assert!(counted > 1, "the audit lost the coverage tile's count");
                // The sentence stated both totals side by side while the
                // second contained the first, so five and ten read as
                // fifteen out of ten. Its parts account for the tile exactly.
                let coverage_sentence = summary
                    .split("<p>")
                    .skip(1)
                    .map(|paragraph| {
                        &paragraph[..paragraph.find("</p>").expect("a summary paragraph closes")]
                    })
                    .find(|paragraph| {
                        paragraph.contains("did not complete") || paragraph.contains("沒有完成")
                    })
                    .expect("the summary names unfinished coverage");
                let parts = coverage_sentence
                    .split(|character: char| !character.is_ascii_digit())
                    .filter(|part| !part.is_empty())
                    .map(|part| part.parse::<usize>().expect("a counted part"))
                    .collect::<Vec<_>>();
                assert_eq!(
                    parts.iter().sum::<usize>(),
                    counted,
                    "the summary's parts do not add up to the {counted} the tile counts: {parts:?}"
                );
                assert!(
                    parts.len() >= 2,
                    "the summary stopped saying what the uncovered list holds"
                );
                // Cancelled and genuinely unavailable coverage remain in the
                // unfinished count. Record-only unavailable rows are counted
                // separately and never enter this sentence.
                let counts = &report.coverage_counts;
                assert!(counts.cancelled > 0);
                assert!(
                    report
                        .coverage_gaps
                        .iter()
                        .any(|gap| gap.class == CoverageGapClass::RecordNote),
                    "the audit lost its separately counted record notes"
                );
                assert_eq!(
                    parts[0],
                    counts.failed
                        + counts.timed_out
                        + counts.cancelled
                        + counts.not_tested
                        + counts.unavailable,
                    "the summary drops a state that is short of a completed check"
                );
                assert!(
                    !summary.contains("Those areas were not tested")
                        && !summary.contains("這些範圍未經測試"),
                    "the summary calls a check that returned no verdict untested"
                );
            }

            // Cloudsplaining keys a policy finding on the action it found, so
            // sixteen of the eighteen policy records printed that one string
            // under two labels. Both rows stay where the list says more, or
            // where it is not the whole list.
            for (html, identity, actions) in [
                (
                    &ordered_html,
                    "<dt>Upstream finding</dt><dd>",
                    "<dt>Reported actions</dt><dd>",
                ),
                (&zh_html, "<dt>上游問題</dt><dd>", "<dt>回報的動作</dt><dd>"),
            ] {
                let policies = html.matches(actions).count();
                assert!(policies >= 10, "the audit lost the policy records");
                let identities = html.matches(identity).count();
                assert!(
                    identities < policies / 4,
                    "{identities} of {policies} policy records restate their identity"
                );
                assert!(identities > 0, "an upstream identity is never reported");
                for (at, _) in html.match_indices(identity) {
                    let named = &html[at + identity.len()..];
                    let named = &named[..named.find("</dd>").expect("a value closes")];
                    assert!(
                        !html.contains(&format!("{actions}{named}</dd>")),
                        "an upstream identity repeats the action list beside it: {named}"
                    );
                }
            }

            // The phase is the state under a finer name. Twenty-three of the
            // twenty-four records printed the same word twice -- "Completed"
            // as the state, then the backend's raw "completed" as the phase,
            // which under a translated Chinese label was the English one.
            for (html, state, phase) in [
                (
                    &ordered_html,
                    "<strong>State:</strong> ",
                    "<strong>Phase:</strong> ",
                ),
                (
                    &zh_html,
                    "<strong>狀態：</strong>",
                    "<strong>階段：</strong>",
                ),
            ] {
                let states = html.matches(state).count();
                assert!(states >= 20, "the audit lost the task records");
                let phases = html
                    .match_indices(phase)
                    .map(|(at, _)| {
                        let value = &html[at + phase.len()..];
                        value[..value.find(" \u{b7} ").expect("a phase ends")].to_owned()
                    })
                    .collect::<Vec<_>>();
                assert!(
                    phases.len() < states / 4,
                    "{} of {states} records restate their state as a phase",
                    phases.len()
                );
                assert!(!phases.is_empty(), "a phase that differs is not reported");
                for named in &phases {
                    assert!(
                        !named.contains('_'),
                        "a phase reached the report as a raw key: {named}"
                    );
                    let stated = format!("{state}{named} \u{b7} ");
                    assert!(
                        !html.contains(&stated),
                        "a phase repeats the state beside it: {named}"
                    );
                }
            }
            // Under a translated label, in the translated vocabulary.
            assert!(
                zh_html.contains("<strong>階段：</strong>已擷取，等待轉接器處理"),
                "a task phase stayed in English in the Chinese report"
            );

            // Severity is a closed list and the profile is read as one: the
            // reader who wants to know whether anything was Critical reads the
            // Critical row. A severity with no findings still gets a row, for
            // the same reason the cover keeps a zero tile -- a missing row
            // cannot be told from an unmeasured one.
            for (html, named, severities) in [
                (
                    &ordered_html,
                    "English",
                    [
                        "Critical",
                        "High",
                        "Medium",
                        "Low",
                        "Informational",
                        "Unknown",
                    ],
                ),
                (
                    &zh_html,
                    "Chinese",
                    ["嚴重", "高", "中", "低", "資訊", "未知"],
                ),
            ] {
                let rows = html
                    .match_indices("<span class=\"severity-row__label\">")
                    .map(|(at, marker)| {
                        let rest = &html[at + marker.len()..];
                        let label = &rest[..rest.find('<').expect("a label closes")];
                        let counted = rest
                            .find("<span class=\"severity-row__count\">")
                            .expect("a severity row carries its count");
                        let rest = &rest[counted + "<span class=\"severity-row__count\">".len()..];
                        let count: usize = rest[..rest.find('<').expect("a count closes")]
                            .parse()
                            .expect("a severity count is a number");
                        (label.to_owned(), count)
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    rows.iter()
                        .map(|(label, _)| label.as_str())
                        .collect::<Vec<_>>(),
                    severities,
                    "the {named} severity profile dropped or reordered a severity"
                );
                // The native ZAP fixture adds informational alerts, so this
                // full-catalog run now legitimately covers all six severities.
                // The zero is dimmed rather than drawn as a bar of its own.
                assert_eq!(
                    html.matches("severity-row severity-row--none").count(),
                    rows.iter().filter(|(_, count)| *count == 0).count(),
                    "a zero severity row is not marked as one in {named}"
                );
            }

            // A reader moving by heading -- a screen reader, a print outline,
            // an export to a document -- follows the levels. A skipped level
            // is a hole they cannot see around.
            for (html, named) in [(&ordered_html, "English"), (&zh_html, "Chinese")] {
                let mut depth = 0usize;
                let mut seen = 0usize;
                let mut rest = html.as_str();
                while let Some(at) = rest.find("<h") {
                    rest = &rest[at + 2..];
                    let Some(level) = rest.chars().next().and_then(|glyph| glyph.to_digit(10))
                    else {
                        continue;
                    };
                    let level = level as usize;
                    if !(1..=6).contains(&level) {
                        continue;
                    }
                    if seen > 0 {
                        assert!(
                            level <= depth + 1,
                            "the {named} report skips from h{depth} to h{level}"
                        );
                    }
                    depth = level;
                    seen += 1;
                }
                assert!(seen > 200, "the {named} report lost its headings: {seen}");
            }

            // The error code is the sibling of the phase and the state, and
            // was the one value on that line the backend's own spelling
            // reached the page through. A reader only meets it on the run
            // that went wrong.
            assert!(
                ordered_html.contains("<strong>Error code:</strong> Execution Failed"),
                "the audit lost the failing run's error code"
            );
            assert!(
                zh_html.contains("<strong>錯誤碼：</strong>執行失敗"),
                "a task error code stayed in English in the Chinese report"
            );

            // The class, not the one case: no value under a translated label
            // may be a raw backend key. Upstream identifiers -- a resource
            // type, a purl -- are not printed this way and are unaffected.
            let raw_key_after_a_label = |html: &str| {
                html.match_indices("</strong> ").find_map(|(at, marker)| {
                    let value = &html[at + marker.len()..];
                    let end = value.find(['<', ' ', '\u{b7}']).unwrap_or(value.len());
                    let value = &value[..end];
                    let is_key = value.contains('_')
                        && value
                            .chars()
                            .all(|glyph| glyph.is_ascii_lowercase() || glyph == '_');
                    is_key.then(|| value.to_owned())
                })
            };
            if let Some(raw) = raw_key_after_a_label(&zh_html) {
                panic!("a backend key reached the Chinese report unnamed: {raw}");
            }

            // One embedded catalog produced every coordinate in this run, so
            // its version and digest are one fact about the report, not a
            // hundred and forty-nine facts about individual references. The
            // report's terms carry it; the cards carry the coordinate.
            for (html, catalogued, digest) in [
                (
                    &ordered_html,
                    "Framework references come from mapping catalog ",
                    "Catalog SHA-256",
                ),
                (&zh_html, "框架參考來自對照目錄 ", "目錄 SHA-256"),
            ] {
                assert_eq!(
                    html.matches(catalogued).count(),
                    1,
                    "the mapping catalog is stated once, in the report's terms"
                );
                let terms = html
                    .rfind("<footer>")
                    .expect("the report terms close the report");
                assert!(
                    html[terms..].contains(catalogued),
                    "the mapping catalog left the report's terms"
                );
                assert_eq!(
                    html.matches(digest).count(),
                    1,
                    "a card repeated the catalog digest the terms already give"
                );
            }

            // A redacted case is built before a locale is chosen, so its
            // markers go in in English. The standard-redacted report is the
            // one export a reader hands to someone else, and the Chinese one
            // carried three hundred and fifty-three English brackets under
            // translated labels.
            let redacted = |locale, name: &str| {
                let path = artifact_root.join(name);
                reopened_service
                    .export_case(
                        case_id,
                        scan_run_id,
                        CaseExportFormat::Html,
                        path.clone(),
                        ExportOptions {
                            redaction: RedactionProfile::Standard,
                            include_raw_artifacts: false,
                            locale,
                        },
                    )
                    .unwrap();
                fs::read_to_string(&path).unwrap()
            };
            let redacted_english = redacted(ReportLocale::En, "redaction-markers-en.html");
            let redacted_chinese = redacted(ReportLocale::ZhHant, "redaction-markers-zh.html");
            let marked = redacted_english.matches("[redacted ").count();
            assert!(
                marked > 100,
                "the audit lost the redaction markers: {marked}"
            );
            assert_eq!(
                redacted_chinese.matches("[redacted ").count(),
                0,
                "the Chinese redacted report keeps English redaction markers"
            );
            // Named, not merely removed: a withheld value still says which
            // kind of value it was, on the page as much as in the JSON.
            for (english, chinese) in [
                ("[redacted location]", "\u{ff08}\u{4f4d}\u{7f6e}\u{ff09}"),
                (
                    "[redacted result pointer]",
                    "\u{ff08}\u{7d50}\u{679c}\u{6307}\u{6a19}\u{ff09}",
                ),
                (
                    "[redacted evidence summary]",
                    "\u{ff08}\u{8b49}\u{64da}\u{6458}\u{8981}\u{ff09}",
                ),
            ] {
                let named = redacted_english.matches(english).count();
                assert!(named > 0, "the audit lost {english}");
                assert_eq!(
                    redacted_chinese.matches(chinese).count(),
                    named,
                    "{english} lost its Chinese placeholder"
                );
            }

            // Numbered, so eighteen findings over three policies do not all
            // read as one. The unnumbered marker is the fallback for a name
            // the alias walk never reached, and this fixture reaches them all.
            for (kind, translated) in [
                ("policy", "IAM \u{653f}\u{7b56}"),
                ("group", "IAM \u{7fa4}\u{7d44}"),
                ("user", "IAM \u{4f7f}\u{7528}\u{8005}"),
            ] {
                assert_eq!(
                    redacted_english
                        .matches(&format!("[redacted IAM {kind}]"))
                        .count(),
                    0,
                    "an IAM {kind} was withheld without a number"
                );
                let numbered = (1..=9)
                    .map(|at| {
                        let named = redacted_english
                            .matches(&format!("[redacted IAM {kind} {at}]"))
                            .count();
                        assert_eq!(
                            redacted_chinese
                                .matches(&format!("\u{ff08}{translated} {at}\u{ff09}"))
                                .count(),
                            named,
                            "IAM {kind} {at} lost its Chinese placeholder"
                        );
                        named
                    })
                    .filter(|named| *named > 0)
                    .count();
                assert!(numbered > 0, "no IAM {kind} survived the redaction");
                if kind == "policy" {
                    assert_eq!(numbered, 3, "the three policies stopped being told apart");
                }
            }

            // The stand-in title the redaction writes when the case's own is
            // withheld. It is printed where a document says what it is -- the
            // tab, the cover, and the running head every page after the first
            // repeats -- so on the Chinese redacted report it was the most
            // repeated English on the paper.
            for (locale_html, present, absent) in [
                (
                    &redacted_english,
                    "Redacted assessment case",
                    "\u{5df2}\u{906e}\u{853d}\u{7684}\u{8a55}\u{4f30}\u{6848}\u{4ef6}",
                ),
                (
                    &redacted_chinese,
                    "\u{5df2}\u{906e}\u{853d}\u{7684}\u{8a55}\u{4f30}\u{6848}\u{4ef6}",
                    "Redacted assessment case",
                ),
            ] {
                assert_eq!(
                    locale_html.matches(present).count(),
                    3,
                    "the redacted title lost one of its three places"
                );
                assert_eq!(
                    locale_html.matches(absent).count(),
                    0,
                    "the redacted title was printed in the other language"
                );
            }
            // A title the case really carries is the user's own words, and a
            // rule that reaches it would rewrite a name rather than a marker.
            for html in [&ordered_html, &zh_html] {
                assert_eq!(
                    html.matches("All integrated engines, one report (InternalItEnvironment)")
                        .count(),
                    3,
                    "the case's own title stopped reaching the tab, cover and running head"
                );
                assert_eq!(
                    html.matches(
                        "\u{5df2}\u{906e}\u{853d}\u{7684}\u{8a55}\u{4f30}\u{6848}\u{4ef6}"
                    )
                    .count(),
                    0,
                    "an unredacted case was titled as redacted"
                );
            }

            if let Some(dump) = std::env::var_os("AI_SCANNER_REPORT_DUMP_DIR").map(PathBuf::from) {
                fs::create_dir_all(&dump).unwrap();
                for (name, format, locale, redaction) in [
                    (
                        "report-en.html",
                        CaseExportFormat::Html,
                        ReportLocale::En,
                        RedactionProfile::None,
                    ),
                    (
                        "report-zh.html",
                        CaseExportFormat::Html,
                        ReportLocale::ZhHant,
                        RedactionProfile::None,
                    ),
                    (
                        "report-standard-redacted-en.html",
                        CaseExportFormat::Html,
                        ReportLocale::En,
                        RedactionProfile::Standard,
                    ),
                    (
                        "report-standard-redacted-zh.html",
                        CaseExportFormat::Html,
                        ReportLocale::ZhHant,
                        RedactionProfile::Standard,
                    ),
                    (
                        "report.json",
                        CaseExportFormat::CanonicalJson,
                        ReportLocale::En,
                        RedactionProfile::None,
                    ),
                    (
                        "framework.json",
                        CaseExportFormat::FrameworkReport,
                        ReportLocale::En,
                        RedactionProfile::None,
                    ),
                ] {
                    reopened_service
                        .export_case(
                            case_id,
                            scan_run_id,
                            format,
                            dump.join(name),
                            ExportOptions {
                                redaction,
                                include_raw_artifacts: false,
                                locale,
                            },
                        )
                        .unwrap();
                }
                fs::write(
                    dump.join("beginner-report.json"),
                    serde_json::to_string_pretty(&report).unwrap(),
                )
                .unwrap();
            }
        },
    );
}

/// What one set of case answers leaves in the AIDEFEND half of a finished
/// report.
struct AidefendView {
    state: String,
    /// Coordinate to the engines whose evidence carried it.
    reached: BTreeMap<String, BTreeSet<String>>,
    finding_titles: Vec<String>,
    html: String,
    zh_html: String,
    /// The framework export's own account of how much of the run it placed.
    mapped: usize,
    unmapped: usize,
    limitations: Vec<String>,
    mapping_states: BTreeMap<String, usize>,
}

/// Runs the whole 21-engine batch under one set of case answers and reads back
/// what AIDEFEND received.
///
/// Running the whole batch is the point. A coordinate that only a hand-built
/// single-engine case can reach is not a coordinate a reader will ever see,
/// and the reach depends on the run: a check that failed, timed out or was
/// cancelled carries no evidence, so its coordinates stay out no matter what
/// the catalog says.
fn aidefend_view(
    intent: AssessmentIntent,
    ai_generated: AiGeneratedArtifactAnswer,
) -> AidefendView {
    all_engines_in_one_report(
        intent,
        ai_generated,
        EngineOutcomes::MixedTerminalStates,
        |subject| {
            let storage = Storage::open(subject.database).unwrap();
            let service = CaseService::new(
                &storage,
                subject.engines,
                subject.adapters,
                subject.artifact_root,
                subject.signing_key,
            );
            let export = |format, name: &str, locale| {
                let path = subject.artifact_root.join(name);
                service
                    .export_case(
                        subject.case_id,
                        subject.scan_run_id,
                        format,
                        path.clone(),
                        ExportOptions {
                            redaction: RedactionProfile::None,
                            include_raw_artifacts: false,
                            locale,
                        },
                    )
                    .unwrap();
                fs::read(&path).unwrap()
            };
            let framework: serde_json::Value = serde_json::from_slice(&export(
                CaseExportFormat::FrameworkReport,
                "aidefend-framework.json",
                ReportLocale::En,
            ))
            .unwrap();
            assert!(
                framework["unrecognized_relationships"]
                    .as_array()
                    .unwrap()
                    .is_empty(),
                "a relationship the catalog cannot explain must never reach a reader"
            );
            let family = framework["frameworks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["framework"] == "AIDEFEND")
                .expect("AIDEFEND is one of the declared families")
                .clone();
            let mut reached = BTreeMap::<String, BTreeSet<String>>::new();
            for control in family["controls"].as_array().unwrap() {
                for relationship in control["relationships"].as_array().unwrap() {
                    // A drifted mapping version is a different claim than one the
                    // current catalog still states, and the reader cannot tell
                    // them apart from the coordinate alone.
                    assert_eq!(relationship["mapping_version_state"], "exact_match");
                    assert_eq!(
                        relationship["mapping_provenance_state"],
                        "verified_current_catalog"
                    );
                    let engines = reached
                        .entry(control["control_id"].as_str().unwrap().to_owned())
                        .or_default();
                    for engine in relationship["finding"]["engine_ids"].as_array().unwrap() {
                        engines.insert(engine.as_str().unwrap().to_owned());
                    }
                }
            }
            let mut mapping_states = BTreeMap::<String, usize>::new();
            for entry in framework["observation_provenance"].as_array().unwrap() {
                *mapping_states
                    .entry(
                        entry["framework_mapping_state"]
                            .as_str()
                            .unwrap()
                            .to_owned(),
                    )
                    .or_default() += 1;
            }
            let html = String::from_utf8(export(
                CaseExportFormat::Html,
                "aidefend-report.html",
                ReportLocale::En,
            ))
            .unwrap();
            let zh_html = String::from_utf8(export(
                CaseExportFormat::Html,
                "aidefend-report-zh.html",
                ReportLocale::ZhHant,
            ))
            .unwrap();
            assert_paragraphs_are_well_formed(&html, "the English report");
            assert_paragraphs_are_well_formed(&zh_html, "the Chinese report");
            AidefendView {
                state: family["state"].as_str().unwrap().to_owned(),
                mapped: framework["coverage"]["selected_run_findings_with_framework_relationship"]
                    .as_u64()
                    .unwrap() as usize,
                unmapped:
                    framework["coverage"]["selected_run_findings_without_framework_relationship"]
                        .as_u64()
                        .unwrap() as usize,
                limitations: framework["coverage"]["limitations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|limitation| limitation.as_str().unwrap().to_owned())
                    .collect(),
                mapping_states,
                reached,
                finding_titles: {
                    // Context may change prioritization; compare the retained
                    // detector content, including duplicates, independently of rank.
                    let mut titles = subject
                        .report
                        .findings
                        .iter()
                        .map(|finding| finding.title.clone())
                        .collect::<Vec<_>>();
                    titles.sort();
                    titles
                },
                html,
                zh_html,
            }
        },
    )
}

/// AIDEFEND is a third of the framework structure this product maps to, and
/// the audit above cannot reach any of it: coordinates are withheld from a
/// case that declares a non-AI assessment, which is exactly what the
/// IT-environment run declares. So the AI half of the mapping is exercised
/// here -- catalog, adapter, report layer and export -- on the same 25 checks.
#[test]
fn the_ai_framework_follows_the_case_answers_and_nothing_else() {
    let withheld = aidefend_view(
        AssessmentIntent::InternalItEnvironment,
        AiGeneratedArtifactAnswer::No,
    );
    assert_eq!(withheld.state, "not_applicable_to_declared_context");
    assert!(
        withheld.reached.is_empty(),
        "a non-AI assessment infers no AI coordinate: {:?}",
        withheld.reached
    );
    assert!(
        !withheld.html.contains("AIDEFEND 1.20260805 /"),
        "no AIDEFEND coordinate reaches the reader of a non-AI run"
    );

    let declared = aidefend_view(
        AssessmentIntent::AiApplication,
        AiGeneratedArtifactAnswer::Yes,
    );
    assert_eq!(declared.state, "related_coordinates_observed");
    // Coordinate by coordinate, with the engine that earned it. The catalog
    // also carries IaC-scanning and static-analysis coordinates; Checkov
    // failed, KICS timed out and Semgrep completed empty on this run, so
    // those three carry no evidence and correctly stay out.
    assert_eq!(
        declared
            .reached
            .iter()
            .map(|(control, engines)| (
                control.as_str(),
                engines.iter().map(String::as_str).collect::<Vec<_>>()
            ))
            .collect::<Vec<_>>(),
        vec![
            ("AID-H-003.001", vec!["grype", "trivy"]),
            ("AID-H-003.010", vec!["greenbone", "grype", "trivy"]),
            ("AID-H-031.002", vec!["gitleaks"]),
            ("AID-I-001.001", vec!["kubescape"]),
        ]
    );
    assert!(
        declared.html.contains(
            "<strong>AIDEFEND 1.20260805 / AID-H-003.001</strong> \
             — Software Dependency &amp; Package Security"
        ),
        "the coordinate has to reach the report, not only the export"
    );

    // The artifact answer moves one coordinate and nothing else: the
    // static-admission gate is about artifacts an AI wrote, so a declared AI
    // system that wrote none of its own code does not acquire it.
    let no_artifact = aidefend_view(
        AssessmentIntent::AiApplication,
        AiGeneratedArtifactAnswer::No,
    );
    assert_eq!(no_artifact.state, "related_coordinates_observed");
    assert_eq!(
        no_artifact.reached.keys().collect::<Vec<_>>(),
        ["AID-H-003.001", "AID-H-003.010", "AID-I-001.001"]
    );

    // The synthetic Nuclei rule and three native ZAP instances have no reviewed
    // relationship. Garak's four AI mappings also stay unknown when the case
    // does not declare an AI system; enabling the engine must not infer it.
    for view in [&withheld, &declared, &no_artifact] {
        assert_eq!(view.mapped + view.unmapped, 56);
        assert_eq!(
            view.mapping_states.get("no_packaged_catalog_relationship"),
            Some(&view.unmapped),
            "every unplaced finding says so in the provenance ledger"
        );
        // And the reader is told on the card, in either language, instead of
        // reading the absence as "no control relates to this".
        assert_eq!(
            view.html
                .matches("The packaged mapping catalog has no entry for this finding's rule, so its framework position is unknown, not absent.")
                .count(),
            view.unmapped
        );
        assert_eq!(
            view.zh_html
                .matches("內建的對照目錄沒有此問題規則的項目，因此其框架位置為未知，而非不存在。")
                .count(),
            view.unmapped
        );
        assert!(
            !view
                .html
                .contains("No framework reference was retained for the selected run.")
        );
        assert!(!view.zh_html.contains("未保留本輪的框架參考。"));
        assert!(
            view.limitations.iter().any(|limitation| limitation
                == &format!("{} of 56 selected-run findings have no relationship in the packaged mapping catalog. Their framework position is unknown, not absent.", view.unmapped)),
            "{:#?}",
            view.limitations
        );
    }
    // Declaring an AI system admits the four native Garak relationships. The
    // unrelated Nuclei/ZAP rules remain unknown in either context.
    assert_eq!((withheld.mapped, withheld.unmapped), (48, 8));
    assert_eq!((declared.mapped, declared.unmapped), (52, 4));
    assert_eq!((no_artifact.mapped, no_artifact.unmapped), (52, 4));

    // None of this is detection. The same 25 checks found the same problems
    // in all three runs; only the coordinates the report may name changed.
    assert_eq!(withheld.finding_titles.len(), 56);
    assert_eq!(declared.finding_titles, withheld.finding_titles);
    assert_eq!(no_artifact.finding_titles, withheld.finding_titles);
}
