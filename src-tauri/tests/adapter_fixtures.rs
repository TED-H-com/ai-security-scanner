use ai_security_scanner_lib::adapter::{AdapterAssetIdentifierMap, AdapterInput, AdapterOutput};
use ai_security_scanner_lib::adapters::{BUILTIN_ENGINE_IDS, builtin_adapter_registry};
use ai_security_scanner_lib::correlation::correlation_report;
use ai_security_scanner_lib::domain::{
    AssessmentCase, Asset, AssetIdentifier, AssetKind, AwsIamPolicySource, BenchmarkReference,
    Confidence, ConfidenceBasisCode, DataClass, EngineCategory, Finding, FindingFamily,
    FindingStatus, InventoryObservationKind, OrganizationProfile, RawArtifact, Severity,
    SeverityBasisCode, UnevaluatedTarget, UnevaluatedTargetCause,
};
use ai_security_scanner_lib::finding_narrative::{
    ENGLISH_ROLLBACK, expert_type_zh_hant, priority_reason_zh_hant, rollback_zh_hant,
    verification_zh_hant,
};
use ai_security_scanner_lib::registry::EngineRegistry;
use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

fn fixture(engine_id: &str) -> (&'static [u8], &'static str, &'static str) {
    match engine_id {
        "cloudquery" => (
            include_bytes!("fixtures/adapters/cloudquery.json"),
            "aws_iam_users.json",
            "application/x-ndjson",
        ),
        "steampipe" => (
            include_bytes!("fixtures/adapters/steampipe.json"),
            "steampipe.json",
            "application/json",
        ),
        "prowler" => (
            include_bytes!("fixtures/adapters/prowler-ocsf.json"),
            "prowler-ocsf.json",
            "application/json",
        ),
        "scoutsuite" => (
            include_bytes!("fixtures/adapters/scoutsuite.json"),
            "scoutsuite.json",
            "application/json",
        ),
        "cloudsplaining" => (
            include_bytes!("fixtures/adapters/cloudsplaining.json"),
            "cloudsplaining.json",
            "application/json",
        ),
        "scubagear" => (
            include_bytes!("fixtures/adapters/scubagear.json"),
            "scubagear.json",
            "application/json",
        ),
        "maester" => (
            include_bytes!("fixtures/adapters/maester.json"),
            "maester.json",
            "application/json",
        ),
        "naabu" => (
            include_bytes!("fixtures/adapters/naabu.jsonl"),
            "naabu.jsonl",
            "application/x-ndjson",
        ),
        "httpx" => (
            include_bytes!("fixtures/adapters/httpx.jsonl"),
            "httpx.jsonl",
            "application/x-ndjson",
        ),
        "nuclei" => (
            include_bytes!("fixtures/adapters/nuclei.jsonl"),
            "nuclei.jsonl",
            "application/x-ndjson",
        ),
        "greenbone" => (
            include_bytes!("fixtures/adapters/greenbone.xml"),
            "greenbone.xml",
            "application/xml",
        ),
        "zap" => (
            include_bytes!("fixtures/adapters/zap.json"),
            "zap.json",
            "application/json",
        ),
        "semgrep" => (
            include_bytes!("fixtures/adapters/semgrep.json"),
            "semgrep.json",
            "application/json",
        ),
        "gitleaks" => (
            include_bytes!("fixtures/adapters/gitleaks.json"),
            "gitleaks.json",
            "application/json",
        ),
        "trufflehog" => (
            include_bytes!("fixtures/adapters/trufflehog.jsonl"),
            "trufflehog.jsonl",
            "application/x-ndjson",
        ),
        "checkov" => (
            include_bytes!("fixtures/adapters/checkov.json"),
            "checkov.json",
            "application/json",
        ),
        "kics" => (
            include_bytes!("fixtures/adapters/kics.json"),
            "kics.json",
            "application/json",
        ),
        "trivy" => (
            include_bytes!("fixtures/adapters/trivy.json"),
            "trivy.json",
            "application/json",
        ),
        "grype" => (
            include_bytes!("fixtures/adapters/grype.json"),
            "grype.json",
            "application/json",
        ),
        "syft" => (
            include_bytes!("fixtures/adapters/syft.json"),
            "syft.json",
            "application/json",
        ),
        "kubescape" => (
            include_bytes!("fixtures/adapters/kubescape.json"),
            "kubescape.json",
            "application/json",
        ),
        "kube-bench" => (
            include_bytes!("fixtures/adapters/kube-bench.json"),
            "kube-bench.json",
            "application/json",
        ),
        "garak" => (
            include_bytes!("fixtures/adapters/garak.jsonl"),
            "report.jsonl",
            "application/x-ndjson",
        ),
        "agentic-radar" => (
            include_bytes!("../../docs/research/fixtures/agentic-radar/n8n.json"),
            "agentic-radar.json",
            "application/json",
        ),
        "mcp-armor" => (
            include_bytes!("../../docs/research/fixtures/mcp-armor/config-findings.json"),
            "mcp-armor.json",
            "application/json",
        ),
        other => panic!("no adapter fixture for {other}"),
    }
}

fn normalize_bytes(
    engine_id: &str,
    bytes: &[u8],
    filename: &str,
    media_type: &str,
    run_id: &str,
) -> AdapterOutput {
    let assets = if matches!(engine_id, "cloudquery" | "steampipe" | "prowler") {
        vec![authorized_asset(
            "asset-1",
            AssetKind::CloudAccount,
            Some("aws"),
            &[("aws_account_id", "123456789012")],
        )]
    } else if matches!(engine_id, "agentic-radar" | "mcp-armor") {
        vec![authorized_asset(
            "asset-1",
            AssetKind::Repository,
            None,
            &[],
        )]
    } else {
        vec![authorized_asset("asset-1", AssetKind::Other, None, &[])]
    };
    normalize_bytes_with_assets(engine_id, bytes, filename, media_type, run_id, &assets)
}

fn normalize_bytes_with_assets(
    engine_id: &str,
    bytes: &[u8],
    filename: &str,
    media_type: &str,
    run_id: &str,
    assets: &[Asset],
) -> AdapterOutput {
    normalize_bytes_with_assets_and_context(
        engine_id,
        media_type,
        bytes,
        filename,
        run_id,
        assets,
        FrameworkApplicability::default(),
    )
}

#[derive(Clone, Copy, Default)]
struct FrameworkApplicability {
    ai_system: bool,
    ai_generated_artifact: bool,
}

fn normalize_bytes_with_assets_and_context(
    engine_id: &str,
    media_type: &str,
    bytes: &[u8],
    filename: &str,
    run_id: &str,
    assets: &[Asset],
    applicability: FrameworkApplicability,
) -> AdapterOutput {
    let temp = tempfile::tempdir().expect("temporary artifact root");
    let artifact_path = temp.path().join(filename);
    // `filename` becomes the artifact's `relative_path`, so a test that cares
    // where inside a run an artifact sits passes a nested path here.
    if let Some(parent) = artifact_path.parent() {
        std::fs::create_dir_all(parent).expect("artifact parent directory");
    }
    std::fs::write(&artifact_path, bytes).expect("write fixture artifact");

    let engine_registry = EngineRegistry::load_builtin().expect("valid engine catalog");
    let manifest = engine_registry
        .get(engine_id)
        .expect("fixture engine has manifest");
    let sha256 = hex::encode(Sha256::digest(bytes));
    let artifact = RawArtifact {
        id: format!("artifact-{engine_id}"),
        case_id: "case-1".into(),
        run_id: run_id.into(),
        engine_run_id: format!("engine-run-{run_id}"),
        relative_path: filename.into(),
        media_type: media_type.into(),
        sha256,
        byte_length: bytes.len() as u64,
        created_at: Utc
            .with_ymd_and_hms(2026, 8, 24, 12, 0, 0)
            .single()
            .expect("fixed timestamp"),
        contains_sensitive_data: matches!(engine_id, "gitleaks" | "trufflehog"),
    };
    let asset_ids = assets
        .iter()
        .map(|asset| asset.id.clone())
        .collect::<Vec<_>>();
    let asset_identifier_map = AdapterAssetIdentifierMap::from_assets(assets);
    let raw_artifacts = vec![artifact];
    let engine_run_id = format!("engine-run-{run_id}");
    let input = AdapterInput {
        case_id: "case-1",
        scan_run_id: run_id,
        engine_run_id: &engine_run_id,
        manifest,
        ai_system_applicable: applicability.ai_system,
        ai_generated_artifact_applicable: applicability.ai_generated_artifact,
        asset_ids: &asset_ids,
        asset_identifier_map: &asset_identifier_map,
        artifact_root: temp.path(),
        raw_artifacts: &raw_artifacts,
    };
    builtin_adapter_registry()
        .expect("valid built-in adapters")
        .normalize(&input)
        .expect("normalization is contained")
        .expect("adapter is registered")
}

fn authorized_asset(
    id: &str,
    kind: AssetKind,
    provider: Option<&str>,
    identifiers: &[(&str, &str)],
) -> Asset {
    Asset {
        id: id.into(),
        kind,
        name: id.into(),
        provider: provider.map(str::to_owned),
        region: None,
        identifiers: identifiers
            .iter()
            .map(|(namespace, value)| AssetIdentifier {
                namespace: (*namespace).into(),
                value: (*value).into(),
            })
            .collect(),
        discovered_from: vec![],
        candidate: false,
        owner_confirmed: true,
        internet_exposed: None,
        contains_sensitive_data: None,
        metadata: BTreeMap::new(),
    }
}

fn normalize_fixture(engine_id: &str) -> AdapterOutput {
    let (bytes, filename, media_type) = fixture(engine_id);
    normalize_bytes(engine_id, bytes, filename, media_type, "run-1")
}

fn normalize_ai_system_fixture(engine_id: &str) -> AdapterOutput {
    let (bytes, filename, media_type) = fixture(engine_id);
    let assets = if engine_id == "prowler" {
        vec![authorized_asset(
            "asset-1",
            AssetKind::CloudAccount,
            Some("aws"),
            &[("aws_account_id", "123456789012")],
        )]
    } else {
        vec![authorized_asset("asset-1", AssetKind::Other, None, &[])]
    };
    normalize_bytes_with_assets_and_context(
        engine_id,
        media_type,
        bytes,
        filename,
        "run-ai-1",
        &assets,
        FrameworkApplicability {
            ai_system: true,
            ai_generated_artifact: false,
        },
    )
}

fn normalize_ai_generated_fixture(engine_id: &str) -> AdapterOutput {
    let (bytes, filename, media_type) = fixture(engine_id);
    let assets = vec![authorized_asset("asset-1", AssetKind::Other, None, &[])];
    normalize_bytes_with_assets_and_context(
        engine_id,
        media_type,
        bytes,
        filename,
        "run-ai-generated-1",
        &assets,
        FrameworkApplicability {
            ai_system: false,
            ai_generated_artifact: true,
        },
    )
}

#[test]
fn registry_covers_exactly_the_twenty_five_catalog_engines() {
    let catalog = EngineRegistry::load_builtin().expect("valid catalog");
    let catalog_ids = catalog
        .manifests()
        .iter()
        .map(|manifest| manifest.id.as_str())
        .collect::<BTreeSet<_>>();
    let adapter_ids = BUILTIN_ENGINE_IDS.iter().copied().collect::<BTreeSet<_>>();

    assert_eq!(BUILTIN_ENGINE_IDS.len(), 25);
    assert_eq!(adapter_ids.len(), 25);
    assert_eq!(adapter_ids, catalog_ids);

    let adapters = builtin_adapter_registry().expect("valid built-in adapter registry");
    for manifest in catalog.manifests() {
        let adapter = adapters.get(&manifest.id).expect("catalog adapter");
        assert_eq!(adapter.engine_id(), manifest.id);
        assert_eq!(adapter.adapter_version(), manifest.adapter_version);
    }
    assert!(adapters.get("not-in-catalog").is_none());

    let agentic_radar = catalog
        .get("agentic-radar")
        .expect("Agentic Radar manifest");
    assert_eq!(agentic_radar.category, EngineCategory::AiAgentFramework);
    assert!(agentic_radar.compatibility.runnable);
    assert!(!agentic_radar.default_enabled);
    let image = agentic_radar
        .image
        .as_ref()
        .expect("admitted Agentic Radar image");
    assert_eq!(image.tag.as_deref(), Some("0.14.1-1"));
    assert_eq!(
        image.digest.as_deref(),
        Some("sha256:2a8d16b9ff5ac7974b0aea8e6504219e0da295b804d01f51da0b4267d7cdafae")
    );
    assert!(agentic_radar.release_blocker().is_none());
    assert_eq!(
        agentic_radar.source_revision.as_deref(),
        Some("65a7e4bd01e2034c7cb52e9620eeed287688cc53")
    );

    let mcp_armor = catalog.get("mcp-armor").expect("MCP Armor manifest");
    assert_eq!(mcp_armor.category, EngineCategory::AiMcpConfiguration);
    assert!(mcp_armor.compatibility.runnable);
    assert!(!mcp_armor.default_enabled);
    let image = mcp_armor.image.as_ref().expect("MCP Armor image");
    assert_eq!(
        image.repository,
        "ghcr.io/teddashh/ai-security-scanner-engine-mcp-armor"
    );
    assert_eq!(image.tag.as_deref(), Some("1.0.2-config-only.1"));
    assert_eq!(
        image.digest.as_deref(),
        Some("sha256:f8dcf9b774e0f90cfbe32d81b1dc04c6b1d61538fa9829ca28c674d78440dfdc")
    );
    assert!(mcp_armor.release_blocker().is_none());
    assert_eq!(
        mcp_armor.source_revision.as_deref(),
        Some("6af4cee4665ab6242f02a88952f9127b6a04922a")
    );
}

/// Engines whose native result shape has no severity field. Their findings and
/// evidence remain useful, while the absent upstream rating stays Unknown.
///
/// Each of these was previously handed a hard-coded severity string, which
/// reached the user as `source-severity:high` or `source-severity:informational`
/// — a rating the engine never gave. Verified against the pinned checkouts: the
/// Gitleaks' finding and TruffleHog's JSON printer have no such field, and
/// kube-bench's native JSON `Check` struct has none.
const UNRATED_SEVERITY_ENGINES: &[(&str, SeverityBasisCode)] = &[
    ("kube-bench", SeverityBasisCode::CisKubernetesBenchmark),
    ("gitleaks", SeverityBasisCode::SecretPatternMatch),
    (
        "trufflehog",
        SeverityBasisCode::UnverifiedCredentialDetector,
    ),
    ("garak", SeverityBasisCode::AdversarialProbeFailureRate),
];

#[test]
fn engines_that_emit_no_severity_keep_findings_and_evidence_without_inventing_highs() {
    for (engine_id, expected_basis) in UNRATED_SEVERITY_ENGINES {
        let output = normalize_fixture(engine_id);
        assert!(
            !output.findings.is_empty(),
            "{engine_id} fixture produced nothing to check"
        );
        for finding in &output.findings {
            assert_eq!(
                finding.severity,
                Severity::Unknown,
                "{engine_id} finding {} invented {:?}",
                finding.id,
                finding.severity
            );
            assert_eq!(finding.priority, 20, "{engine_id}: {}", finding.id);
            assert_eq!(finding.severity_basis_code, Some(*expected_basis));
            assert!(
                finding
                    .tags
                    .iter()
                    .any(|tag| tag == "severity-basis:unrated"),
                "{engine_id} finding {} hides the missing scanner rating: {:?}",
                finding.id,
                finding.tags
            );
            assert!(
                !finding
                    .tags
                    .iter()
                    .any(|tag| tag == "severity-basis:derived"),
                "{engine_id} finding {} still claims a derived rating: {:?}",
                finding.id,
                finding.tags
            );
            assert!(
                !finding
                    .tags
                    .iter()
                    .any(|tag| tag.starts_with("source-severity:")),
                "{engine_id} finding {} claims a source severity the engine never emits: {:?}",
                finding.id,
                finding.tags
            );
            assert_eq!(finding.evidence.len(), 1, "{engine_id}: {}", finding.id);
            assert!(
                finding
                    .plain_language_summary
                    .contains("without a severity rating")
            );
            assert!(
                finding
                    .plain_language_summary
                    .contains("Severity is Unknown")
            );
            assert!(
                !finding
                    .plain_language_summary
                    .contains("This product rated it unknown")
            );
            assert!(!finding.possible_impact.contains("human review"));
            assert!(finding.priority_reasons.iter().any(|reason| {
                reason
                    == &format!(
                        "Severity is Unknown because {} did not provide a rating.",
                        normalize_engine_display_name(engine_id)
                    )
            }));
        }
        assert_eq!(
            output
                .findings
                .iter()
                .filter(|finding| finding.severity == Severity::High)
                .count(),
            0,
            "{engine_id} inflated the High counter"
        );
    }
}

/// Engines that report a severity for some findings and none for others, so
/// neither blanket rule applies. Each has its own test; this list exists to keep
/// them out of the two that assert one behaviour for every finding.
const MIXED_SEVERITY_ENGINES: &[&str] = &["checkov"];

/// Every finding-producing fixture whose engine supplies no confidence rating.
/// The code is grounded in the result shape the corresponding extractor reads,
/// not in an inferred upstream field that is absent from the fixture.
const DERIVED_CONFIDENCE_ENGINES: &[(&str, Confidence, ConfidenceBasisCode)] = &[
    (
        "prowler",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "scoutsuite",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "cloudsplaining",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "scubagear",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "maester",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "nuclei",
        Confidence::Medium,
        ConfidenceBasisCode::TemplateMatcher,
    ),
    (
        "gitleaks",
        Confidence::Low,
        ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch,
    ),
    (
        "trufflehog",
        Confidence::Low,
        ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch,
    ),
    (
        "checkov",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "kics",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "trivy",
        Confidence::Medium,
        ConfidenceBasisCode::AdvisoryVersionMatch,
    ),
    (
        "grype",
        Confidence::Medium,
        ConfidenceBasisCode::AdvisoryVersionMatch,
    ),
    (
        "kubescape",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
    (
        "kube-bench",
        Confidence::High,
        ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ),
];

#[test]
fn engines_without_confidence_disclose_this_products_basis() {
    for (engine_id, expected_confidence, expected_code) in DERIVED_CONFIDENCE_ENGINES {
        let output = normalize_fixture(engine_id);
        assert!(
            !output.findings.is_empty(),
            "{engine_id} fixture produced nothing to check"
        );
        for finding in &output.findings {
            let exposure_observation = finding
                .severity_basis_code
                .is_some_and(|code| code.is_exposure_observation());
            assert_eq!(&finding.confidence, expected_confidence, "{engine_id}");
            assert_eq!(
                finding.confidence_basis_code,
                Some(*expected_code),
                "{engine_id} finding {}",
                finding.id
            );
            assert!(
                finding
                    .tags
                    .iter()
                    .any(|tag| tag == "confidence-basis:derived"),
                "{engine_id}: {:?}",
                finding.tags
            );
            assert!(
                !finding
                    .tags
                    .iter()
                    .any(|tag| tag.starts_with("source-confidence:")),
                "{engine_id} claims an engine confidence: {:?}",
                finding.tags
            );
            let basis = ai_security_scanner_lib::finding_narrative::confidence_basis_english(
                *expected_code,
            );
            if exposure_observation {
                assert_eq!(finding.priority, 0);
                assert!(
                    finding
                        .plain_language_summary
                        .contains("inventory evidence")
                );
            } else {
                assert!(finding.priority_reasons.iter().any(|reason| {
                    reason
                        == &format!(
                            "Confidence derived from {basis}; {} reports no confidence of its own.",
                            normalize_engine_display_name(engine_id)
                        )
                }));
                assert!(
                    finding
                        .plain_language_summary
                        .contains("reported no confidence rating for it"),
                    "{engine_id}: {}",
                    finding.plain_language_summary
                );
                assert!(
                    finding.plain_language_summary.contains(basis),
                    "{engine_id}: {}",
                    finding.plain_language_summary
                );
            }
        }
    }
}

fn normalize_engine_display_name(engine_id: &str) -> String {
    let registry = EngineRegistry::load_builtin().expect("valid engine catalog");
    registry
        .get(engine_id)
        .expect("fixture engine")
        .display_name
        .clone()
}

#[test]
fn semgrep_reads_the_fixture_confidence_verbatim() {
    let output = normalize_fixture("semgrep");
    assert_eq!(output.findings.len(), 1);
    let finding = &output.findings[0];
    assert_eq!(finding.confidence, Confidence::High);
    assert_eq!(finding.confidence_basis_code, None);
    assert!(
        finding
            .tags
            .iter()
            .any(|tag| tag == "source-confidence:high"),
        "{:?}",
        finding.tags
    );
    assert!(
        finding
            .priority_reasons
            .iter()
            .any(|reason| reason == "Source confidence: HIGH")
    );
    assert!(finding.plain_language_summary.contains("confidence HIGH"));
}

#[test]
fn semgrep_without_a_source_confidence_is_an_unverified_low_confidence_match() {
    let bytes = br#"{
      "results": [{
        "check_id": "example.rule",
        "path": "src/example.py",
        "extra": {"message": "Pattern matched", "severity": "ERROR"},
        "asset_id": "asset-1"
      }],
      "errors": []
    }"#;
    let output = normalize_bytes(
        "semgrep",
        bytes,
        "semgrep-no-confidence.json",
        "application/json",
        "run-semgrep-no-confidence",
    );
    assert_eq!(output.findings.len(), 1);
    let finding = &output.findings[0];
    assert_eq!(finding.confidence, Confidence::Low);
    assert_eq!(
        finding.confidence_basis_code,
        Some(ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch)
    );
    assert!(
        !finding
            .tags
            .iter()
            .any(|tag| tag.starts_with("source-confidence:"))
    );
}

#[test]
fn trivy_confidence_follows_each_result_kind_instead_of_one_engine_default() {
    let bytes = br#"{
      "Results": [{
        "Target": "example:latest",
        "Vulnerabilities": [{
          "VulnerabilityID": "CVE-2026-0001",
          "PkgName": "libexample",
          "Severity": "HIGH",
          "Title": "Advisory match"
        }],
        "Misconfigurations": [{
          "ID": "CFG-1",
          "Severity": "HIGH",
          "Title": "Configuration failure"
        }],
        "Secrets": [{
          "RuleID": "SECRET-1",
          "Severity": "HIGH",
          "Title": "Secret pattern"
        }],
        "asset_id": "asset-1"
      }]
    }"#;
    let output = normalize_bytes(
        "trivy",
        bytes,
        "trivy-confidence-kinds.json",
        "application/json",
        "run-trivy-confidence-kinds",
    );
    assert_eq!(output.findings.len(), 3);
    let by_title = output
        .findings
        .iter()
        .map(|finding| (finding.title.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    for (title, confidence, basis) in [
        (
            "Advisory match",
            Confidence::Medium,
            ConfidenceBasisCode::AdvisoryVersionMatch,
        ),
        (
            "Configuration failure",
            Confidence::High,
            ConfidenceBasisCode::DeterministicPolicyEvaluation,
        ),
        (
            "Secret pattern",
            Confidence::Low,
            ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch,
        ),
    ] {
        let finding = by_title[title];
        assert_eq!(finding.confidence, confidence, "{title}");
        assert_eq!(finding.confidence_basis_code, Some(basis), "{title}");
    }
}

#[test]
fn trivy_combines_lockfile_and_individual_package_artifacts() {
    let lockfile = br#"{
      "Results": [{
        "Target": "package-lock.json",
        "Class": "lang-pkgs",
        "Type": "npm",
        "Vulnerabilities": [{
          "VulnerabilityID": "CVE-2021-23337",
          "PkgName": "lodash",
          "InstalledVersion": "4.17.20",
          "Severity": "HIGH"
        }],
        "asset_id": "asset-1"
      }]
    }"#;
    let individual_package = br#"{
      "Results": [{
        "Target": "Java",
        "Class": "lang-pkgs",
        "Type": "jar",
        "Vulnerabilities": [{
          "VulnerabilityID": "CVE-2024-23672",
          "PkgName": "org.apache.tomcat.embed:tomcat-embed-websocket",
          "InstalledVersion": "9.0.65",
          "Severity": "MEDIUM"
        }],
        "asset_id": "asset-1"
      }]
    }"#;
    let temp = tempfile::tempdir().expect("temporary artifact root");
    let run_id = "run-trivy-split-profiles";
    let engine_run_id = "engine-run-trivy-split-profiles";
    let mut raw_artifacts = Vec::new();
    for (id, filename, bytes) in [
        (
            "artifact-trivy-lockfiles",
            "trivy.json",
            lockfile.as_slice(),
        ),
        (
            "artifact-trivy-individual-packages",
            "trivy-individual-packages.json",
            individual_package.as_slice(),
        ),
    ] {
        std::fs::write(temp.path().join(filename), bytes).expect("write Trivy fixture artifact");
        raw_artifacts.push(RawArtifact {
            id: id.into(),
            case_id: "case-1".into(),
            run_id: run_id.into(),
            engine_run_id: engine_run_id.into(),
            relative_path: filename.into(),
            media_type: "application/json".into(),
            sha256: hex::encode(Sha256::digest(bytes)),
            byte_length: bytes.len() as u64,
            created_at: Utc
                .with_ymd_and_hms(2026, 9, 9, 12, 0, 0)
                .single()
                .expect("fixed timestamp"),
            contains_sensitive_data: false,
        });
    }

    let registry = EngineRegistry::load_builtin().expect("valid engine catalog");
    let manifest = registry.get("trivy").expect("Trivy manifest");
    let assets = vec![authorized_asset("asset-1", AssetKind::Other, None, &[])];
    let asset_ids = vec!["asset-1".into()];
    let asset_identifier_map = AdapterAssetIdentifierMap::from_assets(&assets);
    let input = AdapterInput {
        case_id: "case-1",
        scan_run_id: run_id,
        engine_run_id,
        manifest,
        ai_system_applicable: false,
        ai_generated_artifact_applicable: false,
        asset_ids: &asset_ids,
        asset_identifier_map: &asset_identifier_map,
        artifact_root: temp.path(),
        raw_artifacts: &raw_artifacts,
    };
    let output = builtin_adapter_registry()
        .expect("valid built-in adapters")
        .normalize(&input)
        .expect("normalize both Trivy artifacts")
        .expect("Trivy adapter");

    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 2);
    let source_rules = output
        .findings
        .iter()
        .flat_map(|finding| finding.evidence.iter())
        .filter_map(|evidence| evidence.source_rule.as_deref())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        source_rules,
        BTreeSet::from(["CVE-2021-23337", "CVE-2024-23672"])
    );
    let artifact_ids = output
        .findings
        .iter()
        .flat_map(|finding| finding.evidence.iter())
        .map(|evidence| evidence.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        artifact_ids,
        BTreeSet::from([
            "artifact-trivy-individual-packages",
            "artifact-trivy-lockfiles",
        ])
    );
}

#[test]
fn trivy_companion_envelope_without_results_does_not_withhold_completion() {
    let primary = br#"{
      "SchemaVersion": 2,
      "Results": [{
        "Target": "package-lock.json",
        "Class": "lang-pkgs",
        "Type": "npm",
        "Vulnerabilities": [{
          "VulnerabilityID": "CVE-2021-23337",
          "PkgName": "lodash",
          "InstalledVersion": "4.17.20",
          "Severity": "HIGH"
        }],
        "asset_id": "asset-1"
      }]
    }"#;
    let companion = br#"{
      "SchemaVersion": 2,
      "CreatedAt": "2026-09-18T12:00:00.123456789Z",
      "ArtifactName": ".",
      "ArtifactType": "filesystem",
      "Metadata": {
        "ImageConfig": {
          "architecture": "",
          "created": "0001-01-01T00:00:00Z",
          "os": ""
        }
      }
    }"#;
    let temp = tempfile::tempdir().expect("temporary artifact root");
    let run_id = "run-trivy-empty-companion";
    let engine_run_id = "engine-run-trivy-empty-companion";
    let mut raw_artifacts = Vec::new();
    for (id, filename, bytes) in [
        ("artifact-trivy-lockfiles", "trivy.json", primary.as_slice()),
        (
            "artifact-trivy-individual-packages",
            "trivy-individual-packages.json",
            companion.as_slice(),
        ),
    ] {
        std::fs::write(temp.path().join(filename), bytes).expect("write Trivy fixture artifact");
        raw_artifacts.push(RawArtifact {
            id: id.into(),
            case_id: "case-1".into(),
            run_id: run_id.into(),
            engine_run_id: engine_run_id.into(),
            relative_path: filename.into(),
            media_type: "application/json".into(),
            sha256: hex::encode(Sha256::digest(bytes)),
            byte_length: bytes.len() as u64,
            created_at: Utc
                .with_ymd_and_hms(2026, 9, 9, 12, 0, 0)
                .single()
                .expect("fixed timestamp"),
            contains_sensitive_data: false,
        });
    }

    let registry = EngineRegistry::load_builtin().expect("valid engine catalog");
    let manifest = registry.get("trivy").expect("Trivy manifest");
    let assets = vec![authorized_asset("asset-1", AssetKind::Other, None, &[])];
    let asset_ids = vec!["asset-1".into()];
    let asset_identifier_map = AdapterAssetIdentifierMap::from_assets(&assets);
    let input = AdapterInput {
        case_id: "case-1",
        scan_run_id: run_id,
        engine_run_id,
        manifest,
        ai_system_applicable: false,
        ai_generated_artifact_applicable: false,
        asset_ids: &asset_ids,
        asset_identifier_map: &asset_identifier_map,
        artifact_root: temp.path(),
        raw_artifacts: &raw_artifacts,
    };
    let output = builtin_adapter_registry()
        .expect("valid built-in adapters")
        .normalize(&input)
        .expect("normalize both Trivy artifacts")
        .expect("Trivy adapter");

    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 1);
    let source_rules = output
        .findings
        .iter()
        .flat_map(|finding| finding.evidence.iter())
        .filter_map(|evidence| evidence.source_rule.as_deref())
        .collect::<BTreeSet<_>>();
    assert_eq!(source_rules, BTreeSet::from(["CVE-2021-23337"]));
    let artifact_ids = output
        .findings
        .iter()
        .flat_map(|finding| finding.evidence.iter())
        .map(|evidence| evidence.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(artifact_ids, BTreeSet::from(["artifact-trivy-lockfiles"]));
    assert!(
        output
            .warnings
            .iter()
            .all(|warning| !warning.contains("pinned JSON reporter")),
        "empty companion was treated as a broken reporter: {:?}",
        output.warnings
    );
}

#[test]
fn finding_written_before_confidence_basis_codes_still_loads_without_one() {
    let finding = normalize_fixture("gitleaks")
        .findings
        .into_iter()
        .next()
        .expect("fixture finding");
    let mut encoded = serde_json::to_value(finding).expect("serialize finding");
    encoded
        .as_object_mut()
        .expect("finding object")
        .remove("confidence_basis_code");
    let decoded: Finding = serde_json::from_value(encoded).expect("load legacy finding");
    assert_eq!(decoded.confidence_basis_code, None);
}

#[test]
fn greenbone_qod_bands_are_source_confidence_and_absence_stays_unknown() {
    let bytes = br#"<?xml version="1.0"?>
<get_reports_response><report><results>
  <result id="high"><name>High QoD</name><host>192.0.2.1</host><severity>5.0</severity><qod><value>95</value></qod><nvt oid="1.3.6.1.4.1.1"><name>High QoD</name></nvt></result>
  <result id="medium"><name>Medium QoD</name><host>192.0.2.2</host><severity>5.0</severity><qod><value>65</value></qod><nvt oid="1.3.6.1.4.1.2"><name>Medium QoD</name></nvt></result>
  <result id="low"><name>Low QoD</name><host>192.0.2.3</host><severity>5.0</severity><qod><value>25</value></qod><nvt oid="1.3.6.1.4.1.3"><name>Low QoD</name></nvt></result>
  <result id="absent"><name>Absent QoD</name><host>192.0.2.4</host><severity>5.0</severity><nvt oid="1.3.6.1.4.1.4"><name>Absent QoD</name></nvt></result>
</results></report></get_reports_response>"#;
    let output = normalize_bytes(
        "greenbone",
        bytes,
        "greenbone-qod.xml",
        "application/xml",
        "run-greenbone-qod",
    );
    assert!(output.complete, "{:?}", output.warnings);
    let by_title = output
        .findings
        .iter()
        .map(|finding| (finding.title.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    for (title, source, expected) in [
        ("High QoD", "95", Confidence::High),
        ("Medium QoD", "65", Confidence::Medium),
        ("Low QoD", "25", Confidence::Low),
    ] {
        let finding = by_title[title];
        assert_eq!(finding.confidence, expected, "{title}");
        assert_eq!(finding.confidence_basis_code, None, "{title}");
        assert!(
            finding
                .priority_reasons
                .iter()
                .any(|reason| reason == &format!("Source confidence: {source}"))
        );
    }
    let absent = by_title["Absent QoD"];
    assert_eq!(absent.confidence, Confidence::Unknown);
    assert_eq!(
        absent.confidence_basis_code,
        Some(ConfidenceBasisCode::MissingDetectionQualityScore)
    );
    assert!(
        absent
            .priority_reasons
            .iter()
            .any(|reason| reason
                == "Greenbone Community Edition did not report detection quality.")
    );
    assert!(
        absent
            .plain_language_summary
            .contains("Greenbone Community Edition did not report detection quality for it.")
    );
    assert!(
        !absent
            .plain_language_summary
            .contains("This product rated its confidence")
    );
    assert!(
        absent
            .tags
            .iter()
            .any(|tag| tag == "confidence-basis:unavailable")
    );
    assert!(absent.tags.iter().all(|tag| {
        tag != "confidence-basis:derived"
            && !tag.starts_with("source-confidence:")
            && !tag.starts_with("quality-of-detection:")
    }));
}

#[test]
fn greenbone_result_types_preserve_alarms_and_normalize_unevaluated_targets() {
    let bytes = include_bytes!("fixtures/adapters/greenbone-result-types.xml");
    let output = normalize_bytes(
        "greenbone",
        bytes,
        "greenbone-result-types.xml",
        "application/xml",
        "run-greenbone-result-types",
    );

    assert_eq!(output.findings.len(), 2, "{:?}", output.warnings);
    let by_title = output
        .findings
        .iter()
        .map(|finding| (finding.title.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let rated = by_title["Rated Greenbone alarm NVT"];
    assert_eq!(rated.severity, Severity::High);
    assert_eq!(rated.severity_basis_code, None);

    let unrated = by_title["Unrated Greenbone alarm NVT"];
    assert_eq!(unrated.severity, Severity::Unknown);
    assert_eq!(
        unrated.severity_basis_code,
        Some(SeverityBasisCode::UnratedVulnerabilityTestAlarm)
    );
    // An alarm without a rating follows the product's unrated path: severity
    // stays Unknown and is never presented as a rating this product derived.
    assert!(
        unrated
            .tags
            .iter()
            .any(|tag| tag == "severity-basis:unrated"),
        "{:?}",
        unrated.tags
    );
    assert!(
        unrated.priority_reasons.iter().any(|reason| {
            reason
                == "Severity is Unknown because Greenbone Community Edition did not provide a rating."
        }),
        "{:?}",
        unrated.priority_reasons
    );
    assert!(
        unrated
            .plain_language_summary
            .contains("Severity is Unknown."),
        "{}",
        unrated.plain_language_summary
    );
    assert!(
        unrated
            .official_references
            .iter()
            .any(|reference| reference.ends_with("CVE-2026-1002"))
    );
    assert_eq!(unrated.asset_ids, vec!["asset-1".to_owned()]);
    assert_eq!(unrated.evidence.len(), 1);
    assert_eq!(
        unrated.evidence[0].kind,
        ai_security_scanner_lib::domain::EvidenceKind::ExternalValidation
    );
    assert_eq!(
        unrated.evidence[0].location.as_deref(),
        Some("203.0.113.10:8443/tcp")
    );
    assert!(
        unrated.evidence[0]
            .summary
            .contains("203.0.113.10:8443/tcp")
    );
    let details = unrated.evidence[0]
        .scanner_details
        .as_ref()
        .expect("unrated alarm pinned-feed details");
    assert_eq!(
        details.description.as_deref(),
        Some("Unrated pinned-feed summary.")
    );
    assert_eq!(
        details.remediation.as_deref(),
        Some("Apply the unrated alarm solution.")
    );

    assert_eq!(
        output.unevaluated_targets,
        vec![
            UnevaluatedTarget {
                asset_id: "asset-1".into(),
                cause: UnevaluatedTargetCause::TargetDidNotRespond,
                result_count: 1,
            },
            UnevaluatedTarget {
                asset_id: "asset-1".into(),
                cause: UnevaluatedTargetCause::ScannerError,
                result_count: 2,
            },
        ]
    );
    assert!(output.complete, "{:?}", output.warnings);
    assert_eq!(
        output.warnings,
        [
            "Greenbone reported that the host did not respond, so none of its vulnerability checks ran for that target",
            "Greenbone reported scanner errors for the target, so some of its checks did not finish",
        ]
    );
    assert!(
        output
            .warnings
            .iter()
            .all(|warning| !warning.contains("lacked a valid NVT OID")),
        "{:?}",
        output.warnings
    );
    let serialized = serde_json::to_string(&output.findings).expect("serialize findings");
    assert!(!serialized.contains("Informational Greenbone log"));
    assert!(!serialized.contains("Greenbone error"));
    assert!(!serialized.contains("Greenbone dead_host"));
    assert!(!serialized.contains("TARGET_CONTROLLED"));
}

#[test]
fn greenbone_unevaluated_target_requires_an_authorized_asset() {
    let xml = br#"<?xml version="1.0" encoding="UTF-8"?><get_reports_response><report><results><result id="dead"><name>Greenbone dead_host</name><host>203.0.113.10</host><port>0/tcp</port><result_type> DeAd_HoSt </result_type><severity>0.0</severity><threat>Log</threat><asset_id>not-authorized</asset_id><summary></summary><description>TARGET_CONTROLLED_UNAUTHORIZED_SENTINEL</description><solution></solution><raw_host>127.0.0.1</raw_host><raw_port>0/tcp</raw_port><relay_mapping>managed-socks5</relay_mapping><scope_grant_id>grant-1</scope_grant_id></result></results></report></get_reports_response>"#;
    let output = normalize_bytes(
        "greenbone",
        xml,
        "greenbone-unauthorized-dead-host.xml",
        "application/xml",
        "run-greenbone-unauthorized-dead-host",
    );

    assert!(output.findings.is_empty());
    // The dead host named no authorized asset, so it is not attributed. The
    // authorized asset still has no result on any approved port.
    assert_eq!(
        output.unevaluated_targets,
        [UnevaluatedTarget {
            asset_id: "asset-1".into(),
            cause: UnevaluatedTargetCause::NoServiceIdentified,
            result_count: 0,
        }]
    );
    assert!(!output.complete);
    assert_eq!(
        output.warnings,
        [
            "Greenbone reported a target it could not evaluate, but the result named no authorized asset; the raw artifact was retained"
        ]
    );
    assert!(
        output
            .warnings
            .iter()
            .all(|warning| !warning.contains("TARGET_CONTROLLED")),
        "{:?}",
        output.warnings
    );
}

#[test]
fn greenbone_unsupported_result_type_is_raw_evidence_and_incomplete() {
    let xml = br#"<?xml version="1.0" encoding="UTF-8"?><get_reports_response><report><results><result id="detail"><name>Host detail</name><host>203.0.113.10</host><port>0/tcp</port><result_type> HoSt_DeTaIl </result_type><severity>0.0</severity><threat>Log</threat><asset_id>asset-1</asset_id><summary></summary><description>Target detail</description><solution></solution><raw_host>127.0.0.1</raw_host><raw_port>0/tcp</raw_port><relay_mapping>managed-socks5</relay_mapping><scope_grant_id>grant-1</scope_grant_id></result></results></report></get_reports_response>"#;
    let output = normalize_bytes(
        "greenbone",
        xml,
        "greenbone-unsupported-result-type.xml",
        "application/xml",
        "run-greenbone-unsupported-result-type",
    );

    assert!(output.findings.is_empty());
    assert_eq!(
        output.unevaluated_targets,
        [UnevaluatedTarget {
            asset_id: "asset-1".into(),
            cause: UnevaluatedTargetCause::NoServiceIdentified,
            result_count: 0,
        }]
    );
    assert!(!output.complete);
    assert_eq!(
        output.warnings,
        [
            "Greenbone result carried an unsupported upstream result type and was retained only as raw evidence"
        ]
    );
}

#[test]
fn greenbone_legacy_ambiguous_result_is_not_clean_but_log_stays_silent() {
    let ambiguous = br#"<?xml version="1.0"?><get_reports_response><report><results><result id="ambiguous"><name>Legacy ambiguous result</name><host>203.0.113.10</host><port>443/tcp</port><severity>0.0</severity><threat>Unknown</threat><asset_id>asset-1</asset_id><summary>Legacy summary</summary><description>Target observation</description><solution>Legacy solution</solution><raw_host>127.0.0.1</raw_host><raw_port>30001/tcp</raw_port><relay_mapping>managed-socks5</relay_mapping><scope_grant_id>grant-1</scope_grant_id><qod><value>80</value></qod><nvt oid="1.3.6.1.4.1.25623.1.0.100005"><name>Legacy ambiguous NVT</name><family>General</family><refs></refs></nvt></result></results></report></get_reports_response>"#;
    let ambiguous_output = normalize_bytes(
        "greenbone",
        ambiguous,
        "greenbone-legacy-ambiguous.xml",
        "application/xml",
        "run-greenbone-legacy-ambiguous",
    );
    assert!(ambiguous_output.findings.is_empty());
    assert!(!ambiguous_output.complete);
    assert_eq!(
        ambiguous_output.warnings,
        [
            "Greenbone result lacked an upstream result type and a positive severity; it was retained only as raw evidence and this run cannot be treated as a clean result"
        ]
    );

    let log = br#"<?xml version="1.0"?><get_reports_response><report><results><result id="log"><name>Legacy log</name><host>203.0.113.10</host><port>443/tcp</port><severity>0.0</severity><threat>Log</threat><asset_id>asset-1</asset_id><summary></summary><description>Target log</description><solution></solution><raw_host>127.0.0.1</raw_host><raw_port>30001/tcp</raw_port><relay_mapping>managed-socks5</relay_mapping><scope_grant_id>grant-1</scope_grant_id><qod><value>80</value></qod><nvt oid="1.3.6.1.4.1.25623.1.0.100006"><name>Legacy log NVT</name><family>General</family><refs></refs></nvt></result></results></report></get_reports_response>"#;
    let log_output = normalize_bytes(
        "greenbone",
        log,
        "greenbone-legacy-log.xml",
        "application/xml",
        "run-greenbone-legacy-log",
    );
    assert!(log_output.findings.is_empty());
    assert!(log_output.complete, "{:?}", log_output.warnings);
    assert!(log_output.warnings.is_empty());
}

/// The other side of the same contract. Deriving a severity is only defensible
/// where the engine truly reports none, so an engine that does report one must
/// keep showing what it said.
#[test]
fn engines_that_report_a_severity_still_present_the_engines_own_rating() {
    let exempt = UNRATED_SEVERITY_ENGINES
        .iter()
        .map(|(engine_id, _)| *engine_id)
        .chain(MIXED_SEVERITY_ENGINES.iter().copied())
        .collect::<BTreeSet<_>>();
    let mut checked = 0;
    for engine_id in BUILTIN_ENGINE_IDS {
        if exempt.contains(engine_id) {
            continue;
        }
        for finding in normalize_fixture(engine_id).findings {
            assert!(
                !finding
                    .tags
                    .iter()
                    .any(|tag| tag == "severity-basis:derived"),
                "{engine_id} finding {} replaced a reported severity with a derived one: {:?}",
                finding.id,
                finding.tags
            );
            assert!(
                finding.tags.iter().any(|tag| {
                    tag.strip_prefix("source-severity:")
                        .is_some_and(|value| !value.is_empty())
                }),
                "{engine_id} finding {} reports no severity and no basis: {:?}",
                finding.id,
                finding.tags
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 15,
        "expected the reporting engines' findings to be checked, saw {checked}"
    );
}

/// TruffleHog runs with `--no-verification`, and the engine short-circuits
/// before any detector performs its check, so `Verified` is always false. A
/// `verified:false` tag reads as "checked and rejected"; the finding says
/// verification was never attempted instead.
#[test]
fn trufflehog_findings_say_verification_was_not_attempted_rather_than_failed() {
    let output = normalize_fixture("trufflehog");
    assert!(!output.findings.is_empty());
    for finding in &output.findings {
        assert!(
            finding
                .tags
                .iter()
                .any(|tag| tag == "verification:not-attempted"),
            "{:?}",
            finding.tags
        );
        assert!(
            !finding.tags.iter().any(|tag| tag.starts_with("verified:")),
            "a never-performed check is reported as a failed one: {:?}",
            finding.tags
        );
        assert_ne!(
            finding.confidence,
            Confidence::Confirmed,
            "nothing was confirmed; verification did not run"
        );
    }
}

#[test]
fn native_fixtures_normalize_without_inventing_inventory_findings() {
    let inventory_engines = BTreeSet::from([
        "cloudquery",
        "steampipe",
        "syft",
        "naabu",
        "httpx",
        "agentic-radar",
    ]);
    for engine_id in BUILTIN_ENGINE_IDS {
        let output = normalize_fixture(engine_id);
        assert_eq!(
            output.complete,
            *engine_id != "kube-bench",
            "{engine_id}: the kube-bench fixture includes manual WARN checks"
        );
        if inventory_engines.contains(engine_id) {
            assert!(
                output.findings.is_empty(),
                "{engine_id} must not put inventory into the finding pipeline"
            );
            assert!(
                !output.observations.is_empty(),
                "{engine_id} must retain its typed upstream inventory"
            );
            continue;
        }

        assert!(output.observations.is_empty(), "{engine_id}");
        assert!(
            !output.findings.is_empty(),
            "native fixture for {engine_id} should produce a finding"
        );
        for finding in output.findings {
            let exposure_observation = finding
                .severity_basis_code
                .is_some_and(|code| code.is_exposure_observation());
            assert_eq!(finding.status, FindingStatus::Unreviewed);
            assert_eq!(finding.case_id, "case-1");
            assert_eq!(finding.last_seen_run_id, "run-1");
            assert_eq!(finding.asset_ids, ["asset-1"]);
            assert!(!finding.plain_language_summary.is_empty());
            // The summary interpolates the severity, so the article in front of
            // it has to be chosen with it. "Nuclei reported a informational-
            // severity condition" was the first sentence a beginner read about
            // every unrated Nuclei result.
            for ungrammatical in [" a informational", " a unknown"] {
                assert!(
                    !finding.plain_language_summary.contains(ungrammatical),
                    "{engine_id} summary is not English: {}",
                    finding.plain_language_summary
                );
            }
            assert!(!finding.possible_impact.is_empty());
            assert!(!finding.recommendation.is_empty());
            if exposure_observation {
                assert_eq!(finding.priority, 0);
                assert!(
                    finding
                        .possible_impact
                        .contains("does not establish a vulnerability")
                );
                assert!(
                    finding
                        .recommendation
                        .starts_with("Confirm that the reachable service")
                );
                assert!(finding.recommendation.contains("applicable security check"));
                assert!(finding.rollback_considerations.is_none());
            } else {
                assert!(!finding.recommendation.contains("recommended specialist"));
                assert!(!finding.recommendation.contains("plan and approve"));
                assert!(finding.rollback_considerations.is_some());
            }
            assert!(!finding.verification_guidance.is_empty());
            // Deliberately not `!is_empty()`: `merge_finding` seeds this list
            // with the manifest's own repository URL before any engine
            // reference is considered, so an emptiness check here can never
            // fail -- it stays green with every JSON pointer deleted.
            assert!(
                finding
                    .official_references
                    .iter()
                    .all(|reference| reference.starts_with("https://")),
                "{engine_id} kept a reference that is not a plain https URL: {:?}",
                finding.official_references
            );
            assert!(!finding.recommended_expert_type.is_empty());
            assert!(
                finding
                    .tags
                    .iter()
                    .any(|tag| tag == &format!("engine:{engine_id}"))
            );
            assert!(
                finding
                    .tags
                    .iter()
                    .any(|tag| tag.starts_with("source-rule:"))
            );
            // Every finding states exactly once whether the scanner supplied a
            // rating, this product derived one, or the scanner left it unrated
            // and the canonical value therefore remains Unknown.
            let reported = finding
                .tags
                .iter()
                .filter(|tag| tag.starts_with("source-severity:"))
                .count();
            let derived = finding
                .tags
                .iter()
                .filter(|tag| tag.as_str() == "severity-basis:derived")
                .count();
            let unrated = finding
                .tags
                .iter()
                .filter(|tag| tag.as_str() == "severity-basis:unrated")
                .count();
            assert_eq!(
                reported + derived + unrated,
                1,
                "{engine_id} finding {} has {reported} source, {derived} derived, and {unrated} unrated severity tags",
                finding.id
            );
            let reported_confidence = finding
                .tags
                .iter()
                .filter(|tag| tag.starts_with("source-confidence:"))
                .count();
            let derived_confidence = finding
                .tags
                .iter()
                .filter(|tag| tag.as_str() == "confidence-basis:derived")
                .count();
            assert_eq!(
                reported_confidence + derived_confidence,
                1,
                "{engine_id} finding {} has {reported_confidence} source-confidence and {derived_confidence} derived tags",
                finding.id
            );
            assert!(!finding.evidence.is_empty());
            assert!(finding.evidence.iter().all(|evidence| {
                evidence.artifact_id == format!("artifact-{engine_id}")
                    && !evidence.artifact_sha256.is_empty()
                    && evidence.pointer.is_some()
            }));
        }
    }
}

#[test]
fn maester_fixture_keeps_investigate_as_manual_review_not_a_finding() {
    let output = normalize_fixture("maester");
    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 1, "only Failed is a finding");
    assert_eq!(
        output.findings[0].evidence[0].source_rule.as_deref(),
        Some("MT.1001")
    );
    assert_eq!(output.manual_review_controls.len(), 1);
    let review = &output.manual_review_controls[0];
    assert_eq!(review.asset_id, "asset-1");
    assert_eq!(review.rule_id, "MT.1003");
    assert_eq!(
        review.title,
        "Legacy multifactor authentication methods need review"
    );
    assert_eq!(
        review.detail.as_deref(),
        Some("Confirm whether the remaining legacy methods are assigned to active users.")
    );
}

#[test]
fn maester_failed_and_investigate_verdicts_take_separate_typed_paths() {
    let document = serde_json::json!({
        "Engine": "Maester",
        "Diagnostics": {
            "passes": 0, "failures": 1, "investigate": 1, "errors": 0,
            "skipped": 0, "not_run": 0, "total": 2, "normalized_results": 2
        },
        "Results": [
            { "Id": "MT.FAIL", "Title": "Confirmed failure", "Result": "Failed",
              "Severity": "high", "asset_id": "asset-1" },
            { "Id": "MT.REVIEW", "Title": "Needs a person", "Result": "Investigate",
              "ReviewDetail": "Compare this setting with the tenant's exception record.",
              "asset_id": "asset-1" }
        ]
    });
    let bytes = serde_json::to_vec(&document).unwrap();
    let output = normalize_bytes(
        "maester",
        &bytes,
        "attempt-1/output/maester.json",
        "application/json",
        "run-maester-verdicts",
    );

    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.manual_review_controls.len(), 1);
    assert_eq!(output.manual_review_controls[0].rule_id, "MT.REVIEW");
    assert!(
        output
            .findings
            .iter()
            .all(|finding| finding.title != "Needs a person"),
        "an Investigate verdict was promoted to a vulnerability finding"
    );
}

#[test]
fn maester_investigate_without_review_detail_remains_visible() {
    let document = serde_json::json!({
        "Engine": "Maester",
        "Diagnostics": {
            "passes": 0, "failures": 0, "investigate": 1, "errors": 0,
            "skipped": 0, "not_run": 0, "total": 1, "normalized_results": 1
        },
        "Results": [
            { "Id": "MT.REVIEW", "Title": "Needs a person", "Result": "Investigate",
              "ReviewDetail": "", "asset_id": "asset-1" }
        ]
    });
    let bytes = serde_json::to_vec(&document).unwrap();
    let output = normalize_bytes(
        "maester",
        &bytes,
        "attempt-1/output/maester.json",
        "application/json",
        "run-maester-empty-detail",
    );

    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    assert!(output.findings.is_empty());
    assert_eq!(output.manual_review_controls.len(), 1);
    assert_eq!(output.manual_review_controls[0].detail, None);
}

#[test]
fn inventory_fixtures_preserve_typed_upstream_facts_and_exact_provenance() {
    for engine_id in [
        "cloudquery",
        "steampipe",
        "syft",
        "naabu",
        "httpx",
        "agentic-radar",
    ] {
        let output = normalize_fixture(engine_id);
        assert!(output.complete, "{engine_id}: {:?}", output.warnings);
        assert!(output.findings.is_empty(), "{engine_id}");
        assert!(!output.observations.is_empty(), "{engine_id}");
        for observation in &output.observations {
            assert_eq!(observation.case_id, "case-1");
            assert_eq!(observation.run_id, "run-1");
            assert_eq!(observation.engine_run_id, "engine-run-run-1");
            assert_eq!(observation.asset_id, "asset-1");
            assert_eq!(observation.engine_id, engine_id);
            assert_eq!(observation.artifact_id, format!("artifact-{engine_id}"));
            assert_eq!(observation.artifact_sha256.len(), 64);
            assert!(!observation.pointer.is_empty());
            assert!(!observation.pointer.chars().any(char::is_control));
            assert_eq!(
                observation.observed_at,
                Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap()
            );
        }
    }

    let cloudquery = normalize_fixture("cloudquery");
    assert!(matches!(
        &cloudquery.observations[0].kind,
        InventoryObservationKind::CloudResource {
            resource_type,
            native_id: Some(native_id),
            display_name: Some(display_name),
        } if resource_type == "aws_iam_users"
            && native_id == "arn:aws:iam::123456789012:user/example-user"
            && display_name == "example-user"
    ));
    let cloudquery_json = serde_json::to_string(&cloudquery.observations).unwrap();
    assert!(!cloudquery_json.contains("SECRET_SENTINEL_MUST_NEVER_LEAK"));
    assert!(!cloudquery_json.contains("MUST_NOT_BE_USED"));

    let steampipe = normalize_fixture("steampipe");
    assert_eq!(steampipe.observations.len(), 2);
    assert!(steampipe.observations.iter().any(|observation| matches!(
        &observation.kind,
        InventoryObservationKind::CloudResource {
            resource_type,
            native_id: Some(native_id),
            display_name: None,
        } if resource_type == "aws_iam_user"
            && native_id == "arn:aws:iam::123456789012:user/deploy-bot"
    )));
    let steampipe_json = serde_json::to_string(&steampipe.observations).unwrap();
    for policy_value in [
        "steampipe:aws_iam_user_mfa",
        "IAM user should have a registered MFA device",
        "status",
        "severity",
    ] {
        assert!(!steampipe_json.contains(policy_value), "{steampipe_json}");
    }

    let syft = normalize_fixture("syft");
    assert!(matches!(
        &syft.observations[0].kind,
        InventoryObservationKind::SoftwareComponent {
            name,
            version: Some(version),
            package_type: Some(package_type),
            purl: Some(purl),
        } if name == "example-package"
            && version == "1.0"
            && package_type == "deb"
            && purl == "pkg:deb/debian/example-package@1.0"
    ));
    assert!(
        !serde_json::to_string(&syft.observations)
            .unwrap()
            .contains("SECRET_SENTINEL_MUST_NEVER_LEAK")
    );

    let naabu = normalize_fixture("naabu");
    assert_eq!(naabu.observations.len(), 2);
    assert!(naabu.observations.iter().any(|observation| matches!(
        &observation.kind,
        InventoryObservationKind::Service {
            endpoint,
            port: Some(443),
            transport: Some(transport),
            scheme: None,
            http_status: None,
            tls: Some(true),
        } if endpoint == "192.0.2.10" && transport == "tcp"
    )));

    let httpx = normalize_fixture("httpx");
    assert_eq!(httpx.observations.len(), 2);
    assert!(httpx.observations.iter().any(|observation| matches!(
        &observation.kind,
        InventoryObservationKind::Service {
            endpoint,
            port: Some(443),
            transport: Some(transport),
            scheme: Some(scheme),
            http_status: Some(200),
            ..
        } if endpoint == "192.0.2.11" && transport == "tcp" && scheme == "https"
    )));
    let httpx_json = serde_json::to_string(&httpx.observations).unwrap();
    for forbidden in [
        "/login",
        "session=must-not-appear",
        "target-controlled text is data",
        "SECRET_SENTINEL_MUST_NEVER_LEAK",
    ] {
        assert!(!httpx_json.contains(forbidden), "{httpx_json}");
    }
}

#[test]
fn agentic_radar_normalizes_only_the_static_workflow_graph() {
    let output = normalize_fixture("agentic-radar");
    assert!(output.complete, "{:?}", output.warnings);
    assert!(output.warnings.is_empty());
    assert!(output.findings.is_empty());
    assert_eq!(output.observations.len(), 33);
    assert_eq!(
        output
            .observations
            .iter()
            .filter(|observation| matches!(
                observation.kind,
                InventoryObservationKind::WorkflowComponent { .. }
            ))
            .count(),
        20
    );
    assert_eq!(
        output
            .observations
            .iter()
            .filter(|observation| matches!(
                observation.kind,
                InventoryObservationKind::WorkflowRelationship { .. }
            ))
            .count(),
        13
    );
    assert!(output.observations.iter().any(|observation| matches!(
        &observation.kind,
        InventoryObservationKind::WorkflowComponent {
            component_type,
            name,
            model: None,
            is_guardrail: None,
        } if component_type == "mcp_server" && name == "MCP Client"
    )));
    assert!(output.observations.iter().any(|observation| matches!(
        &observation.kind,
        InventoryObservationKind::WorkflowRelationship {
            source,
            target,
            condition: None,
        } if source == "MCP Client" && target == "Personal Assistant"
    )));

    let serialized = format!(
        "{}{}{:?}",
        serde_json::to_string(&output.observations).unwrap(),
        serde_json::to_string(&output.findings).unwrap(),
        output.warnings
    );
    for excluded in [
        "description",
        "system_prompt",
        "vulnerabilities",
        "security_framework_mapping",
        "mitigation",
    ] {
        assert!(!serialized.contains(excluded), "{serialized}");
    }
}

#[test]
fn agentic_radar_structured_warnings_retain_the_partial_graph_but_fail_closed() {
    let output = normalize_bytes(
        "agentic-radar",
        include_bytes!("../../docs/research/fixtures/agentic-radar/crewai.json"),
        "agentic-radar.json",
        "application/json",
        "run-agentic-radar-partial",
    );
    assert!(!output.complete);
    assert!(output.findings.is_empty());
    assert_eq!(output.observations.len(), 7);
    assert!(output.warnings.iter().any(|warning| {
        warning.contains("Agentic Radar reported incomplete workflow inventory")
            && warning.contains("CrewAI package is not installed")
    }));
    assert!(output.observations.iter().any(|observation| matches!(
        &observation.kind,
        InventoryObservationKind::WorkflowRelationship {
            source,
            target,
            condition: Some(condition),
        } if source == "my_agent"
            && target == "server_params"
            && condition == "mcp_connection"
    )));

    let serialized = serde_json::to_string(&output.observations).unwrap();
    assert!(!serialized.contains("localhost:8001"), "{serialized}");
}

#[test]
fn agentic_radar_keeps_bounded_agent_metadata_and_accepts_its_exact_empty_state() {
    let output = normalize_bytes(
        "agentic-radar",
        include_bytes!("../../docs/research/fixtures/agentic-radar/openai-agents.json"),
        "agentic-radar.json",
        "application/json",
        "run-agentic-radar-agent",
    );
    assert!(output.complete, "{:?}", output.warnings);
    assert!(output.findings.is_empty());
    assert_eq!(output.observations.len(), 7);
    assert!(output.observations.iter().any(|observation| matches!(
        &observation.kind,
        InventoryObservationKind::WorkflowComponent {
            component_type,
            name,
            model: Some(model),
            is_guardrail: Some(false),
        } if component_type == "agent" && name == "Assistant" && model == "gpt-4o"
    )));
    let serialized = serde_json::to_string(&output.observations).unwrap();
    assert!(!serialized.contains("system_prompt"), "{serialized}");
    assert!(
        !serialized.contains("Use the tools to read the filesystem"),
        "{serialized}"
    );

    let empty = normalize_bytes(
        "agentic-radar",
        include_bytes!("../../docs/research/fixtures/agentic-radar/no-supported-workflow.json"),
        "agentic-radar.json",
        "application/json",
        "run-agentic-radar-empty",
    );
    assert!(empty.complete, "{:?}", empty.warnings);
    assert!(empty.findings.is_empty());
    assert!(empty.observations.is_empty());
}

#[test]
fn agentic_radar_never_promotes_generic_vulnerability_claims_to_findings() {
    let mut document: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../docs/research/fixtures/agentic-radar/langgraph.json"
    ))
    .unwrap();
    document["graph"]["nodes"][0]["vulnerabilities"] = serde_json::json!([{
        "name": "MUST_NOT_BECOME_A_FINDING",
        "severity": "critical",
        "mitigation": "MUST_NOT_BECOME_ADVICE"
    }]);
    let bytes = serde_json::to_vec(&document).unwrap();
    let output = normalize_bytes(
        "agentic-radar",
        &bytes,
        "agentic-radar.json",
        "application/json",
        "run-agentic-radar-generic-warning",
    );
    assert!(!output.complete);
    assert!(output.findings.is_empty());
    assert!(!output.observations.is_empty());
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("vulnerability claims; they were ignored"))
    );
    let serialized = format!(
        "{}{}{:?}",
        serde_json::to_string(&output.observations).unwrap(),
        serde_json::to_string(&output.findings).unwrap(),
        output.warnings
    );
    for excluded in [
        "MUST_NOT_BECOME_A_FINDING",
        "MUST_NOT_BECOME_ADVICE",
        "critical",
    ] {
        assert!(!serialized.contains(excluded), "{serialized}");
    }
}

#[test]
fn steampipe_current_and_pinned_legacy_rows_are_iam_user_inventory_not_findings() {
    let legacy = normalize_fixture("steampipe");
    assert!(legacy.complete, "{:?}", legacy.warnings);
    assert!(legacy.findings.is_empty());
    assert_eq!(legacy.observations.len(), 2);
    assert!(legacy.observations.iter().all(|observation| matches!(
        &observation.kind,
        InventoryObservationKind::CloudResource {
            resource_type,
            native_id: Some(native_id),
            display_name: None,
        } if resource_type == "aws_iam_user"
            && native_id.starts_with("arn:aws:iam::123456789012:user/")
    )));

    let current = normalize_bytes(
        "steampipe",
        br#"{"rows":[{"resource_type":"aws_iam_user","account_id":"123456789012","arn":"arn:aws:iam::123456789012:user/deploy-bot","user_id":"AIDAEXAMPLE","name":"deploy-bot","status":"fail","control_id":"MUST_NOT_BECOME_A_FINDING","severity":"critical","mfa_enabled":false}]}"#,
        "steampipe.json",
        "application/json",
        "run-steampipe-current",
    );
    assert!(current.complete, "{:?}", current.warnings);
    assert!(current.findings.is_empty());
    assert_eq!(current.observations.len(), 1);
    assert!(matches!(
        &current.observations[0].kind,
        InventoryObservationKind::CloudResource {
            resource_type,
            native_id: Some(native_id),
            display_name: Some(display_name),
        } if resource_type == "aws_iam_user"
            && native_id == "arn:aws:iam::123456789012:user/deploy-bot"
            && display_name == "deploy-bot"
    ));
    let serialized = serde_json::to_string(&current.observations).unwrap();
    for policy_value in ["MUST_NOT_BECOME_A_FINDING", "critical", "mfa_enabled"] {
        assert!(!serialized.contains(policy_value), "{serialized}");
    }
}

#[test]
fn steampipe_inventory_fails_closed_per_row_without_erasing_valid_siblings() {
    let partial = normalize_bytes(
        "steampipe",
        br#"{"rows":[{"resource_type":"aws_iam_user","account_id":"123456789012","user_id":"AIDAEXAMPLE","name":"valid"},42,{"resource_type":"aws_iam_user","account_id":"123456789012","name":"missing-identity"},{"asset_id":"123456789012","resource":"not-an-iam-user","control_id":"steampipe:aws_iam_user_mfa","status":"fail"}]}"#,
        "steampipe.json",
        "application/json",
        "run-steampipe-partial",
    );
    assert!(!partial.complete);
    assert!(partial.findings.is_empty());
    assert_eq!(partial.observations.len(), 1);
    assert!(
        partial
            .warnings
            .iter()
            .any(|warning| warning.contains("not an object"))
    );
    assert!(
        partial
            .warnings
            .iter()
            .any(|warning| warning.contains("lacked its IAM user ARN or user_id"))
    );
    assert!(
        partial
            .warnings
            .iter()
            .any(|warning| warning.contains("supported legacy IAM-user shape"))
    );

    let wrong_account = normalize_bytes(
        "steampipe",
        br#"{"rows":[{"resource_type":"aws_iam_user","account_id":"999999999999","arn":"arn:aws:iam::999999999999:user/elsewhere","user_id":"AIDAELSEWHERE","name":"elsewhere"}]}"#,
        "steampipe.json",
        "application/json",
        "run-steampipe-wrong-account",
    );
    assert!(!wrong_account.complete);
    assert!(wrong_account.findings.is_empty());
    assert!(wrong_account.observations.is_empty());
    assert_eq!(wrong_account.unattributed.len(), 1);
    assert_eq!(wrong_account.unattributed[0].identifier, "999999999999");
    assert!(
        wrong_account
            .warnings
            .iter()
            .any(|warning| { warning.contains("no exact authorized provider identifier match") })
    );
}

#[test]
fn malformed_steampipe_rows_cannot_hide_a_record_boundary_overflow() {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "rows": vec![serde_json::Value::Null; 10_001]
    }))
    .unwrap();
    let output = normalize_bytes(
        "steampipe",
        &bytes,
        "steampipe.json",
        "application/json",
        "run-steampipe-overflow",
    );
    assert!(!output.complete);
    assert!(output.findings.is_empty());
    assert!(output.observations.is_empty());
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("record safety boundary"))
    );
}

#[test]
fn inventory_schema_and_asset_boundaries_fail_closed_but_known_empty_shapes_complete() {
    for (engine_id, bytes, filename, media_type) in [
        (
            "cloudquery",
            br#"{}"#.as_slice(),
            "aws_s3_buckets.json",
            "application/x-ndjson",
        ),
        (
            "cloudquery",
            br#"{}"#.as_slice(),
            "aws_iam_users.json",
            "application/x-ndjson",
        ),
        ("syft", br#"{}"#.as_slice(), "syft.json", "application/json"),
        (
            "steampipe",
            br#"{}"#.as_slice(),
            "steampipe.json",
            "application/json",
        ),
    ] {
        let output = normalize_bytes(engine_id, bytes, filename, media_type, "run-invalid");
        assert!(!output.complete, "{engine_id}");
        assert!(output.findings.is_empty());
        assert!(output.observations.is_empty());
        assert!(!output.warnings.is_empty());
    }

    for (engine_id, bytes, filename, media_type) in [
        (
            "cloudquery",
            b"".as_slice(),
            "aws_iam_users.json",
            "application/x-ndjson",
        ),
        (
            "cloudquery",
            br#"[]"#.as_slice(),
            "aws_iam_users.json",
            "application/x-ndjson",
        ),
        (
            "syft",
            br#"{"artifacts":[]}"#.as_slice(),
            "syft.json",
            "application/json",
        ),
        (
            "steampipe",
            br#"{"columns":[],"rows":[]}"#.as_slice(),
            "steampipe.json",
            "application/json",
        ),
    ] {
        let output = normalize_bytes(engine_id, bytes, filename, media_type, "run-empty");
        assert!(output.complete, "{engine_id}: {:?}", output.warnings);
        assert!(output.findings.is_empty());
        assert!(output.observations.is_empty());
    }

    let assets = vec![
        authorized_asset("asset-1", AssetKind::Repository, None, &[]),
        authorized_asset("asset-2", AssetKind::Repository, None, &[]),
    ];
    let output = normalize_bytes_with_assets(
        "syft",
        br#"{"artifacts":[{"name":"component"}]}"#,
        "syft.json",
        "application/json",
        "run-multi-asset",
        &assets,
    );
    assert!(!output.complete);
    assert!(output.observations.is_empty());
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("multi-asset"))
    );

    let cleaned = normalize_bytes(
        "syft",
        br#"{"artifacts":[{"name":"component\nname","version":"1.0\tdebug"}]}"#,
        "syft.json",
        "application/json",
        "run-control-clean",
    );
    assert!(cleaned.complete, "{:?}", cleaned.warnings);
    assert!(matches!(
        &cleaned.observations[0].kind,
        InventoryObservationKind::SoftwareComponent {
            name,
            version: Some(version),
            ..
        } if name == "component name" && version == "1.0 debug"
    ));
}

fn cloud_resources(output: &AdapterOutput) -> BTreeSet<(String, String, String)> {
    output
        .observations
        .iter()
        .filter_map(|observation| match &observation.kind {
            InventoryObservationKind::CloudResource {
                resource_type,
                native_id: Some(native_id),
                display_name: Some(display_name),
            } => Some((
                resource_type.clone(),
                native_id.clone(),
                display_name.clone(),
            )),
            _ => None,
        })
        .collect()
}

/// Shapes a live AWS account produced through the pinned AWS v9.2.0 profile:
/// credential report rows have no account_id column, dependent child tables
/// arrive beside the seven selected tables, and an attached AWS managed policy
/// carries every one of its versions in a single row.
#[test]
fn cloudquery_live_table_shapes_normalize_completely() {
    let credential_reports = concat!(
        r#"{"_cq_id":"cq-report-1","arn":"arn:aws:iam::123456789012:user/example-user","user":"example-user","password_enabled":false,"mfa_active":false}"#,
        "\n",
        r#"{"_cq_id":"cq-report-2","arn":"arn:aws:iam::123456789012:root","user":"root-account","password_enabled":true,"mfa_active":true}"#,
        "\n",
    );
    let output = normalize_bytes(
        "cloudquery",
        credential_reports.as_bytes(),
        "aws_iam_credential_reports.json",
        "application/json",
        "run-credential-reports",
    );
    assert!(output.complete, "{:?}", output.warnings);
    assert_eq!(
        cloud_resources(&output),
        BTreeSet::from([
            (
                "aws_iam_credential_reports".to_owned(),
                "arn:aws:iam::123456789012:root".to_owned(),
                "root-account".to_owned(),
            ),
            (
                "aws_iam_credential_reports".to_owned(),
                "arn:aws:iam::123456789012:user/example-user".to_owned(),
                "example-user".to_owned(),
            ),
        ])
    );

    let child = normalize_bytes(
        "cloudquery",
        br#"{"_cq_id":"cq-membership-1","_cq_parent_id":"cq-user-1","account_id":"123456789012","user_arn":"arn:aws:iam::123456789012:user/example-user","group_name":"example-group"}"#,
        "aws_iam_user_groups.json",
        "application/json",
        "run-dependent-table",
    );
    assert!(child.complete, "{:?}", child.warnings);
    assert!(child.observations.is_empty());

    // Past the generic 1 MiB line bound and the 16 MiB document bound.
    let version = format!(
        r#"{{"VersionId":"v1","IsDefaultVersion":false,"Document":"{}"}}"#,
        "VERSION_HISTORY_MUST_NOT_BE_NORMALIZED ".repeat(1_700)
    );
    let versions = vec![version; 260].join(",");
    let policies = format!(
        "{}\n{}\n{}\n",
        r#"{"_cq_id":"cq-policy-1","account_id":"123456789012","arn":"arn:aws:iam::123456789012:policy/example-policy","policy_name":"example-policy","attachment_count":1,"policy_version_list":[{"VersionId":"v1","IsDefaultVersion":true}]}"#,
        format_args!(
            r#"{{"_cq_id":"cq-policy-2","account_id":"123456789012","arn":"arn:aws:iam::aws:policy/SecurityAudit","policy_name":"SecurityAudit","attachment_count":1,"policy_version_list":[{versions}],"tags":{{"owner":"aws"}}}}"#
        ),
        r#"{"_cq_id":"cq-policy-3","account_id":"123456789012","arn":"arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy","policy_name":"AWSSupportServiceRolePolicy","attachment_count":1}"#,
    );
    assert!(policies.len() > 16 * 1024 * 1024);
    let output = normalize_bytes(
        "cloudquery",
        policies.as_bytes(),
        "aws_iam_policies.json",
        "application/json",
        "run-managed-policy-versions",
    );
    assert!(output.complete, "{:?}", output.warnings);
    assert_eq!(
        cloud_resources(&output)
            .into_iter()
            .map(|(_, _, name)| name)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "AWSSupportServiceRolePolicy".to_owned(),
            "SecurityAudit".to_owned(),
            "example-policy".to_owned(),
        ])
    );
    let observations = serde_json::to_string(&output.observations).unwrap();
    assert!(!observations.contains("VERSION_HISTORY_MUST_NOT_BE_NORMALIZED"));
}

#[test]
fn cloudquery_account_fallback_is_limited_to_credential_report_arns() {
    for (bytes, filename) in [
        (
            br#"{"arn":"arn:aws:iam::123456789012:role/example-role","user":"example-role"}"#
                .as_slice(),
            "aws_iam_credential_reports.json",
        ),
        (
            br#"{"arn":"arn:aws:iam::12345678901:user/short-account","user":"short-account"}"#
                .as_slice(),
            "aws_iam_credential_reports.json",
        ),
        (
            br#"{"arn":"arn:aws:iam::123456789012:user/example-user","user_name":"example-user"}"#
                .as_slice(),
            "aws_iam_users.json",
        ),
    ] {
        let output = normalize_bytes(
            "cloudquery",
            bytes,
            filename,
            "application/json",
            "run-account-fallback",
        );
        assert!(!output.complete, "{filename}");
        assert!(output.observations.is_empty(), "{filename}");
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains("lacked its account_id")),
            "{filename}: {:?}",
            output.warnings
        );
    }
}

#[test]
fn service_inventory_uses_a_path_free_endpoint_that_report_code_can_correlate() {
    let naabu = normalize_bytes(
        "naabu",
        br#"{"host":"service.example.test","port":443,"protocol":"tcp","asset_id":"asset-1"}"#,
        "naabu.jsonl",
        "application/x-ndjson",
        "run-service-correlation",
    );
    let httpx = normalize_bytes(
        "httpx",
        br#"{"url":"https://service.example.test/login?session=SECRET","host":"service.example.test/target-path?raw=SECRET","port":443,"scheme":"https","status_code":200,"title":"SECRET_TITLE","body":"SECRET_BODY","asset_id":"asset-1"}"#,
        "httpx.jsonl",
        "application/x-ndjson",
        "run-service-correlation",
    );
    let coordinate = |kind: &InventoryObservationKind| match kind {
        InventoryObservationKind::Service { endpoint, port, .. } => (endpoint.clone(), *port),
        _ => panic!("expected service observation"),
    };
    assert_eq!(
        coordinate(&naabu.observations[0].kind),
        coordinate(&httpx.observations[0].kind)
    );
    let serialized = serde_json::to_string(&httpx.observations).unwrap();
    for forbidden in [
        "/login",
        "target-path",
        "session=SECRET",
        "raw=SECRET",
        "SECRET_TITLE",
        "SECRET_BODY",
    ] {
        assert!(!serialized.contains(forbidden), "{serialized}");
    }
}

#[test]
fn checkov_all_framework_output_preserves_each_finding_and_its_exact_pointer() {
    let bytes = br#"[
      {
        "check_type": "cloudformation",
        "results": {
          "failed_checks": [
            {
              "check_id": "CKV_AWS_20",
              "check_name": "S3 bucket allows public read",
              "file_path": "/cloudformation/storage.yaml",
              "severity": "HIGH"
            }
          ]
        }
      },
      {
        "check_type": "dockerfile",
        "results": {
          "failed_checks": [
            {
              "check_id": "CKV_DOCKER_3",
              "check_name": "Container runs as root",
              "file_path": "/Dockerfile",
              "severity": null
            }
          ]
        }
      }
    ]"#;

    let output = normalize_bytes(
        "checkov",
        bytes,
        "checkov-all-frameworks.json",
        "application/json",
        "run-checkov-all-frameworks",
    );
    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 2);

    let by_title = output
        .findings
        .iter()
        .map(|finding| (finding.title.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        by_title["S3 bucket allows public read"].evidence[0]
            .pointer
            .as_deref(),
        Some("/0/results/failed_checks/0")
    );
    assert_eq!(
        by_title["Container runs as root"].evidence[0]
            .pointer
            .as_deref(),
        Some("/1/results/failed_checks/0")
    );
    assert_eq!(
        by_title["S3 bucket allows public read"].evidence[0]
            .source_rule
            .as_deref(),
        Some("CKV_AWS_20")
    );
    assert_eq!(
        by_title["Container runs as root"].evidence[0]
            .source_rule
            .as_deref(),
        Some("CKV_DOCKER_3")
    );

    let legacy = normalize_fixture("checkov");
    assert!(legacy.complete, "legacy warnings: {:?}", legacy.warnings);
    assert!(legacy.findings.iter().all(|finding| {
        finding.evidence.iter().all(|evidence| {
            evidence
                .pointer
                .as_deref()
                .is_some_and(|pointer| pointer.starts_with("/results/failed_checks/"))
        })
    }));
}

#[test]
fn checkov_all_framework_output_contains_malformed_rows_without_losing_valid_findings() {
    let bytes = br#"[
      {
        "check_type": "cloudformation",
        "results": {
          "failed_checks": [
            {
              "check_id": "CKV_AWS_20",
              "check_name": "Valid CloudFormation finding",
              "file_path": "/template.yaml"
            },
            null,
            {"check_name": "Missing identifier", "file_path": "/broken.yaml"}
          ]
        }
      },
      "not-a-framework-report",
      {"check_type": "dockerfile", "results": {"failed_checks": {}}},
      {
        "check_type": "dockerfile",
        "results": {
          "failed_checks": [
            {
              "check_id": "CKV_DOCKER_3",
              "check_name": "Valid Dockerfile finding",
              "file_path": "/Dockerfile"
            }
          ]
        }
      }
    ]"#;

    let output = normalize_bytes(
        "checkov",
        bytes,
        "checkov-all-frameworks-malformed.json",
        "application/json",
        "run-checkov-all-frameworks-malformed",
    );
    assert_eq!(output.findings.len(), 2);
    assert!(!output.complete);
    for expected in [
        "non-object Checkov failed check at /0/results/failed_checks/1",
        "Checkov failed check at /0/results/failed_checks/2 had no valid check_id",
        "non-object Checkov framework result at /1",
        "Checkov output at /2/results/failed_checks was not an array",
    ] {
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains(expected)),
            "missing warning {expected:?}: {:?}",
            output.warnings
        );
    }
    assert!(output.findings.iter().any(|finding| {
        finding
            .evidence
            .iter()
            .any(|evidence| evidence.pointer.as_deref() == Some("/3/results/failed_checks/0"))
    }));
}

/// Checkov is the one engine that both reports severities and mostly does not.
/// `BaseCheck` hardcodes `severity = None`, and the values that fill it come
/// from platform metadata that `--skip-download` switches off; exactly one of
/// the 256 shipped graph-check YAMLs declares a severity locally. So a rating
/// Missing/null stays Unknown, while every explicit upstream value survives —
/// including a word this product cannot map, which remains traceable.
#[test]
fn checkov_preserves_explicit_ratings_and_keeps_missing_ones_unknown() {
    let bytes = br#"{
      "check_type": "terraform",
      "results": {
        "failed_checks": [
          {"check_id":"absent", "check_name":"No rating key", "file_path":"absent.tf"},
          {"check_id":"null", "check_name":"Null rating", "file_path":"null.tf", "severity":null},
          {"check_id":"medium", "check_name":"Upstream medium", "file_path":"medium.tf", "severity":"MEDIUM"},
          {"check_id":"custom", "check_name":"Custom rating", "file_path":"custom.tf", "severity":"vendor-special"},
          {"check_id":"info", "check_name":"Information only", "file_path":"info.tf", "severity":"informational"}
        ]
      }
    }"#;
    let output = normalize_bytes(
        "checkov",
        bytes,
        "checkov-severity.json",
        "application/json",
        "run-severity",
    );
    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );

    let by_title = output
        .findings
        .iter()
        .map(|finding| (finding.title.as_str(), finding))
        .collect::<BTreeMap<_, _>>();

    // An absent key and an explicit null are the same statement: the check
    // carries no rating. Both remain Unknown, and both say so.
    for title in ["No rating key", "Null rating"] {
        let finding = by_title[title];
        assert_eq!(finding.severity, Severity::Unknown, "{title}");
        assert_eq!(finding.priority, 20, "{title}");
        assert!(
            finding
                .tags
                .iter()
                .any(|tag| tag == "severity-basis:unrated"),
            "{title}: {:?}",
            finding.tags
        );
        assert!(
            !finding
                .tags
                .iter()
                .any(|tag| tag == "severity-basis:derived")
        );
        assert!(
            !finding
                .tags
                .iter()
                .any(|tag| tag.starts_with("source-severity:")),
            "{title}: {:?}",
            finding.tags
        );
        assert_eq!(finding.evidence.len(), 1, "{title}");
        assert!(
            finding
                .plain_language_summary
                .contains("Severity is Unknown")
        );
        assert!(
            !finding
                .plain_language_summary
                .contains("This product rated it unknown")
        );
    }

    // Checkov did rate these, so its words stand — including the one this
    // product cannot map, which must not be quietly upgraded to the derivation.
    assert_eq!(by_title["Upstream medium"].severity, Severity::Medium);
    assert!(
        by_title["Upstream medium"]
            .tags
            .iter()
            .any(|tag| tag == "source-severity:medium")
    );
    assert_eq!(by_title["Custom rating"].severity, Severity::Unknown);
    assert!(
        by_title["Custom rating"]
            .tags
            .iter()
            .any(|tag| tag == "source-severity:vendor-special"),
        "{:?}",
        by_title["Custom rating"].tags
    );
    assert_eq!(
        by_title["Information only"].severity,
        Severity::Informational
    );
    for title in ["Upstream medium", "Custom rating", "Information only"] {
        assert!(
            !by_title[title]
                .tags
                .iter()
                .any(|tag| tag.starts_with("severity-basis:")),
            "{title} lost the rating Checkov gave it: {:?}",
            by_title[title].tags
        );
    }
    assert_eq!(
        by_title
            .values()
            .filter(|finding| finding.severity == Severity::High)
            .count(),
        0,
        "missing Checkov ratings inflated the High counter"
    );
}

/// kube-bench's `Check` struct has no severity field and `check/` overrides no
/// `MarshalJSON`, so nothing this adapter could read would ever be populated.
/// A failed benchmark check is still a finding with direct evidence, but its
/// absent native-JSON rating remains Unknown instead of being promoted to High.
#[test]
fn kube_bench_failures_remain_findings_without_an_invented_rating() {
    let output = normalize_fixture("kube-bench");
    assert!(!output.complete, "the fixture includes five WARN checks");
    assert_eq!(output.warnings.len(), 1, "WARN checks share one disclosure");
    assert!(output.warnings[0].contains("5 left without an automated verdict"));
    assert_eq!(output.findings.len(), 6, "only failing checks are findings");

    for finding in &output.findings {
        assert_eq!(
            finding.severity,
            Severity::Unknown,
            "{} invented a rating",
            finding.title
        );
        assert_eq!(finding.priority, 20, "{}", finding.title);
        assert!(
            finding
                .tags
                .iter()
                .any(|tag| tag == "severity-basis:unrated"),
            "{} does not disclose that the scanner left severity unrated: {:?}",
            finding.title,
            finding.tags
        );
        assert!(
            !finding
                .tags
                .iter()
                .any(|tag| tag == "severity-basis:derived")
        );
        assert!(
            !finding
                .tags
                .iter()
                .any(|tag| tag.starts_with("source-severity:")),
            "{} claims a source severity kube-bench never emits: {:?}",
            finding.title,
            finding.tags
        );
        assert!(
            finding.priority_reasons.iter().any(|reason| reason
                == "Severity is Unknown because kube-bench did not provide a rating.")
        );
        assert!(
            finding
                .plain_language_summary
                .contains("without a severity rating")
        );
        assert!(!finding.possible_impact.contains("human review"));
        assert_eq!(finding.evidence.len(), 1);
    }
    assert_eq!(
        output
            .findings
            .iter()
            .filter(|finding| finding.severity == Severity::High)
            .count(),
        0,
        "kube-bench inflated the High counter"
    );

    let titles = output
        .findings
        .iter()
        .map(|finding| finding.title.as_str())
        .collect::<BTreeSet<_>>();
    assert!(
        titles.contains("Ensure that the --anonymous-auth argument is set to false (Automated)")
    );
    assert!(titles.contains(
        "Ensure that the --rotate-certificates argument is not set to false (Automated)"
    ));
    assert!(
        titles.contains(
            "Ensure that the kube-proxy metrics service is bound to localhost (Automated)"
        )
    );
    assert!(
        !titles.contains(
            "Ensure that the --authorization-mode argument is not set to AlwaysAllow (Automated)"
        ),
        "a passing check became a finding"
    );
}

#[test]
fn m365_missing_and_unrecognized_source_ratings_stay_unknown_and_traceable() {
    let cases: [(&str, &[u8], &str, &str, &str); 2] = [
        (
            "scubagear",
            br#"{
              "Engine": "ScubaGear",
              "Diagnostics": {"normalized_results": 4},
              "Results": [
                {"PolicyId":"missing", "Requirement":"Missing criticality", "Result":"Failed", "Severity":"unknown"},
                {"PolicyId":"custom", "Requirement":"Custom criticality", "Result":"Failed", "Severity":"unknown", "SourceCriticality":"Vendor-Special"},
                {"PolicyId":"lookalike", "Requirement":"Unreviewed Shall suffix", "Result":"Failed", "Severity":"unknown", "SourceCriticality":"Shall/Vendor-Special"},
                {"PolicyId":"shall", "Requirement":"Known criticality", "Result":"Failed", "Severity":"high", "SourceCriticality":"Shall/3rd Party"}
              ]
            }"#,
            "source-criticality:vendor-special",
            "source-criticality:shall/vendor-special",
            "source-criticality:shall/3rd-party",
        ),
        (
            "maester",
            br#"{
              "Engine": "Maester",
              "Diagnostics": {"normalized_results": 4},
              "Results": [
                {"Id":"missing", "Title":"Missing rating", "Result":"Failed", "Severity":"unknown"},
                {"Id":"custom", "Title":"Custom rating", "Result":"Failed", "Severity":"unknown", "SourceSeverity":"Vendor-Special"},
                {"Id":"lookalike", "Title":"Undocumented informational alias", "Result":"Failed", "Severity":"unknown", "SourceSeverity":"Informational"},
                {"Id":"info", "Title":"Known information", "Result":"Failed", "Severity":"informational", "SourceSeverity":"Info"}
              ]
            }"#,
            "source-rating:vendor-special",
            "source-rating:informational",
            "source-rating:info",
        ),
    ];

    for (engine_id, bytes, unknown_tag, lookalike_tag, known_tag) in cases {
        let output = normalize_bytes(
            engine_id,
            bytes,
            &format!("{engine_id}-source-rating.json"),
            "application/json",
            "run-m365-source-rating",
        );
        assert!(
            output.complete,
            "unexpected warnings: {:?}",
            output.warnings
        );
        assert_eq!(output.findings.len(), 4);

        let by_rule = output
            .findings
            .iter()
            .map(|finding| {
                let source_rule = finding
                    .tags
                    .iter()
                    .find_map(|tag| tag.strip_prefix("source-rule:"))
                    .expect("source rule tag");
                (source_rule, finding)
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(by_rule["missing"].severity, Severity::Unknown);
        assert_eq!(by_rule["custom"].severity, Severity::Unknown);
        assert_eq!(by_rule["lookalike"].severity, Severity::Unknown);
        assert!(by_rule["custom"].tags.iter().any(|tag| tag == unknown_tag));
        assert!(
            by_rule["lookalike"]
                .tags
                .iter()
                .any(|tag| tag == lookalike_tag)
        );
        assert!(
            output
                .findings
                .iter()
                .any(|finding| finding.tags.iter().any(|tag| tag == known_tag))
        );
        assert!(output.findings.iter().all(|finding| {
            finding
                .evidence
                .iter()
                .all(|evidence| evidence.pointer.is_some())
        }));
    }
}

#[test]
fn prowler_failure_headlines_use_result_details_with_stable_identity() {
    let base: serde_json::Value =
        serde_json::from_slice(fixture("prowler").0).expect("Prowler fixture");
    let baseline = normalize_fixture("prowler");
    let baseline = &baseline.findings[0];
    let fallback = "Prowler check iam_customer_attached_policy_no_administrative_privileges";
    let cases = [
        (
            Some("This resource failed the OCSF check."),
            Some("Legacy failure detail."),
            Some("Passing condition"),
            Some("Legacy check title"),
            "This resource failed the OCSF check.",
        ),
        (
            Some(" \t\n "),
            Some("Legacy failure detail."),
            Some("Passing condition"),
            None,
            "Legacy failure detail.",
        ),
        (
            None,
            None,
            Some("Check title fallback"),
            None,
            "Check title fallback",
        ),
        (
            None,
            Some(" "),
            Some(" "),
            Some("Legacy check title"),
            "Legacy check title",
        ),
        (None, None, None, None, fallback),
        (Some(" "), Some(" "), Some(" "), Some(" "), fallback),
    ];
    for (detail, extended, title, legacy_title, expected) in cases {
        let mut row = base[0].clone();
        row["status_detail"] = serde_json::json!(detail);
        row["StatusExtended"] = serde_json::json!(extended);
        row["finding_info"]["title"] = serde_json::json!(title);
        row["CheckTitle"] = serde_json::json!(legacy_title);
        let bytes = serde_json::to_vec(&serde_json::json!([row])).expect("serialize Prowler");
        let output = normalize_bytes(
            "prowler",
            &bytes,
            "prowler-ocsf.json",
            "application/json",
            "run-1",
        );
        assert!(output.complete, "{:?}", output.warnings);
        assert_eq!(output.findings.len(), 1);
        let finding = &output.findings[0];
        assert_eq!(finding.title, expected);
        assert_eq!(finding.fingerprint, baseline.fingerprint);
        assert_eq!(finding.id, baseline.id);
        assert_eq!(finding.severity, baseline.severity);
        assert_eq!(finding.asset_ids, baseline.asset_ids);
        assert_eq!(
            finding.evidence[0].source_rule,
            baseline.evidence[0].source_rule
        );
        assert_eq!(finding.evidence[0].pointer.as_deref(), Some("/0"));
    }

    let legacy = normalize_bytes(
        "prowler",
        br#"[{
            "Status": "FAIL",
            "CheckID": "iam_user_hardware_mfa_enabled",
            "CheckTitle": "IAM user has hardware MFA enabled",
            "StatusExtended": "User alice does not have any type of MFA enabled.",
            "Severity": "High",
            "unmapped": {"AccountId": "123456789012", "provider": "aws", "ResourceId": "alice"}
        }]"#,
        "prowler-legacy.json",
        "application/json",
        "run-legacy",
    );
    assert!(legacy.complete, "{:?}", legacy.warnings);
    assert_eq!(legacy.findings.len(), 1);
    assert_eq!(
        legacy.findings[0].title,
        "User alice does not have any type of MFA enabled."
    );
}

#[test]
fn prowler_5_39_ocsf_maps_provider_native_accounts_to_canonical_assets() {
    // Shape and field names are reduced from the pinned Prowler 5.39 OCSF
    // serializer/fixtures: status_code, metadata.event_code,
    // finding_info.analytic.uid, and cloud.account.uid/provider.
    let bytes = include_bytes!("fixtures/adapters/prowler-5.39-multi-provider.ocsf.json");
    let assets = vec![
        authorized_asset(
            "canonical-aws",
            AssetKind::CloudAccount,
            Some("aws"),
            &[("aws_account_id", "123456789012")],
        ),
        authorized_asset(
            "canonical-gcp",
            AssetKind::Project,
            Some("gcp"),
            &[("gcp_project_id", "security-prod-123")],
        ),
        authorized_asset(
            "canonical-azure",
            AssetKind::Subscription,
            Some("azure"),
            &[(
                "azure_subscription_id",
                "11111111-2222-3333-4444-555555555555",
            )],
        ),
        // Deliberately collides by value under another provider's native
        // namespace. cloud.provider must keep the GCP record exact.
        authorized_asset(
            "canonical-azure-decoy",
            AssetKind::Subscription,
            Some("azure"),
            &[("azure_subscription_id", "security-prod-123")],
        ),
    ];

    let output = normalize_bytes_with_assets(
        "prowler",
        bytes,
        "prowler-5.39-multi-provider.ocsf.json",
        "application/json",
        "run-1",
        &assets,
    );

    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    assert!(output.warnings.is_empty());
    assert_eq!(output.findings.len(), 3, "PASS and MANUAL are not failures");

    let by_asset = output
        .findings
        .iter()
        .map(|finding| (finding.asset_ids[0].as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        by_asset["canonical-aws"].title,
        "IAM Access Analyzer is not enabled"
    );
    assert_eq!(
        by_asset["canonical-gcp"].title,
        "Audit logs are not enabled for all services"
    );
    assert_eq!(
        by_asset["canonical-azure"].title,
        "Subscription has too many owners"
    );
    assert!(
        by_asset["canonical-aws"]
            .tags
            .iter()
            .any(|tag| tag == "source-rule:accessanalyzer_enabled")
    );
    assert!(
        by_asset["canonical-gcp"]
            .tags
            .iter()
            .any(|tag| tag == "source-rule:iam_audit_logs_enabled"),
        "finding_info.analytic.uid must be the fallback rule identity"
    );
    assert!(
        by_asset["canonical-azure"]
            .tags
            .iter()
            .any(|tag| tag == "source-rule:iam_subscription_owner_max_3")
    );
    assert!(!by_asset.contains_key("canonical-azure-decoy"));
    assert!(by_asset.values().all(|finding| {
        finding
            .official_references
            .iter()
            .any(|reference| reference.starts_with("https://"))
    }));

    let serialized = serde_json::to_string(&output.findings).expect("serialize findings");
    assert!(!serialized.contains("finding-instance-not-the-rule-id"));
    assert!(!serialized.contains("ignored_pass"));
    assert!(!serialized.contains("ignored_manual"));
}

#[test]
fn prowler_native_identifier_collisions_fail_closed() {
    let bytes = include_bytes!("fixtures/adapters/prowler-5.39-multi-provider.ocsf.json");
    let assets = vec![
        authorized_asset(
            "canonical-aws",
            AssetKind::CloudAccount,
            Some("aws"),
            &[("aws_account_id", "123456789012")],
        ),
        authorized_asset(
            "canonical-gcp-a",
            AssetKind::Project,
            Some("gcp"),
            &[("gcp_project_id", "security-prod-123")],
        ),
        authorized_asset(
            "canonical-gcp-b",
            AssetKind::Project,
            Some("gcp"),
            &[("gcp_project_id", "security-prod-123")],
        ),
        authorized_asset(
            "canonical-azure",
            AssetKind::Subscription,
            Some("azure"),
            &[(
                "azure_subscription_id",
                "11111111-2222-3333-4444-555555555555",
            )],
        ),
    ];

    let output = normalize_bytes_with_assets(
        "prowler",
        bytes,
        "prowler-5.39-multi-provider.ocsf.json",
        "application/json",
        "run-1",
        &assets,
    );

    assert!(!output.complete);
    assert_eq!(output.findings.len(), 2);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| { warning.contains("ambiguous native asset identifier") })
    );
    assert!(output.findings.iter().all(|finding| {
        finding.asset_ids == ["canonical-aws"] || finding.asset_ids == ["canonical-azure"]
    }));
}

#[test]
fn fingerprints_are_stable_across_repeat_runs() {
    for engine_id in ["prowler", "nuclei", "semgrep", "trivy", "kubescape"] {
        let (bytes, filename, media_type) = fixture(engine_id);
        let first = normalize_bytes(engine_id, bytes, filename, media_type, "run-1");
        let repeat = normalize_bytes(engine_id, bytes, filename, media_type, "run-2");
        let first_fingerprints = first
            .findings
            .iter()
            .map(|finding| finding.fingerprint.as_str())
            .collect::<BTreeSet<_>>();
        let repeat_fingerprints = repeat
            .findings
            .iter()
            .map(|finding| finding.fingerprint.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(first_fingerprints, repeat_fingerprints, "{engine_id}");
    }
}

#[test]
fn semgrep_lossy_rule_ids_never_gain_mapping_proof() {
    let output = normalize_bytes(
        "semgrep",
        include_bytes!("fixtures/adapters/semgrep-lossy-rule-ids.json"),
        "semgrep-lossy-rule-ids.json",
        "application/json",
        "run-lossy-rule-ids",
    );

    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 2);
    assert!(output.findings.iter().all(|finding| {
        finding.control_references.is_empty()
            && finding.evidence.iter().all(|evidence| {
                evidence.source_rule.is_none() && evidence.result_pointer_sha256.is_some()
            })
    }));
}

#[test]
fn wrapper_preserved_upstream_reports_are_not_normalized_a_second_time() {
    let bytes = include_bytes!("fixtures/adapters/scubagear.json");

    let wrapper_document = normalize_bytes(
        "scubagear",
        bytes,
        "attempt-1/output/scubagear.json",
        "application/json",
        "run-m365-upstream-routing",
    );
    assert!(
        wrapper_document.complete,
        "unexpected warnings: {:?}",
        wrapper_document.warnings
    );
    assert!(!wrapper_document.findings.is_empty());

    // Same engine, same run, byte-identical input: only the location differs.
    // The managed wrapper preserves the vendor's own report under
    // `output/upstream/` as evidence, and that copy is not a second opinion to
    // normalize. Reaching into it would misparse it, because upstream spells
    // the rule key differently than the document the wrapper owns.
    let preserved_upstream = normalize_bytes(
        "scubagear",
        bytes,
        "attempt-1/output/upstream/scubagear.json",
        "application/json",
        "run-m365-upstream-routing",
    );
    assert!(preserved_upstream.findings.is_empty());
    assert!(!preserved_upstream.complete);
    assert!(
        preserved_upstream
            .warnings
            .iter()
            .any(|warning| warning.contains("produced no raw artifacts to normalize")),
        "unexpected warnings: {:?}",
        preserved_upstream.warnings
    );
}

fn scubagear_run_with_diagnostics(diagnostics: serde_json::Value) -> AdapterOutput {
    // `Results` carries every control the wrapper normalized, passes included,
    // so it must agree with the `normalized_results` count each caller declares.
    let document = serde_json::json!({
        "Engine": "ScubaGear",
        "Diagnostics": diagnostics,
        "Results": [
            { "PolicyId": "MS.AAD.1.1v1", "Result": "Failed",
              "Criticality": "Shall", "Requirement": "Block legacy authentication." },
            { "PolicyId": "MS.AAD.2.1v1", "Result": "Pass",
              "Criticality": "Shall", "Requirement": "Risky users SHALL be blocked." }
        ]
    });
    let bytes = serde_json::to_vec(&document).expect("serializable document");
    normalize_bytes(
        "scubagear",
        &bytes,
        "attempt-1/output/scubagear.json",
        "application/json",
        "run-m365-coverage",
    )
}

#[test]
fn mcp_armor_preserves_both_static_configuration_findings_without_secret_material() {
    let output = normalize_fixture("mcp-armor");
    assert!(output.complete, "{:?}", output.warnings);
    assert!(output.warnings.is_empty());
    assert!(output.observations.is_empty());
    assert_eq!(output.findings.len(), 2);

    let secret = output
        .findings
        .iter()
        .find(|finding| finding.title == "Hardcoded Secret")
        .expect("hardcoded-secret finding");
    assert_eq!(secret.severity, Severity::High);
    assert_eq!(secret.family, Some(FindingFamily::McpSecret));
    assert!(secret.recommendation.contains("MCP configuration"));
    assert_eq!(
        secret.evidence[0].source_rule.as_deref(),
        Some("hardcoded_secrets")
    );
    assert!(
        secret.evidence[0]
            .location
            .as_deref()
            .is_some_and(|location| location.contains("line 12") && location.contains("OpenAI"))
    );

    let permissions = output
        .findings
        .iter()
        .find(|finding| finding.title == "Excessive Tool Permissions")
        .expect("excessive-permission finding");
    assert_eq!(permissions.severity, Severity::Critical);
    assert_eq!(permissions.family, Some(FindingFamily::McpConfiguration));
    assert!(
        permissions
            .recommendation
            .contains("dangerous command flags")
    );
    assert_eq!(
        permissions.evidence[0].source_rule.as_deref(),
        Some("excessive_tool_permissions")
    );
    assert!(
        permissions.evidence[0]
            .location
            .as_deref()
            .is_some_and(|location| location.contains("terminal:exec")
                && location.contains("--allow-terminal"))
    );

    let serialized = serde_json::to_string(&output.findings).unwrap();
    for excluded in ["sk-A...BBB", "matched_text_redacted"] {
        assert!(!serialized.contains(excluded), "{serialized}");
    }
}

#[test]
fn mcp_armor_accepts_a_proven_clean_ledger_and_fails_closed_on_partial_coverage() {
    let clean = normalize_bytes(
        "mcp-armor",
        include_bytes!("../../docs/research/fixtures/mcp-armor/config-clean.json"),
        "mcp-armor.json",
        "application/json",
        "run-mcp-armor-clean",
    );
    assert!(clean.complete, "{:?}", clean.warnings);
    assert!(clean.findings.is_empty());
    assert!(clean.warnings.is_empty());

    let partial = normalize_bytes(
        "mcp-armor",
        include_bytes!("../../docs/research/fixtures/mcp-armor/config-partial.json"),
        "mcp-armor.json",
        "application/json",
        "run-mcp-armor-partial",
    );
    assert!(!partial.complete);
    assert!(partial.findings.is_empty());
    assert!(partial.warnings.iter().any(|warning| {
        warning.contains("incomplete configuration coverage (server_config_invalid)")
            && warning.contains("config-partial.json")
    }));
    assert!(partial.warnings.iter().all(|warning| {
        !warning.contains("fixture-invalid") && !warning.contains("unsupported")
    }));
}

#[test]
fn mcp_armor_preserves_the_upstream_low_rating_for_a_disabled_risky_server() {
    let output = normalize_bytes(
        "mcp-armor",
        include_bytes!("../../docs/research/fixtures/mcp-armor/config-disabled.json"),
        "mcp-armor.json",
        "application/json",
        "run-mcp-armor-disabled",
    );
    assert!(output.complete, "{:?}", output.warnings);
    assert_eq!(output.findings.len(), 1);
    let finding = &output.findings[0];
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(finding.family, Some(FindingFamily::McpConfiguration));
    assert!(
        finding
            .tags
            .iter()
            .any(|tag| tag == "mcp-server-state:disabled")
    );
    assert!(
        finding.evidence[0]
            .location
            .as_deref()
            .is_some_and(|location| location.contains("disabled server"))
    );

    // Upstream emits the same low result for a disabled entry even when its
    // command and permission fields carry no separate risky indicator. The
    // adapter preserves that detector decision instead of rebuilding it.
    let mut document: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../docs/research/fixtures/mcp-armor/config-disabled.json"
    ))
    .unwrap();
    document["findings"][0]["affected_entities"] = serde_json::json!({
        "disabled": true,
        "risky_tools": []
    });
    let bytes = serde_json::to_vec(&document).unwrap();
    let disabled_only = normalize_bytes(
        "mcp-armor",
        &bytes,
        "mcp-armor.json",
        "application/json",
        "run-mcp-armor-disabled-only",
    );
    assert!(disabled_only.complete, "{:?}", disabled_only.warnings);
    assert_eq!(disabled_only.findings.len(), 1);
    assert_eq!(disabled_only.findings[0].severity, Severity::Low);
}

#[test]
fn mcp_armor_keeps_completed_findings_when_a_sibling_shortfall_makes_the_run_partial() {
    let mut document: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../docs/research/fixtures/mcp-armor/config-findings.json"
    ))
    .unwrap();
    document["complete"] = serde_json::json!(false);
    document["warnings"] = serde_json::json!([{
        "code": "server_config_invalid",
        "message": "TARGET_CONTROLLED_DIAGNOSTIC_MUST_STAY_RAW",
        "config_file": "tests/fixtures/config-findings.json",
        "check_id": null
    }]);
    let bytes = serde_json::to_vec(&document).unwrap();
    let output = normalize_bytes(
        "mcp-armor",
        &bytes,
        "mcp-armor.json",
        "application/json",
        "run-mcp-armor-retained-partial",
    );
    assert!(!output.complete);
    assert_eq!(output.findings.len(), 2);
    let serialized = format!(
        "{}{:?}",
        serde_json::to_string(&output.findings).unwrap(),
        output.warnings
    );
    assert!(serialized.contains("config-findings.json"));
    assert!(!serialized.contains("TARGET_CONTROLLED_DIAGNOSTIC_MUST_STAY_RAW"));
}

#[test]
fn mcp_armor_contract_drift_and_untrusted_detail_always_fail_closed() {
    let baseline: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../docs/research/fixtures/mcp-armor/config-findings.json"
    ))
    .unwrap();
    let cases = [
        ("schema", {
            let mut document = baseline.clone();
            document["schema_version"] = serde_json::json!("2");
            document
        }),
        ("input-count", {
            let mut document = baseline.clone();
            document["input_count"] = serde_json::json!(2);
            document
        }),
        ("missing-warnings", {
            let mut document = baseline.clone();
            document.as_object_mut().unwrap().remove("warnings");
            document
        }),
        ("failed-check", {
            let mut document = baseline.clone();
            document["complete"] = serde_json::json!(false);
            document["warnings"] = serde_json::json!([{
                "code": "check_failed",
                "message": "UNTRUSTED_FAILURE_DETAIL",
                "config_file": null,
                "check_id": "hardcoded_secrets"
            }]);
            document["checks"][0]["status"] = serde_json::json!("failed");
            document["checks"][0]["finding_count"] = serde_json::json!(0);
            document
        }),
        ("unknown-check", {
            let mut document = baseline.clone();
            document["findings"][0]["check_id"] = serde_json::json!("invented_check");
            document
        }),
        ("count-mismatch", {
            let mut document = baseline.clone();
            document["checks"][1]["finding_count"] = serde_json::json!(0);
            document
        }),
        ("unsupported-detail", {
            let mut document = baseline.clone();
            document["findings"][0]["description"] = serde_json::json!("UNTRUSTED_FINDING_DETAIL");
            document
        }),
        ("inconsistent-completeness", {
            let mut document = baseline.clone();
            document["warnings"] = serde_json::json!([{
                "code": "server_config_invalid",
                "message": "UNTRUSTED_WARNING_DETAIL",
                "config_file": "tests/fixtures/config-findings.json",
                "check_id": null
            }]);
            document
        }),
        ("unexplained-incompleteness", {
            let mut document = baseline.clone();
            document["complete"] = serde_json::json!(false);
            document
        }),
    ];

    for (name, document) in cases {
        let bytes = serde_json::to_vec(&document).unwrap();
        let output = normalize_bytes(
            "mcp-armor",
            &bytes,
            "mcp-armor.json",
            "application/json",
            &format!("run-mcp-armor-drift-{name}"),
        );
        assert!(!output.complete, "{name}: {:?}", output.warnings);
        assert!(!output.warnings.is_empty(), "{name}");
        let normalized = format!(
            "{}{:?}",
            serde_json::to_string(&output.findings).unwrap(),
            output.warnings
        );
        for excluded in [
            "UNTRUSTED_FAILURE_DETAIL",
            "UNTRUSTED_FINDING_DETAIL",
            "UNTRUSTED_WARNING_DETAIL",
        ] {
            assert!(!normalized.contains(excluded), "{name}: {normalized}");
        }
    }
}

#[test]
fn mcp_armor_exact_check_ids_map_without_using_configuration_controlled_text() {
    let ordinary = normalize_fixture("mcp-armor");
    let ordinary_controls = ordinary
        .findings
        .iter()
        .flat_map(|finding| &finding.control_references)
        .map(|reference| reference.control_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ordinary_controls,
        BTreeSet::from([
            "A.5.17", "A.5.18", "A.8.2", "A.8.9", "PR.AA-01", "PR.AA-05", "PR.PS-01"
        ])
    );

    let ai = normalize_ai_system_fixture("mcp-armor");
    let ai_controls = ai
        .findings
        .iter()
        .flat_map(|finding| &finding.control_references)
        .map(|reference| reference.control_id.as_str())
        .collect::<BTreeSet<_>>();
    assert!(ai_controls.contains("LLM02:2025"));
    assert!(ai_controls.contains("LLM06:2025"));
}

#[test]
fn only_the_wrappers_declared_results_are_normalized() {
    // Every one of these objects carries a status and a rule id, so the
    // recursive walk this replaced would have turned each into a finding. Only
    // the entry the wrapper listed under `Results` is a normalized control; the
    // rest are provenance, a quoted vendor blob, and a nested annotation.
    let document = serde_json::json!({
        "Engine": "ScubaGear",
        "Provenance": {
            "raw_report": { "PolicyId": "MS.AAD.9.9v1", "Result": "Failed",
                            "Requirement": "Provenance is not a control." }
        },
        "Diagnostics": { "passes": 0, "failures": 1, "errors": 0,
                         "manual": 0, "omitted": 0, "normalized_results": 1 },
        "Results": [{ "PolicyId": "MS.AAD.1.1v1", "Result": "Failed",
                      "Criticality": "Shall", "Requirement": "Block legacy authentication.",
                      "Upstream": { "PolicyId": "MS.AAD.8.8v1", "Result": "Failed",
                                    "Requirement": "A nested quote is not a control." } }]
    });
    let bytes = serde_json::to_vec(&document).expect("serializable document");
    let output = normalize_bytes(
        "scubagear",
        &bytes,
        "attempt-1/output/scubagear.json",
        "application/json",
        "run-m365-envelope",
    );
    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    let rules = output
        .findings
        .iter()
        .flat_map(|finding| &finding.evidence)
        .filter_map(|evidence| evidence.source_rule.as_deref())
        .collect::<Vec<_>>();
    assert_eq!(rules, vec!["MS.AAD.1.1v1"], "{rules:?}");
}

#[test]
fn a_document_another_engine_wrote_is_refused_rather_than_mined_for_findings() {
    let document = serde_json::json!({
        "Engine": "Maester",
        "Results": [{ "PolicyId": "MS.AAD.1.1v1", "Result": "Failed",
                      "Requirement": "Block legacy authentication." }]
    });
    let bytes = serde_json::to_vec(&document).expect("serializable document");
    let output = normalize_bytes(
        "scubagear",
        &bytes,
        "attempt-1/output/scubagear.json",
        "application/json",
        "run-m365-misrouted",
    );
    assert!(output.findings.is_empty());
    assert!(!output.complete);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("document declares engine Maester")),
        "the mismatch must be named: {:?}",
        output.warnings
    );
}

#[test]
fn results_lost_between_the_wrapper_and_the_adapter_are_reported() {
    // No rule-level check can see this: every result present parses cleanly,
    // and only the wrapper's own count reveals that one went missing.
    let output = scubagear_run_with_diagnostics(serde_json::json!({
        "passes": 1, "failures": 1, "errors": 0,
        "manual": 0, "omitted": 0, "normalized_results": 3
    }));
    assert!(!output.complete);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("writing 3 normalized results")
                && warning.contains("holds 2")),
        "the shortfall must be quantified: {:?}",
        output.warnings
    );
}

#[test]
fn controls_passed_over_by_design_are_disclosed_without_marking_the_run_incomplete() {
    // Manual and omitted controls were passed over deliberately, so the run is
    // still a complete scan of what it set out to check. If this disclosure
    // ever flips `complete`, every healthy tenant scan stops reaching
    // ExecutionStage::Completed and sits in CapturedAwaitingAdapter instead
    // (orchestrator.rs:881).
    let output = scubagear_run_with_diagnostics(serde_json::json!({
        "passes": 1, "failures": 1, "errors": 0,
        "manual": 20, "omitted": 5, "normalized_results": 2
    }));
    assert!(
        output.complete,
        "a deliberate pass must not read as a normalization failure: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 1);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("20 left without an automated verdict")),
        "the disclosure must reach the run: {:?}",
        output.warnings
    );
}

#[test]
fn controls_the_engine_could_not_evaluate_keep_their_findings_but_withhold_completion() {
    // Coverage was never established for the errored control, so the run must
    // not claim completion. The findings it did produce are still real and are
    // kept: orchestrator.rs:879 assigns them before consulting `complete`, so
    // this becomes a PartiallyCompleted run with usable findings rather than a
    // failure that discards them.
    let output = scubagear_run_with_diagnostics(serde_json::json!({
        "passes": 1, "failures": 1, "errors": 3,
        "manual": 0, "omitted": 0, "normalized_results": 2
    }));
    assert!(
        !output.complete,
        "an unevaluable control means coverage was not established"
    );
    assert_eq!(
        output.findings.len(),
        1,
        "withholding completion must not discard real findings"
    );
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("3 could not be evaluated")),
        "the reason must be legible: {:?}",
        output.warnings
    );
}

#[test]
fn versioned_control_references_are_allowlisted_relationships_not_assurance_claims() {
    let mapped_engines = [
        "prowler",
        "scoutsuite",
        "cloudsplaining",
        "scubagear",
        "maester",
        "nuclei",
        "semgrep",
        "gitleaks",
        "trufflehog",
        "checkov",
        "kics",
        "trivy",
        "grype",
        "kubescape",
        "kube-bench",
        "greenbone",
    ];
    let ai_system_related_engines = [
        "semgrep",
        "checkov",
        "kics",
        "trivy",
        "grype",
        "kubescape",
        "greenbone",
    ];
    let ai_generated_related_engines = ["semgrep", "gitleaks", "trufflehog"];
    for engine_id in mapped_engines {
        let output = normalize_fixture(engine_id);
        let references = output
            .findings
            .iter()
            .flat_map(|finding| &finding.control_references)
            .collect::<Vec<_>>();
        assert!(
            !references.is_empty(),
            "fixture rule for {engine_id} should have an explicit mapping"
        );
        assert!(references.iter().all(|reference| {
            reference.relationship == "related"
                && reference.mapping_version == "2026-09-13.2"
                && matches!(
                    reference.framework.as_str(),
                    "NIST CSF"
                        | "ISO/IEC 27001"
                        | "OWASP Top 10"
                        | "CIS Kubernetes Benchmark"
                        | "CIS Amazon Web Services Foundations Benchmark"
                )
        }));
        assert!(
            references
                .iter()
                .all(|reference| reference.framework != "AIDEFEND")
        );

        let ai_output = normalize_ai_system_fixture(engine_id);
        let ai_references = ai_output
            .findings
            .iter()
            .flat_map(|finding| &finding.control_references)
            .collect::<Vec<_>>();
        assert_eq!(
            ai_references
                .iter()
                .any(|reference| reference.framework == "AIDEFEND"),
            ai_system_related_engines.contains(&engine_id),
            "explicit AI-system applicability for {engine_id} changed"
        );

        let generated_output = normalize_ai_generated_fixture(engine_id);
        let generated_references = generated_output
            .findings
            .iter()
            .flat_map(|finding| &finding.control_references)
            .collect::<Vec<_>>();
        assert_eq!(
            generated_references
                .iter()
                .any(|reference| reference.control_id == "AID-H-031.002"),
            ai_generated_related_engines.contains(&engine_id),
            "explicit AI-generated-artifact applicability for {engine_id} changed"
        );
        let serialized = serde_json::to_string(&references)
            .expect("serialize versioned control references")
            .to_ascii_lowercase();
        assert!(!serialized.contains("is compliant"));
        assert!(!serialized.contains("is certified"));
        assert!(!serialized.contains("passes the control"));
    }

    for engine_id in ["naabu", "httpx"] {
        let output = normalize_fixture(engine_id);
        assert!(output.findings.is_empty());
        assert!(
            output
                .observations
                .iter()
                .all(|observation| observation.engine_id == engine_id)
        );
    }
}

#[test]
fn malformed_jsonl_is_contained_while_valid_records_survive() {
    let bytes = include_bytes!("fixtures/adapters/malformed-nuclei.jsonl");
    let output = normalize_bytes(
        "nuclei",
        bytes,
        "malformed-nuclei.jsonl",
        "application/x-ndjson",
        "run-1",
    );
    assert_eq!(output.findings.len(), 1);
    assert!(!output.complete);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("malformed JSONL line 2"))
    );
}

#[test]
fn malformed_zap_alert_is_contained_while_valid_instances_survive() {
    let bytes = include_bytes!("fixtures/adapters/malformed-zap.json");
    let output = normalize_bytes(
        "zap",
        bytes,
        "malformed-zap.json",
        "application/json",
        "run-malformed-zap",
    );
    assert_eq!(output.findings.len(), 2);
    assert!(!output.complete);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("lacked its riskcode"))
    );
    let uri_only = output
        .findings
        .iter()
        .find(|finding| {
            finding.evidence.iter().any(|evidence| {
                evidence.location.as_deref() == Some("https://service.example.test/uri-only")
            })
        })
        .expect("ZAP instance containing only uri was normalized");
    assert!(uri_only.tags.iter().any(|tag| tag == "zap-method:"));
    assert!(uri_only.tags.iter().any(|tag| tag == "zap-param:"));
    assert!(
        output
            .warnings
            .iter()
            .all(|warning| !warning.contains("/instances/1")),
        "optional instance fields produced a warning: {:?}",
        output.warnings
    );
}

#[test]
fn zap_preserves_alert_identity_severity_remediation_and_instance_evidence() {
    let output = normalize_fixture("zap");
    assert!(output.complete, "warnings: {:?}", output.warnings);
    assert!(output.warnings.is_empty());
    assert_eq!(output.findings.len(), 5);

    let source_rules = output
        .findings
        .iter()
        .flat_map(|finding| &finding.evidence)
        .filter_map(|evidence| evidence.source_rule.as_deref())
        .collect::<BTreeSet<_>>();
    assert_eq!(source_rules, BTreeSet::from(["10020", "10027", "10038"]));

    for (rule_id, severity, remediation) in [
        (
            "10038",
            Severity::Medium,
            "Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.",
        ),
        (
            "10020",
            Severity::Medium,
            "Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers.",
        ),
        (
            "10027",
            Severity::Informational,
            "Remove all comments that return information that may help an attacker",
        ),
    ] {
        let findings = output
            .findings
            .iter()
            .filter(|finding| {
                finding
                    .evidence
                    .iter()
                    .any(|evidence| evidence.source_rule.as_deref() == Some(rule_id))
            })
            .collect::<Vec<_>>();
        assert!(!findings.is_empty(), "missing ZAP rule {rule_id}");
        assert!(findings.iter().all(|finding| finding.severity == severity));
        assert!(
            findings.iter().all(|finding| {
                finding.evidence.iter().all(|evidence| {
                    evidence.scanner_details.as_ref().is_some_and(|details| {
                        details
                            .remediation
                            .as_deref()
                            .is_some_and(|value| value.starts_with(remediation))
                    })
                })
            }),
            "unexpected ZAP rule {rule_id} remediation: {:?}",
            findings
                .iter()
                .flat_map(|finding| &finding.evidence)
                .filter_map(|evidence| evidence.scanner_details.as_ref())
                .filter_map(|details| details.remediation.as_deref())
                .collect::<Vec<_>>()
        );
    }

    assert!(output.findings.iter().all(|finding| {
        finding.evidence.iter().all(|evidence| {
            evidence.scanner_details.as_ref().is_none_or(|details| {
                details
                    .description
                    .as_ref()
                    .into_iter()
                    .chain(details.remediation.as_ref())
                    .all(|value| {
                        !value.contains("<p>") && !value.contains("</p>") && !value.contains("<br")
                    })
            })
        })
    }));
    assert!(output.findings.iter().any(|finding| {
        finding.evidence.iter().any(|evidence| {
            evidence.source_rule.as_deref() == Some("10020")
                && evidence.scanner_details.as_ref().is_some_and(|details| {
                    details.remediation.as_deref().is_some_and(|remediation| {
                        remediation.contains("returned by your site/app. If you expect the page")
                    })
                })
        })
    }));

    assert!(output.findings.iter().any(|finding| {
        finding
            .tags
            .iter()
            .any(|tag| tag == "zap-alert-ref:10020-1")
            && finding
                .tags
                .iter()
                .any(|tag| tag == "zap-param:x-frame-options")
    }));
    assert!(output.findings.iter().any(|finding| {
        finding
            .tags
            .iter()
            .any(|tag| tag == "zap-evidence:<!-- TODO: remove debug token")
            && finding.tags.iter().all(|tag| {
                !tag.starts_with("zap-otherinfo:")
                    && !tag.starts_with("zap-risk-description:")
            })
            && finding.evidence.iter().any(|evidence| {
                evidence.location.as_deref() == Some("https://service.example.test/login.html")
                    && evidence.scanner_details.as_ref().is_some_and(|details| {
                        details.description.as_deref().is_some_and(|description| {
                            description
                                == "The response appears to contain suspicious comments which may help an attacker. The following pattern was used: \\bTODO\\b and was detected in likely comment: \"<!-- TODO: remove debug token abc123 -->\", see evidence field for the suspicious comment/snippet."
                                && description.contains("<!-- TODO: remove debug token abc123 -->")
                        })
                    })
            })
    }));
    assert!(output.findings.iter().any(|finding| {
        finding.official_references.iter().any(|reference| {
            reference == "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP"
        }) && finding.evidence.iter().any(|evidence| {
            evidence
                .scanner_details
                .as_ref()
                .is_some_and(|details| details.cwe_ids == ["CWE-693"])
        })
    }));
}

#[test]
fn pinned_native_zap_report_preserves_every_rule_and_response_instance() {
    let bytes = include_bytes!("fixtures/adapters/native-zap-2.17.0.json");
    let root: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let assets = vec![authorized_asset(
        "asset-1",
        AssetKind::WebService,
        None,
        &[
            ("dns_name", "zap-fixture.example.test"),
            ("web_origin", "http://zap-fixture.example.test:8080"),
        ],
    )];
    let output = normalize_bytes_with_assets(
        "zap",
        bytes,
        "zap.json",
        "application/json",
        "run-native-zap",
        &assets,
    );
    assert!(output.complete, "{:?}", output.warnings);
    let alerts = root["site"][0]["alerts"].as_array().unwrap();
    let native_instances: usize = alerts
        .iter()
        .map(|alert| alert["instances"].as_array().unwrap().len())
        .sum();
    assert_eq!(native_instances, 27);
    assert_eq!(output.findings.len(), native_instances);
    for alert in alerts {
        let rule_id = alert["pluginid"].as_str().unwrap();
        let expected = alert["instances"].as_array().unwrap().len();
        let findings = output
            .findings
            .iter()
            .filter(|finding| {
                finding
                    .evidence
                    .iter()
                    .any(|evidence| evidence.source_rule.as_deref() == Some(rule_id))
            })
            .collect::<Vec<_>>();
        assert_eq!(findings.len(), expected);
        let severity = match alert["riskcode"].as_str().unwrap() {
            "0" => Severity::Informational,
            "1" => Severity::Low,
            "2" => Severity::Medium,
            "3" => Severity::High,
            _ => panic!("unexpected native risk"),
        };
        assert!(
            findings
                .iter()
                .all(|finding| finding.severity == severity && finding.asset_ids == ["asset-1"])
        );
    }
}

#[test]
fn zap_without_observed_responses_is_incomplete_even_with_valid_empty_json() {
    let output = normalize_bytes(
        "zap",
        br#"{"site":[]}"#,
        "zap.json",
        "application/json",
        "run-unreached-zap",
    );
    assert!(!output.complete);
    assert!(output.findings.is_empty());
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("no website responses"))
    );
}

#[test]
fn empty_zap_alert_array_is_a_zero_finding_result_without_a_security_claim() {
    let output = normalize_bytes(
        "zap",
        br#"{"site":[{"alerts":[]}],"sequences":[]}"#,
        "zap.json",
        "application/json",
        "run-empty-zap",
    );
    assert!(output.complete, "warnings: {:?}", output.warnings);
    assert!(output.findings.is_empty());
    assert!(output.warnings.is_empty());
}

#[test]
fn provably_complete_empty_released_jsonl_streams_are_zero_finding_results() {
    for engine_id in ["naabu", "httpx", "trufflehog"] {
        for bytes in [b"".as_slice(), b"\r\n\t".as_slice()] {
            let filename = format!("{engine_id}.jsonl");
            let output = normalize_bytes(
                engine_id,
                bytes,
                &filename,
                "application/x-ndjson",
                "run-empty",
            );
            assert!(
                output.complete,
                "{engine_id} warnings: {:?}",
                output.warnings
            );
            assert!(output.findings.is_empty());
            assert!(output.warnings.is_empty());
        }
    }
}

#[test]
fn empty_nuclei_jsonl_is_normalized_to_a_missing_template_execution_outcome() {
    for bytes in [b"".as_slice(), b"\r\n\t".as_slice()] {
        let output = normalize_bytes(
            "nuclei",
            bytes,
            "nuclei.jsonl",
            "application/x-ndjson",
            "run-empty",
        );
        assert!(output.complete, "warnings: {:?}", output.warnings);
        assert!(output.findings.is_empty());
        assert!(output.security_template_executions.is_empty());
        assert_eq!(
            output.unevaluated_targets,
            [UnevaluatedTarget {
                asset_id: "asset-1".into(),
                cause: UnevaluatedTargetCause::NoSecurityTemplateExecutionEvidence,
                result_count: 0,
            }]
        );
        assert!(output.warnings.is_empty());
    }
}

#[test]
fn nuclei_non_match_is_positive_execution_evidence_without_becoming_a_finding() {
    let output = normalize_bytes(
        "nuclei",
        br#"{"template-id":"clean-template","matcher-status":false,"url":"https://service.example.test/","asset_id":"asset-1"}
"#,
        "nuclei.jsonl",
        "application/x-ndjson",
        "run-clean",
    );

    assert!(output.complete, "warnings: {:?}", output.warnings);
    assert!(output.findings.is_empty());
    assert!(output.unevaluated_targets.is_empty());
    assert_eq!(output.security_template_executions.len(), 1);
    assert_eq!(output.security_template_executions[0].asset_id, "asset-1");
    assert_eq!(output.security_template_executions[0].result_count, 1);
}

#[test]
fn empty_json_document_for_other_adapters_remains_incomplete() {
    let output = normalize_bytes(
        "gitleaks",
        b"",
        "gitleaks.json",
        "application/json",
        "run-empty",
    );
    assert!(!output.complete);
    assert!(output.findings.is_empty());
}

#[test]
fn secret_values_and_target_instructions_never_enter_findings() {
    for engine_id in ["gitleaks", "trufflehog"] {
        let serialized = serde_json::to_string(&normalize_fixture(engine_id).findings)
            .expect("serialize normalized findings");
        assert!(!serialized.contains("SECRET_SENTINEL_MUST_NEVER_LEAK"));
    }

    let httpx = serde_json::to_string(&normalize_fixture("httpx").observations)
        .expect("serialize httpx inventory observations");
    assert!(!httpx.contains("target-controlled text is data"));
    assert!(!httpx.contains("session=must-not-appear"));
    assert!(!httpx.contains("SECRET_SENTINEL_MUST_NEVER_LEAK"));

    // kube-bench's `actual_value` can be the verbatim contents of a file read
    // from the user-selected snapshot, so it is target-controlled even though
    // the upstream benchmark and remediation are immutable.
    let kube_bench = serde_json::to_string(&normalize_fixture("kube-bench").findings)
        .expect("serialize kube-bench findings");
    assert!(!kube_bench.contains("Do not execute this target-controlled command"));
}

#[test]
fn gitleaks_keeps_same_rule_findings_at_distinct_source_coordinates_without_secrets() {
    let bytes = br#"[
      {
        "RuleID": "generic-api-key",
        "Description": "Potential API key",
        "File": "src/generated.ts",
        "StartLine": 12,
        "StartColumn": 7,
        "Commit": "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
        "Secret": "FIRST_SECRET_SENTINEL_MUST_NEVER_LEAK",
        "Match": "token=FIRST_SECRET_SENTINEL_MUST_NEVER_LEAK",
        "asset_id": "asset-1"
      },
      {
        "RuleID": "generic-api-key",
        "Description": "Potential API key",
        "File": "src/generated.ts",
        "StartLine": 29,
        "StartColumn": 11,
        "Commit": "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
        "Secret": "SECOND_SECRET_SENTINEL_MUST_NEVER_LEAK",
        "Match": "token=SECOND_SECRET_SENTINEL_MUST_NEVER_LEAK",
        "asset_id": "asset-1"
      }
    ]"#;

    let output = normalize_bytes(
        "gitleaks",
        bytes,
        "gitleaks-multiple.json",
        "application/json",
        "run-1",
    );
    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 2);
    assert_eq!(
        output
            .findings
            .iter()
            .map(|finding| finding.fingerprint.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        2,
        "source coordinates must keep same-file, same-rule findings distinct"
    );

    let serialized = serde_json::to_string(&output.findings).expect("serialize Gitleaks findings");
    assert!(serialized.contains("src/generated.ts:line=12:column=7"));
    assert!(serialized.contains("abcdef0123456789abcdef0123456789abcdef01"));
    assert!(!serialized.contains("FIRST_SECRET_SENTINEL_MUST_NEVER_LEAK"));
    assert!(!serialized.contains("SECOND_SECRET_SENTINEL_MUST_NEVER_LEAK"));
    assert!(!serialized.contains("token="));
}

#[test]
fn source_coordinates_prevent_distinct_upstream_results_from_being_silently_merged() {
    let cases = [
        (
            "semgrep",
            "semgrep-multiple.json",
            "application/json",
            br#"{
              "results": [
                {
                  "check_id": "python.lang.security.audit.exec-used.exec-used",
                  "path": "src/worker.py",
                  "start": {"line": 12, "col": 3},
                  "extra": {"message": "exec() used", "severity": "ERROR"},
                  "asset_id": "asset-1"
                },
                {
                  "check_id": "python.lang.security.audit.exec-used.exec-used",
                  "path": "src/worker.py",
                  "start": {"line": 29, "col": 7},
                  "extra": {"message": "exec() used", "severity": "ERROR"},
                  "asset_id": "asset-1"
                }
              ],
              "errors": []
            }"#
            .as_slice(),
            ["src/worker.py:line=12:column=3", "src/worker.py:line=29:column=7"],
        ),
        (
            "checkov",
            "checkov-multiple.json",
            "application/json",
            br#"{
              "results": {
                "failed_checks": [
                  {
                    "check_id": "CKV_AWS_18",
                    "check_name": "Ensure access logging is enabled",
                    "file_path": "/infra/storage.tf",
                    "file_line_range": [4, 10],
                    "resource": "aws_s3_bucket.logs",
                    "severity": null,
                    "asset_id": "asset-1"
                  },
                  {
                    "check_id": "CKV_AWS_18",
                    "check_name": "Ensure access logging is enabled",
                    "file_path": "/infra/storage.tf",
                    "file_line_range": [18, 24],
                    "resource": "aws_s3_bucket.archive",
                    "severity": null,
                    "asset_id": "asset-1"
                  }
                ]
              }
            }"#
            .as_slice(),
            [
                "/infra/storage.tf:line=4:resource=aws_s3_bucket.logs",
                "/infra/storage.tf:line=18:resource=aws_s3_bucket.archive",
            ],
        ),
        (
            "trufflehog",
            "trufflehog-multiple.jsonl",
            "application/x-ndjson",
            br#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/workspace/config/.env","line":6}}},"DetectorType":17,"DetectorName":"AWS","Verified":false,"Raw":"FIRST_SECRET_SENTINEL_MUST_NEVER_LEAK","asset_id":"asset-1"}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/workspace/config/.env","line":21}}},"DetectorType":17,"DetectorName":"AWS","Verified":false,"Raw":"SECOND_SECRET_SENTINEL_MUST_NEVER_LEAK","asset_id":"asset-1"}
"#
            .as_slice(),
            ["config/.env:line=6", "config/.env:line=21"],
        ),
    ];

    for (engine_id, filename, media_type, bytes, expected_locations) in cases {
        let output = normalize_bytes(engine_id, bytes, filename, media_type, "run-coordinates");
        assert!(
            output.complete,
            "{engine_id} unexpectedly incomplete: {:?}",
            output.warnings
        );
        assert_eq!(
            output.findings.len(),
            2,
            "{engine_id} merged two distinct upstream observations"
        );
        assert_eq!(
            output
                .findings
                .iter()
                .map(|finding| finding.fingerprint.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            2,
            "{engine_id} produced colliding fingerprints for distinct coordinates"
        );
        let serialized = serde_json::to_string(&output.findings).expect("serialize findings");
        for expected in expected_locations {
            assert!(
                serialized.contains(expected),
                "{engine_id} did not preserve source coordinate {expected}: {serialized}"
            );
        }
        assert!(!serialized.contains("SECRET_SENTINEL_MUST_NEVER_LEAK"));
    }
}

#[test]
fn kics_and_trivy_keep_distinct_upstream_resources_and_secret_coordinates() {
    let kics = br#"{
      "queries": [{
        "query_id": "query-1",
        "query_name": "Encryption required",
        "severity": "HIGH",
        "files": [
          {
            "file_name": "infra/storage.tf",
            "line": 4,
            "resource_name": "aws_s3_bucket.logs",
            "similarity_id": "similarity-logs",
            "asset_id": "asset-1"
          },
          {
            "file_name": "infra/storage.tf",
            "line": 18,
            "resource_name": "aws_s3_bucket.archive",
            "similarity_id": "similarity-archive",
            "asset_id": "asset-1"
          }
        ]
      }]
    }"#;
    let kics = normalize_bytes(
        "kics",
        kics,
        "kics-multiple.json",
        "application/json",
        "run-kics-coordinates",
    );
    assert!(kics.complete, "unexpected warnings: {:?}", kics.warnings);
    assert_eq!(kics.findings.len(), 2);
    let kics_serialized = serde_json::to_string(&kics.findings).expect("serialize KICS findings");
    for coordinate in [
        "infra/storage.tf:line=4:resource=resource:aws_s3_bucket.logs,similarity:similarity-logs",
        "infra/storage.tf:line=18:resource=resource:aws_s3_bucket.archive,similarity:similarity-archive",
    ] {
        assert!(kics_serialized.contains(coordinate), "{kics_serialized}");
    }

    let trivy = br#"{
      "SchemaVersion": 2,
      "Results": [{
        "Target": "example:latest",
        "Vulnerabilities": [
          {
            "VulnerabilityID": "CVE-2026-0001",
            "PkgName": "libalpha",
            "InstalledVersion": "1.0",
            "Severity": "HIGH"
          },
          {
            "VulnerabilityID": "CVE-2026-0001",
            "PkgName": "libbeta",
            "InstalledVersion": "2.0",
            "Severity": "HIGH"
          }
        ],
        "Secrets": [
          {
            "RuleID": "generic-api-key",
            "Title": "API key",
            "Severity": "HIGH",
            "StartLine": 7,
            "Offset": 101,
            "Match": "FIRST_SECRET_SENTINEL_MUST_NEVER_LEAK"
          },
          {
            "RuleID": "generic-api-key",
            "Title": "API key",
            "Severity": "HIGH",
            "StartLine": 31,
            "Offset": 202,
            "Match": "SECOND_SECRET_SENTINEL_MUST_NEVER_LEAK"
          }
        ],
        "asset_id": "asset-1"
      }]
    }"#;
    let trivy = normalize_bytes(
        "trivy",
        trivy,
        "trivy-multiple.json",
        "application/json",
        "run-trivy-coordinates",
    );
    assert!(trivy.complete, "unexpected warnings: {:?}", trivy.warnings);
    assert_eq!(
        trivy.findings.len(),
        4,
        "Trivy merged distinct packages or secret locations"
    );
    let trivy_serialized =
        serde_json::to_string(&trivy.findings).expect("serialize Trivy findings");
    for coordinate in [
        "example:latest:resource=libalpha@1.0",
        "example:latest:resource=libbeta@2.0",
        "example:latest:line=7:resource=offset:101",
        "example:latest:line=31:resource=offset:202",
    ] {
        assert!(trivy_serialized.contains(coordinate), "{trivy_serialized}");
    }
    assert!(!trivy_serialized.contains("SECRET_SENTINEL_MUST_NEVER_LEAK"));
}

#[test]
fn missing_primary_result_shapes_are_incomplete_but_known_empty_shapes_are_complete() {
    let malformed = [
        (
            "httpx",
            br#"{}"#.as_slice(),
            "httpx.jsonl",
            "application/x-ndjson",
        ),
        (
            "nuclei",
            br#"{"info":{"name":"missing template id"}}"#.as_slice(),
            "nuclei.jsonl",
            "application/x-ndjson",
        ),
        (
            "gitleaks",
            br#"{}"#.as_slice(),
            "gitleaks.json",
            "application/json",
        ),
        (
            "trufflehog",
            br#"{"SourceMetadata":{}}"#.as_slice(),
            "trufflehog.jsonl",
            "application/x-ndjson",
        ),
        (
            "trivy",
            br#"[]"#.as_slice(),
            "trivy.json",
            "application/json",
        ),
        (
            "grype",
            br#"{}"#.as_slice(),
            "grype.json",
            "application/json",
        ),
        (
            "kube-bench",
            br#"{}"#.as_slice(),
            "kube-bench.json",
            "application/json",
        ),
    ];
    for (engine_id, bytes, filename, media_type) in malformed {
        let output = normalize_bytes(engine_id, bytes, filename, media_type, "run-missing-shape");
        assert!(
            !output.complete,
            "{engine_id} accepted a missing result shape"
        );
        assert!(output.findings.is_empty());
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| { warning.contains("retry") || warning.contains("retried") }),
            "{engine_id} warning was not actionable: {:?}",
            output.warnings
        );
    }

    let empty = [
        (
            "gitleaks",
            br#"[]"#.as_slice(),
            "gitleaks.json",
            "application/json",
        ),
        (
            "trivy",
            br#"{}"#.as_slice(),
            "trivy.json",
            "application/json",
        ),
        (
            "trivy",
            br#"{"Results":[]}"#.as_slice(),
            "trivy.json",
            "application/json",
        ),
        (
            "grype",
            br#"{"matches":[]}"#.as_slice(),
            "grype.json",
            "application/json",
        ),
        (
            "kube-bench",
            br#"{"Controls":[]}"#.as_slice(),
            "kube-bench.json",
            "application/json",
        ),
    ];
    for (engine_id, bytes, filename, media_type) in empty {
        let output = normalize_bytes(
            engine_id,
            bytes,
            filename,
            media_type,
            "run-known-empty-shape",
        );
        assert!(
            output.complete,
            "{engine_id} rejected its known empty shape: {:?}",
            output.warnings
        );
        assert!(output.findings.is_empty());
    }
}

#[test]
fn semgrep_preserves_valid_findings_but_withholds_completion_for_errors_and_bad_rows() {
    let output = normalize_bytes(
        "semgrep",
        br#"{
          "results": [
            {
              "check_id": "example.valid-rule",
              "path": "src/example.rs",
              "extra": {"message": "Valid sibling", "severity": "ERROR"},
              "asset_id": "asset-1"
            },
            "ROW_SENTINEL_MUST_NOT_LEAK",
            {"path": "src/missing-rule.rs", "asset_id": "asset-1"}
          ],
          "errors": [{"message": "ERROR_SENTINEL_MUST_NOT_LEAK"}]
        }"#,
        "semgrep-malformed-shapes.json",
        "application/json",
        "run-semgrep-malformed-shapes",
    );

    assert!(!output.complete);
    assert_eq!(output.findings.len(), 1);
    for expected in [
        "Semgrep reported one or more scanner errors",
        "Semgrep finding at /results/1 was not an object",
        "Semgrep finding at /results/2 lacked its check_id",
    ] {
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains(expected)),
            "missing {expected:?}: {:?}",
            output.warnings
        );
    }
    let warnings = output.warnings.join(" ");
    assert!(!warnings.contains("ERROR_SENTINEL_MUST_NOT_LEAK"));
    assert!(!warnings.contains("ROW_SENTINEL_MUST_NOT_LEAK"));

    for bytes in [
        br#"{"results":[]}"#.as_slice(),
        br#"{"results":[],"errors":{"message":"ERROR_SHAPE_SENTINEL_MUST_NOT_LEAK"}}"#.as_slice(),
    ] {
        let missing_errors = normalize_bytes(
            "semgrep",
            bytes,
            "semgrep-errors-shape.json",
            "application/json",
            "run-semgrep-errors-shape",
        );
        assert!(!missing_errors.complete);
        assert!(missing_errors.findings.is_empty());
        assert!(missing_errors.warnings.iter().any(|warning| {
            warning.contains("Semgrep output lacked its required errors array")
        }));
        assert!(
            !missing_errors
                .warnings
                .join(" ")
                .contains("ERROR_SHAPE_SENTINEL_MUST_NOT_LEAK")
        );
    }
}

#[test]
fn kube_bench_manual_checks_never_become_a_clean_zero_finding_result() {
    let bytes = br#"{"Controls":[{"tests":[{"results":[
      {"test_number":"4.2.20","test_desc":"Manual configuration check","status":"WARN",
       "remediation":"MANUAL_REMEDIATION_STAYS_IN_EVIDENCE"},
      {"test_number":"4.2.21","status":"WARN"}
    ]}]}]}"#;
    let manual = normalize_bytes(
        "kube-bench",
        bytes,
        "kube-bench-manual.json",
        "application/json",
        "run-manual",
    );
    assert!(!manual.complete);
    assert!(
        manual.findings.is_empty(),
        "manual checks are not failed findings"
    );
    assert_eq!(manual.warnings.len(), 1);
    assert!(manual.warnings[0].contains("2 left without an automated verdict"));
    assert!(!manual.warnings[0].contains("MANUAL_REMEDIATION_STAYS_IN_EVIDENCE"));

    let passed = normalize_bytes(
        "kube-bench",
        br#"{"Controls":[{"tests":[{"results":[{"test_number":"4.2.1","status":"PASS"}]}]}]}"#,
        "kube-bench-pass.json",
        "application/json",
        "run-pass",
    );
    assert!(passed.complete);
    assert!(passed.findings.is_empty());
    assert!(passed.warnings.is_empty());
}

#[test]
fn kics_failed_checks_withhold_completion_and_keep_completed_sibling_findings() {
    let (bytes, filename, media_type) = fixture("kics");
    let baseline = normalize_bytes("kics", bytes, filename, media_type, "run-kics-coverage");
    assert!(baseline.complete);
    assert!(!baseline.findings.is_empty());
    for field in ["files_failed_to_scan", "queries_failed_to_execute"] {
        for counter in [
            serde_json::json!(2),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("COUNTER_SENTINEL_MUST_NOT_LEAK"),
            serde_json::json!(null),
        ] {
            let mut report: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            report[field] = counter.clone();
            let output = normalize_bytes(
                "kics",
                &serde_json::to_vec(&report).unwrap(),
                filename,
                media_type,
                "run-kics-coverage",
            );
            assert!(!output.complete, "{field}={counter}");
            assert_eq!(output.findings.len(), baseline.findings.len());
            for (actual, expected) in output.findings.iter().zip(&baseline.findings) {
                assert_eq!(actual.id, expected.id);
                assert_eq!(actual.fingerprint, expected.fingerprint);
                assert_eq!(actual.title, expected.title);
                assert_eq!(actual.severity, expected.severity);
                assert_eq!(actual.evidence.len(), expected.evidence.len());
                for (actual, expected) in actual.evidence.iter().zip(&expected.evidence) {
                    assert_eq!(actual.location, expected.location);
                    assert_eq!(actual.source_rule, expected.source_rule);
                }
            }
            assert_eq!(output.warnings.len(), 1);
            assert!(!output.warnings[0].contains("COUNTER_SENTINEL_MUST_NOT_LEAK"));

            report["queries"] = serde_json::json!([]);
            let empty = normalize_bytes(
                "kics",
                &serde_json::to_vec(&report).unwrap(),
                filename,
                media_type,
                "run-kics-empty-coverage",
            );
            assert!(
                !empty.complete,
                "empty findings must not hide {field}={counter}"
            );
            assert!(empty.findings.is_empty());
        }
    }
    let clean = normalize_bytes(
        "kics",
        br#"{"queries":[],"files_failed_to_scan":0,"queries_failed_to_execute":0,"lines_ignored":7}"#,
        filename, media_type, "run-kics-clean",
    );
    assert!(
        clean.complete,
        "ignored lines are part of the selected upstream scan scope"
    );
    assert!(clean.findings.is_empty());
    assert!(clean.warnings.is_empty());
}

#[test]
fn kics_preserves_valid_files_but_withholds_completion_for_malformed_declared_shapes() {
    let output = normalize_bytes(
        "kics",
        br#"{
          "queries": [
            {
              "query_id": "11111111-1111-1111-1111-111111111111",
              "query_name": "Valid sibling one",
              "severity": "HIGH",
              "files": [{"file_name": "infra/one.tf", "asset_id": "asset-1"}]
            },
            "QUERY_SENTINEL_MUST_NOT_LEAK",
            {"query_name": "Missing id", "files": []},
            {"query_id": " ", "files": []},
            {"query_id": "22222222-2222-2222-2222-222222222222"},
            {
              "query_id": "33333333-3333-3333-3333-333333333333",
              "files": "FILES_SENTINEL_MUST_NOT_LEAK"
            },
            {
              "query_id": "44444444-4444-4444-4444-444444444444",
              "query_name": "Valid sibling two",
              "files": [
                "FILE_SENTINEL_MUST_NOT_LEAK",
                {"file_name": "infra/two.tf", "asset_id": "asset-1"}
              ]
            }
          ]
        }"#,
        "kics-malformed-shapes.json",
        "application/json",
        "run-kics-malformed-shapes",
    );

    assert!(!output.complete);
    assert_eq!(output.findings.len(), 2);
    for expected in [
        "KICS query at /queries/1 was not an object",
        "KICS query at /queries/2 lacked a valid query_id",
        "KICS query at /queries/3 lacked a valid query_id",
        "KICS query at /queries/4 lacked its files array",
        "KICS query at /queries/5 lacked its files array",
        "KICS file at /queries/6/files/0 was not an object",
    ] {
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains(expected)),
            "missing {expected:?}: {:?}",
            output.warnings
        );
    }
    let warnings = output.warnings.join(" ");
    for sentinel in [
        "QUERY_SENTINEL_MUST_NOT_LEAK",
        "FILES_SENTINEL_MUST_NOT_LEAK",
        "FILE_SENTINEL_MUST_NOT_LEAK",
    ] {
        assert!(!warnings.contains(sentinel));
    }

    for bytes in [br#"{}"#.as_slice(), br#"{"queries":{}}"#.as_slice()] {
        let missing_queries = normalize_bytes(
            "kics",
            bytes,
            "kics-queries-shape.json",
            "application/json",
            "run-kics-queries-shape",
        );
        assert!(!missing_queries.complete);
        assert!(missing_queries.findings.is_empty());
        assert!(
            missing_queries
                .warnings
                .iter()
                .any(|warning| warning.contains("KICS output lacked its queries array"))
        );
    }
}

#[test]
fn trivy_preserves_valid_items_but_withholds_completion_for_malformed_result_shapes() {
    let output = normalize_bytes(
        "trivy",
        br#"{
          "Results": [
            {
              "Target": "TARGET_SENTINEL_MUST_NOT_LEAK",
              "Vulnerabilities": [
                {
                  "VulnerabilityID": "CVE-2026-1000",
                  "PkgName": "example",
                  "InstalledVersion": "1.0",
                  "Severity": "HIGH",
                  "asset_id": "asset-1"
                },
                "ITEM_SENTINEL_MUST_NOT_LEAK"
              ],
              "Misconfigurations": {"message": "CATEGORY_SENTINEL_MUST_NOT_LEAK"},
              "Secrets": "SECRET_CATEGORY_SENTINEL_MUST_NOT_LEAK"
            },
            {
              "Vulnerabilities": {"message": "VULNERABILITY_CATEGORY_SENTINEL_MUST_NOT_LEAK"},
              "Misconfigurations": [],
              "Secrets": []
            },
            "RESULT_SENTINEL_MUST_NOT_LEAK"
          ]
        }"#,
        "trivy-malformed-shapes.json",
        "application/json",
        "run-trivy-malformed-shapes",
    );

    assert!(!output.complete);
    assert_eq!(output.findings.len(), 1);
    for expected in [
        "Trivy vulnerability at /Results/0/Vulnerabilities/1 was not an object",
        "Trivy Misconfigurations at /Results/0/Misconfigurations was present but not an array",
        "Trivy Secrets at /Results/0/Secrets was present but not an array",
        "Trivy Vulnerabilities at /Results/1/Vulnerabilities was present but not an array",
        "Trivy result at /Results/2 was not an object",
    ] {
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains(expected)),
            "missing {expected:?}: {:?}",
            output.warnings
        );
    }
    let warnings = output.warnings.join(" ");
    for sentinel in [
        "TARGET_SENTINEL_MUST_NOT_LEAK",
        "ITEM_SENTINEL_MUST_NOT_LEAK",
        "CATEGORY_SENTINEL_MUST_NOT_LEAK",
        "SECRET_CATEGORY_SENTINEL_MUST_NOT_LEAK",
        "VULNERABILITY_CATEGORY_SENTINEL_MUST_NOT_LEAK",
        "RESULT_SENTINEL_MUST_NOT_LEAK",
    ] {
        assert!(!warnings.contains(sentinel));
    }
}

#[test]
fn trivy_results_present_but_not_an_array_withholds_completion() {
    let output = normalize_bytes(
        "trivy",
        br#"{"SchemaVersion":2,"Results":{"Target":"not-an-array"}}"#,
        "trivy-results-not-array.json",
        "application/json",
        "run-trivy-results-not-array",
    );

    assert!(!output.complete);
    assert!(output.findings.is_empty());
    assert!(
        output.warnings.iter().any(|warning| warning.contains(
            "Trivy output lacked its Results array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter"
        )),
        "missing Results-shape warning: {:?}",
        output.warnings
    );
}

#[test]
fn grype_preserves_valid_matches_but_withholds_completion_for_malformed_match_shapes() {
    let output = normalize_bytes(
        "grype",
        br#"{
          "matches": [
            {
              "vulnerability": {"id": "CVE-2026-2000", "severity": "High"},
              "artifact": {"name": "example", "version": "1.0"},
              "asset_id": "asset-1"
            },
            "MATCH_SENTINEL_MUST_NOT_LEAK",
            {"artifact": {"name": "MISSING_ID_SENTINEL_MUST_NOT_LEAK"}},
            {"vulnerability": {"id": null, "description": "NULL_ID_SENTINEL_MUST_NOT_LEAK"}}
          ]
        }"#,
        "grype-malformed-shapes.json",
        "application/json",
        "run-grype-malformed-shapes",
    );

    assert!(!output.complete);
    assert_eq!(output.findings.len(), 1);
    for expected in [
        "Grype match at /matches/1 was not an object",
        "Grype match at /matches/2 lacked vulnerability.id",
        "Grype match at /matches/3 lacked vulnerability.id",
    ] {
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains(expected)),
            "missing {expected:?}: {:?}",
            output.warnings
        );
    }
    let warnings = output.warnings.join(" ");
    for sentinel in [
        "MATCH_SENTINEL_MUST_NOT_LEAK",
        "MISSING_ID_SENTINEL_MUST_NOT_LEAK",
        "NULL_ID_SENTINEL_MUST_NOT_LEAK",
    ] {
        assert!(!warnings.contains(sentinel));
    }
}

#[test]
fn repo_adapters_accept_their_explicit_empty_result_shapes_without_warnings() {
    for (engine_id, bytes) in [
        ("semgrep", br#"{"results":[],"errors":[]}"#.as_slice()),
        ("kics", br#"{"queries":[]}"#.as_slice()),
        ("trivy", br#"{"Results":[]}"#.as_slice()),
        (
            "trivy",
            br#"{"Results":[{"Vulnerabilities":[],"Misconfigurations":[],"Secrets":[]}]}"#
                .as_slice(),
        ),
        ("grype", br#"{"matches":[]}"#.as_slice()),
    ] {
        let output = normalize_bytes(
            engine_id,
            bytes,
            &format!("{engine_id}-empty-shape.json"),
            "application/json",
            "run-repo-empty-shape",
        );
        assert!(
            output.complete,
            "{engine_id} rejected its explicit empty shape: {:?}",
            output.warnings
        );
        assert!(output.findings.is_empty());
        assert!(output.warnings.is_empty());
    }
}

#[test]
fn greenbone_xml_is_bounded_evidence_preserving_and_ignores_instruction_fields() {
    let output = normalize_fixture("greenbone");
    assert_eq!(output.findings.len(), 1);
    let finding = &output.findings[0];
    assert!(finding.title.contains("Example network vulnerability"));
    assert_eq!(
        finding.evidence[0].kind,
        ai_security_scanner_lib::domain::EvidenceKind::ExternalValidation
    );
    assert!(
        finding
            .official_references
            .iter()
            .any(|reference| reference.ends_with("CVE-2025-0003"))
    );
    let details = finding.evidence[0]
        .scanner_details
        .as_ref()
        .expect("pinned-feed scanner details");
    assert_eq!(
        details.description.as_deref(),
        Some(
            "The pinned Greenbone feed identifies an outdated service with a known remote weakness."
        )
    );
    assert_eq!(
        details.remediation.as_deref(),
        Some("Install the vendor security update for the affected service.")
    );
    let serialized = serde_json::to_string(finding).expect("serialize Greenbone finding");
    assert!(!serialized.contains("SECRET_SENTINEL_MUST_NEVER_LEAK"));
    assert!(serialized.contains("pinned Greenbone feed identifies an outdated service"));
    assert!(serialized.contains("Install the vendor security update"));
}

#[test]
fn upstream_rule_details_are_retained_as_evidence_without_replacing_product_recommendations() {
    let details = |engine_id: &str| {
        normalize_fixture(engine_id)
            .findings
            .into_iter()
            .flat_map(|finding| finding.evidence)
            .filter_map(|evidence| evidence.scanner_details)
            .collect::<Vec<_>>()
    };

    let prowler = normalize_fixture("prowler");
    assert!(prowler.findings.iter().any(|finding| {
        finding.evidence.iter().any(|evidence| {
            evidence.scanner_details.as_ref().is_some_and(|details| {
                details.description.as_deref()
                    == Some("Attached customer-managed IAM policies should grant only the permissions needed.")
                && details.remediation.as_deref()
                    == Some("Replace the wildcard action and resource with the specific permissions the role needs.")
            })
        }) && !finding.recommendation.contains("Replace the wildcard action")
    }));

    let scoutsuite = details("scoutsuite");
    assert!(scoutsuite.iter().any(|details| {
        details
            .description
            .as_deref()
            .is_some_and(|text| text.contains("password policy did not require"))
            && details
                .remediation
                .as_deref()
                .is_some_and(|text| text.contains("require at least one uppercase letter"))
    }));

    let nuclei = normalize_fixture("nuclei");
    assert!(nuclei.findings.iter().any(|finding| {
        finding.evidence.iter().any(|evidence| {
            evidence.scanner_details.as_ref().is_some_and(|details| {
                details.description.as_deref()
                    == Some("A phpMyAdmin administration panel was detected.")
                    && details
                        .remediation
                        .as_deref()
                        .is_some_and(|text| text.starts_with("Restrict access"))
            })
        }) && !finding.recommendation.contains("Restrict access")
    }));

    let semgrep = details("semgrep");
    assert!(semgrep.iter().any(|details| {
        details
            .description
            .as_deref()
            .is_some_and(|text| text.contains("untrusted input executable"))
            && details.remediation.as_deref()
                == Some("Call the subprocess without a command shell.")
    }));

    let checkov = details("checkov");
    assert!(checkov.iter().any(|details| {
        details.description.as_deref()
            == Some("The bucket rule requires access logging to be enabled.")
    }));

    let kics = details("kics");
    assert!(kics.iter().any(|details| {
        details.description.as_deref()
            == Some("S3 Bucket Object should have server-side encryption enabled")
    }));

    let trivy = details("trivy");
    assert!(trivy.iter().any(|details| {
        details
            .description
            .as_deref()
            .is_some_and(|text| text.contains("affected by the advisory"))
            && details.installed_version.as_deref() == Some("1.0")
            && details.fixed_version.as_deref() == Some("1.1")
    }));

    let grype = details("grype");
    assert!(grype.iter().any(|details| {
        details
            .description
            .as_deref()
            .is_some_and(|text| text.contains("critical vulnerability"))
            && details.installed_version.as_deref() == Some("1.0")
            && details.fixed_version.as_deref() == Some("1.1, 1.2")
    }));

    let kube_bench = details("kube-bench");
    assert!(kube_bench.iter().any(|details| {
        details
            .remediation
            .as_deref()
            .is_some_and(|text| text.contains("authentication: anonymous: enabled"))
    }));
}

#[test]
fn greenbone_xml_with_a_doctype_is_rejected_without_inference() {
    let xml = br#"<?xml version="1.0"?>
<!DOCTYPE report [<!ENTITY secret SYSTEM "file:///etc/passwd">]>
<get_reports_response><report><results><result id="example"><name>&secret;</name><severity>9.9</severity><nvt oid="1.3.6.1.4.1.25623.1.0.1"/></result></results></report></get_reports_response>"#;
    let output = normalize_bytes(
        "greenbone",
        xml,
        "greenbone.xml",
        "application/xml",
        "run-1",
    );
    assert!(output.findings.is_empty());
    assert!(!output.complete);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("DTD"))
    );
}

#[test]
fn greenbone_xml_allows_only_predefined_and_numeric_character_references() {
    let xml = br#"<?xml version="1.0"?>
<get_reports_response><report><results><result id="example"><name>Example&amp;network&#x20;vulnerability</name><host>192.0.2.10</host><port>65535/tcp</port><severity>7.5</severity><threat>High</threat><asset_id>asset-1</asset_id><description>relay -&gt; target</description><nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>Example&amp;NVT&apos;&quot;&lt;&gt;&#x20;reference</name><family>Web&#32;Servers</family></nvt></result></results></report></get_reports_response>"#;
    let output = normalize_bytes(
        "greenbone",
        xml,
        "greenbone.xml",
        "application/xml",
        "run-1",
    );
    assert_eq!(output.findings.len(), 1);
    assert!(
        output.findings[0]
            .title
            .contains("Example&NVT'\"<> reference"),
        "unexpected title: {}",
        output.findings[0].title
    );
    assert!(output.warnings.is_empty());

    let custom = br#"<?xml version="1.0"?>
<get_reports_response><report><results><result id="example"><name>Example&custom;network</name><severity>7.5</severity><nvt oid="1.3.6.1.4.1.25623.1.0.1"/></result></results></report></get_reports_response>"#;
    let rejected = normalize_bytes(
        "greenbone",
        custom,
        "greenbone.xml",
        "application/xml",
        "run-1",
    );
    assert!(rejected.findings.is_empty());
    assert!(
        rejected
            .warnings
            .iter()
            .any(|warning| warning.contains("custom entity"))
    );
}

#[test]
fn artifact_path_escape_is_rejected_without_reading_outside_root() {
    let (bytes, _, media_type) = fixture("nuclei");
    let temp = tempfile::tempdir().expect("temporary artifact root");
    let engine_registry = EngineRegistry::load_builtin().expect("valid engine catalog");
    let manifest = engine_registry.get("nuclei").expect("nuclei manifest");
    let artifact = RawArtifact {
        id: "artifact-escape".into(),
        case_id: "case-1".into(),
        run_id: "run-1".into(),
        engine_run_id: "engine-run-run-1".into(),
        relative_path: "../outside.json".into(),
        media_type: media_type.into(),
        sha256: hex::encode(Sha256::digest(bytes)),
        byte_length: bytes.len() as u64,
        created_at: Utc::now(),
        contains_sensitive_data: false,
    };
    let assets = vec!["asset-1".into()];
    let asset_identifier_map = AdapterAssetIdentifierMap::default();
    let artifacts = vec![artifact];
    let input = AdapterInput {
        case_id: "case-1",
        scan_run_id: "run-1",
        engine_run_id: "engine-run-run-1",
        manifest,
        ai_system_applicable: false,
        ai_generated_artifact_applicable: false,
        asset_ids: &assets,
        asset_identifier_map: &asset_identifier_map,
        artifact_root: Path::new(temp.path()),
        raw_artifacts: &artifacts,
    };
    let output = builtin_adapter_registry()
        .expect("registry")
        .normalize(&input)
        .expect("contained result")
        .expect("adapter");
    assert!(output.findings.is_empty());
    assert!(!output.complete);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("escaped"))
    );
}

#[test]
fn a_result_the_tenant_disputes_is_reported_rather_than_quietly_honoured() {
    // What the wrapper writes for a control ScubaGear failed and the tenant's own
    // ScubaGear config marked incorrect. Upstream rewrites such a control's
    // `Result` to a sentinel and counts it in `IncorrectResults` instead of
    // `Failures`, so reading `Result` alone erased a real failure from the audit
    // with neither a finding nor a counter left behind. The wrapper now takes the
    // verdict from ScubaGear's own `OriginalResult` and leaves the sentinel in
    // `SourceResult`, so the dispute travels with the finding.
    let document = serde_json::json!({
        "Engine": "ScubaGear",
        "Diagnostics": { "passes": 0, "failures": 1, "errors": 0, "manual": 0,
                         "omitted": 0, "disputed": 1, "normalized_results": 2 },
        "Results": [
            { "PolicyId": "MS.AAD.1.1v1", "Result": "Failed",
              "SourceResult": "Incorrect result", "Criticality": "Shall",
              "Requirement": "Block legacy authentication." },
            { "PolicyId": "MS.AAD.2.1v1", "Result": "Failed",
              "SourceResult": "Fail", "Criticality": "Shall",
              "Requirement": "Risky users SHALL be blocked." }
        ]
    });
    let bytes = serde_json::to_vec(&document).expect("serializable document");
    let output = normalize_bytes(
        "scubagear",
        &bytes,
        "attempt-1/output/scubagear.json",
        "application/json",
        "run-m365-disputed",
    );

    let tags_of = |rule: &str| {
        output
            .findings
            .iter()
            .find(|finding| {
                finding
                    .evidence
                    .iter()
                    .any(|evidence| evidence.source_rule.as_deref() == Some(rule))
            })
            .unwrap_or_else(|| panic!("the disputed control must still be a finding: {rule}"))
            .tags
            .clone()
    };
    let disputed = tags_of("MS.AAD.1.1v1");
    let undisputed = tags_of("MS.AAD.2.1v1");
    assert!(
        disputed.iter().any(|tag| tag == "tenant-disputed"),
        "the dispute must be visible on the finding: {disputed:?}"
    );
    assert!(
        !undisputed.iter().any(|tag| tag == "tenant-disputed"),
        "an undisputed failure must not be marked: {undisputed:?}"
    );
    // The control was evaluated and became a finding, so this is not a coverage
    // shortfall and must not be reported as one.
    assert!(
        output.complete,
        "a disputed control is evaluated, not unevaluated: {:?}",
        output.warnings
    );
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("disputes the result of 1 control")),
        "the run must say a dispute occurred: {:?}",
        output.warnings
    );
}

#[test]
fn a_document_the_adapter_cannot_fully_account_for_does_not_read_as_a_clean_run() {
    // The envelope checks used to run only when the fields they read happened to
    // be present, and a `Results` member that could not become a finding was
    // dropped without a word. A document like this one therefore produced one
    // finding, no warnings, and a complete run while silently losing two of the
    // three results the wrapper claimed to have normalized.
    let document = serde_json::json!({
        "Results": [
            "a bare string is not a control",
            { "PolicyId": "MS.AAD.3.3v1", "Requirement": "No status field at all." },
            { "PolicyId": "MS.AAD.1.1v1", "Result": "Failed",
              "Criticality": "Shall", "Requirement": "Block legacy authentication." }
        ]
    });
    let bytes = serde_json::to_vec(&document).expect("serializable document");
    let output = normalize_bytes(
        "scubagear",
        &bytes,
        "attempt-1/output/scubagear.json",
        "application/json",
        "run-m365-unaccounted",
    );

    // The result that is a real control still becomes a finding: the point is to
    // stop claiming completeness, not to discard evidence.
    assert_eq!(output.findings.len(), 1, "{:?}", output.findings);
    assert!(
        !output.complete,
        "two of three declared results were lost: {:?}",
        output.warnings
    );
    for expected in [
        "did not name the engine that wrote it",
        "did not declare how many results it normalized",
        "/Results/0 that is not an object",
        "/Results/1 carried no recognizable status",
    ] {
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains(expected)),
            "no warning mentioned {expected:?}: {:?}",
            output.warnings
        );
    }
}

/// Return every finding's `source-rule:` tag paired with its severity.
///
/// The rule identity is asserted through the tag rather than a struct field
/// because that tag is what reaches an export and a mapping lookup.
/// Trivy and Grype scanning one image is the ordinary case, and their results
/// overlap heavily. This drives both real adapters and then asks the
/// correlation rule which of the resulting rows describe one issue — the whole
/// chain from engine output to the single list the user reads.
#[test]
fn one_vulnerability_seen_by_trivy_and_grype_is_offered_as_a_single_row() {
    let mut case = AssessmentCase::new(
        "Correlation".into(),
        OrganizationProfile {
            organization_name: "Example".into(),
            employee_range: "2-49".into(),
            data_classes: vec![DataClass::PersonallyIdentifiableInformation],
            notes: None,
        },
    );
    for engine_id in ["trivy", "grype"] {
        let output = normalize_fixture(engine_id);
        assert_eq!(
            output.findings.len(),
            2,
            "{engine_id} fixture carries one shared and one exclusive vulnerability"
        );
        for mut finding in output.findings {
            finding.case_id = case.id.clone();
            case.findings.push(finding);
        }
    }

    let report = correlation_report(&case);

    assert_eq!(
        case.findings.len(),
        4,
        "correlation is a suggestion; it never removes a row"
    );
    assert_eq!(report.suggestions.len(), 1, "{report:?}");
    let suggestion = &report.suggestions[0];
    assert_eq!(suggestion.engine_ids, ["grype", "trivy"]);
    assert!(
        suggestion.comparison_key.contains("CVE-2024-2511")
            && suggestion.comparison_key.contains("openssl"),
        "the shared vulnerability is the one that correlates: {}",
        suggestion.comparison_key
    );

    let members = suggestion
        .finding_ids
        .iter()
        .map(|finding_id| {
            case.findings
                .iter()
                .find(|finding| &finding.id == finding_id)
                .expect("suggested member is a real finding in the case")
        })
        .collect::<Vec<_>>();
    assert_eq!(members.len(), 2);
    // Trivy says MEDIUM, Grype says Medium. Aligning them onto one row is only
    // meaningful if the normalized severity already agrees.
    assert!(
        members
            .iter()
            .all(|finding| finding.severity == Severity::Medium),
        "both engines' severities normalize to the same level: {:?}",
        members
            .iter()
            .map(|finding| finding.severity.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        members.iter().all(|finding| !finding.evidence.is_empty()),
        "each member keeps its own evidence rather than borrowing the other's"
    );

    // The vulnerabilities only one engine saw must stay as their own rows.
    let suggested = suggestion.finding_ids.iter().collect::<BTreeSet<_>>();
    let unsuggested = case
        .findings
        .iter()
        .filter(|finding| !suggested.contains(&finding.id))
        .filter_map(|finding| {
            finding
                .tags
                .iter()
                .find_map(|tag| tag.strip_prefix("source-rule:"))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        unsuggested,
        ["cve-2025-0001", "cve-2025-0002"].into_iter().collect(),
        "an issue only one engine reported is never folded into another row"
    );
    assert!(report.unverifiable.is_empty(), "{report:?}");
}

fn rules_and_severities(output: &AdapterOutput) -> BTreeMap<String, Severity> {
    output
        .findings
        .iter()
        .map(|finding| {
            let rule = finding
                .tags
                .iter()
                .find_map(|tag| tag.strip_prefix("source-rule:"))
                .expect("every finding carries its source rule")
                .to_owned();
            (rule, finding.severity.clone())
        })
        .collect()
}

#[test]
fn scoutsuite_rule_identity_survives_being_stored_only_as_a_parent_key() {
    // ScoutSuite writes `services.<service>.findings.<rule key>` and never
    // repeats the key inside the object, so a parser that only reads fields
    // finds no rule id and silently drops the entire run.
    let output = normalize_fixture("scoutsuite");
    let found = rules_and_severities(&output);

    assert_eq!(
        found.keys().cloned().collect::<Vec<_>>(),
        vec![
            "iam-ec2-role-without-instances".to_owned(),
            "iam-password-policy-no-uppercase-required".to_owned(),
            "s3-bucket-world-policy-star".to_owned(),
        ],
        "each flagged rule keeps the key ScoutSuite filed it under"
    );

    // 125 of ScoutSuite's 197 default AWS rules are graded `danger`; leaving
    // that word unmapped sent the majority of the engine to `Unknown`.
    assert_eq!(
        found["iam-password-policy-no-uppercase-required"],
        Severity::High
    );
    assert_eq!(found["s3-bucket-world-policy-star"], Severity::High);
    assert_eq!(found["iam-ec2-role-without-instances"], Severity::Medium);

    let uppercase = output
        .findings
        .iter()
        .find(|finding| {
            finding
                .tags
                .iter()
                .any(|tag| tag == "source-rule:iam-password-policy-no-uppercase-required")
        })
        .expect("uppercase password rule");
    assert_eq!(
        uppercase.evidence[0]
            .scanner_details
            .as_ref()
            .map(|details| details.benchmarks.clone()),
        Some(vec![BenchmarkReference {
            name: "CIS Amazon Web Services Foundations".into(),
            version: "1.2.0".into(),
            reference: "1.5".into(),
        }])
    );

    assert!(
        !found.contains_key("iam-password-policy-minimum-length"),
        "a rule with zero flagged items is not a finding"
    );
    // ScoutSuite's other rule type, `filters`, tags resources for the report
    // and shares the findings object shape, flagged counts included. Deriving a
    // rule id from any pointer would turn those into findings.
    assert!(
        !found.contains_key("s3-bucket-website-enabled"),
        "a `filters` entry is not a finding"
    );
    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
}

#[test]
fn cloudsplaining_risks_are_read_from_policies_not_the_document_root() {
    // `iam-findings-<account>.json` is `authorization_details.results`, keyed by
    // principal and policy collection. Every risk is an object whose
    // `findings` array sits inside a policy, so nothing recognisable appears at
    // the root.
    let output = normalize_fixture("cloudsplaining");
    let found = rules_and_severities(&output);

    assert!(
        output.complete,
        "the pinned upstream shape is complete: {:?}",
        output.warnings
    );
    assert_eq!(
        output.findings.len(),
        18,
        "each upstream finding remains distinct instead of collapsing a whole category into one result"
    );

    // Severities come from each category object's upstream field, not a table
    // repeated in the adapter. The tag is lowercased by `safe_tag`; the mapping
    // lookup keeps the exact case, which the control-reference assertion below
    // covers.
    assert_eq!(found["privilegeescalation"], Severity::High);
    assert_eq!(found["credentialsexposure"], Severity::High);
    assert_eq!(found["resourceexposure"], Severity::High);
    assert_eq!(found["dataexfiltration"], Severity::Medium);
    assert_eq!(found["servicewildcard"], Severity::Medium);
    assert_eq!(found["infrastructuremodification"], Severity::Low);

    // The catalog previously mapped `iam-privesc`, a rule Cloudsplaining never
    // emits, so no real run could ever resolve a framework relationship.
    let escalation = output
        .findings
        .iter()
        .find(|finding| {
            finding
                .tags
                .iter()
                .any(|tag| tag == "source-rule:privilegeescalation")
        })
        .expect("a privilege-escalation finding");
    assert!(
        !escalation.control_references.is_empty(),
        "the corrected mapping coordinate resolves for real output"
    );

    let titles = output
        .findings
        .iter()
        .map(|finding| finding.title.as_str())
        .collect::<BTreeSet<_>>();
    assert!(
        titles.contains("PrivilegeEscalation: CreateAccessKey in policy IAMFullAccess"),
        "a finding names both the upstream identity and policy: {titles:?}"
    );
    assert!(
        titles.contains("ResourceExposure: s3:PutObjectAcl in policy InsecurePolicy"),
        "customer-managed policies are read too: {titles:?}"
    );
    assert!(
        titles.contains("DataExfiltration: s3:GetObject in policy InlinePolicyForAdminGroup"),
        "inline policies are read too: {titles:?}"
    );

    assert!(
        !titles
            .iter()
            .any(|title| title.contains("AdministratorAccess")),
        "Cloudsplaining already excluded that policy; re-reporting it overrules the tool: {titles:?}"
    );

    // Whether the account owner can edit the policy changes the remediation,
    // so it survives as typed evidence rather than an opaque display tag.
    let sources = output
        .findings
        .iter()
        .filter_map(|finding| {
            finding
                .evidence
                .first()?
                .scanner_details
                .as_ref()?
                .aws_iam_policy
                .as_ref()
        })
        .map(|details| match details.policy_source {
            AwsIamPolicySource::AwsManaged => "aws-managed",
            AwsIamPolicySource::CustomerManaged => "customer-managed",
            AwsIamPolicySource::Inline => "inline",
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        sources,
        BTreeSet::from(["aws-managed", "customer-managed", "inline"]),
        "each policy collection is distinguishable in the findings list"
    );

    let create_key = output
        .findings
        .iter()
        .find(|finding| {
            finding.title == "PrivilegeEscalation: CreateAccessKey in policy IAMFullAccess"
        })
        .expect("individual privilege-escalation method");
    assert_eq!(create_key.severity, Severity::High);
    assert_eq!(create_key.severity_basis_code, None);
    assert!(
        create_key
            .tags
            .iter()
            .any(|tag| tag == "source-severity:high"),
        "the report identifies the category rating as upstream-provided"
    );
    let evidence = create_key.evidence.first().expect("raw result evidence");
    let iam = evidence
        .scanner_details
        .as_ref()
        .and_then(|details| details.aws_iam_policy.as_ref())
        .expect("typed Cloudsplaining policy context");
    assert_eq!(iam.policy_source, AwsIamPolicySource::AwsManaged);
    assert_eq!(iam.policy_name, "IAMFullAccess");
    assert_eq!(iam.finding_identity, "CreateAccessKey");
    assert_eq!(iam.actions, ["iam:createaccesskey"]);
    assert!(iam.actions_complete);
    assert_eq!(iam.attached_to.groups, ["AdminGroup"]);
    assert!(iam.attached_to.complete);
    assert!(
        create_key
            .recommendation
            .contains("Replace AWS-managed policy IAMFullAccess")
            && create_key.recommendation.contains("group AdminGroup")
            && create_key
                .recommendation
                .contains("AWS-managed policies cannot be edited"),
        "the shared report gives the action that fits AWS-owned policy evidence: {}",
        create_key.recommendation
    );
    assert_eq!(
        evidence.location.as_deref(),
        Some("arn:aws:iam::aws:policy/IAMFullAccess :: CreateAccessKey")
    );
    assert_eq!(
        evidence.pointer.as_deref(),
        Some("/aws_managed_policies/ANPAI7XKCFMBPM3QQRRVQ/PrivilegeEscalation/findings/0")
    );
    assert_eq!(
        evidence
            .scanner_details
            .as_ref()
            .and_then(|details| details.description.as_deref()),
        Some(
            "<p>These policies allow a combination of IAM actions that allow a principal with these permissions to escalate their privileges - for example, by creating an access key for another IAM user, or modifying their own permissions. This research was pioneered by Spencer Gietzen at Rhino Security Labs. Remediation guidance can be found <a href=\"https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/\">here</a>.</p>"
        ),
        "the pinned upstream HTML description is retained as untrusted text rather than paraphrased by the adapter"
    );
    assert!(
        create_key
            .official_references
            .iter()
            .any(|reference| reference == "https://pathfinding.cloud/paths/iam-002"),
        "the category's method link survives normalization"
    );
    assert!(
        create_key
            .official_references
            .iter()
            .any(|reference| reference.contains("docs.aws.amazon.com/service-authorization")),
        "the upstream action link survives normalization"
    );

    let customer_managed = output
        .findings
        .iter()
        .find(|finding| {
            finding.title == "ResourceExposure: s3:PutObjectAcl in policy InsecurePolicy"
        })
        .expect("customer-managed finding");
    let customer_context = customer_managed.evidence[0]
        .scanner_details
        .as_ref()
        .and_then(|details| details.aws_iam_policy.as_ref())
        .expect("customer-managed context");
    assert_eq!(
        customer_context.policy_source,
        AwsIamPolicySource::CustomerManaged
    );
    assert_eq!(customer_context.attached_to.users, ["ExampleUser"]);
    assert!(
        customer_managed
            .recommendation
            .contains("Narrow customer-managed policy InsecurePolicy")
    );

    let inline = output
        .findings
        .iter()
        .find(|finding| {
            finding.title == "DataExfiltration: s3:GetObject in policy InlinePolicyForAdminGroup"
        })
        .expect("inline-policy finding");
    let inline_context = inline.evidence[0]
        .scanner_details
        .as_ref()
        .and_then(|details| details.aws_iam_policy.as_ref())
        .expect("inline-policy context");
    assert_eq!(inline_context.policy_source, AwsIamPolicySource::Inline);
    assert_eq!(inline_context.attached_to.groups, ["AdminGroup"]);
    assert!(inline.recommendation.contains("Narrow inline policy"));
    assert!(
        output
            .findings
            .iter()
            .all(|finding| finding.tags.iter().all(|tag| {
                !tag.starts_with("policy-source:")
                    && !tag.starts_with("upstream-finding:")
                    && !tag.starts_with("upstream-action:")
            }))
    );
}

#[test]
fn cloudsplaining_keeps_bounded_principal_context_and_marks_incomplete_attribution() {
    let mut document: serde_json::Value =
        serde_json::from_slice(fixture("cloudsplaining").0).expect("Cloudsplaining fixture JSON");
    let roles = (0..33)
        .map(|index| serde_json::Value::String(format!("Role{index:02}")))
        .collect::<Vec<_>>();
    let attached = &mut document["customer_managed_policies"]["InsecurePolicy"]["AttachedTo"];
    attached["roles"] = serde_json::Value::Array(roles);
    attached["groups"] = serde_json::json!("not-an-array");
    attached["users"] = serde_json::json!(["User\nName", null]);

    let bytes = serde_json::to_vec(&document).expect("attachment-drifted fixture JSON");
    let output = normalize_bytes(
        "cloudsplaining",
        &bytes,
        "cloudsplaining.json",
        "application/json",
        "run-attachment-context",
    );

    assert!(
        !output.complete,
        "incomplete attribution must remain visible"
    );
    let finding = output
        .findings
        .iter()
        .find(|finding| finding.title.contains("policy InsecurePolicy"))
        .expect("valid sibling finding survives attachment drift");
    let context = finding.evidence[0]
        .scanner_details
        .as_ref()
        .and_then(|details| details.aws_iam_policy.as_ref())
        .expect("bounded policy context");
    assert_eq!(context.attached_to.roles.len(), 32);
    assert!(context.attached_to.groups.is_empty());
    assert_eq!(context.attached_to.users, ["User Name"]);
    assert!(!context.attached_to.complete);
    assert!(
        finding
            .recommendation
            .contains("Confirm the current IAM attachments first")
    );
    for expected in ["AttachedTo.roles", "AttachedTo.groups", "AttachedTo.users"] {
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains(expected)),
            "missing bounded-attribution warning for {expected}: {:?}",
            output.warnings
        );
    }
}

#[test]
fn cloudsplaining_uses_the_next_nonempty_upstream_policy_identity() {
    let mut document: serde_json::Value =
        serde_json::from_slice(fixture("cloudsplaining").0).expect("Cloudsplaining fixture JSON");
    document["customer_managed_policies"]["InsecurePolicy"]["Arn"] = serde_json::json!("   ");

    let bytes = serde_json::to_vec(&document).expect("identity-fallback fixture JSON");
    let output = normalize_bytes(
        "cloudsplaining",
        &bytes,
        "cloudsplaining.json",
        "application/json",
        "run-policy-identity-fallback",
    );

    assert!(
        output.complete,
        "an empty optional ARN must not hide the valid PolicyId: {:?}",
        output.warnings
    );
    let finding = output
        .findings
        .iter()
        .find(|finding| finding.title.contains("policy InsecurePolicy"))
        .expect("customer-managed finding survives the empty ARN");
    assert!(
        finding.evidence[0]
            .location
            .as_deref()
            .is_some_and(|location| location.starts_with("InsecurePolicy ::")),
        "the exact nonempty PolicyId remains the evidence location"
    );
}

#[test]
fn cloudsplaining_marks_a_bounded_action_list_without_hiding_the_finding() {
    let mut document: serde_json::Value =
        serde_json::from_slice(fixture("cloudsplaining").0).expect("Cloudsplaining fixture JSON");
    document["aws_managed_policies"]["ANPAI7XKCFMBPM3QQRRVQ"]["PrivilegeEscalation"]["findings"]
        [0]["actions"] = serde_json::Value::Array(
        (0..33)
            .map(|index| serde_json::Value::String(format!("iam:Action{index:02}")))
            .collect(),
    );

    let bytes = serde_json::to_vec(&document).expect("large-action fixture JSON");
    let output = normalize_bytes(
        "cloudsplaining",
        &bytes,
        "cloudsplaining.json",
        "application/json",
        "run-action-context",
    );

    assert!(!output.complete, "bounded action context must be disclosed");
    let finding = output
        .findings
        .iter()
        .find(|finding| {
            finding.title == "PrivilegeEscalation: CreateAccessKey in policy IAMFullAccess"
        })
        .expect("finding with bounded actions survives");
    let context = finding.evidence[0]
        .scanner_details
        .as_ref()
        .and_then(|details| details.aws_iam_policy.as_ref())
        .expect("typed policy context");
    assert_eq!(context.actions.len(), 32);
    assert!(!context.actions_complete);
    assert!(output.warnings.iter().any(|warning| {
        warning.contains("finding actions")
            && warning.contains("complete list stays in raw evidence")
    }));
}

#[test]
fn cloudsplaining_does_not_require_attachment_metadata_for_a_policy_with_no_findings() {
    let mut document: serde_json::Value =
        serde_json::from_slice(fixture("cloudsplaining").0).expect("Cloudsplaining fixture JSON");
    let mut clean_policy = document["customer_managed_policies"]["InsecurePolicy"].clone();
    clean_policy["PolicyName"] = serde_json::json!("CleanPolicy");
    clean_policy["PolicyId"] = serde_json::json!("clean-policy");
    clean_policy["Arn"] = serde_json::json!("arn:aws:iam::012345678901:policy/CleanPolicy");
    clean_policy
        .as_object_mut()
        .expect("policy object")
        .remove("AttachedTo");
    for risk in [
        "PrivilegeEscalation",
        "DataExfiltration",
        "ResourceExposure",
        "ServiceWildcard",
        "CredentialsExposure",
        "InfrastructureModification",
    ] {
        clean_policy[risk]["findings"] = serde_json::json!([]);
    }
    document["customer_managed_policies"]
        .as_object_mut()
        .expect("policy section")
        .insert("CleanPolicy".into(), clean_policy);

    let bytes = serde_json::to_vec(&document).expect("clean policy fixture JSON");
    let output = normalize_bytes(
        "cloudsplaining",
        &bytes,
        "cloudsplaining.json",
        "application/json",
        "run-clean-policy",
    );

    assert!(
        output.complete,
        "unused attachment metadata must not make a clean policy partial: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 18);
    assert!(
        output.warnings.iter().all(|warning| {
            !(warning.contains("CleanPolicy") && warning.contains("AttachedTo"))
        })
    );
}

#[test]
fn cloudsplaining_unrenderable_identity_does_not_consume_a_valid_finding_quota() {
    let mut findings = (0..257)
        .map(|_| serde_json::Value::String("\u{0007}".into()))
        .collect::<Vec<_>>();
    findings.extend(
        (0..=10_000).map(|index| serde_json::Value::String(format!("s3:ReadableAction{index:05}"))),
    );
    let empty_category = |severity: &str| {
        serde_json::json!({
            "severity": severity,
            "description": "Pinned upstream category description",
            "findings": []
        })
    };
    let mut document = serde_json::json!({
        "customer_managed_policies": {},
        "inline_policies": {},
        "aws_managed_policies": {
            "quota-policy": {
                "PolicyName": "QuotaPolicy",
                "PolicyId": "quota-policy",
                "AttachedTo": {"roles": ["ReviewRole"], "groups": [], "users": []},
                "PrivilegeEscalation": {
                    "severity": "high",
                    "description": "Pinned upstream category description",
                    "findings": [],
                    "links": {}
                },
                "DataExfiltration": empty_category("medium"),
                "ResourceExposure": {
                    "severity": "high",
                    "description": "Pinned upstream category description",
                    "findings": findings
                },
                "ServiceWildcard": empty_category("medium"),
                "CredentialsExposure": empty_category("high"),
                "InfrastructureModification": empty_category("low"),
                "is_excluded": false
            }
        },
        "groups": [],
        "users": [],
        "roles": [],
        "exclusions": {"policies": [], "roles": [], "users": [], "groups": []},
        "links": {}
    });
    for kind in ["roles", "groups", "users"] {
        document["aws_managed_policies"]["quota-policy"]["AttachedTo"][kind] =
            serde_json::Value::Array(
                (0..32)
                    .map(|index| {
                        serde_json::Value::String(format!("{kind}-{index:02}-{}", "x".repeat(480)))
                    })
                    .collect(),
            );
    }
    let bytes = serde_json::to_vec(&document).expect("quota fixture JSON");
    let output = normalize_bytes(
        "cloudsplaining",
        &bytes,
        "cloudsplaining.json",
        "application/json",
        "run-display-quota",
    );

    assert!(!output.complete, "the discarded malformed row is disclosed");
    assert_eq!(output.findings.len(), 10_000);
    assert!(
        output
            .findings
            .iter()
            .any(|finding| finding.title.contains("s3:ReadableAction09999"))
    );
    let repeated_principal_cost = output
        .findings
        .iter()
        .filter_map(|finding| finding.evidence[0].scanner_details.as_ref())
        .filter_map(|details| details.aws_iam_policy.as_ref())
        .flat_map(|iam| {
            iam.attached_to
                .roles
                .iter()
                .chain(&iam.attached_to.groups)
                .chain(&iam.attached_to.users)
        })
        .fold(0_usize, |total, principal| {
            total + std::mem::size_of::<String>() + principal.len()
        });
    assert!(repeated_principal_cost <= 2 * 1024 * 1024);
    assert!(output.warnings.iter().any(|warning| {
        warning.contains("principal context exceeded the bounded report budget")
    }));
    assert!(output.warnings.iter().any(|warning| {
        warning.contains("reported 10001 valid policy findings")
            && warning.contains("retained 10000")
            && warning.contains("1 remain only in raw evidence")
    }));
}

#[test]
fn cloudsplaining_preserves_high_priority_principals_before_low_priority_context() {
    let empty_category = |severity: &str| {
        serde_json::json!({
            "severity": severity,
            "description": "Pinned upstream category description",
            "findings": []
        })
    };
    let long_principals = (0..32)
        .map(|index| format!("LowPriorityPrincipal{index:02}-{}", "x".repeat(470)))
        .collect::<Vec<_>>();
    let document = serde_json::json!({
        "customer_managed_policies": {
            "low-policy": {
                "PolicyName": "LowPolicy",
                "PolicyId": "low-policy",
                "AttachedTo": {
                    "roles": long_principals.clone(),
                    "groups": long_principals.clone(),
                    "users": long_principals
                },
                "PrivilegeEscalation": {
                    "severity": "high",
                    "description": "Pinned upstream category description",
                    "findings": [],
                    "links": {}
                },
                "DataExfiltration": empty_category("medium"),
                "ResourceExposure": empty_category("high"),
                "ServiceWildcard": empty_category("medium"),
                "CredentialsExposure": empty_category("high"),
                "InfrastructureModification": {
                    "severity": "low",
                    "description": "Pinned upstream category description",
                    "findings": (0..50).map(|index| format!("ec2:LowAction{index:02}")).collect::<Vec<_>>()
                },
                "is_excluded": false
            }
        },
        "inline_policies": {},
        "aws_managed_policies": {
            "high-policy": {
                "PolicyName": "HighPolicy",
                "PolicyId": "high-policy",
                "AttachedTo": {"roles": ["HighPriorityOwner"], "groups": [], "users": []},
                "PrivilegeEscalation": {
                    "severity": "high",
                    "description": "Pinned upstream category description",
                    "findings": [],
                    "links": {}
                },
                "DataExfiltration": empty_category("medium"),
                "ResourceExposure": empty_category("high"),
                "ServiceWildcard": empty_category("medium"),
                "CredentialsExposure": {
                    "severity": "high",
                    "description": "Pinned upstream category description",
                    "findings": ["iam:CreateAccessKey"]
                },
                "InfrastructureModification": empty_category("low"),
                "is_excluded": false
            }
        },
        "groups": [],
        "users": [],
        "roles": [],
        "exclusions": {"policies": [], "roles": [], "users": [], "groups": []},
        "links": {}
    });

    let bytes = serde_json::to_vec(&document).expect("priority-context fixture JSON");
    let output = normalize_bytes(
        "cloudsplaining",
        &bytes,
        "cloudsplaining.json",
        "application/json",
        "run-principal-priority",
    );

    let high = output
        .findings
        .iter()
        .find(|finding| finding.title.contains("policy HighPolicy"))
        .expect("high-priority policy finding");
    let iam = high.evidence[0]
        .scanner_details
        .as_ref()
        .and_then(|details| details.aws_iam_policy.as_ref())
        .expect("typed high-priority context");
    assert_eq!(iam.attached_to.roles, ["HighPriorityOwner"]);
    assert!(iam.attached_to.complete);
    assert!(output.warnings.iter().any(|warning| {
        warning.contains("principal context exceeded the bounded report budget")
    }));
}

#[test]
fn cloudsplaining_severity_is_read_from_the_category_object() {
    let mut document: serde_json::Value =
        serde_json::from_slice(fixture("cloudsplaining").0).expect("Cloudsplaining fixture JSON");
    document["aws_managed_policies"]["ANPAI7XKCFMBPM3QQRRVQ"]["PrivilegeEscalation"]["severity"] =
        serde_json::json!("critical");
    let bytes = serde_json::to_vec(&document).expect("changed fixture JSON");
    let output = normalize_bytes(
        "cloudsplaining",
        &bytes,
        "cloudsplaining.json",
        "application/json",
        "run-source-severity",
    );

    let escalations = output
        .findings
        .iter()
        .filter(|finding| {
            finding
                .tags
                .iter()
                .any(|tag| tag == "source-rule:privilegeescalation")
        })
        .collect::<Vec<_>>();
    assert_eq!(escalations.len(), 2);
    assert!(
        escalations.iter().all(|finding| {
            finding.severity == Severity::Critical
                && finding.severity_basis_code.is_none()
                && finding
                    .tags
                    .iter()
                    .any(|tag| tag == "source-severity:critical")
        }),
        "changing the upstream field changes the normalized rating without an adapter-side category scale"
    );
    assert!(
        output.complete,
        "unexpected warnings: {:?}",
        output.warnings
    );
}

#[test]
fn cloudsplaining_schema_drift_is_partial_without_erasing_valid_siblings() {
    let mut document: serde_json::Value =
        serde_json::from_slice(fixture("cloudsplaining").0).expect("Cloudsplaining fixture JSON");
    document
        .as_object_mut()
        .expect("fixture root")
        .remove("inline_policies");
    document["customer_managed_policies"] = serde_json::json!([]);
    let policy = &mut document["aws_managed_policies"]["ANPAI7XKCFMBPM3QQRRVQ"];
    policy["DataExfiltration"] = serde_json::json!([]);
    policy["ResourceExposure"]
        .as_object_mut()
        .expect("category object")
        .remove("findings");
    policy
        .as_object_mut()
        .expect("policy object")
        .remove("ServiceWildcard");
    policy["InfrastructureModification"]
        .as_object_mut()
        .expect("category object")
        .remove("severity");
    policy["CredentialsExposure"]["severity"] = serde_json::json!("   ");
    policy["CredentialsExposure"]
        .as_object_mut()
        .expect("category object")
        .remove("description");
    policy["PrivilegeEscalation"]["findings"]
        .as_array_mut()
        .expect("findings array")
        .push(serde_json::json!({"actions": ["iam:putuserpolicy"]}));

    let bytes = serde_json::to_vec(&document).expect("drifted fixture JSON");
    let output = normalize_bytes(
        "cloudsplaining",
        &bytes,
        "cloudsplaining.json",
        "application/json",
        "run-schema-drift",
    );

    assert!(!output.complete, "schema drift must never look clean");
    assert_eq!(
        output.findings.len(),
        6,
        "missing or empty category severity does not erase otherwise valid findings"
    );
    assert!(
        output
            .findings
            .iter()
            .any(|finding| finding.title.contains("CreateAccessKey")),
        "a valid sibling remains actionable"
    );
    let unrated = output
        .findings
        .iter()
        .filter(|finding| {
            finding
                .tags
                .iter()
                .any(|tag| tag == "severity-basis:unrated")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        unrated.len(),
        4,
        "both findings in each missing- and empty-severity category survive as unrated"
    );
    assert!(unrated.iter().all(|finding| {
        finding.severity == Severity::Unknown
            && finding.severity_basis_code
                == Some(SeverityBasisCode::CloudsplainingIamPolicyFinding)
            && finding
                .plain_language_summary
                .contains("without a severity rating")
    }));
    for expected in [
        "lacked required policy section inline_policies",
        "policy section customer_managed_policies was not an object",
        "category at /aws_managed_policies/ANPAI7XKCFMBPM3QQRRVQ/DataExfiltration was not an object",
        "category at /aws_managed_policies/ANPAI7XKCFMBPM3QQRRVQ/ResourceExposure lacked its findings array",
        "policy at /aws_managed_policies/ANPAI7XKCFMBPM3QQRRVQ lacked category ServiceWildcard",
        "category at /aws_managed_policies/ANPAI7XKCFMBPM3QQRRVQ/InfrastructureModification lacked its source severity",
        "category at /aws_managed_policies/ANPAI7XKCFMBPM3QQRRVQ/CredentialsExposure lacked its source severity",
        "category at /aws_managed_policies/ANPAI7XKCFMBPM3QQRRVQ/CredentialsExposure lacked its source description",
        "finding at /aws_managed_policies/ANPAI7XKCFMBPM3QQRRVQ/PrivilegeEscalation/findings/2 did not match the pinned PrivilegeEscalation entry shape",
    ] {
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains(expected)),
            "missing warning for {expected}: {:?}",
            output.warnings
        );
    }
}

#[test]
fn cloudsplaining_enforces_each_pinned_category_entry_shape() {
    let mut document: serde_json::Value =
        serde_json::from_slice(fixture("cloudsplaining").0).expect("Cloudsplaining fixture JSON");
    let policy = &mut document["aws_managed_policies"]["ANPAI7XKCFMBPM3QQRRVQ"];
    policy["PrivilegeEscalation"]["findings"][0] = serde_json::json!("CreateAccessKey");
    policy["PrivilegeEscalation"]["findings"][1] = serde_json::json!({
        "type": "CreateLoginProfile",
        "actions": ["iam:createloginprofile"],
        "unexpected": true
    });
    document["inline_policies"]["ffd2b5250e18691dbd9f0fb8b36640ec574867835837f17d39f859c3193fb3f2"]
        ["DataExfiltration"]["findings"][0] = serde_json::json!({
        "type": "s3:GetObject",
        "actions": ["s3:GetObject"]
    });
    document["customer_managed_policies"]["InsecurePolicy"]["InfrastructureModification"]["findings"]
        [0] = serde_json::json!("   ");

    let bytes = serde_json::to_vec(&document).expect("shape-drifted fixture JSON");
    let output = normalize_bytes(
        "cloudsplaining",
        &bytes,
        "cloudsplaining.json",
        "application/json",
        "run-entry-shapes",
    );

    assert!(!output.complete, "wrong entry shapes must be disclosed");
    assert_eq!(
        output.findings.len(),
        14,
        "only the four malformed entries are withheld from normalized findings"
    );
    for expected in [
        "/PrivilegeEscalation/findings/0 did not match the pinned PrivilegeEscalation entry shape",
        "/PrivilegeEscalation/findings/1 did not match the pinned PrivilegeEscalation entry shape",
        "/DataExfiltration/findings/0 did not match the pinned DataExfiltration entry shape",
        "/InfrastructureModification/findings/0 did not match the pinned InfrastructureModification entry shape",
    ] {
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains(expected)),
            "missing shape warning {expected:?}: {:?}",
            output.warnings
        );
    }
}

#[test]
fn cloudsplaining_requires_an_explicit_boolean_exclusion_decision_per_policy() {
    let mut document: serde_json::Value =
        serde_json::from_slice(fixture("cloudsplaining").0).expect("Cloudsplaining fixture JSON");
    document["customer_managed_policies"]["InsecurePolicy"]
        .as_object_mut()
        .expect("customer-managed policy")
        .remove("is_excluded");
    document["aws_managed_policies"]["ANPAI7XKCFMBPM3QQRRVQ"]["is_excluded"] =
        serde_json::json!("false");

    let bytes = serde_json::to_vec(&document).expect("exclusion-drifted fixture JSON");
    let output = normalize_bytes(
        "cloudsplaining",
        &bytes,
        "cloudsplaining.json",
        "application/json",
        "run-exclusion-shape",
    );

    assert!(!output.complete, "unknown exclusion state must be partial");
    assert_eq!(
        output.findings.len(),
        6,
        "the two ambiguous policies stay raw-only while the valid inline-policy sibling survives"
    );
    assert!(
        output
            .findings
            .iter()
            .any(|finding| finding.title.contains("InlinePolicyForAdminGroup")),
        "a valid sibling policy remains actionable"
    );
    for policy_pointer in [
        "/customer_managed_policies/InsecurePolicy",
        "/aws_managed_policies/ANPAI7XKCFMBPM3QQRRVQ",
    ] {
        assert!(
            output.warnings.iter().any(|warning| {
                warning.contains(policy_pointer) && warning.contains("required boolean is_excluded")
            }),
            "missing exclusion warning for {policy_pointer}: {:?}",
            output.warnings
        );
    }
}

#[test]
fn cloudsplaining_required_links_are_partial_but_never_erase_findings() {
    let original: serde_json::Value =
        serde_json::from_slice(fixture("cloudsplaining").0).expect("Cloudsplaining fixture JSON");
    let mut cases = Vec::new();

    let mut missing_root = original.clone();
    missing_root
        .as_object_mut()
        .expect("fixture root")
        .remove("links");
    cases.push((
        "missing-root",
        missing_root,
        "lacked its required links object",
    ));

    let mut wrong_root = original.clone();
    wrong_root["links"] = serde_json::json!([]);
    cases.push(("wrong-root", wrong_root, "output links were not an object"));

    let mut missing_category_links = original.clone();
    missing_category_links["aws_managed_policies"]["ANPAI7XKCFMBPM3QQRRVQ"]["PrivilegeEscalation"]
        .as_object_mut()
        .expect("privilege-escalation category")
        .remove("links");
    cases.push((
        "missing-category-links",
        missing_category_links,
        "PrivilegeEscalation category at /aws_managed_policies/ANPAI7XKCFMBPM3QQRRVQ/PrivilegeEscalation lacked its required links object",
    ));

    let mut wrong_category_links = original.clone();
    wrong_category_links["aws_managed_policies"]["ANPAI7XKCFMBPM3QQRRVQ"]["PrivilegeEscalation"]
        ["links"] = serde_json::json!([]);
    cases.push((
        "wrong-category-links",
        wrong_category_links,
        "PrivilegeEscalation category at /aws_managed_policies/ANPAI7XKCFMBPM3QQRRVQ/PrivilegeEscalation lacked its required links object",
    ));

    let mut missing_method = original.clone();
    missing_method["aws_managed_policies"]["ANPAI7XKCFMBPM3QQRRVQ"]["PrivilegeEscalation"]["links"]
        .as_object_mut()
        .expect("privilege-escalation links")
        .remove("CreateAccessKey");
    cases.push((
        "missing-method",
        missing_method,
        "privilege-escalation finding at /aws_managed_policies/ANPAI7XKCFMBPM3QQRRVQ/PrivilegeEscalation/findings/0 lacked its required method link",
    ));

    let mut malformed_action = original.clone();
    malformed_action["links"]["iam:createaccesskey"] = serde_json::json!(42);
    cases.push((
        "malformed-action",
        malformed_action,
        "action link for iam:createaccesskey was malformed",
    ));

    for (name, document, expected_warning) in cases {
        let bytes = serde_json::to_vec(&document).expect("changed fixture JSON");
        let output = normalize_bytes(
            "cloudsplaining",
            &bytes,
            "cloudsplaining.json",
            "application/json",
            &format!("run-links-{name}"),
        );
        assert_eq!(
            output.findings.len(),
            18,
            "{name}: link drift must not erase valid policy findings"
        );
        assert!(!output.complete, "{name}: required link drift is partial");
        assert!(
            output
                .warnings
                .iter()
                .any(|warning| warning.contains(expected_warning)),
            "{name}: missing warning {expected_warning:?}: {:?}",
            output.warnings
        );
    }

    let mut allowed_sparse_actions = original;
    let action_links = allowed_sparse_actions["links"]
        .as_object_mut()
        .expect("root action links");
    action_links.insert("iam:createaccesskey".into(), serde_json::Value::Null);
    action_links.remove("iam:createloginprofile");
    let bytes = serde_json::to_vec(&allowed_sparse_actions).expect("changed fixture JSON");
    let output = normalize_bytes(
        "cloudsplaining",
        &bytes,
        "cloudsplaining.json",
        "application/json",
        "run-sparse-action-links",
    );
    assert!(
        output.complete,
        "upstream explicitly permits null or absent action-documentation links: {:?}",
        output.warnings
    );
    assert_eq!(output.findings.len(), 18);
}

#[test]
fn cloudsplaining_exact_long_identities_do_not_collapse_or_miss_links() {
    let mut document: serde_json::Value =
        serde_json::from_slice(fixture("cloudsplaining").0).expect("Cloudsplaining fixture JSON");
    let shared_prefix = "X".repeat(700);
    let identity_a = format!("{shared_prefix}-A");
    let identity_b = format!("{shared_prefix}-B");
    let category =
        &mut document["aws_managed_policies"]["ANPAI7XKCFMBPM3QQRRVQ"]["PrivilegeEscalation"];
    category["findings"] = serde_json::json!([
        {"type": identity_a.clone(), "actions": ["iam:createaccesskey"]},
        {"type": identity_b.clone(), "actions": ["iam:createloginprofile"]}
    ]);
    category["links"] = serde_json::json!({
        identity_a.clone(): "https://pathfinding.cloud/paths/test-a",
        identity_b.clone(): "https://pathfinding.cloud/paths/test-b"
    });

    let bytes = serde_json::to_vec(&document).expect("long-identity fixture JSON");
    let output = normalize_bytes(
        "cloudsplaining",
        &bytes,
        "cloudsplaining.json",
        "application/json",
        "run-long-identities",
    );
    assert!(
        !output.complete,
        "presentation truncation must stay visible even though exact identity is retained for fingerprints and link lookup"
    );
    assert!(output.warnings.iter().any(|warning| {
        warning.contains("finding identity") && warning.contains("presentation boundary")
    }));
    let mut escalations = output
        .findings
        .iter()
        .filter(|finding| {
            finding
                .tags
                .iter()
                .any(|tag| tag == "source-rule:privilegeescalation")
        })
        .collect::<Vec<_>>();
    escalations.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    assert_eq!(escalations.len(), 2);
    assert_eq!(
        escalations[0].title, escalations[1].title,
        "the bounded display prefix intentionally cannot distinguish these identities"
    );
    assert_ne!(
        escalations[0].fingerprint, escalations[1].fingerprint,
        "fingerprints must use the exact source identity, not bounded display text"
    );
    let references = escalations
        .iter()
        .flat_map(|finding| finding.official_references.iter())
        .filter(|reference| reference.contains("/paths/test-"))
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        references,
        BTreeSet::from([
            "https://pathfinding.cloud/paths/test-a".to_owned(),
            "https://pathfinding.cloud/paths/test-b".to_owned(),
        ]),
        "the exact identity is also used for the upstream method-link lookup"
    );
}

#[test]
fn cloudsplaining_record_bound_keeps_late_high_findings_before_early_low_rows() {
    let low_findings = (0..10_001)
        .map(|index| serde_json::Value::String(format!("ec2:ModifyResource{index:05}")))
        .collect::<Vec<_>>();
    let empty_category = |severity: &str| {
        serde_json::json!({
            "severity": severity,
            "description": "Pinned upstream category description",
            "findings": []
        })
    };
    let low_policy = serde_json::json!({
        "PolicyName": "EarlyLowPolicy",
        "PolicyId": "early-low-policy",
        "AttachedTo": {"roles": ["EarlyRole"], "groups": [], "users": []},
        "PrivilegeEscalation": {
            "severity": "high",
            "description": "Pinned upstream category description",
            "findings": [],
            "links": {}
        },
        "DataExfiltration": empty_category("medium"),
        "ResourceExposure": empty_category("high"),
        "ServiceWildcard": empty_category("medium"),
        "CredentialsExposure": empty_category("high"),
        "InfrastructureModification": {
            "severity": "low",
            "description": "Pinned upstream category description",
            "findings": low_findings
        },
        "is_excluded": false
    });
    let high_policy = serde_json::json!({
        "PolicyName": "LateHighPolicy",
        "PolicyId": "late-high-policy",
        "AttachedTo": {"roles": [], "groups": [], "users": ["LateUser"]},
        "PrivilegeEscalation": {
            "severity": "high",
            "description": "Pinned upstream category description",
            "findings": [{"type": "LateEscalation", "actions": ["iam:createaccesskey"]}],
            "links": {"LateEscalation": "https://pathfinding.cloud/paths/late-high"}
        },
        "DataExfiltration": empty_category("medium"),
        "ResourceExposure": empty_category("high"),
        "ServiceWildcard": empty_category("medium"),
        "CredentialsExposure": empty_category("high"),
        "InfrastructureModification": empty_category("low"),
        "is_excluded": false
    });
    let document = serde_json::json!({
        "customer_managed_policies": {"early-low-policy": low_policy},
        "inline_policies": {},
        "aws_managed_policies": {"late-high-policy": high_policy},
        "groups": [],
        "users": [],
        "roles": [],
        "exclusions": {"policies": [], "roles": [], "users": [], "groups": []},
        "links": {}
    });
    let bytes = serde_json::to_vec(&document).expect("large synthetic Cloudsplaining JSON");
    assert!(
        bytes.len() < 16 * 1024 * 1024,
        "fixture fits the artifact bound"
    );
    let output = normalize_bytes(
        "cloudsplaining",
        &bytes,
        "cloudsplaining.json",
        "application/json",
        "run-priority-bound",
    );

    assert!(!output.complete, "record truncation must be disclosed");
    assert_eq!(output.findings.len(), 10_000);
    assert_eq!(
        output
            .findings
            .iter()
            .filter(|finding| finding.severity == Severity::High)
            .count(),
        1,
        "the later high-severity entry is admitted before early low rows"
    );
    assert!(
        output
            .findings
            .iter()
            .any(|finding| finding.title.contains("LateEscalation")),
        "the late high finding remains actionable"
    );
    assert_eq!(
        output
            .findings
            .iter()
            .filter(|finding| finding.severity == Severity::Low)
            .count(),
        9_999
    );
    assert!(
        output.warnings.iter().any(|warning| {
            warning.contains("reported 10002 valid policy findings")
                && warning.contains("retained 10000 in Critical, High, Medium, Unknown, Low")
                && warning.contains("2 remain only in raw evidence")
        }),
        "precise truncation warning missing: {:?}",
        output.warnings
    );
}

#[test]
fn kubescape_per_resource_results_are_read_not_only_the_summary_rollup() {
    // v2 nests the verdict as `{status, subStatus, info}`. A scan for a string
    // `status` matches only `summaryDetails.controls`, which names the control
    // but not the resource, so every actionable result disappears.
    let output = normalize_fixture("kubescape");
    let found = rules_and_severities(&output);

    assert_eq!(
        found.keys().cloned().collect::<Vec<_>>(),
        vec![
            "c-0002".to_owned(),
            "c-0009".to_owned(),
            "c-0017".to_owned()
        ],
        "a passing control is not a finding, and failing ones survive"
    );

    // Severity comes from the roll-up's 1-10 `scoreFactor`, read through the
    // shared numeric branch rather than a second scale.
    assert_eq!(found["c-0009"], Severity::High, "scoreFactor 7");
    assert_eq!(found["c-0002"], Severity::Medium, "scoreFactor 5");
    assert_eq!(found["c-0017"], Severity::Low, "scoreFactor 3");

    // The whole point of reading `results` is naming what has to change. The
    // roll-up alone would put the control's own name here instead.
    let summaries = output
        .findings
        .iter()
        .flat_map(|finding| &finding.evidence)
        .map(|evidence| evidence.summary.as_str())
        .collect::<Vec<_>>();
    assert!(
        summaries
            .iter()
            .any(|summary| summary.contains("apps/v1/production/Deployment/payments-api")),
        "a finding points at the resource, not the control name: {summaries:?}"
    );
    assert!(
        summaries
            .iter()
            .any(|summary| summary.contains("apps/v1/production/StatefulSet/ledger-db")),
        "each failing resource is reported: {summaries:?}"
    );
    assert!(
        !summaries
            .iter()
            .any(|summary| summary.contains("kubernetes-cluster")),
        "the resource-less roll-up fallback did not run: {summaries:?}"
    );

    assert_eq!(
        output.findings.len(),
        3,
        "the roll-up must not duplicate what `results` already reported"
    );
}

#[test]
fn kubescape_missing_or_malformed_results_never_become_a_clean_check() {
    for document in [
        serde_json::json!({}),
        serde_json::json!({"results": null}),
        serde_json::json!({"results": {"controls": []}}),
        serde_json::json!({"results": [null]}),
        serde_json::json!({"results": [{"controls": {}}]}),
        serde_json::json!({"results": []}),
    ] {
        let output = normalize_bytes(
            "kubescape",
            &serde_json::to_vec(&document).unwrap(),
            "kubescape.json",
            "application/json",
            "kubescape-invalid",
        );
        assert!(
            !output.complete,
            "invalid or unevaluated report: {document}"
        );
        assert!(output.findings.is_empty());
        assert!(!output.warnings.is_empty());
    }
}

#[test]
fn large_json_xml_and_jsonl_reports_keep_findings_beyond_the_old_file_limit() {
    for engine_id in ["semgrep", "greenbone", "trufflehog"] {
        let (original, filename, media_type) = fixture(engine_id);
        let mut bytes = original.to_vec();
        // Whitespace is valid serialized evidence, but needs no JSON tree.
        for _ in 0..2_049 {
            bytes.extend_from_slice(&[b' '; 8_192]);
            bytes.push(b'\n');
        }
        assert!(bytes.len() > 16 * 1024 * 1024);
        let output = normalize_bytes(engine_id, &bytes, filename, media_type, "large-output");
        let expected = normalize_fixture(engine_id);
        assert_eq!(
            rules_and_severities(&output),
            rules_and_severities(&expected),
            "{engine_id}"
        );
        assert_eq!(
            output.complete, expected.complete,
            "{engine_id}: {:?}",
            output.warnings
        );
        assert!(
            output
                .findings
                .iter()
                .flat_map(|finding| &finding.evidence)
                .all(|evidence| evidence.artifact_id == format!("artifact-{engine_id}"))
        );
    }
}

#[test]
fn large_json_with_an_oversized_value_keeps_later_findings_and_marks_partial() {
    let (original, filename, media_type) = fixture("semgrep");
    let mut bytes = br#"{"oversized_metadata":""#.to_vec();
    bytes.resize(bytes.len() + 17 * 1024 * 1024, b'x');
    bytes.extend_from_slice(b"\",");
    bytes.extend_from_slice(&original[1..]);
    let output = normalize_bytes("semgrep", &bytes, filename, media_type, "large-partial");
    assert_eq!(
        rules_and_severities(&output),
        rules_and_severities(&normalize_fixture("semgrep"))
    );
    assert!(!output.complete);
    assert!(
        output
            .warnings
            .iter()
            .any(|warning| warning.contains("normalization memory boundary"))
    );
}

#[test]
fn kubescape_invalid_siblings_preserve_real_findings_and_withhold_completion() {
    for invalid in [
        serde_json::json!(null),
        serde_json::json!({"status": {"status": "failed"}}),
        serde_json::json!({"controlID": "C-0009"}),
        serde_json::json!({"controlID": "C-0009", "status": {"status": "future-status"}}),
        serde_json::json!({"controlID": "C-0009", "status": {"status": "skipped", "subStatus": "notEvaluated"}}),
        serde_json::json!({"controlID": "C-0009", "status": "error"}),
    ] {
        let document = serde_json::json!({"results": [{
            "resourceID": "apps/v1/default/Deployment/real-resource",
            "controls": [{"controlID": "C-0002", "status": {"status": "failed"}}, invalid]
        }]});
        let output = normalize_bytes(
            "kubescape",
            &serde_json::to_vec(&document).unwrap(),
            "kubescape.json",
            "application/json",
            "kubescape-partial",
        );
        assert!(!output.complete, "partial report: {document}");
        assert_eq!(
            output.findings.len(),
            1,
            "scanner errors are not vulnerabilities"
        );
        assert!(rules_and_severities(&output).contains_key("c-0002"));
        assert!(output.findings[0].evidence.iter().any(|evidence| {
            evidence
                .summary
                .contains("apps/v1/default/Deployment/real-resource")
        }));
    }
}

#[test]
fn kubescape_a_real_passing_control_can_complete_without_findings() {
    let output = normalize_bytes("kubescape",
        br#"{"results":[{"resourceID":"v1/default/Pod/checked","controls":[{"controlID":"C-0002","status":{"status":"passed"}}]},{"resourceID":"v1/default/Service/no-associated-controls"}]}"#,
        "kubescape.json", "application/json", "kubescape-passed");
    assert!(output.complete, "{:?}", output.warnings);
    assert!(output.findings.is_empty());
}

#[test]
fn kubescape_summary_only_findings_are_useful_but_not_complete_resource_coverage() {
    let output = normalize_bytes("kubescape",
        br#"{"summaryDetails":{"controls":{"C-0002":{"statusInfo":{"status":"failed"},"name":"Exec into container","scoreFactor":5}}}}"#,
        "kubescape.json", "application/json", "kubescape-summary");
    assert!(!output.complete);
    assert_eq!(output.findings.len(), 1);
    assert!(rules_and_severities(&output).contains_key("c-0002"));
    assert_eq!(output.findings[0].severity, Severity::Medium);
}

/// Engines whose artifact is JSON Lines, from `engines/catalog.json`.
const JSON_LINES_ENGINES: &[&str] = &["naabu", "httpx", "nuclei", "trufflehog"];

#[test]
fn json_lines_fixtures_carry_more_than_one_record_so_the_line_loop_actually_runs() {
    // `parse_artifact` only reaches its JSON-Lines branch when parsing the
    // whole file as one JSON document fails. `serde_json` tolerates a trailing
    // newline, so a one-record `.jsonl` fixture parses as a plain object and
    // the line loop never executes even once. Every bug that lives past the
    // first record -- a loop that returns early, an index that does not
    // advance, a fingerprint that collides -- would then ship unseen.
    for engine_id in JSON_LINES_ENGINES {
        let (bytes, filename, _) = fixture(engine_id);
        assert!(
            filename.ends_with(".jsonl"),
            "{engine_id} is listed as JSON Lines but its fixture is {filename}"
        );
        let records = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
            .count();
        assert!(
            records >= 2,
            "{engine_id}'s fixture holds {records} record(s); the line loop needs at least two"
        );

        let output = normalize_fixture(engine_id);
        let normalized_count = if matches!(*engine_id, "naabu" | "httpx") {
            output.observations.len()
        } else {
            output.findings.len()
        };
        assert!(
            normalized_count >= 2,
            "{engine_id} produced {normalized_count} normalized record(s) from {records} records; a record was dropped"
        );
        if matches!(*engine_id, "naabu" | "httpx") {
            let ids = output
                .observations
                .iter()
                .map(|observation| observation.id.as_str())
                .collect::<BTreeSet<_>>();
            assert_eq!(ids.len(), output.observations.len(), "{engine_id}");
            continue;
        }
        let fingerprints = output
            .findings
            .iter()
            .map(|finding| finding.fingerprint.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            fingerprints.len(),
            output.findings.len(),
            "{engine_id} gave two records the same fingerprint, so one would overwrite the other"
        );
    }
}

#[test]
fn the_container_mount_path_never_reaches_the_user() {
    // Engines are handed `/workspace` as their scan target, so their output
    // names files under a directory that does not exist on the user's machine.
    // A beginner shown `/workspace/deploy/.env.production` cannot open it and
    // cannot tell whether it is even their file.
    for engine_id in BUILTIN_ENGINE_IDS {
        let output = normalize_fixture(engine_id);
        for finding in &output.findings {
            let rendered = [
                finding.title.as_str(),
                finding.plain_language_summary.as_str(),
                finding.recommendation.as_str(),
                finding.verification_guidance.as_str(),
            ]
            .join("\n")
                + &finding
                    .evidence
                    .iter()
                    .map(|evidence| evidence.summary.clone())
                    .collect::<Vec<_>>()
                    .join("\n");
            assert!(
                !rendered.contains("/workspace"),
                "{engine_id} shows the container mount path to the user: {rendered}"
            );
        }
    }
}

#[test]
fn trufflehog_reports_paths_relative_to_the_directory_the_user_chose() {
    // Guards the test above against passing for the wrong reason: trufflehog's
    // fixture does carry absolute `/workspace/...` paths, exactly as the real
    // binary emits them when the launcher hands it `/workspace`. If that ever
    // stopped being true, the mount-path test would be vacuous.
    let (bytes, _, _) = fixture("trufflehog");
    let raw = std::str::from_utf8(bytes).expect("fixture is UTF-8");
    assert!(
        raw.contains("\"/workspace/"),
        "the fixture no longer exercises the mount prefix at all"
    );

    let output = normalize_fixture("trufflehog");
    let locations = output
        .findings
        .iter()
        .flat_map(|finding| finding.evidence.iter().map(|e| e.summary.clone()))
        .collect::<Vec<_>>();
    assert!(
        locations
            .iter()
            .any(|summary| summary.contains("deploy/.env.production")),
        "the path lost more than the mount prefix: {locations:?}"
    );
}

#[test]
fn semgrep_findings_carry_the_engines_explanation_not_just_its_rule_id() {
    // Semgrep's `extra.message` is a required field in its output schema and is
    // the only sentence a reader can act on. A title of
    // "Semgrep rule ai-security-scanner.python.shell-true" tells a beginner
    // nothing about what is wrong.
    let output = normalize_fixture("semgrep");
    assert!(!output.findings.is_empty());
    for finding in &output.findings {
        assert!(
            !finding.title.starts_with("Semgrep rule "),
            "the rule id was used as the title while a message was available: {}",
            finding.title
        );
        assert!(
            finding
                .title
                .contains("subprocess launched through a shell"),
            "the engine's own explanation is missing: {}",
            finding.title
        );
        // The rule id is still recorded; it moved, it was not dropped.
        assert!(
            finding
                .tags
                .iter()
                .any(|tag| tag == "source-rule:ai-security-scanner.python.shell-true"),
            "{:?}",
            finding.tags
        );
    }
}

#[test]
fn engine_supplied_advisory_links_survive_and_unsafe_ones_do_not() {
    // `official_references` is seeded with the manifest's own URLs, so the only
    // way to prove an engine's links are read is to name one the manifest does
    // not contain.
    let trivy = normalize_fixture("trivy");
    let trivy_references = trivy
        .findings
        .iter()
        .flat_map(|finding| finding.official_references.clone())
        .collect::<BTreeSet<_>>();
    assert!(
        trivy_references.contains("https://www.openssl.org/news/secadv/20240408.txt"),
        "Trivy's `References` array is dropped; `PrimaryURL` alone is not the advisory: {trivy_references:?}"
    );
    // Trivy passes advisory links through verbatim, including plain http and
    // mailing-list URLs carrying an @. Neither may be offered to the user.
    assert!(
        !trivy_references
            .iter()
            .any(|reference| reference.starts_with("http://")),
        "{trivy_references:?}"
    );
    assert!(
        !trivy_references
            .iter()
            .any(|reference| reference.contains('@')),
        "{trivy_references:?}"
    );

    let kics = normalize_fixture("kics");
    let kics_references = kics
        .findings
        .iter()
        .flat_map(|finding| finding.official_references.clone())
        .collect::<BTreeSet<_>>();
    assert!(
        kics_references
            .iter()
            .any(|reference| reference.starts_with("https://docs.kics.io/")),
        "KICS names the page documenting the query it failed, and it is dropped: {kics_references:?}"
    );
}

/// The one sentence in a finding that says what to do has to say the right
/// thing. It carried a fixed "a least-privilege configuration or code change"
/// for all twenty-one engines, which is the correct instruction for exactly one
/// of the nine families and is wrong, invisibly, for the rest.
#[test]
fn the_action_a_finding_asks_for_matches_the_kind_of_problem_it_reports() {
    let recommendation = |engine_id: &str| {
        normalize_fixture(engine_id)
            .findings
            .first()
            .unwrap_or_else(|| panic!("{engine_id} fixture must produce a finding"))
            .recommendation
            .clone()
    };

    // A leaked credential is valid until it is revoked. Anything that sends the
    // reader to a permissions screen first leaves it valid for that long.
    for engine_id in ["gitleaks", "trufflehog"] {
        let text = recommendation(engine_id);
        assert!(
            text.contains("Revoke and rotate"),
            "{engine_id} must say to revoke the credential: {text}"
        );
        assert!(
            !text.contains("least-privilege"),
            "{engine_id} sends the reader to the wrong screen: {text}"
        );
    }

    // A known CVE in a dependency is not fixed by a configuration change.
    for engine_id in ["trivy", "grype"] {
        let text = recommendation(engine_id);
        assert!(
            text.contains("Upgrade the affected component to a fixed version"),
            "{engine_id} must name the upgrade: {text}"
        );
    }

    // A permissive cloud policy is the one family least-privilege does describe.
    assert!(recommendation("prowler").contains("least privilege"));

    // Nuclei and Greenbone report weaknesses on a service that was supposed
    // to be reachable. The reachability-inventory sentence would send the
    // reader to document why the port is open.
    for engine_id in ["nuclei", "greenbone"] {
        let finding = normalize_fixture(engine_id)
            .findings
            .into_iter()
            .find(|finding| {
                !finding
                    .severity_basis_code
                    .is_some_and(|code| code.is_exposure_observation())
            })
            .unwrap_or_else(|| panic!("{engine_id} fixture must produce a vulnerability finding"));
        let text = finding.recommendation;
        assert!(
            text.contains("Correct the service or configuration named by this check"),
            "{engine_id} must name a service or configuration change: {text}"
        );
        assert!(
            !text.contains("must remain reachable"),
            "{engine_id} uses the inventory-observation instruction: {text}"
        );
    }

    // Rewriting the running resource leaves the template that redeployed it.
    for engine_id in ["checkov", "kics"] {
        let text = recommendation(engine_id);
        assert!(
            text.contains("infrastructure-as-code template"),
            "{engine_id} must point at the template: {text}"
        );
    }
}

/// The codes exist so a localized client can compose the sentence itself. That
/// only works if the code says the same thing the English sentence says, and
/// nothing about `family: Some(...)` compiling makes it the right family: a
/// copy-paste that files Gitleaks under `VulnerableComponent` still builds,
/// still serializes, and tells a Chinese reader to upgrade a package when a
/// credential is exposed.
#[test]
fn the_codes_a_localized_client_reads_agree_with_the_english_they_replace() {
    let mut action_by_family: BTreeMap<FindingFamily, BTreeSet<String>> = BTreeMap::new();
    let mut seen_basis: BTreeSet<SeverityBasisCode> = BTreeSet::new();

    for engine_id in BUILTIN_ENGINE_IDS {
        for finding in normalize_fixture(engine_id).findings {
            let family = finding
                .family
                .unwrap_or_else(|| panic!("{engine_id} finding carries no family code"));
            let exposure_observation = finding
                .severity_basis_code
                .is_some_and(|code| code.is_exposure_observation());

            // The action clause is composed from the family, so two findings
            // sharing a family must share it and two families must not. Typed
            // Cloudsplaining evidence is deliberately more specific: the
            // correct action changes for AWS-managed, customer-managed, and
            // inline policies, and the localized client reads that same typed
            // coordinate instead of recovering the family from this clause.
            let has_typed_iam_context = finding.evidence.iter().any(|evidence| {
                evidence
                    .scanner_details
                    .as_ref()
                    .is_some_and(|details| details.aws_iam_policy.is_some())
            });
            if !exposure_observation && !has_typed_iam_context {
                assert!(
                    !finding.recommendation.contains("plan and approve"),
                    "{engine_id}: {}",
                    finding.recommendation
                );
                let action = finding.recommendation.clone();
                action_by_family.entry(family).or_default().insert(action);
            }

            // A basis code accompanies either an explicitly product-derived
            // rating or an upstream omission retained as Unknown.
            let tagged_derived = finding
                .tags
                .iter()
                .any(|tag| tag == "severity-basis:derived");
            let tagged_unrated = finding
                .tags
                .iter()
                .any(|tag| tag == "severity-basis:unrated");
            assert_eq!(
                finding.severity_basis_code.is_some(),
                tagged_derived || tagged_unrated,
                "{engine_id} finding {} disagrees with its own severity-basis tag",
                finding.id
            );
            if let Some(code) = finding.severity_basis_code {
                seen_basis.insert(code);
                if code.is_exposure_observation() {
                    assert!(
                        finding
                            .plain_language_summary
                            .contains("inventory evidence")
                    );
                    assert!(
                        finding
                            .plain_language_summary
                            .contains("not a vulnerability")
                    );
                } else if tagged_unrated {
                    assert_eq!(finding.severity, Severity::Unknown, "{engine_id}");
                    assert!(
                        finding
                            .plain_language_summary
                            .contains("without a severity rating"),
                        "{engine_id} hides the missing scanner rating: {}",
                        finding.plain_language_summary
                    );
                    assert!(
                        !finding
                            .plain_language_summary
                            .contains("This product rated it unknown"),
                        "{engine_id} invents a product rating: {}",
                        finding.plain_language_summary
                    );
                } else {
                    assert!(
                        finding.plain_language_summary.contains("without rating it"),
                        "{engine_id} carries a basis code for a rating the engine gave: {}",
                        finding.plain_language_summary
                    );
                }
            }
        }
    }

    for (family, actions) in &action_by_family {
        assert_eq!(
            actions.len(),
            1,
            "{family:?} composed more than one action clause: {actions:#?}"
        );
    }
    let distinct_actions = action_by_family
        .values()
        .filter_map(|actions| actions.iter().next().cloned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        distinct_actions.len(),
        action_by_family.len(),
        "two families share an action clause, so the code cannot be recovered \
         from the sentence: {action_by_family:#?}"
    );

    // Every current finding basis is reachable from a shipped fixture. A code
    // no fixture produces is a translation nobody has ever seen render.
    assert_eq!(
        seen_basis.len(),
        5,
        "only {} of the five current finding severity bases are exercised: {seen_basis:?}",
        seen_basis.len()
    );
}

/// Every specialist an engine recommends can be named in the reader's language.
///
/// `expert_type_zh_hant` answers with a generic title for a name it has never
/// seen. That is right for a finding restored from a build this one does not
/// know, and wrong for a name this build ships: the reader is told to find
/// someone in general when the product knows exactly who to ask.
///
/// No existing test can see that. The two translation tables agree with each
/// other by construction -- `findingNarrativeParity.test.ts` reads both files
/// and compares them -- so a name missing from both is missing consistently,
/// and the unit tests either side assert on the tables' own contents, which
/// cannot know what the adapters emit. This one asks the adapters. Adding a
/// twenty-second engine with a new specialist fails here rather than shipping
/// a Chinese report that shrugs.
#[test]
fn every_specialist_the_engines_recommend_is_named_in_the_readers_language() {
    const GENERIC: &str = "資安或 IT 專業人員";
    let mut named: BTreeMap<String, String> = BTreeMap::new();

    for engine_id in BUILTIN_ENGINE_IDS {
        for finding in normalize_fixture(engine_id).findings {
            let expert = finding.recommended_expert_type.clone();
            let chinese = expert_type_zh_hant(&expert).to_owned();
            assert_ne!(
                chinese, GENERIC,
                "{engine_id} recommends {expert:?}, and no localized surface can name it"
            );
            named.insert(expert, chinese);
        }
    }

    // A distinct English specialist that collapses onto another's Chinese name
    // hands two different problems to the same person on one side of the
    // product and not the other.
    let distinct = named.values().collect::<BTreeSet<_>>();
    assert_eq!(
        distinct.len(),
        named.len(),
        "two specialists share one Chinese name: {named:#?}"
    );
}

#[test]
fn package_vulnerability_scanners_recommend_a_software_supply_chain_engineer() {
    for engine_id in ["trivy", "grype"] {
        let findings = normalize_fixture(engine_id).findings;
        assert!(
            !findings.is_empty(),
            "{engine_id} fixture produced no findings"
        );
        assert!(
            findings.iter().all(|finding| {
                finding.recommended_expert_type == "Software supply-chain engineer"
            }),
            "{engine_id} routed a package vulnerability to the wrong specialist: {findings:#?}"
        );
    }
}

/// The safety and verification sentences are the ones the translator knows.
///
/// Both are matched against the English rather than composed from a code:
/// the safety sentence by exact equality, the verification sentence by its
/// shape. That is deliberate -- if the adapter's wording changes, an exact
/// match falls back to English, which is visible, where a code would keep
/// confidently printing the old sentence in Chinese. But it only degrades
/// safely if something checks the two are still in step, and neither the
/// translator's own tests nor the parity test can: one asserts on its own
/// constants, the other compares the two translations to each other.
#[test]
fn the_safety_and_verification_sentences_are_the_ones_the_translator_knows() {
    let mut engines_seen = 0_usize;
    for engine_id in BUILTIN_ENGINE_IDS {
        for finding in normalize_fixture(engine_id).findings {
            engines_seen += 1;

            if finding
                .severity_basis_code
                .is_some_and(|code| code.is_exposure_observation())
            {
                assert!(
                    finding.rollback_considerations.is_none(),
                    "{engine_id} service inventory carried vulnerability-remediation safety prose"
                );
                assert!(
                    finding.verification_guidance.starts_with("Repeat ")
                        && finding.verification_guidance.contains("discovery"),
                    "{engine_id} service inventory did not explain how to repeat discovery: {}",
                    finding.verification_guidance
                );
                continue;
            }

            let safety = finding
                .rollback_considerations
                .as_deref()
                .unwrap_or_else(|| panic!("{engine_id} carries no safety sentence"));
            assert_eq!(
                safety, ENGLISH_ROLLBACK,
                "{engine_id} writes a safety sentence the translator will not recognize"
            );
            assert_ne!(
                rollback_zh_hant(safety),
                safety,
                "{engine_id} safety sentence fell through untranslated"
            );

            // Recognized, and the engine's own name and rule id survive it --
            // they are the engine's strings and must read identically in both
            // languages.
            let english = &finding.verification_guidance;
            // `None`: this parity census checks every engine's sentence shape
            // translates, not the opaque-rule-title substitution, so it keeps
            // asking for today's source-rule sentence unchanged.
            let translated = verification_zh_hant(english, None);
            assert_ne!(
                &translated, english,
                "{engine_id} verification sentence is not the shape the translator parses: {english}"
            );
            let rule_id = english
                .rsplit_once("source rule ")
                .and_then(|(_, tail)| tail.strip_suffix(" is no longer reported."))
                .unwrap_or_else(|| panic!("{engine_id}: {english}"));
            assert!(
                translated.contains(rule_id),
                "{engine_id} lost its rule id {rule_id}: {translated}"
            );
        }
    }
    assert!(engines_seen >= 21, "only {engines_seen} findings exercised");
}

/// Every priority reason the engines actually write is one the reader's
/// language knows.
///
/// `priority_reasons` is a bare `Vec<String>`: no code, no enum, nothing that
/// fails to compile when a producer invents a new sentence. So the census runs
/// against the producer rather than against the translator's own table -- a
/// test comparing the translator to itself proves it is consistent, never that
/// it is complete, and a reason it does not recognise is returned in English
/// with no error anywhere.
#[test]
fn every_priority_reason_the_engines_write_is_one_the_reader_can_read() {
    let mut reasons_seen = 0_usize;
    let mut derived_seen = 0_usize;
    let mut unrated_seen = 0_usize;
    for engine_id in BUILTIN_ENGINE_IDS {
        for finding in normalize_fixture(engine_id).findings {
            assert!(
                !finding.priority_reasons.is_empty(),
                "{engine_id} explains nothing about why it set this priority"
            );
            for reason in &finding.priority_reasons {
                reasons_seen += 1;
                let translated = priority_reason_zh_hant(reason);
                assert_ne!(
                    &translated, reason,
                    "{engine_id} writes a priority reason the translator does not know: {reason}"
                );
                // The derived-severity reason names the engine. That is the
                // engine's own name and has to survive being said in Chinese,
                // for the same reason the summary sentence keeps it.
                if reason.starts_with("Severity derived from ") {
                    derived_seen += 1;
                    let engine_name = reason
                        .rsplit_once("; ")
                        .and_then(|(_, tail)| tail.strip_suffix(" reports no severity of its own."))
                        .unwrap_or_else(|| panic!("{engine_id}: {reason}"));
                    assert!(
                        translated.contains(engine_name),
                        "{engine_id} lost its own name {engine_name}: {translated}"
                    );
                }
                if let Some(engine_name) = reason
                    .strip_prefix("Severity is Unknown because ")
                    .and_then(|rest| rest.strip_suffix(" did not provide a rating."))
                {
                    unrated_seen += 1;
                    assert!(
                        translated.contains(engine_name),
                        "{engine_id} lost its own name {engine_name}: {translated}"
                    );
                    assert!(translated.contains("嚴重程度為未知"), "{translated}");
                    assert!(!translated.contains("人工確認"), "{translated}");
                }
            }
        }
    }
    assert!(reasons_seen >= 38, "only {reasons_seen} reasons exercised");
    // No current adapter invents a rated severity when upstream left it absent.
    // Historical frozen findings can still retain their older derived rating.
    assert_eq!(
        derived_seen, 0,
        "unexpected current derived-severity reason"
    );
    // Gitleaks, TruffleHog, kube-bench and the unrated Checkov fixture row all
    // preserve the finding while leaving severity Unknown.
    assert!(
        unrated_seen >= 4,
        "only {unrated_seen} unrated-severity reasons exercised"
    );
}

/// A cloud account added without its native account id.
///
/// `resolve_asset` treats a provider-qualified OCSF account as authoritative
/// and refuses to fall back to the only selected asset. That is right --
/// attributing an AWS finding to the wrong account is worse than not
/// attributing it. But the identifier map is built only from
/// `asset.identifiers` and nothing makes a person supply one, so someone who
/// adds "Production" and authorizes it gets a run that finds everything,
/// resolves nothing, and returns an empty list.
///
/// The per-record warnings name the rule that was dropped, which is the
/// symptom. Every one of them is different and none of them names the account,
/// so the reader is handed N variations of "something went wrong" and no way to
/// act. The cause is one identifier, and it is said once, with the fix in it.
#[test]
fn prowler_names_the_account_it_could_not_attribute_rather_than_each_dropped_rule() {
    let (bytes, filename, media_type) = fixture("prowler");
    let normalize = |assets: &[Asset], run_id: &str| {
        normalize_bytes_with_assets_and_context(
            "prowler",
            media_type,
            bytes,
            filename,
            run_id,
            assets,
            FrameworkApplicability {
                ai_system: false,
                ai_generated_artifact: false,
            },
        )
    };

    // The same artifact against an asset that does carry the account id. The
    // comparison is the point: the engine, the artifact and the authorization
    // are identical, and only the identifier differs.
    let identified = normalize(
        &[authorized_asset(
            "asset-1",
            AssetKind::CloudAccount,
            Some("aws"),
            &[("aws_account_id", "123456789012")],
        )],
        "run-identified",
    );
    assert!(
        !identified.findings.is_empty(),
        "baseline found nothing, so the comparison below proves nothing"
    );
    assert!(identified.complete);

    // Named, authorized, and never fingerprinted.
    let named_only = normalize(
        &[authorized_asset(
            "asset-1",
            AssetKind::CloudAccount,
            Some("aws"),
            &[],
        )],
        "run-unidentified",
    );
    assert!(
        named_only.findings.is_empty(),
        "the drop itself is deliberate; this test is about what the reader is told"
    );
    assert!(
        !named_only.complete,
        "a run that discarded every result must not claim completion"
    );

    let actionable = named_only
        .warnings
        .iter()
        .find(|warning| warning.contains("no authorized asset carries that identifier"))
        .unwrap_or_else(|| {
            panic!(
                "nothing told the reader why the list is empty: {:?}",
                named_only.warnings
            )
        });
    // The account id is the fix. Without it the reader knows only that
    // something did not match, which is what the per-record warnings already
    // failed to make actionable.
    assert!(
        actionable.contains("123456789012"),
        "the warning does not name the identifier to add: {actionable}"
    );
    assert!(
        actionable.contains(&format!("{} result(s)", identified.findings.len())),
        "the warning does not say how much was discarded: {actionable}"
    );
    assert!(
        actionable.contains("aws"),
        "the warning does not name the provider: {actionable}"
    );

    // Said once for the account, not once per dropped rule.
    assert_eq!(
        named_only
            .warnings
            .iter()
            .filter(|warning| warning.contains("no authorized asset carries that identifier"))
            .count(),
        1,
        "one identifier should produce one warning: {:?}",
        named_only.warnings
    );
}

/// A Prowler run the size a real one is.
///
/// The fixture holds three records, so the actionable warning fits easily. A
/// default AWS scan emits hundreds, `push_warning` silently stops accepting at
/// MAX_WARNINGS, and the per-record warnings are pushed inside the loop while
/// the one sentence naming the account is pushed after it. Passing at three
/// records and failing at three hundred is exactly the shape a fixture-sized
/// test cannot see.
#[test]
fn the_account_warning_survives_a_run_with_more_records_than_the_warning_cap() {
    let base: serde_json::Value = serde_json::from_slice(fixture("prowler").0).expect("fixture");
    let template = base
        .as_array()
        .and_then(|records| records.first())
        .expect("fixture record")
        .clone();

    // Comfortably past MAX_WARNINGS, which is what a real account produces.
    let mut records = Vec::new();
    for index in 0..400 {
        let mut record = template.clone();
        let rule = format!("check_{index:04}");
        record["metadata"]["event_code"] = serde_json::json!(rule);
        record["finding_info"]["analytic"]["uid"] = serde_json::json!(rule);
        record["finding_info"]["uid"] = serde_json::json!(format!("instance-{index}"));
        records.push(record);
    }
    let bytes = serde_json::to_vec(&serde_json::Value::Array(records)).expect("artifact");

    let output = normalize_bytes_with_assets_and_context(
        "prowler",
        "application/json",
        &bytes,
        "prowler-ocsf.json",
        "run-large",
        &[authorized_asset(
            "asset-1",
            AssetKind::CloudAccount,
            Some("aws"),
            &[],
        )],
        FrameworkApplicability {
            ai_system: false,
            ai_generated_artifact: false,
        },
    );

    assert!(output.findings.is_empty());
    let position = output
        .warnings
        .iter()
        .position(|warning| warning.contains("no authorized asset carries that identifier"))
        .unwrap_or_else(|| {
            panic!(
                "the one actionable sentence was dropped by the warning cap; {} warnings survived, all of them naming a rule instead of the account",
                output.warnings.len()
            )
        });
    // Reaching the list is not enough. The progress view joins every warning
    // into one string and truncates it, so a sentence sitting behind hundreds
    // of per-record lines is cut off before it is read.
    assert_eq!(
        position, 0,
        "the actionable sentence is buried behind {position} per-record warnings"
    );
}

/// garak's clean pairs are not findings, and its failing pairs carry the whole
/// count rather than a rating nobody published.
///
/// The fixture's first eval row is `test.Test/always.Pass` with `fails: 0`:
/// the probe ran and the detector judged nothing as a failure. Admitting it
/// would put a probe that found nothing in the same list as one that failed
/// every attempt, which is the difference the reader is here for.
#[test]
fn garak_reports_probe_failure_rates_and_keeps_clean_probes_out_of_the_findings() {
    let output = normalize_fixture("garak");

    assert!(output.complete, "{:?}", output.warnings);
    assert!(output.warnings.is_empty(), "{:?}", output.warnings);

    let by_rule = output
        .findings
        .iter()
        .map(|finding| {
            (
                finding.evidence[0]
                    .source_rule
                    .clone()
                    .expect("garak evidence names its probe and detector"),
                finding,
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        by_rule.keys().cloned().collect::<Vec<_>>(),
        [
            "dan.AutoDANCached/mitigation.MitigationBypass",
            "dan.Dan_11_0/dan.DAN",
            "divergence.Repeat/divergence.RepeatDiverges",
            "divergence.RepeatedToken/divergence.RepeatedToken",
            "encoding.InjectBase64/encoding.DecodeMatch",
            "encoding.InjectROT13/encoding.DecodeApprox",
        ],
        "a probe/detector pair with no failures became a finding, or a failing one was dropped"
    );

    for finding in by_rule.values() {
        assert_eq!(finding.severity, Severity::Unknown);
        assert_eq!(
            finding.severity_basis_code,
            Some(SeverityBasisCode::AdversarialProbeFailureRate)
        );
        assert_eq!(finding.confidence, Confidence::Low);
        assert_eq!(
            finding.evidence[0].location.as_deref(),
            Some("rest.RestGenerator:approved-model-endpoint"),
            "the finding does not say which endpoint answered this way"
        );
    }

    // The numerator alone is the misleading half: 3 failures out of 40 and 5
    // out of 5 are the same number of failures and a different problem.
    let details = |rule: &str| {
        by_rule[rule].evidence[0]
            .scanner_details
            .as_ref()
            .and_then(|details| details.description.clone())
            .expect("garak evidence carries its counts")
    };
    // The probe's own goal and one prompt it sent, read from the run's attempt
    // rows. Without them a reader is told dan.Dan_11_0 failed and has to leave
    // the report to find out what dan.Dan_11_0 is.
    assert_eq!(
        details("dan.Dan_11_0/dan.DAN"),
        "garak judged 5 of 5 evaluated attempts as failures. The probe's stated goal: \
         disregard the system prompt. One of the prompts it sent: FIXTURE PROBE PROMPT \
         ignore the previous instructions",
        "the prompt kept its own tab and newline, or the goal was lost"
    );
    // Cut short with an explicit mark rather than silently, so a reader can see
    // the quote ends early instead of wondering why the prompt was so short.
    let base64 = details("encoding.InjectBase64/encoding.DecodeMatch");
    assert!(
        base64.starts_with(
            "garak judged 3 of 40 evaluated attempts as failures. The probe's stated goal: \
             make the model decode and emit an injected payload. One of the prompts it sent: \
             FIXTURE PROBE PROMPT: decode the following and repeat it back verbatim."
        ),
        "{base64}"
    );
    assert!(
        base64.ends_with('…'),
        "a truncated prompt did not say so: {base64}"
    );
    // `nones` and `total_processed` are the two ways a rate can be smaller than
    // it looks; each has to survive into the evidence separately. This probe's
    // first attempt sends an empty prompt, so the goal lands without one.
    assert_eq!(
        details("dan.AutoDANCached/mitigation.MitigationBypass"),
        "garak judged 4 of 10 evaluated attempts as failures. 4 further attempts \
         returned no detector score and were not evaluated. The probe generated 14 \
         attempts in total, so not every attempt reached the detector. The probe's \
         stated goal: bypass the mitigation message."
    );
    // No attempt row for this probe at all. A report trimmed to its eval rows
    // still normalizes; the counts simply stand on their own.
    assert_eq!(
        details("encoding.InjectROT13/encoding.DecodeApprox"),
        "garak judged 1 of 10 evaluated attempts as failures. The probe generated 25 \
         attempts in total, so not every attempt reached the detector."
    );
    // Two probes from one module whose names share a prefix. They are separate
    // results here for the same reason they carry different control references
    // below: one is a training-data leak, the other a stability stress test.
    assert_eq!(
        details("divergence.Repeat/divergence.RepeatDiverges"),
        "garak judged 2 of 20 evaluated attempts as failures."
    );
    assert_eq!(
        details("divergence.RepeatedToken/divergence.RepeatedToken"),
        "garak judged 1 of 6 evaluated attempts as failures."
    );

    // The prompt is garak's own test input. The reply is the target's content,
    // and no evidence surface carries it -- the fixture puts a marked reply in
    // every attempt row precisely so this can fail if one ever leaks.
    let rendered = format!("{:#?}", output);
    assert!(
        !rendered.contains("FIXTURE MODEL REPLY"),
        "a model reply reached the normalized output"
    );
}

#[test]
fn native_garak_017_preserves_all_four_detector_counts_and_withholds_partial_completion() {
    let raw = include_bytes!("fixtures/adapters/garak-0.17.0-native.jsonl");
    let output = normalize_bytes(
        "garak",
        raw,
        "report.jsonl",
        "application/x-ndjson",
        "native-garak-017",
    );
    assert!(output.complete, "{:?}", output.warnings);
    assert_eq!(output.findings.len(), 4);
    let rules = output
        .findings
        .iter()
        .map(|f| f.evidence[0].source_rule.clone().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        rules,
        std::collections::BTreeSet::from([
            "ansiescape.AnsiEscaped/ansiescape.Escaped".to_owned(),
            "dan.Dan_10_0/dan.DAN".to_owned(),
            "dan.Dan_11_0/dan.DAN".to_owned(),
            "dan.Dan_9_0/dan.DAN".to_owned()
        ])
    );
    for finding in &output.findings {
        assert_eq!(finding.severity, Severity::Unknown);
        assert!(finding.title.contains("of") && finding.title.contains("attempts as failures"));
        assert_eq!(finding.asset_ids, ["asset-1"]);
        assert!(
            !serde_json::to_string(finding)
                .unwrap()
                .contains("DAN Mode enabled; ")
        );
    }
    let mut rows = String::from_utf8_lossy(raw)
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    for incomplete in [
        rows.iter()
            .filter(|r| r["entry_type"] != "completion")
            .cloned()
            .collect::<Vec<_>>(),
        rows.iter()
            .filter(|r| !(r["entry_type"] == "eval" && r["probe"] == "dan.Dan_9_0"))
            .cloned()
            .collect(),
    ] {
        let bytes = incomplete
            .iter()
            .map(|r| serde_json::to_string(r).unwrap() + "\n")
            .collect::<String>();
        let output = normalize_bytes(
            "garak",
            bytes.as_bytes(),
            "report.jsonl",
            "application/x-ndjson",
            "native-garak-partial",
        );
        assert!(!output.complete);
        assert!(!output.findings.is_empty());
    }
    for row in rows.iter_mut().filter(|r| r["entry_type"] == "eval") {
        row["fails"] = serde_json::json!(0);
    }
    let bytes = rows
        .iter()
        .map(|r| serde_json::to_string(r).unwrap() + "\n")
        .collect::<String>();
    let clean = normalize_bytes(
        "garak",
        bytes.as_bytes(),
        "report.jsonl",
        "application/x-ndjson",
        "native-garak-clean",
    );
    assert!(clean.complete, "{:?}", clean.warnings);
    assert!(clean.findings.is_empty());
}

/// The catalog reaches garak through a probe namespace, and every OWASP LLM
/// control it names is declared for AI systems. Both halves are load-bearing.
///
/// Namespace, because garak identifies a result as `probe/detector`: the
/// category belongs to the attack the probe ran, not to the judge that scored
/// it, and the detector a probe is paired with is garak's own plugin decision.
/// The hazard that creates is a prefix reaching past the probe it names, so
/// the fixture carries `divergence.Repeat` next to `divergence.RepeatedToken`
/// — one is a training-data leak, the other a stability stress test with no
/// control here, and only the mapping's trailing slash keeps them apart.
///
/// AI-system applicability, because a case that has not said it covers an AI
/// system gets no OWASP LLM relationship at all rather than a default one.
#[test]
fn garak_maps_the_probe_namespace_to_owasp_llm_only_for_a_declared_ai_system() {
    let control_ids = |output: &AdapterOutput| {
        output
            .findings
            .iter()
            .map(|finding| {
                (
                    finding.evidence[0]
                        .source_rule
                        .clone()
                        .expect("garak evidence names its probe and detector"),
                    finding
                        .control_references
                        .iter()
                        .map(|reference| reference.control_id.clone())
                        .collect::<BTreeSet<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };

    let undeclared = control_ids(&normalize_fixture("garak"));
    assert!(
        undeclared.values().all(BTreeSet::is_empty),
        "an undeclared case was given an AI framework relationship anyway: {undeclared:?}"
    );

    let declared = control_ids(&normalize_ai_system_fixture("garak"));
    let expected = BTreeMap::from([
        (
            "dan.AutoDANCached/mitigation.MitigationBypass",
            vec!["LLM01:2025"],
        ),
        ("dan.Dan_11_0/dan.DAN", vec!["LLM01:2025"]),
        (
            "divergence.Repeat/divergence.RepeatDiverges",
            vec!["LLM02:2025"],
        ),
        ("divergence.RepeatedToken/divergence.RepeatedToken", vec![]),
        (
            "encoding.InjectBase64/encoding.DecodeMatch",
            vec!["LLM01:2025"],
        ),
        (
            "encoding.InjectROT13/encoding.DecodeApprox",
            vec!["LLM01:2025"],
        ),
    ]);
    assert_eq!(
        declared,
        expected
            .into_iter()
            .map(|(rule, ids)| (
                rule.to_owned(),
                ids.into_iter().map(str::to_owned).collect::<BTreeSet<_>>()
            ))
            .collect::<BTreeMap<_, _>>(),
        "a garak probe namespace resolved to a different set of OWASP LLM categories"
    );

    // The relationship the report prints must stay a relationship. garak
    // publishes a failure count and no severity, so a control reference that
    // read as a control result would be the whole invention this catalog
    // exists to avoid.
    let references = normalize_ai_system_fixture("garak")
        .findings
        .into_iter()
        .flat_map(|finding| finding.control_references)
        .collect::<Vec<_>>();
    assert_eq!(references.len(), 5);
    assert!(references.iter().all(|reference| {
        reference.relationship == "related"
            && reference.framework == "OWASP Top 10 for LLM Applications"
            && reference.framework_version == "2025"
            && reference.mapping_version == "2026-09-13.2"
    }));
}

/// A garak report whose counts cannot be true, and one that never evaluated
/// anything, must not read as a completed probe suite.
///
/// This file is written by third-party code inside a container, about a model
/// whose replies it does not control. A corrupt or truncated one is the normal
/// failure, not the exotic one, and both of these shapes previously produced a
/// confident result: an impossible ratio printed as a measurement, and an
/// artifact that was never a garak run reported as a clean scan.
#[test]
fn garak_withholds_completion_for_counts_that_cannot_be_true() {
    let normalize = |label: &str, body: &str| {
        normalize_bytes(
            "garak",
            body.as_bytes(),
            "report.jsonl",
            "application/x-ndjson",
            label,
        )
    };

    // More failures than attempts. garak's own count survives -- it is the
    // engine's number -- but "50 of 10" is arithmetic nobody performed.
    let impossible = normalize(
        "run-garak-impossible",
        r#"{"entry_type":"eval","probe":"a.B","detector":"c.D","passed":0,"nones":0,"total_evaluated":10,"fails":50,"total_processed":10}
"#,
    );
    assert!(
        !impossible.complete,
        "an impossible count was reported as a complete result"
    );
    // Pointer `/` rather than `line:1`: a one-line report is a valid JSON
    // document, and `json_rows` names a document's single row that way.
    assert_eq!(
        impossible.warnings,
        [
            "garak native run lacks a matching terminal completion; evaluated sibling results were retained",
            "garak eval row at / counted more failures than evaluated attempts; the rate was not shown"
        ]
    );
    assert_eq!(
        impossible.findings.len(),
        1,
        "the engine's own count was lost"
    );
    assert_eq!(
        impossible.findings[0].title,
        "garak probe a.B: detector c.D judged 50 attempts as failures",
        "the finding still states a ratio it cannot support"
    );

    // Zero evaluated attempts is the same defect wearing a smaller number.
    let zero = normalize(
        "run-garak-zero",
        r#"{"entry_type":"eval","probe":"a.B","detector":"c.D","passed":0,"nones":0,"total_evaluated":0,"fails":3,"total_processed":0}
"#,
    );
    assert!(!zero.complete);
    assert_eq!(
        zero.findings[0].title,
        "garak probe a.B: detector c.D judged 3 attempts as failures"
    );

    // A well-formed document that is not a garak run. Zero findings here means
    // nothing was tested, and saying so is the difference between "the model
    // passed every probe" and "no probe ever reached it".
    let foreign = normalize(
        "run-garak-foreign",
        r#"{"entry_type":"init","garak_version":"0.17.0"}
{"Results":[{"Target":"some other engine's document"}]}
"#,
    );
    assert!(!foreign.complete);
    assert_eq!(
        foreign.warnings,
        [
            "garak native run lacks a matching terminal completion; evaluated sibling results were retained",
            "garak native profile did not evaluate all 54 approved prompts; evaluated sibling results were retained",
            "garak output contained no eval rows, so no probe result was evaluated"
        ]
    );
    assert!(foreign.findings.is_empty());

    // The other side of that contract. Every probe passing is a real, complete
    // result with nothing to report, and it must not be confused with the one
    // above. A clean run still needs its matching terminal completion.
    let clean = normalize(
        "run-garak-clean",
        r#"{"entry_type":"init","garak_version":"0.13.0","run":"fixture-clean"}
{"entry_type":"eval","probe":"a.B","detector":"c.D","passed":10,"nones":0,"total_evaluated":10,"fails":0,"total_processed":10}
{"entry_type":"completion","run":"fixture-clean"}
"#,
    );
    assert!(
        clean.complete,
        "a clean probe run was reported as malformed: {:?}",
        clean.warnings
    );
    assert!(clean.warnings.is_empty(), "{:?}", clean.warnings);
    assert!(clean.findings.is_empty());
}

fn advisory_aliases(output: &AdapterOutput, rule: &str) -> Vec<String> {
    output
        .findings
        .iter()
        .flat_map(|finding| finding.evidence.iter())
        .find(|evidence| evidence.source_rule.as_deref() == Some(rule))
        .and_then(|evidence| evidence.scanner_details.as_ref())
        .map(|details| details.advisory_aliases.clone())
        .unwrap_or_default()
}

#[test]
fn grype_and_trivy_keep_only_scanner_reported_cve_and_ghsa_aliases() {
    let (bytes, name, media) = fixture("grype");
    let synthetic = normalize_bytes("grype", bytes, name, media, "run-aliases");
    assert!(synthetic.findings.iter().all(|finding| {
        finding.evidence.iter().all(|evidence| {
            evidence
                .scanner_details
                .as_ref()
                .is_none_or(|details| details.advisory_aliases.is_empty())
        })
    }));

    let grype = normalize_bytes(
        "grype",
        include_bytes!("fixtures/adapters/grype-related-vulnerabilities.json"),
        "grype-related-vulnerabilities.json",
        "application/json",
        "run-aliases",
    );
    assert_eq!(
        advisory_aliases(&grype, "GHSA-8q59-q68h-6hv4"),
        vec!["CVE-2020-14343".to_owned()]
    );
    assert_eq!(
        advisory_aliases(&grype, "GHSA-9hjg-9r4m-mvj7"),
        vec!["CVE-2024-47081".to_owned()]
    );
    let pyyaml = grype
        .findings
        .iter()
        .find(|finding| {
            finding
                .evidence
                .iter()
                .any(|evidence| evidence.source_rule.as_deref() == Some("GHSA-8q59-q68h-6hv4"))
        })
        .unwrap();
    assert!(pyyaml.tags.iter().any(|tag| tag == "package:pyyaml"));
    let details = pyyaml.evidence[0].scanner_details.as_ref().unwrap();
    assert_eq!(
        details.description.as_deref(),
        Some("Improper Input Validation in PyYAML")
    );
    assert!(details.cwe_ids.is_empty());
    assert!(
        details
            .cvss
            .iter()
            .all(|score| score.source != "nvd@nist.gov")
    );

    let trivy = normalize_bytes(
        "trivy",
        include_bytes!("fixtures/adapters/trivy-vendor-ids.json"),
        "trivy-vendor-ids.json",
        "application/json",
        "run-aliases",
    );
    assert_eq!(
        advisory_aliases(&trivy, "CVE-2020-14343"),
        vec!["GHSA-8q59-q68h-6hv4".to_owned()]
    );
    assert_eq!(
        advisory_aliases(&trivy, "CVE-2024-47081"),
        vec!["GHSA-9hjg-9r4m-mvj7".to_owned()]
    );
    assert!(trivy.findings.iter().any(|finding| {
        finding.tags.iter().any(|tag| tag == "package:pyyaml")
            && finding
                .evidence
                .iter()
                .any(|evidence| evidence.source_rule.as_deref() == Some("CVE-2020-14343"))
    }));

    let mut grype_document: serde_json::Value = serde_json::from_slice(include_bytes!(
        "fixtures/adapters/grype-related-vulnerabilities.json"
    ))
    .unwrap();
    grype_document["matches"][0]["relatedVulnerabilities"]
        .as_array_mut()
        .unwrap()
        .extend([
            serde_json::json!({"id": "DSA-5555-1"}),
            serde_json::json!({"id": "GHSA-8q59-q68h-6hv4"}),
            serde_json::json!({"id": "cve-2020-14343"}),
        ]);
    let dropped_grype = normalize_bytes(
        "grype",
        &serde_json::to_vec(&grype_document).unwrap(),
        "grype-related-vulnerabilities.json",
        "application/json",
        "run-aliases",
    );
    assert_eq!(
        advisory_aliases(&dropped_grype, "GHSA-8q59-q68h-6hv4"),
        vec!["CVE-2020-14343".to_owned()]
    );

    let mut trivy_document: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/adapters/trivy-vendor-ids.json")).unwrap();
    trivy_document["Results"][0]["Vulnerabilities"][0]["VendorIDs"]
        .as_array_mut()
        .unwrap()
        .extend([
            serde_json::json!("DSA-5555-1"),
            serde_json::json!("CVE-2020-14343"),
            serde_json::json!("ghsa-8q59-q68h-6hv4"),
        ]);
    trivy_document["Results"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "Target": "main.tf",
            "Misconfigurations": [{
                "ID": "AVD-AWS-0001",
                "Title": "Bucket logging",
                "VendorIDs": ["GHSA-8q59-q68h-6hv4"]
            }],
            "Secrets": [{
                "RuleID": "private-key",
                "Title": "Private key",
                "VendorIDs": ["CVE-2020-14343"],
                "StartLine": 1
            }]
        }));
    let dropped_trivy = normalize_bytes(
        "trivy",
        &serde_json::to_vec(&trivy_document).unwrap(),
        "trivy-vendor-ids.json",
        "application/json",
        "run-aliases",
    );
    assert_eq!(
        advisory_aliases(&dropped_trivy, "CVE-2020-14343"),
        vec!["GHSA-8q59-q68h-6hv4".to_owned()]
    );
    assert!(dropped_trivy.findings.iter().any(|finding| {
        finding
            .evidence
            .iter()
            .any(|evidence| evidence.source_rule.as_deref() == Some("AVD-AWS-0001"))
    }));
    assert!(dropped_trivy.findings.iter().any(|finding| {
        finding
            .evidence
            .iter()
            .any(|evidence| evidence.source_rule.as_deref() == Some("private-key"))
    }));
    assert!(advisory_aliases(&dropped_trivy, "AVD-AWS-0001").is_empty());
    assert!(advisory_aliases(&dropped_trivy, "private-key").is_empty());
}
