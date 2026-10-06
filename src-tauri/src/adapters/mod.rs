//! Bounded, evidence-preserving normalizers for the built-in scanner catalog.
//!
//! Scanner output is untrusted input. These adapters only map explicit tool
//! fields into the case schema; they never execute, render, or follow text from
//! a target or a scanner result.

mod bounded_json;
mod control_mapping;

use crate::adapter::{AdapterInput, AdapterOutput, AdapterRegistry, EngineAdapter};
use crate::domain::{
    AwsIamAttachedTo, AwsIamPolicyFindingDetails, AwsIamPolicySource, BenchmarkReference,
    Confidence, ConfidenceBasisCode, CvssScore, Evidence, EvidenceKind, Finding, FindingFamily,
    FindingStatus, InventoryObservation, InventoryObservationKind, ManualReviewControl,
    RawArtifact, ScannerFindingDetails, SecurityTemplateExecution, Severity, SeverityBasisCode,
    UnevaluatedTarget, UnevaluatedTargetCause,
};
use crate::error::{AppError, AppResult};
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Take};
use std::path::{Component, Path};
use std::sync::Arc;

pub const ADAPTER_VERSION: &str = "0.2.6";
/// Stable identity for the canonical finding fingerprint algorithm. Changing
/// this value requires an explicit migration before cross-version diffs may be
/// treated as comparable.
pub const FINGERPRINT_SCHEMA_VERSION: &str = "v1";
/// Stable identity for the evidence-ID commitment. Version 2 binds the
/// producing engine and normalized source rule in addition to the finding,
/// artifact, result pointer, and exact engine execution.
pub const EVIDENCE_ID_SCHEMA_VERSION: &str = "v2";
pub const BUILTIN_ENGINE_IDS: &[&str] = &[
    "cloudquery",
    "steampipe",
    "prowler",
    "scoutsuite",
    "cloudsplaining",
    "scubagear",
    "maester",
    "naabu",
    "httpx",
    "nuclei",
    "greenbone",
    "zap",
    "semgrep",
    "gitleaks",
    "trufflehog",
    "checkov",
    "kics",
    "trivy",
    "grype",
    "syft",
    "kubescape",
    "kube-bench",
    "garak",
    "agentic-radar",
    "mcp-armor",
];

const MAX_ARTIFACTS: usize = 64;
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_JSON_TREE_BYTES: usize = 32 * 1024 * 1024;
const MAX_STREAM_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000;
const MAX_LINE_BYTES: usize = 1024 * 1024;
const MAX_CLOUDQUERY_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CLOUDQUERY_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CLOUDQUERY_ROW_BYTES: usize = 64 * 1024 * 1024;
const MAX_WARNINGS: usize = 256;
/// Distinct unresolved provider identifiers tracked per normalization.
const MAX_UNMATCHED_IDENTIFIERS: usize = 32;
const MAX_SHORT_TEXT: usize = 512;
const MAX_LONG_TEXT: usize = 2_048;
const MAX_MANUAL_REVIEW_DETAIL: usize = 4_096;
const MAX_XML_DEPTH: usize = 64;
const MAX_XML_EVENTS: usize = 200_000;
const MAX_XML_ATTRIBUTES: usize = 256;
const MAX_ZAP_EVIDENCE_TAG_VALUE: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    CloudQuery,
    Steampipe,
    Prowler,
    ScoutSuite,
    Cloudsplaining,
    ScubaGear,
    Maester,
    Naabu,
    Httpx,
    Nuclei,
    Greenbone,
    Zap,
    Semgrep,
    Gitleaks,
    Trufflehog,
    Checkov,
    Kics,
    Trivy,
    Grype,
    Syft,
    Kubescape,
    KubeBench,
    Garak,
    AgenticRadar,
    McpArmor,
}

#[derive(Debug)]
struct BuiltinAdapter {
    id: &'static str,
    profile: Profile,
    expert_type: &'static str,
}

#[derive(Debug, Clone)]
struct SourceRecord {
    pointer: String,
    /// Bounded display text only. It must never be used as mapping proof
    /// because sanitization can be lossy.
    rule_id: String,
    /// Exact raw scanner rule, present only when it was already bounded,
    /// trimmed, and control-free. Only this value can select catalog entries.
    mapping_source_rule: Option<String>,
    /// Collision-resistant internal identity. Valid rules use their exact
    /// bytes; invalid rules use a domain-separated digest of the raw bytes.
    rule_identity: String,
    /// Optional per-result identity used only by the finding fingerprint.
    ///
    /// Some upstream formats map many result instances to one control-mapping
    /// rule. Keeping an exact, hashed instance coordinate separate prevents
    /// long display values from collapsing. This changes only the instance
    /// fingerprint; `mapping_source_rule` remains the scanner's exact category
    /// identifier and continues to drive control mapping.
    fingerprint_identity: Option<String>,
    title: String,
    severity: Severity,
    source_severity: String,
    /// Present only when the engine reports no severity. It retains the kind
    /// of result that lacked a rating so every report surface can distinguish
    /// an upstream rating from an Unknown value that still needs review.
    severity_basis: Option<SeverityBasisCode>,
    location: String,
    asset_hint: Option<String>,
    asset_provider: Option<String>,
    confidence: Confidence,
    source_confidence: String,
    /// Present only when the engine supplied no confidence and this product
    /// assigned one from the behavior that produced the finding.
    confidence_basis: Option<ConfidenceBasisCode>,
    evidence_kind: EvidenceKind,
    scanner_details: Option<ScannerFindingDetails>,
    references: Vec<String>,
    tags: Vec<String>,
    /// A profile normally has one finding family. MCP Armor's bounded static
    /// slice is the exception: a leaked credential and an over-privileged MCP
    /// command require materially different action, so the record carries the
    /// product-owned family selected from its stable upstream check id.
    family_override: Option<FindingFamily>,
}

#[derive(Debug)]
struct InventoryRecord {
    pointer: String,
    asset_hint: Option<String>,
    asset_provider: Option<String>,
    kind: InventoryObservationKind,
}

/// The canonical severity and provenance used when an engine emits none.
///
/// The value remains `Unknown` for upstream results that carry no rating. The
/// basis keeps that absence explicit without presenting a product opinion as
/// scanner output. Historical findings may still carry an older product-owned
/// level beside the same basis and must remain readable as frozen evidence.
struct DerivedSeverity {
    severity: Severity,
    /// Which basis. The sentence is derived from this by [`basis_text`] rather
    /// than written beside it, so the code a localized client reads and the
    /// prose an English one reads cannot come to disagree.
    code: SeverityBasisCode,
}

/// A confidence this product assigned because the engine supplied none.
///
/// A source value always wins. This pair exists so downstream readers can
/// distinguish an engine rating from this product's bounded derivation.
struct DerivedConfidence {
    confidence: Confidence,
    code: ConfidenceBasisCode,
}

/// Completes the sentence "severity derived from ...".
fn basis_text(code: SeverityBasisCode) -> &'static str {
    crate::finding_narrative::basis_english(code)
}

fn confidence_basis_text(code: ConfidenceBasisCode) -> &'static str {
    crate::finding_narrative::confidence_basis_english(code)
}

/// Rates only the evidence described by a derived basis; it does not promote
/// the finding because the engine omitted its own confidence field.
fn derived_confidence(code: ConfidenceBasisCode) -> DerivedConfidence {
    let confidence = match code {
        // These extractors admit a record only after the engine returned an
        // explicit failed policy/configuration verdict. The value either met
        // the rule or it did not, so the retained failure is strong evidence.
        ConfidenceBasisCode::DeterministicPolicyEvaluation => Confidence::High,
        // Naabu and httpx records exist because this run received the network
        // response represented by the finding. High describes that observed
        // exposure fact, not whether the exposed service is vulnerable.
        ConfidenceBasisCode::ObservedResponse => Confidence::High,
        // Inventory-to-advisory matching is useful evidence, but version
        // reporting, distribution backports, and advisory applicability still
        // need confirmation on the installed component.
        ConfidenceBasisCode::AdvisoryVersionMatch => Confidence::Medium,
        // A pattern/detector hit was not validated as a live credential or a
        // true defect. Treat it as a lead, not strong evidence of the claim.
        ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch => Confidence::Low,
        // Nuclei templates range from exact banners to heuristic matchers, and
        // this result shape does not say which kind supplied the evidence.
        ConfidenceBasisCode::TemplateMatcher => Confidence::Medium,
        // With no Greenbone QoD value, the NVT result remains useful but cannot
        // inherit the confidence of one of the engine's scored QoD bands.
        ConfidenceBasisCode::MissingDetectionQualityScore => Confidence::Unknown,
    };
    DerivedConfidence { confidence, code }
}

struct RecordDraft {
    pointer: String,
    rule_id: String,
    title: String,
    source_severity: String,
    derived_severity: Option<DerivedSeverity>,
    location: String,
    asset_hint: Option<String>,
    source_confidence: String,
    derived_confidence: Option<DerivedConfidence>,
    evidence_kind: EvidenceKind,
    references: Vec<String>,
    tags: Vec<String>,
}

macro_rules! record {
    (
        $pointer:expr,
        $rule_id:expr,
        $title:expr,
        $source_severity:expr,
        $location:expr,
        $asset_hint:expr,
        $source_confidence:expr,
        $derived_confidence:expr,
        $evidence_kind:expr,
        $references:expr,
        $tags:expr $(,)?
    ) => {
        record_from_draft(RecordDraft {
            pointer: $pointer,
            rule_id: $rule_id,
            title: $title,
            source_severity: $source_severity,
            derived_severity: None,
            location: $location,
            asset_hint: $asset_hint,
            source_confidence: $source_confidence,
            derived_confidence: $derived_confidence,
            evidence_kind: $evidence_kind,
            references: $references,
            tags: $tags,
        })
    };
}

/// Like [`record!`], for an engine that reports no severity of its own. Takes a
/// [`DerivedSeverity`] where `record!` takes the engine's severity string.
macro_rules! record_with_derived_severity {
    (
        $pointer:expr,
        $rule_id:expr,
        $title:expr,
        $derived:expr,
        $location:expr,
        $asset_hint:expr,
        $source_confidence:expr,
        $derived_confidence:expr,
        $evidence_kind:expr,
        $references:expr,
        $tags:expr $(,)?
    ) => {
        record_from_draft(RecordDraft {
            pointer: $pointer,
            rule_id: $rule_id,
            title: $title,
            source_severity: String::new(),
            derived_severity: Some($derived),
            location: $location,
            asset_hint: $asset_hint,
            source_confidence: $source_confidence,
            derived_confidence: $derived_confidence,
            evidence_kind: $evidence_kind,
            references: $references,
            tags: $tags,
        })
    };
}

/// Like [`record!`], for an engine that has a severity field but leaves it
/// unset for most findings. Takes both the engine's severity — empty when it
/// gave none — and the [`DerivedSeverity`] used only in that case. Whatever the
/// engine did say always wins, so the one rated finding keeps its rating.
macro_rules! record_with_severity_fallback {
    (
        $pointer:expr,
        $rule_id:expr,
        $title:expr,
        $source_severity:expr,
        $derived:expr,
        $location:expr,
        $asset_hint:expr,
        $source_confidence:expr,
        $derived_confidence:expr,
        $evidence_kind:expr,
        $references:expr,
        $tags:expr $(,)?
    ) => {
        record_from_draft(RecordDraft {
            pointer: $pointer,
            rule_id: $rule_id,
            title: $title,
            source_severity: $source_severity,
            derived_severity: Some($derived),
            location: $location,
            asset_hint: $asset_hint,
            source_confidence: $source_confidence,
            derived_confidence: $derived_confidence,
            evidence_kind: $evidence_kind,
            references: $references,
            tags: $tags,
        })
    };
}

/// Like [`record!`], for an engine that supplies no confidence of its own.
macro_rules! record_with_derived_confidence {
    (
        $pointer:expr, $rule_id:expr, $title:expr, $source_severity:expr,
        $location:expr, $asset_hint:expr, $derived_confidence:expr,
        $evidence_kind:expr, $references:expr, $tags:expr $(,)?
    ) => {
        record!(
            $pointer,
            $rule_id,
            $title,
            $source_severity,
            $location,
            $asset_hint,
            String::new(),
            Some($derived_confidence),
            $evidence_kind,
            $references,
            $tags,
        )
    };
}

/// Like [`record!`], when a source confidence may be absent and a derivation
/// is permitted to fill only that gap.
macro_rules! record_with_confidence_fallback {
    (
        $pointer:expr, $rule_id:expr, $title:expr, $source_severity:expr,
        $location:expr, $asset_hint:expr, $source_confidence:expr,
        $derived_confidence:expr, $evidence_kind:expr, $references:expr,
        $tags:expr $(,)?
    ) => {
        record!(
            $pointer,
            $rule_id,
            $title,
            $source_severity,
            $location,
            $asset_hint,
            $source_confidence,
            Some($derived_confidence),
            $evidence_kind,
            $references,
            $tags,
        )
    };
}

/// Both ratings are derived because the engine supplied neither one.
macro_rules! record_with_derived_severity_and_confidence {
    (
        $pointer:expr, $rule_id:expr, $title:expr, $derived_severity:expr,
        $location:expr, $asset_hint:expr, $derived_confidence:expr,
        $evidence_kind:expr, $references:expr, $tags:expr $(,)?
    ) => {
        record_with_derived_severity!(
            $pointer,
            $rule_id,
            $title,
            $derived_severity,
            $location,
            $asset_hint,
            String::new(),
            Some($derived_confidence),
            $evidence_kind,
            $references,
            $tags,
        )
    };
}

/// Severity and confidence each have an independent fallback; the source
/// severity can win while confidence remains explicitly product-derived.
macro_rules! record_with_severity_fallback_and_derived_confidence {
    (
        $pointer:expr, $rule_id:expr, $title:expr, $source_severity:expr,
        $derived_severity:expr, $location:expr, $asset_hint:expr,
        $derived_confidence:expr, $evidence_kind:expr, $references:expr,
        $tags:expr $(,)?
    ) => {
        record_with_severity_fallback!(
            $pointer,
            $rule_id,
            $title,
            $source_severity,
            $derived_severity,
            $location,
            $asset_hint,
            String::new(),
            Some($derived_confidence),
            $evidence_kind,
            $references,
            $tags,
        )
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XmlElement {
    Results,
    Result,
    Name,
    Nvt,
    Host,
    Port,
    ResultType,
    Severity,
    Threat,
    Summary,
    Solution,
    Qod,
    Value,
    AssetId,
    Family,
    Refs,
    Ref,
    Other,
}

#[derive(Debug, Default)]
struct GreenboneXmlResult {
    pointer: String,
    result_id: Option<String>,
    nvt_oid: Option<String>,
    result_name: Option<String>,
    nvt_name: Option<String>,
    host: Option<String>,
    port: Option<String>,
    result_type: Option<String>,
    severity: Option<String>,
    threat: Option<String>,
    summary: Option<String>,
    solution: Option<String>,
    qod: Option<String>,
    asset_id: Option<String>,
    family: Option<String>,
    cves: Vec<String>,
}

#[derive(Debug)]
struct GreenboneExtraction {
    records: Vec<SourceRecord>,
    unevaluated_targets: Vec<UnevaluatedTarget>,
    complete: bool,
}

#[derive(Debug)]
struct ManualReviewCandidate {
    rule_id: String,
    title: String,
    detail: Option<String>,
    asset_hint: Option<String>,
}

#[derive(Debug)]
struct M365Extraction {
    records: Vec<SourceRecord>,
    manual_review_candidates: Vec<ManualReviewCandidate>,
}

#[derive(Debug)]
struct NucleiExtraction {
    records: Vec<SourceRecord>,
    execution_counts: BTreeMap<String, usize>,
}

#[derive(Debug)]
enum ParsedArtifact {
    Json(Value),
    JsonLines(Vec<(usize, Value)>),
    Xml(Vec<GreenboneXmlResult>),
}

/// Construct the adapter set matching the complete built-in engine catalog.
pub fn builtin_adapter_registry() -> AppResult<AdapterRegistry> {
    if let Err(error) = control_mapping::validate_catalog(BUILTIN_ENGINE_IDS) {
        tracing::warn!(
            error = %error,
            "framework relationships are unavailable; finding normalization remains enabled"
        );
    }
    let definitions = [
        ("cloudquery", Profile::CloudQuery, "Cloud security engineer"),
        ("steampipe", Profile::Steampipe, "Cloud security engineer"),
        ("prowler", Profile::Prowler, "Cloud security engineer"),
        ("scoutsuite", Profile::ScoutSuite, "Cloud security engineer"),
        (
            "cloudsplaining",
            Profile::Cloudsplaining,
            "Cloud identity specialist",
        ),
        (
            "scubagear",
            Profile::ScubaGear,
            "Microsoft 365 security administrator",
        ),
        (
            "maester",
            Profile::Maester,
            "Microsoft 365 security administrator",
        ),
        ("naabu", Profile::Naabu, "Network security engineer"),
        ("httpx", Profile::Httpx, "Application security engineer"),
        ("nuclei", Profile::Nuclei, "Application security engineer"),
        ("greenbone", Profile::Greenbone, "Vulnerability manager"),
        ("zap", Profile::Zap, "Application security engineer"),
        ("semgrep", Profile::Semgrep, "Application security engineer"),
        ("gitleaks", Profile::Gitleaks, "Secrets-response specialist"),
        (
            "trufflehog",
            Profile::Trufflehog,
            "Secrets-response specialist",
        ),
        (
            "checkov",
            Profile::Checkov,
            "Infrastructure-as-code engineer",
        ),
        ("kics", Profile::Kics, "Infrastructure-as-code engineer"),
        ("trivy", Profile::Trivy, "Software supply-chain engineer"),
        ("grype", Profile::Grype, "Software supply-chain engineer"),
        ("syft", Profile::Syft, "Software supply-chain engineer"),
        (
            "kubescape",
            Profile::Kubescape,
            "Kubernetes security engineer",
        ),
        (
            "kube-bench",
            Profile::KubeBench,
            "Kubernetes security engineer",
        ),
        ("garak", Profile::Garak, "AI security engineer"),
        (
            "agentic-radar",
            Profile::AgenticRadar,
            "AI security engineer",
        ),
        ("mcp-armor", Profile::McpArmor, "AI security engineer"),
    ];

    let mut registry = AdapterRegistry::default();
    for (id, profile, expert_type) in definitions {
        registry.register(Arc::new(BuiltinAdapter {
            id,
            profile,
            expert_type,
        }))?;
    }
    Ok(registry)
}

/// Exact embedded mapping identity frozen into every planned engine run.
pub(crate) fn control_mapping_version() -> AppResult<&'static str> {
    control_mapping::catalog_version()
}

/// Canonical catalog identity frozen into each new relationship snapshot.
pub(crate) fn control_mapping_provenance() -> AppResult<crate::domain::ControlMappingProvenance> {
    control_mapping::catalog_provenance()
}

/// Fail-closed proof that a frozen relationship carrying the current catalog
/// identity is an exact reviewed entry for its evidence-producing engine and
/// frozen AI context.
pub(crate) fn validate_current_control_reference(
    reference: &crate::domain::ControlReference,
    evidence_sources: &[(String, String)],
    evidence_cwe_ids: &[String],
    ai_system_applicable: bool,
    ai_generated_artifact_applicable: bool,
) -> AppResult<()> {
    control_mapping::validate_current_reference(
        reference,
        evidence_sources,
        evidence_cwe_ids,
        ai_system_applicable,
        ai_generated_artifact_applicable,
    )
}

/// Return the exact scanner rule only when the current structured evidence ID
/// commits to it and to the rest of the frozen evidence identity. Older
/// records deliberately return `None` and cannot be upgraded from prose or
/// tags into verified-current mapping provenance.
pub(crate) fn validated_evidence_source_rule<'a>(
    evidence: &'a crate::domain::Evidence,
    finding_fingerprint: &str,
) -> AppResult<Option<&'a str>> {
    let Some(source_rule) = evidence.source_rule.as_deref() else {
        return Ok(None);
    };
    if source_rule.is_empty()
        || source_rule.chars().count() > MAX_SHORT_TEXT
        || source_rule.trim() != source_rule
        || source_rule.chars().any(char::is_control)
    {
        return Err(AppError::InvalidRequest(format!(
            "evidence {} has malformed structured source-rule provenance",
            evidence.id
        )));
    }
    let engine_run_id = evidence.engine_run_id.as_deref().ok_or_else(|| {
        AppError::InvalidRequest(format!(
            "evidence {} has a structured source rule but no exact engine run",
            evidence.id
        ))
    })?;
    let pointer_sha256 = evidence.result_pointer_sha256.as_deref().ok_or_else(|| {
        AppError::InvalidRequest(format!(
            "evidence {} has a structured source rule but no result-pointer digest",
            evidence.id
        ))
    })?;
    if pointer_sha256.len() != 64
        || !pointer_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppError::InvalidRequest(format!(
            "evidence {} has a malformed result-pointer digest",
            evidence.id
        )));
    }
    let expected = stable_evidence_id(
        finding_fingerprint,
        &evidence.engine_id,
        source_rule,
        &evidence.artifact_sha256,
        pointer_sha256,
        engine_run_id,
    );
    if evidence.id != expected {
        return Err(AppError::InvalidRequest(format!(
            "evidence {} source rule does not match its structured evidence identity",
            evidence.id
        )));
    }
    Ok(Some(source_rule))
}

impl EngineAdapter for BuiltinAdapter {
    fn engine_id(&self) -> &str {
        self.id
    }

    fn adapter_version(&self) -> &str {
        ADAPTER_VERSION
    }

    fn normalize(&self, input: &AdapterInput<'_>) -> AppResult<AdapterOutput> {
        normalize_artifacts(self, input)
    }
}

fn normalize_artifacts(
    adapter: &BuiltinAdapter,
    input: &AdapterInput<'_>,
) -> AppResult<AdapterOutput> {
    let mut output = AdapterOutput::default();
    let mut findings: BTreeMap<String, Finding> = BTreeMap::new();
    let mut observations: BTreeMap<String, InventoryObservation> = BTreeMap::new();
    let mut processed_bytes = 0_u64;
    let mut processed_records = 0_usize;
    let mut nuclei_execution_counts = BTreeMap::<String, usize>::new();
    // Provider-qualified identifiers the engine reported on that no authorized
    // asset claims. Counted per identifier rather than per record: the
    // per-record warnings name the rule that was dropped, which is the symptom.
    // The identifier is the cause, it is the same for every dropped record, and
    // it is the one thing the reader can act on.
    let mut unmatched_identifiers: BTreeMap<(String, String), usize> = BTreeMap::new();

    let relevant: Vec<&RawArtifact> = input
        .raw_artifacts
        .iter()
        .filter(|artifact| {
            artifact.case_id == input.case_id
                && artifact.run_id == input.scan_run_id
                && artifact.engine_run_id == input.engine_run_id
                && !is_runtime_stream_capture_path(&artifact.relative_path)
                && !is_preserved_upstream_evidence_path(&artifact.relative_path)
        })
        .collect();

    if relevant.is_empty() {
        output.complete = false;
        push_warning(
            &mut output.warnings,
            format!("{} produced no raw artifacts to normalize", adapter.id),
        );
        if adapter.profile == Profile::Nuclei {
            output
                .unevaluated_targets
                .extend(input.asset_ids.iter().map(|asset_id| UnevaluatedTarget {
                    asset_id: asset_id.clone(),
                    cause: UnevaluatedTargetCause::NoSecurityTemplateExecutionEvidence,
                    result_count: 0,
                }));
        }
        return Ok(output);
    }

    let relevant_count = relevant.len();
    let total_byte_limit = MAX_CLOUDQUERY_TOTAL_BYTES;
    for artifact in relevant.into_iter().take(MAX_ARTIFACTS) {
        if processed_bytes.saturating_add(artifact.byte_length) > total_byte_limit {
            output.complete = false;
            push_warning(
                &mut output.warnings,
                "adapter input exceeded the total byte limit; remaining raw artifacts were retained but not normalized",
            );
            break;
        }

        let warnings_before_read = output.warnings.len();
        let parsed = if adapter.profile == Profile::CloudQuery {
            let parsed = read_cloudquery_rows(input.artifact_root, artifact, &mut output.warnings);
            if parsed.is_some() {
                processed_bytes += artifact.byte_length;
            }
            parsed
        } else if artifact.byte_length > MAX_ARTIFACT_BYTES {
            let parsed = read_large_artifact(input.artifact_root, artifact, &mut output.warnings);
            if parsed.is_some() {
                processed_bytes += artifact.byte_length;
            }
            parsed
        } else {
            match read_bounded_artifact(input.artifact_root, artifact, &mut output.warnings) {
                Some(bytes) => {
                    processed_bytes += bytes.len() as u64;
                    if is_complete_empty_json_lines(adapter.profile, artifact, &bytes) {
                        Some(ParsedArtifact::JsonLines(Vec::new()))
                    } else {
                        parse_artifact(&bytes, artifact, &mut output.warnings)
                    }
                }
                None => None,
            }
        };
        if output.warnings.len() > warnings_before_read {
            output.complete = false;
        }
        let Some(parsed) = parsed else {
            continue;
        };
        if matches!(
            adapter.profile,
            Profile::CloudQuery
                | Profile::Steampipe
                | Profile::Naabu
                | Profile::Httpx
                | Profile::Syft
                | Profile::AgenticRadar
        ) {
            let warnings_before_extract = output.warnings.len();
            let records =
                extract_inventory_records(adapter.profile, &parsed, artifact, &mut output.warnings);
            if output.warnings.len() > warnings_before_extract {
                output.complete = false;
            }
            if records.len() >= MAX_RECORDS {
                output.complete = false;
                push_warning(
                    &mut output.warnings,
                    "adapter extraction reached the record safety boundary; completeness cannot be established",
                );
            }
            for record in records {
                if processed_records >= MAX_RECORDS {
                    output.complete = false;
                    push_warning(
                        &mut output.warnings,
                        "adapter record limit reached; remaining raw records were retained but not normalized",
                    );
                    break;
                }
                processed_records += 1;
                let warnings_before_resolution = output.warnings.len();
                let asset_id = resolve_inventory_asset(
                    &record,
                    input.asset_ids,
                    input.asset_identifier_map,
                    &mut output.warnings,
                    &mut unmatched_identifiers,
                );
                if output.warnings.len() > warnings_before_resolution {
                    output.complete = false;
                }
                let Some(asset_id) = asset_id else {
                    continue;
                };
                merge_inventory_observation(
                    &mut observations,
                    adapter,
                    input,
                    artifact,
                    record,
                    asset_id,
                );
            }
            continue;
        }
        let warnings_before_extract = output.warnings.len();
        let records = if adapter.profile == Profile::Greenbone {
            let extraction = extract_greenbone(&parsed, &mut output.warnings, input.asset_ids);
            output
                .unevaluated_targets
                .extend(extraction.unevaluated_targets);
            if !extraction.complete {
                output.complete = false;
            }
            extraction.records
        } else if adapter.profile == Profile::Maester {
            let extraction = extract_maester(&parsed, &mut output.warnings);
            for candidate in extraction.manual_review_candidates {
                if processed_records >= MAX_RECORDS {
                    output.complete = false;
                    push_warning(
                        &mut output.warnings,
                        "adapter record limit reached; remaining raw records were retained but not normalized",
                    );
                    break;
                }
                processed_records += 1;
                let warnings_before_resolution = output.warnings.len();
                let asset_id = resolve_asset_coordinates(
                    &candidate.rule_id,
                    candidate.asset_hint.as_deref(),
                    None,
                    input.asset_ids,
                    input.asset_identifier_map,
                    &mut output.warnings,
                    &mut unmatched_identifiers,
                );
                if output.warnings.len() > warnings_before_resolution {
                    output.complete = false;
                }
                let Some(asset_id) = asset_id else {
                    continue;
                };
                output.manual_review_controls.push(ManualReviewControl {
                    asset_id,
                    rule_id: candidate.rule_id,
                    title: candidate.title,
                    detail: candidate.detail,
                });
            }
            extraction.records
        } else if adapter.profile == Profile::Nuclei {
            let extraction = extract_nuclei(&parsed, &mut output.warnings);
            for (asset_hint, result_count) in extraction.execution_counts {
                if input
                    .asset_ids
                    .iter()
                    .any(|asset_id| asset_id == &asset_hint)
                {
                    let count = nuclei_execution_counts.entry(asset_hint).or_default();
                    *count = count.saturating_add(result_count);
                } else {
                    push_warning(
                        &mut output.warnings,
                        "Nuclei execution evidence named an asset outside this engine task and was not counted",
                    );
                }
            }
            extraction.records
        } else {
            extract_records(adapter.profile, &parsed, &mut output.warnings)
        };
        if adapter.profile != Profile::Greenbone && output.warnings.len() > warnings_before_extract
        {
            output.complete = false;
        }
        // Deliberately after the window above, so that disclosing a shortfall
        // is not itself read as evidence that failed to normalize. A control
        // the engine passed over by design was normalized correctly and must
        // leave the run complete; only a control it could not evaluate
        // withholds completion, and it says so for itself.
        if let Some(unevaluated) = unevaluated_controls(adapter.profile, &parsed) {
            push_warning(&mut output.warnings, unevaluated.disclosure);
            if unevaluated.withholds_completion {
                output.complete = false;
            }
        }
        // A disputed control was evaluated and still becomes a finding, so this
        // discloses without touching `complete`.
        if let Some(disputed) = tenant_disputed_controls(adapter.profile, &parsed) {
            push_warning(&mut output.warnings, disputed);
        }
        if records.len() >= MAX_RECORDS {
            output.complete = false;
            push_warning(
                &mut output.warnings,
                "adapter extraction reached the record safety boundary; completeness cannot be established",
            );
        }
        for record in records {
            if processed_records >= MAX_RECORDS {
                output.complete = false;
                push_warning(
                    &mut output.warnings,
                    "adapter record limit reached; remaining raw records were retained but not normalized",
                );
                break;
            }
            processed_records += 1;
            let warnings_before_resolution = output.warnings.len();
            let asset_id = resolve_asset(
                &record,
                input.asset_ids,
                input.asset_identifier_map,
                &mut output.warnings,
                &mut unmatched_identifiers,
            );
            if output.warnings.len() > warnings_before_resolution {
                output.complete = false;
            }
            let Some(asset_id) = asset_id else {
                continue;
            };
            merge_finding(&mut findings, adapter, input, artifact, record, asset_id);
        }
    }

    // The engine ran, produced results, and every one of them was discarded
    // because nothing the person authorized claims the identifier the engine
    // reported on. Said once per identifier, naming the identifier, because
    // adding it to the authorized asset is the whole fix -- and without this
    // the run reads as a clean scan that found nothing.
    //
    // Put in front of the per-record warnings and exempt from MAX_WARNINGS,
    // both deliberately. A real cloud account produces far more records than
    // the cap, so appending this through `push_warning` meant the one sentence
    // worth reading was the one silently dropped, and the surface that renders
    // warnings joins them into a single truncated string, so arriving last is
    // nearly the same as not arriving. Exempting it is safe because the map it
    // comes from is capped at MAX_UNMATCHED_IDENTIFIERS entries.
    let attribution_warnings = unmatched_identifiers
        .iter()
        .map(|((provider, identifier), count)| {
            safe_text(
                &format!(
                    "{} reported {count} result(s) for {provider} identifier {identifier}, but no authorized asset carries that identifier; none of them were attributed. Add {identifier} to the asset you authorized and scan again.",
                    adapter.id
                ),
                MAX_SHORT_TEXT,
            )
        })
        .collect::<Vec<_>>();
    output.warnings.splice(0..0, attribution_warnings);
    output.unattributed = unmatched_identifiers
        .into_iter()
        .map(
            |((provider, identifier), discarded_results)| crate::domain::UnattributedResults {
                provider,
                identifier,
                discarded_results,
            },
        )
        .collect();

    if adapter.profile == Profile::Nuclei {
        for asset_id in input.asset_ids {
            if let Some(result_count) = nuclei_execution_counts.get(asset_id) {
                output
                    .security_template_executions
                    .push(SecurityTemplateExecution {
                        asset_id: asset_id.clone(),
                        result_count: *result_count,
                    });
            } else {
                output.unevaluated_targets.push(UnevaluatedTarget {
                    asset_id: asset_id.clone(),
                    cause: UnevaluatedTargetCause::NoSecurityTemplateExecutionEvidence,
                    result_count: 0,
                });
            }
        }
        output.security_template_executions.sort();
    }

    output.unevaluated_targets.sort();
    let mut aggregated_unevaluated = Vec::<UnevaluatedTarget>::new();
    for target in output.unevaluated_targets.drain(..) {
        if let Some(existing) = aggregated_unevaluated.last_mut()
            && existing.asset_id == target.asset_id
            && existing.cause == target.cause
        {
            existing.result_count = existing.result_count.saturating_add(target.result_count);
        } else {
            aggregated_unevaluated.push(target);
        }
    }
    output.unevaluated_targets = aggregated_unevaluated;
    output.manual_review_controls.sort();
    output.manual_review_controls.dedup();

    if relevant_count > MAX_ARTIFACTS {
        output.complete = false;
        push_warning(
            &mut output.warnings,
            "adapter artifact-count limit reached; extra raw artifacts were retained but not normalized",
        );
    }

    if matches!(
        adapter.profile,
        Profile::CloudQuery | Profile::Steampipe | Profile::Syft
    ) {
        push_warning(
            &mut output.warnings,
            format!(
                "{} output is inventory evidence; no security issue was invented from inventory rows",
                adapter.id
            ),
        );
    }

    output.findings = findings.into_values().collect();
    output.observations = observations.into_values().collect();
    Ok(output)
}

/// The released Naabu, HTTPx, and TruffleHog contracts can prove a complete
/// zero-record result with a real, hashed output artifact containing zero bytes
/// (or only line-ending whitespace). A Nuclei empty stream is also valid input,
/// but it produces a typed missing-execution outcome rather than a clean scan.
/// Document-shaped adapters keep their schema-specific empty checks.
fn is_complete_empty_json_lines(profile: Profile, artifact: &RawArtifact, bytes: &[u8]) -> bool {
    if !matches!(
        profile,
        Profile::CloudQuery
            | Profile::Naabu
            | Profile::Httpx
            | Profile::Nuclei
            | Profile::Trufflehog
    ) || bytes.iter().any(|byte| !byte.is_ascii_whitespace())
    {
        return false;
    }
    is_json_lines_artifact(artifact)
}

fn is_json_lines_artifact(artifact: &RawArtifact) -> bool {
    let extension_is_json_lines = Path::new(&artifact.relative_path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(extension.to_ascii_lowercase().as_str(), "jsonl" | "ndjson")
        });
    extension_is_json_lines
        || artifact
            .media_type
            .eq_ignore_ascii_case("application/x-ndjson")
}

/// Mapping catalogs cannot affect a released JSONL engine whose contract can
/// prove a complete result from a verified zero-byte stream: there are no
/// source records from which a finding or control reference could be produced.
/// Nuclei stays excluded: adapting its empty stream now creates a typed
/// coverage outcome, so adapter drift can change durable meaning even though
/// no finding can be remapped. This remains narrower than normal adapter
/// parsing (which also accepts whitespace-only streams) so cross-version resume
/// planning can prove the exception from durable metadata plus the artifact
/// hash alone.
pub(crate) fn is_mapping_independent_empty_json_lines(
    engine_id: &str,
    artifact: &RawArtifact,
) -> bool {
    matches!(engine_id, "naabu" | "httpx" | "trufflehog")
        && artifact.byte_length == 0
        && (Path::new(&artifact.relative_path)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                matches!(extension.to_ascii_lowercase().as_str(), "jsonl" | "ndjson")
            })
            || artifact
                .media_type
                .eq_ignore_ascii_case("application/x-ndjson"))
}

/// Stdout and stderr are retained as raw evidence, but the released engine
/// contract writes normalizer input below `/output`. Feeding the backend-owned
/// stream captures to JSON/XML adapters would make every otherwise-valid run
/// look malformed (including the normal empty-stream case). Match the complete
/// private run layout so an engine-created `output/raw/stdout.log` remains
/// ordinary untrusted output instead of being silently skipped.
const RUNTIME_STREAM_CAPTURE_FILE_NAMES: [&str; 2] = ["stdout.log", "stderr.log"];
const RUNTIME_STREAM_CAPTURE_RAW_DIRECTORY: &str = "raw";
const RUNTIME_STREAM_CAPTURE_ATTEMPT_PREFIX: &str = "attempt-";

pub(crate) fn is_runtime_stream_capture_path(relative_path: &str) -> bool {
    let mut components = Path::new(relative_path).components().rev();
    let Some(Component::Normal(file_name)) = components.next() else {
        return false;
    };
    let Some(Component::Normal(raw_directory)) = components.next() else {
        return false;
    };
    let Some(Component::Normal(attempt_directory)) = components.next() else {
        return false;
    };
    let Some(attempt_directory) = attempt_directory.to_str() else {
        return false;
    };

    file_name
        .to_str()
        .is_some_and(|file_name| RUNTIME_STREAM_CAPTURE_FILE_NAMES.contains(&file_name))
        && raw_directory == RUNTIME_STREAM_CAPTURE_RAW_DIRECTORY
        && attempt_directory
            .strip_prefix(RUNTIME_STREAM_CAPTURE_ATTEMPT_PREFIX)
            .is_some_and(|attempt| {
                !attempt.is_empty() && attempt.bytes().all(|byte| byte.is_ascii_digit())
            })
}

/// Whether the artifact is a raw vendor report a managed wrapper preserved as
/// evidence rather than the normalized document the wrapper owns.
///
/// The Microsoft 365 wrappers write the untouched upstream report under
/// `output/upstream/` next to their own document (`run-scubagear.ps1` and
/// `run-maester.ps1`). Both are captured, because the raw report is what a
/// reviewer needs in order to check the wrapper against, but only the wrapper's
/// document uses the field names the adapters read. Normalizing the raw report
/// too is not a second opinion, it is a misparse: upstream ScubaGear spells the
/// key `Control ID`, so every raw control is dropped with a "lacked a rule id"
/// warning, and a raw report whose keys happen to match can contribute a second
/// record for a control the wrapper already reported.
pub(crate) fn is_preserved_upstream_evidence_path(relative_path: &str) -> bool {
    let components = Path::new(relative_path)
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    components.windows(3).any(|window| {
        window[0].strip_prefix("attempt-").is_some_and(|attempt| {
            !attempt.is_empty() && attempt.bytes().all(|byte| byte.is_ascii_digit())
        }) && window[1] == "output"
            && window[2] == "upstream"
    })
}

fn read_bounded_artifact(
    root: &Path,
    artifact: &RawArtifact,
    warnings: &mut Vec<String>,
) -> Option<Vec<u8>> {
    let file = open_bounded_artifact(root, artifact, MAX_ARTIFACT_BYTES, warnings)?;
    let mut bytes =
        Vec::with_capacity((artifact.byte_length as usize).min(MAX_ARTIFACT_BYTES as usize));
    let mut reader: Take<File> = file.take(MAX_ARTIFACT_BYTES + 1);
    if reader.read_to_end(&mut bytes).is_err() || bytes.len() as u64 > MAX_ARTIFACT_BYTES {
        push_warning(
            warnings,
            "an artifact exceeded the byte limit while being read",
        );
        return None;
    }
    if bytes.len() as u64 != artifact.byte_length {
        push_warning(
            warnings,
            "an artifact length did not match its recorded evidence metadata",
        );
        return None;
    }
    let actual_hash = hex::encode(Sha256::digest(&bytes));
    if !actual_hash.eq_ignore_ascii_case(&artifact.sha256) {
        push_warning(
            warnings,
            "an artifact hash did not match its recorded evidence metadata",
        );
        return None;
    }
    Some(bytes)
}

fn open_bounded_artifact(
    root: &Path,
    artifact: &RawArtifact,
    max_bytes: u64,
    warnings: &mut Vec<String>,
) -> Option<File> {
    if artifact.byte_length > max_bytes {
        push_warning(
            warnings,
            format!(
                "artifact {} exceeded the per-file byte limit and was not parsed",
                safe_text(&artifact.id, MAX_SHORT_TEXT)
            ),
        );
        return None;
    }

    let relative = Path::new(&artifact.relative_path);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        push_warning(
            warnings,
            "an artifact path escaped the case artifact root and was rejected",
        );
        return None;
    }

    let root = match root.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            push_warning(warnings, "the case artifact root could not be opened");
            return None;
        }
    };
    let path = root.join(relative);
    let canonical = match path.canonicalize() {
        Ok(path) if path.starts_with(&root) => path,
        _ => {
            push_warning(
                warnings,
                "an artifact path did not resolve inside the case artifact root",
            );
            return None;
        }
    };
    match File::open(&canonical) {
        Ok(file) => Some(file),
        Err(_) => {
            push_warning(
                warnings,
                format!(
                    "artifact {} could not be read; its metadata remains in the case",
                    safe_text(&artifact.id, MAX_SHORT_TEXT)
                ),
            );
            None
        }
    }
}

/// Match the launchers' on-disk output boundary without materializing their
/// entire report. The serialized stream and the retained JSON tree have
/// independent bounds; whole-file length and SHA-256 still bind all evidence,
/// including data omitted from normalization.
fn read_large_artifact(
    root: &Path,
    artifact: &RawArtifact,
    warnings: &mut Vec<String>,
) -> Option<ParsedArtifact> {
    let file = open_bounded_artifact(root, artifact, MAX_STREAM_ARTIFACT_BYTES, warnings)?;
    let mut reader = BufReader::new(HashingReader {
        inner: file.take(MAX_STREAM_ARTIFACT_BYTES + 1),
        hasher: Sha256::new(),
        length: 0,
    });
    let mut budget = bounded_json::Budget::new(MAX_JSON_TREE_BYTES);
    let parsed = if artifact.media_type.contains("xml") || artifact.relative_path.ends_with(".xml")
    {
        parse_greenbone_xml_reader(&mut reader, warnings).map(ParsedArtifact::Xml)
    } else if is_json_lines_artifact(artifact) {
        let mut rows = Vec::new();
        let mut line = Vec::new();
        let mut line_number = 0;
        loop {
            let (consumed, oversized) =
                match read_bounded_line(&mut reader, &mut line, MAX_LINE_BYTES) {
                    Ok(value) => value,
                    Err(_) => {
                        push_warning(
                            warnings,
                            "an artifact exceeded the byte limit while being read",
                        );
                        return None;
                    }
                };
            if consumed == 0 {
                break;
            }
            line_number += 1;
            if oversized {
                push_warning(
                    warnings,
                    format!("JSONL line {line_number} exceeded the line limit and was skipped"),
                );
                continue;
            }
            let bytes = trim_ascii(&line);
            if bytes.is_empty() {
                continue;
            }
            if rows.len() >= MAX_RECORDS {
                push_warning(
                    warnings,
                    "JSONL record limit reached; later lines remain only as raw evidence",
                );
                break;
            }
            match bounded_json::read(bytes, &mut budget) {
                Ok(value) => rows.push((line_number, value)),
                Err(_) => push_warning(
                    warnings,
                    format!("malformed JSONL line {line_number} was skipped"),
                ),
            }
        }
        Some(ParsedArtifact::JsonLines(rows))
    } else {
        match bounded_json::read(&mut reader, &mut budget) {
            Ok(value) => Some(ParsedArtifact::Json(value)),
            Err(error) => {
                push_warning(
                    warnings,
                    format!(
                        "artifact {} was neither valid bounded JSON nor JSONL: {}",
                        safe_text(&artifact.id, MAX_SHORT_TEXT),
                        safe_text(&error.to_string(), MAX_SHORT_TEXT)
                    ),
                );
                None
            }
        }
    };
    if budget.omitted {
        push_warning(
            warnings,
            "report data exceeded the normalization memory boundary; check results are incomplete",
        );
    }
    // Parsers may stop at a row/event bound or syntax error. Verify the entire
    // captured artifact before releasing any successfully read records.
    if std::io::copy(&mut reader, &mut std::io::sink()).is_err() {
        push_warning(
            warnings,
            "an artifact exceeded the byte limit while being read",
        );
        return None;
    }
    let HashingReader { hasher, length, .. } = reader.into_inner();
    if length > MAX_STREAM_ARTIFACT_BYTES {
        push_warning(
            warnings,
            "an artifact exceeded the byte limit while being read",
        );
        return None;
    }
    if length != artifact.byte_length {
        push_warning(
            warnings,
            "an artifact length did not match its recorded evidence metadata",
        );
        return None;
    }
    if !hex::encode(hasher.finalize()).eq_ignore_ascii_case(&artifact.sha256) {
        push_warning(
            warnings,
            "an artifact hash did not match its recorded evidence metadata",
        );
        return None;
    }
    parsed
}

/// Streams one CloudQuery NDJSON table file. The aws_iam_policies table carries
/// every version of each attached AWS managed policy, so on a live account one
/// row measured 7 MB and the file 11 MB. Each row is reduced to its top-level
/// scalar columns while it is read, which is all the inventory mapping uses, so
/// these bounds follow the engine's 512 MiB output budget instead of the
/// in-memory document bounds. The length and hash are verified over the whole
/// stream before any row is used.
fn read_cloudquery_rows(
    root: &Path,
    artifact: &RawArtifact,
    warnings: &mut Vec<String>,
) -> Option<ParsedArtifact> {
    let file = open_bounded_artifact(root, artifact, MAX_CLOUDQUERY_ARTIFACT_BYTES, warnings)?;
    let mut reader = BufReader::new(HashingReader {
        inner: file.take(MAX_CLOUDQUERY_ARTIFACT_BYTES + 1),
        hasher: Sha256::new(),
        length: 0,
    });
    let mut rows = Vec::new();
    let mut row_lines = 0_usize;
    let mut line = Vec::new();
    let mut line_number = 0_usize;
    loop {
        let (consumed, oversized) =
            match read_bounded_line(&mut reader, &mut line, MAX_CLOUDQUERY_ROW_BYTES) {
                Ok(result) => result,
                Err(_) => {
                    push_warning(
                        warnings,
                        "an artifact exceeded the byte limit while being read",
                    );
                    return None;
                }
            };
        if consumed == 0 {
            break;
        }
        line_number += 1;
        if oversized {
            row_lines += 1;
            push_warning(
                warnings,
                format!("JSONL line {line_number} exceeded the line limit and was skipped"),
            );
            continue;
        }
        let row = trim_ascii(&line);
        if row.is_empty() {
            continue;
        }
        row_lines += 1;
        if rows.len() >= MAX_RECORDS {
            push_warning(
                warnings,
                "JSONL record limit reached; later lines remain only as raw evidence",
            );
            if std::io::copy(&mut reader, &mut std::io::sink()).is_err() {
                push_warning(
                    warnings,
                    "an artifact exceeded the byte limit while being read",
                );
                return None;
            }
            break;
        }
        match serde_json::from_slice::<CloudQueryRow>(row) {
            Ok(CloudQueryRow(value)) => rows.push((line_number, value)),
            Err(_) => push_warning(
                warnings,
                format!("malformed JSONL line {line_number} was skipped"),
            ),
        }
    }

    let HashingReader { hasher, length, .. } = reader.into_inner();
    if length > MAX_CLOUDQUERY_ARTIFACT_BYTES {
        push_warning(
            warnings,
            "an artifact exceeded the byte limit while being read",
        );
        return None;
    }
    if length != artifact.byte_length {
        push_warning(
            warnings,
            "an artifact length did not match its recorded evidence metadata",
        );
        return None;
    }
    if !hex::encode(hasher.finalize()).eq_ignore_ascii_case(&artifact.sha256) {
        push_warning(
            warnings,
            "an artifact hash did not match its recorded evidence metadata",
        );
        return None;
    }

    if row_lines == 0 {
        if is_json_lines_artifact(artifact) {
            return Some(ParsedArtifact::JsonLines(Vec::new()));
        }
    } else if row_lines == 1 && rows.len() == 1 {
        // A one-row file is also a complete JSON document; keep its document
        // pointer, as the generic parser does.
        let (_, value) = rows.pop()?;
        return Some(ParsedArtifact::Json(value));
    }
    if rows.is_empty() {
        push_warning(
            warnings,
            format!(
                "artifact {} was neither valid bounded JSON nor JSONL",
                safe_text(&artifact.id, MAX_SHORT_TEXT)
            ),
        );
        return None;
    }
    Some(ParsedArtifact::JsonLines(rows))
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    length: u64,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        self.length += read as u64;
        Ok(read)
    }
}

/// Reads one line, keeping at most `limit` bytes of it. Returns the bytes
/// consumed, zero at end of input, and whether the line was longer than the
/// limit; an oversized line is consumed to its end but not kept.
fn read_bounded_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
    limit: usize,
) -> std::io::Result<(usize, bool)> {
    line.clear();
    let mut consumed = 0;
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok((consumed, oversized));
        }
        let (length, ends_line) = match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => (index + 1, true),
            None => (available.len(), false),
        };
        if !oversized {
            if line.len() + length > limit {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(&available[..length]);
            }
        }
        reader.consume(length);
        consumed += length;
        if ends_line {
            return Ok((consumed, oversized));
        }
    }
}

/// One CloudQuery line reduced to what the inventory mapping reads: an object
/// keeps its top-level scalar columns, an array keeps each object element that
/// way, and anything else becomes `null`. Nested values are skipped without
/// being built.
struct CloudQueryRow(Value);

impl<'de> serde::Deserialize<'de> for CloudQueryRow {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RowVisitor;

        impl<'de> serde::de::Visitor<'de> for RowVisitor {
            type Value = CloudQueryRow;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a CloudQuery row")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<Self::Value, A::Error> {
                scalar_columns(map).map(|columns| CloudQueryRow(Value::Object(columns)))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut elements = Vec::new();
                while let Some(CloudQueryElement(element)) = sequence.next_element()? {
                    // One past the limit lets `json_rows` report the truncation.
                    if elements.len() <= MAX_RECORDS {
                        elements.push(element);
                    }
                }
                Ok(CloudQueryRow(Value::Array(elements)))
            }

            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(CloudQueryRow(Value::Null))
            }

            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(CloudQueryRow(Value::Null))
            }

            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(CloudQueryRow(Value::Null))
            }

            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(CloudQueryRow(Value::Null))
            }

            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Ok(CloudQueryRow(Value::Null))
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(CloudQueryRow(Value::Null))
            }
        }

        deserializer.deserialize_any(RowVisitor)
    }
}

struct CloudQueryElement(Value);

impl<'de> serde::Deserialize<'de> for CloudQueryElement {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.deserialize_any(ScalarColumnVisitor { keep_objects: true })? {
            ScalarColumn::Object(columns) => Ok(CloudQueryElement(Value::Object(columns))),
            ScalarColumn::Scalar(_) | ScalarColumn::Skipped => Ok(CloudQueryElement(Value::Null)),
        }
    }
}

enum ScalarColumn {
    Scalar(Value),
    Object(Map<String, Value>),
    Skipped,
}

impl<'de> serde::Deserialize<'de> for ScalarColumn {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ScalarColumnVisitor {
            keep_objects: false,
        })
    }
}

struct ScalarColumnVisitor {
    keep_objects: bool,
}

impl<'de> serde::de::Visitor<'de> for ScalarColumnVisitor {
    type Value = ScalarColumn;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a CloudQuery column")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(ScalarColumn::Scalar(Value::Bool(value)))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(ScalarColumn::Scalar(Value::from(value)))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(ScalarColumn::Scalar(Value::from(value)))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Ok(ScalarColumn::Scalar(Value::from(value)))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(ScalarColumn::Scalar(Value::String(value.to_owned())))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(ScalarColumn::Scalar(Value::String(value)))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(ScalarColumn::Scalar(Value::Null))
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> Result<Self::Value, A::Error> {
        while sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {}
        Ok(ScalarColumn::Skipped)
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        if self.keep_objects {
            return scalar_columns(map).map(ScalarColumn::Object);
        }
        while map
            .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
            .is_some()
        {}
        Ok(ScalarColumn::Skipped)
    }
}

fn scalar_columns<'de, A: serde::de::MapAccess<'de>>(
    mut map: A,
) -> Result<Map<String, Value>, A::Error> {
    let mut columns = Map::new();
    while let Some(key) = map.next_key::<String>()? {
        match map.next_value::<ScalarColumn>()? {
            ScalarColumn::Scalar(value) => {
                columns.insert(key, value);
            }
            ScalarColumn::Object(_) | ScalarColumn::Skipped => {
                columns.remove(&key);
            }
        }
    }
    Ok(columns)
}

fn parse_artifact(
    bytes: &[u8],
    artifact: &RawArtifact,
    warnings: &mut Vec<String>,
) -> Option<ParsedArtifact> {
    let first_non_whitespace = bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace());
    if first_non_whitespace == Some(b'<') || artifact.media_type.contains("xml") {
        return parse_greenbone_xml(bytes, warnings).map(ParsedArtifact::Xml);
    }

    match serde_json::from_slice::<Value>(bytes) {
        Ok(value) => Some(ParsedArtifact::Json(value)),
        Err(document_error) => {
            let mut rows = Vec::new();
            for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
                let line = trim_ascii(line);
                if line.is_empty() {
                    continue;
                }
                if rows.len() >= MAX_RECORDS {
                    push_warning(
                        warnings,
                        "JSONL record limit reached; later lines remain only as raw evidence",
                    );
                    break;
                }
                if line.len() > MAX_LINE_BYTES {
                    push_warning(
                        warnings,
                        format!(
                            "JSONL line {} exceeded the line limit and was skipped",
                            index + 1
                        ),
                    );
                    continue;
                }
                match serde_json::from_slice::<Value>(line) {
                    Ok(value) => rows.push((index + 1, value)),
                    Err(_) => push_warning(
                        warnings,
                        format!("malformed JSONL line {} was skipped", index + 1),
                    ),
                }
            }
            if rows.is_empty() {
                push_warning(
                    warnings,
                    format!(
                        "artifact {} was neither valid bounded JSON nor JSONL: {}",
                        safe_text(&artifact.id, MAX_SHORT_TEXT),
                        safe_text(&document_error.to_string(), MAX_SHORT_TEXT)
                    ),
                );
                None
            } else {
                Some(ParsedArtifact::JsonLines(rows))
            }
        }
    }
}

fn parse_greenbone_xml(
    bytes: &[u8],
    warnings: &mut Vec<String>,
) -> Option<Vec<GreenboneXmlResult>> {
    parse_greenbone_xml_reader(bytes, warnings)
}

fn parse_greenbone_xml_reader(
    bytes: impl BufRead,
    warnings: &mut Vec<String>,
) -> Option<Vec<GreenboneXmlResult>> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    reader.config_mut().check_end_names = true;
    reader.config_mut().expand_empty_elements = true;

    let mut buffer = Vec::new();
    let mut stack = Vec::new();
    let mut current: Option<GreenboneXmlResult> = None;
    let mut records = Vec::new();
    let mut event_count = 0_usize;
    let mut result_index = 0_usize;

    loop {
        event_count += 1;
        if event_count > MAX_XML_EVENTS {
            push_warning(
                warnings,
                "Greenbone XML event limit reached; later results remain only as raw evidence",
            );
            break;
        }

        match reader.read_event_into(&mut buffer) {
            Ok(Event::Eof) => break,
            Ok(Event::DocType(_)) => {
                push_warning(
                    warnings,
                    "Greenbone XML containing a DTD or custom entity reference was rejected",
                );
                return None;
            }
            Ok(Event::GeneralRef(reference)) => {
                let Some(value) = safe_xml_reference(&reference) else {
                    push_warning(
                        warnings,
                        "Greenbone XML containing a DTD or custom entity reference was rejected",
                    );
                    return None;
                };
                if is_greenbone_field(&stack)
                    && let Some(record) = current.as_mut()
                {
                    let mut encoded = [0_u8; 4];
                    apply_greenbone_text(record, &stack, value.encode_utf8(&mut encoded));
                }
            }
            Ok(Event::Start(start)) => {
                if stack.len() >= MAX_XML_DEPTH {
                    push_warning(
                        warnings,
                        "Greenbone XML nesting limit was exceeded; no XML findings were normalized",
                    );
                    return None;
                }
                let element = xml_element(start.local_name().as_ref());
                if element == XmlElement::Result && stack.last() == Some(&XmlElement::Results) {
                    if current.is_some() {
                        push_warning(warnings, "nested Greenbone result elements were rejected");
                        return None;
                    }
                    if records.len() >= MAX_RECORDS {
                        push_warning(
                            warnings,
                            "Greenbone result limit reached; later results remain only as raw evidence",
                        );
                        break;
                    }
                    result_index += 1;
                    let mut record = GreenboneXmlResult {
                        pointer: format!("/report/results/result[{result_index}]"),
                        ..GreenboneXmlResult::default()
                    };
                    match xml_attribute(&start, "id") {
                        Ok(value) => record.result_id = value,
                        Err(error) => {
                            push_warning(warnings, error);
                            return None;
                        }
                    }
                    current = Some(record);
                } else if element == XmlElement::Nvt && current.is_some() {
                    match xml_attribute(&start, "oid") {
                        Ok(Some(value)) => {
                            if let Some(oid) = normalize_greenbone_oid(&value) {
                                if let Some(record) = current.as_mut() {
                                    record.nvt_oid = Some(oid);
                                }
                            } else {
                                push_warning(warnings, "Greenbone result had an invalid NVT OID");
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            push_warning(warnings, error);
                            return None;
                        }
                    }
                } else if element == XmlElement::Ref
                    && stack.last() == Some(&XmlElement::Refs)
                    && current.is_some()
                {
                    let reference_type = match xml_attribute(&start, "type") {
                        Ok(value) => value,
                        Err(error) => {
                            push_warning(warnings, error);
                            return None;
                        }
                    };
                    let reference_id = match xml_attribute(&start, "id") {
                        Ok(value) => value,
                        Err(error) => {
                            push_warning(warnings, error);
                            return None;
                        }
                    };
                    if reference_type
                        .as_deref()
                        .is_some_and(|value| value.eq_ignore_ascii_case("cve"))
                        && let Some(cve) = reference_id.and_then(|value| normalize_cve(&value))
                        && let Some(record) = current.as_mut()
                        && record.cves.len() < 32
                        && !record.cves.contains(&cve)
                    {
                        record.cves.push(cve);
                    }
                }
                stack.push(element);
            }
            Ok(Event::End(end)) => {
                let element = xml_element(end.local_name().as_ref());
                if element == XmlElement::Result
                    && stack.last() == Some(&XmlElement::Result)
                    && let Some(record) = current.take()
                {
                    records.push(record);
                }
                stack.pop();
            }
            Ok(Event::Text(text)) if current.is_some() && is_greenbone_field(&stack) => {
                let raw_text: &str = text.as_ref();
                if raw_text.len() > MAX_LONG_TEXT * 4 {
                    push_warning(warnings, "an oversized Greenbone XML field was ignored");
                    buffer.clear();
                    continue;
                }
                let unescaped = match quick_xml::escape::unescape(raw_text) {
                    Ok(value) => value,
                    Err(_) => {
                        push_warning(
                            warnings,
                            "a Greenbone XML field used an unsupported entity and was ignored",
                        );
                        buffer.clear();
                        continue;
                    }
                };
                apply_greenbone_text(current.as_mut().expect("checked above"), &stack, &unescaped);
            }
            Ok(Event::CData(text)) if current.is_some() && is_greenbone_field(&stack) => {
                let raw_text: &str = text.as_ref();
                if raw_text.len() > MAX_LONG_TEXT * 4 {
                    push_warning(warnings, "an oversized Greenbone XML field was ignored");
                    buffer.clear();
                    continue;
                }
                apply_greenbone_text(current.as_mut().expect("checked above"), &stack, raw_text);
            }
            Ok(Event::PI(_)) => {
                push_warning(
                    warnings,
                    "a Greenbone XML processing instruction was ignored",
                );
            }
            Ok(_) => {}
            Err(error) => {
                push_warning(
                    warnings,
                    format!(
                        "Greenbone XML parsing stopped at byte {}: {}",
                        reader.error_position(),
                        safe_text(&error.to_string(), 240)
                    ),
                );
                break;
            }
        }
        buffer.clear();
    }

    if current.is_some() {
        push_warning(
            warnings,
            "an incomplete Greenbone result was retained only as raw evidence",
        );
    }
    if records.is_empty() {
        push_warning(
            warnings,
            "Greenbone XML contained no complete bounded result records; no findings were inferred",
        );
    }
    Some(records)
}

fn xml_attribute(start: &BytesStart<'_>, name: &str) -> Result<Option<String>, String> {
    let mut matched = None;
    for (index, attribute) in start.attributes().with_checks(true).enumerate() {
        if index >= MAX_XML_ATTRIBUTES {
            return Err("Greenbone XML element exceeded the attribute limit".to_owned());
        }
        let attribute =
            attribute.map_err(|_| "Greenbone XML contained a malformed attribute".to_owned())?;
        if attribute.key.as_ref() == name && matched.is_none() {
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|_| "Greenbone XML attribute decode failed".to_owned())?;
            matched = Some(safe_text(&value, MAX_SHORT_TEXT));
        }
    }
    Ok(matched)
}

fn safe_xml_reference(reference: &BytesRef<'_>) -> Option<char> {
    let value = match reference.as_ref() {
        "amp" => '&',
        "apos" => '\'',
        "gt" => '>',
        "lt" => '<',
        "quot" => '"',
        _ => reference.resolve_char_ref().ok().flatten()?,
    };
    matches!(
        value,
        '\u{9}' | '\u{A}' | '\u{D}'
            | '\u{20}'..='\u{D7FF}'
            | '\u{E000}'..='\u{FFFD}'
            | '\u{10000}'..='\u{10FFFF}'
    )
    .then_some(value)
}

fn xml_element(name: &str) -> XmlElement {
    match name {
        "results" => XmlElement::Results,
        "result" => XmlElement::Result,
        "name" => XmlElement::Name,
        "nvt" => XmlElement::Nvt,
        "host" => XmlElement::Host,
        "port" => XmlElement::Port,
        "result_type" => XmlElement::ResultType,
        "severity" => XmlElement::Severity,
        "threat" => XmlElement::Threat,
        "summary" => XmlElement::Summary,
        "solution" => XmlElement::Solution,
        "qod" => XmlElement::Qod,
        "value" => XmlElement::Value,
        "asset_id" => XmlElement::AssetId,
        "family" => XmlElement::Family,
        "refs" => XmlElement::Refs,
        "ref" => XmlElement::Ref,
        _ => XmlElement::Other,
    }
}

fn is_greenbone_field(stack: &[XmlElement]) -> bool {
    stack.ends_with(&[XmlElement::Result, XmlElement::Name])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Nvt, XmlElement::Name])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Host])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Port])
        || stack.ends_with(&[XmlElement::Result, XmlElement::ResultType])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Severity])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Threat])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Summary])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Solution])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Qod, XmlElement::Value])
        || stack.ends_with(&[XmlElement::Result, XmlElement::AssetId])
        || stack.ends_with(&[XmlElement::Result, XmlElement::Nvt, XmlElement::Family])
}

fn apply_greenbone_text(record: &mut GreenboneXmlResult, stack: &[XmlElement], value: &str) {
    let value = value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(MAX_LONG_TEXT)
        .collect::<String>();
    if value.is_empty() {
        return;
    }
    let target = if stack.ends_with(&[XmlElement::Result, XmlElement::Name]) {
        &mut record.result_name
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Nvt, XmlElement::Name]) {
        &mut record.nvt_name
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Host]) {
        &mut record.host
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Port]) {
        &mut record.port
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::ResultType]) {
        &mut record.result_type
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Severity]) {
        &mut record.severity
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Threat]) {
        &mut record.threat
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Summary]) {
        &mut record.summary
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Solution]) {
        &mut record.solution
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Qod, XmlElement::Value]) {
        &mut record.qod
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::AssetId]) {
        &mut record.asset_id
    } else if stack.ends_with(&[XmlElement::Result, XmlElement::Nvt, XmlElement::Family]) {
        &mut record.family
    } else {
        return;
    };
    if let Some(target) = target.as_mut() {
        let remaining = MAX_LONG_TEXT.saturating_sub(target.chars().count());
        target.extend(value.chars().take(remaining));
    } else {
        let value = value.trim().to_owned();
        if !value.is_empty() {
            *target = Some(value);
        }
    }
}

fn normalize_greenbone_oid(value: &str) -> Option<String> {
    let value = value.trim();
    if value.len() < 3
        || value.len() > 128
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|segment| {
            segment.is_empty() || !segment.chars().all(|character| character.is_ascii_digit())
        })
    {
        return None;
    }
    Some(value.to_owned())
}

fn normalize_cve(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_uppercase();
    let mut segments = value.split('-');
    let prefix = segments.next()?;
    let year = segments.next()?;
    let sequence = segments.next()?;
    if segments.next().is_some()
        || prefix != "CVE"
        || year.len() != 4
        || !year.chars().all(|character| character.is_ascii_digit())
        || !(4..=12).contains(&sequence.len())
        || !sequence.chars().all(|character| character.is_ascii_digit())
    {
        return None;
    }
    Some(value)
}

/// Attach only explicitly selected scanner rule/advisory metadata.
///
/// Scanner output remains untrusted data. Every field is bounded and stripped
/// of control characters here, in one place, before it reaches durable
/// evidence. Callers must still allowlist the source paths: secret values, raw
/// matches, response bodies, and target-observed values never belong here.
/// The most CWE identifiers and CVSS scores retained for one result.
///
/// Upstream can attach many of each (Trivy publishes a score per scoring
/// vendor). Both are bounded so a hostile or merely verbose artifact cannot
/// grow a case file through a field the reader only ever skims.
const MAX_CWE_IDS: usize = 16;
const MAX_CVSS_SCORES: usize = 8;

/// Bounded upstream weakness classification for one result.
///
/// The identifiers are the scanner's, not this product's. Normalization is
/// limited to shape -- `cwe-78`, `CWE-78`, and
/// `CWE-78: Improper Neutralization of Special Elements` all name CWE-78 --
/// and anything that cannot be read is dropped rather than guessed at.
#[derive(Debug, Default)]
struct UpstreamWeakness {
    cwe_ids: Vec<String>,
    cvss: Vec<CvssScore>,
}

impl UpstreamWeakness {
    fn is_empty(&self) -> bool {
        self.cwe_ids.is_empty() && self.cvss.is_empty()
    }
}

/// Read `CWE-<digits>` out of one scanner value.
///
/// Scanners publish the same identifier in at least four shapes: the bare
/// string, the lowercase `cwe-78` Nuclei uses, the numeric `78` some SARIF
/// producers emit, and Semgrep's `CWE-78: <title>`. Only the number is the
/// identifier; the rest is that scanner's presentation.
fn cwe_identifier(value: &Value) -> Option<String> {
    let text = match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        _ => return None,
    };
    let text = text.trim();
    let digits = match text.get(..4) {
        Some(prefix) if prefix.eq_ignore_ascii_case("cwe-") => &text[4..],
        _ => text,
    };
    let digits = digits
        .split(|character: char| !character.is_ascii_digit())
        .find(|part| !part.is_empty())?;
    // A CWE id is a small integer; anything longer is not one, and truncating
    // it would invent a different weakness.
    if digits.len() > 7 {
        return None;
    }
    Some(format!("CWE-{}", digits.trim_start_matches('0')))
}

/// Collect CWE identifiers from a field that may hold one value or a list.
fn cwe_identifiers(value: Option<&Value>) -> Vec<String> {
    let mut ids = Vec::new();
    let mut push = |value: &Value| {
        if ids.len() >= MAX_CWE_IDS {
            return;
        }
        if let Some(id) = cwe_identifier(value)
            && !ids.contains(&id)
        {
            ids.push(id);
        }
    };
    match value {
        Some(Value::Array(items)) => items.iter().for_each(&mut push),
        Some(other) => push(other),
        None => {}
    }
    ids
}

/// A CVSS base score kept as the scanner printed it.
///
/// Validated as a number in 0.0-10.0 and otherwise dropped: a score outside
/// the scale is not a CVSS score, and passing it through would put a number
/// the reader trusts next to one this product never checked. The digits are
/// returned unreformatted so `9.8` stays `9.8`.
fn cvss_base_score(value: Option<&Value>) -> Option<String> {
    let text = match value? {
        Value::String(text) => text.trim().to_owned(),
        Value::Number(number) => number.to_string(),
        _ => return None,
    };
    if text.is_empty() || text.len() > 8 {
        return None;
    }
    let parsed = text.parse::<f64>().ok()?;
    if !parsed.is_finite() || !(0.0..=10.0).contains(&parsed) {
        return None;
    }
    Some(text)
}

/// Read the specification version out of a CVSS vector, e.g. `CVSS:3.1/AV:N`.
///
/// A vector that names no version is CVSS 2.0, which is the one version whose
/// vectors carry no prefix.
fn cvss_version_from_vector(vector: &str) -> String {
    vector
        .strip_prefix("CVSS:")
        .and_then(|rest| rest.split('/').next())
        .filter(|version| {
            !version.is_empty()
                && version.len() <= 4
                && version
                    .chars()
                    .all(|character| character.is_ascii_digit() || character == '.')
        })
        .unwrap_or("2.0")
        .to_owned()
}

/// Build one score from a vector and/or a base score, dropping the pair when
/// the scanner supplied neither.
fn cvss_score(
    source: &str,
    vector: Option<String>,
    base_score: Option<String>,
) -> Option<CvssScore> {
    let vector = vector
        .map(|vector| safe_text(&vector, MAX_SHORT_TEXT))
        .filter(|vector| !vector.is_empty());
    let base_score = base_score?;
    Some(CvssScore {
        version: vector
            .as_deref()
            .map(cvss_version_from_vector)
            .unwrap_or_else(|| "unspecified".into()),
        vector,
        base_score,
        source: safe_text(source, MAX_SHORT_TEXT),
    })
}

/// Attach an upstream weakness classification to a record.
///
/// Creates the scanner-detail block when the record has none, so a parser can
/// report a CWE for a result that carried no description or fix text.
fn with_weakness(mut record: SourceRecord, weakness: UpstreamWeakness) -> SourceRecord {
    if weakness.is_empty() {
        return record;
    }
    let details = record
        .scanner_details
        .get_or_insert_with(|| ScannerFindingDetails {
            description: None,
            remediation: None,
            installed_version: None,
            fixed_version: None,
            aws_iam_policy: None,
            cwe_ids: Vec::new(),
            cvss: Vec::new(),
            benchmarks: Vec::new(),
            advisory_aliases: Vec::new(),
        });
    details.cwe_ids = weakness.cwe_ids;
    details.cvss = weakness.cvss;
    record
}

fn with_scanner_details(
    mut record: SourceRecord,
    description: Option<String>,
    remediation: Option<String>,
    installed_version: Option<String>,
    fixed_version: Option<String>,
) -> SourceRecord {
    let advisory_aliases = record
        .scanner_details
        .as_ref()
        .map(|details| details.advisory_aliases.clone())
        .unwrap_or_default();
    let details = ScannerFindingDetails {
        description: bounded_scanner_detail(description, MAX_LONG_TEXT),
        remediation: bounded_scanner_detail(remediation, MAX_LONG_TEXT),
        installed_version: bounded_scanner_detail(installed_version, MAX_SHORT_TEXT),
        fixed_version: bounded_scanner_detail(fixed_version, MAX_SHORT_TEXT),
        aws_iam_policy: None,
        cwe_ids: Vec::new(),
        cvss: Vec::new(),
        benchmarks: Vec::new(),
        advisory_aliases,
    };
    if details.description.is_some()
        || details.remediation.is_some()
        || details.installed_version.is_some()
        || details.fixed_version.is_some()
        || !details.advisory_aliases.is_empty()
    {
        record.scanner_details = Some(details);
    }
    record
}

/// Keep identifiers the scanner itself listed for this result. An empty list
/// leaves the record unchanged, including a details block created earlier.
fn with_advisory_aliases(mut record: SourceRecord, aliases: Vec<String>) -> SourceRecord {
    if aliases.is_empty() {
        return record;
    }
    let details = record
        .scanner_details
        .get_or_insert_with(|| ScannerFindingDetails {
            description: None,
            remediation: None,
            installed_version: None,
            fixed_version: None,
            aws_iam_policy: None,
            cwe_ids: Vec::new(),
            cvss: Vec::new(),
            benchmarks: Vec::new(),
            advisory_aliases: Vec::new(),
        });
    details.advisory_aliases = aliases;
    record
}

/// CVE- or GHSA-shaped ids, in scanner order, as the scanner wrote them.
///
/// Compared case-insensitively. The record's own id, anything else, and
/// uppercase duplicates are dropped. At most 16 remain.
fn reported_advisory_aliases(
    raw_ids: impl IntoIterator<Item = String>,
    own_id: &str,
) -> Vec<String> {
    let own = own_id.trim().to_ascii_uppercase();
    let mut seen = BTreeSet::new();
    let mut aliases = Vec::new();
    for raw in raw_ids {
        let display = raw.trim();
        if display.is_empty() {
            continue;
        }
        let upper = display.to_ascii_uppercase();
        if upper == own || seen.contains(&upper) {
            continue;
        }
        if !crate::correlation::is_cve_identifier(&upper)
            && !crate::correlation::is_ghsa_identifier(&upper)
        {
            continue;
        }
        seen.insert(upper);
        aliases.push(display.to_owned());
        if aliases.len() == 16 {
            break;
        }
    }
    aliases
}

fn object_advisory_ids(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("id").and_then(exact_rule_scalar))
                .collect()
        })
        .unwrap_or_default()
}

fn string_advisory_ids(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(exact_rule_scalar).collect())
        .unwrap_or_default()
}

fn bounded_scanner_detail(value: Option<String>, max_chars: usize) -> Option<String> {
    let value = value?;
    let cleaned = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(max_chars)
        .collect::<String>();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    (!cleaned.is_empty()).then_some(cleaned)
}

fn bounded_string_list(value: Option<&Value>, max_items: usize) -> Option<String> {
    let values = value?.as_array()?;
    let joined = values
        .iter()
        .filter_map(Value::as_str)
        .map(|value| safe_text(value, MAX_SHORT_TEXT))
        .filter(|value| !value.is_empty())
        .take(max_items)
        .collect::<Vec<_>>()
        .join(", ");
    (!joined.is_empty()).then_some(joined)
}

fn inventory_text(value: Option<String>, max_chars: usize) -> Option<String> {
    bounded_scanner_detail(value, max_chars)
}

fn inventory_string_any(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    inventory_text(string_any(object, keys), MAX_SHORT_TEXT)
}

fn inventory_u16(value: Option<&Value>) -> Option<u16> {
    value
        .and_then(scalar_string)
        .and_then(|value| value.parse::<u16>().ok())
}

fn inventory_host(value: Option<String>) -> Option<String> {
    let value = inventory_text(value, MAX_SHORT_TEXT)?;
    if let Ok(address) = value.parse::<std::net::IpAddr>() {
        return Some(address.to_string());
    }
    let parsed = url::Url::parse(&format!("http://{value}")).ok()?;
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    inventory_text(parsed.host_str().map(str::to_owned), MAX_SHORT_TEXT)
}

fn extract_inventory_records(
    profile: Profile,
    parsed: &ParsedArtifact,
    artifact: &RawArtifact,
    warnings: &mut Vec<String>,
) -> Vec<InventoryRecord> {
    match profile {
        Profile::CloudQuery => extract_cloudquery_inventory(parsed, artifact, warnings),
        Profile::Steampipe => extract_steampipe_inventory(parsed, warnings),
        Profile::Naabu => extract_naabu_inventory(parsed, warnings),
        Profile::Httpx => extract_httpx_inventory(parsed, warnings),
        Profile::Syft => extract_syft_inventory(parsed, warnings),
        Profile::AgenticRadar => extract_agentic_radar_inventory(parsed, warnings),
        _ => Vec::new(),
    }
}

fn extract_agentic_radar_inventory(
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
) -> Vec<InventoryRecord> {
    let ParsedArtifact::Json(Value::Object(document)) = parsed else {
        push_warning(
            warnings,
            "Agentic Radar output was not its supported JSON document; the raw artifact was retained, and workflow inventory is incomplete",
        );
        return Vec::new();
    };
    if document.get("schema_version").and_then(Value::as_str) != Some("1")
        || document.get("scanner_version").and_then(Value::as_str) != Some("0.14.1")
    {
        push_warning(
            warnings,
            "Agentic Radar output did not match the pinned schema and scanner version; the raw artifact was retained, and workflow inventory is incomplete",
        );
        return Vec::new();
    }
    let Some(framework) = document.get("framework").and_then(Value::as_str) else {
        push_warning(
            warnings,
            "Agentic Radar output lacked its framework; the raw artifact was retained, and workflow inventory is incomplete",
        );
        return Vec::new();
    };
    if !matches!(
        framework,
        "langgraph" | "crewai" | "n8n" | "openai-agents" | "autogen"
    ) {
        push_warning(
            warnings,
            "Agentic Radar output named an unsupported framework; the raw artifact was retained, and workflow inventory is incomplete",
        );
        return Vec::new();
    }
    let Some(status) = document.get("status").and_then(Value::as_str) else {
        push_warning(
            warnings,
            "Agentic Radar output lacked its status; the raw artifact was retained, and workflow inventory is incomplete",
        );
        return Vec::new();
    };
    if !matches!(status, "workflow_found" | "no_supported_workflow") {
        push_warning(
            warnings,
            "Agentic Radar output named an unsupported status; the raw artifact was retained, and workflow inventory is incomplete",
        );
        return Vec::new();
    }

    let complete = document.get("complete").and_then(Value::as_bool);
    let upstream_warnings = document.get("warnings").and_then(Value::as_array);
    match (complete, upstream_warnings) {
        (Some(true), Some(values)) if values.is_empty() => {}
        (Some(false), Some(values)) if !values.is_empty() => {}
        _ => push_warning(
            warnings,
            "Agentic Radar completeness did not agree with its structured warnings; the partial graph was retained, but workflow inventory is incomplete",
        ),
    }
    if let Some(upstream_warnings) = upstream_warnings {
        if upstream_warnings.len() > MAX_WARNINGS {
            push_warning(
                warnings,
                "Agentic Radar warnings exceeded the adapter safety boundary; later diagnostics remain only in the raw artifact",
            );
        }
        for (index, value) in upstream_warnings.iter().take(MAX_WARNINGS).enumerate() {
            let pointer = format!("/warnings/{index}");
            let Some(object) = value.as_object() else {
                push_warning(
                    warnings,
                    format!(
                        "Agentic Radar warning at {pointer} was malformed; the partial graph was retained"
                    ),
                );
                continue;
            };
            if object.get("code").and_then(Value::as_str) != Some("analyzer_diagnostic") {
                push_warning(
                    warnings,
                    format!(
                        "Agentic Radar warning at {pointer} used an unsupported code; the partial graph was retained"
                    ),
                );
                continue;
            }
            let Some(message) = inventory_string_any(object, &["message"]) else {
                push_warning(
                    warnings,
                    format!(
                        "Agentic Radar warning at {pointer} lacked a bounded message; the partial graph was retained"
                    ),
                );
                continue;
            };
            push_warning(
                warnings,
                format!("Agentic Radar reported incomplete workflow inventory: {message}"),
            );
        }
    }

    let Some(graph) = document.get("graph").and_then(Value::as_object) else {
        push_warning(
            warnings,
            "Agentic Radar output lacked its graph object; the raw artifact was retained, and workflow inventory is incomplete",
        );
        return Vec::new();
    };
    let Some(nodes) = graph.get("nodes").and_then(Value::as_array) else {
        push_warning(
            warnings,
            "Agentic Radar graph lacked its nodes array; the raw artifact was retained, and workflow inventory is incomplete",
        );
        return Vec::new();
    };
    let Some(edges) = graph.get("edges").and_then(Value::as_array) else {
        push_warning(
            warnings,
            "Agentic Radar graph lacked its edges array; the raw artifact was retained, and workflow inventory is incomplete",
        );
        return Vec::new();
    };
    let Some(agents) = graph.get("agents").and_then(Value::as_array) else {
        push_warning(
            warnings,
            "Agentic Radar graph lacked its agents array; the raw artifact was retained, and workflow inventory is incomplete",
        );
        return Vec::new();
    };
    let Some(tools) = graph.get("tools").and_then(Value::as_array) else {
        push_warning(
            warnings,
            "Agentic Radar graph lacked its tools array; the raw artifact was retained, and workflow inventory is incomplete",
        );
        return Vec::new();
    };

    if (status == "workflow_found") != (nodes.len() > 2) {
        push_warning(
            warnings,
            "Agentic Radar graph membership did not agree with its workflow status; the graph was retained, but workflow inventory is incomplete",
        );
    }

    let mut components = BTreeMap::<String, InventoryRecord>::new();
    for (collection_name, values) in [("nodes", nodes), ("tools", tools)] {
        if values.len() > MAX_RECORDS {
            push_warning(
                warnings,
                format!(
                    "Agentic Radar {collection_name} exceeded the record safety boundary; later components remain only in the raw artifact"
                ),
            );
        }
        for (index, value) in values.iter().take(MAX_RECORDS).enumerate() {
            let pointer = format!("/graph/{collection_name}/{index}");
            let Some(object) = value.as_object() else {
                push_warning(
                    warnings,
                    format!(
                        "Agentic Radar component at {pointer} was not an object and was not normalized"
                    ),
                );
                continue;
            };
            let Some(component_type) = agentic_radar_identity(object, "node_type") else {
                push_warning(
                    warnings,
                    format!(
                        "Agentic Radar component at {pointer} lacked its node type and was not normalized"
                    ),
                );
                continue;
            };
            if !matches!(
                component_type.as_str(),
                "agent" | "basic" | "tool" | "custom_tool" | "mcp_server" | "default"
            ) {
                push_warning(
                    warnings,
                    format!(
                        "Agentic Radar component at {pointer} used an unsupported node type and was not normalized"
                    ),
                );
                continue;
            }
            let Some(name) = agentic_radar_identity(object, "name") else {
                push_warning(
                    warnings,
                    format!(
                        "Agentic Radar component at {pointer} lacked its name and was not normalized"
                    ),
                );
                continue;
            };
            agentic_radar_reject_vulnerability_claims(object, &pointer, warnings);
            let key = format!("{component_type}\0{name}");
            components.entry(key).or_insert(InventoryRecord {
                pointer,
                asset_hint: None,
                asset_provider: None,
                kind: InventoryObservationKind::WorkflowComponent {
                    component_type,
                    name,
                    model: None,
                    is_guardrail: None,
                },
            });
        }
    }

    if agents.len() > MAX_RECORDS {
        push_warning(
            warnings,
            "Agentic Radar agents exceeded the record safety boundary; later agent metadata remains only in the raw artifact",
        );
    }
    for (index, value) in agents.iter().take(MAX_RECORDS).enumerate() {
        let pointer = format!("/graph/agents/{index}");
        let Some(object) = value.as_object() else {
            push_warning(
                warnings,
                format!(
                    "Agentic Radar agent at {pointer} was not an object and was not normalized"
                ),
            );
            continue;
        };
        let Some(name) = agentic_radar_identity(object, "name") else {
            push_warning(
                warnings,
                format!("Agentic Radar agent at {pointer} lacked its name and was not normalized"),
            );
            continue;
        };
        let model = agentic_radar_identity(object, "llm");
        if object.get("llm").is_some() && model.is_none() {
            push_warning(
                warnings,
                format!("Agentic Radar agent at {pointer} had no bounded model identifier"),
            );
        }
        let is_guardrail = object.get("is_guardrail").and_then(Value::as_bool);
        if object.get("is_guardrail").is_some() && is_guardrail.is_none() {
            push_warning(
                warnings,
                format!("Agentic Radar agent at {pointer} had an invalid guardrail flag"),
            );
        }
        agentic_radar_reject_vulnerability_claims(object, &pointer, warnings);
        components.insert(
            format!("agent\0{name}"),
            InventoryRecord {
                pointer,
                asset_hint: None,
                asset_provider: None,
                kind: InventoryObservationKind::WorkflowComponent {
                    component_type: "agent".into(),
                    name,
                    model,
                    is_guardrail,
                },
            },
        );
    }

    let mut relationships = BTreeMap::<String, InventoryRecord>::new();
    if edges.len() > MAX_RECORDS {
        push_warning(
            warnings,
            "Agentic Radar edges exceeded the record safety boundary; later relationships remain only in the raw artifact",
        );
    }
    for (index, value) in edges.iter().take(MAX_RECORDS).enumerate() {
        let pointer = format!("/graph/edges/{index}");
        let Some(object) = value.as_object() else {
            push_warning(
                warnings,
                format!(
                    "Agentic Radar relationship at {pointer} was not an object and was not normalized"
                ),
            );
            continue;
        };
        let (Some(source), Some(target)) = (
            agentic_radar_identity(object, "start"),
            agentic_radar_identity(object, "end"),
        ) else {
            push_warning(
                warnings,
                format!(
                    "Agentic Radar relationship at {pointer} lacked an endpoint and was not normalized"
                ),
            );
            continue;
        };
        let condition = match object.get("condition") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) => {
                let condition = agentic_radar_text(value);
                if condition.is_none() {
                    push_warning(
                        warnings,
                        format!("Agentic Radar relationship at {pointer} had no bounded condition"),
                    );
                }
                condition
            }
            Some(_) => {
                push_warning(
                    warnings,
                    format!("Agentic Radar relationship at {pointer} had an invalid condition"),
                );
                None
            }
        };
        let key = format!("{source}\0{target}\0{}", condition.as_deref().unwrap_or(""));
        relationships.entry(key).or_insert(InventoryRecord {
            pointer,
            asset_hint: None,
            asset_provider: None,
            kind: InventoryObservationKind::WorkflowRelationship {
                source,
                target,
                condition,
            },
        });
    }

    components
        .into_values()
        .chain(relationships.into_values())
        .take(MAX_RECORDS)
        .collect()
}

fn agentic_radar_identity(object: &Map<String, Value>, key: &str) -> Option<String> {
    agentic_radar_text(object.get(key)?.as_str()?)
}

fn agentic_radar_text(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > MAX_SHORT_TEXT
        || value.chars().any(char::is_control)
    {
        return None;
    }
    Some(value.to_owned())
}

fn agentic_radar_reject_vulnerability_claims(
    object: &Map<String, Value>,
    pointer: &str,
    warnings: &mut Vec<String>,
) {
    match object.get("vulnerabilities") {
        Some(Value::Array(values)) if values.is_empty() => {}
        Some(Value::Array(_)) => push_warning(
            warnings,
            format!(
                "Agentic Radar record at {pointer} carried vulnerability claims; they were ignored, and workflow inventory is incomplete"
            ),
        ),
        _ => push_warning(
            warnings,
            format!(
                "Agentic Radar record at {pointer} lacked its empty vulnerability array; workflow inventory is incomplete"
            ),
        ),
    }
}

fn extract_steampipe_inventory(
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
) -> Vec<InventoryRecord> {
    let ParsedArtifact::Json(Value::Object(document)) = parsed else {
        push_warning(
            warnings,
            "Steampipe output was not its supported JSON document; the raw artifact was retained, and the inventory query should be retried",
        );
        return Vec::new();
    };
    let Some(rows) = document.get("rows").and_then(Value::as_array) else {
        push_warning(
            warnings,
            "Steampipe output lacked its rows array; the raw artifact was retained, and the inventory query should be retried",
        );
        return Vec::new();
    };
    if rows.len() > MAX_RECORDS {
        push_warning(
            warnings,
            "Steampipe rows exceeded the record safety boundary; later inventory rows remain only as raw evidence",
        );
    }

    rows.iter()
        .take(MAX_RECORDS)
        .enumerate()
        .filter_map(|(index, row)| {
            let pointer = format!("/rows/{index}");
            let Some(object) = row.as_object() else {
                push_warning(
                    warnings,
                    format!(
                        "Steampipe inventory record at {pointer} was not an object and was not normalized"
                    ),
                );
                return None;
            };

            let Some(account_id) = inventory_string_any(object, &["account_id", "asset_id"])
            else {
                push_warning(
                    warnings,
                    format!(
                        "Steampipe inventory record at {pointer} lacked its account identifier and was not normalized"
                    ),
                );
                return None;
            };
            let legacy = match object.get("resource_type") {
                None => true,
                Some(Value::String(resource_type)) if resource_type.trim() == "aws_iam_user" => {
                    false
                }
                Some(_) => {
                    push_warning(
                        warnings,
                        format!(
                            "Steampipe inventory record at {pointer} did not identify an aws_iam_user and was not normalized"
                        ),
                    );
                    return None;
                }
            };

            let arn = inventory_string_any(object, &["arn"]);
            let legacy_resource = inventory_string_any(object, &["resource"]);
            let user_id = inventory_string_any(object, &["user_id"]);
            if arn
                .as_deref()
                .is_some_and(|arn| !steampipe_iam_user_arn_matches_account(arn, &account_id))
            {
                push_warning(
                    warnings,
                    format!(
                        "Steampipe inventory record at {pointer} carried an IAM user ARN outside its declared account and was not normalized"
                    ),
                );
                return None;
            }
            if legacy {
                let exact_legacy_control = object
                    .get("control_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    == Some("steampipe:aws_iam_user_mfa");
                let account_bound_resource = legacy_resource.as_deref().is_some_and(|resource| {
                    steampipe_iam_user_arn_matches_account(resource, &account_id)
                });
                if !account_bound_resource || !exact_legacy_control {
                    push_warning(
                        warnings,
                        format!(
                            "Steampipe inventory record at {pointer} was not the supported legacy IAM-user shape and was not normalized"
                        ),
                    );
                    return None;
                }
            }
            let native_id = if legacy {
                legacy_resource
            } else {
                arn.or(user_id)
            };
            let Some(native_id) = native_id else {
                push_warning(
                    warnings,
                    format!(
                        "Steampipe inventory record at {pointer} lacked its IAM user ARN or user_id and was not normalized"
                    ),
                );
                return None;
            };
            let display_name = (!legacy)
                .then(|| inventory_string_any(object, &["name"]))
                .flatten();

            Some(InventoryRecord {
                pointer,
                asset_hint: Some(account_id),
                asset_provider: Some("aws".into()),
                kind: InventoryObservationKind::CloudResource {
                    resource_type: "aws_iam_user".into(),
                    native_id: Some(native_id),
                    display_name,
                },
            })
        })
        .collect()
}

fn steampipe_iam_user_arn_matches_account(arn: &str, account_id: &str) -> bool {
    let mut parts = arn.splitn(6, ':');
    matches!(
        (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ),
        (Some("arn"), Some(partition), Some("iam"), Some(""), Some(account), Some(resource))
            if matches!(partition, "aws" | "aws-cn" | "aws-us-gov" | "aws-iso" | "aws-iso-b")
                && account == account_id
                && resource.starts_with("user/")
                && resource.len() > "user/".len()
    )
}

fn cloudquery_resource_type(relative_path: &str) -> Option<&'static str> {
    let basename = Path::new(relative_path).file_name()?.to_str()?;
    match basename {
        "aws_iam_accounts.json" => Some("aws_iam_accounts"),
        "aws_iam_credential_reports.json" => Some("aws_iam_credential_reports"),
        "aws_iam_groups.json" => Some("aws_iam_groups"),
        "aws_iam_password_policies.json" => Some("aws_iam_password_policies"),
        "aws_iam_policies.json" => Some("aws_iam_policies"),
        "aws_iam_roles.json" => Some("aws_iam_roles"),
        "aws_iam_users.json" => Some("aws_iam_users"),
        _ => None,
    }
}

/// Child tables the pinned AWS v9.2.0 plugin syncs beneath the seven selected
/// tables. Their parent rows carry the inventory; the child rows stay raw
/// evidence.
fn is_cloudquery_dependent_table(relative_path: &str) -> bool {
    matches!(
        Path::new(relative_path)
            .file_name()
            .and_then(|basename| basename.to_str()),
        Some(
            "aws_iam_group_policies.json"
                | "aws_iam_role_policies.json"
                | "aws_iam_ssh_public_keys.json"
                | "aws_iam_user_access_keys.json"
                | "aws_iam_user_attached_policies.json"
                | "aws_iam_user_groups.json"
                | "aws_iam_user_policies.json"
        )
    )
}

/// The v9.2.0 aws_iam_credential_reports table has no account_id column; each
/// report row's ARN names its account, for an IAM user or the root user.
fn cloudquery_credential_report_account(arn: &str) -> Option<String> {
    let mut parts = arn.splitn(6, ':');
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some("arn"), Some(partition), Some("iam"), Some(""), Some(account), Some(resource))
            if matches!(
                partition,
                "aws" | "aws-cn" | "aws-us-gov" | "aws-iso" | "aws-iso-b"
            ) && account.len() == 12
                && account.bytes().all(|byte| byte.is_ascii_digit())
                && (resource == "root"
                    || (resource.starts_with("user/") && resource.len() > "user/".len())) =>
        {
            Some(account.to_owned())
        }
        _ => None,
    }
}

fn extract_cloudquery_inventory(
    parsed: &ParsedArtifact,
    artifact: &RawArtifact,
    warnings: &mut Vec<String>,
) -> Vec<InventoryRecord> {
    if is_cloudquery_dependent_table(&artifact.relative_path) {
        return Vec::new();
    }
    let Some(resource_type) = cloudquery_resource_type(&artifact.relative_path) else {
        push_warning(
            warnings,
            "CloudQuery artifact basename was not one of the fixed seven IAM tables; it was retained only as raw evidence",
        );
        return Vec::new();
    };
    let mut records = Vec::new();
    for (pointer, value) in json_rows(parsed, warnings) {
        let Some(object) = value.as_object() else {
            push_warning(
                warnings,
                format!(
                    "CloudQuery inventory record at {pointer} was not an object and was not normalized"
                ),
            );
            continue;
        };
        let account_id = inventory_string_any(object, &["account_id"]).or_else(|| {
            (resource_type == "aws_iam_credential_reports")
                .then(|| inventory_string_any(object, &["arn"]))
                .flatten()
                .and_then(|arn| cloudquery_credential_report_account(&arn))
        });
        let Some(account_id) = account_id else {
            push_warning(
                warnings,
                format!(
                    "CloudQuery inventory record at {pointer} lacked its account_id and was not normalized"
                ),
            );
            continue;
        };
        let (native_id, display_name) = match resource_type {
            "aws_iam_accounts" | "aws_iam_password_policies" => (Some(account_id.clone()), None),
            "aws_iam_credential_reports" => (
                inventory_string_any(object, &["arn", "user_id"]),
                inventory_string_any(object, &["user", "user_name"]),
            ),
            "aws_iam_groups" => (
                inventory_string_any(object, &["arn", "group_id"]),
                inventory_string_any(object, &["group_name"]),
            ),
            "aws_iam_policies" => (
                inventory_string_any(object, &["arn", "policy_id"]),
                inventory_string_any(object, &["policy_name"]),
            ),
            "aws_iam_roles" => (
                inventory_string_any(object, &["arn", "role_id"]),
                inventory_string_any(object, &["role_name"]),
            ),
            "aws_iam_users" => (
                inventory_string_any(object, &["arn", "user_id"]),
                inventory_string_any(object, &["user_name"]),
            ),
            _ => unreachable!("resource type came from the fixed table allowlist"),
        };
        records.push(InventoryRecord {
            pointer,
            asset_hint: Some(account_id),
            asset_provider: Some("aws".into()),
            kind: InventoryObservationKind::CloudResource {
                resource_type: resource_type.into(),
                native_id,
                display_name,
            },
        });
        if records.len() >= MAX_RECORDS {
            break;
        }
    }
    records
}

fn extract_syft_inventory(
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
) -> Vec<InventoryRecord> {
    let ParsedArtifact::Json(Value::Object(document)) = parsed else {
        push_warning(
            warnings,
            "Syft output was not its supported JSON document; the raw artifact was retained, and the scan should be retried with the pinned Syft JSON reporter",
        );
        return Vec::new();
    };
    let Some(artifacts) = document.get("artifacts").and_then(Value::as_array) else {
        push_warning(
            warnings,
            "Syft output lacked its artifacts array; the raw artifact was retained, and the scan should be retried with the pinned Syft JSON reporter",
        );
        return Vec::new();
    };
    artifacts
        .iter()
        .take(MAX_RECORDS)
        .enumerate()
        .filter_map(|(index, value)| {
            let pointer = format!("/artifacts/{index}");
            let Some(object) = value.as_object() else {
                push_warning(
                    warnings,
                    format!("Syft component at {pointer} was not an object and was not normalized"),
                );
                return None;
            };
            let Some(name) = inventory_string_any(object, &["name"]) else {
                push_warning(
                    warnings,
                    format!("Syft component at {pointer} lacked its name and was not normalized"),
                );
                return None;
            };
            Some(InventoryRecord {
                pointer,
                asset_hint: None,
                asset_provider: None,
                kind: InventoryObservationKind::SoftwareComponent {
                    name,
                    version: inventory_string_any(object, &["version"]),
                    package_type: inventory_string_any(object, &["type"]),
                    purl: inventory_string_any(object, &["purl"]),
                },
            })
        })
        .collect()
}

fn extract_naabu_inventory(
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
) -> Vec<InventoryRecord> {
    json_rows(parsed, warnings)
        .into_iter()
        .filter_map(|(pointer, value)| {
            let Some(object) = value.as_object() else {
                push_warning(
                    warnings,
                    format!("Naabu record at {pointer} was not an object and was not normalized"),
                );
                return None;
            };
            let Some(host) = inventory_host(string_any(object, &["host", "ip"])) else {
                push_warning(
                    warnings,
                    format!("Naabu record at {pointer} had no bounded host and was not normalized"),
                );
                return None;
            };
            let Some(port) = inventory_u16(object.get("port")).filter(|port| *port > 0) else {
                push_warning(
                    warnings,
                    format!("Naabu record at {pointer} had no bounded port and was not normalized"),
                );
                return None;
            };
            Some(InventoryRecord {
                pointer,
                asset_hint: inventory_string_any(object, &["asset_id"]),
                asset_provider: None,
                kind: InventoryObservationKind::Service {
                    endpoint: host,
                    port: Some(port),
                    transport: inventory_string_any(object, &["protocol"])
                        .or_else(|| Some("tcp".into())),
                    scheme: None,
                    http_status: None,
                    tls: object.get("tls").and_then(Value::as_bool),
                },
            })
        })
        .collect()
}

fn extract_httpx_inventory(
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
) -> Vec<InventoryRecord> {
    json_rows(parsed, warnings)
        .into_iter()
        .filter_map(|(pointer, value)| {
            let Some(object) = value.as_object() else {
                push_warning(
                    warnings,
                    format!("HTTPx record at {pointer} was not an object; retry with the supported pinned JSONL output"),
                );
                return None;
            };
            let parsed_url = inventory_string_any(object, &["url"])
                .and_then(|value| url::Url::parse(&value).ok());
            let Some(endpoint) = inventory_host(string_any(object, &["host"]))
                .or_else(|| inventory_host(string_any(object, &["input"])))
                .or_else(|| {
                    parsed_url.as_ref().and_then(|url| {
                        inventory_text(url.host_str().map(str::to_owned), MAX_SHORT_TEXT)
                    })
                })
            else {
                push_warning(
                    warnings,
                    format!("HTTPx record at {pointer} lacked its target; the raw record was retained, and the scan should be retried with the supported pinned JSONL output"),
                );
                return None;
            };
            let Some(status) = inventory_u16(
                object
                    .get("status_code")
                    .or_else(|| object.get("status-code")),
            )
            .filter(|status| (100..=599).contains(status))
            else {
                push_warning(
                    warnings,
                    format!("HTTPx record at {pointer} lacked its HTTP status; the raw record was retained, and the scan should be retried with the supported pinned JSONL output"),
                );
                return None;
            };
            Some(InventoryRecord {
                pointer,
                asset_hint: inventory_string_any(object, &["asset_id"]),
                asset_provider: None,
                kind: InventoryObservationKind::Service {
                    endpoint,
                    port: inventory_u16(object.get("port"))
                        .filter(|port| *port > 0)
                        .or_else(|| parsed_url.as_ref().and_then(url::Url::port_or_known_default)),
                    transport: Some("tcp".into()),
                    scheme: inventory_string_any(object, &["scheme"]).or_else(|| {
                        parsed_url.as_ref().and_then(|url| {
                            inventory_text(Some(url.scheme().to_owned()), MAX_SHORT_TEXT)
                        })
                    }),
                    http_status: Some(status),
                    tls: object.get("tls").and_then(Value::as_bool),
                },
            })
        })
        .collect()
}

fn extract_records(
    profile: Profile,
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
) -> Vec<SourceRecord> {
    if matches!(
        profile,
        Profile::CloudQuery
            | Profile::Steampipe
            | Profile::Naabu
            | Profile::Httpx
            | Profile::Syft
            | Profile::AgenticRadar
    ) {
        return Vec::new();
    }

    match profile {
        Profile::Prowler => extract_prowler(parsed, warnings),
        Profile::ScoutSuite => extract_scoutsuite(parsed, warnings),
        Profile::Cloudsplaining => extract_cloudsplaining(parsed, warnings),
        Profile::ScubaGear => extract_scubagear(parsed, warnings),
        Profile::Maester => extract_maester(parsed, warnings).records,
        Profile::Nuclei => extract_nuclei(parsed, warnings).records,
        Profile::Greenbone => unreachable!("Greenbone extraction needs authorized asset ids"),
        Profile::Zap => extract_zap(parsed, warnings),
        Profile::Semgrep => extract_semgrep(parsed, warnings),
        Profile::Gitleaks => extract_gitleaks(parsed, warnings),
        Profile::Trufflehog => extract_trufflehog(parsed, warnings),
        Profile::Checkov => extract_checkov(parsed, warnings),
        Profile::Kics => extract_kics(parsed, warnings),
        Profile::Trivy => extract_trivy(parsed, warnings),
        Profile::Grype => extract_grype(parsed, warnings),
        Profile::Kubescape => extract_kubescape(parsed, warnings),
        Profile::KubeBench => extract_kube_bench(parsed, warnings),
        Profile::Garak => extract_garak(parsed, warnings),
        Profile::McpArmor => extract_mcp_armor(parsed, warnings),
        Profile::CloudQuery
        | Profile::Steampipe
        | Profile::Naabu
        | Profile::Httpx
        | Profile::Syft
        | Profile::AgenticRadar => Vec::new(),
    }
}

const MCP_ARMOR_CHECKS: [(&str, &str, FindingFamily); 2] = [
    (
        "hardcoded_secrets",
        "Hardcoded Secret",
        FindingFamily::McpSecret,
    ),
    (
        "excessive_tool_permissions",
        "Excessive Tool Permissions",
        FindingFamily::McpConfiguration,
    ),
];

/// Read only the versioned, configuration-only envelope produced by the
/// retained MCP Armor patch. The adapter does not infer whether a server was
/// contacted: the dedicated mode and exact schema are the evidence boundary.
/// Findings from completed checks survive a sibling shortfall, while every
/// malformed ledger, warning, failed check, or unevaluated input clears
/// `AdapterOutput::complete` through the warnings emitted here.
fn extract_mcp_armor(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let ParsedArtifact::Json(Value::Object(document)) = parsed else {
        push_warning(
            warnings,
            "MCP Armor output was not its supported configuration-only JSON document; result processing is incomplete",
        );
        return Vec::new();
    };
    if document.get("schema_version").and_then(Value::as_str) != Some("1")
        || document.get("scanner_version").and_then(Value::as_str) != Some("1.0.2")
        || document.get("mode").and_then(Value::as_str) != Some("configuration_only")
    {
        push_warning(
            warnings,
            "MCP Armor output did not match the supported configuration-only schema, scanner version, and mode; result processing is incomplete",
        );
        return Vec::new();
    }

    let input_count = document.get("input_count").and_then(Value::as_u64);
    let evaluated_input_count = document
        .get("evaluated_input_count")
        .and_then(Value::as_u64);
    if input_count != Some(1) || evaluated_input_count.is_none_or(|count| count > 1) {
        push_warning(
            warnings,
            "MCP Armor input counts did not describe the one approved configuration snapshot; result processing is incomplete",
        );
    }

    let declared_complete = document.get("complete").and_then(Value::as_bool);
    if declared_complete.is_none() {
        push_warning(
            warnings,
            "MCP Armor output lacked its completeness flag; result processing is incomplete",
        );
    }

    let mut upstream_warning_count = 0_usize;
    match document.get("warnings").and_then(Value::as_array) {
        Some(values) => {
            if values.len() > MAX_WARNINGS {
                push_warning(
                    warnings,
                    "MCP Armor warnings exceeded the result safety boundary; additional diagnostics excluded",
                );
            }
            for (index, value) in values.iter().take(MAX_WARNINGS).enumerate() {
                let pointer = format!("/warnings/{index}");
                let Some(object) = value.as_object() else {
                    push_warning(
                        warnings,
                        format!(
                            "MCP Armor warning at {pointer} was malformed; result processing is incomplete"
                        ),
                    );
                    continue;
                };
                let Some(code) = mcp_armor_text(object.get("code")) else {
                    push_warning(
                        warnings,
                        format!(
                            "MCP Armor warning at {pointer} lacked a bounded code; result processing is incomplete"
                        ),
                    );
                    continue;
                };
                if !matches!(
                    code.as_str(),
                    "config_invalid" | "server_config_invalid" | "check_failed"
                ) {
                    push_warning(
                        warnings,
                        format!(
                            "MCP Armor warning at {pointer} used an unsupported code; result processing is incomplete"
                        ),
                    );
                    continue;
                }
                if mcp_armor_text(object.get("message")).is_none() {
                    push_warning(
                        warnings,
                        format!(
                            "MCP Armor warning at {pointer} lacked a bounded message; result processing is incomplete"
                        ),
                    );
                    continue;
                }
                let check_id = mcp_armor_text(object.get("check_id"));
                let config_file = mcp_armor_text(object.get("config_file"));
                let context = if code == "check_failed"
                    && check_id.as_deref().is_some_and(|candidate| {
                        MCP_ARMOR_CHECKS.iter().any(|(id, ..)| *id == candidate)
                    })
                    && config_file.is_none()
                {
                    format!("check {}", check_id.unwrap_or_default())
                } else if code != "check_failed" && check_id.is_none() && config_file.is_some() {
                    format!("configuration {}", config_file.unwrap_or_default())
                } else {
                    push_warning(
                        warnings,
                        format!(
                            "MCP Armor warning at {pointer} had invalid context; result processing is incomplete"
                        ),
                    );
                    continue;
                };
                push_warning(
                    warnings,
                    format!(
                        "MCP Armor reported incomplete configuration coverage ({code}) for {context}"
                    ),
                );
                upstream_warning_count += 1;
            }
        }
        None => push_warning(
            warnings,
            "MCP Armor output lacked its structured warnings array; result processing is incomplete",
        ),
    }

    let mut checks = BTreeMap::<String, (String, u64)>::new();
    match document.get("checks").and_then(Value::as_array) {
        Some(values) => {
            if values.len() != MCP_ARMOR_CHECKS.len() {
                push_warning(
                    warnings,
                    "MCP Armor check ledger did not contain exactly the two supported configuration checks; result processing is incomplete",
                );
            }
            for (index, value) in values.iter().enumerate() {
                let pointer = format!("/checks/{index}");
                let Some(object) = value.as_object() else {
                    push_warning(
                        warnings,
                        format!(
                            "MCP Armor check at {pointer} was malformed; result processing is incomplete"
                        ),
                    );
                    continue;
                };
                let Some(check_id) = mcp_armor_text(object.get("id")) else {
                    push_warning(
                        warnings,
                        format!(
                            "MCP Armor check at {pointer} lacked a bounded id; result processing is incomplete"
                        ),
                    );
                    continue;
                };
                if !MCP_ARMOR_CHECKS.iter().any(|(id, ..)| *id == check_id) {
                    push_warning(
                        warnings,
                        format!(
                            "MCP Armor check at {pointer} named an unsupported id; result processing is incomplete"
                        ),
                    );
                    continue;
                }
                let Some(status) = mcp_armor_text(object.get("status"))
                    .filter(|value| matches!(value.as_str(), "completed" | "failed" | "not_run"))
                else {
                    push_warning(
                        warnings,
                        format!(
                            "MCP Armor check {check_id} had an unsupported status; result processing is incomplete"
                        ),
                    );
                    continue;
                };
                let Some(finding_count) = object.get("finding_count").and_then(Value::as_u64)
                else {
                    push_warning(
                        warnings,
                        format!(
                            "MCP Armor check {check_id} lacked its finding count; result processing is incomplete"
                        ),
                    );
                    continue;
                };
                if finding_count > MAX_RECORDS as u64 {
                    push_warning(
                        warnings,
                        format!(
                            "MCP Armor check {check_id} exceeded the finding safety boundary; result processing is incomplete"
                        ),
                    );
                    continue;
                }
                if status != "completed" && finding_count != 0 {
                    push_warning(
                        warnings,
                        format!(
                            "MCP Armor check {check_id} reported findings without completing; result processing is incomplete"
                        ),
                    );
                    continue;
                }
                if checks
                    .insert(check_id.clone(), (status.clone(), finding_count))
                    .is_some()
                {
                    push_warning(
                        warnings,
                        format!(
                            "MCP Armor check ledger repeated {check_id}; result processing is incomplete"
                        ),
                    );
                }
                if status != "completed" {
                    push_warning(
                        warnings,
                        format!("MCP Armor did not complete configuration check {check_id}"),
                    );
                }
            }
        }
        None => push_warning(
            warnings,
            "MCP Armor output lacked its check ledger; result processing is incomplete",
        ),
    }
    for (check_id, ..) in MCP_ARMOR_CHECKS {
        if !checks.contains_key(check_id) {
            push_warning(
                warnings,
                format!(
                    "MCP Armor check ledger lacked {check_id}; result processing is incomplete"
                ),
            );
        }
    }

    let Some(findings) = document.get("findings").and_then(Value::as_array) else {
        push_warning(
            warnings,
            "MCP Armor output lacked its findings array; result processing is incomplete",
        );
        return Vec::new();
    };
    if findings.len() > MAX_RECORDS {
        push_warning(
            warnings,
            "MCP Armor findings exceeded the result safety boundary; additional findings remain only in raw evidence",
        );
    }

    let mut records = Vec::new();
    let mut observed_counts = BTreeMap::<String, u64>::new();
    for (index, value) in findings.iter().take(MAX_RECORDS).enumerate() {
        let pointer = format!("/findings/{index}");
        let Some(object) = value.as_object() else {
            push_warning(
                warnings,
                format!("MCP Armor finding at {pointer} was malformed and was not normalized"),
            );
            continue;
        };
        let Some(check_id) = mcp_armor_text(object.get("check_id")) else {
            push_warning(
                warnings,
                format!(
                    "MCP Armor finding at {pointer} lacked a bounded check id and was not normalized"
                ),
            );
            continue;
        };
        let Some((_, expected_type, family)) = MCP_ARMOR_CHECKS
            .iter()
            .find(|(id, ..)| *id == check_id)
            .copied()
        else {
            push_warning(
                warnings,
                format!(
                    "MCP Armor finding at {pointer} named an unsupported check and was not normalized"
                ),
            );
            continue;
        };
        if checks
            .get(&check_id)
            .is_none_or(|(status, _)| status != "completed")
        {
            push_warning(
                warnings,
                format!(
                    "MCP Armor finding at {pointer} belonged to a check that did not complete and was not normalized"
                ),
            );
            continue;
        }
        let finding_type = mcp_armor_text(object.get("finding_type"));
        let severity = mcp_armor_text(object.get("severity"));
        let severity_is_supported = match check_id.as_str() {
            "hardcoded_secrets" => severity.as_deref() == Some("high"),
            "excessive_tool_permissions" => {
                matches!(severity.as_deref(), Some("critical" | "low"))
            }
            _ => false,
        };
        if finding_type.as_deref() != Some(expected_type)
            || !severity_is_supported
            || object.get("entity_type").and_then(Value::as_str) != Some("configuration")
        {
            push_warning(
                warnings,
                format!(
                    "MCP Armor finding at {pointer} did not match its pinned check shape and was not normalized"
                ),
            );
            continue;
        }
        let Some(config_file) = mcp_armor_text(object.get("config_file")) else {
            push_warning(
                warnings,
                format!(
                    "MCP Armor finding at {pointer} lacked a bounded configuration path and was not normalized"
                ),
            );
            continue;
        };
        if [
            "description",
            "recommendation",
            "affected_tool",
            "affected_resource",
            "affected_resource_uri",
        ]
        .iter()
        .any(|key| object.get(*key) != Some(&Value::Null))
        {
            push_warning(
                warnings,
                format!(
                    "MCP Armor finding at {pointer} carried unsupported detail fields and was not normalized"
                ),
            );
            continue;
        }
        let server = match object.get("affected_server") {
            Some(Value::Null) => None,
            value => mcp_armor_text(value),
        };
        if object.get("affected_server") != Some(&Value::Null) && server.is_none() {
            push_warning(
                warnings,
                format!(
                    "MCP Armor finding at {pointer} lacked a bounded server name and was not normalized"
                ),
            );
            continue;
        }
        let Some(entities) = object.get("affected_entities").and_then(Value::as_object) else {
            push_warning(
                warnings,
                format!(
                    "MCP Armor finding at {pointer} lacked bounded affected entities and was not normalized"
                ),
            );
            continue;
        };

        let mut location_details = Vec::<String>::new();
        let mut identity = format!(
            "{check_id}\0{config_file}\0{}",
            server.as_deref().unwrap_or_default()
        );
        let mut tags = Vec::new();
        if let Some(server) = &server {
            location_details.push(format!("MCP server {server}"));
            tags.push(format!("mcp-server:{}", safe_tag(server)));
        }
        if check_id == "hardcoded_secrets" {
            let Some(secret_type) = mcp_armor_text(entities.get("secret_type")) else {
                push_warning(
                    warnings,
                    format!(
                        "MCP Armor finding at {pointer} lacked a bounded secret type and was not normalized"
                    ),
                );
                continue;
            };
            let Some(line_number) = entities
                .get("line_number")
                .and_then(Value::as_u64)
                .filter(|line| *line > 0)
            else {
                push_warning(
                    warnings,
                    format!(
                        "MCP Armor finding at {pointer} lacked a valid line number and was not normalized"
                    ),
                );
                continue;
            };
            // The upstream report retains a redacted token excerpt. Even that
            // excerpt is unnecessary in the product finding, so validate only
            // that the field exists and leave its bytes in raw evidence.
            if mcp_armor_text(entities.get("matched_text_redacted")).is_none() {
                push_warning(
                    warnings,
                    format!(
                        "MCP Armor finding at {pointer} lacked its redacted match marker and was not normalized"
                    ),
                );
                continue;
            }
            location_details.push(format!("line {line_number}"));
            location_details.push(format!("{secret_type} credential pattern"));
            identity.push_str(&format!("\0{line_number}\0{secret_type}"));
            tags.push(format!("secret-type:{}", safe_tag(&secret_type)));
        } else {
            if server.is_none() {
                push_warning(
                    warnings,
                    format!(
                        "MCP Armor finding at {pointer} lacked a bounded server name and was not normalized"
                    ),
                );
                continue;
            }
            let risky_tools = mcp_armor_optional_string_array(entities.get("risky_tools"));
            let risky_permissions =
                mcp_armor_optional_string_array(entities.get("risky_permissions"));
            let risky_flags = mcp_armor_optional_string_array(entities.get("risky_command_flags"));
            let command = mcp_armor_optional_text(entities.get("risky_command"));
            let disabled = match entities.get("disabled") {
                None | Some(Value::Null) => Some(false),
                Some(Value::Bool(value)) => Some(*value),
                _ => None,
            };
            if risky_tools.is_none()
                || risky_permissions.is_none()
                || risky_flags.is_none()
                || command.is_none()
                || disabled.is_none()
            {
                push_warning(
                    warnings,
                    format!(
                        "MCP Armor finding at {pointer} carried malformed permission evidence and was not normalized"
                    ),
                );
                continue;
            }
            let risky_tools = risky_tools.unwrap_or_default();
            let risky_permissions = risky_permissions.unwrap_or_default();
            let risky_flags = risky_flags.unwrap_or_default();
            let command = command.unwrap_or_default();
            let disabled = disabled.unwrap_or_default();
            if (severity.as_deref() == Some("low")) != disabled {
                push_warning(
                    warnings,
                    format!(
                        "MCP Armor finding at {pointer} did not match its pinned check shape and was not normalized"
                    ),
                );
                continue;
            }
            if risky_tools.is_empty()
                && risky_permissions.is_empty()
                && risky_flags.is_empty()
                && command.is_none()
                && !disabled
            {
                push_warning(
                    warnings,
                    format!(
                        "MCP Armor finding at {pointer} carried no permission evidence and was not normalized"
                    ),
                );
                continue;
            }
            if disabled {
                location_details.push("disabled server".into());
                tags.push("mcp-server-state:disabled".into());
            }
            if let Some(command) = &command {
                location_details.push(format!("command {command}"));
                tags.push(format!("mcp-command:{}", safe_tag(command)));
            }
            for (label, values) in [
                ("tool", &risky_tools),
                ("permission", &risky_permissions),
                ("command-flag", &risky_flags),
            ] {
                if !values.is_empty() {
                    location_details.push(format!("{label}s {}", values.join(", ")));
                    for value in values {
                        tags.push(format!("mcp-{label}:{}", safe_tag(value)));
                    }
                }
            }
            identity.push_str(&format!(
                "\0{}\0{}\0{}\0{}",
                command.unwrap_or_default(),
                risky_tools.join("\0"),
                risky_permissions.join("\0"),
                risky_flags.join("\0")
            ));
        }
        let location = if location_details.is_empty() {
            config_file.clone()
        } else {
            format!("{config_file} ({})", location_details.join(", "))
        };

        let mut record = record!(
            pointer,
            check_id.clone(),
            expected_type.to_owned(),
            severity.unwrap_or_default(),
            location,
            None,
            String::new(),
            Some(derived_confidence(
                ConfidenceBasisCode::DeterministicPolicyEvaluation
            )),
            EvidenceKind::Configuration,
            vec![],
            tags,
        );
        record.family_override = Some(family);
        record.fingerprint_identity = Some(identity);
        *observed_counts.entry(check_id).or_default() += 1;
        records.push(record);
    }

    for (check_id, (_, declared_count)) in &checks {
        if *declared_count != observed_counts.get(check_id).copied().unwrap_or_default() {
            push_warning(
                warnings,
                format!(
                    "MCP Armor check {check_id} finding count did not match its findings; result processing is incomplete"
                ),
            );
        }
    }
    if declared_complete == Some(false) && upstream_warning_count == 0 {
        push_warning(
            warnings,
            "MCP Armor reported incomplete configuration coverage without a usable structured warning",
        );
    }
    if declared_complete == Some(true)
        && (upstream_warning_count != 0
            || input_count != evaluated_input_count
            || checks.len() != MCP_ARMOR_CHECKS.len()
            || checks.values().any(|(status, _)| status != "completed"))
    {
        push_warning(
            warnings,
            "MCP Armor completeness did not agree with its input and check ledger; result processing is incomplete",
        );
    }
    records
}

fn mcp_armor_text(value: Option<&Value>) -> Option<String> {
    let value = value?.as_str()?;
    if value.is_empty()
        || value.trim() != value
        || value.chars().count() > MAX_SHORT_TEXT
        || value.chars().any(char::is_control)
    {
        None
    } else {
        Some(value.to_owned())
    }
}

fn mcp_armor_optional_text(value: Option<&Value>) -> Option<Option<String>> {
    match value {
        None | Some(Value::Null) => Some(None),
        value => mcp_armor_text(value).map(Some),
    }
}

fn mcp_armor_optional_string_array(value: Option<&Value>) -> Option<Vec<String>> {
    let Some(value) = value else {
        return Some(Vec::new());
    };
    if value.is_null() {
        return Some(Vec::new());
    }
    let values = value.as_array()?;
    if values.len() > 32 {
        return None;
    }
    values
        .iter()
        .map(|value| mcp_armor_text(Some(value)))
        .collect()
}

fn json_rows<'a>(
    parsed: &'a ParsedArtifact,
    warnings: &mut Vec<String>,
) -> Vec<(String, &'a Value)> {
    match parsed {
        ParsedArtifact::Json(Value::Array(values)) => {
            if values.len() > MAX_RECORDS {
                push_warning(
                    warnings,
                    "top-level JSON record limit reached; later rows remain only as raw evidence",
                );
            }
            values
                .iter()
                .take(MAX_RECORDS)
                .enumerate()
                .map(|(index, value)| (format!("/{index}"), value))
                .collect()
        }
        ParsedArtifact::Json(value @ Value::Object(_)) => vec![("/".into(), value)],
        ParsedArtifact::Json(_) => {
            push_warning(warnings, "top-level JSON scalar was ignored");
            Vec::new()
        }
        ParsedArtifact::JsonLines(values) => values
            .iter()
            .take(MAX_RECORDS)
            .map(|(line, value)| (format!("line:{line}"), value))
            .collect(),
        ParsedArtifact::Xml(_) => Vec::new(),
    }
}

fn extract_prowler(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let mut records = Vec::new();
    for (pointer, value) in json_rows(parsed, warnings) {
        let Some(object) = value.as_object() else {
            push_warning(
                warnings,
                format!("non-object Prowler record at {pointer} was skipped"),
            );
            continue;
        };
        // Prowler 5.39 OCSF uses status="New" for finding lifecycle state;
        // PASS/FAIL/MANUAL is carried by the top-level status_code field.
        let status = string_any(object, &["status_code", "StatusCode"])
            .or_else(|| string_any(object, &["Status", "status"]))
            .or_else(|| nested_string(value, &["unmapped", "Status"]))
            .or_else(|| nested_string(value, &["unmapped", "status"]));
        if status
            .as_deref()
            .is_some_and(|status| is_pass(status) || status.eq_ignore_ascii_case("manual"))
        {
            continue;
        }
        if !status.as_deref().is_some_and(is_failure) {
            push_warning(
                warnings,
                format!("Prowler record at {pointer} had no explicit failing status"),
            );
            continue;
        }
        let rule = exact_nested_rule_scalar(value, &["metadata", "event_code"])
            .or_else(|| exact_nested_rule_scalar(value, &["finding_info", "analytic", "uid"]))
            .or_else(|| exact_rule_string_any(object, &["CheckID", "check_id"]))
            .or_else(|| exact_nested_rule_scalar(value, &["unmapped", "CheckID"]))
            .or_else(|| exact_nested_rule_scalar(value, &["unmapped", "check_id"]));
        let Some(rule_id) = rule else {
            push_warning(
                warnings,
                format!("Prowler failure at {pointer} lacked a check id"),
            );
            continue;
        };
        // The check title describes the passing condition; the result detail
        // names what actually failed on this resource.
        let title = [
            string_any(object, &["status_detail"]),
            string_any(object, &["StatusExtended"]),
            nested_string(value, &["finding_info", "title"]),
            string_any(object, &["CheckTitle", "check_title"]),
        ]
        .into_iter()
        .flatten()
        .find(|title| !title.is_empty())
        .unwrap_or_else(|| format!("Prowler check {rule_id}"));
        let severity_text = string_any(object, &["Severity", "severity"])
            .or_else(|| nested_string(value, &["unmapped", "Severity"]))
            .unwrap_or_else(|| "unknown".into());
        let location = first_resource_location(value)
            .or_else(|| nested_string(value, &["unmapped", "ResourceId"]))
            .unwrap_or_else(|| "cloud-resource".into());
        let mut record = record_with_derived_confidence!(
            pointer,
            rule_id,
            title,
            severity_text,
            location,
            nested_string(value, &["cloud", "account", "uid"])
                .or_else(|| nested_string(value, &["unmapped", "provider_uid"]))
                .or_else(|| nested_string(value, &["unmapped", "AccountId"])),
            derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
            EvidenceKind::Configuration,
            references_from(value),
            vec!["format:ocsf".into()],
        );
        record.asset_provider = nested_string(value, &["cloud", "provider"])
            .or_else(|| nested_string(value, &["unmapped", "provider"]));
        records.push(with_scanner_details(
            record,
            nested_string(value, &["finding_info", "desc"]),
            nested_string(value, &["remediation", "desc"]),
            None,
            None,
        ));
    }
    records
}

fn extract_scoutsuite(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let mut candidates = Vec::new();
    match parsed {
        ParsedArtifact::Json(root) => {
            if let Some(findings) = root.get("findings") {
                collect_named_objects(findings, "/findings", 0, &mut candidates);
            } else if let Some(services) = root.get("services") {
                collect_named_objects(services, "/services", 0, &mut candidates);
            } else {
                candidates.extend(json_rows(parsed, warnings));
            }
        }
        _ => candidates.extend(json_rows(parsed, warnings)),
    }
    candidates
        .into_iter()
        .filter_map(|(pointer, value)| {
            let object = value.as_object()?;
            let flagged = number_any(object, &["flagged_items", "flaggedItems"])
                .is_some_and(|count| count > 0.0);
            let status = string_any(object, &["status", "result"]);
            if !flagged && !status.as_deref().is_some_and(is_failure) {
                return None;
            }
            // ScoutSuite writes each rule under
            // `services.<service>.findings.<rule key>` and never repeats that
            // key inside the object (`core/processingengine.py`), so for real
            // output the pointer holds the only copy of the rule identity.
            let rule_id = exact_rule_string_any(object, &["id", "rule_id", "key"])
                .or_else(|| scoutsuite_rule_key(&pointer))?;
            let title = string_any(object, &["description", "title", "name"])
                .unwrap_or_else(|| format!("ScoutSuite rule {rule_id}"));
            Some(attach_scoutsuite_benchmarks(
                with_scanner_details(
                    record_with_derived_confidence!(
                        pointer,
                        rule_id,
                        title,
                        string_any(object, &["level", "severity"])
                            .unwrap_or_else(|| "unknown".into()),
                        string_any(object, &["resource", "path", "service"])
                            .unwrap_or_else(|| "cloud-resource".into()),
                        string_any(object, &["account_id", "subscription_id", "project_id"]),
                        derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
                        EvidenceKind::Configuration,
                        references_from(value),
                        vec![],
                    ),
                    string_any(object, &["rationale"]),
                    string_any(object, &["remediation"]),
                    None,
                    None,
                ),
                object,
            ))
        })
        .take(MAX_RECORDS)
        .collect()
}

/// A rule file can cite the same benchmark item under several versions. Eight
/// covers every password-policy compliance list ScoutSuite ships and still
/// bounds untrusted input.
const MAX_SCOUTSUITE_BENCHMARKS: usize = 8;

/// Benchmark items ScoutSuite attached to one rule, cleaned the same way as
/// other short scanner text. Exact duplicates and incomplete entries are
/// dropped. Upstream order is kept.
fn scoutsuite_benchmarks(object: &Map<String, Value>) -> Vec<BenchmarkReference> {
    let Some(entries) = object.get("compliance").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut benchmarks = Vec::new();
    for entry in entries {
        let Some(entry) = entry.as_object() else {
            continue;
        };
        let Some(name) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(version) = entry.get("version").and_then(Value::as_str) else {
            continue;
        };
        let Some(reference) = entry.get("reference").and_then(Value::as_str) else {
            continue;
        };
        let Some(name) = bounded_scanner_detail(Some(name.to_owned()), MAX_SHORT_TEXT) else {
            continue;
        };
        let Some(version) = bounded_scanner_detail(Some(version.to_owned()), MAX_SHORT_TEXT) else {
            continue;
        };
        let Some(reference) = bounded_scanner_detail(Some(reference.to_owned()), MAX_SHORT_TEXT)
        else {
            continue;
        };
        let benchmark = BenchmarkReference {
            name,
            version,
            reference,
        };
        if benchmarks.contains(&benchmark) {
            continue;
        }
        if benchmarks.len() >= MAX_SCOUTSUITE_BENCHMARKS {
            break;
        }
        benchmarks.push(benchmark);
    }
    benchmarks
}

fn attach_scoutsuite_benchmarks(
    mut record: SourceRecord,
    object: &Map<String, Value>,
) -> SourceRecord {
    let benchmarks = scoutsuite_benchmarks(object);
    if benchmarks.is_empty() {
        return record;
    }
    let details = record
        .scanner_details
        .get_or_insert_with(|| ScannerFindingDetails {
            description: None,
            remediation: None,
            installed_version: None,
            fixed_version: None,
            aws_iam_policy: None,
            cwe_ids: Vec::new(),
            cvss: Vec::new(),
            benchmarks: Vec::new(),
            advisory_aliases: Vec::new(),
        });
    details.benchmarks = benchmarks;
    record
}

/// Recover a ScoutSuite rule key from the pointer of the object it names.
///
/// Scoped to the `findings` container ScoutSuite actually writes rules into, so
/// an unrelated nested object cannot be admitted as a rule just because it sits
/// somewhere under `services`.
fn scoutsuite_rule_key(pointer: &str) -> Option<String> {
    let mut segments = pointer.rsplit('/');
    let leaf = segments.next()?;
    if leaf.is_empty() || segments.next()? != "findings" {
        return None;
    }
    Some(leaf.replace("~1", "/").replace("~0", "~"))
}

/// Where Cloudsplaining files policies in `iam-findings-<account>.json`, paired
/// with the typed upstream fact that tells the report whether the account can
/// edit the policy. It is evidence, not an opaque tag or a scanner verdict.
const CLOUDSPLAINING_POLICY_SECTIONS: [(&str, AwsIamPolicySource); 3] = [
    (
        "customer_managed_policies",
        AwsIamPolicySource::CustomerManaged,
    ),
    ("inline_policies", AwsIamPolicySource::Inline),
    ("aws_managed_policies", AwsIamPolicySource::AwsManaged),
];

/// A single policy may be attached throughout a large account. Keep enough
/// names for a useful handoff without letting untrusted output make the report
/// unbounded; the raw artifact retains everything beyond this per-kind limit.
const MAX_CLOUDSPLAINING_PRINCIPALS_PER_KIND: usize = 32;
const MAX_CLOUDSPLAINING_ACTIONS_PER_FINDING: usize = 32;
/// `AttachedTo` appears once per upstream policy but the canonical schema puts
/// actionable context beside each finding. Bound the aggregate string data
/// copied into those records so one policy with many findings cannot multiply
/// a small input into hundreds of megabytes of report state. The complete
/// upstream attachment object remains available in raw evidence.
const MAX_CLOUDSPLAINING_REPEATED_PRINCIPAL_BYTES: usize = 2 * 1024 * 1024;

/// The category keys Cloudsplaining 0.9.1 writes into every policy object.
///
/// Their severity and description are fields in that same upstream object and
/// must be read from the artifact. Repeating those values here would make this
/// adapter a second, independently drifting detector.
const CLOUDSPLAINING_RISKS: [&str; 6] = [
    "PrivilegeEscalation",
    "DataExfiltration",
    "ResourceExposure",
    "ServiceWildcard",
    "CredentialsExposure",
    "InfrastructureModification",
];

/// Admission order when a real account contains more findings than one
/// bounded report can normalize. Unknown precedes Low deliberately: a missing
/// upstream rating needs review and must not be buried under tens of thousands
/// of known-low infrastructure-modification actions.
const CLOUDSPLAINING_SEVERITY_ORDER: [Severity; 6] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Unknown,
    Severity::Low,
    Severity::Informational,
];

struct CloudsplainingEntry<'a> {
    exact_identity: &'a str,
    actions: &'a [Value],
}

struct CloudsplainingPolicyIdentity<'a> {
    exact: &'a str,
    name: String,
    location: String,
    sanitized: bool,
}

fn cloudsplaining_entry<'a>(risk: &str, value: &'a Value) -> Option<CloudsplainingEntry<'a>> {
    if risk == "PrivilegeEscalation" {
        let object = value.as_object()?;
        if object.len() != 2 || !object.contains_key("type") || !object.contains_key("actions") {
            return None;
        }
        let exact_identity = object.get("type")?.as_str()?.trim();
        let actions = object.get("actions")?.as_array()?.as_slice();
        if exact_identity.is_empty() || actions.is_empty() {
            return None;
        }
        if actions
            .iter()
            .any(|action| action.as_str().map(str::trim).is_none_or(str::is_empty))
        {
            return None;
        }
        return Some(CloudsplainingEntry {
            exact_identity,
            actions,
        });
    }

    let exact_identity = value.as_str()?.trim();
    (!exact_identity.is_empty()).then(|| CloudsplainingEntry {
        exact_identity,
        actions: std::slice::from_ref(value),
    })
}

fn cloudsplaining_source_severity(category: &Map<String, Value>) -> Option<&str> {
    category
        .get("severity")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|severity| !severity.is_empty())
}

/// The exact source value remains available for identity and link lookup while
/// this bounded form is safe to persist and render. Both Cloudsplaining passes
/// call this helper so an unusable entry can never consume a report quota.
fn cloudsplaining_bounded_display(exact: &str) -> Option<(String, bool)> {
    let bounded = bounded_scanner_detail(Some(exact.to_owned()), MAX_SHORT_TEXT)?;
    let changed = bounded != exact;
    Some((bounded, changed))
}

fn cloudsplaining_severity_slot(severity: &Severity) -> usize {
    CLOUDSPLAINING_SEVERITY_ORDER
        .iter()
        .position(|candidate| candidate == severity)
        .expect("every canonical severity has an admission slot")
}

fn cloudsplaining_exact_string_any<'a>(
    object: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .filter_map(|key| {
            object
                .get(*key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .next()
}

fn cloudsplaining_policy_identity<'a>(
    policy_key: &'a str,
    policy: &'a Map<String, Value>,
) -> Option<CloudsplainingPolicyIdentity<'a>> {
    let exact = cloudsplaining_exact_string_any(policy, &["Arn", "PolicyId", "PolicyName"])
        .unwrap_or_else(|| policy_key.trim());
    if exact.is_empty() {
        return None;
    }
    let raw_name = cloudsplaining_exact_string_any(policy, &["PolicyName", "PolicyId"])
        .or_else(|| (!policy_key.trim().is_empty()).then(|| policy_key.trim()))
        .unwrap_or(exact);
    let name = bounded_scanner_detail(Some(raw_name.to_owned()), MAX_SHORT_TEXT)?;
    let location = bounded_scanner_detail(Some(exact.to_owned()), MAX_SHORT_TEXT)?;
    Some(CloudsplainingPolicyIdentity {
        exact,
        sanitized: name != raw_name || location != exact,
        name,
        location,
    })
}

fn cloudsplaining_fingerprint_identity(
    section: &str,
    risk: &str,
    exact_policy_identity: &str,
    exact_finding_identity: &str,
) -> String {
    let mut hasher = Sha256::new();
    for component in [
        "ai-security-scanner.cloudsplaining-finding-v1",
        section,
        risk,
        exact_policy_identity,
        exact_finding_identity,
    ] {
        hasher.update(component.as_bytes());
        hasher.update([0]);
    }
    format!(
        "cloudsplaining-instance:sha256:{}",
        hex::encode(hasher.finalize())
    )
}

fn cloudsplaining_attached_to(
    policy: &Map<String, Value>,
    policy_pointer: &str,
    warnings: &mut Vec<String>,
) -> AwsIamAttachedTo {
    let Some(attached) = policy.get("AttachedTo").and_then(Value::as_object) else {
        push_warning(
            warnings,
            format!(
                "Cloudsplaining policy at {policy_pointer} lacked its required AttachedTo object; findings were preserved without complete principal attribution"
            ),
        );
        return AwsIamAttachedTo {
            roles: Vec::new(),
            groups: Vec::new(),
            users: Vec::new(),
            complete: false,
        };
    };

    let mut complete = true;
    let mut read = |kind: &str| {
        let Some(values) = attached.get(kind).and_then(Value::as_array) else {
            complete = false;
            push_warning(
                warnings,
                format!(
                    "Cloudsplaining AttachedTo.{kind} at {policy_pointer}/AttachedTo was not an array; valid principal names were preserved"
                ),
            );
            return Vec::new();
        };
        let mut retained = Vec::new();
        let mut incomplete = values.len() > MAX_CLOUDSPLAINING_PRINCIPALS_PER_KIND;
        for value in values {
            let Some(exact) = value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                incomplete = true;
                continue;
            };
            let Some(bounded) = bounded_scanner_detail(Some(exact.to_owned()), MAX_SHORT_TEXT)
            else {
                incomplete = true;
                continue;
            };
            if bounded != exact {
                incomplete = true;
            }
            if retained.len() < MAX_CLOUDSPLAINING_PRINCIPALS_PER_KIND {
                retained.push(bounded);
            }
        }
        if incomplete {
            complete = false;
            push_warning(
                warnings,
                format!(
                    "Cloudsplaining AttachedTo.{kind} at {policy_pointer}/AttachedTo contained invalid, overlong, or excess entries; bounded valid names were preserved and the remainder stays in raw evidence"
                ),
            );
        }
        retained
    };

    let roles = read("roles");
    let groups = read("groups");
    let users = read("users");
    AwsIamAttachedTo {
        roles,
        groups,
        users,
        complete,
    }
}

fn cloudsplaining_repeated_principal_cost(attached_to: &AwsIamAttachedTo) -> usize {
    attached_to
        .roles
        .iter()
        .chain(&attached_to.groups)
        .chain(&attached_to.users)
        .fold(0_usize, |total, principal| {
            total
                .saturating_add(std::mem::size_of::<String>())
                .saturating_add(principal.len())
        })
}

fn with_aws_iam_policy_details(
    mut record: SourceRecord,
    details: AwsIamPolicyFindingDetails,
) -> SourceRecord {
    match &mut record.scanner_details {
        Some(scanner_details) => scanner_details.aws_iam_policy = Some(details),
        None => {
            record.scanner_details = Some(ScannerFindingDetails {
                description: None,
                remediation: None,
                installed_version: None,
                fixed_version: None,
                aws_iam_policy: Some(details),
                cwe_ids: Vec::new(),
                cvss: Vec::new(),
                benchmarks: Vec::new(),
                advisory_aliases: Vec::new(),
            });
        }
    }
    record
}

/// Read Cloudsplaining's IAM findings document.
///
/// The artifact is `authorization_details.results` (`command/scan.py`). Each
/// risk category inside a policy is an object containing the upstream
/// `severity`, `description`, and `findings` array. Privilege-escalation
/// findings are `{type, actions}` objects; the other current categories carry
/// action strings. Each entry remains a separate finding and points back to its
/// exact raw JSON location.
fn extract_cloudsplaining(
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed).and_then(Value::as_object) else {
        push_warning(
            warnings,
            "Cloudsplaining results were not a single JSON object, so no policy findings could be read.",
        );
        return Vec::new();
    };
    let root_links = match root.get("links") {
        Some(Value::Object(links)) => Some(links),
        Some(_) => {
            push_warning(
                warnings,
                "Cloudsplaining output links were not an object; findings were preserved without those references",
            );
            None
        }
        None => {
            push_warning(
                warnings,
                "Cloudsplaining output lacked its required links object; findings were preserved without those references",
            );
            None
        }
    };

    // First pass: validate the entire pinned document and count only entries
    // whose category-specific upstream shape is intact. Counting is bounded
    // constant memory, so a huge early Low category cannot prevent a later
    // High or Unknown category from being considered for admission.
    let mut severity_counts = [0_usize; 6];
    for (section, _) in CLOUDSPLAINING_POLICY_SECTIONS {
        let policies = match root.get(section) {
            Some(Value::Object(policies)) => policies,
            Some(_) => {
                push_warning(
                    warnings,
                    format!(
                        "Cloudsplaining policy section {section} was not an object; valid sibling findings were preserved"
                    ),
                );
                continue;
            }
            None => {
                push_warning(
                    warnings,
                    format!(
                        "Cloudsplaining output lacked required policy section {section}; valid sibling findings were preserved"
                    ),
                );
                continue;
            }
        };
        for (policy_key, policy) in policies {
            let escaped_policy = policy_key.replace('~', "~0").replace('/', "~1");
            let policy_pointer = format!("/{section}/{escaped_policy}");
            let Some(policy) = policy.as_object() else {
                push_warning(
                    warnings,
                    format!(
                        "Cloudsplaining policy at {policy_pointer} was not an object; valid sibling findings were preserved"
                    ),
                );
                continue;
            };
            // Cloudsplaining already applied the operator's exclusions file;
            // re-reporting what it excluded would overrule the tool's own call.
            // Absence is not equivalent to false: the adapter cannot know
            // whether a malformed policy was intentionally excluded.
            match policy.get("is_excluded").and_then(Value::as_bool) {
                Some(true) => continue,
                Some(false) => {}
                None => {
                    push_warning(
                        warnings,
                        format!(
                            "Cloudsplaining policy at {policy_pointer} did not carry its required boolean is_excluded value and was retained only as raw evidence"
                        ),
                    );
                    continue;
                }
            }
            let Some(identity) = cloudsplaining_policy_identity(policy_key, policy) else {
                push_warning(
                    warnings,
                    format!(
                        "Cloudsplaining policy at {policy_pointer} had no bounded nonempty identity or name and was retained only as raw evidence"
                    ),
                );
                continue;
            };
            if identity.sanitized {
                push_warning(
                    warnings,
                    format!(
                        "Cloudsplaining policy identity at {policy_pointer} contained control characters or exceeded its presentation boundary; a bounded display value was preserved"
                    ),
                );
            }
            for risk in CLOUDSPLAINING_RISKS {
                let category_pointer = format!("{policy_pointer}/{risk}");
                let category = match policy.get(risk) {
                    Some(Value::Object(category)) => category,
                    Some(_) => {
                        push_warning(
                            warnings,
                            format!(
                                "Cloudsplaining category at {category_pointer} was not an object; valid sibling findings were preserved"
                            ),
                        );
                        continue;
                    }
                    None => {
                        push_warning(
                            warnings,
                            format!(
                                "Cloudsplaining policy at {policy_pointer} lacked category {risk}; valid sibling findings were preserved"
                            ),
                        );
                        continue;
                    }
                };

                let Some(entries) = category.get("findings").and_then(Value::as_array) else {
                    push_warning(
                        warnings,
                        format!(
                            "Cloudsplaining category at {category_pointer} lacked its findings array; valid sibling findings were preserved"
                        ),
                    );
                    continue;
                };
                let source_severity = cloudsplaining_source_severity(category);
                if source_severity.is_none() {
                    push_warning(
                        warnings,
                        format!(
                            "Cloudsplaining category at {category_pointer} lacked its source severity; valid sibling findings were preserved"
                        ),
                    );
                }
                match category.get("description") {
                    Some(Value::String(_)) => {}
                    Some(_) | None => {
                        push_warning(
                            warnings,
                            format!(
                                "Cloudsplaining category at {category_pointer} lacked its source description; findings were preserved without it"
                            ),
                        );
                    }
                }
                let category_links = match (risk, category.get("links")) {
                    ("PrivilegeEscalation", Some(Value::Object(links))) => Some(links),
                    ("PrivilegeEscalation", _) => {
                        push_warning(
                            warnings,
                            format!(
                                "Cloudsplaining PrivilegeEscalation category at {category_pointer} lacked its required links object; findings were preserved without those references"
                            ),
                        );
                        None
                    }
                    (_, Some(Value::Object(links))) => Some(links),
                    (_, Some(_)) => {
                        push_warning(
                            warnings,
                            format!(
                                "Cloudsplaining category links at {category_pointer}/links were not an object; findings were preserved without those references"
                            ),
                        );
                        None
                    }
                    (_, None) => None,
                };

                for (entry_index, entry) in entries.iter().enumerate() {
                    let entry_pointer = format!("{category_pointer}/findings/{entry_index}");
                    let Some(entry) = cloudsplaining_entry(risk, entry) else {
                        push_warning(
                            warnings,
                            format!(
                                "Cloudsplaining finding at {entry_pointer} did not match the pinned {risk} entry shape and was retained only as raw evidence"
                            ),
                        );
                        continue;
                    };
                    let Some((_, identity_sanitized)) =
                        cloudsplaining_bounded_display(entry.exact_identity)
                    else {
                        push_warning(
                            warnings,
                            format!(
                                "Cloudsplaining finding at {entry_pointer} had no bounded nonempty identity and was retained only as raw evidence"
                            ),
                        );
                        continue;
                    };
                    if identity_sanitized {
                        push_warning(
                            warnings,
                            format!(
                                "Cloudsplaining finding identity at {entry_pointer} contained control characters or exceeded its presentation boundary; a bounded display value was preserved"
                            ),
                        );
                    }
                    if risk == "PrivilegeEscalation"
                        && !category_links.is_some_and(|links| {
                            links
                                .get(entry.exact_identity)
                                .and_then(Value::as_str)
                                .is_some_and(|link| !link.trim().is_empty())
                        })
                    {
                        push_warning(
                            warnings,
                            format!(
                                "Cloudsplaining privilege-escalation finding at {entry_pointer} lacked its required method link; the finding was preserved without that reference"
                            ),
                        );
                    }
                    if let Some(links) = root_links {
                        for action in entry
                            .actions
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::trim)
                        {
                            if links.get(action).is_some_and(|link| {
                                !matches!(link, Value::Null | Value::String(_))
                                    || link.as_str().is_some_and(|link| link.trim().is_empty())
                            }) {
                                push_warning(
                                    warnings,
                                    format!(
                                        "Cloudsplaining action link for {} was malformed; the finding was preserved without that reference",
                                        safe_text(action, 160)
                                    ),
                                );
                            }
                        }
                    }
                    let severity = source_severity
                        .map(parse_severity)
                        .unwrap_or(Severity::Unknown);
                    let slot = cloudsplaining_severity_slot(&severity);
                    severity_counts[slot] = severity_counts[slot].saturating_add(1);
                }
            }
        }
    }

    let total_findings = severity_counts
        .iter()
        .copied()
        .fold(0_usize, usize::saturating_add);
    let mut severity_quotas = [0_usize; 6];
    let mut remaining = MAX_RECORDS;
    for slot in 0..severity_quotas.len() {
        severity_quotas[slot] = severity_counts[slot].min(remaining);
        remaining -= severity_quotas[slot];
    }
    if total_findings > MAX_RECORDS {
        let retained_findings = MAX_RECORDS;
        let omitted_findings = total_findings - MAX_RECORDS;
        push_priority_warning(
            warnings,
            format!(
                "Cloudsplaining reported {total_findings} valid policy findings; the bounded report retained {retained_findings} in Critical, High, Medium, Unknown, Low, then Informational order, and {omitted_findings} remain only in raw evidence"
            ),
        );
    }

    // Second pass: create at most MAX_RECORDS records using the quotas above.
    // Walk severity first so both finding admission and the repeated-principal
    // context budget preserve the most important results before lower-rated
    // ones. Source document order matters only within one severity.
    let mut emitted = [0_usize; 6];
    let mut records = Vec::with_capacity(total_findings.min(MAX_RECORDS));
    let mut repeated_principal_bytes = 0_usize;
    let mut repeated_principal_limit_warned = false;
    let mut attached_to_by_policy = BTreeMap::<String, AwsIamAttachedTo>::new();
    for admission_slot in 0..CLOUDSPLAINING_SEVERITY_ORDER.len() {
        for (section, policy_source) in CLOUDSPLAINING_POLICY_SECTIONS {
            let Some(policies) = root.get(section).and_then(Value::as_object) else {
                continue;
            };
            for (policy_key, policy) in policies {
                let Some(policy) = policy.as_object() else {
                    continue;
                };
                if policy.get("is_excluded").and_then(Value::as_bool) != Some(false) {
                    continue;
                }
                let escaped_policy = policy_key.replace('~', "~0").replace('/', "~1");
                let policy_pointer = format!("/{section}/{escaped_policy}");
                let Some(policy_identity) = cloudsplaining_policy_identity(policy_key, policy)
                else {
                    continue;
                };
                let exact_policy_identity = policy_identity.exact;
                let policy_name = policy_identity.name;
                let policy_location = policy_identity.location;
                for risk in CLOUDSPLAINING_RISKS {
                    let Some(category) = policy.get(risk).and_then(Value::as_object) else {
                        continue;
                    };
                    let Some(entries) = category.get("findings").and_then(Value::as_array) else {
                        continue;
                    };
                    let source_severity = cloudsplaining_source_severity(category);
                    let severity = source_severity
                        .map(parse_severity)
                        .unwrap_or(Severity::Unknown);
                    let slot = cloudsplaining_severity_slot(&severity);
                    if slot != admission_slot || emitted[slot] >= severity_quotas[slot] {
                        continue;
                    }
                    let category_pointer = format!("{policy_pointer}/{risk}");
                    let description = bounded_scanner_detail(
                        category
                            .get("description")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        MAX_LONG_TEXT,
                    );
                    let category_links = category.get("links").and_then(Value::as_object);

                    for (entry_index, value) in entries.iter().enumerate() {
                        if emitted[slot] >= severity_quotas[slot] {
                            break;
                        }
                        let Some(entry) = cloudsplaining_entry(risk, value) else {
                            continue;
                        };
                        let entry_pointer = format!("{category_pointer}/findings/{entry_index}");
                        let Some((display_identity, _)) =
                            cloudsplaining_bounded_display(entry.exact_identity)
                        else {
                            continue;
                        };
                        // Increment only after the same display-admissibility check
                        // used by the counting pass. Otherwise a malformed early
                        // identity could hide a valid later finding of this rating.
                        emitted[slot] += 1;
                        let mut references = Vec::new();
                        if risk == "PrivilegeEscalation"
                            && let Some(link) = category_links
                                .and_then(|links| links.get(entry.exact_identity))
                                .and_then(Value::as_str)
                                .map(str::trim)
                                .filter(|link| !link.is_empty())
                        {
                            references.push(link.to_owned());
                        }
                        if let Some(links) = root_links {
                            references.extend(
                                entry
                                    .actions
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .filter_map(|action| {
                                        links
                                            .get(action.trim())
                                            .and_then(Value::as_str)
                                            .map(str::trim)
                                            .filter(|link| !link.is_empty())
                                            .map(str::to_owned)
                                    })
                                    .take(12_usize.saturating_sub(references.len())),
                            );
                        }
                        references.sort();
                        references.dedup();

                        let mut actions = Vec::new();
                        let mut actions_complete =
                            entry.actions.len() <= MAX_CLOUDSPLAINING_ACTIONS_PER_FINDING;
                        for exact in entry
                            .actions
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::trim)
                        {
                            if actions.len() >= MAX_CLOUDSPLAINING_ACTIONS_PER_FINDING {
                                actions_complete = false;
                                continue;
                            }
                            let Some((bounded, changed)) = cloudsplaining_bounded_display(exact)
                            else {
                                actions_complete = false;
                                continue;
                            };
                            actions_complete &= !changed;
                            actions.push(bounded);
                        }
                        if !actions_complete {
                            push_warning(
                                warnings,
                                format!(
                                    "Cloudsplaining finding actions at {entry_pointer} contained sanitized or excess values; bounded valid actions were preserved and the complete list stays in raw evidence"
                                ),
                            );
                        }
                        // Attachment metadata is parsed only when this policy has
                        // an admitted finding. Cache it across severity passes so
                        // malformed metadata is disclosed once and clean policies
                        // with no findings do not become Partial.
                        let policy_attached_to = attached_to_by_policy
                            .entry(policy_pointer.clone())
                            .or_insert_with(|| {
                                cloudsplaining_attached_to(policy, &policy_pointer, warnings)
                            });
                        let principal_cost =
                            cloudsplaining_repeated_principal_cost(policy_attached_to);
                        let attached_to = if principal_cost == 0
                            || repeated_principal_bytes
                                .checked_add(principal_cost)
                                .is_some_and(|total| {
                                    total <= MAX_CLOUDSPLAINING_REPEATED_PRINCIPAL_BYTES
                                }) {
                            repeated_principal_bytes =
                                repeated_principal_bytes.saturating_add(principal_cost);
                            policy_attached_to.clone()
                        } else {
                            if !repeated_principal_limit_warned {
                                push_priority_warning(
                                    warnings,
                                    "Cloudsplaining principal context exceeded the bounded report budget; later findings retain policy and action details, while their complete AttachedTo values stay in raw evidence",
                                );
                                repeated_principal_limit_warned = true;
                            }
                            AwsIamAttachedTo {
                                roles: Vec::new(),
                                groups: Vec::new(),
                                users: Vec::new(),
                                complete: false,
                            }
                        };
                        let mut record = with_aws_iam_policy_details(
                            with_scanner_details(
                                record_with_severity_fallback_and_derived_confidence!(
                                    entry_pointer,
                                    risk.to_owned(),
                                    format!("{risk}: {display_identity} in policy {policy_name}"),
                                    source_severity.unwrap_or_default().to_owned(),
                                    DerivedSeverity {
                                        severity: Severity::Unknown,
                                        code: SeverityBasisCode::CloudsplainingIamPolicyFinding,
                                    },
                                    format!("{policy_location} :: {display_identity}"),
                                    // The document has no canonical top-level account
                                    // identifier shared by every policy (AWS-managed
                                    // ARNs carry no customer account). A policy ARN is
                                    // the finding location, not an authorized asset ID.
                                    None,
                                    derived_confidence(
                                        ConfidenceBasisCode::DeterministicPolicyEvaluation
                                    ),
                                    EvidenceKind::Configuration,
                                    references,
                                    vec![],
                                ),
                                description.clone(),
                                None,
                                None,
                                None,
                            ),
                            AwsIamPolicyFindingDetails {
                                policy_source,
                                policy_name: policy_name.clone(),
                                finding_identity: display_identity.clone(),
                                actions,
                                actions_complete,
                                attached_to,
                            },
                        );
                        record.fingerprint_identity = Some(cloudsplaining_fingerprint_identity(
                            section,
                            risk,
                            exact_policy_identity,
                            entry.exact_identity,
                        ));
                        records.push(record);
                    }
                }
            }
        }
    }
    records
}

fn extract_scubagear(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    extract_m365(
        parsed,
        warnings,
        "ScubaGear",
        &["PolicyId", "ControlId", "id"],
        &["Result", "status"],
        &["SourceCriticality", "Criticality"],
        "source-criticality",
    )
    .records
}

fn extract_maester(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> M365Extraction {
    extract_m365(
        parsed,
        warnings,
        "Maester",
        &["Id", "TestId", "id"],
        &["Result", "Outcome", "status"],
        &["SourceSeverity"],
        "source-rating",
    )
}

/// The sentence around the counted shortfall `unevaluated_controls` discloses.
/// The report reads it back with `disclosed_unevaluated_controls`, so both
/// directions share these two pieces.
const UNEVALUATED_CONTROLS_FRAME: (&str, &str) = (
    " did not evaluate every control in scope (",
    "); those controls are absent from findings and this run does not establish their state",
);

/// The engine and the counted items of a disclosure `unevaluated_controls`
/// wrote, or `None` for any other warning.
///
/// The disclosure is stored as a run warning, which only Progress shows. The
/// report reads it so that a tenant check with no findings does not read as a
/// clean tenant while controls in its scope went unevaluated.
pub(crate) fn disclosed_unevaluated_controls(warning: &str) -> Option<(&str, Vec<&str>)> {
    let (engine, rest) = warning.split_once(UNEVALUATED_CONTROLS_FRAME.0)?;
    let items = rest.strip_suffix(UNEVALUATED_CONTROLS_FRAME.1)?;
    if engine.is_empty() || items.is_empty() {
        return None;
    }
    Some((engine, items.split(", ").collect()))
}

/// What a scanner run left unevaluated, and whether that shortfall is
/// severe enough that the run must not claim completion.
struct UnevaluatedControls {
    disclosure: String,
    /// True when the engine was asked to check controls and could not, as
    /// opposed to passing over them by design or by tenant configuration. Such
    /// a run produced usable findings but did not establish coverage, which is
    /// exactly what `AdapterOutput::complete` exists to say.
    withholds_completion: bool,
}

/// Controls left without a verdict, phrased for the person reading the run.
/// kube-bench exposes WARN directly; Microsoft 365 wrappers expose counters.
///
/// Both wrappers drop any control whose upstream status they do not map
/// (`run-scubagear.ps1:126`, `run-maester.ps1:123`), and they record what they
/// dropped in `Diagnostics`. Nothing read it, so a tenant with twenty controls
/// reserved for manual review and five omitted by configuration rendered as an
/// unqualified list of findings.
///
/// The two kinds of shortfall are not equivalent. A control reserved for manual
/// review or omitted in the tenant's own config was passed over deliberately, so
/// the run is still a complete scan of what it set out to check. A control the
/// engine *could not evaluate* means coverage was never established, and
/// upstream is explicit that this is what its error counter means: a missing
/// provider command becomes an error. Only the second withholds completion.
fn unevaluated_controls(profile: Profile, parsed: &ParsedArtifact) -> Option<UnevaluatedControls> {
    if profile == Profile::KubeBench {
        let root = json_root(parsed)?;
        let controls = root
            .get("Controls")
            .or_else(|| root.get("controls"))?
            .as_array()?;
        let count = controls
            .iter()
            .filter_map(|control| control.get("tests").and_then(Value::as_array))
            .flatten()
            .filter_map(|test| test.get("results").and_then(Value::as_array))
            .flatten()
            .filter(|result| {
                result
                    .get("status")
                    .and_then(Value::as_str)
                    .is_some_and(|status| status.eq_ignore_ascii_case("WARN"))
            })
            .count();
        return (count > 0).then(|| UnevaluatedControls {
            disclosure: format!(
                "kube-bench{}{count} left without an automated verdict{}",
                UNEVALUATED_CONTROLS_FRAME.0, UNEVALUATED_CONTROLS_FRAME.1
            ),
            // WARN covers both manual checks and checks that could not run.
            // Status alone cannot establish which checks actually completed.
            withholds_completion: true,
        });
    }
    // `Diagnostics` counters for controls the wrapper did not represent, paired
    // with how to say each one out loud. `by_design` was a deliberate pass;
    // `unevaluable` means the engine tried and could not.
    let (engine, by_design, unevaluable) = match profile {
        Profile::ScubaGear => (
            "ScubaGear",
            [
                ("manual", "left without an automated verdict"),
                ("omitted", "omitted by configuration"),
            ]
            .as_slice(),
            [("errors", "could not be evaluated")].as_slice(),
        ),
        Profile::Maester => (
            "Maester",
            [("skipped", "skipped"), ("not_run", "not run")].as_slice(),
            [("errors", "could not be evaluated")].as_slice(),
        ),
        _ => return None,
    };
    let ParsedArtifact::Json(root) = parsed else {
        return None;
    };
    let diagnostics = root.get("Diagnostics")?.as_object()?;
    let count_of = |group: &[(&str, &str)]| {
        group
            .iter()
            .filter_map(|(key, description)| {
                let count = diagnostics.get(*key)?.as_u64().filter(|count| *count > 0)?;
                Some(format!("{count} {description}"))
            })
            .collect::<Vec<_>>()
    };
    let passed_over = count_of(by_design);
    let could_not_evaluate = count_of(unevaluable);
    let lost = normalization_shortfall(profile, diagnostics);
    if passed_over.is_empty() && could_not_evaluate.is_empty() && lost.is_empty() {
        return None;
    }
    let all = passed_over
        .iter()
        .chain(could_not_evaluate.iter())
        .chain(lost.iter())
        .cloned()
        .collect::<Vec<_>>();
    Some(UnevaluatedControls {
        disclosure: format!(
            "{engine}{}{}{}",
            UNEVALUATED_CONTROLS_FRAME.0,
            all.join(", "),
            UNEVALUATED_CONTROLS_FRAME.1
        ),
        // Losing verdicts is not a smaller problem than failing to produce
        // them: either way the run does not establish those controls' state.
        withholds_completion: !could_not_evaluate.is_empty() || !lost.is_empty(),
    })
}

/// How many verdicts the engine reported that the wrapper did not carry across.
///
/// `Diagnostics.normalized_results` is the wrapper's count of the list it just
/// built, so checking it against `Results.len()` is true by construction — it
/// stays true when the wrapper's verdict `switch` matched nothing and silently
/// dropped every control. These counters come from the engine itself, so they
/// are the independent number. Without them, an upstream rename of `Passed` to
/// `Success` produces a clean, confident, completely empty tenant audit.
fn normalization_shortfall(
    profile: Profile,
    diagnostics: &serde_json::Map<String, Value>,
) -> Vec<String> {
    let count = |key: &str| {
        diagnostics
            .get(key)
            .and_then(Value::as_u64)
            .unwrap_or_default()
    };
    // Only the verdicts each wrapper actually converts into a result row. The
    // by-design and unevaluable counters are disclosed separately above.
    //
    // Deliberately a lower bound. A ScubaGear control the tenant disputed is
    // judged on `OriginalResult` and counted in `disputed` rather than
    // `failures`, so it can add a row no verdict counter accounts for -- it can
    // only push `normalized` above this floor, never below it.
    let carried = match profile {
        // `Passed`, `Failed`, and `Investigate` all become rows.
        Profile::Maester => count("passes") + count("failures") + count("investigate"),
        // `Pass`, `Fail`, and `Warning` become rows.
        Profile::ScubaGear => count("passes") + count("failures") + count("warnings"),
        _ => return Vec::new(),
    };
    let mut shortfalls = Vec::new();
    if matches!(profile, Profile::Maester) {
        // Inferred from `run-maester.ps1`: `total` is the upstream test count,
        // while these are every category the wrapper reports. A positive
        // remainder therefore names controls the wrapper accounted for under
        // no category at all. Those controls were in scope but their state is
        // unknown, so, like a verdict lost during normalization, they withhold
        // completion. Saturation matters because upstream counters may overlap;
        // a counter surplus is not evidence that the wrapper dropped controls.
        if let Some(total) = diagnostics.get("total").and_then(Value::as_u64) {
            let accounted = [
                "passes",
                "failures",
                "investigate",
                "errors",
                "skipped",
                "not_run",
            ]
            .into_iter()
            .fold(0_u64, |sum, key| sum.saturating_add(count(key)));
            let uncategorized = total.saturating_sub(accounted);
            if uncategorized > 0 {
                shortfalls.push(format!(
                    "{uncategorized} not accounted for by any reported category"
                ));
            }
        }
    }
    let normalized = diagnostics
        .get("normalized_results")
        .and_then(Value::as_u64);
    if let Some(normalized) = normalized
        && normalized < carried
    {
        let lost = carried - normalized;
        shortfalls.push(format!(
            "{lost} reported by the engine but not carried into results"
        ));
    }
    shortfalls
}

/// Controls whose result the audited tenant's own configuration declares wrong.
///
/// ScubaGear rewrites such a control's `Result` to the sentinel `Incorrect
/// result`, keeps its real determination in `OriginalResult`, and counts it in
/// `IncorrectResults` rather than `Failures` (CreateReport.psm1:331, :342, :348).
/// A tenant could therefore erase a genuine failure from its own audit and leave
/// no finding and no counter behind. The wrapper now judges these on ScubaGear's
/// verdict, so they are not a coverage gap and must not be reported as one — but
/// the dispute is still material to whoever reads the run, so it is said plainly
/// here and marked on each affected finding by `extract_m365`.
fn tenant_disputed_controls(profile: Profile, parsed: &ParsedArtifact) -> Option<String> {
    if !matches!(profile, Profile::ScubaGear) {
        return None;
    }
    let ParsedArtifact::Json(root) = parsed else {
        return None;
    };
    let disputed = root
        .pointer("/Diagnostics/disputed")
        .and_then(Value::as_u64)
        .filter(|count| *count > 0)?;
    let controls = if disputed == 1 { "control" } else { "controls" };
    Some(format!(
        "the tenant's ScubaGear configuration disputes the result of {disputed} {controls}; they are reported on ScubaGear's own determination and tagged tenant-disputed rather than suppressed"
    ))
}

fn extract_m365(
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
    engine: &str,
    rule_keys: &[&str],
    status_keys: &[&str],
    source_rating_keys: &[&str],
    source_rating_tag: &str,
) -> M365Extraction {
    let capture_investigate = engine == "Maester";
    let mut candidates = Vec::new();
    // Whether the candidates came from a wrapper's declared `Results` list. Every
    // member of such a list is a control the wrapper says it normalized, so one
    // that cannot become a finding is a loss worth naming. Rows recovered from a
    // tabular artifact carry no such promise and are skipped quietly.
    let mut declared_envelope = false;
    match parsed {
        ParsedArtifact::Json(root) => {
            declared_envelope = true;
            // The wrapper owns this document: it names the engine that wrote it
            // and lists every control it normalized under `Results`. Walking the
            // whole tree instead would let any object that happens to carry a
            // status and a rule id become a finding, including one nested inside
            // provenance or a vendor blob the wrapper merely quoted.
            match root.get("Engine").and_then(Value::as_str) {
                Some(declared) if declared.eq_ignore_ascii_case(engine) => {}
                Some(declared) => {
                    push_warning(
                        warnings,
                        format!(
                            "{engine} adapter input mismatch: document declares engine {declared}"
                        ),
                    );
                    return M365Extraction {
                        records: Vec::new(),
                        manual_review_candidates: Vec::new(),
                    };
                }
                // Checking the envelope only when it happens to be present would
                // let a malformed or future-schema document skip every check
                // below and still read as a clean run. Its results are kept,
                // because they are probably real, but the run cannot claim to
                // have accounted for a document it could not identify.
                None => push_warning(
                    warnings,
                    format!(
                        "{engine} document did not name the engine that wrote it; it was normalized but not verified as this engine's own output"
                    ),
                ),
            }
            let Some(results) = root.get("Results").and_then(Value::as_array) else {
                push_warning(
                    warnings,
                    format!("{engine} document declared no Results list and was not normalized"),
                );
                return M365Extraction {
                    records: Vec::new(),
                    manual_review_candidates: Vec::new(),
                };
            };
            // The wrapper counts what it wrote. A disagreement means results were
            // lost between writing and reading, which no rule-level check sees.
            match root
                .pointer("/Diagnostics/normalized_results")
                .and_then(Value::as_u64)
            {
                Some(declared) if declared == results.len() as u64 => {}
                Some(declared) => push_warning(
                    warnings,
                    format!(
                        "{engine} reported writing {declared} normalized results but its Results list holds {}",
                        results.len()
                    ),
                ),
                None => push_warning(
                    warnings,
                    format!(
                        "{engine} document did not declare how many results it normalized, so nothing can confirm none were lost"
                    ),
                ),
            }
            candidates.extend(
                results
                    .iter()
                    .enumerate()
                    .map(|(index, value)| (format!("/Results/{index}"), value)),
            );
        }
        _ => candidates.extend(json_rows(parsed, warnings)),
    }
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    let mut manual_review_candidates = Vec::new();
    for (pointer, value) in candidates {
        let Some(object) = value.as_object() else {
            if declared_envelope {
                push_warning(
                    warnings,
                    format!(
                        "{engine} listed a result at {pointer} that is not an object; it was not normalized"
                    ),
                );
            }
            continue;
        };
        let Some(status) = string_any(object, status_keys) else {
            if declared_envelope {
                push_warning(
                    warnings,
                    format!(
                        "{engine} result at {pointer} carried no recognizable status; it was not normalized"
                    ),
                );
            }
            continue;
        };
        let is_manual_review = capture_investigate && status.eq_ignore_ascii_case("investigate");
        if !is_manual_review && !is_failure(&status) {
            continue;
        }
        let Some(rule_id) = exact_rule_string_any(object, rule_keys) else {
            push_warning(
                warnings,
                format!("{engine} evaluated result at {pointer} lacked a rule id"),
            );
            continue;
        };
        let display_rule_id = safe_text(&rule_id, MAX_SHORT_TEXT);
        if display_rule_id.is_empty() {
            push_warning(
                warnings,
                format!("{engine} evaluated result at {pointer} lacked a usable rule id"),
            );
            continue;
        }
        let dedup = format!("{rule_id}:{pointer}");
        if !seen.insert(dedup) {
            continue;
        }
        if is_manual_review {
            let detail = object
                .get("ReviewDetail")
                .and_then(Value::as_str)
                .map(|detail| safe_text(detail, MAX_MANUAL_REVIEW_DETAIL))
                .filter(|detail| !detail.is_empty());
            let title = string_any(object, &["Name", "Title", "Requirement", "Description"])
                .map(|title| safe_text(&title, MAX_SHORT_TEXT))
                .filter(|title| !title.is_empty())
                .unwrap_or_else(|| format!("{engine} control {display_rule_id}"));
            manual_review_candidates.push(ManualReviewCandidate {
                rule_id: display_rule_id,
                title,
                detail,
                asset_hint: string_any(object, &["asset_id", "AssetId"]),
            });
            if records.len().saturating_add(manual_review_candidates.len()) >= MAX_RECORDS {
                break;
            }
            continue;
        }
        let source_rating = string_any(object, source_rating_keys);
        let mut tags = source_rating
            .as_deref()
            .filter(|rating| !rating.is_empty())
            .map(|rating| vec![format!("{source_rating_tag}:{}", safe_tag(rating))])
            .unwrap_or_default();
        // The wrapper leaves the upstream status in `SourceResult` and judges the
        // verdict elsewhere when the tenant disputed the result. Carrying the
        // dispute onto the finding is the difference between reporting it and
        // quietly honouring it; the run-level note alone would not say which
        // control was disputed.
        if string_any(object, &["SourceResult"])
            .is_some_and(|source| source.eq_ignore_ascii_case("incorrect result"))
        {
            tags.push("tenant-disputed".into());
        }
        records.push(record_with_derived_confidence!(
            pointer,
            rule_id.clone(),
            string_any(object, &["Name", "Title", "Requirement", "Description"])
                .unwrap_or_else(|| format!("{engine} control {rule_id}")),
            string_any(object, &["Severity", "severity"]).unwrap_or_else(|| "unknown".into()),
            string_any(object, &["Service", "Product", "Resource", "TenantId"])
                .unwrap_or_else(|| "microsoft-365-tenant".into()),
            string_any(object, &["asset_id", "AssetId"]),
            derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
            EvidenceKind::Configuration,
            references_from(value),
            tags,
        ));
        if records.len() >= MAX_RECORDS {
            break;
        }
    }
    M365Extraction {
        records,
        manual_review_candidates,
    }
}

fn extract_nuclei(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> NucleiExtraction {
    let mut records = Vec::new();
    let mut execution_counts = BTreeMap::<String, usize>::new();
    for (pointer, value) in json_rows(parsed, warnings) {
        let Some(object) = value.as_object() else {
            push_warning(
                warnings,
                format!(
                    "Nuclei record at {pointer} was not an object; retry with the supported pinned JSONL output"
                ),
            );
            continue;
        };
        // Upstream Nuclei uses `matcher-status: false` for a template that
        // executed but did not match. Automatic technology detection writes
        // matches directly and never writes failures, so an error-free false
        // record proves that the final applicable security-template phase ran.
        if object.get("matcher-status") == Some(&Value::Bool(false)) {
            let has_error = object.get("error").is_some_and(|error| match error {
                Value::Null => false,
                Value::String(value) => !value.trim().is_empty(),
                _ => true,
            });
            if has_error {
                continue;
            }
            let template_id =
                exact_rule_string_any(object, &["template-id", "template_id", "templateID"])
                    .and_then(|value| exact_mapping_source_rule(&value));
            let asset_hint = exact_rule_string_any(object, &["asset_id"])
                .and_then(|value| exact_mapping_source_rule(&value));
            if template_id.is_none() || asset_hint.is_none() {
                push_warning(
                    warnings,
                    format!(
                        "Nuclei non-match at {pointer} lacked a bounded template or normalized asset id; it was not accepted as execution evidence"
                    ),
                );
                continue;
            }
            let count = execution_counts
                .entry(asset_hint.expect("checked above"))
                .or_default();
            *count = count.saturating_add(1);
            continue;
        }
        if object.contains_key("matcher-status")
            && object.get("matcher-status") != Some(&Value::Bool(true))
        {
            push_warning(
                warnings,
                format!(
                    "Nuclei record at {pointer} had a malformed matcher status and was not normalized"
                ),
            );
            continue;
        }
        let Some(rule_id) =
            exact_rule_string_any(object, &["template-id", "template_id", "templateID"])
        else {
            push_warning(
                warnings,
                format!(
                    "Nuclei record at {pointer} lacked its template id; the raw record was retained, and the scan should be retried with the supported pinned JSONL output"
                ),
            );
            continue;
        };
        let title = nested_string(value, &["info", "name"])
            .unwrap_or_else(|| format!("Nuclei template {rule_id}"));
        let severity = nested_string(value, &["info", "severity"])
            .or_else(|| string_any(object, &["severity"]))
            .unwrap_or_else(|| "unknown".into());
        let target = string_any(object, &["matched-at", "matched_at", "host", "url"])
            .unwrap_or_else(|| "authorized-target".into());
        let mut tags = nested_strings(value, &["info", "tags"])
            .into_iter()
            .map(|tag| format!("template-tag:{}", safe_tag(&tag)))
            .collect::<Vec<_>>();
        if let Some(matcher) = string_any(object, &["matcher-name", "matcher_name"]) {
            tags.push(format!("matcher:{}", safe_tag(&matcher)));
        }
        records.push(with_weakness(
            with_scanner_details(
                record_with_derived_confidence!(
                    pointer,
                    rule_id,
                    title,
                    severity,
                    redact_location(&target),
                    string_any(object, &["asset_id"]),
                    derived_confidence(ConfidenceBasisCode::TemplateMatcher),
                    EvidenceKind::ExternalValidation,
                    references_from(value),
                    tags,
                ),
                nested_string(value, &["info", "description"]),
                nested_string(value, &["info", "remediation"]),
                None,
                None,
            ),
            // Nuclei's template classification. It writes CWE ids lowercase
            // (`cwe-78`) and publishes one unattributed score, which is the
            // template author's, so the template engine is named as its source.
            UpstreamWeakness {
                cwe_ids: cwe_identifiers(value.pointer("/info/classification/cwe-id")),
                cvss: cvss_score(
                    "nuclei",
                    nested_string(value, &["info", "classification", "cvss-metrics"]),
                    cvss_base_score(value.pointer("/info/classification/cvss-score")),
                )
                .into_iter()
                .collect(),
            },
        ));
    }
    NucleiExtraction {
        records,
        execution_counts,
    }
}

fn extract_zap(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed).and_then(Value::as_object) else {
        push_warning(warnings, "ZAP expected one JSON report object");
        return Vec::new();
    };
    let Some(sites) = root.get("site").and_then(Value::as_array) else {
        push_warning(
            warnings,
            "ZAP output lacked its site array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter",
        );
        return Vec::new();
    };

    if sites.is_empty() {
        push_warning(
            warnings,
            "ZAP observed no website responses; no passive security check could be confirmed",
        );
        return Vec::new();
    }
    let mut records = Vec::new();
    for (site_index, site) in sites.iter().enumerate() {
        let site_pointer = format!("/site/{site_index}");
        let Some(site) = site.as_object() else {
            push_warning(
                warnings,
                format!(
                    "ZAP site at {site_pointer} was not an object; the raw record was retained"
                ),
            );
            continue;
        };
        let Some(alerts) = site.get("alerts").and_then(Value::as_array) else {
            push_warning(
                warnings,
                format!(
                    "ZAP site at {site_pointer} lacked its alerts array; the raw record was retained"
                ),
            );
            continue;
        };

        for (alert_index, alert) in alerts.iter().enumerate() {
            let alert_pointer = format!("{site_pointer}/alerts/{alert_index}");
            let Some(alert) = alert.as_object() else {
                push_warning(
                    warnings,
                    format!(
                        "ZAP alert at {alert_pointer} was not an object; the raw record was retained"
                    ),
                );
                continue;
            };
            let Some(plugin_id) = exact_rule_string_any(alert, &["pluginid"]) else {
                push_warning(
                    warnings,
                    format!(
                        "ZAP alert at {alert_pointer} lacked its pluginid; the raw record was retained"
                    ),
                );
                continue;
            };
            let Some(title) = alert.get("alert").and_then(Value::as_str) else {
                push_warning(
                    warnings,
                    format!(
                        "ZAP alert at {alert_pointer} lacked its alert title; the raw record was retained"
                    ),
                );
                continue;
            };
            let Some(risk_code) = alert.get("riskcode").and_then(Value::as_str) else {
                push_warning(
                    warnings,
                    format!(
                        "ZAP alert at {alert_pointer} lacked its riskcode; the raw record was retained"
                    ),
                );
                continue;
            };
            let Some(severity) = zap_severity(risk_code) else {
                push_warning(
                    warnings,
                    format!(
                        "ZAP alert at {alert_pointer} had an unsupported riskcode and was not normalized"
                    ),
                );
                continue;
            };
            let Some(confidence_code) = alert.get("confidence").and_then(Value::as_str) else {
                push_warning(
                    warnings,
                    format!(
                        "ZAP alert at {alert_pointer} lacked its confidence; the raw record was retained"
                    ),
                );
                continue;
            };
            let Some(confidence) = zap_confidence(confidence_code) else {
                push_warning(
                    warnings,
                    format!(
                        "ZAP alert at {alert_pointer} had an unsupported confidence and was not normalized"
                    ),
                );
                continue;
            };
            let Some(instances) = alert.get("instances").and_then(Value::as_array) else {
                push_warning(
                    warnings,
                    format!(
                        "ZAP alert at {alert_pointer} lacked its instances array; the raw record was retained"
                    ),
                );
                continue;
            };

            let alert_ref = alert.get("alertRef").and_then(Value::as_str);
            let description = alert
                .get("desc")
                .and_then(Value::as_str)
                .map(zap_plain_text);
            let remediation = alert
                .get("solution")
                .and_then(Value::as_str)
                .map(zap_plain_text);
            let references = zap_references(alert.get("reference"));
            let cwe_ids = cwe_identifiers(alert.get("cweid"));
            let wasc_id = alert.get("wascid").and_then(Value::as_str);

            for (instance_index, instance) in instances.iter().enumerate() {
                if records.len() >= MAX_RECORDS {
                    return records;
                }
                let pointer = format!("{alert_pointer}/instances/{instance_index}");
                let Some(instance) = instance.as_object() else {
                    push_warning(
                        warnings,
                        format!(
                            "ZAP instance at {pointer} was not an object; the raw record was retained"
                        ),
                    );
                    continue;
                };
                let Some(uri) = instance.get("uri").and_then(Value::as_str) else {
                    push_warning(
                        warnings,
                        format!(
                            "ZAP instance at {pointer} lacked its uri; the raw record was retained"
                        ),
                    );
                    continue;
                };
                let method = instance
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let parameter = instance
                    .get("param")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let instance_evidence = instance
                    .get("evidence")
                    .and_then(Value::as_str)
                    .and_then(bounded_zap_evidence_tag_value);
                // `otherinfo` is plain text even when it quotes the matched
                // response markup, so preserve it without HTML conversion.
                let instance_other_info = instance
                    .get("otherinfo")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_default();
                let instance_id = instance
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();

                let mut tags = vec![
                    format!("zap-risk-code:{risk_code}"),
                    format!("zap-confidence-code:{confidence_code}"),
                    format!("zap-method:{method}"),
                    format!("zap-param:{parameter}"),
                ];
                if let Some(alert_ref) = alert_ref {
                    tags.push(format!("zap-alert-ref:{alert_ref}"));
                }
                if let Some(wasc_id) = wasc_id {
                    tags.push(format!("wasc:{wasc_id}"));
                }
                if !instance_id.is_empty() {
                    tags.push(format!("zap-instance-id:{instance_id}"));
                }
                if let Some(instance_evidence) = instance_evidence {
                    tags.push(format!("zap-evidence:{instance_evidence}"));
                }

                let instance_description = if instance_other_info.trim().is_empty() {
                    description.clone()
                } else if let Some(description) = description.as_deref() {
                    Some(format!("{description} {instance_other_info}"))
                } else {
                    Some(instance_other_info)
                };

                let mut record = with_weakness(
                    with_scanner_details(
                        record!(
                            pointer,
                            plugin_id.clone(),
                            title.to_owned(),
                            severity.to_owned(),
                            uri.to_owned(),
                            None,
                            confidence.to_owned(),
                            None,
                            EvidenceKind::ExternalValidation,
                            references.clone(),
                            tags,
                        ),
                        instance_description,
                        remediation.clone(),
                        None,
                        None,
                    ),
                    UpstreamWeakness {
                        cwe_ids: cwe_ids.clone(),
                        cvss: Vec::new(),
                    },
                );
                let alert_identity = alert_ref.unwrap_or(&plugin_id);
                record.fingerprint_identity = Some(format!(
                    "zap-alert-instance:{alert_identity}:{}",
                    if instance_id.is_empty() {
                        instance_index.to_string()
                    } else {
                        instance_id.to_owned()
                    }
                ));
                records.push(record);
            }
        }
    }
    records
}

fn zap_severity(risk_code: &str) -> Option<&'static str> {
    match risk_code {
        "0" => Some("Informational"),
        "1" => Some("Low"),
        "2" => Some("Medium"),
        "3" => Some("High"),
        _ => None,
    }
}

fn zap_confidence(confidence: &str) -> Option<&'static str> {
    match confidence {
        "0" => Some("False Positive"),
        "1" => Some("Low"),
        "2" => Some("Medium"),
        "3" => Some("High"),
        "4" => Some("Confirmed"),
        _ => None,
    }
}

fn bounded_zap_evidence_tag_value(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let mut characters = value.chars();
    let bounded = characters
        .by_ref()
        .take(MAX_ZAP_EVIDENCE_TAG_VALUE)
        .collect::<String>();
    Some(if characters.next().is_some() {
        format!("{bounded}…")
    } else {
        bounded
    })
}

/// Convert ZAP's presentation-only HTML fragments to bounded report text.
///
/// Paragraph and line-break tags become spaces, remaining tags are
/// discarded, and the small entity set ZAP uses for quoted markup is decoded.
fn zap_plain_text(value: &str) -> String {
    let mut plain = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(tag_start) = rest.find('<') {
        plain.push_str(&rest[..tag_start]);
        let after_start = &rest[tag_start + 1..];
        let Some(tag_end) = after_start.find('>') else {
            plain.push_str(&rest[tag_start..]);
            rest = "";
            break;
        };
        let tag = after_start[..tag_end].trim().to_ascii_lowercase();
        let closing = tag.starts_with('/');
        let tag_name = tag
            .strip_prefix('/')
            .unwrap_or(&tag)
            .trim_start()
            .split(|character: char| character.is_ascii_whitespace() || character == '/')
            .next()
            .unwrap_or_default();
        if tag_name == "br" || (closing && tag_name == "p") {
            plain.push(' ');
        }
        rest = &after_start[tag_end + 1..];
    }
    plain.push_str(rest);
    decode_zap_html_entities(&plain)
}

fn decode_zap_html_entities(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(entity_start) = rest.find('&') {
        decoded.push_str(&rest[..entity_start]);
        let entity = &rest[entity_start..];
        let replacement = [
            ("&amp;", '&'),
            ("&lt;", '<'),
            ("&gt;", '>'),
            ("&quot;", '"'),
            ("&#39;", '\''),
            ("&apos;", '\''),
        ]
        .into_iter()
        .find_map(|(encoded, decoded)| entity.starts_with(encoded).then_some((encoded, decoded)));
        if let Some((encoded, replacement)) = replacement {
            decoded.push(replacement);
            rest = &entity[encoded.len()..];
        } else {
            decoded.push('&');
            rest = &entity[1..];
        }
    }
    decoded.push_str(rest);
    decoded
}

fn zap_references(reference: Option<&Value>) -> Vec<String> {
    let Some(reference) = reference.and_then(Value::as_str) else {
        return Vec::new();
    };
    zap_plain_text(reference)
        .split_whitespace()
        .filter(|value| value.starts_with("https://"))
        .take(32)
        .map(str::to_owned)
        .collect()
}

fn extract_greenbone(
    parsed: &ParsedArtifact,
    warnings: &mut Vec<String>,
    authorized_asset_ids: &[String],
) -> GreenboneExtraction {
    let ParsedArtifact::Xml(results) = parsed else {
        push_warning(warnings, "Greenbone expected a bounded XML report");
        return GreenboneExtraction {
            records: Vec::new(),
            unevaluated_targets: Vec::new(),
            complete: false,
        };
    };

    let mut records = Vec::new();
    let mut unevaluated_counts: BTreeMap<(String, UnevaluatedTargetCause), usize> = BTreeMap::new();
    let mut complete = true;
    let mut saw_dead_host = false;
    let mut saw_scanner_error = false;
    // Assets with at least one log or alarm on an approved port. The launcher
    // maps every relay port back to its approved port and writes 0 for
    // host-level results, so a non-zero port is a result about a service.
    let mut assets_with_service_results = BTreeSet::new();
    for result in results.iter().take(MAX_RECORDS) {
        let numeric_severity = result
            .severity
            .as_deref()
            .and_then(|value| value.trim().parse::<f64>().ok());
        let positive_severity = numeric_severity.is_some_and(|severity| severity > 0.0);
        let threat = result
            .threat
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let result_type = result
            .result_type
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase);
        if matches!(result_type.as_deref(), Some("alarm" | "log") | None)
            && result
                .port
                .as_deref()
                .and_then(greenbone_service_port)
                .is_some()
            && let Some(asset_id) = result
                .asset_id
                .as_ref()
                .filter(|asset_id| authorized_asset_ids.contains(asset_id))
        {
            assets_with_service_results.insert(asset_id.clone());
        }
        let is_unrated_alarm = match result_type.as_deref() {
            Some("alarm") => !positive_severity,
            Some("log") => continue,
            Some("error") => {
                if let Some(asset_id) = result
                    .asset_id
                    .as_ref()
                    .filter(|asset_id| authorized_asset_ids.contains(asset_id))
                {
                    saw_scanner_error = true;
                    let count = unevaluated_counts
                        .entry((asset_id.clone(), UnevaluatedTargetCause::ScannerError))
                        .or_default();
                    *count = count.saturating_add(1);
                } else {
                    push_warning(
                        warnings,
                        "Greenbone reported a target it could not evaluate, but the result named no authorized asset; the raw artifact was retained",
                    );
                    complete = false;
                }
                continue;
            }
            Some("dead_host") => {
                if let Some(asset_id) = result
                    .asset_id
                    .as_ref()
                    .filter(|asset_id| authorized_asset_ids.contains(asset_id))
                {
                    saw_dead_host = true;
                    let count = unevaluated_counts
                        .entry((
                            asset_id.clone(),
                            UnevaluatedTargetCause::TargetDidNotRespond,
                        ))
                        .or_default();
                    *count = count.saturating_add(1);
                } else {
                    push_warning(
                        warnings,
                        "Greenbone reported a target it could not evaluate, but the result named no authorized asset; the raw artifact was retained",
                    );
                    complete = false;
                }
                continue;
            }
            Some(_) => {
                push_warning(
                    warnings,
                    "Greenbone result carried an unsupported upstream result type and was retained only as raw evidence",
                );
                complete = false;
                continue;
            }
            None if matches!(threat.as_str(), "log" | "false positive") => continue,
            None if positive_severity => false,
            None => {
                push_warning(
                    warnings,
                    "Greenbone result lacked an upstream result type and a positive severity; it was retained only as raw evidence and this run cannot be treated as a clean result",
                );
                complete = false;
                continue;
            }
        };

        let Some(rule_id) = result
            .nvt_oid
            .clone()
            .or_else(|| result.cves.first().cloned())
        else {
            push_warning(
                warnings,
                format!(
                    "Greenbone result {} lacked a valid NVT OID or CVE and was not normalized",
                    safe_text(result.result_id.as_deref().unwrap_or(&result.pointer), 120)
                ),
            );
            complete = false;
            continue;
        };

        let host = result.host.as_deref().unwrap_or("authorized-target");
        let location = result
            .port
            .as_deref()
            .filter(|port| !port.trim().is_empty())
            .map(|port| format!("{host}:{port}"))
            .unwrap_or_else(|| host.to_owned());
        let qod = result
            .qod
            .as_deref()
            .and_then(|value| value.parse::<u8>().ok())
            .filter(|value| *value <= 100);
        let source_confidence = result.qod.clone().unwrap_or_default();
        let mut references = result
            .cves
            .iter()
            .map(|cve| format!("https://nvd.nist.gov/vuln/detail/{cve}"))
            .collect::<Vec<_>>();
        references.sort();
        references.dedup();
        references.truncate(12);
        let mut tags = result
            .cves
            .iter()
            .take(16)
            .map(|cve| format!("cve:{}", safe_tag(cve)))
            .collect::<Vec<_>>();
        if let Some(family) = &result.family {
            tags.push(format!("nvt-family:{}", safe_tag(family)));
        }
        if let Some(qod) = qod {
            tags.push(format!("quality-of-detection:{qod}"));
        }

        let title = result
            .nvt_name
            .clone()
            .or_else(|| result.result_name.clone())
            .unwrap_or_else(|| format!("Greenbone NVT {rule_id}"));
        let record = if is_unrated_alarm {
            record_with_severity_fallback!(
                result.pointer.clone(),
                rule_id.clone(),
                title,
                String::new(),
                DerivedSeverity {
                    severity: Severity::Unknown,
                    code: SeverityBasisCode::UnratedVulnerabilityTestAlarm,
                },
                location,
                result.asset_id.clone(),
                source_confidence,
                Some(derived_confidence(
                    ConfidenceBasisCode::MissingDetectionQualityScore,
                )),
                EvidenceKind::ExternalValidation,
                references,
                tags,
            )
        } else {
            record_with_confidence_fallback!(
                result.pointer.clone(),
                rule_id.clone(),
                title,
                result.severity.clone().unwrap_or_default(),
                location,
                result.asset_id.clone(),
                source_confidence,
                derived_confidence(ConfidenceBasisCode::MissingDetectionQualityScore),
                EvidenceKind::ExternalValidation,
                references,
                tags,
            )
        };
        records.push(with_weakness(
            with_scanner_details(
                record,
                // Only these two result-level fields are copied from the product
                // launcher, which writes them from the pinned feed metadata.
                // `<description>` is the target-observed result message and must
                // remain only in the raw artifact.
                result.summary.clone(),
                result.solution.clone(),
                None,
                None,
            ),
            // GMP defines a result's `<severity>` as its CVSS base score, so it
            // is republished under the name the reader's other tools use. The
            // vector lives on the NVT rather than the result, so the version
            // stays unstated instead of being guessed from the number.
            //
            // Only a positive score is one: GMP writes 0.0 for a Log result
            // that was never scored, and printing "CVSS 0.0" beside it would
            // read as a scored, harmless vulnerability rather than as an
            // observation nobody rated.
            UpstreamWeakness {
                cwe_ids: Vec::new(),
                cvss: positive_severity
                    .then(|| {
                        cvss_score(
                            "greenbone",
                            None,
                            cvss_base_score(
                                result
                                    .severity
                                    .as_deref()
                                    .map(|severity| Value::String(severity.to_owned()))
                                    .as_ref(),
                            ),
                        )
                    })
                    .flatten()
                    .into_iter()
                    .collect(),
            },
        ));
    }
    if saw_dead_host {
        push_warning(
            warnings,
            "Greenbone reported that the host did not respond, so none of its vulnerability checks ran for that target",
        );
    }
    if saw_scanner_error {
        push_warning(
            warnings,
            "Greenbone reported scanner errors for the target, so some of its checks did not finish",
        );
    }
    for asset_id in authorized_asset_ids {
        let did_not_respond = unevaluated_counts.contains_key(&(
            asset_id.clone(),
            UnevaluatedTargetCause::TargetDidNotRespond,
        ));
        if !did_not_respond && !assets_with_service_results.contains(asset_id) {
            unevaluated_counts.insert(
                (
                    asset_id.clone(),
                    UnevaluatedTargetCause::NoServiceIdentified,
                ),
                0,
            );
        }
    }
    let mut unevaluated_targets = unevaluated_counts
        .into_iter()
        .map(|((asset_id, cause), result_count)| UnevaluatedTarget {
            asset_id,
            cause,
            result_count,
        })
        .collect::<Vec<_>>();
    unevaluated_targets.sort();
    GreenboneExtraction {
        records,
        unevaluated_targets,
        complete,
    }
}

/// The TCP port of a Greenbone `<port>` value such as `8080/tcp`. Host-level
/// values (`0/tcp`, `general/tcp`) name no service and return `None`.
fn greenbone_service_port(value: &str) -> Option<u16> {
    let (port, protocol) = value.trim().split_once('/')?;
    if !protocol.eq_ignore_ascii_case("tcp") {
        return None;
    }
    port.parse::<u16>().ok().filter(|port| *port > 0)
}

fn extract_semgrep(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed) else {
        push_warning(warnings, "Semgrep expected a JSON document");
        return Vec::new();
    };
    // Semgrep errors may contain source paths and scanner/target-controlled
    // messages. Their presence affects completeness, but only this fixed
    // aggregate warning leaves the raw artifact.
    match root.get("errors").and_then(Value::as_array) {
        Some(errors) if !errors.is_empty() => push_warning(
            warnings,
            "Semgrep reported one or more scanner errors; valid findings were preserved, but the error details remain only in the raw artifact and completeness cannot be established",
        ),
        Some(_) => {}
        None => push_warning(
            warnings,
            "Semgrep output lacked its required errors array; valid findings were preserved, but completeness cannot be established",
        ),
    }
    let Some(results) = root.get("results").and_then(Value::as_array) else {
        push_warning(warnings, "Semgrep output had no results array");
        return Vec::new();
    };
    results
        .iter()
        .take(MAX_RECORDS)
        .enumerate()
        .filter_map(|(index, value)| {
            let pointer = format!("/results/{index}");
            let Some(object) = value.as_object() else {
                push_warning(
                    warnings,
                    format!(
                        "Semgrep finding at {pointer} was not an object; the raw record was retained"
                    ),
                );
                return None;
            };
            let Some(rule_id) = exact_rule_string_any(object, &["check_id"]) else {
                push_warning(
                    warnings,
                    format!(
                        "Semgrep finding at {pointer} lacked its check_id; the raw record was retained"
                    ),
                );
                return None;
            };
            let path = string_any(object, &["path"]).unwrap_or_else(|| "source-file".into());
            let line = value.pointer("/start/line").and_then(positive_u32_scalar);
            let column = value.pointer("/start/col").and_then(positive_u32_scalar);
            let location = source_coordinate_location(&path, line, column, None);
            Some(with_weakness(
                with_scanner_details(
                record_with_confidence_fallback!(
                    pointer,
                    rule_id.clone(),
                    // Semgrep writes the human-readable explanation here and it is
                    // the only sentence a reader can act on; the rule id alone says
                    // nothing. Falls back to the id when a rule ships no message.
                    nested_string(value, &["extra", "message"])
                        .map(|message| safe_text(&message, MAX_SHORT_TEXT))
                        .filter(|message| !message.is_empty())
                        .unwrap_or_else(|| format!("Semgrep rule {rule_id}")),
                    nested_string(value, &["extra", "severity"])
                        .unwrap_or_else(|| "unknown".into()),
                    location,
                    string_any(object, &["asset_id"]),
                    nested_string(value, &["extra", "metadata", "confidence"]).unwrap_or_default(),
                    derived_confidence(ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch),
                    EvidenceKind::SourceCode,
                    references_from(value),
                    line.map(|line| vec![format!("source-line:{line}")])
                        .unwrap_or_default(),
                ),
                nested_string(value, &["extra", "metadata", "description"]),
                nested_string(value, &["extra", "fix"]),
                None,
                None,
                ),
                // Semgrep's own rule metadata. `cwe` is a string on some rules
                // and a list on others, and each entry reads
                // `CWE-78: <weakness title>`.
                UpstreamWeakness {
                    cwe_ids: cwe_identifiers(value.pointer("/extra/metadata/cwe")),
                    cvss: Vec::new(),
                },
            ))
        })
        .collect()
}

fn extract_gitleaks(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    if !matches!(parsed, ParsedArtifact::Json(Value::Array(_))) {
        push_warning(
            warnings,
            "Gitleaks output was not its supported JSON finding array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter",
        );
        return Vec::new();
    }
    json_rows(parsed, warnings)
        .into_iter()
        .filter_map(|(pointer, value)| {
            let Some(object) = value.as_object() else {
                push_warning(
                    warnings,
                    format!("Gitleaks finding at {pointer} was not an object; the raw record was retained"),
                );
                return None;
            };
            let Some(rule_id) = exact_rule_string_any(object, &["RuleID", "rule_id"]) else {
                push_warning(
                    warnings,
                    format!("Gitleaks finding at {pointer} lacked its RuleID; the raw record was retained, and the scan should be retried with the pinned JSON reporter"),
                );
                return None;
            };
            let location = gitleaks_location(object);
            Some(record_with_derived_severity_and_confidence!(
                pointer,
                rule_id.clone(),
                string_any(object, &["Description", "description"])
                    .unwrap_or_else(|| format!("Potential secret detected by {rule_id}")),
                // The word "severity" does not occur anywhere in Gitleaks'
                // finding shape. Preserve the match as a finding, but leave its
                // absent upstream rating Unknown.
                DerivedSeverity {
                    severity: Severity::Unknown,
                    code: SeverityBasisCode::SecretPatternMatch,
                },
                location,
                string_any(object, &["asset_id"]),
                derived_confidence(ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch),
                EvidenceKind::SourceCode,
                vec![],
                vec!["secret-value:redacted".into()],
            ))
        })
        .collect()
}

/// One finding per garak `eval` row that recorded at least one failure.
///
/// garak's report is a JSONL run log, not a finding list. The only rows that
/// carry a verdict are `eval` rows, one per probe/detector pair, and what they
/// carry is a count: how many of the attempts the detector judged as failures,
/// how many it could not judge, and how many it saw. There is no severity in
/// the shape and no per-attempt result to promote, so the count is the finding.
///
/// A pair with zero failures is not admitted. That row means the probe ran and
/// the detector judged nothing as a failure, which is coverage evidence rather
/// than a problem, and admitting it would put a clean probe in the same list as
/// a failing one.
///
/// The rate matters more than any single attempt here. garak's detectors are
/// keyword and classifier matchers over free text, and upstream is explicit
/// that they over-trigger; one attempt is a lead, and "37 of 40" is the part
/// worth acting on. Keeping the counts as the evidence is also why the severity
/// stays Unknown: rating a probe failure would be this product's opinion about
/// how much a model's answer matters, on a scale garak never published.
fn extract_garak(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let rows = json_rows(parsed, warnings);
    let inits = rows
        .iter()
        .filter(|(_, r)| r["entry_type"] == "init")
        .map(|(_, r)| *r)
        .collect::<Vec<_>>();
    let completions = rows
        .iter()
        .filter(|(_, r)| r["entry_type"] == "completion")
        .map(|(_, r)| *r)
        .collect::<Vec<_>>();
    if inits.len() != 1
        || completions.len() != 1
        || inits[0]["run"].as_str().is_none_or(str::is_empty)
        || inits[0]["run"] != completions[0]["run"]
    {
        push_warning(
            warnings,
            "garak native run lacks a matching terminal completion; evaluated sibling results were retained",
        );
    }
    if inits
        .first()
        .is_some_and(|r| r["garak_version"] == "0.17.0")
    {
        let expected = BTreeMap::from([
            ("dan.Dan_11_0", ("dan.DAN", 1_u64)),
            ("dan.Dan_10_0", ("dan.DAN", 1_u64)),
            ("dan.Dan_9_0", ("dan.DAN", 1_u64)),
            ("ansiescape.AnsiEscaped", ("ansiescape.Escaped", 51_u64)),
        ]);
        let evals = rows
            .iter()
            .filter(|(_, r)| r["entry_type"] == "eval")
            .map(|(_, r)| *r)
            .collect::<Vec<_>>();
        let valid = evals.len() == expected.len()
            && expected.iter().all(|(probe, (detector, count))| {
                let matching = evals
                    .iter()
                    .filter(|r| r["probe"] == *probe)
                    .collect::<Vec<_>>();
                matching.len() == 1
                    && matching[0]["detector"] == *detector
                    && matching[0]["total_evaluated"].as_u64() == Some(*count)
                    && matching[0]["total_processed"].as_u64() == Some(*count)
                    && matching[0]["nones"].as_u64() == Some(0)
                    && matching[0]["fails"]
                        .as_u64()
                        .is_some_and(|fails| fails <= *count)
            });
        if !valid {
            push_warning(
                warnings,
                "garak native profile did not evaluate all 54 approved prompts; evaluated sibling results were retained",
            );
        }
    }
    let target = garak_target(&rows);
    let contexts = garak_probe_contexts(&rows);
    let mut records = Vec::new();
    let mut evaluated_pairs = 0_usize;
    for (pointer, value) in &rows {
        let Some(object) = value.as_object() else {
            continue;
        };
        if string_any(object, &["entry_type"]).as_deref() != Some("eval") {
            continue;
        }
        evaluated_pairs += 1;
        let (Some(probe), Some(detector)) = (
            exact_rule_string_any(object, &["probe"]),
            exact_rule_string_any(object, &["detector"]),
        ) else {
            push_warning(
                warnings,
                format!(
                    "garak eval row at {pointer} did not name both its probe and its detector; the raw record was retained"
                ),
            );
            continue;
        };
        let Some(fails) = garak_count(object, "fails") else {
            push_warning(
                warnings,
                format!(
                    "garak eval row at {pointer} carried no failure count; the raw record was retained"
                ),
            );
            continue;
        };
        if fails == 0 {
            continue;
        }
        // More failures than attempts is not a measurement, and rendering it
        // puts "3 of 0 attempts" in a security report as though someone had
        // counted it. The count garak reported is still its own and survives;
        // only the ratio, which cannot be true, is withheld.
        let evaluated = match garak_count(object, "total_evaluated") {
            Some(evaluated) if evaluated < fails => {
                push_warning(
                    warnings,
                    format!(
                        "garak eval row at {pointer} counted more failures than evaluated attempts; the rate was not shown"
                    ),
                );
                None
            }
            evaluated => evaluated,
        };
        let processed = garak_count(object, "total_processed");
        let unjudged = garak_count(object, "nones");
        let rule_id = format!("{probe}/{detector}");
        records.push(with_scanner_details(
            record_with_derived_severity_and_confidence!(
                pointer.clone(),
                rule_id.clone(),
                match evaluated {
                    Some(evaluated) => format!(
                        "garak probe {probe}: detector {detector} judged {fails} of {evaluated} attempts as failures"
                    ),
                    None => format!(
                        "garak probe {probe}: detector {detector} judged {fails} attempts as failures"
                    ),
                },
                // No garak result shape carries a severity, and the run log
                // does not rank probes against each other. The failure rate is
                // what the engine measured; this product's own prioritization
                // ranks it rather than a level invented here.
                DerivedSeverity {
                    severity: Severity::Unknown,
                    code: SeverityBasisCode::AdversarialProbeFailureRate,
                },
                target.clone(),
                None,
                // A detector hit is a matcher's opinion about generated text,
                // not a confirmed policy breach, and garak's own documentation
                // warns that its detectors produce false positives.
                derived_confidence(ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch),
                EvidenceKind::ExternalValidation,
                vec![],
                vec![],
            ),
            Some(garak_counts_sentence(
                fails,
                evaluated,
                unjudged,
                processed,
                contexts.get(probe.as_str()),
            )),
            None,
            None,
            None,
        ));
    }
    if evaluated_pairs == 0 {
        push_warning(
            warnings,
            "garak output contained no eval rows, so no probe result was evaluated",
        );
    }
    records
}

/// The model garak was pointed at, as garak's own run setup named it.
///
/// Read from the run's `start_run setup` row rather than composed here: the
/// eval rows carry no target, and the finding has to say which endpoint
/// answered this way or it cannot be acted on.
///
/// That row is a flattened config dump, so the keys are literal dotted strings
/// rather than nested objects. `plugins.model_type` and `plugins.model_name`
/// are the pre-0.14 spellings garak still lists as deprecated aliases, and an
/// older report should not lose its target for having used them.
fn garak_target(rows: &[(String, &Value)]) -> String {
    rows.iter()
        .filter_map(|(_, value)| value.as_object())
        .find_map(|object| {
            let name = string_any(object, &["plugins.target_name", "plugins.model_name"])?;
            let kind = string_any(object, &["plugins.target_type", "plugins.model_type"])
                .filter(|kind| !kind.is_empty());
            Some(match kind {
                Some(kind) => format!("{kind}:{name}"),
                None => name,
            })
        })
        .map(|target| safe_text(&target, 360))
        .filter(|target| !target.is_empty())
        .unwrap_or_else(|| "model endpoint".into())
}

/// What a garak probe said it was trying to do, and one prompt it sent doing it.
///
/// Both come from the run's own `attempt` rows. Neither is required: a report
/// trimmed to its eval rows still normalizes, it just carries the counts alone.
#[derive(Default)]
struct GarakProbeContext {
    goal: Option<String>,
    prompt: Option<String>,
}

/// Index the run's attempt rows by the probe that produced them.
///
/// The eval rows carry a verdict and nothing else -- not what the probe was
/// after, not what it sent. Without this a reader is told that
/// `dan.AutoDANCached` failed four times and has no way to find out what that
/// means without leaving the report.
///
/// Deliberately not the attempt that failed. Deciding which attempts failed is
/// garak's own scoring, threshold included, and re-deriving it here to pick a
/// prettier quote would be this product doing detection. The first attempt that
/// carries each field is representative of what the probe sends, which is the
/// question a reader actually has, and it is answered without judging anything.
///
/// Model outputs are never read. The prompt is garak's own test input; the
/// reply is the target's content, and evidence does not carry it.
fn garak_probe_contexts(rows: &[(String, &Value)]) -> BTreeMap<String, GarakProbeContext> {
    let mut contexts: BTreeMap<String, GarakProbeContext> = BTreeMap::new();
    for object in rows.iter().filter_map(|(_, value)| value.as_object()) {
        if string_any(object, &["entry_type"]).as_deref() != Some("attempt") {
            continue;
        }
        let Some(probe) = exact_rule_string_any(object, &["probe_classname"]) else {
            continue;
        };
        let context = contexts.entry(probe).or_default();
        if context.goal.is_none() {
            context.goal = garak_bounded_line(string_any(object, &["goal"]), MAX_SHORT_TEXT);
        }
        // An empty first turn is normal -- `test.Test` sends empty strings -- so
        // a later attempt still gets to supply the example.
        if context.prompt.is_none() {
            context.prompt = garak_bounded_line(garak_first_prompt_text(object), 240);
        }
    }
    contexts
}

/// The text of the first turn garak sent, ignoring every later turn and every
/// reply. Only the `user` role is read: an `assistant` turn in a multi-turn
/// probe is generated content, not the probe's input.
fn garak_first_prompt_text(object: &Map<String, Value>) -> Option<String> {
    object
        .get("prompt")?
        .as_object()?
        .get("turns")?
        .as_array()?
        .iter()
        .filter_map(Value::as_object)
        .find(|turn| string_any(turn, &["role"]).as_deref() == Some("user"))?
        .get("content")?
        .as_object()?
        .get("text")?
        .as_str()
        .map(str::to_owned)
}

/// One printable line, bounded, with an explicit mark when it was cut short.
///
/// A probe prompt arrives with its own newlines and padding, and a sentence
/// that inlines it verbatim stops being one line. Silently truncating is worse
/// than either: a reader who cannot see that the quote ends early may go
/// looking for why the prompt was so short.
fn garak_bounded_line(value: Option<String>, max_chars: usize) -> Option<String> {
    let collapsed = value?.split_whitespace().collect::<Vec<_>>().join(" ");
    let bounded = safe_text(&collapsed, max_chars);
    if bounded.is_empty() {
        return None;
    }
    Some(if collapsed.chars().count() > bounded.chars().count() {
        format!("{bounded}…")
    } else {
        bounded
    })
}

fn garak_count(object: &Map<String, Value>, key: &str) -> Option<u64> {
    object.get(key)?.as_u64()
}

/// garak's own counts, spelled out, because the numerator alone is misleading.
///
/// `total_evaluated` excludes the attempts the detector returned no score for,
/// and `total_processed` counts every attempt that was generated. A reader
/// shown only "12 failures" cannot tell 12-of-12 from 12-of-500, and cannot
/// tell either from a run where most attempts were never judged at all.
fn garak_counts_sentence(
    fails: u64,
    evaluated: Option<u64>,
    unjudged: Option<u64>,
    processed: Option<u64>,
    context: Option<&GarakProbeContext>,
) -> String {
    let mut sentence = match evaluated {
        Some(evaluated) => {
            format!("garak judged {fails} of {evaluated} evaluated attempts as failures")
        }
        None => format!("garak judged {fails} attempts as failures"),
    };
    if let Some(unjudged) = unjudged.filter(|count| *count > 0) {
        sentence.push_str(&format!(
            ". {unjudged} further attempts returned no detector score and were not evaluated"
        ));
    }
    if let Some(processed) = processed
        && evaluated.is_some_and(|evaluated| processed > evaluated)
    {
        sentence.push_str(&format!(
            ". The probe generated {processed} attempts in total, so not every attempt reached the detector"
        ));
    }
    sentence.push('.');
    if let Some(goal) = context.and_then(|context| context.goal.as_deref()) {
        sentence.push_str(&format!(" The probe's stated goal: {goal}."));
    }
    if let Some(prompt) = context.and_then(|context| context.prompt.as_deref()) {
        sentence.push_str(&format!(" One of the prompts it sent: {prompt}"));
    }
    sentence
}

fn gitleaks_location(object: &Map<String, Value>) -> String {
    // Gitleaks' Secret and Match fields must never participate in a durable
    // identity. File coordinates and a validated Git object ID distinguish
    // multiple observations without retaining the detected value.
    let file = string_any(object, &["File", "file"])
        .map(|value| redact_location(&value))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "repository".into());
    let mut location = safe_text(&file, 360);

    if let Some(line) = positive_u32_any(object, &["StartLine", "start_line"]) {
        location.push_str(&format!(":line={line}"));
    }
    if let Some(column) = positive_u32_any(object, &["StartColumn", "start_column"]) {
        location.push_str(&format!(":column={column}"));
    }
    if let Some(commit) =
        string_any(object, &["Commit", "commit"]).and_then(|value| normalized_git_object_id(&value))
    {
        location.push_str(":commit=");
        location.push_str(&commit);
    }

    location
}

fn positive_u32_any(object: &Map<String, Value>, keys: &[&str]) -> Option<u32> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(positive_u32_scalar))
}

fn positive_u32_scalar(value: &Value) -> Option<u32> {
    let parsed = match value {
        Value::Number(number) => number.as_u64()?,
        Value::String(value) => value.parse::<u64>().ok()?,
        _ => return None,
    };
    u32::try_from(parsed).ok().filter(|value| *value > 0)
}

/// Build a stable, secret-free source coordinate from fields the scanner
/// explicitly reports. The fingerprint includes this location, so omitting a
/// line or resource silently merges distinct observations from the same rule
/// and file into one finding.
fn source_coordinate_location(
    path: &str,
    line: Option<u32>,
    column: Option<u32>,
    resource: Option<&str>,
) -> String {
    let mut location = safe_text(&redact_location(path), 360);
    if let Some(line) = line {
        location.push_str(&format!(":line={line}"));
    }
    if let Some(column) = column {
        location.push_str(&format!(":column={column}"));
    }
    if let Some(resource) = resource
        .map(|resource| safe_text(resource, 120))
        .filter(|resource| !resource.is_empty())
    {
        location.push_str(":resource=");
        location.push_str(&resource);
    }
    safe_text(&location, MAX_SHORT_TEXT)
}

fn normalized_git_object_id(value: &str) -> Option<String> {
    let value = value.trim();
    if !matches!(value.len(), 40 | 64)
        || !value.bytes().all(|character| character.is_ascii_hexdigit())
    {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn extract_trufflehog(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    json_rows(parsed, warnings)
        .into_iter()
        .filter_map(|(pointer, value)| {
            let Some(object) = value.as_object() else {
                push_warning(
                    warnings,
                    format!("TruffleHog record at {pointer} was not an object; retry with the supported pinned JSONL output"),
                );
                return None;
            };
            let Some(detector) = exact_rule_string_any(object, &["DetectorName", "DetectorType"])
            else {
                push_warning(
                    warnings,
                    format!("TruffleHog record at {pointer} lacked its detector identity; the raw record was retained, and the scan should be retried with the supported pinned JSONL output"),
                );
                return None;
            };
            let filesystem = value.pointer("/SourceMetadata/Data/Filesystem");
            let git = value.pointer("/SourceMetadata/Data/Git");
            let source = filesystem
                .and_then(|metadata| nested_string(metadata, &["file"]))
                .or_else(|| git.and_then(|metadata| nested_string(metadata, &["file"])))
                .unwrap_or_else(|| "repository".into());
            let line = filesystem
                .and_then(|metadata| metadata.get("line"))
                .and_then(positive_u32_scalar)
                .or_else(|| {
                    git.and_then(|metadata| metadata.get("line"))
                        .and_then(positive_u32_scalar)
                });
            let location = source_coordinate_location(&source, line, None, None);
            Some(record_with_derived_severity_and_confidence!(
                pointer,
                format!("trufflehog:{detector}"),
                format!("Potential {detector} secret detected"),
                // TruffleHog emits no severity; its JSON printer marshals a
                // fixed struct with no such field. It emits `Verified`, which
                // this product's launcher forces to false by passing
                // `--no-verification`: the engine short-circuits before any
                // detector runs its check. Reading that field would grade every
                // secret on a test that was never performed.
                DerivedSeverity {
                    severity: Severity::Unknown,
                    code: SeverityBasisCode::UnverifiedCredentialDetector,
                },
                location,
                string_any(object, &["asset_id"]),
                derived_confidence(ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch),
                EvidenceKind::SourceCode,
                vec![],
                vec![
                    "verification:not-attempted".into(),
                    "secret-value:redacted".into(),
                ],
            ))
        })
        .collect()
}

fn extract_checkov(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed) else {
        push_warning(warnings, "Checkov expected a JSON document");
        return Vec::new();
    };
    let mut records = Vec::new();
    let mut inspected_rows = 0_usize;

    match root {
        // Checkov serializes a single detected framework as this legacy object
        // shape. Keep its pointers stable for already-saved evidence.
        Value::Object(_) => {
            extract_checkov_framework(root, "", &mut inspected_rows, &mut records, warnings)
        }
        // With `--framework all`, Checkov serializes one report object per
        // detected framework. The record limit applies across the whole
        // document, not once per framework.
        Value::Array(frameworks) => {
            if frameworks.len() > MAX_RECORDS {
                push_warning(
                    warnings,
                    "Checkov framework result limit reached; later framework results remain only as raw evidence",
                );
            }
            for (framework_index, framework) in frameworks.iter().take(MAX_RECORDS).enumerate() {
                if inspected_rows >= MAX_RECORDS {
                    push_warning(
                        warnings,
                        "Checkov failed-check record limit reached; later rows remain only as raw evidence",
                    );
                    break;
                }
                extract_checkov_framework(
                    framework,
                    &format!("/{framework_index}"),
                    &mut inspected_rows,
                    &mut records,
                    warnings,
                );
            }
        }
        _ => push_warning(
            warnings,
            "Checkov expected a JSON object or an array of framework result objects",
        ),
    }

    records
}

fn extract_checkov_framework(
    framework: &Value,
    framework_pointer: &str,
    inspected_rows: &mut usize,
    records: &mut Vec<SourceRecord>,
    warnings: &mut Vec<String>,
) {
    let display_pointer = if framework_pointer.is_empty() {
        "/"
    } else {
        framework_pointer
    };
    let Some(object) = framework.as_object() else {
        push_warning(
            warnings,
            format!("non-object Checkov framework result at {display_pointer} was skipped"),
        );
        return;
    };

    let failed_pointer = format!("{framework_pointer}/results/failed_checks");
    let Some(results) = object.get("results") else {
        // When no runner found an applicable framework, upstream emits its
        // summary object directly rather than a report object. That is a valid
        // zero-finding result and must stay distinct from a malformed report.
        if object.contains_key("checkov_version")
            && object.contains_key("passed")
            && object.contains_key("failed")
            && object.contains_key("skipped")
        {
            return;
        }
        push_warning(
            warnings,
            format!("Checkov framework result at {display_pointer} had no results object"),
        );
        return;
    };
    let Some(results) = results.as_object() else {
        push_warning(
            warnings,
            format!("Checkov results at {display_pointer} were not an object"),
        );
        return;
    };
    let Some(failed) = results.get("failed_checks").and_then(Value::as_array) else {
        push_warning(
            warnings,
            format!("Checkov output at {failed_pointer} was not an array"),
        );
        return;
    };

    for (index, value) in failed.iter().enumerate() {
        if *inspected_rows >= MAX_RECORDS {
            push_warning(
                warnings,
                "Checkov failed-check record limit reached; later rows remain only as raw evidence",
            );
            return;
        }
        *inspected_rows += 1;

        let pointer = format!("{failed_pointer}/{index}");
        let Some(check) = value.as_object() else {
            push_warning(
                warnings,
                format!("non-object Checkov failed check at {pointer} was skipped"),
            );
            continue;
        };
        let Some(rule_id) = exact_rule_string_any(check, &["check_id"]) else {
            push_warning(
                warnings,
                format!("Checkov failed check at {pointer} had no valid check_id and was skipped"),
            );
            continue;
        };
        let path = string_any(check, &["file_path", "repo_file_path"])
            .unwrap_or_else(|| "iac-resource".into());
        let line = check
            .get("file_line_range")
            .and_then(Value::as_array)
            .and_then(|range| range.first())
            .and_then(positive_u32_scalar);
        let resource = string_any(check, &["resource", "resource_address"]);
        records.push(with_scanner_details(
            record_with_severity_fallback_and_derived_confidence!(
                pointer,
                rule_id.clone(),
                string_any(check, &["check_name"])
                    .unwrap_or_else(|| format!("Checkov check {rule_id}")),
                // `Record.severity` is whatever the check object carried, and
                // `BaseCheck` hardcodes `None`. The values that fill it come
                // from downloaded platform metadata, which `--skip-download`
                // switches off entirely. Of the 256 shipped graph-check YAMLs
                // exactly one declares a severity locally, so this is populated
                // for CKV2_AWS_34 and null for every other check.
                string_any(check, &["severity"]).unwrap_or_default(),
                // A missing/null source field stays Unknown. An explicit
                // Checkov severity still wins in `record_from_draft`.
                DerivedSeverity {
                    severity: Severity::Unknown,
                    code: SeverityBasisCode::IacPolicyCheck,
                },
                source_coordinate_location(&path, line, None, resource.as_deref()),
                string_any(check, &["asset_id"]),
                derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
                EvidenceKind::Configuration,
                references_from(value),
                vec![],
            ),
            string_any(check, &["description", "short_description"]),
            None,
            None,
            None,
        ));
    }
}

fn extract_kics(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed) else {
        push_warning(warnings, "KICS expected a JSON document");
        return Vec::new();
    };
    // Older reports omit these counters. A declared failure must still prevent
    // a clean result, even when the findings array is empty. Ignored lines and
    // similarity-id failures are not evidence that a security query failed.
    for field in ["files_failed_to_scan", "queries_failed_to_execute"] {
        if let Some(counter) = root.get(field) {
            match counter.as_u64() {
                Some(0) => {}
                Some(_) => push_warning(
                    warnings,
                    format!(
                        "KICS reported failures in {field}; review the scan evidence and retry the affected checks"
                    ),
                ),
                None => push_warning(
                    warnings,
                    format!(
                        "KICS {field} counter was not a non-negative integer; scan completeness cannot be established"
                    ),
                ),
            }
        }
    }
    let Some(queries) = root.get("queries").and_then(Value::as_array) else {
        push_warning(
            warnings,
            "KICS output lacked its queries array; the raw artifact was retained",
        );
        return Vec::new();
    };
    let mut records = Vec::new();
    for (query_index, query) in queries.iter().enumerate() {
        let query_pointer = format!("/queries/{query_index}");
        let Some(query_object) = query.as_object() else {
            push_warning(
                warnings,
                format!(
                    "KICS query at {query_pointer} was not an object; the raw record was retained"
                ),
            );
            continue;
        };
        let Some(rule_id) = query_object
            .get("query_id")
            .and_then(Value::as_str)
            .filter(|value| exact_mapping_source_rule(value).is_some())
            .map(str::to_owned)
        else {
            push_warning(
                warnings,
                format!(
                    "KICS query at {query_pointer} lacked a valid query_id; the raw record was retained"
                ),
            );
            continue;
        };
        let title = string_any(query_object, &["query_name"])
            .unwrap_or_else(|| format!("KICS query {rule_id}"));
        let severity = string_any(query_object, &["severity"]).unwrap_or_else(|| "unknown".into());
        let Some(files) = query_object.get("files").and_then(Value::as_array) else {
            push_warning(
                warnings,
                format!(
                    "KICS query at {query_pointer} lacked its files array; the raw record was retained"
                ),
            );
            continue;
        };
        for (file_index, file) in files.iter().enumerate() {
            let file_pointer = format!("{query_pointer}/files/{file_index}");
            let Some(file_object) = file.as_object() else {
                push_warning(
                    warnings,
                    format!(
                        "KICS file at {file_pointer} was not an object; the raw record was retained"
                    ),
                );
                continue;
            };
            let path =
                string_any(file_object, &["file_name"]).unwrap_or_else(|| "iac-resource".into());
            let line = positive_u32_any(file_object, &["line", "search_line"]);
            let resource = [
                string_any(file_object, &["resource_name"])
                    .filter(|value| !value.is_empty())
                    .map(|value| format!("resource:{value}")),
                string_any(file_object, &["similarity_id", "old_similarity_id"])
                    .filter(|value| !value.is_empty())
                    .map(|value| format!("similarity:{value}")),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(",");
            records.push(with_weakness(
                with_scanner_details(
                    record_with_derived_confidence!(
                        file_pointer,
                        rule_id.clone(),
                        title.clone(),
                        severity.clone(),
                        source_coordinate_location(
                            &path,
                            line,
                            None,
                            (!resource.is_empty()).then_some(resource.as_str()),
                        ),
                        string_any(file_object, &["asset_id"]),
                        derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
                        EvidenceKind::Configuration,
                        references_from(query),
                        vec![],
                    ),
                    string_any(query_object, &["description"]),
                    None,
                    None,
                    None,
                ),
                // Present on queries in newer KICS rule packs and absent on
                // older ones; an absent field simply yields no classification.
                UpstreamWeakness {
                    cwe_ids: cwe_identifiers(query_object.get("cwe")),
                    cvss: Vec::new(),
                },
            ));
            if records.len() >= MAX_RECORDS {
                return records;
            }
        }
    }
    records
}

fn extract_trivy(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed) else {
        push_warning(warnings, "Trivy expected a JSON document");
        return Vec::new();
    };
    // Absent Results is an empty Trivy document. Warn only when the root is
    // not an object or Results/results is present but not an array.
    if !root.is_object() {
        push_warning(
            warnings,
            "Trivy output lacked its Results array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter",
        );
        return Vec::new();
    }
    let Some(results_value) = root.get("Results").or_else(|| root.get("results")) else {
        return Vec::new();
    };
    let Some(results) = results_value.as_array() else {
        push_warning(
            warnings,
            "Trivy output lacked its Results array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter",
        );
        return Vec::new();
    };
    let mut records = Vec::new();
    for (result_index, result) in results.iter().enumerate() {
        let result_pointer = format!("/Results/{result_index}");
        let Some(result_object) = result.as_object() else {
            push_warning(
                warnings,
                format!(
                    "Trivy result at {result_pointer} was not an object; the raw record was retained"
                ),
            );
            continue;
        };
        let target = string_any(result_object, &["Target", "target"])
            .unwrap_or_else(|| "container-image".into());
        for (field, prefix, kind) in [
            (
                "Vulnerabilities",
                "vulnerability",
                EvidenceKind::PackageInventory,
            ),
            (
                "Misconfigurations",
                "misconfiguration",
                EvidenceKind::Configuration,
            ),
            ("Secrets", "secret", EvidenceKind::SourceCode),
        ] {
            let confidence_basis = match field {
                "Vulnerabilities" => ConfidenceBasisCode::AdvisoryVersionMatch,
                "Misconfigurations" => ConfidenceBasisCode::DeterministicPolicyEvaluation,
                "Secrets" => ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch,
                _ => unreachable!("closed Trivy result kinds"),
            };
            let Some(category) = result_object.get(field) else {
                continue;
            };
            let Some(items) = category.as_array() else {
                push_warning(
                    warnings,
                    format!(
                        "Trivy {field} at {result_pointer}/{field} was present but not an array; the raw value was retained"
                    ),
                );
                continue;
            };
            for (item_index, item) in items.iter().enumerate() {
                let Some(object) = item.as_object() else {
                    push_warning(
                        warnings,
                        format!(
                            "Trivy {prefix} at /Results/{result_index}/{field}/{item_index} was not an object and remains only as raw evidence"
                        ),
                    );
                    continue;
                };
                let Some(rule_id) =
                    exact_rule_string_any(object, &["VulnerabilityID", "ID", "RuleID"])
                else {
                    push_warning(
                        warnings,
                        format!(
                            "Trivy {prefix} at /Results/{result_index}/{field}/{item_index} lacked its native rule id; the raw record was retained, and the scan should be retried with the pinned JSON reporter"
                        ),
                    );
                    continue;
                };
                let title = string_any(object, &["Title", "Message"])
                    .unwrap_or_else(|| format!("Trivy {prefix} {rule_id}"));
                let mut tags = Vec::new();
                if let Some(package) = string_any(object, &["PkgName"]) {
                    tags.push(format!("package:{}", safe_tag(&package)));
                }
                if field == "Secrets" {
                    tags.push("secret-value:redacted".into());
                }
                let (location, asset_hint) = match field {
                    "Vulnerabilities" => {
                        let package =
                            string_any(object, &["PkgName"]).unwrap_or_else(|| "package".into());
                        let installed = string_any(object, &["InstalledVersion"])
                            .unwrap_or_else(|| "unknown-version".into());
                        let package_path = string_any(object, &["PkgPath", "PkgID"]);
                        let resource = package_path
                            .map(|path| format!("{package}@{installed}:{path}"))
                            .unwrap_or_else(|| format!("{package}@{installed}"));
                        (
                            source_coordinate_location(&target, None, None, Some(&resource)),
                            string_any(object, &["asset_id"]),
                        )
                    }
                    "Secrets" => {
                        let offset = positive_u32_any(object, &["Offset"])
                            .map(|offset| format!("offset:{offset}"));
                        (
                            source_coordinate_location(
                                &target,
                                positive_u32_any(object, &["StartLine"]),
                                None,
                                offset.as_deref(),
                            ),
                            string_any(object, &["asset_id"]),
                        )
                    }
                    "Misconfigurations" => (
                        source_coordinate_location(
                            &target,
                            object
                                .get("CauseMetadata")
                                .and_then(Value::as_object)
                                .and_then(|cause| positive_u32_any(cause, &["StartLine"])),
                            None,
                            object
                                .get("CauseMetadata")
                                .and_then(Value::as_object)
                                .and_then(|cause| string_any(cause, &["Resource"]))
                                .as_deref(),
                        ),
                        string_any(object, &["asset_id"]),
                    ),
                    _ => unreachable!("closed Trivy result kinds"),
                };
                let aliases = if field == "Vulnerabilities" {
                    reported_advisory_aliases(
                        string_advisory_ids(object.get("VendorIDs")),
                        &rule_id,
                    )
                } else {
                    Vec::new()
                };
                records.push(with_advisory_aliases(
                    with_weakness(
                        with_scanner_details(
                            record_with_derived_confidence!(
                                format!("/Results/{result_index}/{field}/{item_index}"),
                                rule_id,
                                title,
                                string_any(object, &["Severity"])
                                    .unwrap_or_else(|| "unknown".into()),
                                location,
                                asset_hint,
                                derived_confidence(confidence_basis),
                                kind.clone(),
                                references_from(item),
                                tags,
                            ),
                            string_any(object, &["Description"]),
                            None,
                            string_any(object, &["InstalledVersion"]),
                            string_any(object, &["FixedVersion"]),
                        ),
                        trivy_weakness(object),
                    ),
                    aliases,
                ));
                if records.len() >= MAX_RECORDS {
                    return records;
                }
            }
        }
    }
    records
}

/// Trivy's own classification for one result.
///
/// Trivy publishes a score per scoring vendor under `CVSS`, keyed by that
/// vendor (`nvd`, `redhat`, `ghsa`), and each key may carry a v2, v3, and v4
/// pair. Every published score is kept with its vendor attached: which vendor
/// scored a vulnerability 9.8 and which scored it 5.3 is the reader's call to
/// make, not this product's.
fn trivy_weakness(object: &Map<String, Value>) -> UpstreamWeakness {
    let cwe_ids = cwe_identifiers(object.get("CweIDs").or_else(|| object.get("cweIDs")));
    let mut cvss = Vec::new();
    if let Some(sources) = object.get("CVSS").and_then(Value::as_object) {
        for (vendor, scores) in sources {
            for (vector_key, score_key) in [
                ("V4Vector", "V4Score"),
                ("V3Vector", "V3Score"),
                ("V2Vector", "V2Score"),
            ] {
                if cvss.len() >= MAX_CVSS_SCORES {
                    break;
                }
                if let Some(score) = cvss_score(
                    vendor,
                    scores
                        .get(vector_key)
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    cvss_base_score(scores.get(score_key)),
                ) {
                    cvss.push(score);
                }
            }
        }
    }
    UpstreamWeakness { cwe_ids, cvss }
}

fn extract_grype(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed) else {
        push_warning(warnings, "Grype expected a JSON document");
        return Vec::new();
    };
    let Some(matches) = root.get("matches").and_then(Value::as_array) else {
        push_warning(
            warnings,
            "Grype output lacked its matches array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter",
        );
        return Vec::new();
    };
    matches
        .iter()
        .take(MAX_RECORDS)
        .enumerate()
        .filter_map(|(index, value)| {
            let pointer = format!("/matches/{index}");
            let Some(object) = value.as_object() else {
                push_warning(
                    warnings,
                    format!(
                        "Grype match at {pointer} was not an object; the raw record was retained"
                    ),
                );
                return None;
            };
            let Some(rule_id) = exact_nested_rule_scalar(value, &["vulnerability", "id"]) else {
                push_warning(
                    warnings,
                    format!(
                        "Grype match at {pointer} lacked vulnerability.id; the raw record was retained"
                    ),
                );
                return None;
            };
            let package =
                nested_string(value, &["artifact", "name"]).unwrap_or_else(|| "package".into());
            let location = nested_string(value, &["artifact", "locations", "0", "path"])
                .unwrap_or_else(|| package.clone());
            // Only each related vulnerability's id. Its scores, CWE, and
            // description stay unread; `grype_weakness` reads the direct block.
            let aliases = reported_advisory_aliases(
                object_advisory_ids(value.get("relatedVulnerabilities")),
                &rule_id,
            );
            Some(with_advisory_aliases(with_weakness(
                with_scanner_details(
                    record_with_derived_confidence!(
                        pointer,
                        rule_id.clone(),
                        format!("Vulnerable package {package} ({rule_id})"),
                        nested_string(value, &["vulnerability", "severity"])
                            .unwrap_or_else(|| "unknown".into()),
                        location,
                        string_any(object, &["asset_id"]),
                        derived_confidence(ConfidenceBasisCode::AdvisoryVersionMatch),
                        EvidenceKind::PackageInventory,
                        references_from(value),
                        vec![format!("package:{}", safe_tag(&package))],
                    ),
                    nested_string(value, &["vulnerability", "description"]),
                    None,
                    nested_string(value, &["artifact", "version"]),
                    bounded_string_list(value.pointer("/vulnerability/fix/versions"), 16),
                ),
                grype_weakness(value),
            ), aliases))
        })
        .collect()
}

/// Grype's own classification for one match.
///
/// Grype lists each upstream score as its own object carrying the source that
/// published it, and repeats the same vulnerability's scores from `relatedVulnerabilities`
/// when the advisory it matched only points at another one. Only the direct
/// `vulnerability` block is read: a related advisory's score is a score for a
/// different identifier.
fn grype_weakness(value: &Value) -> UpstreamWeakness {
    let mut cvss = Vec::new();
    if let Some(entries) = value
        .pointer("/vulnerability/cvss")
        .and_then(Value::as_array)
    {
        for entry in entries.iter().take(MAX_CVSS_SCORES) {
            let vector = entry
                .get("vector")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let source = entry
                .get("source")
                .and_then(Value::as_str)
                .filter(|source| !source.is_empty())
                .unwrap_or("grype");
            if let Some(mut score) = cvss_score(
                source,
                vector,
                cvss_base_score(entry.pointer("/metrics/baseScore")),
            ) {
                // Grype names the version outright; prefer it over the one this
                // product would infer from the vector prefix.
                if let Some(version) = entry
                    .get("version")
                    .and_then(Value::as_str)
                    .filter(|version| !version.is_empty() && version.len() <= 8)
                {
                    score.version = version.to_owned();
                }
                cvss.push(score);
            }
        }
    }
    UpstreamWeakness {
        cwe_ids: Vec::new(),
        cvss,
    }
}

/// What Kubescape's `summaryDetails.controls` roll-up knows about a control.
struct KubescapeControlSummary {
    name: Option<String>,
    /// Kubescape grades controls 1-10, the same direction and range the shared
    /// numeric severity branch already reads, so the roll-up's score passes
    /// straight through rather than through a second scale invented here.
    score_factor: Option<String>,
}

/// Read Kubescape's v2 posture report.
///
/// `results[].controls[].status` is an object (`{status, subStatus, info}`), so
/// scanning for a string `status` matches only the `summaryDetails.controls`
/// roll-up and silently loses every per-resource result. The roll-up says how
/// bad a control is; `results` says which resource actually failed it, which is
/// the part a reader needs in order to fix anything.
fn extract_kubescape(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed).and_then(Value::as_object) else {
        push_warning(warnings, "Kubescape expected a JSON document");
        return Vec::new();
    };

    let summary_controls = root
        .get("summaryDetails")
        .and_then(Value::as_object)
        .and_then(|summary| summary.get("controls"))
        .and_then(Value::as_object);
    if root.contains_key("summaryDetails") && summary_controls.is_none() {
        push_warning(
            warnings,
            "Kubescape summaryDetails lacked its controls object; result processing is incomplete",
        );
    }
    let mut summaries: BTreeMap<String, KubescapeControlSummary> = BTreeMap::new();
    for (control_id, control) in summary_controls.into_iter().flatten() {
        let Some(control) = control.as_object() else {
            push_warning(
                warnings,
                "Kubescape summary control was not an object; result processing is incomplete",
            );
            continue;
        };
        if control_id.trim().is_empty() || control_id.len() > MAX_SHORT_TEXT {
            push_warning(
                warnings,
                "Kubescape summary control lacked a valid control ID; result processing is incomplete",
            );
            continue;
        }
        kubescape_control_failed(
            control,
            &format!("/summaryDetails/controls/{control_id}"),
            warnings,
        );
        summaries.insert(
            control_id.clone(),
            KubescapeControlSummary {
                name: string_any(control, &["name"]),
                score_factor: control
                    .get("scoreFactor")
                    .and_then(Value::as_f64)
                    .map(|score| score.to_string()),
            },
        );
    }

    let mut records = Vec::new();
    let results = root.get("results").and_then(Value::as_array);
    if results.is_none() {
        push_warning(
            warnings,
            "Kubescape output lacked its results array; result processing is incomplete",
        );
    }
    let mut evaluated_controls = 0_usize;
    for (index, result) in results.into_iter().flatten().enumerate() {
        let Some(result) = result.as_object() else {
            push_warning(
                warnings,
                format!(
                    "Kubescape result at /results/{index} was not an object; result processing is incomplete"
                ),
            );
            continue;
        };
        let location = string_any(result, &["resourceID", "resource"])
            .unwrap_or_else(|| "kubernetes-resource".into());
        // Upstream uses omitempty for resources with no associated controls.
        let controls = result.get("controls").and_then(Value::as_array);
        if result.contains_key("controls") && controls.is_none() {
            push_warning(
                warnings,
                format!(
                    "Kubescape result at /results/{index} had an invalid controls array; result processing is incomplete"
                ),
            );
        }
        for (control_index, control) in controls.into_iter().flatten().enumerate() {
            if records.len() >= MAX_RECORDS {
                return records;
            }
            let Some(control) = control.as_object() else {
                push_warning(
                    warnings,
                    format!(
                        "Kubescape control at /results/{index}/controls/{control_index} was not an object; result processing is incomplete"
                    ),
                );
                continue;
            };
            // v2 nests the verdict; older shapes put a plain string here.
            let pointer = format!("/results/{index}/controls/{control_index}");
            let Some(failed) = kubescape_control_failed(control, &pointer, warnings) else {
                continue;
            };
            let Some(rule_id) = exact_rule_string_any(control, &["controlID"]) else {
                push_warning(
                    warnings,
                    format!(
                        "Kubescape control at {pointer} lacked its controlID; result processing is incomplete"
                    ),
                );
                continue;
            };
            evaluated_controls += 1;
            if !failed {
                continue;
            }
            let summary = summaries.get(&rule_id);
            records.push(record_with_derived_confidence!(
                format!("/results/{index}/controls/{control_index}"),
                rule_id.clone(),
                string_any(control, &["name"])
                    .or_else(|| summary.and_then(|summary| summary.name.clone()))
                    .unwrap_or_else(|| format!("Kubescape control {rule_id}")),
                summary
                    .and_then(|summary| summary.score_factor.clone())
                    .unwrap_or_else(|| "unknown".into()),
                location.clone(),
                None,
                derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
                EvidenceKind::Configuration,
                references_from(control.get("rules").unwrap_or(&Value::Null)),
                vec![],
            ));
        }
    }

    // A report can carry the roll-up without per-resource results. A failing
    // control is still a finding then; it just cannot name a resource.
    if records.is_empty() {
        for (rule_id, control) in summary_controls.into_iter().flatten() {
            if records.len() >= MAX_RECORDS {
                break;
            }
            let Some(object) = control.as_object() else {
                continue;
            };
            let pointer = format!("/summaryDetails/controls/{rule_id}");
            if kubescape_control_failed(object, &pointer, warnings) != Some(true) {
                continue;
            }
            push_warning(
                warnings,
                "Kubescape reported failing summary controls without matching resource findings; result processing is incomplete",
            );
            let Some(summary) = summaries.get(rule_id) else {
                continue;
            };
            records.push(record_with_derived_confidence!(
                format!("/summaryDetails/controls/{rule_id}"),
                rule_id.clone(),
                summary
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("Kubescape control {rule_id}")),
                summary
                    .score_factor
                    .clone()
                    .unwrap_or_else(|| "unknown".into()),
                "kubernetes-cluster".to_owned(),
                None,
                derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
                EvidenceKind::Configuration,
                vec![],
                vec![],
            ));
        }
    }
    if evaluated_controls == 0 {
        push_warning(
            warnings,
            "Kubescape output contained no evaluated resource controls; check coverage is incomplete",
        );
    }
    records
}

/// OPA-utils v0.0.303 owns these verdicts. An error or skipped evaluation is
/// coverage evidence, never a vulnerability or a passing control.
fn kubescape_control_failed(
    control: &Map<String, Value>,
    pointer: &str,
    warnings: &mut Vec<String>,
) -> Option<bool> {
    let status = control
        .get("statusInfo")
        .and_then(Value::as_object)
        .and_then(|status| string_any(status, &["status"]))
        .or_else(|| {
            control
                .get("status")
                .and_then(Value::as_object)
                .and_then(|status| string_any(status, &["status"]))
        })
        .or_else(|| string_any(control, &["status"]));
    match status.as_deref() {
        Some("failed") => Some(true),
        Some("passed" | "excluded" | "irrelevant") => Some(false),
        Some("skipped" | "error") => {
            push_warning(
                warnings,
                format!(
                    "Kubescape control at {pointer} was not evaluated; check coverage is incomplete"
                ),
            );
            None
        }
        _ => {
            push_warning(
                warnings,
                format!(
                    "Kubescape control at {pointer} lacked a supported status; result processing is incomplete"
                ),
            );
            None
        }
    }
}

fn extract_kube_bench(parsed: &ParsedArtifact, warnings: &mut Vec<String>) -> Vec<SourceRecord> {
    let Some(root) = json_root(parsed) else {
        push_warning(warnings, "kube-bench expected a JSON document");
        return Vec::new();
    };
    let controls = root
        .get("Controls")
        .or_else(|| root.get("controls"))
        .and_then(Value::as_array);
    let Some(controls) = controls else {
        push_warning(
            warnings,
            "kube-bench output lacked its Controls array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter",
        );
        return Vec::new();
    };
    let mut records = Vec::new();
    for (control_index, control) in controls.iter().enumerate() {
        let tests = control
            .get("tests")
            .and_then(Value::as_array)
            .into_iter()
            .flatten();
        for (test_index, test) in tests.enumerate() {
            let results = test
                .get("results")
                .and_then(Value::as_array)
                .into_iter()
                .flatten();
            for (result_index, value) in results.enumerate() {
                let Some(object) = value.as_object() else {
                    continue;
                };
                let status = string_any(object, &["status"]).unwrap_or_default();
                if !is_failure(&status) {
                    continue;
                }
                let Some(rule_id) = exact_rule_string_any(object, &["test_number", "id"]) else {
                    continue;
                };
                records.push(with_scanner_details(
                    record_with_derived_severity_and_confidence!(
                        format!(
                            "/Controls/{control_index}/tests/{test_index}/results/{result_index}"
                        ),
                        rule_id.clone(),
                        string_any(object, &["test_desc", "desc"])
                            .unwrap_or_else(|| format!("kube-bench control {rule_id}")),
                        // kube-bench's native JSON `Check` carries no severity
                        // field. Its failure and evidence remain intact while the
                        // absent upstream rating stays Unknown.
                        DerivedSeverity {
                            severity: Severity::Unknown,
                            code: SeverityBasisCode::CisKubernetesBenchmark,
                        },
                        string_any(object, &["resource", "node_type"])
                            .unwrap_or_else(|| "kubernetes-cluster".into()),
                        string_any(object, &["asset_id"]),
                        derived_confidence(ConfidenceBasisCode::DeterministicPolicyEvaluation),
                        EvidenceKind::Configuration,
                        references_from(value),
                        vec![],
                    ),
                    None,
                    string_any(object, &["remediation"]),
                    None,
                    None,
                ));
                if records.len() >= MAX_RECORDS {
                    return records;
                }
            }
        }
    }
    records
}

fn merge_finding(
    findings: &mut BTreeMap<String, Finding>,
    adapter: &BuiltinAdapter,
    input: &AdapterInput<'_>,
    artifact: &RawArtifact,
    record: SourceRecord,
    asset_id: String,
) {
    let aws_iam_policy = record
        .scanner_details
        .as_ref()
        .and_then(|details| details.aws_iam_policy.clone());
    let rule_id = record.rule_id.clone();
    let family = record
        .family_override
        .unwrap_or_else(|| family_for(adapter.profile));
    let location = redact_location(&record.location);
    let fingerprint_identity = record
        .fingerprint_identity
        .as_deref()
        .unwrap_or(&record.rule_identity);
    let fingerprint = stable_fingerprint(adapter.id, fingerprint_identity, &asset_id, &location);
    let finding_id = format!(
        "finding-{}",
        &fingerprint.rsplit(':').next().unwrap_or(&fingerprint)[..32]
    );
    let result_pointer_sha256 = hex::encode(Sha256::digest(record.pointer.as_bytes()));
    let evidence_id = stable_evidence_id(
        &fingerprint,
        adapter.id,
        &record.rule_identity,
        &artifact.sha256,
        &result_pointer_sha256,
        input.engine_run_id,
    );
    let evidence = Evidence {
        id: evidence_id,
        finding_id: finding_id.clone(),
        run_id: input.scan_run_id.to_owned(),
        engine_run_id: Some(input.engine_run_id.to_owned()),
        kind: record.evidence_kind,
        engine_id: adapter.id.to_owned(),
        scanner_details: record.scanner_details.clone(),
        source_rule: record.mapping_source_rule.clone(),
        result_pointer_sha256: Some(result_pointer_sha256),
        observed_at: artifact.created_at,
        summary: format!(
            "{} reported rule {} at {}. Raw target text is retained only as untrusted evidence.",
            adapter.id,
            rule_id,
            safe_text(&location, MAX_SHORT_TEXT)
        ),
        location: Some(location.clone()),
        artifact_id: artifact.id.clone(),
        artifact_sha256: artifact.sha256.clone(),
        pointer: Some(safe_text(&record.pointer, MAX_SHORT_TEXT)),
        redacted: matches!(adapter.profile, Profile::Gitleaks | Profile::Trufflehog),
    };

    if let Some(existing) = findings.get_mut(&fingerprint) {
        if !existing.evidence.iter().any(|item| item.id == evidence.id) {
            existing.evidence.push(evidence);
        }
        return;
    }

    let mut official_references = vec![input.manifest.repository_url.clone()];
    if let Some(homepage) = &input.manifest.homepage_url {
        official_references.push(homepage.clone());
    }
    official_references.extend(
        record
            .references
            .into_iter()
            .filter_map(safe_https_reference),
    );
    official_references.sort();
    official_references.dedup();
    official_references.truncate(12);

    let severity = record.severity;
    let confidence = record.confidence;
    let severity_basis = record.severity_basis;
    let confidence_basis = record.confidence_basis;
    let exposure_observation = severity_basis.is_some_and(|code| code.is_exposure_observation());
    let scanner_severity_unrated =
        matches!(severity, Severity::Unknown) && severity_basis.is_some() && !exposure_observation;
    let priority = if exposure_observation {
        0
    } else {
        priority_for(&severity)
    };
    let mut tags = vec![
        format!("engine:{}", adapter.id),
        format!("source-rule:{}", safe_tag(&rule_id)),
    ];
    // Exactly one of these records whether the scanner supplied a rating, this
    // product supplied one, or the missing value stayed honestly Unknown.
    match (&severity_basis, scanner_severity_unrated) {
        (Some(_), true) => tags.push("severity-basis:unrated".into()),
        (Some(_), false) => tags.push("severity-basis:derived".into()),
        (None, _) => tags.push(format!(
            "source-severity:{}",
            safe_tag(&record.source_severity)
        )),
    }
    match &confidence_basis {
        Some(ConfidenceBasisCode::MissingDetectionQualityScore) => {
            tags.push("confidence-basis:unavailable".into());
        }
        Some(_) => tags.push("confidence-basis:derived".into()),
        None => tags.push(format!(
            "source-confidence:{}",
            safe_tag(&record.source_confidence)
        )),
    }
    tags.extend(
        record
            .tags
            .into_iter()
            .map(|tag| safe_text(&tag, MAX_SHORT_TEXT)),
    );
    tags.sort();
    tags.dedup();
    tags.truncate(32);

    let title = safe_text(&record.title, MAX_SHORT_TEXT);
    let impact = if exposure_observation {
        "The service responded within the tested scope. Reachability alone does not identify a vulnerability.".into()
    } else {
        impact_for(adapter.profile, family, &severity, severity_basis)
    };
    let plain_language_summary = if exposure_observation {
        format!(
            "{} observed a reachable service on the assessed asset. Reachability is inventory evidence, not a vulnerability.",
            input.manifest.display_name,
        )
    } else {
        format!(
            "{} {}",
            match (&severity_basis, scanner_severity_unrated) {
                (Some(_), true) => format!(
                    "{} reported this condition without a severity rating. Severity is Unknown.",
                    input.manifest.display_name,
                ),
                (Some(code), false) => format!(
                    "{} reported this condition on the assessed asset without rating it. This product rated it {} from {}.",
                    input.manifest.display_name,
                    severity_label(&severity),
                    basis_text(*code)
                ),
                (None, _) => format!(
                    "{} reported {} {}-severity condition on the assessed asset.",
                    input.manifest.display_name,
                    severity_article(&severity),
                    severity_label(&severity)
                ),
            },
            match &confidence_basis {
                Some(ConfidenceBasisCode::MissingDetectionQualityScore) => format!(
                    "{} did not report detection quality for it.",
                    input.manifest.display_name,
                ),
                Some(code) => format!(
                    "{} reported no confidence rating for it. This product rated its confidence {} from {}.",
                    input.manifest.display_name,
                    confidence_label(&confidence),
                    confidence_basis_text(*code)
                ),
                None => format!(
                    "{} reported confidence {} for it; this product maps that to {} confidence.",
                    input.manifest.display_name,
                    safe_text(&record.source_confidence, 80),
                    confidence_label(&confidence)
                ),
            }
        )
    };
    let priority_reasons = if exposure_observation {
        vec![crate::finding_narrative::ENGLISH_EXPOSURE_OBSERVATION_REASON.into()]
    } else {
        vec![
            match (&severity_basis, scanner_severity_unrated) {
                (Some(_), true) => format!(
                    "Severity is Unknown because {} did not provide a rating.",
                    input.manifest.display_name
                ),
                (Some(code), false) => format!(
                    "Severity derived from {}; {} reports no severity of its own.",
                    basis_text(*code),
                    input.manifest.display_name
                ),
                (None, _) => format!(
                    "Source severity: {}",
                    safe_text(&record.source_severity, 80)
                ),
            },
            match &confidence_basis {
                Some(ConfidenceBasisCode::MissingDetectionQualityScore) => format!(
                    "{} did not report detection quality.",
                    input.manifest.display_name,
                ),
                Some(code) => format!(
                    "Confidence derived from {}; {} reports no confidence of its own.",
                    confidence_basis_text(*code),
                    input.manifest.display_name
                ),
                None => format!(
                    "Source confidence: {}",
                    safe_text(&record.source_confidence, 80)
                ),
            },
        ]
    };
    let recommendation = if exposure_observation {
        "Confirm that the reachable service is expected, then run an applicable security check against it."
            .into()
    } else if let Some(details) = aws_iam_policy.as_ref() {
        crate::finding_narrative::aws_iam_policy_action_english(adapter.expert_type, details)
    } else {
        format!("{}.", remedy_for(adapter.profile, family))
    };
    let verification_guidance = if exposure_observation {
        format!(
            "Repeat {} discovery with the same target and scope to confirm whether the service is still reachable.",
            input.manifest.display_name
        )
    } else {
        format!(
            "Rerun {} with the same scope after the change and confirm that source rule {} is no longer reported.",
            input.manifest.display_name, rule_id
        )
    };
    findings.insert(
        fingerprint.clone(),
        Finding {
            id: finding_id,
            case_id: input.case_id.to_owned(),
            first_seen_run_id: input.scan_run_id.to_owned(),
            last_seen_run_id: input.scan_run_id.to_owned(),
            fingerprint,
            title,
            plain_language_summary,
            possible_impact: impact,
            severity,
            confidence,
            priority,
            priority_reasons,
            asset_ids: vec![asset_id],
            evidence: vec![evidence],
            control_references: mapping_control_references(
                adapter.id,
                record.mapping_source_rule.as_deref(),
                record
                    .scanner_details
                    .as_ref()
                    .map(|details| details.cwe_ids.as_slice())
                    .unwrap_or_default(),
                input.ai_system_applicable,
                input.ai_generated_artifact_applicable,
            ),
            recommendation,
            verification_guidance,
            rollback_considerations: (!exposure_observation)
                .then(|| crate::finding_narrative::ENGLISH_ROLLBACK.into()),
            official_references,
            recommended_expert_type: adapter.expert_type.into(),
            status: FindingStatus::Unreviewed,
            tags,
            // The codes the prose above was composed from, so a client that
            // renders in another language composes its own sentence rather
            // than showing a translated heading over an English paragraph.
            family: Some(family),
            severity_basis_code: severity_basis,
            confidence_basis_code: confidence_basis,
            context_factors: Vec::new(),
        },
    );
}

fn record_from_draft(draft: RecordDraft) -> SourceRecord {
    let mapping_source_rule = exact_mapping_source_rule(&draft.rule_id);
    let rule_identity = mapping_source_rule.clone().unwrap_or_else(|| {
        let mut hasher = Sha256::new();
        hasher.update(b"ai-security-scanner.unmappable-source-rule");
        hasher.update([0]);
        hasher.update(draft.rule_id.as_bytes());
        format!("unmappable-sha256:{}", hex::encode(hasher.finalize()))
    });
    let reported_severity = safe_text(&draft.source_severity, 80);
    let (severity, source_severity, severity_basis) = match draft.derived_severity {
        // The engine reported nothing, so the source severity stays empty. The
        // canonical fallback and its basis remain separate; current upstream
        // omissions use Unknown rather than inventing a scanner rating.
        Some(derived) if reported_severity.is_empty() => {
            (derived.severity, String::new(), Some(derived.code))
        }
        // A rating the engine did give always wins, including one this product
        // does not recognize: that has to surface as unknown and needing review,
        // not be replaced by a derivation.
        _ => (
            parse_severity(&draft.source_severity),
            reported_severity,
            None,
        ),
    };
    let reported_confidence = safe_text(&draft.source_confidence, 80);
    let (confidence, source_confidence, confidence_basis) = match draft.derived_confidence {
        // The engine reported nothing, so the source confidence stays empty
        // rather than borrowing the derived level. Nothing downstream may
        // present the derived rating as the engine's own.
        Some(derived) if reported_confidence.is_empty() => {
            (derived.confidence, String::new(), Some(derived.code))
        }
        // A value the engine gave always wins. A derivation only fills a gap;
        // even an unfamiliar source value must not be replaced and presented
        // as though it came from this product.
        _ => (
            parse_confidence(&draft.source_confidence),
            reported_confidence,
            None,
        ),
    };
    debug_assert!(
        confidence_basis.is_some() ^ !source_confidence.is_empty(),
        "every confidence must be either a non-empty engine value or a disclosed derivation"
    );
    if let Some(code) = confidence_basis {
        debug_assert!(!confidence_basis_text(code).is_empty());
        debug_assert!(
            crate::finding_narrative::confidence_basis_zh_hant(code)
                .chars()
                .any(|character| ('\u{3400}'..='\u{9fff}').contains(&character)),
            "every derived confidence basis must have a Chinese form"
        );
    }
    SourceRecord {
        pointer: safe_text(&draft.pointer, MAX_SHORT_TEXT),
        rule_id: safe_text(&draft.rule_id, MAX_SHORT_TEXT),
        mapping_source_rule,
        rule_identity,
        fingerprint_identity: None,
        title: safe_text(&draft.title, MAX_SHORT_TEXT),
        severity,
        source_severity,
        severity_basis,
        location: redact_location(&draft.location),
        asset_hint: draft
            .asset_hint
            .map(|value| safe_text(&value, MAX_SHORT_TEXT)),
        asset_provider: None,
        confidence,
        source_confidence,
        confidence_basis,
        evidence_kind: draft.evidence_kind,
        scanner_details: None,
        references: draft.references,
        tags: draft.tags,
        family_override: None,
    }
}

fn exact_mapping_source_rule(value: &str) -> Option<String> {
    if value.is_empty()
        || value.chars().count() > MAX_SHORT_TEXT
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        None
    } else {
        Some(value.to_owned())
    }
}

/// Every reviewed control this result relates to, by both routes the catalog
/// offers.
///
/// The rule route is the scanner's own identifier matched against a reviewed
/// entry. The CWE route is the scanner's own weakness classification matched
/// against the CWE sets OWASP publishes for each Top 10 category. A result
/// reached by both keeps one copy of each coordinate.
fn mapping_control_references(
    engine_id: &str,
    mapping_source_rule: Option<&str>,
    cwe_ids: &[String],
    ai_system_applicable: bool,
    ai_generated_artifact_applicable: bool,
) -> Vec<crate::domain::ControlReference> {
    let mut references = mapping_source_rule
        .map(|source_rule| {
            control_mapping::lookup(
                engine_id,
                source_rule,
                ai_system_applicable,
                ai_generated_artifact_applicable,
            )
        })
        .unwrap_or_default();
    for derived in control_mapping::lookup_by_cwe(
        cwe_ids,
        ai_system_applicable,
        ai_generated_artifact_applicable,
    ) {
        if !references.iter().any(|existing| {
            existing.framework == derived.framework && existing.control_id == derived.control_id
        }) {
            references.push(derived);
        }
    }
    references
}

fn resolve_asset(
    record: &SourceRecord,
    allowed_assets: &[String],
    asset_identifier_map: &crate::adapter::AdapterAssetIdentifierMap,
    warnings: &mut Vec<String>,
    unmatched_identifiers: &mut BTreeMap<(String, String), usize>,
) -> Option<String> {
    resolve_asset_coordinates(
        &record.rule_id,
        record.asset_hint.as_deref(),
        record.asset_provider.as_deref(),
        allowed_assets,
        asset_identifier_map,
        warnings,
        unmatched_identifiers,
    )
}

fn resolve_asset_coordinates(
    rule_id: &str,
    asset_hint: Option<&str>,
    asset_provider: Option<&str>,
    allowed_assets: &[String],
    asset_identifier_map: &crate::adapter::AdapterAssetIdentifierMap,
    warnings: &mut Vec<String>,
    unmatched_identifiers: &mut BTreeMap<(String, String), usize>,
) -> Option<String> {
    if let Some(hint) = asset_hint {
        if asset_provider.is_none() && allowed_assets.iter().any(|asset| asset == hint) {
            return Some(hint.to_owned());
        }

        if let Some(candidates) = asset_identifier_map.candidates(asset_provider, hint) {
            let authorized = candidates
                .iter()
                .filter(|candidate| allowed_assets.iter().any(|asset| asset == *candidate))
                .collect::<Vec<_>>();
            if authorized.len() == 1 {
                return authorized.first().map(|asset| (*asset).clone());
            }
            if authorized.len() > 1 {
                push_warning(
                    warnings,
                    format!(
                        "record {} matched an ambiguous native asset identifier and was not normalized",
                        safe_text(rule_id, 120)
                    ),
                );
                return None;
            }
        }

        // A provider-qualified OCSF account is authoritative. Falling back to
        // the only selected asset would silently misattribute a provider or
        // account mismatch.
        if let Some(provider) = asset_provider {
            push_warning(
                warnings,
                format!(
                    "record {} had no exact authorized provider identifier match and was not normalized",
                    safe_text(rule_id, 120)
                ),
            );
            // Bounded because both halves come from the scanned artifact.
            // Beyond the cap the counts stay accurate for what is already
            // tracked rather than growing without limit on hostile input.
            let key = (
                safe_text(provider, 60).to_ascii_lowercase(),
                safe_text(hint, 120),
            );
            if unmatched_identifiers.len() < MAX_UNMATCHED_IDENTIFIERS
                || unmatched_identifiers.contains_key(&key)
            {
                *unmatched_identifiers.entry(key).or_insert(0) += 1;
            }
            return None;
        }
    }
    if allowed_assets.len() == 1 {
        return allowed_assets.first().cloned();
    }
    push_warning(
        warnings,
        format!(
            "record {} could not be mapped unambiguously to an authorized asset and was not normalized",
            safe_text(rule_id, 120)
        ),
    );
    None
}

fn resolve_inventory_asset(
    record: &InventoryRecord,
    allowed_assets: &[String],
    asset_identifier_map: &crate::adapter::AdapterAssetIdentifierMap,
    warnings: &mut Vec<String>,
    unmatched_identifiers: &mut BTreeMap<(String, String), usize>,
) -> Option<String> {
    if let Some(hint) = record.asset_hint.as_deref() {
        if record.asset_provider.is_none() {
            if allowed_assets.iter().any(|asset| asset == hint) {
                return Some(hint.to_owned());
            }
            push_warning(
                warnings,
                "inventory record named an asset outside this engine task and was not normalized",
            );
            return None;
        }

        if let Some(candidates) =
            asset_identifier_map.candidates(record.asset_provider.as_deref(), hint)
        {
            let authorized = candidates
                .iter()
                .filter(|candidate| allowed_assets.iter().any(|asset| asset == *candidate))
                .collect::<Vec<_>>();
            if authorized.len() == 1 {
                return authorized.first().map(|asset| (*asset).clone());
            }
            if authorized.len() > 1 {
                push_warning(
                    warnings,
                    "inventory record matched an ambiguous native asset identifier and was not normalized",
                );
                return None;
            }
        }

        let provider = record
            .asset_provider
            .as_deref()
            .unwrap_or("unknown-provider");
        push_warning(
            warnings,
            "inventory record had no exact authorized provider identifier match and was not normalized",
        );
        let key = (
            safe_text(provider, 60).to_ascii_lowercase(),
            safe_text(hint, 120),
        );
        if unmatched_identifiers.len() < MAX_UNMATCHED_IDENTIFIERS
            || unmatched_identifiers.contains_key(&key)
        {
            *unmatched_identifiers.entry(key).or_insert(0) += 1;
        }
        return None;
    }

    if allowed_assets.len() == 1 {
        return allowed_assets.first().cloned();
    }
    push_warning(
        warnings,
        "inventory record carried no asset identifier in a multi-asset task and was not normalized",
    );
    None
}

fn merge_inventory_observation(
    observations: &mut BTreeMap<String, InventoryObservation>,
    adapter: &BuiltinAdapter,
    input: &AdapterInput<'_>,
    artifact: &RawArtifact,
    record: InventoryRecord,
    asset_id: String,
) {
    let kind_bytes = serde_json::to_vec(&record.kind).unwrap_or_default();
    let mut hasher = Sha256::new();
    for component in [
        b"ai-security-scanner.inventory-observation-v1".as_slice(),
        input.case_id.as_bytes(),
        input.scan_run_id.as_bytes(),
        input.engine_run_id.as_bytes(),
        adapter.id.as_bytes(),
        asset_id.as_bytes(),
        artifact.sha256.as_bytes(),
        record.pointer.as_bytes(),
        kind_bytes.as_slice(),
    ] {
        hasher.update(component);
        hasher.update([0]);
    }
    let id = format!("inventory-{}", &hex::encode(hasher.finalize())[..32]);
    observations
        .entry(id.clone())
        .or_insert(InventoryObservation {
            id,
            case_id: input.case_id.to_owned(),
            run_id: input.scan_run_id.to_owned(),
            engine_run_id: input.engine_run_id.to_owned(),
            asset_id,
            engine_id: adapter.id.to_owned(),
            kind: record.kind,
            artifact_id: artifact.id.clone(),
            artifact_sha256: artifact.sha256.clone(),
            pointer: inventory_text(Some(record.pointer), MAX_SHORT_TEXT)
                .unwrap_or_else(|| "/".into()),
            observed_at: artifact.created_at,
        });
}

fn stable_fingerprint(engine: &str, rule: &str, asset: &str, location: &str) -> String {
    let mut hasher = Sha256::new();
    for component in [FINGERPRINT_SCHEMA_VERSION, engine, rule, asset, location] {
        hasher.update(component.as_bytes());
        hasher.update([0]);
    }
    format!("{engine}:{}", hex::encode(hasher.finalize()))
}

pub(crate) fn stable_evidence_id(
    fingerprint: &str,
    engine_id: &str,
    source_rule: &str,
    artifact_hash: &str,
    result_pointer_sha256: &str,
    engine_run_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    for component in [
        "ai-security-scanner.evidence-id",
        EVIDENCE_ID_SCHEMA_VERSION,
        fingerprint,
        engine_id,
        source_rule,
        artifact_hash,
        result_pointer_sha256,
        engine_run_id,
    ] {
        hasher.update(component.as_bytes());
        hasher.update([0]);
    }
    format!("evidence-{}", &hex::encode(hasher.finalize())[..32])
}

fn parse_severity(value: &str) -> Severity {
    let normalized = value.trim().to_ascii_lowercase();
    if let Ok(score) = normalized.parse::<f64>() {
        return if !score.is_finite() || !(0.0..=10.0).contains(&score) {
            Severity::Unknown
        } else if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Informational
        };
    }
    match normalized.as_str() {
        "critical" | "fatal" => Severity::Critical,
        // ScoutSuite grades every rule `danger` or `warning`; 125 of its 197
        // default AWS rules are `danger`, so leaving it unmapped sent the
        // majority of that engine's output to `Unknown`.
        "high" | "error" | "danger" => Severity::High,
        "medium" | "moderate" | "warning" | "warn" => Severity::Medium,
        "low" | "minor" => Severity::Low,
        "informational" | "info" | "log" | "none" | "negligible" => Severity::Informational,
        _ => Severity::Unknown,
    }
}

fn parse_confidence(value: &str) -> Confidence {
    let normalized = value.trim().to_ascii_lowercase();
    if let Ok(score) = normalized.parse::<u8>() {
        return match score {
            80..=100 => Confidence::High,
            50..=79 => Confidence::Medium,
            _ => Confidence::Low,
        };
    }
    match normalized.as_str() {
        "confirmed" => Confidence::Confirmed,
        "high" => Confidence::High,
        "medium" | "moderate" => Confidence::Medium,
        "low" => Confidence::Low,
        // Preserve an unfamiliar engine word in source_confidence without
        // converting it into a confidence rating the engine did not provide.
        _ => Confidence::Unknown,
    }
}

fn priority_for(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 95,
        Severity::High => 80,
        Severity::Medium => 60,
        Severity::Low => 35,
        // Unknown impact stays above a known informational observation so it
        // is not buried as low risk, while never pretending to be Low/Medium.
        Severity::Unknown => 20,
        Severity::Informational => 15,
    }
}

fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Unknown => "unknown",
        Severity::Informational => "informational",
    }
}

fn confidence_label(confidence: &Confidence) -> &'static str {
    match confidence {
        Confidence::Unknown => "unknown",
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
        Confidence::Confirmed => "confirmed",
    }
}

/// The English article that precedes a severity label.
///
/// `informational` and `unknown` both open with a vowel sound, so the fixed
/// "a" this sentence used to carry produced "reported a informational-severity
/// condition" — on the first line of the first thing a beginner reads about a
/// finding. Matched on the variant rather than sniffed from the first letter so
/// that adding a severity forces the choice instead of inheriting a wrong one.
fn severity_article(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High | Severity::Medium | Severity::Low => "a",
        Severity::Informational | Severity::Unknown => "an",
    }
}

fn impact_for(
    profile: Profile,
    family: FindingFamily,
    _severity: &Severity,
    _severity_basis: Option<SeverityBasisCode>,
) -> String {
    let consequence = match profile {
        Profile::CloudQuery | Profile::Steampipe | Profile::Prowler | Profile::ScoutSuite => {
            "cloud resources or data may be exposed, changed, or used beyond the organization's intent"
        }
        Profile::Cloudsplaining => {
            "an identity may be able to perform broader actions than its role requires"
        }
        Profile::ScubaGear | Profile::Maester => {
            "Microsoft 365 identities, messages, files, or administrative settings may have weaker protection"
        }
        Profile::Naabu | Profile::Httpx | Profile::Nuclei | Profile::Greenbone | Profile::Zap => {
            "an internet-reachable service may expose unexpected functionality or a known weakness"
        }
        Profile::Semgrep | Profile::Gitleaks | Profile::Trufflehog => {
            "source code or credentials may permit unauthorized access or unsafe application behavior"
        }
        Profile::Checkov | Profile::Kics => {
            "deployed infrastructure may inherit the reported insecure configuration"
        }
        Profile::Trivy | Profile::Grype | Profile::Syft => {
            "a container or software component may expose the workload to a known weakness"
        }
        Profile::Kubescape | Profile::KubeBench => {
            "the Kubernetes cluster or workload may have reduced isolation or administrative protection"
        }
        Profile::Garak => "the model endpoint may produce output it is supposed to refuse",
        Profile::AgenticRadar => unreachable!("Agentic Radar emits inventory only"),
        Profile::McpArmor => match family {
            FindingFamily::McpSecret => {
                "a credential embedded in MCP configuration may let anyone who obtains that file access the service without authorization"
            }
            FindingFamily::McpConfiguration => {
                "an MCP server process or tool may receive broader local capabilities than its purpose requires"
            }
            _ => unreachable!("MCP Armor records carry one of its two reviewed families"),
        },
    };
    format!("{consequence}.")
}

/// The family whose sentences this profile's findings are composed from.
///
/// The single grouping [`impact_for`] and [`remedy_for`] both switch on, named
/// once so a localized client can reach the same nine cases without matching on
/// twenty-one engine profiles it has no other reason to know about.
fn family_for(profile: Profile) -> FindingFamily {
    match profile {
        Profile::CloudQuery | Profile::Steampipe | Profile::Prowler | Profile::ScoutSuite => {
            FindingFamily::CloudPosture
        }
        Profile::Cloudsplaining => FindingFamily::CloudIdentity,
        Profile::ScubaGear | Profile::Maester => FindingFamily::Microsoft365,
        Profile::Naabu | Profile::Httpx | Profile::Nuclei | Profile::Greenbone | Profile::Zap => {
            FindingFamily::NetworkExposure
        }
        Profile::Semgrep => FindingFamily::SourceCode,
        Profile::Gitleaks | Profile::Trufflehog => FindingFamily::Secret,
        Profile::Checkov | Profile::Kics => FindingFamily::InfrastructureAsCode,
        Profile::Trivy | Profile::Grype | Profile::Syft => FindingFamily::VulnerableComponent,
        Profile::Kubescape | Profile::KubeBench => FindingFamily::Kubernetes,
        Profile::Garak => FindingFamily::ModelBehavior,
        Profile::AgenticRadar => unreachable!("Agentic Radar emits inventory only"),
        Profile::McpArmor => unreachable!("MCP Armor records carry an explicit family"),
    }
}

/// The kind of change that actually resolves this family of finding.
///
/// This clause completes the one sentence in a finding that tells a reader what
/// to do, so it has to name the right action. It was a fixed "a least-privilege
/// configuration or code change" for all twenty-one engines: correct for a
/// permissive IAM policy, and wrong in a way a beginner cannot detect for the
/// rest. Someone told that a leaked AWS key needs "a least-privilege
/// configuration change" goes looking for a permissions setting instead of
/// revoking the credential, and the key stays valid for however long that
/// takes. Someone told the same about `CVE-2024-2511` in openssl has no reason
/// to think the answer is an upgrade.
///
/// Grouped the way [`impact_for`] groups the same profiles, except that secret
/// scanners split away from Semgrep: the three share a consequence but not a
/// remedy, and the remedy is the half that is urgent.
fn remedy_for(profile: Profile, family: FindingFamily) -> &'static str {
    match profile {
        Profile::CloudQuery | Profile::Steampipe | Profile::Prowler | Profile::ScoutSuite => {
            "Apply least privilege to the affected resource's configuration or policy"
        }
        Profile::Cloudsplaining => {
            "Replace the affected policy with a narrower policy that grants only the actions the identity's role requires"
        }
        Profile::ScubaGear | Profile::Maester => {
            "Correct the Microsoft 365 tenant setting named by this control"
        }
        // Nuclei, Greenbone, and ZAP are the findings that actually use this clause.
        // Naabu/httpx observations take the exposure-observation path instead.
        Profile::Naabu | Profile::Httpx | Profile::Nuclei | Profile::Greenbone | Profile::Zap => {
            "Correct the service or configuration named by this check"
        }
        Profile::Semgrep => "Change the code to remove the reported unsafe pattern",
        Profile::Gitleaks | Profile::Trufflehog => {
            "Revoke and rotate the exposed credential, then remove it from the source and every retained history entry"
        }
        Profile::Checkov | Profile::Kics => {
            "Correct the infrastructure-as-code template so redeployment does not restore the insecure setting"
        }
        Profile::Trivy | Profile::Grype | Profile::Syft => {
            "Upgrade the affected component to a fixed version; if none is available, record the blocker and track the fix"
        }
        Profile::Kubescape | Profile::KubeBench => {
            "Correct the workload or cluster setting named by this check"
        }
        Profile::Garak => {
            "Reproduce the probe, decide whether those replies actually breach this endpoint's usage policy, and if so add a guardrail in front of or behind the model"
        }
        Profile::AgenticRadar => unreachable!("Agentic Radar emits inventory only"),
        Profile::McpArmor => match family {
            FindingFamily::McpSecret => {
                "Revoke and rotate the credential, then remove it from the MCP configuration and every retained history entry"
            }
            FindingFamily::McpConfiguration => {
                "Remove unnecessary permissions and dangerous command flags from the MCP configuration, leaving only the capabilities the server's purpose requires"
            }
            _ => unreachable!("MCP Armor records carry one of its two reviewed families"),
        },
    }
}

fn is_failure(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "fail"
            | "failed"
            | "failure"
            | "error"
            | "alarm"
            | "danger"
            | "noncompliant"
            | "non-compliant"
            | "notpassed"
            | "not_passed"
            | "false"
    )
}

fn is_pass(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "pass" | "passed" | "ok" | "compliant" | "true"
    )
}

fn json_root(parsed: &ParsedArtifact) -> Option<&Value> {
    match parsed {
        ParsedArtifact::Json(value) => Some(value),
        _ => None,
    }
}

fn nested_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = if let Ok(index) = segment.parse::<usize>() {
            current.as_array()?.get(index)?
        } else {
            current.get(*segment)?
        };
    }
    scalar_string(current)
}

/// Rule identifiers need their exact scalar bytes until `RecordDraft` decides
/// whether they are eligible to become structured mapping proof. General UI
/// text uses `scalar_string`, which is intentionally lossy and must not be
/// reused for this purpose.
fn exact_nested_rule_scalar(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = if let Ok(index) = segment.parse::<usize>() {
            current.as_array()?.get(index)?
        } else {
            current.get(*segment)?
        };
    }
    exact_rule_scalar(current)
}

fn nested_strings(value: &Value, path: &[&str]) -> Vec<String> {
    let mut current = value;
    for segment in path {
        let Some(next) = current.get(*segment) else {
            return Vec::new();
        };
        current = next;
    }
    match current {
        Value::Array(values) => values.iter().filter_map(scalar_string).take(32).collect(),
        Value::String(value) => value
            .split(',')
            .map(|part| safe_text(part, 80))
            .filter(|part| !part.is_empty())
            .take(32)
            .collect(),
        _ => Vec::new(),
    }
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(safe_text(value, MAX_LONG_TEXT)),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn exact_rule_scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn string_any(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(scalar_string))
}

fn exact_rule_string_any(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(exact_rule_scalar))
}

fn number_any(object: &Map<String, Value>, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_f64))
}

fn first_resource_location(value: &Value) -> Option<String> {
    let resource = value.get("resources")?.as_array()?.first()?;
    ["uid", "name", "cloud_partition", "type"]
        .iter()
        .find_map(|key| resource.get(*key).and_then(scalar_string))
}

fn references_from(value: &Value) -> Vec<String> {
    const POINTERS: &[&str] = &[
        "/reference",
        "/references",
        "/Reference",
        // JSON Pointer is case-sensitive and Trivy emits `References` on every
        // vulnerability. Without this the advisory links a user needs in order
        // to act are dropped while `PrimaryURL` alone survives.
        "/References",
        // KICS names the page documenting the query it just failed.
        "/query_url",
        "/PrimaryURL",
        "/primary_url",
        "/guideline",
        "/help",
        "/HelpUrl",
        "/remediation/references",
        "/unmapped/related_url",
        "/info/reference",
        "/extra/metadata/references",
        "/vulnerability/dataSource",
        "/vulnerability/urls",
    ];
    let mut references = Vec::new();
    for pointer in POINTERS {
        let Some(reference) = value.pointer(pointer) else {
            continue;
        };
        match reference {
            Value::String(url) => references.push(url.clone()),
            Value::Array(urls) => {
                references.extend(urls.iter().filter_map(Value::as_str).map(str::to_owned))
            }
            _ => {}
        }
    }
    references.truncate(32);
    references
}

fn safe_https_reference(value: String) -> Option<String> {
    let value = safe_text(&value, MAX_LONG_TEXT);
    if value.starts_with("https://")
        && !value.chars().any(char::is_whitespace)
        && !value.contains('@')
    {
        Some(value)
    } else {
        None
    }
}

fn collect_named_objects<'a>(
    value: &'a Value,
    pointer: &str,
    depth: usize,
    output: &mut Vec<(String, &'a Value)>,
) {
    if depth > 12 || output.len() >= MAX_RECORDS {
        return;
    }
    match value {
        Value::Object(object) => {
            output.push((pointer.to_owned(), value));
            for (key, child) in object.iter().take(256) {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                collect_named_objects(child, &format!("{pointer}/{escaped}"), depth + 1, output);
                if output.len() >= MAX_RECORDS {
                    break;
                }
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().take(MAX_RECORDS - output.len()).enumerate() {
                collect_named_objects(child, &format!("{pointer}/{index}"), depth + 1, output);
                if output.len() >= MAX_RECORDS {
                    break;
                }
            }
        }
        _ => {}
    }
}

/// Where `container_runtime` bind-mounts the directory the user chose. Engines
/// are handed this path as their scan target, so their output names files under
/// it -- a location that does not exist on the user's machine. Imported rather
/// than repeated so the mount and the strip cannot drift apart.
use crate::container_runtime::CONTAINER_WORKSPACE_PATH;

/// Stands in for the scanned directory itself, matching the `"source-file"`
/// placeholder the extractors use when an engine names no path at all.
const SCANNED_DIRECTORY_LOCATION: &str = "scanned-directory";

fn redact_location(value: &str) -> String {
    let value = value.split(['?', '#']).next().unwrap_or(value);
    let normalized = value.replace('\\', "/");
    // Reported relative to the directory the user picked. Showing the mount
    // path instead would hand a beginner a filename they cannot open, and
    // reading it as their own filesystem would be wrong on every platform.
    let relative = match normalized.strip_prefix(CONTAINER_WORKSPACE_PATH) {
        Some("") | Some("/") => SCANNED_DIRECTORY_LOCATION,
        // Only a path *inside* the mount qualifies. `/workspaces/app.js` is an
        // unrelated directory and must not silently lose its first characters.
        Some(rest) if rest.starts_with('/') => rest.trim_start_matches('/'),
        _ => &normalized,
    };
    safe_text(relative, MAX_SHORT_TEXT)
}

fn safe_tag(value: &str) -> String {
    let value = safe_text(value, 120).to_ascii_lowercase();
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '/') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn safe_text(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn push_warning(warnings: &mut Vec<String>, warning: impl AsRef<str>) {
    if warnings.len() < MAX_WARNINGS {
        warnings.push(safe_text(warning.as_ref(), MAX_SHORT_TEXT));
    }
}

/// Keep one report-honesty summary visible even when per-row diagnostics have
/// already filled the bounded warning list. Priority warnings are themselves
/// bounded and displace only the least prominent trailing diagnostic.
fn push_priority_warning(warnings: &mut Vec<String>, warning: impl AsRef<str>) {
    while warnings.len() >= MAX_WARNINGS {
        warnings.pop();
    }
    warnings.insert(0, safe_text(warning.as_ref(), MAX_SHORT_TEXT));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_report_reader_verifies_even_the_suffix_beyond_the_record_limit() {
        let root = tempfile::tempdir().unwrap();
        let mut bytes = b"{\"rule\":\"one\"}\n".repeat(MAX_RECORDS + 1);
        let path = root.path().join("results.jsonl");
        std::fs::write(&path, &bytes).unwrap();
        let artifact = RawArtifact {
            id: "streamed-report".into(),
            case_id: "case-1".into(),
            run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            relative_path: "results.jsonl".into(),
            media_type: "application/x-ndjson".into(),
            sha256: hex::encode(Sha256::digest(&bytes)),
            byte_length: bytes.len() as u64,
            created_at: chrono::Utc::now(),
            contains_sensitive_data: false,
        };
        let mut warnings = Vec::new();
        assert!(
            matches!(read_large_artifact(root.path(), &artifact, &mut warnings),
            Some(ParsedArtifact::JsonLines(rows)) if rows.len() == MAX_RECORDS)
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("record limit"))
        );
        let index = bytes.len() - 4;
        bytes[index] = b'x';
        std::fs::write(&path, &bytes).unwrap();
        warnings.clear();
        assert!(read_large_artifact(root.path(), &artifact, &mut warnings).is_none());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("hash did not match"))
        );
        let mut oversized = artifact;
        oversized.byte_length = MAX_STREAM_ARTIFACT_BYTES + 1;
        warnings.clear();
        assert!(read_large_artifact(root.path(), &oversized, &mut warnings).is_none());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("per-file byte limit"))
        );
    }

    #[test]
    fn bounded_lines_keep_short_lines_and_consume_long_ones() {
        let mut reader = BufReader::with_capacity(3, b"abc\nabcdefgh\n\nxy".as_slice());
        let mut line = Vec::new();
        let mut lines = Vec::new();
        loop {
            let (consumed, oversized) = read_bounded_line(&mut reader, &mut line, 5).unwrap();
            if consumed == 0 {
                break;
            }
            lines.push((consumed, oversized, line.clone()));
        }
        assert_eq!(
            lines,
            vec![
                (4, false, b"abc\n".to_vec()),
                (9, true, Vec::new()),
                (1, false, b"\n".to_vec()),
                (2, false, b"xy".to_vec()),
            ]
        );
    }

    #[test]
    fn cloudquery_rows_keep_only_top_level_scalar_columns() {
        let row = |text: &str| serde_json::from_str::<CloudQueryRow>(text).unwrap().0;
        assert_eq!(
            row(
                r#"{"arn":"a","count":2,"active":true,"none":null,"tags":{"k":"v"},"versions":[{"Document":"d"}],"name":"n","name":{"nested":1}}"#
            ),
            serde_json::json!({"arn":"a","count":2,"active":true,"none":null})
        );
        assert_eq!(
            row(r#"[{"arn":"a","tags":{}},5,[1]]"#),
            serde_json::json!([{"arn":"a"}, null, null])
        );
        assert_eq!(row(r#""text""#), Value::Null);
        assert!(serde_json::from_str::<CloudQueryRow>(r#"{"arn":"a""#).is_err());
    }

    #[test]
    fn cloudquery_rows_verify_the_recorded_length_and_hash() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"{\"account_id\":\"123456789012\"}\n{\"account_id\":\"123456789012\"}\n";
        std::fs::write(root.path().join("aws_iam_users.json"), bytes).unwrap();
        let artifact = |byte_length: u64, sha256: String| RawArtifact {
            id: "artifact-cloudquery".into(),
            case_id: "case-1".into(),
            run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            relative_path: "aws_iam_users.json".into(),
            media_type: "application/json".into(),
            sha256,
            byte_length,
            created_at: chrono::Utc::now(),
            contains_sensitive_data: false,
        };
        let digest = hex::encode(Sha256::digest(bytes));

        let mut warnings = Vec::new();
        let parsed = read_cloudquery_rows(
            root.path(),
            &artifact(bytes.len() as u64, digest.clone()),
            &mut warnings,
        );
        assert!(
            matches!(parsed, Some(ParsedArtifact::JsonLines(ref rows)) if rows.len() == 2),
            "{warnings:?}"
        );
        assert!(warnings.is_empty());

        for (byte_length, sha256, expected) in [
            (
                bytes.len() as u64,
                "0".repeat(64),
                "hash did not match its recorded evidence metadata",
            ),
            (
                bytes.len() as u64 - 1,
                digest,
                "length did not match its recorded evidence metadata",
            ),
        ] {
            let mut warnings = Vec::new();
            assert!(
                read_cloudquery_rows(root.path(), &artifact(byte_length, sha256), &mut warnings)
                    .is_none()
            );
            assert!(
                warnings.iter().any(|warning| warning.contains(expected)),
                "{warnings:?}"
            );
        }
    }

    #[test]
    fn zap_plain_text_separates_boundaries_and_decodes_entities() {
        assert_eq!(
            zap_plain_text(
                "<p>First &amp; &quot;quoted&quot;.</p><p>Second&lt;value&gt;.<br />Third &#39;line&#39;.</p>"
            ),
            "First & \"quoted\". Second<value>. Third 'line'. "
        );
    }

    #[test]
    fn zap_evidence_tag_value_preserves_markup_and_marks_truncation() {
        assert_eq!(
            bounded_zap_evidence_tag_value(" <!-- matched --> "),
            Some("<!-- matched -->".into())
        );
        assert_eq!(bounded_zap_evidence_tag_value("  "), None);

        let long_value = format!("{}tail", "x".repeat(MAX_ZAP_EVIDENCE_TAG_VALUE));
        assert_eq!(
            bounded_zap_evidence_tag_value(&long_value),
            Some(format!("{}…", "x".repeat(MAX_ZAP_EVIDENCE_TAG_VALUE)))
        );
    }

    #[test]
    fn only_provably_complete_zero_byte_jsonl_engines_ignore_mapping_drift() {
        let artifact = RawArtifact {
            id: "empty-output".into(),
            case_id: "case-1".into(),
            run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            relative_path: "output/results.jsonl".into(),
            media_type: "application/x-ndjson".into(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            byte_length: 0,
            created_at: chrono::Utc::now(),
            contains_sensitive_data: false,
        };

        for engine_id in ["naabu", "httpx", "trufflehog"] {
            assert!(is_mapping_independent_empty_json_lines(
                engine_id, &artifact
            ));
        }
        assert!(!is_mapping_independent_empty_json_lines(
            "nuclei", &artifact
        ));
    }

    fn draft_with_rule(rule_id: &str) -> RecordDraft {
        RecordDraft {
            pointer: "/results/0".into(),
            rule_id: rule_id.into(),
            title: "Rule finding".into(),
            source_severity: "high".into(),
            derived_severity: None,
            location: "src/example.py".into(),
            asset_hint: Some("asset-1".into()),
            source_confidence: "HIGH".into(),
            derived_confidence: None,
            evidence_kind: EvidenceKind::SourceCode,
            references: vec![],
            tags: vec![],
        }
    }

    #[test]
    fn absent_or_unrecognized_severity_is_unknown_without_erasing_explicit_informational() {
        for value in ["", "unknown", "not-rated", "NaN", "-1", "11"] {
            assert_eq!(parse_severity(value), Severity::Unknown, "{value}");
        }
        for value in ["informational", "INFO", "log", "none", "negligible", "0"] {
            assert_eq!(parse_severity(value), Severity::Informational, "{value}");
        }
        assert_eq!(priority_for(&Severity::Unknown), 20);
        assert!(
            priority_for(&Severity::Unknown) > priority_for(&Severity::Informational),
            "unknown impact must not be buried as a known informational observation"
        );
    }

    #[test]
    fn scanner_details_are_bounded_and_control_clean() {
        let record = record_from_draft(draft_with_rule("example-rule"));
        let details = with_scanner_details(
            record,
            Some(format!(
                "description\0with\ncontrols{}",
                "x".repeat(MAX_LONG_TEXT * 2)
            )),
            Some("  review\tupstream guidance  ".into()),
            Some("1.0\r\n".into()),
            Some("1.1\u{7f}".into()),
        )
        .scanner_details
        .expect("non-empty scanner details");

        for value in [
            details.description.as_deref(),
            details.remediation.as_deref(),
            details.installed_version.as_deref(),
            details.fixed_version.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            assert!(!value.chars().any(char::is_control), "{value:?}");
        }
        assert!(
            details
                .description
                .as_deref()
                .is_some_and(|value| value.chars().count() <= MAX_LONG_TEXT)
        );
        assert_eq!(
            details.remediation.as_deref(),
            Some("review upstream guidance")
        );
        assert_eq!(details.installed_version.as_deref(), Some("1.0"));
        assert_eq!(details.fixed_version.as_deref(), Some("1.1"));
    }

    #[test]
    fn source_confidence_values_map_to_the_canonical_bands() {
        for (source, expected) in [
            ("HIGH", Confidence::High),
            ("MEDIUM", Confidence::Medium),
            ("LOW", Confidence::Low),
            ("95", Confidence::High),
            ("65", Confidence::Medium),
            ("25", Confidence::Low),
        ] {
            assert_eq!(parse_confidence(source), expected, "{source}");
        }
    }

    #[test]
    fn production_extractors_never_pass_a_bare_confidence_constant() {
        let production = include_str!("mod.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production module");
        // Any bare band, not just the High this change removed: a later
        // extractor that hardcodes Medium is the same defect wearing a
        // different number.
        for (index, line) in production.lines().enumerate() {
            // A whole line that is only a band and a comma is an argument
            // being passed; a `=>` on the line is a mapping arm, which is
            // where a deliberate band belongs.
            let trimmed = line.trim();
            assert!(
                !(trimmed.starts_with("Confidence::")
                    && trimmed.ends_with(',')
                    && !trimmed.contains("=>")),
                "bare extractor confidence `{trimmed}` at source line {}",
                index + 1
            );
        }
    }

    #[test]
    fn the_container_mount_prefix_is_stripped_without_eating_look_alike_paths() {
        // Engines are handed `/workspace` as their target, so their paths name
        // a directory the user does not have. Reporting the remainder keeps the
        // path true relative to the directory they chose.
        assert_eq!(
            redact_location("/workspace/deploy/.env.production"),
            "deploy/.env.production"
        );
        assert_eq!(redact_location("/workspace//src/app.js"), "src/app.js");
        // The mount root itself is the scanned directory, not an empty path.
        assert_eq!(redact_location("/workspace"), SCANNED_DIRECTORY_LOCATION);
        assert_eq!(redact_location("/workspace/"), SCANNED_DIRECTORY_LOCATION);

        // A prefix match is not a path match. These are unrelated directories
        // and must keep every character; a bare `strip_prefix` would turn the
        // first into `s/app.js` and quietly point at a file that never existed.
        assert_eq!(redact_location("/workspaces/app.js"), "/workspaces/app.js");
        assert_eq!(
            redact_location("/workspace-backup/app.js"),
            "/workspace-backup/app.js"
        );
        // Not anchored at the root, so not the mount.
        assert_eq!(
            redact_location("/srv/workspace/app.js"),
            "/srv/workspace/app.js"
        );
        // Windows separators are normalized first, so the strip still applies.
        assert_eq!(redact_location("\\workspace\\src\\app.js"), "src/app.js");
    }

    #[test]
    fn fingerprints_are_stable_and_location_queries_are_removed() {
        assert_eq!(
            stable_fingerprint("nuclei", "rule", "asset", "https://example.test/a"),
            stable_fingerprint(
                "nuclei",
                "rule",
                "asset",
                &redact_location("https://example.test/a?token=secret")
            )
        );
    }

    #[test]
    fn nuclei_explicit_non_match_is_not_a_finding() {
        let parsed = ParsedArtifact::JsonLines(vec![(
            1,
            serde_json::json!({
                "template-id": "executed-without-match",
                "matcher-status": false,
                "asset_id": "asset-1"
            }),
        )]);
        let mut warnings = Vec::new();

        let extraction = extract_nuclei(&parsed, &mut warnings);

        assert!(extraction.records.is_empty());
        assert_eq!(extraction.execution_counts.get("asset-1"), Some(&1));
        assert!(warnings.is_empty());
    }

    #[test]
    fn nuclei_explicit_match_remains_a_finding() {
        let parsed = ParsedArtifact::JsonLines(vec![(
            1,
            serde_json::json!({
                "template-id": "matched-template",
                "matcher-status": true
            }),
        )]);
        let mut warnings = Vec::new();

        let records = extract_nuclei(&parsed, &mut warnings).records;

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rule_id, "matched-template");
        assert!(warnings.is_empty());
    }

    #[test]
    fn nuclei_record_without_matcher_status_remains_a_finding() {
        let parsed = ParsedArtifact::JsonLines(vec![(
            1,
            serde_json::json!({
                "template-id": "deployed-output-shape"
            }),
        )]);
        let mut warnings = Vec::new();

        let records = extract_nuclei(&parsed, &mut warnings).records;

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rule_id, "deployed-output-shape");
        assert!(warnings.is_empty());
    }

    #[test]
    fn nuclei_mixed_match_stream_only_reports_the_matching_record() {
        let parsed = ParsedArtifact::JsonLines(vec![
            (
                1,
                serde_json::json!({
                    "template-id": "matching-template",
                    "matcher-status": true
                }),
            ),
            (
                2,
                serde_json::json!({
                    "template-id": "non-matching-template",
                    "matcher-status": false,
                    "asset_id": "asset-1"
                }),
            ),
        ]);
        let mut warnings = Vec::new();

        let extraction = extract_nuclei(&parsed, &mut warnings);

        assert_eq!(extraction.records.len(), 1);
        assert_eq!(extraction.records[0].rule_id, "matching-template");
        assert_eq!(extraction.execution_counts.get("asset-1"), Some(&1));
        assert!(warnings.is_empty());
    }

    #[test]
    fn nuclei_error_non_match_is_not_execution_proof_or_a_finding() {
        let parsed = ParsedArtifact::JsonLines(vec![(
            1,
            serde_json::json!({
                "template-id": "request-failed",
                "matcher-status": false,
                "error": "connection failed",
                "asset_id": "asset-1"
            }),
        )]);
        let mut warnings = Vec::new();

        let extraction = extract_nuclei(&parsed, &mut warnings);

        assert!(extraction.records.is_empty());
        assert!(extraction.execution_counts.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn evidence_identity_is_distinct_for_each_engine_execution() {
        assert_eq!(EVIDENCE_ID_SCHEMA_VERSION, "v2");
        let first = stable_evidence_id(
            "fingerprint",
            "semgrep",
            "rule-1",
            "artifact",
            &"a".repeat(64),
            "engine-run-1",
        );
        let second = stable_evidence_id(
            "fingerprint",
            "semgrep",
            "rule-1",
            "artifact",
            &"a".repeat(64),
            "engine-run-2",
        );
        assert_ne!(first, second);
        assert_eq!(
            first,
            stable_evidence_id(
                "fingerprint",
                "semgrep",
                "rule-1",
                "artifact",
                &"a".repeat(64),
                "engine-run-1",
            )
        );
    }

    #[test]
    fn lossy_rule_display_text_never_becomes_mapping_proof() {
        const RULE: &str = "ai-security-scanner.python.dynamic-code-execution";
        let valid = record_from_draft(draft_with_rule(RULE));
        assert_eq!(valid.rule_id, RULE);
        assert_eq!(valid.mapping_source_rule.as_deref(), Some(RULE));
        assert!(
            !mapping_control_references(
                "semgrep",
                valid.mapping_source_rule.as_deref(),
                &[],
                false,
                false,
            )
            .is_empty()
        );

        for raw_rule in [
            "ai-security-\0scanner.python.dynamic-code-execution".to_owned(),
            format!(" {RULE} "),
        ] {
            let invalid = record_from_draft(draft_with_rule(&raw_rule));
            // Both values sanitize to text that looks exactly like a reviewed
            // rule, but their raw bytes are not acceptable mapping evidence.
            assert_eq!(invalid.rule_id, RULE);
            assert!(invalid.mapping_source_rule.is_none());
            assert_ne!(invalid.rule_identity, RULE);
            assert!(
                mapping_control_references(
                    "semgrep",
                    invalid.mapping_source_rule.as_deref(),
                    &[],
                    true,
                    true,
                )
                .is_empty()
            );
        }
    }

    #[test]
    fn secret_fields_are_never_selected_by_helpers() {
        let value: Value = serde_json::json!({
            "Raw": "do-not-copy",
            "Secret": "do-not-copy",
            "DetectorName": "Example"
        });
        assert_eq!(
            nested_string(&value, &["DetectorName"]).as_deref(),
            Some("Example")
        );
        assert!(references_from(&value).is_empty());
    }

    #[test]
    fn only_backend_runtime_stream_capture_paths_are_excluded() {
        assert!(is_runtime_stream_capture_path(
            "case/run/engine/attempt-1/raw/stdout.log"
        ));
        assert!(is_runtime_stream_capture_path(
            "case/run/engine/attempt-42/raw/stderr.log"
        ));
        assert!(!is_runtime_stream_capture_path(
            "case/run/engine/attempt-1/output/raw/stdout.log"
        ));
        assert!(!is_runtime_stream_capture_path(
            "case/run/engine/attempt-one/raw/stdout.log"
        ));
        assert!(!is_runtime_stream_capture_path(
            "case/run/engine/attempt-1/raw/result.json"
        ));
    }

    #[test]
    fn runtime_stream_capture_path_matches_the_progress_adapter() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../src/services/nativeAdapter.ts");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("reading {} failed: {error}", path.display()));

        assert!(source.contains(&format!(
            "const runtimeStreamCaptureFileNames = {RUNTIME_STREAM_CAPTURE_FILE_NAMES:?} as const;"
        )));
        assert!(source.contains(&format!(
            r#"const runtimeStreamCaptureRawDirectory = "{RUNTIME_STREAM_CAPTURE_RAW_DIRECTORY}";"#
        )));
        assert!(source.contains(&format!(
            r#"const runtimeStreamCaptureAttemptPrefix = "{RUNTIME_STREAM_CAPTURE_ATTEMPT_PREFIX}";"#
        )));
        assert!(source.contains(
            r#"const isRuntimeStreamCapturePath = (relativePath: string): boolean => {
  const components = relativePath
    .split("/")
    .filter((component) => component !== "" && component !== ".");
  const fileName = components.at(-1);
  const rawDirectory = components.at(-2);
  const attemptDirectory = components.at(-3);
  const attempt = attemptDirectory?.startsWith(runtimeStreamCaptureAttemptPrefix)
    ? attemptDirectory.slice(runtimeStreamCaptureAttemptPrefix.length)
    : "";

  return runtimeStreamCaptureFileNames.some((candidate) => candidate === fileName)
    && rawDirectory === runtimeStreamCaptureRawDirectory
    && attempt.length > 0
    && [...attempt].every((character) => character >= "0" && character <= "9");
};"#
        ));
    }

    #[test]
    fn only_wrapper_preserved_upstream_evidence_is_excluded() {
        assert!(is_preserved_upstream_evidence_path(
            "case/run/engine/attempt-1/output/upstream/scubagear-raw.json"
        ));
        assert!(is_preserved_upstream_evidence_path(
            "case/run/engine/attempt-7/output/upstream/nested/report.json"
        ));
        // The wrapper's own normalized document sits beside `upstream/`, not
        // inside it, and must still be normalized.
        assert!(!is_preserved_upstream_evidence_path(
            "case/run/engine/attempt-1/output/scubagear.json"
        ));
        assert!(!is_preserved_upstream_evidence_path(
            "case/run/engine/attempt-1/output/upstream.json"
        ));
        assert!(!is_preserved_upstream_evidence_path(
            "case/run/engine/attempt-one/output/upstream/report.json"
        ));
    }

    #[test]
    fn upstream_scubagear_control_key_is_not_normalized_beside_the_wrapper_document() {
        // Upstream ScubaGear spells the identifier `Control ID`, which the
        // adapter cannot read, so normalizing the preserved raw report emits a
        // warning per control and contributes nothing. Guard the exclusion with
        // the real upstream shape rather than a synthetic one.
        let upstream = serde_json::json!({
            "Results": [{
                "Control ID": "MS.AAD.1.1v1",
                "Requirement": "Legacy authentication SHALL be blocked.",
                "Result": "Fail",
                "Criticality": "Shall"
            }]
        });
        let mut warnings = Vec::new();
        let parsed = ParsedArtifact::Json(upstream);
        let records = extract_scubagear(&parsed, &mut warnings);
        assert!(
            records.is_empty(),
            "the upstream key must remain unreadable, otherwise this exclusion is unnecessary: {records:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("lacked a rule id")),
            "expected the misparse this exclusion exists to prevent, got: {warnings:?}"
        );
    }

    #[test]
    fn unevaluated_microsoft365_controls_are_disclosed_with_the_wrappers_own_counts() {
        let scubagear = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 30, "failures": 2, "warnings": 0, "errors": 1,
                             "manual": 20, "omitted": 5, "normalized_results": 32 }
        }));
        let unevaluated = unevaluated_controls(Profile::ScubaGear, &scubagear)
            .expect("a run with manual, omitted and errored controls discloses all three");
        let note = &unevaluated.disclosure;
        assert!(
            note.contains("20 left without an automated verdict"),
            "{note}"
        );
        assert!(note.contains("5 omitted by configuration"), "{note}");
        assert!(note.contains("1 could not be evaluated"), "{note}");
        // Passing controls are evaluated, so they are not a coverage shortfall.
        assert!(!note.contains("30"), "{note}");

        let maester = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 8, "failures": 1, "investigate": 0, "errors": 0,
                             "skipped": 3, "not_run": 0, "total": 12, "normalized_results": 9 }
        }));
        let unevaluated = unevaluated_controls(Profile::Maester, &maester)
            .expect("skipped tests are a coverage shortfall");
        let note = &unevaluated.disclosure;
        assert!(note.contains("3 skipped"), "{note}");
        assert!(!note.contains("not run"), "{note}");
    }

    #[test]
    fn only_controls_the_engine_could_not_evaluate_withhold_completion() {
        // Passed over by design or by the tenant's own config: the run is still
        // a complete scan of what it set out to check.
        let by_design = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 30, "failures": 2, "errors": 0,
                             "manual": 20, "omitted": 5, "normalized_results": 32 }
        }));
        let unevaluated = unevaluated_controls(Profile::ScubaGear, &by_design)
            .expect("a shortfall is still disclosed");
        assert!(
            !unevaluated.withholds_completion,
            "{}",
            unevaluated.disclosure
        );

        // Asked to check and could not: coverage was never established.
        let unevaluable = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 30, "failures": 2, "errors": 1,
                             "manual": 0, "omitted": 0, "normalized_results": 32 }
        }));
        assert!(
            unevaluated_controls(Profile::ScubaGear, &unevaluable)
                .expect("an unevaluable control is a shortfall")
                .withholds_completion
        );
        let maester_errors = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 8, "failures": 1, "errors": 2,
                             "skipped": 0, "not_run": 0, "normalized_results": 9 }
        }));
        assert!(
            unevaluated_controls(Profile::Maester, &maester_errors)
                .expect("an errored test is a shortfall")
                .withholds_completion
        );
    }

    #[test]
    fn every_severity_label_is_introduced_by_a_grammatical_article() {
        // Cross-checks two hand-written functions that have to agree. The
        // article match is exhaustive, so a new severity cannot compile without
        // being assigned one -- but nothing stops it being assigned the wrong
        // one, which is exactly how "a informational-severity condition"
        // shipped. Deriving the expectation from the label instead makes the
        // two disagree loudly.
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Informational,
            Severity::Unknown,
        ] {
            let label = severity_label(&severity);
            let expected = if label.starts_with(['a', 'e', 'i', 'o', 'u']) {
                "an"
            } else {
                "a"
            };
            assert_eq!(
                severity_article(&severity),
                expected,
                "\"reported {} {label}-severity condition\" is not English",
                severity_article(&severity)
            );
        }
    }

    #[test]
    fn verdicts_the_wrapper_dropped_are_disclosed_rather_than_read_as_a_clean_tenant() {
        // The scenario: upstream renames a verdict, the wrapper's `switch`
        // matches nothing, and every control is dropped by its `default { $null
        // }`. `normalized_results` still equals `Results.len()` -- the wrapper
        // counts the list it just built -- so the existing integrity check
        // holds. Without the engine's own counters the user is handed a
        // confident, completely empty tenant audit.
        let everything_dropped = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 300, "failures": 42, "investigate": 0, "errors": 0,
                             "skipped": 0, "not_run": 0, "total": 342, "normalized_results": 0 },
            "Results": []
        }));
        let unevaluated = unevaluated_controls(Profile::Maester, &everything_dropped)
            .expect("342 evaluated tests and no results is not a clean run");
        assert!(
            unevaluated
                .disclosure
                .contains("342 reported by the engine but not carried into results"),
            "{}",
            unevaluated.disclosure
        );
        assert!(
            unevaluated.withholds_completion,
            "a run that lost every verdict cannot be reported as complete"
        );

        // Partial loss counts too: 3 of 33 verdicts never became rows.
        let partially_dropped = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 30, "failures": 2, "warnings": 1, "errors": 0,
                             "manual": 0, "omitted": 0, "normalized_results": 30 }
        }));
        assert!(
            unevaluated_controls(Profile::ScubaGear, &partially_dropped)
                .expect("three lost verdicts are a shortfall")
                .withholds_completion
        );

        // A disputed control is judged on ScubaGear's own `OriginalResult` and
        // counted in `disputed` rather than `failures`, so it adds a row that
        // no verdict counter accounts for. That is a surplus, not a loss, and
        // must not be reported as one.
        let disputed_surplus = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 30, "failures": 2, "warnings": 0, "errors": 0,
                             "manual": 0, "omitted": 0, "disputed": 4, "normalized_results": 36 }
        }));
        assert!(
            unevaluated_controls(Profile::ScubaGear, &disputed_surplus).is_none(),
            "a disputed control resolving to a verdict is not a lost one"
        );
    }

    #[test]
    fn maester_total_discloses_controls_missing_from_every_reported_category() {
        let uncategorized = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 7, "failures": 1, "investigate": 1, "errors": 1,
                             "skipped": 1, "not_run": 1, "total": 15, "normalized_results": 9 }
        }));
        let unevaluated = unevaluated_controls(Profile::Maester, &uncategorized)
            .expect("three controls outside every reported category must be disclosed");
        assert!(
            unevaluated
                .disclosure
                .contains("3 not accounted for by any reported category"),
            "{}",
            unevaluated.disclosure
        );
    }

    #[test]
    fn maester_total_equal_to_all_reported_counters_adds_no_disclosure() {
        let fully_accounted = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 7, "failures": 1, "investigate": 1, "errors": 1,
                             "skipped": 1, "not_run": 1, "total": 12, "normalized_results": 9 }
        }));
        let unevaluated = unevaluated_controls(Profile::Maester, &fully_accounted)
            .expect("existing error, skipped, and not-run disclosures remain");
        assert!(
            !unevaluated
                .disclosure
                .contains("not accounted for by any reported category"),
            "{}",
            unevaluated.disclosure
        );
    }

    #[test]
    fn maester_without_total_preserves_older_document_behavior_exactly() {
        let older_document = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 8, "failures": 1, "investigate": 0, "errors": 0,
                             "skipped": 0, "not_run": 0, "normalized_results": 8 }
        }));
        let unevaluated = unevaluated_controls(Profile::Maester, &older_document)
            .expect("the pre-existing normalization shortfall still applies");
        assert_eq!(
            unevaluated.disclosure,
            "Maester did not evaluate every control in scope (1 reported by the engine but not carried into results); those controls are absent from findings and this run does not establish their state"
        );
        assert!(unevaluated.withholds_completion);
    }

    #[test]
    fn the_report_reads_back_the_disclosure_this_adapter_writes() {
        let document = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 3, "failures": 1, "warnings": 0, "errors": 2,
                             "manual": 20, "omitted": 5, "normalized_results": 4 }
        }));
        let unevaluated = unevaluated_controls(Profile::ScubaGear, &document)
            .expect("manual, omitted, and error counts are disclosed");
        assert_eq!(
            disclosed_unevaluated_controls(&unevaluated.disclosure),
            Some((
                "ScubaGear",
                vec![
                    "20 left without an automated verdict",
                    "5 omitted by configuration",
                    "2 could not be evaluated",
                ]
            ))
        );
        assert_eq!(
            disclosed_unevaluated_controls(
                "the tenant's ScubaGear configuration disputes the result of 1 control; they are reported on ScubaGear's own determination and tagged tenant-disputed rather than suppressed"
            ),
            None
        );
        assert_eq!(
            disclosed_unevaluated_controls(&format!(
                "{}{}",
                UNEVALUATED_CONTROLS_FRAME.0, UNEVALUATED_CONTROLS_FRAME.1
            )),
            None,
            "a disclosure names an engine and at least one item"
        );
    }

    #[test]
    fn maester_counters_exceeding_total_saturate_without_a_false_shortfall() {
        let overlapping_counters = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 8, "failures": 2, "investigate": 1, "errors": 0,
                             "skipped": 0, "not_run": 0, "total": 10, "normalized_results": 11 }
        }));
        assert!(
            unevaluated_controls(Profile::Maester, &overlapping_counters).is_none(),
            "a counter surplus is not evidence of an uncategorized control"
        );
    }

    #[test]
    fn maester_uncategorized_controls_withhold_completion_because_their_state_is_unknown() {
        let uncategorized = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 8, "failures": 1, "investigate": 0, "errors": 0,
                             "skipped": 0, "not_run": 0, "total": 10, "normalized_results": 9 }
        }));
        assert!(
            unevaluated_controls(Profile::Maester, &uncategorized)
                .expect("the unaccounted control is a coverage gap")
                .withholds_completion,
            "an in-scope control with no reported category has no established state"
        );
    }

    #[test]
    fn a_microsoft365_run_that_evaluated_everything_is_not_qualified() {
        let complete = ParsedArtifact::Json(serde_json::json!({
            "Diagnostics": { "passes": 30, "failures": 2, "warnings": 0, "errors": 0,
                             "manual": 0, "omitted": 0, "normalized_results": 32 }
        }));
        assert!(unevaluated_controls(Profile::ScubaGear, &complete).is_none());
        // Upstream's own report has no wrapper accounting to read.
        let upstream = ParsedArtifact::Json(serde_json::json!({ "Results": [] }));
        assert!(unevaluated_controls(Profile::ScubaGear, &upstream).is_none());
        // The disclosure is specific to the wrappers that produce these counts.
        assert!(unevaluated_controls(Profile::Semgrep, &complete).is_none());
    }

    #[test]
    fn greenbone_attribute_flood_is_bounded_before_normalization() {
        let mut xml = String::from("<results><result id=\"result-1\" ");
        for index in 0..=MAX_XML_ATTRIBUTES {
            xml.push_str(&format!("a{index}=\"x\" "));
        }
        xml.push_str("><name>bounded</name></result></results>");

        let mut warnings = Vec::new();
        assert!(parse_greenbone_xml(xml.as_bytes(), &mut warnings).is_none());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("attribute limit"))
        );
    }

    #[test]
    fn greenbone_xml_contract_binds_launcher_field_names() {
        let xml = br#"<results><result id="result-7"><name>Result name</name><host>198.51.100.7</host><port>443/tcp</port><result_type>alarm</result_type><severity>8.1</severity><threat>High</threat><summary>Summary text</summary><solution>Solution text</solution><qod><value>95</value></qod><asset_id>asset-7</asset_id><nvt oid="1.3.6.1.4.1.25623.1.0.100007"><name>NVT name</name><family>General</family><refs><ref type="cve" id="CVE-2026-1007"/></refs></nvt></result></results>"#;

        let mut warnings = Vec::new();
        let records = parse_greenbone_xml(xml, &mut warnings).expect("launcher XML parses");
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.result_id.as_deref(), Some("result-7"));
        assert_eq!(
            record.nvt_oid.as_deref(),
            Some("1.3.6.1.4.1.25623.1.0.100007")
        );
        assert_eq!(record.result_name.as_deref(), Some("Result name"));
        assert_eq!(record.nvt_name.as_deref(), Some("NVT name"));
        assert_eq!(record.host.as_deref(), Some("198.51.100.7"));
        assert_eq!(record.port.as_deref(), Some("443/tcp"));
        assert_eq!(record.result_type.as_deref(), Some("alarm"));
        assert_eq!(record.severity.as_deref(), Some("8.1"));
        assert_eq!(record.threat.as_deref(), Some("High"));
        assert_eq!(record.summary.as_deref(), Some("Summary text"));
        assert_eq!(record.solution.as_deref(), Some("Solution text"));
        assert_eq!(record.qod.as_deref(), Some("95"));
        assert_eq!(record.asset_id.as_deref(), Some("asset-7"));
        assert_eq!(record.family.as_deref(), Some("General"));
        assert_eq!(record.cves, ["CVE-2026-1007"]);
    }

    #[test]
    fn greenbone_missing_qod_stays_unknown_without_detection_quality_tag() {
        let parsed = ParsedArtifact::Xml(vec![GreenboneXmlResult {
            pointer: "/report/results/result[1]".to_owned(),
            result_id: Some("result-1".to_owned()),
            nvt_oid: Some("1.3.6.1.4.1.25623.1.0.100007".to_owned()),
            nvt_name: Some("NVT name".to_owned()),
            host: Some("198.51.100.7".to_owned()),
            port: Some("443/tcp".to_owned()),
            result_type: Some("alarm".to_owned()),
            severity: Some("8.1".to_owned()),
            threat: Some("High".to_owned()),
            asset_id: Some("asset-7".to_owned()),
            ..GreenboneXmlResult::default()
        }]);
        let mut warnings = Vec::new();

        let extraction = extract_greenbone(&parsed, &mut warnings, &["asset-7".to_owned()]);

        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert_eq!(extraction.records.len(), 1);
        let record = &extraction.records[0];
        assert_eq!(record.confidence, Confidence::Unknown);
        assert!(record.source_confidence.is_empty());
        assert_eq!(
            record.confidence_basis,
            Some(ConfidenceBasisCode::MissingDetectionQualityScore)
        );
        assert!(
            record
                .tags
                .iter()
                .all(|tag| !tag.starts_with("quality-of-detection:")),
            "missing QoD produced a detection-quality tag: {:?}",
            record.tags
        );
    }

    #[test]
    fn greenbone_unknown_result_type_withholds_completion() {
        let parsed = ParsedArtifact::Xml(vec![GreenboneXmlResult {
            pointer: "/report/results/result[1]".to_owned(),
            result_id: Some("result-1".to_owned()),
            nvt_oid: Some("1.3.6.1.4.1.25623.1.0.100007".to_owned()),
            result_type: Some("new_upstream_type".to_owned()),
            severity: Some("8.1".to_owned()),
            asset_id: Some("asset-7".to_owned()),
            ..GreenboneXmlResult::default()
        }]);
        let mut warnings = Vec::new();
        let extraction = extract_greenbone(&parsed, &mut warnings, &["asset-7".to_owned()]);

        assert!(extraction.records.is_empty());
        assert!(!extraction.complete);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("unsupported upstream result type"))
        );
    }

    fn greenbone_log(asset_id: &str, port: &str) -> GreenboneXmlResult {
        GreenboneXmlResult {
            pointer: "/report/results/result[1]".to_owned(),
            result_id: Some("result-1".to_owned()),
            nvt_oid: Some("1.3.6.1.4.1.25623.1.0.10107".to_owned()),
            host: Some("198.51.100.7".to_owned()),
            port: Some(port.to_owned()),
            result_type: Some("log".to_owned()),
            severity: Some("0.0".to_owned()),
            threat: Some("Log".to_owned()),
            asset_id: Some(asset_id.to_owned()),
            ..GreenboneXmlResult::default()
        }
    }

    /// Route, OS and open-port summaries are host-level (`0/tcp`). Without a
    /// result on an approved port, Greenbone identified no service there and
    /// its service-dependent checks never ran, so the host was not checked.
    #[test]
    fn greenbone_host_level_results_alone_leave_the_host_unchecked() {
        let parsed = ParsedArtifact::Xml(vec![
            greenbone_log("asset-7", "0/tcp"),
            greenbone_log("asset-7", "general/tcp"),
            greenbone_log("asset-8", "8080/tcp"),
        ]);
        let mut warnings = Vec::new();

        let extraction = extract_greenbone(
            &parsed,
            &mut warnings,
            &["asset-7".to_owned(), "asset-8".to_owned()],
        );

        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert!(extraction.records.is_empty());
        assert!(extraction.complete);
        assert_eq!(
            extraction.unevaluated_targets,
            [UnevaluatedTarget {
                asset_id: "asset-7".into(),
                cause: UnevaluatedTargetCause::NoServiceIdentified,
                result_count: 0,
            }]
        );
    }

    #[test]
    fn greenbone_error_on_an_approved_port_does_not_show_a_service_was_checked() {
        let mut error = greenbone_log("asset-7", "8080/tcp");
        error.result_type = Some("error".to_owned());
        let parsed = ParsedArtifact::Xml(vec![error]);
        let mut warnings = Vec::new();

        let extraction = extract_greenbone(&parsed, &mut warnings, &["asset-7".to_owned()]);

        assert_eq!(
            extraction
                .unevaluated_targets
                .iter()
                .map(|target| target.cause)
                .collect::<Vec<_>>(),
            [
                UnevaluatedTargetCause::ScannerError,
                UnevaluatedTargetCause::NoServiceIdentified,
            ]
        );
    }

    #[test]
    fn greenbone_dead_host_is_not_also_reported_as_no_service() {
        let mut dead = greenbone_log("asset-7", "0/tcp");
        dead.result_type = Some("dead_host".to_owned());
        let parsed = ParsedArtifact::Xml(vec![dead]);
        let mut warnings = Vec::new();

        let extraction = extract_greenbone(&parsed, &mut warnings, &["asset-7".to_owned()]);

        assert_eq!(
            extraction.unevaluated_targets,
            [UnevaluatedTarget {
                asset_id: "asset-7".into(),
                cause: UnevaluatedTargetCause::TargetDidNotRespond,
                result_count: 1,
            }]
        );
    }

    #[test]
    fn greenbone_service_port_reads_only_a_nonzero_tcp_port() {
        assert_eq!(greenbone_service_port("8080/tcp"), Some(8080));
        assert_eq!(greenbone_service_port(" 65535/TCP "), Some(65535));
        assert_eq!(greenbone_service_port("0/tcp"), None);
        assert_eq!(greenbone_service_port("general/tcp"), None);
        assert_eq!(greenbone_service_port("161/udp"), None);
        assert_eq!(greenbone_service_port("65536/tcp"), None);
        assert_eq!(greenbone_service_port("8080"), None);
    }

    /// A Greenbone report is UTF-8. A stray non-UTF-8 byte inside a field
    /// means the artifact was truncated or corrupted, so parsing stops at
    /// that point instead of guessing at the intended text; results that
    /// were already fully read are kept and the raw artifact stays retained.
    #[test]
    fn greenbone_non_utf8_field_stops_parsing_but_keeps_completed_results() {
        let mut xml =
            br#"<results><result id="result-1"><name>First result</name></result><result id="result-2"><name>Bad"#
                .to_vec();
        xml.push(0xFF);
        xml.extend_from_slice(b"</name></result></results>");

        let mut warnings = Vec::new();
        let records = parse_greenbone_xml(&xml, &mut warnings)
            .expect("the earlier complete result stays preserved");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].result_id.as_deref(), Some("result-1"));
        assert!(
            warnings
                .iter()
                .any(|warning| warning.starts_with("Greenbone XML parsing stopped at byte")),
            "unexpected warnings: {warnings:?}"
        );
    }

    /// Only the predefined and numeric XML references are safe to resolve
    /// without a DTD; an HTML-only name like `&nbsp;` is exactly the kind of
    /// undeclared entity the allow-list exists to catch.
    #[test]
    fn greenbone_undefined_named_entity_is_rejected_as_a_custom_entity() {
        let xml =
            br#"<results><result id="result-1"><name>Example&nbsp;Name</name></result></results>"#;
        let mut warnings = Vec::new();
        assert!(parse_greenbone_xml(xml, &mut warnings).is_none());
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("custom entity reference was rejected")),
            "unexpected warnings: {warnings:?}"
        );
    }

    /// The attribute-count limit must trip on the attribute that actually
    /// crosses it, not one attribute later: exactly `MAX_XML_ATTRIBUTES + 1`
    /// attributes on one element is already one too many.
    #[test]
    fn greenbone_attribute_limit_boundary_is_exact() {
        let mut xml = String::from("<results><result id=\"result-1\"");
        for index in 0..MAX_XML_ATTRIBUTES {
            xml.push_str(&format!(" a{index}=\"x\""));
        }
        xml.push_str("><name>bounded</name></result></results>");

        let mut warnings = Vec::new();
        assert!(parse_greenbone_xml(xml.as_bytes(), &mut warnings).is_none());
        assert!(
            warnings
                .iter()
                .any(|warning| warning == "Greenbone XML element exceeded the attribute limit"),
            "unexpected warnings: {warnings:?}"
        );
    }

    fn cis(version: &str, reference: &str) -> BenchmarkReference {
        BenchmarkReference {
            name: "CIS Amazon Web Services Foundations".into(),
            version: version.into(),
            reference: reference.into(),
        }
    }

    #[test]
    fn scoutsuite_compliance_is_cleaned_deduplicated_and_bounded() {
        let payload = serde_json::json!({
            "findings": {
                "iam-password-policy-no-uppercase-required": {
                    "description": "Password Policy Lacks Uppercase Requirement",
                    "flagged_items": 1,
                    "level": "danger",
                    "compliance": [
                        {
                            "name": "CIS\nAmazon   Web Services Foundations",
                            "version": "1.0.0",
                            "reference": "1.5"
                        },
                        {
                            "name": "CIS Amazon Web Services Foundations",
                            "version": "1.1.0",
                            "reference": "1.5"
                        },
                        {
                            "name": "CIS Amazon Web Services Foundations",
                            "version": "1.2.0",
                            "reference": "1.5"
                        },
                        {
                            "name": "CIS Amazon Web Services Foundations",
                            "version": "1.2.0",
                            "reference": "  "
                        },
                        {
                            "name": "CIS Amazon Web Services Foundations",
                            "version": 12,
                            "reference": "1.5"
                        },
                        {
                            "name": "CIS Amazon Web Services Foundations",
                            "version": "1.2.0",
                            "reference": "1.5"
                        }
                    ]
                }
            }
        });
        let mut warnings = Vec::new();
        let records = extract_scoutsuite(&ParsedArtifact::Json(payload), &mut warnings);
        assert_eq!(records.len(), 1);
        let details = records[0]
            .scanner_details
            .as_ref()
            .expect("benchmarks create the details block");
        assert!(details.description.is_none());
        assert_eq!(
            details.benchmarks,
            vec![
                cis("1.0.0", "1.5"),
                cis("1.1.0", "1.5"),
                cis("1.2.0", "1.5")
            ]
        );

        let mut compliance = Vec::new();
        for index in 0..9 {
            compliance.push(serde_json::json!({
                "name": "CIS Amazon Web Services Foundations",
                "version": format!("1.{index}"),
                "reference": "1.5"
            }));
        }
        let overflow = serde_json::json!({
            "findings": {
                "iam-password-policy-no-uppercase-required": {
                    "description": "Password Policy Lacks Uppercase Requirement",
                    "flagged_items": 1,
                    "level": "danger",
                    "compliance": compliance
                }
            }
        });
        let records = extract_scoutsuite(&ParsedArtifact::Json(overflow), &mut warnings);
        let kept = &records[0].scanner_details.as_ref().unwrap().benchmarks;
        assert_eq!(kept.len(), MAX_SCOUTSUITE_BENCHMARKS);
        assert_eq!(
            kept.iter()
                .map(|item| item.version.clone())
                .collect::<Vec<_>>(),
            (0..8).map(|index| format!("1.{index}")).collect::<Vec<_>>()
        );
    }
}
