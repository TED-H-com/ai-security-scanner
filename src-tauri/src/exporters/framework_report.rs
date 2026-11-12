use crate::adapters::{
    control_mapping_provenance, validate_current_control_reference, validated_evidence_source_rule,
};
use crate::domain::{
    AiGeneratedArtifactAnswer, AiSystemApplicabilityAnswer, AssessmentCase, Confidence,
    ControlMappingProvenance, ControlReference, CoverageStatus, EngineRun, EngineRunStatus,
    Finding, FindingObservation, ScanRun, Severity,
};
use crate::error::{AppError, AppResult};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub const MASTER_FRAMEWORK_REPORT_SCHEMA_VERSION: &str = "1.4.0";
pub const MASTER_FRAMEWORK_REPORT_NOTICE: &str = "This report groups preliminary scanner observations by related framework coordinate. It is not an audit, certification, attestation, compliance determination, implementation assessment, score, pass, or fail. Missing relationships are unknown whenever coverage is incomplete. The legacy knowledge_date is only a run-level compatibility timestamp; engine, rule, feed, database, and mapping freshness come from their own technical records.";

const FRAMEWORKS: [(&str, &str); 7] = [
    ("NIST CSF", "2.0"),
    ("ISO/IEC 27001", "2022"),
    ("AIDEFEND", "1.20260805"),
    ("OWASP Top 10", "2021"),
    ("OWASP Top 10 for LLM Applications", "2025"),
    ("CIS Kubernetes Benchmark", "1.11"),
    ("CIS Amazon Web Services Foundations Benchmark", "3.0.0"),
];

/// Frameworks that describe AI systems specifically, and so are withheld until
/// the case declares the AI involvement they assume. Kept beside the catalog's
/// own gate rather than derived from it: this export refuses the coordinate a
/// second time so a stale frozen finding cannot carry one past the check.
const AI_GATED_FRAMEWORKS: [&str; 2] = ["AIDEFEND", "OWASP Top 10 for LLM Applications"];
const MAPPING_REVIEW_PROCESS_V1: &str = "source_coordinate_and_rationale_review_v1";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MasterFrameworkReport {
    pub schema_version: String,
    pub product_name: String,
    pub product_version: String,
    pub export_kind: String,
    pub case_id: String,
    pub selected_run_id: String,
    pub selected_run_sequence: u32,
    pub selected_run_recorded_at: DateTime<Utc>,
    /// Legacy v1.2 wire field. This aggregate timestamp is not engine, rule,
    /// feed, database, or mapping freshness and never establishes coverage.
    #[serde(rename = "knowledge_date")]
    pub legacy_knowledge_date: DateTime<Utc>,
    pub notice: String,
    pub coverage: FrameworkCoverageSummary,
    pub declared_ai_context: DeclaredAiContext,
    pub observation_provenance: Vec<HistoricalObservationProvenance>,
    pub frameworks: Vec<FrameworkSummary>,
    pub unrecognized_relationships: Vec<UnrecognizedRelationship>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FrameworkCoverageSummary {
    pub state: String,
    pub selected_run_coverage_ledger_basis: String,
    pub selected_run_checks_complete: bool,
    pub selected_run_coverage_ledger_available: bool,
    pub selected_run_coverage_has_unknown_or_incomplete_entries: bool,
    pub excluded_other_run_coverage_entry_count: usize,
    pub excluded_unbound_coverage_entry_count: usize,
    pub planned_engine_count: usize,
    pub completed_engine_count: usize,
    pub unfinished_engine_count: usize,
    pub not_executed_engine_count: usize,
    pub selected_run_planned_asset_count: usize,
    pub selected_run_matched_coverage_entry_count: usize,
    pub selected_run_missing_planned_asset_coverage_count: usize,
    pub selected_run_unmatched_coverage_entry_count: usize,
    pub unknown_source_count: usize,
    pub connected_no_asset_count: usize,
    pub authorized_incomplete_count: usize,
    pub discovered_not_authorized_count: usize,
    pub selected_run_finding_count: usize,
    pub selected_run_snapshot_count: usize,
    pub selected_run_missing_snapshot_count: usize,
    pub selected_run_observations_without_evidence_count: usize,
    /// How many of the run's findings the packaged mapping catalog could
    /// place, and how many it could not. Without the second number an absent
    /// coordinate reads as an assertion that no control relates.
    pub selected_run_findings_with_framework_relationship: usize,
    pub selected_run_findings_without_framework_relationship: usize,
    pub engine_states: BTreeMap<String, usize>,
    pub selected_run_coverage_states: BTreeMap<String, usize>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DeclaredAiContext {
    pub ai_system_applicability: String,
    pub ai_generated_artifact: String,
    pub aidefend_applicability: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FrameworkSummary {
    pub framework: String,
    pub expected_version: String,
    pub source: FrameworkSourceAttribution,
    pub observed_versions: Vec<String>,
    pub version_state: String,
    pub observed_mapping_versions: Vec<String>,
    pub evidence_engine_mapping_versions: Vec<String>,
    pub mapping_version_state: String,
    pub exact_match_relationship_count: usize,
    pub mismatch_relationship_count: usize,
    pub unavailable_relationship_count: usize,
    pub state: String,
    pub relationship_count: usize,
    pub control_count: usize,
    pub finding_count: usize,
    pub explanation: String,
    pub controls: Vec<FrameworkControlSummary>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FrameworkSourceAttribution {
    pub source_url: String,
    pub attribution_notice: String,
    pub license_notice: String,
    pub modifications_notice: String,
    pub non_endorsement_notice: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FrameworkControlSummary {
    pub control_id: String,
    pub title: String,
    pub framework_version: String,
    pub relationships: Vec<FrameworkRelationship>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FrameworkRelationship {
    pub relationship: String,
    pub rationale: String,
    pub mapping_version: String,
    pub mapping_provenance_state: String,
    pub mapping_provenance: Option<ControlMappingProvenance>,
    pub mapping_version_state: String,
    pub finding: FrameworkFindingReference,
    pub evidence_bindings: Vec<RelationshipEvidenceBinding>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RelationshipEvidenceBinding {
    pub evidence_id: String,
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub engine_run_id: String,
    pub engine_id: String,
    pub source_rule: Option<String>,
    pub engine_mapping_version: Option<String>,
    pub engine_mapping_provenance_state: String,
    pub engine_mapping_provenance: Option<ControlMappingProvenance>,
    pub mapping_version_state: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FrameworkFindingReference {
    pub observation_id: String,
    pub finding_id: String,
    pub fingerprint: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub observed_at: DateTime<Utc>,
    pub snapshot_source: String,
    pub evidence_hashes: Vec<String>,
    pub asset_ids: Vec<String>,
    pub engine_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HistoricalObservationProvenance {
    pub observation_id: String,
    pub finding_id: String,
    pub fingerprint: String,
    pub snapshot_state: String,
    pub evidence_reference_state: String,
    pub framework_mapping_state: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UnrecognizedRelationship {
    pub finding_id: String,
    pub framework: String,
    pub framework_version: String,
    pub control_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ControlCoordinate {
    framework: String,
    framework_version: String,
    control_id: String,
}

#[derive(Debug, Clone)]
struct ControlAccumulator {
    title: String,
    relationships: Vec<FrameworkRelationship>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AidefendApplicability {
    Applicable,
    NotApplicable,
    Unknown,
}

/// What the observation walk counted, handed to the coverage summary so it
/// reports the run the export actually produced rather than recounting it.
#[derive(Debug, Clone, Copy, Default)]
struct ObservationCounts {
    findings: usize,
    snapshots: usize,
    missing_snapshots: usize,
    without_evidence: usize,
    findings_with_relationship: usize,
}

#[derive(Debug, Clone)]
struct ValidatedObservationEvidence {
    state: &'static str,
    bindings: Vec<ValidatedEvidenceBinding>,
}

#[derive(Debug, Clone)]
struct ValidatedEvidenceBinding {
    evidence_id: Option<String>,
    artifact_id: String,
    artifact_sha256: String,
    engine_run_id: String,
    engine_id: String,
    source_rule: Option<String>,
    /// The scanner's own CWE classification for this evidence record. It is the
    /// second thing a relationship can be proved from: an OWASP Top 10
    /// coordinate is reached through the CWE, not through the rule id.
    cwe_ids: Vec<String>,
    engine_mapping_version: Option<String>,
    engine_mapping_provenance_state: &'static str,
    engine_mapping_provenance: Option<ControlMappingProvenance>,
}

pub fn export_master_framework_report(
    case: &AssessmentCase,
    run_id: &str,
) -> AppResult<MasterFrameworkReport> {
    let run = super::terminal_run(case, run_id)?;

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
    validate_report_wide_evidence_ids(&observations)?;

    let mut controls = BTreeMap::<ControlCoordinate, ControlAccumulator>::new();
    let mut unrecognized_relationships = Vec::new();
    let mut observation_provenance = Vec::with_capacity(observations.len());
    let mut selected_run_snapshot_count = 0_usize;
    let mut selected_run_missing_snapshot_count = 0_usize;
    let mut selected_run_observations_without_evidence_count = 0_usize;
    let mut findings_with_relationship = BTreeSet::<String>::new();
    let aidefend_applicability = aidefend_applicability(run);
    for observation in &observations {
        let Some(finding) = observation.finding_snapshot.as_ref() else {
            let validated_evidence = validate_observation_evidence(case, run, observation, None)?;
            if validated_evidence.state == "missing" {
                selected_run_observations_without_evidence_count += 1;
            }
            selected_run_missing_snapshot_count += 1;
            observation_provenance.push(HistoricalObservationProvenance {
                observation_id: observation.id.clone(),
                finding_id: observation.finding_id.clone(),
                fingerprint: observation.fingerprint.clone(),
                snapshot_state: "legacy_run_snapshot_missing".into(),
                evidence_reference_state: validated_evidence.state.into(),
                framework_mapping_state: "not_exported_without_run_snapshot".into(),
            });
            // A mutable current Finding is deliberately not used to reconstruct
            // historical control relationships. The limitation remains visible
            // in the selected-run provenance ledger instead.
            continue;
        };
        selected_run_snapshot_count += 1;
        let validated_evidence =
            validate_observation_evidence(case, run, observation, Some(finding))?;
        if validated_evidence.state == "missing" {
            selected_run_observations_without_evidence_count += 1;
        }
        observation_provenance.push(HistoricalObservationProvenance {
            observation_id: observation.id.clone(),
            finding_id: observation.finding_id.clone(),
            fingerprint: observation.fingerprint.clone(),
            snapshot_state: "run_snapshot".into(),
            evidence_reference_state: validated_evidence.state.into(),
            framework_mapping_state: if validated_evidence.bindings.is_empty() {
                "not_exported_without_exact_evidence"
            } else if finding.control_references.is_empty() {
                // The snapshot is complete and its evidence is exact. The
                // packaged catalog simply carries no entry for the rule that
                // produced this finding, and saying relationships were used
                // would read as "this finding relates to no control" -- a
                // claim about the frameworks that this product never made.
                "no_packaged_catalog_relationship"
            } else {
                "run_snapshot_relationships_used"
            }
            .into(),
        });
        if validated_evidence.bindings.is_empty() {
            // A coordinate without an exact selected-run evidence artifact is
            // historical metadata, not an evidence-bound relationship.
            continue;
        }
        for reference in &finding.control_references {
            let recognized = FRAMEWORKS
                .iter()
                .find(|(framework, _)| *framework == reference.framework);
            validate_reference_identity(reference, recognized.is_some())?;
            if recognized.is_none() {
                unrecognized_relationships.push(UnrecognizedRelationship {
                    finding_id: finding.id.clone(),
                    framework: reference.framework.clone(),
                    framework_version: reference.framework_version.clone(),
                    control_id: reference.control_id.clone(),
                });
                continue;
            }
            if AI_GATED_FRAMEWORKS.contains(&reference.framework.as_str())
                && aidefend_applicability != AidefendApplicability::Applicable
            {
                return Err(AppError::InvalidRequest(format!(
                    "{} reference {} has no explicit applicable AI-system or AI-generated-artifact context",
                    reference.framework, reference.control_id
                )));
            }
            findings_with_relationship.insert(finding.id.clone());
            let coordinate = control_coordinate(reference);
            let relationship = relationship_from_reference(
                reference,
                finding,
                observation,
                &validated_evidence.bindings,
                run.frozen_ai_system_applicability() == AiSystemApplicabilityAnswer::Applicable,
                run.ai_generated_artifact == AiGeneratedArtifactAnswer::Yes,
            )?;
            match controls.entry(coordinate) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(ControlAccumulator {
                        title: reference.title.clone(),
                        relationships: vec![relationship],
                    });
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    if entry.get().title != reference.title {
                        return Err(AppError::InvalidRequest(format!(
                            "framework coordinate {} {} {} has conflicting titles in immutable finding snapshots",
                            reference.framework, reference.framework_version, reference.control_id
                        )));
                    }
                    entry.get_mut().relationships.push(relationship);
                }
            }
        }
    }
    unrecognized_relationships.sort_by(|left, right| {
        left.framework
            .cmp(&right.framework)
            .then_with(|| left.framework_version.cmp(&right.framework_version))
            .then_with(|| left.control_id.cmp(&right.control_id))
            .then_with(|| left.finding_id.cmp(&right.finding_id))
    });

    let selected_run_finding_count = observations
        .iter()
        .filter(|observation| {
            let details = observation.finding_snapshot.as_ref().or_else(|| {
                case.findings
                    .iter()
                    .find(|finding| finding.id == observation.finding_id)
            });
            !details.is_some_and(|finding| {
                finding
                    .severity_basis_code
                    .is_some_and(|code| code.is_exposure_observation())
            })
        })
        .map(|observation| observation.finding_id.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let coverage = coverage_summary(
        case,
        run_id,
        ObservationCounts {
            findings: selected_run_finding_count,
            snapshots: selected_run_snapshot_count,
            missing_snapshots: selected_run_missing_snapshot_count,
            without_evidence: selected_run_observations_without_evidence_count,
            findings_with_relationship: findings_with_relationship.len(),
        },
    );
    let frameworks = FRAMEWORKS
        .into_iter()
        .map(|(framework, expected_version)| {
            framework_summary(
                framework,
                expected_version,
                &controls,
                &coverage,
                aidefend_applicability,
            )
        })
        .collect::<AppResult<Vec<_>>>()?;
    let frozen_ai_system_applicability = run.frozen_ai_system_applicability();
    let declared_ai_context = DeclaredAiContext {
        ai_system_applicability: enum_key(&frozen_ai_system_applicability),
        ai_generated_artifact: enum_key(&run.ai_generated_artifact),
        aidefend_applicability: aidefend_applicability_key(aidefend_applicability).into(),
        explanation: match aidefend_applicability {
            AidefendApplicability::Applicable => "At least one frozen answer explicitly identifies an AI system or an AI-generated or materially AI-modified artifact. Evidence-bound AIDEFEND coordinates may therefore appear when their mapping condition is met.",
            AidefendApplicability::NotApplicable => "The frozen answers explicitly identify a non-AI assessment and a non-AI-generated artifact. AIDEFEND coordinates are not inferred for this run.",
            AidefendApplicability::Unknown => "At least one required AI-context answer is legacy or unanswered, and no answer explicitly establishes AI applicability. AIDEFEND applicability remains unknown.",
        }
        .into(),
    };

    Ok(MasterFrameworkReport {
        schema_version: MASTER_FRAMEWORK_REPORT_SCHEMA_VERSION.into(),
        product_name: "ai-security-scanner".into(),
        product_version: env!("CARGO_PKG_VERSION").into(),
        export_kind: "master_framework_relationship_report".into(),
        case_id: case.id.clone(),
        selected_run_id: run.id.clone(),
        selected_run_sequence: run.sequence,
        selected_run_recorded_at: run.completed_at.unwrap_or(run.created_at),
        legacy_knowledge_date: run.knowledge_cutoff,
        notice: MASTER_FRAMEWORK_REPORT_NOTICE.into(),
        coverage,
        declared_ai_context,
        observation_provenance,
        frameworks,
        unrecognized_relationships,
    })
}

pub fn export_master_framework_report_bytes(
    case: &AssessmentCase,
    run_id: &str,
) -> AppResult<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(&export_master_framework_report(case, run_id)?)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate_observation_evidence(
    case: &AssessmentCase,
    run: &ScanRun,
    observation: &FindingObservation,
    snapshot: Option<&Finding>,
) -> AppResult<ValidatedObservationEvidence> {
    let observation_engines = normalized_strings(&observation.engine_ids);
    for engine_id in &observation_engines {
        let present = run
            .engine_runs
            .iter()
            .any(|engine_run| engine_run.engine_id == *engine_id);
        if !present {
            return Err(AppError::InvalidRequest(format!(
                "framework report observation {} does not resolve a selected-run engine for {}",
                observation.id, engine_id
            )));
        }
    }
    let observation_hashes = normalized_evidence_hashes(&observation.evidence_hashes)?;

    let Some(finding) = snapshot else {
        let mut bindings = Vec::new();
        for hash in &observation_hashes {
            let matching_artifacts = case
                .raw_artifacts
                .iter()
                .filter(|artifact| {
                    artifact.case_id == case.id
                        && artifact.run_id == run.id
                        && artifact.sha256.eq_ignore_ascii_case(hash)
                        && run.engine_runs.iter().any(|engine_run| {
                            engine_run.id == artifact.engine_run_id
                                && observation_engines.contains(&engine_run.engine_id)
                        })
                })
                .collect::<Vec<_>>();
            if matching_artifacts.len() != 1 {
                return Err(AppError::InvalidRequest(format!(
                    "framework report observation {} evidence hash does not resolve to one exact selected-run artifact and engine",
                    observation.id
                )));
            }
            let artifact = matching_artifacts[0];
            let engine_run = run
                .engine_runs
                .iter()
                .find(|engine_run| engine_run.id == artifact.engine_run_id)
                .expect("the exact artifact filter resolved its engine run");
            if let Some(mapping_version) = engine_run.mapping_version.as_deref() {
                validate_reference_text("evidence engine mapping version", mapping_version, 128)?;
            }
            let engine_mapping_provenance_state = validate_engine_mapping_provenance(engine_run)?;
            bindings.push(ValidatedEvidenceBinding {
                evidence_id: None,
                artifact_id: artifact.id.clone(),
                artifact_sha256: hash.clone(),
                engine_run_id: engine_run.id.clone(),
                engine_id: engine_run.engine_id.clone(),
                source_rule: None,
                cwe_ids: Vec::new(),
                engine_mapping_version: engine_run.mapping_version.clone(),
                engine_mapping_provenance_state,
                engine_mapping_provenance: engine_run.mapping_provenance.clone(),
            });
        }
        return Ok(ValidatedObservationEvidence {
            state: if observation_hashes.is_empty() {
                "missing"
            } else {
                "validated_from_observation_only"
            },
            bindings,
        });
    };

    if finding.case_id != case.id
        || finding.id != observation.finding_id
        || finding.fingerprint != observation.fingerprint
        || finding.last_seen_run_id != observation.run_id
        || normalized_strings(&finding.asset_ids) != normalized_strings(&observation.asset_ids)
        || finding.severity != observation.severity
        || finding.confidence != observation.confidence
    {
        return Err(AppError::InvalidRequest(format!(
            "framework report observation {} does not match its immutable finding snapshot",
            observation.id
        )));
    }
    if finding.evidence.is_empty() && observation_hashes.is_empty() {
        return Ok(ValidatedObservationEvidence {
            state: "missing",
            bindings: Vec::new(),
        });
    }
    if finding.evidence.is_empty() || observation_hashes.is_empty() {
        return Err(AppError::InvalidRequest(format!(
            "framework report observation {} has inconsistent snapshot evidence references",
            observation.id
        )));
    }

    let mut evidence_ids = BTreeSet::new();
    let mut snapshot_hashes = Vec::with_capacity(finding.evidence.len());
    let mut snapshot_engines = Vec::with_capacity(finding.evidence.len());
    let mut bindings = Vec::with_capacity(finding.evidence.len());
    for evidence in &finding.evidence {
        if !evidence_ids.insert(evidence.id.as_str()) {
            return Err(AppError::InvalidRequest(format!(
                "framework report finding snapshot contains duplicate evidence ID {}",
                evidence.id
            )));
        }
        let artifacts = case
            .raw_artifacts
            .iter()
            .filter(|artifact| artifact.id == evidence.artifact_id)
            .collect::<Vec<_>>();
        if artifacts.len() != 1 {
            return Err(AppError::InvalidRequest(format!(
                "framework report evidence {} does not resolve one exact raw artifact",
                evidence.id
            )));
        }
        let artifact = artifacts[0];
        let engine_runs = run
            .engine_runs
            .iter()
            .filter(|engine_run| engine_run.id == artifact.engine_run_id)
            .collect::<Vec<_>>();
        if engine_runs.len() != 1 {
            return Err(AppError::InvalidRequest(format!(
                "framework report evidence {} does not resolve one exact engine run",
                evidence.id
            )));
        }
        let engine_run = engine_runs[0];
        if let Some(mapping_version) = engine_run.mapping_version.as_deref() {
            validate_reference_text("evidence engine mapping version", mapping_version, 128)?;
        }
        let engine_mapping_provenance_state = validate_engine_mapping_provenance(engine_run)?;
        let evidence_hash = normalized_evidence_hash(&evidence.artifact_sha256)?;
        let artifact_hash = normalized_evidence_hash(&artifact.sha256)?;
        if evidence.finding_id != finding.id
            || evidence.run_id != run.id
            || artifact.case_id != case.id
            || artifact.run_id != run.id
            || evidence_hash != artifact_hash
            || evidence.engine_id != engine_run.engine_id
            || evidence
                .engine_run_id
                .as_deref()
                .is_some_and(|engine_run_id| engine_run_id != engine_run.id)
        {
            return Err(AppError::InvalidRequest(format!(
                "framework report evidence {} does not match its finding, artifact, run, or engine provenance",
                evidence.id
            )));
        }
        let source_rule =
            validated_evidence_source_rule(evidence, &finding.fingerprint)?.map(str::to_owned);
        snapshot_hashes.push(evidence_hash);
        snapshot_engines.push(evidence.engine_id.clone());
        bindings.push(ValidatedEvidenceBinding {
            evidence_id: Some(evidence.id.clone()),
            artifact_id: artifact.id.clone(),
            artifact_sha256: artifact_hash,
            engine_run_id: engine_run.id.clone(),
            engine_id: engine_run.engine_id.clone(),
            source_rule,
            cwe_ids: evidence
                .scanner_details
                .as_ref()
                .map(|details| details.cwe_ids.clone())
                .unwrap_or_default(),
            engine_mapping_version: engine_run.mapping_version.clone(),
            engine_mapping_provenance_state,
            engine_mapping_provenance: engine_run.mapping_provenance.clone(),
        });
    }
    snapshot_hashes.sort();
    snapshot_hashes.dedup();
    snapshot_engines.sort();
    snapshot_engines.dedup();
    if snapshot_hashes != observation_hashes || snapshot_engines != observation_engines {
        return Err(AppError::InvalidRequest(format!(
            "framework report observation {} evidence hashes or engines differ from its immutable finding snapshot",
            observation.id
        )));
    }
    bindings.sort_by(|left, right| {
        left.engine_run_id
            .cmp(&right.engine_run_id)
            .then_with(|| left.artifact_id.cmp(&right.artifact_id))
            .then_with(|| left.artifact_sha256.cmp(&right.artifact_sha256))
            .then_with(|| left.evidence_id.cmp(&right.evidence_id))
    });
    Ok(ValidatedObservationEvidence {
        state: "validated_from_run_snapshot",
        bindings,
    })
}

fn validate_report_wide_evidence_ids(observations: &[&FindingObservation]) -> AppResult<()> {
    let mut evidence_ids = BTreeMap::<&str, (&str, &str)>::new();
    for observation in observations {
        let Some(snapshot) = observation.finding_snapshot.as_ref() else {
            continue;
        };
        for evidence in &snapshot.evidence {
            validate_reference_text("evidence ID", &evidence.id, 512)?;
            if let Some((first_observation, first_finding)) = evidence_ids.insert(
                evidence.id.as_str(),
                (observation.id.as_str(), snapshot.id.as_str()),
            ) {
                return Err(AppError::InvalidRequest(format!(
                    "framework report evidence ID {} is reused by selected-run observations {} / {} and {} / {}; evidence IDs must be report-wide unique",
                    evidence.id, first_observation, first_finding, observation.id, snapshot.id
                )));
            }
        }
    }
    Ok(())
}

fn normalized_strings(values: &[String]) -> Vec<String> {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    values
}

fn normalized_evidence_hashes(values: &[String]) -> AppResult<Vec<String>> {
    let mut values = values
        .iter()
        .map(|value| normalized_evidence_hash(value))
        .collect::<AppResult<Vec<_>>>()?;
    values.sort();
    values.dedup();
    Ok(values)
}

fn normalized_evidence_hash(value: &str) -> AppResult<String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::InvalidRequest(
            "framework report evidence SHA-256 must contain exactly 64 hexadecimal characters"
                .into(),
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn coverage_summary(
    case: &AssessmentCase,
    run_id: &str,
    counts: ObservationCounts,
) -> FrameworkCoverageSummary {
    let ObservationCounts {
        findings: selected_run_finding_count,
        snapshots: selected_run_snapshot_count,
        missing_snapshots: selected_run_missing_snapshot_count,
        without_evidence: selected_run_observations_without_evidence_count,
        findings_with_relationship: selected_run_findings_with_framework_relationship,
    } = counts;
    let selected_run_findings_without_framework_relationship = selected_run_finding_count
        .saturating_sub(selected_run_findings_with_framework_relationship);
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .expect("selected run was validated");
    let mut engine_states = BTreeMap::new();
    for engine in &run.engine_runs {
        *engine_states.entry(enum_key(&engine.status)).or_insert(0) += 1;
    }
    let selected_run_bound_coverage = case
        .coverage
        .iter()
        .filter(|entry| entry.last_run_id.as_deref() == Some(run_id))
        .collect::<Vec<_>>();
    let selected_run_planned_assets = run
        .scope_grant_snapshots
        .iter()
        .filter(|grant| run.scope_grant_ids.contains(&grant.id))
        .map(|grant| grant.asset_id.as_str())
        .chain(
            run.engine_runs
                .iter()
                .flat_map(|engine_run| engine_run.asset_ids.iter().map(String::as_str)),
        )
        .collect::<BTreeSet<_>>();
    let selected_run_matched_coverage = selected_run_planned_assets
        .iter()
        .filter_map(|asset_id| {
            let expected_scope_key = format!("asset:{asset_id}");
            let matches = selected_run_bound_coverage
                .iter()
                .copied()
                .filter(|entry| {
                    entry.asset_id.as_deref() == Some(*asset_id)
                        && entry.scope_key == expected_scope_key
                })
                .collect::<Vec<_>>();
            if matches.len() == 1 {
                Some(matches[0])
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let selected_run_missing_planned_asset_coverage_count = selected_run_planned_assets
        .len()
        .saturating_sub(selected_run_matched_coverage.len());
    let selected_run_unmatched_coverage_entry_count = selected_run_bound_coverage
        .len()
        .saturating_sub(selected_run_matched_coverage.len());
    let mut selected_run_coverage_states = BTreeMap::new();
    for entry in &selected_run_matched_coverage {
        *selected_run_coverage_states
            .entry(enum_key(&entry.status))
            .or_insert(0) += 1;
    }
    let completed_engine_count = run
        .engine_runs
        .iter()
        .filter(|engine| engine.status == EngineRunStatus::Completed)
        .count();
    let not_executed_engine_count = run
        .engine_runs
        .iter()
        .filter(|engine| engine.status == EngineRunStatus::NotExecuted)
        .count();
    let unfinished_engine_count = run.engine_runs.len().saturating_sub(completed_engine_count);
    let unknown_source_count = count_coverage(
        &selected_run_matched_coverage,
        CoverageStatus::SourceNotConnectedUnknown,
    );
    let connected_no_asset_count = count_coverage(
        &selected_run_matched_coverage,
        CoverageStatus::SourceConnectedNothingDiscovered,
    );
    let authorized_incomplete_count = count_coverage(
        &selected_run_matched_coverage,
        CoverageStatus::AuthorizedScanIncomplete,
    );
    let discovered_not_authorized_count = count_coverage(
        &selected_run_matched_coverage,
        CoverageStatus::DiscoveredNotAuthorized,
    );
    let selected_run_checks_complete =
        run.completed_at.is_some() && !run.engine_runs.is_empty() && unfinished_engine_count == 0;
    let excluded_other_run_coverage_entry_count = case
        .coverage
        .iter()
        .filter(|entry| {
            entry
                .last_run_id
                .as_deref()
                .is_some_and(|last_run_id| last_run_id != run_id)
        })
        .count();
    let excluded_unbound_coverage_entry_count = case
        .coverage
        .iter()
        .filter(|entry| entry.last_run_id.is_none())
        .count();
    let selected_run_coverage_ledger_available = !selected_run_matched_coverage.is_empty();
    let selected_run_coverage_has_unknown_or_incomplete_entries = selected_run_planned_assets
        .is_empty()
        || selected_run_missing_planned_asset_coverage_count > 0
        || selected_run_unmatched_coverage_entry_count > 0
        || !run.engine_admission_issues.is_empty()
        || unknown_source_count > 0
        || connected_no_asset_count > 0
        || authorized_incomplete_count > 0
        || discovered_not_authorized_count > 0;

    let mut limitations = Vec::new();
    if run.engine_runs.is_empty() {
        limitations.push("No scanner checks were recorded for the selected run.".into());
    }
    if selected_run_planned_assets.is_empty() {
        limitations.push(
            "The selected run has no frozen planned asset coordinate. Exact selected-run coverage cannot be established and remains unknown."
                .into(),
        );
    }
    if selected_run_missing_planned_asset_coverage_count > 0 {
        limitations.push(format!(
            "{selected_run_missing_planned_asset_coverage_count} frozen planned asset(s) have no unique coverage-ledger entry bound to the selected run. Missing historical coverage remains unknown; entries from later or unbound snapshots were not borrowed."
        ));
    }
    if selected_run_unmatched_coverage_entry_count > 0 {
        limitations.push(format!(
            "{selected_run_unmatched_coverage_entry_count} selected-run-bound coverage-ledger entry or entries do not uniquely match the frozen planned asset coordinates and were excluded from coverage states and counts."
        ));
    }
    if unfinished_engine_count > 0 {
        limitations.push(format!(
            "{unfinished_engine_count} scanner check(s) did not complete; their areas remain unknown."
        ));
    }
    if !run.engine_admission_issues.is_empty() {
        limitations.push(format!(
            "Packaged scanner catalog limitations: {}. Applicability: unknown. Tested or passed checks from this set: 0.",
            run.engine_admission_issues.len()
        ));
    }
    if unknown_source_count > 0 {
        limitations.push(format!(
            "{unknown_source_count} source area(s) had no visibility; this is unknown coverage, not zero assets."
        ));
    }
    if authorized_incomplete_count > 0 {
        limitations.push(format!(
            "{authorized_incomplete_count} authorized area(s) were only partly scanned."
        ));
    }
    if discovered_not_authorized_count > 0 {
        limitations.push(format!(
            "{discovered_not_authorized_count} discovered area(s) were outside the approved scan scope."
        ));
    }
    if connected_no_asset_count > 0 {
        limitations.push(format!(
            "{connected_no_asset_count} connected source(s) returned zero assets in the saved snapshot. Inventory completeness: unverified."
        ));
    }
    if selected_run_missing_snapshot_count > 0 {
        limitations.push(format!(
            "Selected-run observations without an immutable finding snapshot: {selected_run_missing_snapshot_count}. Reconstruction from mutable text or mappings: disabled."
        ));
    }
    if selected_run_observations_without_evidence_count > 0 {
        limitations.push(format!(
            "Selected-run observations without an exact evidence hash: {selected_run_observations_without_evidence_count}. Provenance status: incomplete."
        ));
    }
    if excluded_other_run_coverage_entry_count > 0 {
        let (noun, verb) = if excluded_other_run_coverage_entry_count == 1 {
            ("entry", "is")
        } else {
            ("entries", "are")
        };
        limitations.push(format!(
            "{excluded_other_run_coverage_entry_count} coverage-ledger {noun} {verb} bound to other runs and excluded from selected-run coverage states, counts, and completeness."
        ));
    }
    if excluded_unbound_coverage_entry_count > 0 {
        let (noun, verb, excluded_verb) = if excluded_unbound_coverage_entry_count == 1 {
            ("entry", "has", "was")
        } else {
            ("entries", "have", "were")
        };
        limitations.push(format!(
            "{excluded_unbound_coverage_entry_count} coverage-ledger {noun} {verb} no run ID and {excluded_verb} excluded from selected-run coverage states, counts, and completeness."
        ));
    }
    if selected_run_findings_without_framework_relationship > 0 {
        let (verb, pronoun) = if selected_run_findings_without_framework_relationship == 1 {
            ("has", "Its")
        } else {
            ("have", "Their")
        };
        limitations.push(format!(
            "{selected_run_findings_without_framework_relationship} of {selected_run_finding_count} selected-run findings {verb} no relationship in the packaged mapping catalog. {pronoun} framework position is unknown, not absent."
        ));
    }
    limitations.push(
        "No related finding or framework coordinate is interpreted as a passed control or a complete environment.".into(),
    );
    limitations.push(
        "This optional framework-relationship export retains an engine/asset ledger, not exact requested-versus-executed host, address, port, protocol, path, stage, and task dimensions. It cannot establish complete scan coverage; use the beginner master report for coverage.".into(),
    );

    FrameworkCoverageSummary {
        state: "incomplete_or_unknown".into(),
        selected_run_coverage_ledger_basis: "selected_run_entries_matching_frozen_planned_assets"
            .into(),
        selected_run_checks_complete,
        selected_run_coverage_ledger_available,
        selected_run_coverage_has_unknown_or_incomplete_entries,
        excluded_other_run_coverage_entry_count,
        excluded_unbound_coverage_entry_count,
        planned_engine_count: run.engine_runs.len(),
        completed_engine_count,
        unfinished_engine_count,
        not_executed_engine_count,
        selected_run_planned_asset_count: selected_run_planned_assets.len(),
        selected_run_matched_coverage_entry_count: selected_run_matched_coverage.len(),
        selected_run_missing_planned_asset_coverage_count,
        selected_run_unmatched_coverage_entry_count,
        unknown_source_count,
        connected_no_asset_count,
        authorized_incomplete_count,
        discovered_not_authorized_count,
        selected_run_finding_count,
        selected_run_snapshot_count,
        selected_run_missing_snapshot_count,
        selected_run_observations_without_evidence_count,
        selected_run_findings_with_framework_relationship,
        selected_run_findings_without_framework_relationship,
        engine_states,
        selected_run_coverage_states,
        limitations,
    }
}

fn count_coverage(coverage: &[&crate::domain::CoverageEntry], status: CoverageStatus) -> usize {
    coverage
        .iter()
        .filter(|entry| entry.status == status)
        .count()
}

/// Orders two control identifiers the way their own numbering reads.
///
/// Comparing them a character at a time is comparing digits as text, which put
/// ISO/IEC 27001 A.8.20 and A.8.24 between A.8.2 and A.8.6 in every framework
/// export. A digit run is compared by value: leading zeros dropped, longer run
/// first, then character by character, so no length of identifier overflows.
fn compare_control_id(left: &str, right: &str) -> std::cmp::Ordering {
    let mut left_segments = control_id_segments(left);
    let mut right_segments = control_id_segments(right);
    loop {
        return match (left_segments.next(), right_segments.next()) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (Some(left), Some(right)) => {
                let ordering = match (left, right) {
                    (ControlIdSegment::Digits(left), ControlIdSegment::Digits(right)) => {
                        let left = left.trim_start_matches('0');
                        let right = right.trim_start_matches('0');
                        left.len().cmp(&right.len()).then_with(|| left.cmp(right))
                    }
                    (ControlIdSegment::Text(left), ControlIdSegment::Text(right)) => {
                        left.cmp(right)
                    }
                    // A number sorts ahead of a word at the same position, the
                    // way "A.8.2" sorts ahead of "A.8.general".
                    (ControlIdSegment::Digits(_), ControlIdSegment::Text(_)) => {
                        std::cmp::Ordering::Less
                    }
                    (ControlIdSegment::Text(_), ControlIdSegment::Digits(_)) => {
                        std::cmp::Ordering::Greater
                    }
                };
                if ordering != std::cmp::Ordering::Equal {
                    return ordering;
                }
                continue;
            }
        };
    }
}

enum ControlIdSegment<'a> {
    Digits(&'a str),
    Text(&'a str),
}

/// Splits a control identifier into its alternating digit and non-digit runs.
fn control_id_segments(control_id: &str) -> impl Iterator<Item = ControlIdSegment<'_>> {
    let mut rest = control_id;
    std::iter::from_fn(move || {
        let first = rest.chars().next()?;
        let digits = first.is_ascii_digit();
        let at = rest
            .find(|character: char| character.is_ascii_digit() != digits)
            .unwrap_or(rest.len());
        let (segment, remainder) = rest.split_at(at);
        rest = remainder;
        Some(if digits {
            ControlIdSegment::Digits(segment)
        } else {
            ControlIdSegment::Text(segment)
        })
    })
}

fn framework_summary(
    framework: &str,
    expected_version: &str,
    catalog_controls: &BTreeMap<ControlCoordinate, ControlAccumulator>,
    coverage: &FrameworkCoverageSummary,
    aidefend_applicability: AidefendApplicability,
) -> AppResult<FrameworkSummary> {
    let mut controls = catalog_controls
        .iter()
        .filter(|(key, _)| key.framework == framework)
        .map(|(key, accumulator)| {
            let mut relationships = accumulator.relationships.clone();
            relationships.sort_by(|left, right| {
                left.mapping_version
                    .cmp(&right.mapping_version)
                    .then_with(|| left.rationale.cmp(&right.rationale))
                    .then_with(|| left.finding.fingerprint.cmp(&right.finding.fingerprint))
                    .then_with(|| {
                        left.finding
                            .observation_id
                            .cmp(&right.finding.observation_id)
                    })
            });
            relationships.dedup();
            FrameworkControlSummary {
                control_id: key.control_id.clone(),
                title: accumulator.title.clone(),
                framework_version: key.framework_version.clone(),
                relationships,
            }
        })
        .collect::<Vec<_>>();
    controls.sort_by(|left, right| {
        left.framework_version
            .cmp(&right.framework_version)
            .then_with(|| compare_control_id(&left.control_id, &right.control_id))
            .then_with(|| left.control_id.cmp(&right.control_id))
    });
    let observed_versions = controls
        .iter()
        .map(|control| control.framework_version.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let observed_mapping_versions = controls
        .iter()
        .flat_map(|control| {
            control
                .relationships
                .iter()
                .map(|relationship| relationship.mapping_version.clone())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let evidence_engine_mapping_versions = controls
        .iter()
        .flat_map(|control| {
            control
                .relationships
                .iter()
                .flat_map(|relationship| relationship.evidence_bindings.iter())
                .filter_map(|binding| binding.engine_mapping_version.clone())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let version_state = if observed_versions.is_empty() {
        "no_relationship_observed"
    } else if observed_versions
        .iter()
        .all(|observed| observed == expected_version)
    {
        "expected_version_only"
    } else {
        "unexpected_version_observed"
    };
    let exact_match_relationship_count = controls
        .iter()
        .flat_map(|control| control.relationships.iter())
        .filter(|relationship| relationship.mapping_version_state == "exact_match")
        .count();
    let mismatch_relationship_count = controls
        .iter()
        .flat_map(|control| control.relationships.iter())
        .filter(|relationship| relationship.mapping_version_state == "mismatch")
        .count();
    let unavailable_relationship_count = controls
        .iter()
        .flat_map(|control| control.relationships.iter())
        .filter(|relationship| relationship.mapping_version_state == "unavailable")
        .count();
    let mapping_version_state = if observed_mapping_versions.is_empty() {
        "no_relationship_observed"
    } else if mismatch_relationship_count > 0 {
        "relationship_mismatch_observed"
    } else if unavailable_relationship_count > 0 {
        "relationship_provenance_unavailable"
    } else {
        "all_relationships_exact_match"
    };
    let finding_count = controls
        .iter()
        .flat_map(|control| {
            control
                .relationships
                .iter()
                .map(|relationship| relationship.finding.finding_id.as_str())
        })
        .collect::<BTreeSet<_>>()
        .len();
    let relationship_count = controls
        .iter()
        .map(|control| control.relationships.len())
        .sum();
    let (state, explanation) = if !controls.is_empty() {
        (
            "related_coordinates_observed",
            "One or more preliminary findings carry an evidence-bound relationship to this framework. The relationship is a navigation aid, not a control result.",
        )
    } else if AI_GATED_FRAMEWORKS.contains(&framework)
        && aidefend_applicability == AidefendApplicability::NotApplicable
    {
        (
            "not_applicable_to_declared_context",
            "The frozen answers explicitly identify a non-AI assessment and a non-AI-generated artifact, so coordinates from frameworks that only describe AI systems were not inferred.",
        )
    } else if AI_GATED_FRAMEWORKS.contains(&framework)
        && aidefend_applicability == AidefendApplicability::Unknown
    {
        (
            "unknown_due_to_unanswered_context",
            "No coordinate from this AI-specific framework was inferred because at least one required AI-context answer is legacy or unanswered. This remains unknown, not not-applicable.",
        )
    } else if coverage.state == "incomplete_or_unknown" {
        (
            "unknown_due_to_incomplete_coverage",
            "No related coordinate was observed, but coverage is incomplete or unknown. This cannot be interpreted as a passed or implemented control.",
        )
    } else {
        (
            "no_related_coordinate_observed",
            "No selected-run finding carried an evidence-bound relationship to this framework. This is not a pass, implementation claim, or compliance conclusion.",
        )
    };
    Ok(FrameworkSummary {
        framework: framework.into(),
        expected_version: expected_version.into(),
        source: framework_source_attribution(framework),
        observed_versions,
        version_state: version_state.into(),
        observed_mapping_versions,
        evidence_engine_mapping_versions,
        mapping_version_state: mapping_version_state.into(),
        exact_match_relationship_count,
        mismatch_relationship_count,
        unavailable_relationship_count,
        state: state.into(),
        relationship_count,
        control_count: controls.len(),
        finding_count,
        explanation: explanation.into(),
        controls,
    })
}

fn framework_source_attribution(framework: &str) -> FrameworkSourceAttribution {
    match framework {
        "NIST CSF" => FrameworkSourceAttribution {
            source_url: "https://doi.org/10.6028/NIST.CSWP.29".into(),
            attribution_notice: "NIST Cybersecurity Framework (CSF) 2.0, National Institute of Standards and Technology.".into(),
            license_notice: "Use of NIST source material remains subject to the source publication's notices.".into(),
            modifications_notice: "Framework relationships and rationales in this report are project-authored navigation metadata.".into(),
            non_endorsement_notice: "NIST has not reviewed or endorsed this report or integration.".into(),
        },
        "ISO/IEC 27001" => FrameworkSourceAttribution {
            source_url: "https://www.iso.org/standard/27001".into(),
            attribution_notice: "ISO/IEC 27001:2022 control coordinates are referenced nominatively.".into(),
            license_notice: "ISO/IEC standard content remains subject to ISO's terms; this report is not a copy of the standard.".into(),
            modifications_notice: "Framework relationships and rationales in this report are project-authored navigation metadata.".into(),
            non_endorsement_notice: "ISO and IEC have not reviewed or endorsed this report or integration.".into(),
        },
        "AIDEFEND" => FrameworkSourceAttribution {
            source_url: "https://github.com/edward-playground/aidefense-framework/blob/e10c1678ee49f03f8fb0c97d446ba3fbc3543655/data/data.json".into(),
            attribution_notice: "AIDEFEND AI Defense Framework, created by Edward Lee, https://aidefend.net, licensed under CC BY 4.0.".into(),
            license_notice: "Creative Commons Attribution 4.0 International: https://creativecommons.org/licenses/by/4.0/".into(),
            modifications_notice: "ai-security-scanner uses a modified, project-authored six-record metadata selection from AIDEFEND 1.20260805 at pinned commit e10c1678ee49f03f8fb0c97d446ba3fbc3543655.".into(),
            non_endorsement_notice: "This independent integration is not affiliated with, approved, certified, sponsored, or endorsed by AIDEFEND or its owner.".into(),
        },
        "OWASP Top 10" => FrameworkSourceAttribution {
            source_url: "https://owasp.org/Top10/".into(),
            attribution_notice: "OWASP Top 10:2021, Copyright (c) 2003-2025 The OWASP Foundation, Inc., licensed under CC BY-SA 4.0.".into(),
            license_notice: "Creative Commons Attribution-ShareAlike 4.0 International: https://creativecommons.org/licenses/by-sa/4.0/".into(),
            modifications_notice: "Category membership is read from the CWE sets OWASP publishes for each 2021 category; the rationales beside them are project-authored navigation metadata.".into(),
            non_endorsement_notice: "The OWASP Foundation has not reviewed or endorsed this report or integration.".into(),
        },
        "OWASP Top 10 for LLM Applications" => FrameworkSourceAttribution {
            source_url: "https://genai.owasp.org/llm-top-10/".into(),
            attribution_notice: "OWASP Top 10 for LLM Applications 2025, OWASP GenAI Security Project, Copyright (c) The OWASP Foundation, Inc., licensed under CC BY-SA 4.0.".into(),
            license_notice: "Creative Commons Attribution-ShareAlike 4.0 International: https://creativecommons.org/licenses/by-sa/4.0/".into(),
            modifications_notice: "This report references three of the ten 2025 categories, the only ones the packaged engines produce evidence for; the rationales are project-authored navigation metadata.".into(),
            non_endorsement_notice: "The OWASP Foundation and the OWASP GenAI Security Project have not reviewed or endorsed this report or integration.".into(),
        },
        "CIS Kubernetes Benchmark" => FrameworkSourceAttribution {
            source_url: "https://www.cisecurity.org/benchmark/kubernetes".into(),
            attribution_notice: "CIS Kubernetes Benchmark v1.11 recommendation numbers and titles are referenced nominatively; they are the coordinates kube-bench itself reports against.".into(),
            license_notice: "CIS Benchmark content remains subject to the Center for Internet Security's terms of use; this report is not a copy of the benchmark.".into(),
            modifications_notice: "Recommendation titles are reproduced as the pinned kube-bench image reports them.".into(),
            non_endorsement_notice: "The Center for Internet Security has not reviewed or endorsed this report or integration.".into(),
        },
        "CIS Amazon Web Services Foundations Benchmark" => FrameworkSourceAttribution {
            source_url: "https://www.cisecurity.org/benchmark/amazon_web_services".into(),
            attribution_notice: "CIS Amazon Web Services Foundations Benchmark v3.0.0 recommendation numbers and titles are referenced nominatively.".into(),
            license_notice: "CIS Benchmark content remains subject to the Center for Internet Security's terms of use; this report is not a copy of the benchmark.".into(),
            modifications_notice: "The recommendation-to-check relationship is the one Prowler publishes in its own CIS 3.0 compliance file.".into(),
            non_endorsement_notice: "The Center for Internet Security has not reviewed or endorsed this report or integration.".into(),
        },
        _ => unreachable!("framework source is defined for every fixed report framework"),
    }
}

fn validate_reference_identity(
    reference: &ControlReference,
    recognized_framework: bool,
) -> AppResult<()> {
    validate_reference_text("framework", &reference.framework, 80)?;
    validate_reference_text("framework version", &reference.framework_version, 80)?;
    validate_reference_text("control ID", &reference.control_id, 160)?;
    if !recognized_framework {
        return Ok(());
    }
    if reference.relationship != "related" {
        return Err(AppError::InvalidRequest(format!(
            "recognized framework reference {} {} must use the exact relationship 'related'",
            reference.framework, reference.control_id
        )));
    }
    validate_reference_text("control title", &reference.title, 256)?;
    validate_reference_text("relationship rationale", &reference.rationale, 2_048)?;
    validate_reference_text("mapping version", &reference.mapping_version, 128)
}

fn validate_reference_text(label: &str, value: &str, maximum_bytes: usize) -> AppResult<()> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(AppError::InvalidRequest(format!(
            "framework report {label} is empty, malformed, or exceeds {maximum_bytes} bytes"
        )));
    }
    Ok(())
}

fn control_coordinate(reference: &ControlReference) -> ControlCoordinate {
    ControlCoordinate {
        framework: reference.framework.clone(),
        framework_version: reference.framework_version.clone(),
        control_id: reference.control_id.clone(),
    }
}

fn relationship_from_reference(
    reference: &ControlReference,
    finding: &Finding,
    observation: &FindingObservation,
    validated_bindings: &[ValidatedEvidenceBinding],
    ai_system_applicable: bool,
    ai_generated_artifact_applicable: bool,
) -> AppResult<FrameworkRelationship> {
    let (mapping_provenance_state, mapping_provenance) = validate_mapping_provenance(reference)?;
    let distinct_engine_runs = validated_bindings
        .iter()
        .map(|binding| binding.engine_run_id.as_str())
        .collect::<BTreeSet<_>>();
    let source_is_unambiguous = distinct_engine_runs.len() == 1;
    if mapping_provenance_state == "verified_current_catalog" {
        let evidence_sources = validated_bindings
            .iter()
            .map(|binding| {
                binding
                    .source_rule
                    .as_ref()
                    .map(|source_rule| (binding.engine_id.clone(), source_rule.clone()))
                    .ok_or_else(|| {
                        AppError::InvalidRequest(format!(
                            "framework reference {} {} has current catalog provenance but its evidence lacks a verified structured source rule",
                            reference.framework, reference.control_id
                        ))
                    })
            })
            .collect::<AppResult<Vec<_>>>()?;
        let evidence_cwe_ids = validated_bindings
            .iter()
            .flat_map(|binding| binding.cwe_ids.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        validate_current_control_reference(
            reference,
            &evidence_sources,
            &evidence_cwe_ids,
            ai_system_applicable,
            ai_generated_artifact_applicable,
        )?;
    }
    let mut evidence_bindings = Vec::with_capacity(validated_bindings.len());
    for binding in validated_bindings {
        let evidence_id = binding.evidence_id.clone().ok_or_else(|| {
            AppError::InvalidRequest(format!(
                "framework relationship {} {} has no exact evidence record ID",
                reference.framework, reference.control_id
            ))
        })?;
        let mapping_version_state = if !source_is_unambiguous
            || mapping_provenance_state != "verified_current_catalog"
            || binding.engine_mapping_provenance_state != "verified_current_catalog"
        {
            "unavailable"
        } else {
            match (
                binding.engine_mapping_version.as_deref(),
                reference.mapping_provenance.as_ref(),
                binding.engine_mapping_provenance.as_ref(),
            ) {
                (Some(version), _, _) if version != reference.mapping_version => "mismatch",
                (Some(_), Some(reference_provenance), Some(engine_provenance))
                    if reference_provenance == engine_provenance =>
                {
                    "exact_match"
                }
                (Some(_), Some(_), Some(_)) => "mismatch",
                _ => "unavailable",
            }
        };
        evidence_bindings.push(RelationshipEvidenceBinding {
            evidence_id,
            artifact_id: binding.artifact_id.clone(),
            artifact_sha256: binding.artifact_sha256.clone(),
            engine_run_id: binding.engine_run_id.clone(),
            engine_id: binding.engine_id.clone(),
            source_rule: binding.source_rule.clone(),
            engine_mapping_version: binding.engine_mapping_version.clone(),
            engine_mapping_provenance_state: binding.engine_mapping_provenance_state.into(),
            engine_mapping_provenance: binding.engine_mapping_provenance.clone(),
            mapping_version_state: mapping_version_state.into(),
        });
    }
    let mapping_version_state = if evidence_bindings
        .iter()
        .any(|binding| binding.mapping_version_state == "mismatch")
    {
        "mismatch"
    } else if evidence_bindings.is_empty()
        || evidence_bindings
            .iter()
            .any(|binding| binding.mapping_version_state == "unavailable")
    {
        "unavailable"
    } else {
        "exact_match"
    };
    Ok(FrameworkRelationship {
        relationship: reference.relationship.clone(),
        rationale: reference.rationale.clone(),
        mapping_version: reference.mapping_version.clone(),
        mapping_provenance_state: mapping_provenance_state.into(),
        mapping_provenance,
        mapping_version_state: mapping_version_state.into(),
        finding: finding_reference(finding, observation),
        evidence_bindings,
    })
}

fn validate_mapping_provenance(
    reference: &ControlReference,
) -> AppResult<(&'static str, Option<ControlMappingProvenance>)> {
    let Some(provenance) = reference.mapping_provenance.as_ref() else {
        return Ok(("unavailable_legacy", None));
    };
    if provenance.mapping_version != reference.mapping_version {
        return Err(AppError::InvalidRequest(format!(
            "framework reference {} {} mapping provenance version does not match its relationship snapshot",
            reference.framework, reference.control_id
        )));
    }
    let state = validate_mapping_provenance_document(
        provenance,
        &format!(
            "framework reference {} {}",
            reference.framework, reference.control_id
        ),
    )?;
    Ok((state, Some(provenance.clone())))
}

fn validate_engine_mapping_provenance(engine_run: &EngineRun) -> AppResult<&'static str> {
    let Some(provenance) = engine_run.mapping_provenance.as_ref() else {
        return Ok("unavailable_legacy");
    };
    let Some(mapping_version) = engine_run.mapping_version.as_deref() else {
        return Err(AppError::InvalidRequest(format!(
            "framework report engine run {} has mapping provenance but no mapping version",
            engine_run.id
        )));
    };
    if provenance.mapping_version != mapping_version {
        return Err(AppError::InvalidRequest(format!(
            "framework report engine run {} mapping provenance version does not match its frozen mapping version",
            engine_run.id
        )));
    }
    validate_mapping_provenance_document(
        provenance,
        &format!("framework report engine run {}", engine_run.id),
    )
}

fn validate_mapping_provenance_document(
    provenance: &ControlMappingProvenance,
    context: &str,
) -> AppResult<&'static str> {
    let mapping_date = mapping_version_date(&provenance.mapping_version)?;
    let reviewed_at =
        NaiveDate::parse_from_str(&provenance.reviewed_at, "%Y-%m-%d").map_err(|_| {
            AppError::InvalidRequest(format!(
                "{context} mapping provenance reviewed_at is not a real calendar date"
            ))
        })?;
    if provenance.reviewed_at.len() != 10 || reviewed_at < mapping_date {
        return Err(AppError::InvalidRequest(format!(
            "{context} mapping provenance review date predates its mapping version or is malformed"
        )));
    }
    validate_reference_text("mapping review process", &provenance.review_process, 128)?;
    if provenance.review_process != MAPPING_REVIEW_PROCESS_V1 {
        return Err(AppError::InvalidRequest(format!(
            "{context} mapping provenance review process is not recognized"
        )));
    }
    let canonical_sha256 = normalized_evidence_hash(&provenance.catalog_sha256)?;
    if canonical_sha256 != provenance.catalog_sha256 {
        return Err(AppError::InvalidRequest(
            "framework report mapping catalog SHA-256 must use lowercase hexadecimal".into(),
        ));
    }

    let current = control_mapping_provenance()?;
    let state = if provenance.mapping_version == current.mapping_version {
        if provenance != &current {
            return Err(AppError::InvalidRequest(format!(
                "{context} current catalog provenance does not match the embedded canonical catalog"
            )));
        }
        "verified_current_catalog"
    } else {
        // The digest remains useful as a frozen identifier, but this binary
        // has no authenticated copy of that historical catalog to verify.
        // Never turn mutually matching, user-editable historical fields into
        // an exact relationship claim.
        "unverified_historical_catalog"
    };
    Ok(state)
}

fn mapping_version_date(value: &str) -> AppResult<NaiveDate> {
    let Some((date, revision)) = value.split_once('.') else {
        return Err(AppError::InvalidRequest(
            "framework report mapping provenance version must be YYYY-MM-DD.N".into(),
        ));
    };
    if date.len() != 10
        || date.as_bytes().get(4) != Some(&b'-')
        || date.as_bytes().get(7) != Some(&b'-')
        || revision.starts_with('0')
        || !revision.parse::<u32>().is_ok_and(|value| value > 0)
    {
        return Err(AppError::InvalidRequest(
            "framework report mapping provenance version must be YYYY-MM-DD.N".into(),
        ));
    }
    NaiveDate::parse_from_str(date, "%Y-%m-%d").map_err(|_| {
        AppError::InvalidRequest(
            "framework report mapping provenance version contains an invalid calendar date".into(),
        )
    })
}

fn aidefend_applicability(run: &ScanRun) -> AidefendApplicability {
    if run.frozen_ai_system_applicability() == AiSystemApplicabilityAnswer::Applicable
        || run.ai_generated_artifact == AiGeneratedArtifactAnswer::Yes
    {
        AidefendApplicability::Applicable
    } else if run.frozen_ai_system_applicability() == AiSystemApplicabilityAnswer::NotApplicable
        && run.ai_generated_artifact == AiGeneratedArtifactAnswer::No
    {
        AidefendApplicability::NotApplicable
    } else {
        AidefendApplicability::Unknown
    }
}

fn aidefend_applicability_key(value: AidefendApplicability) -> &'static str {
    match value {
        AidefendApplicability::Applicable => "applicable",
        AidefendApplicability::NotApplicable => "not_applicable",
        AidefendApplicability::Unknown => "unknown",
    }
}

fn finding_reference(
    finding: &Finding,
    observation: &FindingObservation,
) -> FrameworkFindingReference {
    let mut asset_ids = observation.asset_ids.clone();
    asset_ids.sort();
    asset_ids.dedup();
    let mut engine_ids = observation.engine_ids.clone();
    engine_ids.sort();
    engine_ids.dedup();
    let mut evidence_hashes = observation
        .evidence_hashes
        .iter()
        .map(|hash| hash.to_ascii_lowercase())
        .collect::<Vec<_>>();
    evidence_hashes.sort();
    evidence_hashes.dedup();
    FrameworkFindingReference {
        observation_id: observation.id.clone(),
        finding_id: finding.id.clone(),
        fingerprint: observation.fingerprint.clone(),
        title: finding.title.clone(),
        severity: severity_name(&observation.severity).into(),
        confidence: confidence_name(&observation.confidence).into(),
        observed_at: observation.observed_at,
        snapshot_source: "run_snapshot".into(),
        evidence_hashes,
        asset_ids,
        engine_ids,
    }
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

fn enum_key<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::stable_evidence_id;
    use crate::domain::*;
    use chrono::TimeZone;
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    const DYNAMIC_CODE_RULE: &str = "ai-security-scanner.python.dynamic-code-execution";
    const SHELL_RULE: &str = "ai-security-scanner.python.shell-true";

    #[test]
    fn control_identifiers_order_by_their_own_numbering() {
        let mut ordered = vec![
            "A.8.24", "A.5.7", "A.8.2", "A.8.9", "A.5.15", "A.8.20", "A.8.6", "A.5.7a",
        ];
        ordered.sort_by(|left, right| compare_control_id(left, right));
        assert_eq!(
            ordered,
            [
                "A.5.7", "A.5.7a", "A.5.15", "A.8.2", "A.8.6", "A.8.9", "A.8.20", "A.8.24",
            ],
            "string order puts A.8.20 and A.8.24 between A.8.2 and A.8.6"
        );

        // Zero padding is a spelling of the same number, and no digit run is
        // long enough to be parsed into an integer that could overflow.
        assert_eq!(
            compare_control_id("PR.AA-01", "PR.AA-1"),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            compare_control_id(&format!("A.{}", "9".repeat(40)), "A.100"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn framework_export_preserves_unknown_severity() {
        assert_eq!(severity_name(&Severity::Unknown), "unknown");
    }

    fn bind_current_evidence_identity(
        evidence: &mut Evidence,
        finding_fingerprint: &str,
        source_rule: &str,
        pointer: &str,
    ) {
        let pointer_sha256 = hex::encode(Sha256::digest(pointer.as_bytes()));
        let engine_run_id = evidence
            .engine_run_id
            .as_deref()
            .expect("current evidence requires an exact engine run");
        evidence.id = stable_evidence_id(
            finding_fingerprint,
            &evidence.engine_id,
            source_rule,
            &evidence.artifact_sha256,
            &pointer_sha256,
            engine_run_id,
        );
        evidence.source_rule = Some(source_rule.into());
        evidence.result_pointer_sha256 = Some(pointer_sha256);
        evidence.pointer = Some(pointer.into());
    }

    fn fixture() -> AssessmentCase {
        let time = Utc.with_ymd_and_hms(2026, 8, 29, 12, 0, 0).unwrap();
        let mapping_provenance = control_mapping_provenance().unwrap();
        let mut case = AssessmentCase::new(
            "Framework report".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "1-10".into(),
                data_classes: vec![DataClass::General],
                notes: None,
            },
        );
        case.id = "case-1".into();
        case.coverage.push(CoverageEntry {
            id: "coverage-1".into(),
            scope_key: "asset:asset-1".into(),
            label: "Planned asset".into(),
            source_kind: SourceKind::AwsOrganization,
            asset_id: Some("asset-1".into()),
            status: CoverageStatus::SourceNotConnectedUnknown,
            explanation: "Not connected".into(),
            last_run_id: Some("run-1".into()),
            observed_at: Some(time),
        });
        case.scan_runs.push(ScanRun {
            campaign_id: None,
            id: "run-1".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: time,
            completed_at: Some(time),
            request_outcome: None,
            report_asset_snapshots: Vec::new(),
            knowledge_cutoff: time,
            ai_system_applicable: true,
            ai_system_applicability: AiSystemApplicabilityAnswer::Applicable,
            ai_generated_artifact: AiGeneratedArtifactAnswer::Yes,
            verification_baseline_run_id: None,
            scope_grant_ids: vec![],
            scope_grant_snapshots: vec![],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![EngineRun {
                unattributed: Vec::new(),
                unevaluated_targets: Vec::new(),
                security_template_executions: Vec::new(),
                manual_review_controls: Vec::new(),
                id: "engine-run-1".into(),
                scan_run_id: "run-1".into(),
                engine_id: "semgrep".into(),
                task_kind: Default::default(),
                localhost_tcp_observation: None,
                asset_ids: vec!["asset-1".into()],
                status: EngineRunStatus::Failed,
                progress_percent: 40,
                phase: "failed".into(),
                started_at: Some(time),
                finished_at: Some(time),
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
                mapping_version: Some(mapping_provenance.mapping_version.clone()),
                mapping_provenance: Some(mapping_provenance.clone()),
                fingerprint_schema_version: None,
                runtime_provider: None,
                runtime_version: None,
                runtime_security_options: None,
                exit_code: Some(1),
                cleanup_removed: Some(true),
                cleanup_detail: None,
                gateway_refusals: None,
                warnings: vec![],
                raw_artifact_ids: vec![],
                error_code: Some("execution_failed".into()),
                error_message: None,
            }],
        });
        let evidence_hash = "a".repeat(64);
        case.raw_artifacts.push(RawArtifact {
            id: "artifact-1".into(),
            case_id: case.id.clone(),
            run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            relative_path: "evidence.json".into(),
            media_type: "application/json".into(),
            sha256: evidence_hash.clone(),
            byte_length: 2,
            created_at: time,
            contains_sensitive_data: false,
        });
        let mut finding = Finding { family: None, severity_basis_code: None, confidence_basis_code: None,
        context_factors: Vec::new(),
            id: "finding-1".into(),
            case_id: case.id.clone(),
            first_seen_run_id: "run-1".into(),
            last_seen_run_id: "run-1".into(),
            fingerprint: "fp-1".into(),
            title: "Review generated code".into(),
            plain_language_summary: "A risky construct was found.".into(),
            possible_impact: "Unexpected code execution".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            priority: 90,
            priority_reasons: vec![],
            asset_ids: vec!["asset-1".into()],
            evidence: vec![Evidence {
                id: "evidence-1".into(),
                finding_id: "finding-1".into(),
                run_id: "run-1".into(),
                engine_run_id: Some("engine-run-1".into()),
                kind: EvidenceKind::SourceCode,
                engine_id: "semgrep".into(),
                scanner_details: None,
                source_rule: None,
                result_pointer_sha256: None,
                observed_at: time,
                summary: "Exact fixture evidence".into(),
                location: None,
                artifact_id: "artifact-1".into(),
                artifact_sha256: evidence_hash.clone(),
                pointer: None,
                redacted: false,
            }],
            control_references: vec![
                ControlReference {
                    framework: "NIST CSF".into(),
                    framework_version: "2.0".into(),
                    control_id: "PR.PS-06".into(),
                    title: "Secure software development practices".into(),
                    relationship: "related".into(),
                    rationale: "Static-analysis evidence of dynamic code execution is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.".into(),
                    mapping_version: mapping_provenance.mapping_version.clone(),
                    mapping_provenance: Some(mapping_provenance.clone()),
                },
                ControlReference {
                    framework: "ISO/IEC 27001".into(),
                    framework_version: "2022".into(),
                    control_id: "A.8.28".into(),
                    title: "Secure coding practices".into(),
                    relationship: "related".into(),
                    rationale: "Static-analysis evidence of dynamic code execution is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.".into(),
                    mapping_version: mapping_provenance.mapping_version.clone(),
                    mapping_provenance: Some(mapping_provenance.clone()),
                },
                ControlReference {
                    framework: "AIDEFEND".into(),
                    framework_version: "1.20260805".into(),
                    control_id: "AID-H-025.001".into(),
                    title: "Pre-Execution Static Analysis & Dangerous Construct Blocking".into(),
                    relationship: "related".into(),
                    rationale: "Static-analysis evidence of dynamic code execution is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.".into(),
                    mapping_version: mapping_provenance.mapping_version.clone(),
                    mapping_provenance: Some(mapping_provenance),
                },
            ],
            recommendation: "Ask an application security engineer to review it.".into(),
            verification_guidance: "Repeat the check.".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Application security engineer".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![],
        };
        bind_current_evidence_identity(
            &mut finding.evidence[0],
            "fp-1",
            DYNAMIC_CODE_RULE,
            "/result/0",
        );
        case.findings.push(finding.clone());
        case.finding_observations.push(FindingObservation {
            id: "observation-1".into(),
            run_id: "run-1".into(),
            finding_id: finding.id.clone(),
            fingerprint: finding.fingerprint.clone(),
            asset_ids: vec!["asset-1".into()],
            engine_ids: vec!["semgrep".into()],
            severity: Severity::High,
            confidence: Confidence::High,
            evidence_hashes: vec![evidence_hash],
            observed_at: time,
            finding_snapshot: Some(finding),
        });
        case
    }

    /// A second finding on the same run whose rule the packaged catalog does
    /// not carry. Everything about it is complete -- immutable snapshot, exact
    /// evidence, terminal run -- so nothing else in the export flags it.
    fn add_unmapped_finding(case: &mut AssessmentCase) {
        let source = case.finding_observations[0]
            .finding_snapshot
            .clone()
            .expect("the fixture observation carries its snapshot");
        let mut finding = source.clone();
        finding.id = "finding-2".into();
        finding.fingerprint = "fp-2".into();
        finding.title = "A rule the catalog does not carry".into();
        finding.control_references.clear();
        for evidence in &mut finding.evidence {
            evidence.finding_id = finding.id.clone();
            bind_current_evidence_identity(
                evidence,
                &finding.fingerprint,
                "ai-security-scanner.python.rule-no-catalog-entry",
                "/result/1",
            );
        }
        let observation = FindingObservation {
            id: "observation-2".into(),
            finding_id: finding.id.clone(),
            fingerprint: finding.fingerprint.clone(),
            finding_snapshot: Some(finding.clone()),
            ..case.finding_observations[0].clone()
        };
        case.findings.push(finding);
        case.finding_observations.push(observation);
    }

    #[test]
    fn a_finding_the_catalog_cannot_place_is_counted_and_said_so() {
        let mut case = fixture();
        add_unmapped_finding(&mut case);
        let report = export_master_framework_report(&case, "run-1").unwrap();

        // The provenance ledger has to separate the two. Before it did, an
        // unmapped finding claimed "run_snapshot_relationships_used" -- the
        // same words as a finding that carried three coordinates.
        let states = report
            .observation_provenance
            .iter()
            .map(|entry| {
                (
                    entry.finding_id.as_str(),
                    entry.framework_mapping_state.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            states,
            [
                ("finding-1", "run_snapshot_relationships_used"),
                ("finding-2", "no_packaged_catalog_relationship"),
            ]
        );

        assert_eq!(report.coverage.selected_run_finding_count, 2);
        assert_eq!(
            report
                .coverage
                .selected_run_findings_with_framework_relationship,
            1
        );
        assert_eq!(
            report
                .coverage
                .selected_run_findings_without_framework_relationship,
            1
        );
        // And the reader of the summary alone is told, without walking the
        // per-observation ledger.
        assert!(
            report.coverage.limitations.iter().any(|limitation| limitation
                == "1 of 2 selected-run findings has no relationship in the packaged mapping catalog. Its framework position is unknown, not absent."),
            "{:#?}",
            report.coverage.limitations
        );
    }

    #[test]
    fn a_fully_mapped_run_claims_no_mapping_limitation() {
        let report = export_master_framework_report(&fixture(), "run-1").unwrap();

        assert_eq!(
            report
                .coverage
                .selected_run_findings_without_framework_relationship,
            0
        );
        assert!(
            !report
                .coverage
                .limitations
                .iter()
                .any(|limitation| limitation.contains("packaged mapping catalog")),
            "{:#?}",
            report.coverage.limitations
        );
    }

    /// The framework blocks that actually carry a control.
    ///
    /// Every block is always present -- an empty one is the report saying "no
    /// related coordinate observed", which is a real answer -- so a test about
    /// what a relationship looks like walks only the populated blocks, and
    /// fails outright if the fixture stopped producing any.
    fn populated(report: &MasterFrameworkReport) -> Vec<&FrameworkSummary> {
        let blocks = report
            .frameworks
            .iter()
            .filter(|framework| !framework.controls.is_empty())
            .collect::<Vec<_>>();
        assert!(
            !blocks.is_empty(),
            "the fixture produced no framework block with a control"
        );
        blocks
    }

    #[test]
    fn consolidates_every_reference_framework_without_claiming_compliance() {
        let case = fixture();
        let expected_mapping_version = case.scan_runs[0].engine_runs[0]
            .mapping_version
            .clone()
            .unwrap();
        let report = export_master_framework_report(&case, "run-1").unwrap();
        assert_eq!(report.frameworks.len(), FRAMEWORKS.len());
        assert!(
            populated(&report)
                .iter()
                .all(|framework| framework.control_count == 1)
        );
        assert!(populated(&report).iter().all(|framework| {
            framework.mapping_version_state == "all_relationships_exact_match"
                && framework.evidence_engine_mapping_versions == [expected_mapping_version.clone()]
        }));
        assert!(!report.coverage.selected_run_checks_complete);
        assert!(
            report
                .coverage
                .selected_run_coverage_has_unknown_or_incomplete_entries
        );
        assert_eq!(report.coverage.unknown_source_count, 1);
        assert_eq!(report.coverage.unfinished_engine_count, 1);
        let encoded = serde_json::to_string(&report).unwrap().to_lowercase();
        for prohibited in ["compliance_score", "control_passed", "control_failed"] {
            assert!(!encoded.contains(prohibited));
        }
        assert!(report.notice.contains("not an audit"));
        assert!(report.notice.contains("legacy knowledge_date"));
        assert!(encoded.contains("\"knowledge_date\""));
        assert!(!encoded.contains("legacy_knowledge_date"));
        assert!(
            report
                .frameworks
                .iter()
                .all(|framework| framework.explanation.contains("not")
                    || framework.control_count > 0)
        );
    }

    #[test]
    fn active_run_cannot_be_exported() {
        let mut case = fixture();
        case.scan_runs[0].engine_runs[0].status = EngineRunStatus::Running;
        case.scan_runs[0].engine_runs[0].finished_at = None;
        case.scan_runs[0].completed_at = None;

        let error = export_master_framework_report(&case, "run-1").unwrap_err();
        assert!(
            matches!(error, AppError::NotAvailable(message) if message == "scan is in progress")
        );
    }

    #[test]
    fn framework_finding_count_excludes_reachable_service_inventory() {
        let mut case = fixture();
        let mut exposure = case.findings[0].clone();
        exposure.id = "service-inventory-1".into();
        exposure.fingerprint = "naabu:service-inventory-1".into();
        exposure.title = "Reachable service".into();
        exposure.severity = Severity::Informational;
        exposure.severity_basis_code = Some(crate::domain::SeverityBasisCode::OpenPort);
        exposure.priority = 0;
        exposure.priority_reasons.clear();
        exposure.control_references.clear();
        exposure.evidence.clear();
        case.findings.push(exposure.clone());
        case.finding_observations.push(FindingObservation {
            id: "service-inventory-observation-1".into(),
            run_id: "run-1".into(),
            finding_id: exposure.id.clone(),
            fingerprint: exposure.fingerprint.clone(),
            asset_ids: exposure.asset_ids.clone(),
            engine_ids: vec!["semgrep".into()],
            severity: exposure.severity.clone(),
            confidence: exposure.confidence.clone(),
            evidence_hashes: Vec::new(),
            observed_at: case.scan_runs[0].created_at,
            finding_snapshot: Some(exposure),
        });

        let report = export_master_framework_report(&case, "run-1").unwrap();

        assert_eq!(report.observation_provenance.len(), 2);
        assert_eq!(report.coverage.selected_run_finding_count, 1);
        assert_eq!(report.coverage.selected_run_snapshot_count, 2);
    }

    #[test]
    fn exact_evidence_run_prevents_same_engine_execution_set_aggregation_and_swap() {
        let mut case = fixture();
        let first_provenance = case.scan_runs[0].engine_runs[0]
            .mapping_provenance
            .clone()
            .unwrap();
        let second_provenance = ControlMappingProvenance {
            mapping_version: "2026-08-27.1".into(),
            reviewed_at: "2026-08-28".into(),
            review_process: MAPPING_REVIEW_PROCESS_V1.into(),
            catalog_sha256: "e".repeat(64),
        };
        let mut second_execution = case.scan_runs[0].engine_runs[0].clone();
        second_execution.id = "engine-run-2".into();
        second_execution.asset_ids = vec!["asset-2".into()];
        second_execution.mapping_version = Some(second_provenance.mapping_version.clone());
        second_execution.mapping_provenance = Some(second_provenance.clone());
        case.scan_runs[0].engine_runs.push(second_execution);

        let report = export_master_framework_report(&case, "run-1").unwrap();
        assert!(populated(&report).iter().all(|framework| {
            framework.mapping_version_state == "all_relationships_exact_match"
                && framework.evidence_engine_mapping_versions
                    == [first_provenance.mapping_version.clone()]
        }));

        // The set of mapping versions for `semgrep` remains unchanged, but
        // moving unverified historical provenance onto the exact evidence run
        // must make the relationship unavailable rather than exact.
        case.scan_runs[0].engine_runs[0].mapping_version =
            Some(second_provenance.mapping_version.clone());
        case.scan_runs[0].engine_runs[0].mapping_provenance = Some(second_provenance.clone());
        case.scan_runs[0].engine_runs[1].mapping_version =
            Some(first_provenance.mapping_version.clone());
        case.scan_runs[0].engine_runs[1].mapping_provenance = Some(first_provenance);
        let report = export_master_framework_report(&case, "run-1").unwrap();
        assert!(populated(&report).iter().all(|framework| {
            framework.mapping_version_state == "relationship_provenance_unavailable"
                && framework.evidence_engine_mapping_versions
                    == [second_provenance.mapping_version.clone()]
                && framework.unavailable_relationship_count == 1
        }));
    }

    #[test]
    fn output_is_deterministic_and_incomplete_absence_stays_unknown() {
        let mut case = fixture();
        case.findings[0]
            .control_references
            .retain(|reference| reference.framework != "ISO/IEC 27001");
        case.finding_observations[0].finding_snapshot = Some(case.findings[0].clone());
        let first = export_master_framework_report_bytes(&case, "run-1").unwrap();
        let second = export_master_framework_report_bytes(&case, "run-1").unwrap();
        assert_eq!(first, second);
        let report = export_master_framework_report(&case, "run-1").unwrap();
        let iso = report
            .frameworks
            .iter()
            .find(|framework| framework.framework == "ISO/IEC 27001")
            .unwrap();
        assert_eq!(iso.state, "unknown_due_to_incomplete_coverage");
        assert_eq!(iso.control_count, 0);
    }

    #[test]
    fn coverage_without_selected_run_provenance_stays_unknown() {
        let mut case = fixture();
        let mut unknown_provenance = case.coverage[0].clone();
        unknown_provenance.id = "coverage-legacy".into();
        unknown_provenance.last_run_id = None;
        case.coverage.push(unknown_provenance);
        let report = export_master_framework_report(&case, "run-1").unwrap();
        assert_eq!(report.coverage.excluded_unbound_coverage_entry_count, 1);
        assert_eq!(report.coverage.selected_run_planned_asset_count, 1);
        assert_eq!(report.coverage.selected_run_matched_coverage_entry_count, 1);
        assert_eq!(report.coverage.selected_run_finding_count, 1);
        assert!(
            report
                .coverage
                .selected_run_coverage_has_unknown_or_incomplete_entries
        );
    }

    #[test]
    fn run_bound_engine_admission_limitation_keeps_framework_coverage_incomplete() {
        let mut case = fixture();
        case.scan_runs[0]
            .engine_admission_issues
            .push(crate::domain::EngineAdmissionIssue {
                engine_id: Some("gitleaks".into()),
                code: "engine_contract_invalid".into(),
                detail: "test fixture rejection".into(),
            });

        let report = export_master_framework_report(&case, "run-1").unwrap();
        assert_eq!(report.coverage.state, "incomplete_or_unknown");
        assert!(
            report
                .coverage
                .selected_run_coverage_has_unknown_or_incomplete_entries
        );
        assert!(report.coverage.limitations.iter().any(|limitation| {
            limitation.contains("Packaged scanner catalog limitation")
                && limitation.contains("Applicability")
        }));
    }

    #[test]
    fn historical_export_never_borrows_coverage_overwritten_by_a_later_run() {
        let mut case = fixture();
        case.scan_runs[0].engine_runs[0].status = EngineRunStatus::Completed;
        case.scan_runs[0].engine_runs[0].progress_percent = 100;
        case.scan_runs[0].engine_runs[0].error_code = None;

        let mut later_run = case.scan_runs[0].clone();
        later_run.id = "run-2".into();
        later_run.sequence = 2;
        later_run.engine_runs.clear();
        case.scan_runs.push(later_run);
        case.coverage[0].last_run_id = Some("run-2".into());
        case.coverage[0].status = CoverageStatus::DiscoveredAuthorizedScanned;

        let report = export_master_framework_report(&case, "run-1").unwrap();
        assert!(report.coverage.selected_run_checks_complete);
        assert!(!report.coverage.selected_run_coverage_ledger_available);
        assert!(
            report
                .coverage
                .selected_run_coverage_has_unknown_or_incomplete_entries
        );
        assert_eq!(report.coverage.selected_run_planned_asset_count, 1);
        assert_eq!(report.coverage.selected_run_matched_coverage_entry_count, 0);
        assert_eq!(
            report
                .coverage
                .selected_run_missing_planned_asset_coverage_count,
            1
        );
        assert_eq!(
            report.coverage.selected_run_unmatched_coverage_entry_count,
            0
        );
        assert_eq!(report.coverage.excluded_other_run_coverage_entry_count, 1);
        assert!(report.coverage.selected_run_coverage_states.is_empty());
        assert_eq!(report.coverage.unknown_source_count, 0);
        assert_eq!(report.coverage.connected_no_asset_count, 0);
        assert_eq!(report.coverage.authorized_incomplete_count, 0);
        assert_eq!(report.coverage.discovered_not_authorized_count, 0);
        assert_eq!(report.coverage.state, "incomplete_or_unknown");
        assert!(report.coverage.limitations.iter().any(|limitation| {
            limitation.contains("frozen planned asset(s) have no unique coverage-ledger entry")
        }));
        assert!(report.coverage.limitations.iter().any(|limitation| {
            limitation
                .contains("excluded from selected-run coverage states, counts, and completeness")
        }));
        let encoded = serde_json::to_string(&report.coverage).unwrap();
        assert!(!encoded.contains("discovered_authorized_scanned"));
        assert!(!encoded.contains("run-2"));
    }

    #[test]
    fn one_retained_selected_run_row_cannot_hide_another_planned_asset_overwritten_later() {
        let mut case = fixture();
        case.scan_runs[0].engine_runs[0].status = EngineRunStatus::Completed;
        case.scan_runs[0].engine_runs[0].progress_percent = 100;
        case.scan_runs[0].engine_runs[0].error_code = None;
        case.scan_runs[0].engine_runs[0]
            .asset_ids
            .push("asset-2".into());
        case.coverage[0].status = CoverageStatus::DiscoveredAuthorizedScanned;

        let mut overwritten_asset = case.coverage[0].clone();
        overwritten_asset.id = "coverage-asset-2".into();
        overwritten_asset.scope_key = "asset:asset-2".into();
        overwritten_asset.asset_id = Some("asset-2".into());
        overwritten_asset.last_run_id = Some("run-2".into());
        overwritten_asset.status = CoverageStatus::SourceNotConnectedUnknown;
        case.coverage.push(overwritten_asset);

        let report = export_master_framework_report(&case, "run-1").unwrap();
        assert!(report.coverage.selected_run_checks_complete);
        assert_eq!(report.coverage.selected_run_planned_asset_count, 2);
        assert_eq!(report.coverage.selected_run_matched_coverage_entry_count, 1);
        assert_eq!(
            report
                .coverage
                .selected_run_missing_planned_asset_coverage_count,
            1
        );
        assert_eq!(report.coverage.excluded_other_run_coverage_entry_count, 1);
        assert_eq!(report.coverage.unknown_source_count, 0);
        assert_eq!(
            report.coverage.selected_run_coverage_states,
            BTreeMap::from([("discovered_authorized_scanned".into(), 1)])
        );
        assert!(
            report
                .coverage
                .selected_run_coverage_has_unknown_or_incomplete_entries
        );
        assert_eq!(report.coverage.state, "incomplete_or_unknown");
        let encoded = serde_json::to_string(&report.coverage).unwrap();
        assert!(!encoded.contains("source_not_connected_unknown"));
        assert!(!encoded.contains("run-2"));
    }

    #[test]
    fn completed_engine_and_asset_ledger_never_claim_exact_dimension_coverage() {
        let mut case = fixture();
        case.scan_runs[0].engine_runs[0].status = EngineRunStatus::Completed;
        case.scan_runs[0].engine_runs[0].progress_percent = 100;
        case.scan_runs[0].engine_runs[0].error_code = None;
        case.coverage[0].status = CoverageStatus::DiscoveredAuthorizedScanned;

        let mut other_run_entry = case.coverage[0].clone();
        other_run_entry.id = "coverage-run-2".into();
        other_run_entry.last_run_id = Some("run-2".into());
        other_run_entry.status = CoverageStatus::SourceNotConnectedUnknown;
        case.coverage.push(other_run_entry);

        let report = export_master_framework_report(&case, "run-1").unwrap();
        assert!(report.coverage.selected_run_coverage_ledger_available);
        assert!(report.coverage.selected_run_checks_complete);
        assert!(
            !report
                .coverage
                .selected_run_coverage_has_unknown_or_incomplete_entries
        );
        assert_eq!(report.coverage.selected_run_planned_asset_count, 1);
        assert_eq!(report.coverage.selected_run_matched_coverage_entry_count, 1);
        assert_eq!(
            report
                .coverage
                .selected_run_missing_planned_asset_coverage_count,
            0
        );
        assert_eq!(report.coverage.excluded_other_run_coverage_entry_count, 1);
        assert_eq!(report.coverage.unknown_source_count, 0);
        assert_eq!(
            report.coverage.selected_run_coverage_states,
            BTreeMap::from([("discovered_authorized_scanned".into(), 1)])
        );
        assert_eq!(report.coverage.state, "incomplete_or_unknown");
        assert!(report.coverage.limitations.iter().any(|limitation| {
            limitation.contains("not exact requested-versus-executed host")
                && limitation.contains("cannot establish complete scan coverage")
        }));
        for framework in &report.frameworks {
            if framework.controls.is_empty()
                && framework.state != "not_applicable_to_declared_context"
            {
                assert!(framework.state.starts_with("unknown_due_to_"));
            }
        }
    }

    #[test]
    fn evidence_ids_must_be_unique_across_all_selected_run_snapshots() {
        let mut case = fixture();
        let mut duplicate = case.finding_observations[0].clone();
        duplicate.id = "observation-2".into();
        duplicate.finding_id = "finding-2".into();
        duplicate.fingerprint = "fp-2".into();
        let snapshot = duplicate.finding_snapshot.as_mut().unwrap();
        snapshot.id = "finding-2".into();
        snapshot.fingerprint = "fp-2".into();
        snapshot.evidence[0].finding_id = "finding-2".into();
        case.finding_observations.push(duplicate);

        let error = export_master_framework_report(&case, "run-1").unwrap_err();
        assert!(error.to_string().contains("report-wide unique"));
        assert!(error.to_string().contains("observation-1"));
        assert!(error.to_string().contains("observation-2"));
    }

    #[test]
    fn connected_source_with_no_discovered_asset_remains_unknown() {
        let mut case = fixture();
        case.findings.clear();
        case.finding_observations.clear();
        case.scan_runs[0].engine_runs[0].status = EngineRunStatus::Completed;
        case.scan_runs[0].engine_runs[0].progress_percent = 100;
        case.scan_runs[0].engine_runs[0].error_code = None;
        case.coverage[0].status = CoverageStatus::SourceConnectedNothingDiscovered;

        let report = export_master_framework_report(&case, "run-1").unwrap();
        assert!(report.coverage.selected_run_checks_complete);
        assert_eq!(report.coverage.connected_no_asset_count, 1);
        assert!(
            report
                .coverage
                .selected_run_coverage_has_unknown_or_incomplete_entries
        );
        assert_eq!(report.coverage.state, "incomplete_or_unknown");
        assert!(report.frameworks.iter().all(|framework| {
            framework.state == "unknown_due_to_incomplete_coverage"
                || framework.state == "not_applicable_to_declared_context"
        }));
    }

    #[test]
    fn missing_historical_snapshot_never_hydrates_from_mutable_current_finding() {
        let mut case = fixture();
        case.finding_observations[0].finding_snapshot = None;
        let before = export_master_framework_report_bytes(&case, "run-1").unwrap();
        case.findings[0].title = "Later mutable title".into();
        case.findings[0].control_references.clear();
        let after = export_master_framework_report_bytes(&case, "run-1").unwrap();

        assert_eq!(before, after);
        let report = export_master_framework_report(&case, "run-1").unwrap();
        assert_eq!(report.coverage.selected_run_snapshot_count, 0);
        assert_eq!(report.coverage.selected_run_missing_snapshot_count, 1);
        assert_eq!(
            report.observation_provenance[0].framework_mapping_state,
            "not_exported_without_run_snapshot"
        );
        assert!(
            report
                .frameworks
                .iter()
                .all(|framework| framework.control_count == 0)
        );
    }

    #[test]
    fn exact_snapshot_evidence_is_validated_against_artifact_and_engine_provenance() {
        let mut case = fixture();
        let hash = "a".repeat(64);
        let time = case.scan_runs[0].created_at;
        case.raw_artifacts.push(RawArtifact {
            id: "artifact-2".into(),
            case_id: case.id.clone(),
            run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            relative_path: "evidence.json".into(),
            media_type: "application/json".into(),
            sha256: hash.clone(),
            byte_length: 2,
            created_at: time,
            contains_sensitive_data: false,
        });
        let mut evidence = Evidence {
            id: "evidence-1".into(),
            finding_id: "finding-1".into(),
            run_id: "run-1".into(),
            engine_run_id: Some("engine-run-1".into()),
            kind: EvidenceKind::SourceCode,
            engine_id: "semgrep".into(),
            scanner_details: None,
            source_rule: None,
            result_pointer_sha256: None,
            observed_at: time,
            summary: "Exact evidence".into(),
            location: None,
            artifact_id: "artifact-2".into(),
            artifact_sha256: hash.clone(),
            pointer: None,
            redacted: false,
        };
        bind_current_evidence_identity(&mut evidence, "fp-1", DYNAMIC_CODE_RULE, "/result/0");
        let expected_evidence_id = evidence.id.clone();
        case.findings[0].evidence = vec![evidence.clone()];
        case.finding_observations[0]
            .finding_snapshot
            .as_mut()
            .unwrap()
            .evidence = vec![evidence];
        case.finding_observations[0].evidence_hashes = vec![hash];

        let report = export_master_framework_report(&case, "run-1").unwrap();
        assert_eq!(
            report.observation_provenance[0].evidence_reference_state,
            "validated_from_run_snapshot"
        );
        for framework in populated(&report) {
            let relationship = &framework.controls[0].relationships[0];
            assert_eq!(relationship.mapping_version_state, "exact_match");
            assert_eq!(relationship.evidence_bindings.len(), 1);
            let binding = &relationship.evidence_bindings[0];
            assert_eq!(binding.evidence_id, expected_evidence_id);
            assert_eq!(binding.artifact_id, "artifact-2");
            assert_eq!(binding.engine_run_id, "engine-run-1");
            assert_eq!(binding.engine_id, "semgrep");
            assert_eq!(
                binding.engine_mapping_provenance_state,
                "verified_current_catalog"
            );
            assert_eq!(
                binding.engine_mapping_version,
                case.scan_runs[0].engine_runs[0].mapping_version
            );
            assert_eq!(
                binding.engine_mapping_provenance,
                case.scan_runs[0].engine_runs[0].mapping_provenance
            );
        }
        case.raw_artifacts.last_mut().unwrap().sha256 = "b".repeat(64);
        assert!(
            export_master_framework_report(&case, "run-1")
                .unwrap_err()
                .to_string()
                .contains("does not match its finding, artifact, run, or engine provenance")
        );
    }

    #[test]
    fn two_evidence_records_for_one_artifact_remain_exactly_distinguishable() {
        let mut case = fixture();
        let snapshot = case.finding_observations[0]
            .finding_snapshot
            .as_mut()
            .unwrap();
        let mut second = snapshot.evidence[0].clone();
        bind_current_evidence_identity(&mut second, "fp-1", DYNAMIC_CODE_RULE, "/result/1");
        let first_id = snapshot.evidence[0].id.clone();
        let second_id = second.id.clone();
        snapshot.evidence.push(second);

        let report = export_master_framework_report(&case, "run-1").unwrap();
        for framework in populated(&report) {
            let bindings = &framework.controls[0].relationships[0].evidence_bindings;
            assert_eq!(bindings.len(), 2);
            assert_eq!(
                bindings
                    .iter()
                    .map(|binding| binding.evidence_id.as_str())
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([first_id.as_str(), second_id.as_str()])
            );
            assert!(bindings.iter().all(|binding| {
                binding.artifact_id == "artifact-1"
                    && binding.engine_run_id == "engine-run-1"
                    && binding.engine_id == "semgrep"
            }));
        }
    }

    #[test]
    fn current_catalog_identity_does_not_bless_invented_or_mutated_relationship_fields() {
        let mut case = fixture();
        let reference = &mut case.finding_observations[0]
            .finding_snapshot
            .as_mut()
            .unwrap()
            .control_references[0];
        reference.control_id = "PR.FAKE-999".into();
        reference.title = "Invented current-catalog control".into();
        let coordinate_error = export_master_framework_report(&case, "run-1").unwrap_err();
        assert!(
            coordinate_error
                .to_string()
                .contains("not one exact current-catalog coordinate")
        );

        let mut case = fixture();
        case.finding_observations[0]
            .finding_snapshot
            .as_mut()
            .unwrap()
            .control_references[0]
            .rationale = "Invented rationale absent from every reviewed mapping entry".into();
        let rationale_error = export_master_framework_report(&case, "run-1").unwrap_err();
        assert!(
            rationale_error
                .to_string()
                .contains("do not match one exact current-catalog entry")
        );

        let mut case = fixture();
        let snapshot = case.finding_observations[0]
            .finding_snapshot
            .as_mut()
            .unwrap();
        bind_current_evidence_identity(&mut snapshot.evidence[0], "fp-1", SHELL_RULE, "/result/0");
        let source_rule_error = export_master_framework_report(&case, "run-1").unwrap_err();
        assert!(source_rule_error.to_string().contains(
            "structured evidence source rule do not match one exact current-catalog entry"
        ));

        let mut case = fixture();
        case.finding_observations[0]
            .finding_snapshot
            .as_mut()
            .unwrap()
            .evidence[0]
            .source_rule = Some(SHELL_RULE.into());
        let identity_error = export_master_framework_report(&case, "run-1").unwrap_err();
        assert!(
            identity_error
                .to_string()
                .contains("source rule does not match its structured evidence identity")
        );

        let mut case = fixture();
        let snapshot = case.finding_observations[0]
            .finding_snapshot
            .as_mut()
            .unwrap();
        snapshot.evidence[0].source_rule = None;
        snapshot
            .tags
            .push(format!("source-rule:{DYNAMIC_CODE_RULE}"));
        let tag_error = export_master_framework_report(&case, "run-1").unwrap_err();
        assert!(
            tag_error
                .to_string()
                .contains("evidence lacks a verified structured source rule")
        );
    }

    #[test]
    fn current_aidefend_coordinate_requires_its_own_catalog_applicability_condition() {
        let mut case = fixture();
        case.scan_runs[0].ai_system_applicable = false;
        case.scan_runs[0].ai_system_applicability = AiSystemApplicabilityAnswer::NotApplicable;
        case.scan_runs[0].ai_generated_artifact = AiGeneratedArtifactAnswer::Yes;
        let error = export_master_framework_report(&case, "run-1").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exact current-catalog AI applicability condition")
        );
    }

    #[test]
    fn aidefend_is_not_inferred_without_declared_ai_context() {
        let mut case = fixture();
        case.scan_runs[0].ai_system_applicable = false;
        case.scan_runs[0].ai_system_applicability = AiSystemApplicabilityAnswer::NotApplicable;
        case.scan_runs[0].ai_generated_artifact = AiGeneratedArtifactAnswer::No;
        let invalid = export_master_framework_report(&case, "run-1").unwrap_err();
        assert!(invalid.to_string().contains("no explicit applicable"));
        case.findings[0]
            .control_references
            .retain(|reference| reference.framework != "AIDEFEND");
        case.finding_observations[0].finding_snapshot = Some(case.findings[0].clone());
        let report = export_master_framework_report(&case, "run-1").unwrap();
        let aidefend = report
            .frameworks
            .iter()
            .find(|framework| framework.framework == "AIDEFEND")
            .unwrap();
        assert_eq!(aidefend.state, "not_applicable_to_declared_context");
    }

    #[test]
    fn legacy_false_and_unanswered_ai_context_remain_unknown_never_not_applicable() {
        for artifact_answer in [
            AiGeneratedArtifactAnswer::Unknown,
            AiGeneratedArtifactAnswer::No,
        ] {
            let mut case = fixture();
            case.scan_runs[0].ai_system_applicable = false;
            case.scan_runs[0].ai_system_applicability = AiSystemApplicabilityAnswer::Unknown;
            case.scan_runs[0].ai_generated_artifact = artifact_answer;
            case.findings[0]
                .control_references
                .retain(|reference| reference.framework != "AIDEFEND");
            case.finding_observations[0].finding_snapshot = Some(case.findings[0].clone());

            let report = export_master_framework_report(&case, "run-1").unwrap();
            let aidefend = report
                .frameworks
                .iter()
                .find(|framework| framework.framework == "AIDEFEND")
                .unwrap();
            assert_eq!(aidefend.state, "unknown_due_to_unanswered_context");
            assert_eq!(report.declared_ai_context.aidefend_applicability, "unknown");
            assert_eq!(
                report.declared_ai_context.ai_system_applicability,
                "unknown"
            );
        }

        let mut serialized = serde_json::to_value(&fixture().scan_runs[0]).unwrap();
        serialized
            .as_object_mut()
            .unwrap()
            .remove("ai_system_applicability");
        serialized["ai_generated_artifact"] = Value::String("no".into());
        let legacy_true: ScanRun = serde_json::from_value(serialized).unwrap();
        assert_eq!(
            legacy_true.frozen_ai_system_applicability(),
            AiSystemApplicabilityAnswer::Applicable
        );
        assert_eq!(
            aidefend_applicability(&legacy_true),
            AidefendApplicability::Applicable
        );
    }

    #[test]
    fn declared_ai_generated_artifact_keeps_aidefend_relationships_applicable() {
        let mut case = fixture();
        case.scan_runs[0].ai_system_applicable = false;
        case.scan_runs[0].ai_system_applicability = AiSystemApplicabilityAnswer::NotApplicable;
        case.scan_runs[0].ai_generated_artifact = AiGeneratedArtifactAnswer::Yes;
        let aidefend_reference = case.finding_observations[0]
            .finding_snapshot
            .as_mut()
            .unwrap()
            .control_references
            .iter_mut()
            .find(|reference| reference.framework == "AIDEFEND")
            .unwrap();
        aidefend_reference.control_id = "AID-H-031.002".into();
        aidefend_reference.title = "Static Admission Gates for AI-Generated Artifacts".into();

        let report = export_master_framework_report(&case, "run-1").unwrap();
        let aidefend = report
            .frameworks
            .iter()
            .find(|framework| framework.framework == "AIDEFEND")
            .unwrap();
        assert_eq!(aidefend.state, "related_coordinates_observed");
        assert!(
            report
                .declared_ai_context
                .explanation
                .contains("AI-generated")
        );
    }

    #[test]
    fn recognized_framework_relationship_must_be_exact_and_mapping_version_must_be_present() {
        let mut case = fixture();
        let mut finding = case.findings[0].clone();
        finding.control_references[0].relationship = "supports".into();
        case.finding_observations[0].finding_snapshot = Some(finding.clone());
        let relationship_error = export_master_framework_report(&case, "run-1").unwrap_err();
        assert!(
            relationship_error
                .to_string()
                .contains("exact relationship 'related'")
        );

        finding.control_references[0].relationship = "related".into();
        finding.control_references[0].mapping_version.clear();
        case.finding_observations[0].finding_snapshot = Some(finding);
        let version_error = export_master_framework_report(&case, "run-1").unwrap_err();
        assert!(version_error.to_string().contains("mapping version"));
    }

    #[test]
    fn unexpected_framework_and_multiple_mapping_versions_are_explicit() {
        let mut case = fixture();
        let mut finding = case.findings[0].clone();
        finding.control_references[0].framework_version = "1.1".into();
        finding.control_references[0].mapping_version = "legacy-map-a".into();
        finding.control_references[0].mapping_provenance = None;
        let mut second = finding.control_references[0].clone();
        second.framework_version = "2.0".into();
        second.control_id = "PR.PS-07".into();
        second.mapping_version = "current-map-b".into();
        finding.control_references.push(second);
        case.finding_observations[0].finding_snapshot = Some(finding);

        let report = export_master_framework_report(&case, "run-1").unwrap();
        let nist = report
            .frameworks
            .iter()
            .find(|framework| framework.framework == "NIST CSF")
            .unwrap();
        assert_eq!(nist.version_state, "unexpected_version_observed");
        assert_eq!(nist.observed_versions, ["1.1", "2.0"]);
        assert_eq!(
            nist.mapping_version_state,
            "relationship_provenance_unavailable"
        );
        assert_eq!(
            nist.observed_mapping_versions,
            ["current-map-b", "legacy-map-a"]
        );
        assert_eq!(
            nist.evidence_engine_mapping_versions,
            [case.scan_runs[0].engine_runs[0]
                .mapping_version
                .clone()
                .unwrap()]
        );
    }

    #[test]
    fn duplicate_coordinate_is_one_control_while_findings_and_rationales_stay_distinct() {
        let mut case = fixture();
        let time = case.scan_runs[0].created_at;
        let mut second_finding = case.findings[0].clone();
        second_finding.id = "finding-2".into();
        second_finding.fingerprint = "fp-2".into();
        second_finding.title = "Second observation".into();
        second_finding.control_references = vec![second_finding.control_references[0].clone()];
        second_finding.control_references[0].rationale = "Static-analysis evidence that Python code invokes an operating-system shell is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.".into();
        second_finding.evidence[0].id = "evidence-2".into();
        second_finding.evidence[0].finding_id = "finding-2".into();
        second_finding.evidence[0].artifact_id = "artifact-2".into();
        second_finding.evidence[0].artifact_sha256 = "b".repeat(64);
        bind_current_evidence_identity(
            &mut second_finding.evidence[0],
            "fp-2",
            SHELL_RULE,
            "/result/1",
        );
        case.raw_artifacts.push(RawArtifact {
            id: "artifact-2".into(),
            case_id: case.id.clone(),
            run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            relative_path: "second.json".into(),
            media_type: "application/json".into(),
            sha256: "b".repeat(64),
            byte_length: 2,
            created_at: time,
            contains_sensitive_data: false,
        });
        case.findings.push(second_finding.clone());
        case.finding_observations.push(FindingObservation {
            id: "observation-2".into(),
            run_id: "run-1".into(),
            finding_id: "finding-2".into(),
            fingerprint: "fp-2".into(),
            asset_ids: vec!["asset-1".into()],
            engine_ids: vec!["semgrep".into()],
            severity: Severity::High,
            confidence: Confidence::High,
            evidence_hashes: vec!["b".repeat(64)],
            observed_at: time,
            finding_snapshot: Some(second_finding),
        });

        let report = export_master_framework_report(&case, "run-1").unwrap();
        let nist = report
            .frameworks
            .iter()
            .find(|framework| framework.framework == "NIST CSF")
            .unwrap();
        assert_eq!(nist.controls.len(), 1);
        assert_eq!(nist.controls[0].relationships.len(), 2);
        assert_eq!(
            nist.controls[0]
                .relationships
                .iter()
                .map(|relationship| relationship.rationale.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "Static-analysis evidence of dynamic code execution is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.",
                "Static-analysis evidence that Python code invokes an operating-system shell is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI."
            ])
        );
        assert_eq!(nist.finding_count, 2);

        case.finding_observations[1]
            .finding_snapshot
            .as_mut()
            .unwrap()
            .control_references[0]
            .title = "Conflicting title".into();
        assert!(
            export_master_framework_report(&case, "run-1")
                .unwrap_err()
                .to_string()
                .contains("title does not match the exact current-catalog control")
        );
    }

    #[test]
    fn relationship_with_evidence_from_multiple_engine_runs_is_unavailable_not_exact() {
        let mut case = fixture();
        let time = case.scan_runs[0].created_at;
        let mut second_run = case.scan_runs[0].engine_runs[0].clone();
        second_run.id = "engine-run-2".into();
        case.scan_runs[0].engine_runs.push(second_run);
        case.raw_artifacts.push(RawArtifact {
            id: "artifact-2".into(),
            case_id: case.id.clone(),
            run_id: "run-1".into(),
            engine_run_id: "engine-run-2".into(),
            relative_path: "second-engine-run.json".into(),
            media_type: "application/json".into(),
            sha256: "b".repeat(64),
            byte_length: 2,
            created_at: time,
            contains_sensitive_data: false,
        });
        let mut second_evidence = case.findings[0].evidence[0].clone();
        second_evidence.id = "evidence-2".into();
        second_evidence.engine_run_id = Some("engine-run-2".into());
        second_evidence.artifact_id = "artifact-2".into();
        second_evidence.artifact_sha256 = "b".repeat(64);
        bind_current_evidence_identity(
            &mut second_evidence,
            "fp-1",
            DYNAMIC_CODE_RULE,
            "/result/1",
        );
        case.findings[0].evidence.push(second_evidence);
        case.finding_observations[0]
            .evidence_hashes
            .push("b".repeat(64));
        case.finding_observations[0].finding_snapshot = Some(case.findings[0].clone());

        let report = export_master_framework_report(&case, "run-1").unwrap();
        assert!(populated(&report).iter().all(|framework| {
            let relationship = &framework.controls[0].relationships[0];
            framework.mapping_version_state == "relationship_provenance_unavailable"
                && relationship.mapping_version_state == "unavailable"
                && relationship
                    .evidence_bindings
                    .iter()
                    .all(|binding| binding.mapping_version_state == "unavailable")
        }));
    }

    #[test]
    fn mapping_provenance_is_verified_current_unverified_historical_or_unavailable() {
        let mut case = fixture();
        for reference in &mut case.findings[0].control_references {
            reference.mapping_provenance = None;
        }
        case.finding_observations[0].finding_snapshot = Some(case.findings[0].clone());
        let legacy = export_master_framework_report(&case, "run-1").unwrap();
        assert!(populated(&legacy).iter().all(|framework| {
            framework.controls[0].relationships[0].mapping_provenance_state == "unavailable_legacy"
                && framework.controls[0].relationships[0]
                    .mapping_provenance
                    .is_none()
        }));

        let current = control_mapping_provenance().unwrap();
        case.scan_runs[0].engine_runs[0].mapping_version = Some(current.mapping_version.clone());
        for reference in &mut case.findings[0].control_references {
            reference.mapping_version = current.mapping_version.clone();
            reference.mapping_provenance = Some(current.clone());
        }
        case.finding_observations[0].finding_snapshot = Some(case.findings[0].clone());
        case.scan_runs[0].engine_runs[0].mapping_provenance = None;
        let legacy_engine = export_master_framework_report(&case, "run-1").unwrap();
        assert!(populated(&legacy_engine).iter().all(|framework| {
            framework.mapping_version_state == "relationship_provenance_unavailable"
                && framework.controls[0].relationships[0].mapping_version_state == "unavailable"
        }));
        case.scan_runs[0].engine_runs[0].mapping_provenance = Some(current.clone());
        let report = export_master_framework_report(&case, "run-1").unwrap();
        assert!(populated(&report).iter().all(|framework| {
            framework.controls[0].relationships[0].mapping_provenance_state
                == "verified_current_catalog"
        }));

        let mut tampered = case.clone();
        tampered.finding_observations[0]
            .finding_snapshot
            .as_mut()
            .unwrap()
            .control_references[0]
            .mapping_provenance
            .as_mut()
            .unwrap()
            .catalog_sha256 = "c".repeat(64);
        assert!(
            export_master_framework_report(&tampered, "run-1")
                .unwrap_err()
                .to_string()
                .contains("does not match the embedded canonical catalog")
        );

        let historical = ControlMappingProvenance {
            mapping_version: "2026-08-27.1".into(),
            reviewed_at: "2026-08-28".into(),
            review_process: "source_coordinate_and_rationale_review_v1".into(),
            catalog_sha256: "d".repeat(64),
        };
        case.scan_runs[0].engine_runs[0].mapping_version = Some(historical.mapping_version.clone());
        case.scan_runs[0].engine_runs[0].mapping_provenance = Some(historical.clone());
        for reference in &mut case.findings[0].control_references {
            reference.mapping_version = historical.mapping_version.clone();
            reference.mapping_provenance = Some(historical.clone());
        }
        case.finding_observations[0].finding_snapshot = Some(case.findings[0].clone());
        let report = export_master_framework_report(&case, "run-1").unwrap();
        assert!(populated(&report).iter().all(|framework| {
            let relationship = &framework.controls[0].relationships[0];
            relationship.mapping_provenance_state == "unverified_historical_catalog"
                && relationship.mapping_version_state == "unavailable"
                && relationship.evidence_bindings.iter().all(|binding| {
                    binding.engine_mapping_provenance_state == "unverified_historical_catalog"
                        && binding.mapping_version_state == "unavailable"
                })
        }));
    }

    #[test]
    fn framework_schema_rejects_duplicate_coordinates_reordering_and_arbitrary_expected_versions() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/master-framework-report.schema.json"
        ))
        .unwrap();
        let report =
            serde_json::to_value(export_master_framework_report(&fixture(), "run-1").unwrap())
                .unwrap();

        let mut duplicate = report.clone();
        duplicate["frameworks"][1] = duplicate["frameworks"][0].clone();
        assert!(validate_schema_value(&schema, &schema, &duplicate, "$").is_err());

        let mut arbitrary_version = report.clone();
        arbitrary_version["frameworks"][0]["expected_version"] = "1.1".into();
        assert!(validate_schema_value(&schema, &schema, &arbitrary_version, "$").is_err());

        let mut missing_evidence_id = report.clone();
        missing_evidence_id["frameworks"][0]["controls"][0]["relationships"][0]
            ["evidence_bindings"][0]
            .as_object_mut()
            .unwrap()
            .remove("evidence_id");
        assert!(validate_schema_value(&schema, &schema, &missing_evidence_id, "$").is_err());

        let mut exact_binding_without_source_rule = report.clone();
        exact_binding_without_source_rule["frameworks"][0]["controls"][0]["relationships"][0]["evidence_bindings"]
            [0]["source_rule"] = Value::Null;
        assert!(
            validate_schema_value(&schema, &schema, &exact_binding_without_source_rule, "$")
                .is_err()
        );

        let mut exact_binding_without_verified_engine_provenance = report.clone();
        exact_binding_without_verified_engine_provenance["frameworks"][0]["controls"][0]["relationships"]
            [0]["evidence_bindings"][0]["engine_mapping_provenance_state"] =
            "unverified_historical_catalog".into();
        assert!(
            validate_schema_value(
                &schema,
                &schema,
                &exact_binding_without_verified_engine_provenance,
                "$",
            )
            .is_err()
        );

        let mut exact_binding_without_engine_provenance = report.clone();
        exact_binding_without_engine_provenance["frameworks"][0]["controls"][0]["relationships"]
            [0]["evidence_bindings"][0]["engine_mapping_provenance"] = Value::Null;
        assert!(
            validate_schema_value(
                &schema,
                &schema,
                &exact_binding_without_engine_provenance,
                "$",
            )
            .is_err()
        );

        let mut exact_relationship_without_verified_provenance = report.clone();
        exact_relationship_without_verified_provenance["frameworks"][0]["controls"][0]["relationships"]
            [0]["mapping_provenance_state"] = "unverified_historical_catalog".into();
        assert!(
            validate_schema_value(
                &schema,
                &schema,
                &exact_relationship_without_verified_provenance,
                "$",
            )
            .is_err()
        );

        let mut misleading_historical_state = report.clone();
        misleading_historical_state["frameworks"][0]["controls"][0]["relationships"][0]["mapping_provenance_state"] =
            "frozen_historical_catalog".into();
        assert!(
            validate_schema_value(&schema, &schema, &misleading_historical_state, "$").is_err()
        );

        let mut retired_coverage_state = report.clone();
        retired_coverage_state["coverage"]["state"] =
            "selected_run_checks_complete_with_no_known_coverage_gap".into();
        assert!(
            validate_schema_value(&schema, &schema, &retired_coverage_state, "$").is_err(),
            "the 1.3 schema must not accept the retired engine/asset-ledger completeness claim"
        );

        let mut reordered = report;
        reordered["frameworks"][0]["controls"][0]["relationships"][0]["finding"]["evidence_hashes"] =
            serde_json::json!(["z".repeat(64)]);
        assert!(validate_schema_value(&schema, &schema, &reordered, "$").is_err());

        let mut reordered =
            serde_json::to_value(export_master_framework_report(&fixture(), "run-1").unwrap())
                .unwrap();
        reordered["frameworks"].as_array_mut().unwrap().swap(0, 1);
        assert!(validate_schema_value(&schema, &schema, &reordered, "$").is_err());
    }

    #[test]
    fn generated_report_validates_against_the_checked_in_json_schema() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/master-framework-report.schema.json"
        ))
        .unwrap();
        let report =
            serde_json::to_value(export_master_framework_report(&fixture(), "run-1").unwrap())
                .unwrap();
        validate_schema_value(&schema, &schema, &report, "$").unwrap();
    }

    #[test]
    fn framework_report_schema_preserves_unknown_confidence() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/master-framework-report.schema.json"
        ))
        .unwrap();
        let mut case = fixture();
        case.findings[0].confidence = Confidence::Unknown;
        case.findings[0].confidence_basis_code =
            Some(ConfidenceBasisCode::MissingDetectionQualityScore);
        case.finding_observations[0].confidence = Confidence::Unknown;
        let snapshot = case.finding_observations[0]
            .finding_snapshot
            .as_mut()
            .expect("frozen finding snapshot");
        snapshot.confidence = Confidence::Unknown;
        snapshot.confidence_basis_code = Some(ConfidenceBasisCode::MissingDetectionQualityScore);
        let report =
            serde_json::to_value(export_master_framework_report(&case, "run-1").unwrap()).unwrap();

        assert_eq!(
            report["frameworks"][0]["controls"][0]["relationships"][0]["finding"]["confidence"],
            "unknown"
        );
        validate_schema_value(&schema, &schema, &report, "$").unwrap();
    }

    fn validate_schema_value(
        root: &Value,
        schema: &Value,
        value: &Value,
        path: &str,
    ) -> Result<(), String> {
        if let Some(all_of) = schema.get("allOf").and_then(Value::as_array) {
            for child_schema in all_of {
                validate_schema_value(root, child_schema, value, path)?;
            }
        }
        if let Some(one_of) = schema.get("oneOf").and_then(Value::as_array) {
            let matches = one_of
                .iter()
                .filter(|candidate| validate_schema_value(root, candidate, value, path).is_ok())
                .count();
            if matches != 1 {
                return Err(format!(
                    "expected exactly one matching schema at {path}, found {matches}"
                ));
            }
        }
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            let name = reference
                .strip_prefix("#/$defs/")
                .ok_or_else(|| format!("unsupported schema reference at {path}: {reference}"))?;
            let resolved = root
                .get("$defs")
                .and_then(|defs| defs.get(name))
                .ok_or_else(|| format!("missing schema definition at {path}: {name}"))?;
            return validate_schema_value(root, resolved, value, path);
        }
        if let Some(expected) = schema.get("const")
            && expected != value
        {
            return Err(format!("const mismatch at {path}"));
        }
        if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
            && !allowed.contains(value)
        {
            return Err(format!("enum mismatch at {path}: {value}"));
        }
        if let Some(kind) = schema.get("type").and_then(Value::as_str) {
            match kind {
                "object" => {
                    let object = value
                        .as_object()
                        .ok_or_else(|| format!("expected object at {path}"))?;
                    let properties = schema
                        .get("properties")
                        .and_then(Value::as_object)
                        .cloned()
                        .unwrap_or_default();
                    for required in schema
                        .get("required")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let required = required
                            .as_str()
                            .ok_or_else(|| format!("non-string required key at {path}"))?;
                        if !object.contains_key(required) {
                            return Err(format!("missing required key at {path}.{required}"));
                        }
                    }
                    for (key, child) in object {
                        if let Some(child_schema) = properties.get(key) {
                            validate_schema_value(
                                root,
                                child_schema,
                                child,
                                &format!("{path}.{key}"),
                            )?;
                        } else {
                            match schema.get("additionalProperties") {
                                Some(Value::Bool(false)) => {
                                    return Err(format!("unexpected key at {path}.{key}"));
                                }
                                Some(additional @ Value::Object(_)) => {
                                    validate_schema_value(
                                        root,
                                        additional,
                                        child,
                                        &format!("{path}.{key}"),
                                    )?;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                "array" => {
                    let values = value
                        .as_array()
                        .ok_or_else(|| format!("expected array at {path}"))?;
                    if let Some(minimum) = schema.get("minItems").and_then(Value::as_u64)
                        && values.len() < minimum as usize
                    {
                        return Err(format!("too few array items at {path}"));
                    }
                    if let Some(maximum) = schema.get("maxItems").and_then(Value::as_u64)
                        && values.len() > maximum as usize
                    {
                        return Err(format!("too many array items at {path}"));
                    }
                    if schema.get("uniqueItems") == Some(&Value::Bool(true)) {
                        let unique = values.iter().map(Value::to_string).collect::<BTreeSet<_>>();
                        if unique.len() != values.len() {
                            return Err(format!("duplicate array item at {path}"));
                        }
                    }
                    let prefix_items = schema
                        .get("prefixItems")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    for (index, child_schema) in prefix_items.iter().enumerate() {
                        let child = values
                            .get(index)
                            .ok_or_else(|| format!("missing prefix item at {path}[{index}]"))?;
                        validate_schema_value(
                            root,
                            child_schema,
                            child,
                            &format!("{path}[{index}]"),
                        )?;
                    }
                    if schema.get("items") == Some(&Value::Bool(false))
                        && values.len() > prefix_items.len()
                    {
                        return Err(format!("unexpected trailing array item at {path}"));
                    }
                    if let Some(item_schema @ Value::Object(_)) = schema.get("items") {
                        for (index, child) in values.iter().enumerate() {
                            validate_schema_value(
                                root,
                                item_schema,
                                child,
                                &format!("{path}[{index}]"),
                            )?;
                        }
                    }
                }
                "string" => {
                    let text = value
                        .as_str()
                        .ok_or_else(|| format!("expected string at {path}"))?;
                    if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64)
                        && text.chars().count() < minimum as usize
                    {
                        return Err(format!("string is too short at {path}"));
                    }
                    if let Some(maximum) = schema.get("maxLength").and_then(Value::as_u64)
                        && text.chars().count() > maximum as usize
                    {
                        return Err(format!("string is too long at {path}"));
                    }
                    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
                        match pattern {
                            "^[0-9a-f]{64}$"
                                if text.len() != 64
                                    || !text.bytes().all(|byte| {
                                        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                                    }) =>
                            {
                                return Err(format!(
                                    "string does not match SHA-256 pattern at {path}"
                                ));
                            }
                            "^[0-9a-f]{64}$" => {}
                            "^[0-9]{4}-[0-9]{2}-[0-9]{2}\\.[1-9][0-9]*$"
                                if mapping_version_date(text).is_err() =>
                            {
                                return Err(format!(
                                    "string is not a valid mapping version at {path}"
                                ));
                            }
                            "^[0-9]{4}-[0-9]{2}-[0-9]{2}\\.[1-9][0-9]*$" => {}
                            "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
                                if text.len() != 10
                                    || NaiveDate::parse_from_str(text, "%Y-%m-%d").is_err() =>
                            {
                                return Err(format!("string is not a valid date at {path}"));
                            }
                            "^[0-9]{4}-[0-9]{2}-[0-9]{2}$" => {}
                            other => {
                                return Err(format!(
                                    "unsupported schema string pattern at {path}: {other}"
                                ));
                            }
                        }
                    }
                    if schema.get("format").and_then(Value::as_str) == Some("date-time") {
                        DateTime::parse_from_rfc3339(text)
                            .map_err(|_| format!("invalid date-time at {path}"))?;
                    }
                }
                "integer" => {
                    let number = value
                        .as_i64()
                        .ok_or_else(|| format!("expected integer at {path}"))?;
                    if let Some(minimum) = schema.get("minimum").and_then(Value::as_i64)
                        && number < minimum
                    {
                        return Err(format!("integer is below minimum at {path}"));
                    }
                }
                "boolean" => {
                    if !value.is_boolean() {
                        return Err(format!("expected boolean at {path}"));
                    }
                }
                "null" => {
                    if !value.is_null() {
                        return Err(format!("expected null at {path}"));
                    }
                }
                other => return Err(format!("unsupported schema type at {path}: {other}")),
            }
        }
        Ok(())
    }
}
