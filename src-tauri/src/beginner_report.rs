//! Beginner-facing, run-specific report projection.
//!
//! This module deliberately derives one report from durable case state. It is
//! not another persisted lifecycle or coverage state machine. When an older
//! run did not freeze a requested or executed dimension, the report says so
//! instead of reconstructing it from mutable case state.

use crate::domain::{
    AssessmentCase, Asset, AssetKind, Confidence, ContextFactor, ControlMappingProvenance,
    DeclaredNetworkServiceMetadata, DeclaredNetworkServiceScanProfile, DeclaredWebServiceInput,
    DeclaredWebServiceScanProfile, DistributionMode, EngineRun, EngineRunStatus, EngineTaskKind,
    Finding, FindingFamily, FindingObservation, GatewayRefusalRecord, Id, InventoryObservation,
    InventoryObservationKind, LocalhostTcpObservation, LocalhostTcpOutcome, ReportAssetDisposition,
    ScanRequestOutcome, ScanRequestOutcomeCode, ScanRun, Severity, SeverityBasisCode,
    UnevaluatedTargetCause,
};
use crate::execution_coverage::{
    CumulativeNaabuCoverage, WorkUnitOutcome, reduce_naabu_attempt_coverage,
};
use crate::naabu_work_plan::{NAABU_ENGINE_ID, NaabuWorkStage};
pub use crate::report_problem_groups::{
    LowerPriorityMembers, ReportProblemGroup, ReportProblemKind,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

pub const BEGINNER_MASTER_REPORT_SCHEMA_VERSION: &str = "1.1.0";

pub const FRAMEWORK_NON_CERTIFICATION_NOTICE: &str = "These references do not establish certification, compliance, control implementation, control effectiveness, endorsement, or a pass/fail result.";

const GREENBONE_ENGINE_ID: &str = "greenbone";
const GREENBONE_REMOTE_SAFE_PROFILE_ID: &str = "greenbone_remote_safe_v1";
const NUCLEI_ENGINE_ID: &str = "nuclei";
const NUCLEI_WEB_SAFE_PROFILE_ID: &str = "nuclei_web_safe_v1";
const NUCLEI_TEMPLATE_REVISION: &str = "nuclei-templates@24858b4bfabfa86f0bcfd36aea24fb535152b012";
const INTERNAL_DEVICE_TEMPLATE_REVISION: &str =
    "greenbone-community-feed@816c24126e0375d32c667b78d20342ce7c58ec58";
const INTERNAL_DEVICE_TLS_VULNERABILITY_OIDS: [&str; 11] = [
    "1.3.6.1.4.1.25623.1.0.111012",
    "1.3.6.1.4.1.25623.1.0.117274",
    "1.3.6.1.4.1.25623.1.0.802087",
    "1.3.6.1.4.1.25623.1.0.108094",
    "1.3.6.1.4.1.25623.1.0.108147",
    "1.3.6.1.4.1.25623.1.0.108022",
    "1.3.6.1.4.1.25623.1.0.103440",
    "1.3.6.1.4.1.25623.1.0.103955",
    "1.3.6.1.4.1.25623.1.0.105880",
    "1.3.6.1.4.1.25623.1.0.150710",
    "1.3.6.1.4.1.25623.1.0.150749",
];
const INTERNAL_ENDPOINT_SSH_VULNERABILITY_OIDS: [&str; 7] = [
    "1.3.6.1.4.1.25623.1.0.801993",
    "1.3.6.1.4.1.25623.1.0.105497",
    "1.3.6.1.4.1.25623.1.0.105610",
    "1.3.6.1.4.1.25623.1.0.105611",
    "1.3.6.1.4.1.25623.1.0.117687",
    "1.3.6.1.4.1.25623.1.0.150712",
    "1.3.6.1.4.1.25623.1.0.150713",
];
const INTERNAL_ENDPOINT_RDP_TLS_VULNERABILITY_OIDS: [&str; 11] = [
    "1.3.6.1.4.1.25623.1.0.902658",
    "1.3.6.1.4.1.25623.1.0.111012",
    "1.3.6.1.4.1.25623.1.0.117274",
    "1.3.6.1.4.1.25623.1.0.802087",
    "1.3.6.1.4.1.25623.1.0.108147",
    "1.3.6.1.4.1.25623.1.0.108022",
    "1.3.6.1.4.1.25623.1.0.103440",
    "1.3.6.1.4.1.25623.1.0.103955",
    "1.3.6.1.4.1.25623.1.0.105880",
    "1.3.6.1.4.1.25623.1.0.150710",
    "1.3.6.1.4.1.25623.1.0.150749",
];
const INTERNAL_ENDPOINT_VNC_VULNERABILITY_OIDS: [&str; 1] = ["1.3.6.1.4.1.25623.1.0.108529"];
const INTERNAL_ENDPOINT_SMTP_CLEARTEXT_LOGIN_OID: &str = "1.3.6.1.4.1.25623.1.0.108530";
const INTERNAL_ENDPOINT_SMTP_TLS_VULNERABILITY_OIDS: [&str; 10] = [
    "1.3.6.1.4.1.25623.1.0.111012",
    "1.3.6.1.4.1.25623.1.0.117274",
    "1.3.6.1.4.1.25623.1.0.802087",
    "1.3.6.1.4.1.25623.1.0.108147",
    "1.3.6.1.4.1.25623.1.0.108022",
    "1.3.6.1.4.1.25623.1.0.103440",
    "1.3.6.1.4.1.25623.1.0.103955",
    "1.3.6.1.4.1.25623.1.0.105880",
    "1.3.6.1.4.1.25623.1.0.150710",
    "1.3.6.1.4.1.25623.1.0.150749",
];
const INTERNAL_ENDPOINT_SMTP_VULNERABILITY_OIDS: [&str; 11] = [
    INTERNAL_ENDPOINT_SMTP_CLEARTEXT_LOGIN_OID,
    "1.3.6.1.4.1.25623.1.0.111012",
    "1.3.6.1.4.1.25623.1.0.117274",
    "1.3.6.1.4.1.25623.1.0.802087",
    "1.3.6.1.4.1.25623.1.0.108147",
    "1.3.6.1.4.1.25623.1.0.108022",
    "1.3.6.1.4.1.25623.1.0.103440",
    "1.3.6.1.4.1.25623.1.0.103955",
    "1.3.6.1.4.1.25623.1.0.105880",
    "1.3.6.1.4.1.25623.1.0.150710",
    "1.3.6.1.4.1.25623.1.0.150749",
];
const INTERNAL_ENDPOINT_TELNET_VULNERABILITY_OIDS: [&str; 1] = ["1.3.6.1.4.1.25623.1.0.108522"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerMasterReport {
    pub schema_version: String,
    pub case_id: Id,
    pub run_id: Id,
    pub project_title: String,
    pub state: BeginnerReportState,
    pub requested: RequestedCoverage,
    pub actual: ActualCoverage,
    pub coverage_gaps: Vec<CoverageGap>,
    pub coverage_counts: CoverageCounts,
    #[serde(default)]
    pub inventory: BeginnerInventory,
    pub findings: Vec<BeginnerFinding>,
    #[serde(default)]
    pub finding_groups: Vec<BeginnerFindingGroup>,
    /// Related selected-run checks, grouped only for report presentation.
    /// Every original observation remains in `findings`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problem_groups: Vec<ReportProblemGroup>,
    pub next_steps: Vec<BeginnerNextStep>,
    pub technical_details: TechnicalDetails,
    pub framework_notice: FrameworkNotice,
    pub data_quality_warnings: Vec<String>,
}

impl BeginnerMasterReport {
    /// One first-layer row per problem. Group members retain their original
    /// fields in `findings`; the representative carries the highest severity.
    pub fn problem_findings(&self) -> Vec<&BeginnerFinding> {
        let by_id = self
            .findings
            .iter()
            .map(|finding| (finding.finding_id.as_str(), finding))
            .collect::<BTreeMap<_, _>>();
        let mut membership = BTreeMap::new();
        for group in &self.problem_groups {
            if group.finding_ids.len() < 2
                || !group.finding_ids.contains(&group.representative_finding_id)
                || !group.finding_ids.iter().all(|id| {
                    by_id.get(id.as_str()).is_some_and(|finding| {
                        finding.target_asset_ids.as_slice() == [group.target_asset_id.clone()]
                    })
                })
                || group
                    .finding_ids
                    .iter()
                    .any(|id| membership.contains_key(id.as_str()))
            {
                continue;
            }
            for id in &group.finding_ids {
                membership.insert(id.as_str(), group);
            }
        }
        let mut emitted = BTreeSet::new();
        self.findings
            .iter()
            .filter_map(
                |finding| match membership.get(finding.finding_id.as_str()) {
                    Some(group) if emitted.insert(group.group_id.as_str()) => {
                        by_id.get(group.representative_finding_id.as_str()).copied()
                    }
                    Some(_) => None,
                    None => Some(finding),
                },
            )
            .collect()
    }

    pub fn problem_group(&self, finding_id: &str) -> Option<&ReportProblemGroup> {
        self.problem_groups
            .iter()
            .find(|group| group.finding_ids.iter().any(|id| id == finding_id))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerInventory {
    pub total: usize,
    pub counts: BeginnerInventoryCounts,
    pub asset_ids: Vec<Id>,
    pub representative_sample: Vec<BeginnerInventoryItem>,
    pub items: Vec<BeginnerInventoryItem>,
    pub by_asset: Vec<BeginnerAssetInventory>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct BeginnerInventoryCounts {
    pub services: usize,
    pub software_components: usize,
    pub cloud_resources: usize,
    pub workflow_components: usize,
    pub workflow_relationships: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerAssetInventory {
    pub asset_id: Id,
    pub total: usize,
    pub counts: BeginnerInventoryCounts,
    pub representative_sample: Vec<BeginnerInventoryItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerInventoryItem {
    pub asset_id: Id,
    #[serde(flatten)]
    pub details: BeginnerInventoryItemKind,
    pub sources: Vec<BeginnerInventorySource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BeginnerInventoryItemKind {
    Service {
        endpoint: String,
        port: Option<u16>,
        transport: Option<String>,
        schemes: Vec<String>,
        http_statuses: Vec<u16>,
        tls_observations: Vec<bool>,
    },
    SoftwareComponent {
        name: String,
        version: Option<String>,
        package_type: Option<String>,
        purl: Option<String>,
    },
    CloudResource {
        resource_type: String,
        native_id: Option<String>,
        display_name: Option<String>,
    },
    WorkflowComponent {
        component_type: String,
        name: String,
        model: Option<String>,
        is_guardrail: Option<bool>,
    },
    WorkflowRelationship {
        source: String,
        target: String,
        condition: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct BeginnerInventorySource {
    pub observation_id: Id,
    pub engine_id: String,
    pub engine_run_id: Id,
    pub artifact_id: Id,
    pub artifact_sha256: String,
    pub pointer: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerFindingGroup {
    pub group_id: Id,
    pub presentation_scope: FindingGroupPresentationScope,
    pub title: String,
    pub rationale: String,
    pub actor: String,
    pub created_at: DateTime<Utc>,
    pub members: Vec<BeginnerFindingGroupMember>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingGroupPresentationScope {
    CurrentCasePresentation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerFindingGroupMember {
    pub finding_id: Id,
    pub observed_in_selected_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerReportState {
    pub summary: BeginnerReportSummary,
    pub lifecycle: ReportLifecycle,
    pub last_durable_update: DateTime<Utc>,
    pub explanation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BeginnerReportSummary {
    Complete,
    Partial,
    NoChecksCompleted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportLifecycle {
    Final,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestedCoverage {
    pub targets: Vec<RequestedTarget>,
    pub stage: RecordedStage,
    pub limits: Vec<RequestedLimit>,
    pub requested_check_ids: Vec<String>,
    pub request_outcome_code: Option<ScanRequestOutcomeCode>,
    pub automatic_reductions: Vec<CoverageReduction>,
    pub reductions_availability: DataAvailability,
    pub unavailable_dimensions: Vec<UnavailableDimension>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageReduction {
    pub dimension: String,
    pub requested: String,
    pub executed: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestedTarget {
    pub asset_id: Id,
    pub label: Option<String>,
    pub asset_kind: Option<AssetKind>,
    pub label_availability: DataAvailability,
    pub asset_kind_availability: DataAvailability,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordedStage {
    pub value: Option<ReportScanStage>,
    pub availability: DataAvailability,
    pub explanation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportScanStage {
    ConnectionDiagnostic,
    QuickDiscovery,
    Inventory,
    Deep,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataAvailability {
    Recorded,
    CurrentCaseFallback,
    Unavailable,
    /// This run has no such dimension at all, for example no network
    /// discovery stage. Target labels and kinds never use this: a target
    /// either has a recorded label and kind or does not.
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestedLimit {
    pub name: String,
    pub value: String,
    pub source: RequestedLimitSource,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestedLimitSource {
    FrozenTaskContract,
    FrozenScopeGrant,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnavailableDimension {
    pub dimension: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActualCoverage {
    pub observed_from: Option<DateTime<Utc>>,
    pub observed_until: Option<DateTime<Utc>>,
    pub checks: Vec<ActualCheck>,
    /// Exact, run-frozen network rectangles and their validated outcome. This
    /// keeps a beginner report honest about which addresses and ports were or
    /// were not tested instead of reducing scope truth to only "N of total".
    #[serde(default)]
    pub network_scopes: Vec<NetworkScopeCoverage>,
    pub unavailable_dimensions: Vec<UnavailableDimension>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkScopeCoverage {
    pub task_id: Id,
    pub check_id: String,
    pub work_unit_id: String,
    pub target_asset_id: Id,
    pub target: String,
    pub address_ranges: Vec<String>,
    pub port_ranges: Vec<String>,
    pub transport: String,
    pub stage: ReportScanStage,
    pub outcome: WorkUnitOutcome,
    pub observed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActualCheck {
    pub task_id: Id,
    pub check_id: String,
    /// Product report semantics for this completed work. Optional only so a
    /// report saved before this field existed can still be opened and
    /// classified conservatively from its stable check identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_kind: Option<CheckResultKind>,
    pub target_asset_ids: Vec<Id>,
    pub status: CoverageDimensionStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub tested_dimensions: Vec<TestedDimension>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckResultKind {
    SecurityCheck,
    Inventory,
    Connectivity,
}

impl ActualCheck {
    pub fn effective_result_kind(&self) -> CheckResultKind {
        self.result_kind
            .unwrap_or_else(|| legacy_check_result_kind(&self.check_id))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestedDimension {
    pub dimension: String,
    pub value: String,
    pub observation: String,
    pub observed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageDimensionStatus {
    TestedComplete,
    TestedPartial,
    Failed,
    TimedOut,
    Cancelled,
    NotTested,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageGap {
    pub kind: CoverageGapKind,
    /// Older saved reports called every row a coverage gap and did not retain
    /// enough information to separate record metadata from missing coverage.
    /// Defaulting legacy absence to `CoverageLoss` preserves that conservative
    /// historical claim instead of silently reinterpreting an old record.
    #[serde(default)]
    pub class: CoverageGapClass,
    pub task_id: Option<Id>,
    pub target_asset_ids: Vec<Id>,
    pub dimension: String,
    pub reason: String,
    pub next_action_code: NextActionCode,
    pub next_action: String,
    /// Set only on `Unattributed`. The prose above is English composed here;
    /// this is what a surface reading in another language rebuilds it from,
    /// and it is the identifier the reader has to copy onto the asset.
    #[serde(default)]
    pub unattributed: Option<crate::domain::UnattributedResults>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageGapClass {
    #[default]
    CoverageLoss,
    RecordNote,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageGapKind {
    NotTested,
    Failed,
    TimedOut,
    Cancelled,
    Excluded,
    Truncated,
    Unavailable,
    /// Results were produced but could not be tied to an authorized asset.
    Unattributed,
    /// The check ran, but upstream requires a person to supply the verdict.
    /// This is visible coverage data, not incomplete execution or a finding.
    ManualReview,
}

impl CoverageGapKind {
    /// Classify a newly produced coverage item conservatively. Record-only
    /// producers override this at their construction site. Keeping this match
    /// exhaustive makes every new kind require an explicit classification.
    const fn default_class(self) -> CoverageGapClass {
        match self {
            Self::NotTested
            | Self::Failed
            | Self::TimedOut
            | Self::Cancelled
            | Self::Excluded
            | Self::Truncated
            | Self::Unavailable
            | Self::Unattributed
            | Self::ManualReview => CoverageGapClass::CoverageLoss,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageCounts {
    pub tested_complete: usize,
    pub tested_partial: usize,
    pub failed: usize,
    pub timed_out: usize,
    pub cancelled: usize,
    pub not_tested: usize,
    pub excluded: usize,
    pub truncated: usize,
    pub unavailable: usize,
    /// Results produced but tied to no authorized asset.
    pub unattributed: usize,
    /// Controls evaluated by upstream whose verdict still requires a person.
    /// These remain part of completed coverage and are not findings.
    #[serde(default)]
    pub manual_review: usize,
}

/// Stable UI/export semantic. English prose beside this value is display
/// copy, never the only meaning a localized client has to parse.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum NextActionCode {
    ReviewFinding,
    ConfirmFindingAfterIncompleteCheck,
    RetryCheck,
    StartNewScan,
    ReviewScopeAndRetry,
    ChooseCompatibleCheck,
    StartExpectedServiceAndRetry,
    ReviewCoverage,
    ReviewManualControl,
    PreserveVisibleLimitation,
    NoActionUnlessScopeChanges,
    AddAssetIdentifier,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerFinding {
    pub finding_id: Id,
    pub fingerprint: String,
    pub snapshot_source: FindingSnapshotSource,
    pub title: String,
    pub plain_language_risk: String,
    pub possible_impact: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub priority: Option<u8>,
    pub priority_reasons: Vec<String>,
    pub target_asset_ids: Vec<Id>,
    pub next_step: String,
    pub recommended_expert_type: String,
    pub evidence_references: Vec<FindingEvidenceReference>,
    /// Selected-run official documentation links. `None` means an older
    /// report did not freeze this field; `Some([])` means the frozen finding
    /// really recorded no links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub official_references: Option<Vec<String>>,
    pub framework_references: Vec<FrameworkReference>,
    /// The codes `plain_language_risk`, `possible_impact` and `next_step` were
    /// composed from, carried so a report rendered in another language can
    /// write those sentences instead of printing the English ones under
    /// translated headings. Absent for a legacy run, whose stored prose is all
    /// there is.
    #[serde(default)]
    pub family: Option<FindingFamily>,
    #[serde(default)]
    pub severity_basis_code: Option<SeverityBasisCode>,
    #[serde(default)]
    pub confidence_basis_code: Option<crate::domain::ConfidenceBasisCode>,
    /// Small, product-owned inventory facts such as the observed port,
    /// transport, or HTTP status. These make reachability observations useful
    /// without turning them into vulnerability claims.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observation_details: Vec<String>,
    /// The case-specific reasons this finding's priority was raised. Carried
    /// for the same reason as the two codes above: the surfaces that compose
    /// their own impact sentence replace the prose these were appended to.
    #[serde(default)]
    pub context_factors: Vec<ContextFactor>,
    /// What to preserve before changing anything, and how to confirm the change
    /// worked. The app has always shown both in the finding drawer; the report
    /// handed to an expert omitted them, so the two surfaces disagreed about
    /// what this finding asks a person to do.
    #[serde(default)]
    pub rollback_considerations: Option<String>,
    #[serde(default)]
    pub verification_guidance: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingSnapshotSource {
    FrozenSelectedRun,
    CurrentCanonicalLegacyFallback,
    ObservationOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingEvidenceReference {
    pub evidence_id: Id,
    pub engine_id: String,
    /// True only when the fields below came from the selected run's immutable
    /// finding snapshot. It distinguishes a genuinely absent value from a
    /// field an older report schema never saved.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub details_frozen: bool,
    /// Exact normalized upstream rule or detector identifier. Older evidence
    /// may not have retained it; never infer one from the title or prose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_rule: Option<String>,
    /// Structured scanner-authored detail retained as untrusted evidence. It
    /// never replaces the product-owned finding recommendation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanner_details: Option<crate::domain::ScannerFindingDetails>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<crate::domain::EvidenceKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_run_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted: Option<bool>,
    pub artifact_sha256: String,
    pub observed_at: DateTime<Utc>,
    /// Scanner-reported location after adapter redaction. Older reports may
    /// omit it, in which case the reader is told it was not retained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Where inside the retained artifact this record sits. The artifact
    /// digest proves the file was not altered; this is what lets a reader
    /// find the one record the finding was raised from. Older evidence may
    /// not have kept one, and none is inferred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrameworkReference {
    pub framework: String,
    pub framework_version: String,
    pub control_id: String,
    pub title: String,
    pub relationship: String,
    pub rationale: String,
    pub mapping_version: String,
    pub mapping_provenance: Option<ControlMappingProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrameworkNotice {
    pub non_certification: String,
    pub aidefend_mapping_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeginnerNextStep {
    pub priority: u16,
    pub code: NextActionCode,
    pub action: String,
    pub reason: String,
    pub finding_id: Option<Id>,
    pub task_id: Option<Id>,
    pub recommended_expert_type: Option<String>,
    /// Set on the steps whose `action` is a finding's own recommendation, so a
    /// report rendered in another language can compose that sentence instead of
    /// printing the English one. Absent on gap-derived steps, whose action is
    /// composed from `code` rather than from a finding.
    #[serde(default)]
    pub family: Option<FindingFamily>,
    /// Set on a step derived from an unattributed-results gap, so the reader's
    /// own sentence names the identifier they have to add.
    #[serde(default)]
    pub unattributed: Option<crate::domain::UnattributedResults>,
    /// The other findings that name this same step as their fix, beyond the one
    /// in `finding_id`. One instruction repeated once per finding is a second
    /// copy of the findings list, not a list of things to do: nine findings on
    /// one AWS-managed policy printed the same 168-character sentence nine
    /// times. The findings stay separate everywhere else in the report; only
    /// the instruction is stated once, and every id it covers stays here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_resolves: Vec<Id>,
    /// True when every finding in `finding_id` and `also_resolves` is fixed by
    /// the one specific change `action` names -- today, a typed AWS IAM policy
    /// action. A family-level instruction ("Correct the workload or cluster
    /// setting named by this check") is the same kind of change in different
    /// places, so a step that merged several of those must not call them one fix.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shared_fix: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TechnicalDetails {
    pub collapsed_by_default: bool,
    pub tasks: Vec<TechnicalTaskDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TechnicalTaskDetails {
    pub task_id: Id,
    pub target_asset_ids: Vec<Id>,
    pub status: EngineRunStatus,
    pub phase: String,
    pub progress_percent: u8,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub cleanup_removed: Option<bool>,
    pub cleanup_detail: UnavailableTechnicalValue,
    pub error_code: Option<String>,
    pub redacted_scanner_message: UnavailableTechnicalValue,
    pub redacted_diagnostic_log: UnavailableTechnicalValue,
    pub evidence_sha256: Vec<String>,
    pub execution: TechnicalExecution,
}

// One serialized record per check: boxing the catalog-engine variant would add
// an allocation and reshape every match on it for no measurable saving.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TechnicalExecution {
    CatalogEngine {
        engine_id: String,
        engine_version: Option<String>,
        /// Release version the scanner binary reports. Absent on reports saved
        /// before it was recorded.
        #[serde(default)]
        reported_version: Option<String>,
        image_digest: Option<String>,
        command_sha256: Option<String>,
        runtime_provider: Option<String>,
        runtime_version: Option<String>,
        runtime_security_options: Option<String>,
        distribution_mode: Option<DistributionMode>,
        image_repository: Option<String>,
        adapter_version: String,
        rule_version: Option<String>,
        /// Absent on reports saved before the scanner's last-updated date was recorded.
        #[serde(default)]
        knowledge_date: Option<String>,
    },
    BuiltInLocalhostTcp {
        endpoint: String,
        timeout_ms: u64,
        payload_bytes: u64,
        observation: Option<LocalhostTcpObservation>,
        contract: String,
    },
    InvalidBuiltInTask {
        explanation: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnavailableTechnicalValue {
    pub availability: DataAvailability,
    pub value: Option<String>,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginnerReportError {
    RunNotFound { run_id: Id },
    RunInProgress { run_id: Id },
}

impl fmt::Display for BeginnerReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunNotFound { run_id } => {
                write!(formatter, "scan run {run_id} was not found in this project")
            }
            Self::RunInProgress { run_id } => {
                write!(formatter, "scan run {run_id} is in progress")
            }
        }
    }
}

impl std::error::Error for BeginnerReportError {}

/// Build the single beginner report for a selected durable scan run.
///
/// The builder performs no I/O, loads no mapping catalog, and never mutates the
/// case. Consequently a missing or damaged mapping source cannot suppress a
/// finding or prevent report construction.
pub fn build_beginner_master_report(
    case: &AssessmentCase,
    run_id: &str,
) -> Result<BeginnerMasterReport, BeginnerReportError> {
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .ok_or_else(|| BeginnerReportError::RunNotFound {
            run_id: run_id.to_owned(),
        })?;
    if !run_is_authoritatively_final(run) {
        return Err(BeginnerReportError::RunInProgress {
            run_id: run_id.to_owned(),
        });
    }

    let contradictory_request_outcome =
        run.request_outcome.is_some() && !run.is_terminal_no_checks();
    let mut data_quality_warnings = Vec::new();
    if contradictory_request_outcome {
        data_quality_warnings.push("This run has inconsistent request and check data.".into());
    }
    if run.case_id != case.id {
        data_quality_warnings.push(
            "The selected run has an inconsistent project identity. Report data: selected in-project record."
                .into(),
        );
    }
    let requested = project_requested_coverage(case, run, !contradictory_request_outcome);
    let actual_projection = project_actual_coverage(case, run);
    let actual = actual_projection.actual;
    let mut coverage_gaps = actual_projection.gaps;
    data_quality_warnings.extend(actual_projection.data_quality_warnings);
    append_request_outcome_gaps(run, !contradictory_request_outcome, &mut coverage_gaps);
    append_engine_admission_gaps(run, &mut coverage_gaps);
    append_unattributed_gaps(run, &mut coverage_gaps);
    append_gateway_refusal_gaps(run, &mut coverage_gaps);
    append_manual_review_gaps(run, &mut coverage_gaps);
    append_case_exclusions(case, run, &mut coverage_gaps);
    append_internal_device_profile_gaps(case, run, &mut coverage_gaps);
    append_internal_endpoint_profile_gaps(case, run, &mut coverage_gaps);
    append_cloud_scope_gaps(&requested.targets, &actual, &mut coverage_gaps);
    append_report_asset_snapshot_gaps(run, &mut coverage_gaps);

    for unavailable in requested
        .unavailable_dimensions
        .iter()
        .chain(actual.unavailable_dimensions.iter())
    {
        coverage_gaps.push(CoverageGap {
            unattributed: None,
            kind: CoverageGapKind::Unavailable,
            class: CoverageGapClass::RecordNote,
            task_id: None,
            // These rows describe missing run/report metadata, not a failed
            // security outcome for every asset. Keep them visible globally;
            // asset-scoped execution gaps are projected with their task or
            // asset IDs by the producers above.
            target_asset_ids: Vec::new(),
            dimension: unavailable.dimension.clone(),
            reason: unavailable.explanation.clone(),
            next_action_code: NextActionCode::PreserveVisibleLimitation,
            next_action: "Rerun the scan to create a fully frozen result.".into(),
        });
    }
    if contradictory_request_outcome {
        coverage_gaps.push(CoverageGap {
            unattributed: None,
            kind: CoverageGapKind::Unavailable,
            class: CoverageGapClass::RecordNote,
            task_id: None,
            target_asset_ids: requested
                .targets
                .iter()
                .map(|target| target.asset_id.clone())
                .collect(),
            dimension: "saved run summary".into(),
            reason: "The saved summary did not match this run's checks, so the report follows the checks."
                .into(),
            next_action_code: NextActionCode::RetryCheck,
            next_action: "Retry this scan to create a consistent coverage record."
                .into(),
        });
    }

    let selected_observations = selected_run_observations(case, run);
    let package_by_finding = package_tags_from_observations(&selected_observations);
    let (mut findings, finding_warnings) = project_findings(case, run, &selected_observations);
    apply_coverage_constrained_finding_actions(&mut findings, &actual);
    let finding_groups = project_finding_groups(case, &findings);
    let problem_groups =
        crate::report_problem_groups::build_problem_groups(&findings, run, &package_by_finding);
    data_quality_warnings.extend(finding_warnings);
    debug_assert!(data_quality_warnings.iter().all(|warning| {
        crate::finding_narrative::data_quality_warning_zh_hant(warning).is_some()
    }));
    if findings
        .iter()
        .any(|finding| finding.snapshot_source != FindingSnapshotSource::FrozenSelectedRun)
    {
        coverage_gaps.push(CoverageGap {
            unattributed: None,
            kind: CoverageGapKind::Unavailable,
            class: CoverageGapClass::RecordNote,
            task_id: None,
            target_asset_ids: Vec::new(),
            dimension: "recorded finding wording".into(),
            reason: "Some findings are shown without the wording this scan recorded.".into(),
            next_action_code: NextActionCode::PreserveVisibleLimitation,
            next_action: "Rerun the scan to create a fully frozen result.".into(),
        });
    }

    // Within a kind, order by the name the reader sees. The task id is a
    // per-run identifier that appears nowhere in the report, so ordering on it
    // put two cancelled checks in a different order on every run for no reason
    // a reader could follow. The dimension opens with the check id, so one
    // task's rows still land together. Each check runs on one asset, so one
    // check on three assets is three rows under one name; they follow the
    // order the report lists its targets in.
    let target_position = |gap: &CoverageGap| {
        gap.target_asset_ids.first().and_then(|asset_id| {
            requested
                .targets
                .iter()
                .position(|target| &target.asset_id == asset_id)
        })
    };
    coverage_gaps.sort_by(|left, right| {
        gap_rank(left.kind)
            .cmp(&gap_rank(right.kind))
            .then_with(|| left.dimension.cmp(&right.dimension))
            .then_with(|| target_position(left).cmp(&target_position(right)))
            .then_with(|| left.task_id.cmp(&right.task_id))
    });
    coverage_gaps.dedup();
    debug_assert_coverage_prose_is_translatable(&coverage_gaps);

    let lifecycle = ReportLifecycle::Final;
    let has_useful_tested_outcome =
        !findings.is_empty() || !actual_projection.useful_task_ids.is_empty();
    let summary = if (run.is_terminal_no_checks() && !contradictory_request_outcome)
        || !has_useful_tested_outcome
    {
        BeginnerReportSummary::NoChecksCompleted
    } else if !run.engine_runs.is_empty()
        && run
            .engine_runs
            .iter()
            .all(|task| actual_projection.exact_complete_task_ids.contains(&task.id))
        && coverage_gaps.iter().all(|gap| {
            gap.class == CoverageGapClass::RecordNote || gap.kind == CoverageGapKind::ManualReview
        })
    {
        BeginnerReportSummary::Complete
    } else {
        BeginnerReportSummary::Partial
    };
    let state = BeginnerReportState {
        summary,
        lifecycle,
        last_durable_update: selected_run_last_durable_update(case, run),
        explanation: if run_is_non_security_only(run) {
            non_security_only_explanation(run)
        } else {
            state_explanation(summary).into()
        },
    };
    let next_steps = project_next_steps(&findings, &coverage_gaps, &actual, &problem_groups);
    let technical_details = project_technical_details(case, run);
    let coverage_counts = coverage_counts(&actual, &coverage_gaps);
    let inventory = project_inventory(case, run);

    Ok(BeginnerMasterReport {
        schema_version: BEGINNER_MASTER_REPORT_SCHEMA_VERSION.into(),
        case_id: case.id.clone(),
        run_id: run.id.clone(),
        project_title: case.title.clone(),
        state,
        requested,
        actual,
        coverage_gaps,
        coverage_counts,
        inventory,
        findings,
        finding_groups,
        problem_groups,
        next_steps,
        technical_details,
        framework_notice: FrameworkNotice {
            non_certification: FRAMEWORK_NON_CERTIFICATION_NOTICE.into(),
            aidefend_mapping_status: "AIDEFEND references are an independent, unofficial mapping unless the framework owner states otherwise."
                .into(),
        },
        data_quality_warnings,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum InventoryAggregateKey {
    Service(Id, String, Option<u16>, Option<String>),
    SoftwarePurl(Id, String),
    SoftwareCoordinates(Id, String, Option<String>, Option<String>),
    CloudNativeId(Id, String, String),
    CloudCoordinates(Id, String, Option<String>),
    WorkflowComponent(Id, String, String, Option<String>, Option<bool>),
    WorkflowRelationship(Id, String, String, Option<String>),
}

fn project_inventory(case: &AssessmentCase, run: &ScanRun) -> BeginnerInventory {
    let mut observations = case
        .inventory_observations
        .iter()
        .filter(|observation| observation.run_id == run.id)
        .collect::<Vec<_>>();
    observations.sort_by(|left, right| left.id.cmp(&right.id));

    let mut grouped = BTreeMap::<InventoryAggregateKey, BeginnerInventoryItem>::new();
    for observation in observations {
        let (key, details) = inventory_item(observation);
        let source = BeginnerInventorySource {
            observation_id: observation.id.clone(),
            engine_id: observation.engine_id.clone(),
            engine_run_id: observation.engine_run_id.clone(),
            artifact_id: observation.artifact_id.clone(),
            artifact_sha256: observation.artifact_sha256.clone(),
            pointer: observation.pointer.clone(),
            observed_at: observation.observed_at,
        };
        match grouped.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(BeginnerInventoryItem {
                    asset_id: observation.asset_id.clone(),
                    details,
                    sources: vec![source],
                });
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                merge_inventory_details(&mut entry.get_mut().details, &details);
                entry.get_mut().sources.push(source);
            }
        }
    }

    let mut items = grouped.into_values().collect::<Vec<_>>();
    for item in &mut items {
        item.sources.sort();
        item.sources.dedup();
    }
    let counts = beginner_inventory_counts(&items);
    let asset_ids = items
        .iter()
        .map(|item| item.asset_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let representative_sample = items.iter().take(3).cloned().collect();
    let by_asset = asset_ids
        .iter()
        .map(|asset_id| {
            let asset_items = items
                .iter()
                .filter(|item| item.asset_id == *asset_id)
                .cloned()
                .collect::<Vec<_>>();
            BeginnerAssetInventory {
                asset_id: asset_id.clone(),
                total: asset_items.len(),
                counts: beginner_inventory_counts(&asset_items),
                representative_sample: asset_items.into_iter().take(3).collect(),
            }
        })
        .collect();
    BeginnerInventory {
        total: items.len(),
        counts,
        asset_ids,
        representative_sample,
        items,
        by_asset,
    }
}

fn inventory_item(
    observation: &InventoryObservation,
) -> (InventoryAggregateKey, BeginnerInventoryItemKind) {
    match &observation.kind {
        InventoryObservationKind::Service {
            endpoint,
            port,
            transport,
            scheme,
            http_status,
            tls,
        } => (
            InventoryAggregateKey::Service(
                observation.asset_id.clone(),
                endpoint.clone(),
                *port,
                transport.clone(),
            ),
            BeginnerInventoryItemKind::Service {
                endpoint: endpoint.clone(),
                port: *port,
                transport: transport.clone(),
                schemes: scheme.iter().cloned().collect(),
                http_statuses: http_status.iter().copied().collect(),
                tls_observations: tls.iter().copied().collect(),
            },
        ),
        InventoryObservationKind::SoftwareComponent {
            name,
            version,
            package_type,
            purl,
        } => {
            let key = purl.as_ref().map_or_else(
                || {
                    InventoryAggregateKey::SoftwareCoordinates(
                        observation.asset_id.clone(),
                        name.clone(),
                        version.clone(),
                        package_type.clone(),
                    )
                },
                |purl| {
                    InventoryAggregateKey::SoftwarePurl(observation.asset_id.clone(), purl.clone())
                },
            );
            (
                key,
                BeginnerInventoryItemKind::SoftwareComponent {
                    name: name.clone(),
                    version: version.clone(),
                    package_type: package_type.clone(),
                    purl: purl.clone(),
                },
            )
        }
        InventoryObservationKind::CloudResource {
            resource_type,
            native_id,
            display_name,
        } => {
            let key = native_id.as_ref().map_or_else(
                || {
                    InventoryAggregateKey::CloudCoordinates(
                        observation.asset_id.clone(),
                        resource_type.clone(),
                        display_name.clone(),
                    )
                },
                |native_id| {
                    InventoryAggregateKey::CloudNativeId(
                        observation.asset_id.clone(),
                        resource_type.clone(),
                        native_id.clone(),
                    )
                },
            );
            (
                key,
                BeginnerInventoryItemKind::CloudResource {
                    resource_type: resource_type.clone(),
                    native_id: native_id.clone(),
                    display_name: display_name.clone(),
                },
            )
        }
        InventoryObservationKind::WorkflowComponent {
            component_type,
            name,
            model,
            is_guardrail,
        } => (
            InventoryAggregateKey::WorkflowComponent(
                observation.asset_id.clone(),
                component_type.clone(),
                name.clone(),
                model.clone(),
                *is_guardrail,
            ),
            BeginnerInventoryItemKind::WorkflowComponent {
                component_type: component_type.clone(),
                name: name.clone(),
                model: model.clone(),
                is_guardrail: *is_guardrail,
            },
        ),
        InventoryObservationKind::WorkflowRelationship {
            source,
            target,
            condition,
        } => (
            InventoryAggregateKey::WorkflowRelationship(
                observation.asset_id.clone(),
                source.clone(),
                target.clone(),
                condition.clone(),
            ),
            BeginnerInventoryItemKind::WorkflowRelationship {
                source: source.clone(),
                target: target.clone(),
                condition: condition.clone(),
            },
        ),
    }
}

fn merge_inventory_details(
    retained: &mut BeginnerInventoryItemKind,
    additional: &BeginnerInventoryItemKind,
) {
    if let (
        BeginnerInventoryItemKind::Service {
            schemes,
            http_statuses,
            tls_observations,
            ..
        },
        BeginnerInventoryItemKind::Service {
            schemes: added_schemes,
            http_statuses: added_statuses,
            tls_observations: added_tls,
            ..
        },
    ) = (retained, additional)
    {
        schemes.extend(added_schemes.iter().cloned());
        schemes.sort();
        schemes.dedup();
        http_statuses.extend(added_statuses);
        http_statuses.sort_unstable();
        http_statuses.dedup();
        tls_observations.extend(added_tls);
        tls_observations.sort_unstable();
        tls_observations.dedup();
    }
}

fn beginner_inventory_counts(items: &[BeginnerInventoryItem]) -> BeginnerInventoryCounts {
    let mut counts = BeginnerInventoryCounts::default();
    for item in items {
        match &item.details {
            BeginnerInventoryItemKind::Service { .. } => counts.services += 1,
            BeginnerInventoryItemKind::SoftwareComponent { .. } => {
                counts.software_components += 1;
            }
            BeginnerInventoryItemKind::CloudResource { .. } => counts.cloud_resources += 1,
            BeginnerInventoryItemKind::WorkflowComponent { .. } => {
                counts.workflow_components += 1;
            }
            BeginnerInventoryItemKind::WorkflowRelationship { .. } => {
                counts.workflow_relationships += 1;
            }
        }
    }
    counts
}

fn project_requested_coverage(
    case: &AssessmentCase,
    run: &ScanRun,
    use_request_outcome: bool,
) -> RequestedCoverage {
    let mut target_ids = BTreeSet::new();
    let mut requested_check_ids = BTreeSet::new();
    let mut request_outcome_code = None;

    // New runs freeze every requested asset, and IT-environment runs also
    // freeze explicitly added inventory-only assets. This is the
    // authoritative per-run list for the report; mutable case state must not
    // make an earlier target vanish.
    target_ids.extend(
        run.report_asset_snapshots
            .iter()
            .map(|snapshot| snapshot.asset.id.clone()),
    );

    if use_request_outcome && run.is_terminal_no_checks() {
        if let Some(ScanRequestOutcome::NoChecksCompleted {
            code,
            requested_asset_ids,
            requested_engine_ids,
            ..
        }) = run.request_outcome.as_ref()
        {
            request_outcome_code = Some(*code);
            target_ids.extend(requested_asset_ids.iter().cloned());
            requested_check_ids.extend(requested_engine_ids.iter().cloned());
        }
    } else {
        target_ids.extend(
            run.scope_grant_snapshots
                .iter()
                .map(|grant| grant.asset_id.clone()),
        );
        for task in &run.engine_runs {
            target_ids.extend(task.asset_ids.iter().cloned());
            requested_check_ids.insert(check_id(task));
        }
    }

    let targets = target_ids
        .into_iter()
        .map(|asset_id| project_requested_target(case, run, asset_id))
        .collect::<Vec<_>>();

    let exact_localhost_only = !run.engine_runs.is_empty()
        && run.engine_runs.iter().all(|task| {
            matches!(task.task_kind, EngineTaskKind::BuiltInLocalhostTcp { .. })
                && task.task_kind.is_exact_built_in_localhost_tcp_contract()
        });
    let naabu_tasks = run
        .engine_runs
        .iter()
        .filter(|task| {
            task.engine_id == NAABU_ENGINE_ID
                && matches!(task.task_kind, EngineTaskKind::CatalogEngine)
        })
        .collect::<Vec<_>>();
    let valid_naabu_plans = naabu_tasks
        .iter()
        .filter_map(|task| task.naabu_work_plan.as_ref())
        .filter(|plan| plan.validate().is_ok())
        .collect::<Vec<_>>();
    let all_naabu_plans_valid =
        !naabu_tasks.is_empty() && valid_naabu_plans.len() == naabu_tasks.len();
    // Only a Naabu network-discovery plan or the native localhost diagnostic
    // has a scan-stage or automatic-reductions concept at all. A terminal
    // no-checks run whose request named Naabu still belongs on the
    // Unavailable path below, not NotApplicable, because Naabu work was
    // actually requested.
    let network_stage_applies = exact_localhost_only
        || !naabu_tasks.is_empty()
        || requested_check_ids.contains(NAABU_ENGINE_ID);
    let stage = if exact_localhost_only {
        RecordedStage {
            value: Some(ReportScanStage::ConnectionDiagnostic),
            availability: DataAvailability::Recorded,
            explanation:
                "The frozen native localhost task is a bounded connection diagnostic, not a vulnerability scan."
                    .into(),
        }
    } else if !valid_naabu_plans.is_empty() {
        let includes_inventory = valid_naabu_plans
            .iter()
            .flat_map(|plan| &plan.work_units)
            .any(|unit| unit.stage == NaabuWorkStage::FullInventory);
        RecordedStage {
            value: Some(if includes_inventory {
                ReportScanStage::Inventory
            } else {
                ReportScanStage::QuickDiscovery
            }),
            availability: if all_naabu_plans_valid {
                DataAvailability::Recorded
            } else {
                DataAvailability::Unavailable
            },
            explanation: if !all_naabu_plans_valid {
                if includes_inventory {
                    "At least one readable frozen network plan includes full inventory, but another network check has no valid saved plan. Inventory is the highest known stage, not a complete run-wide record."
                        .into()
                } else {
                    "Readable frozen network plans contain quick discovery only, but another network check has no valid saved plan. Quick discovery is the highest known stage, not a complete run-wide record."
                        .into()
                }
            } else if includes_inventory {
                "The frozen network plan includes quick discovery followed by the full approved port inventory."
                    .into()
            } else {
                "The frozen network plan contains quick discovery work only.".into()
            },
        }
    } else if !network_stage_applies {
        RecordedStage {
            value: None,
            availability: DataAvailability::NotApplicable,
            explanation: "This run has no network discovery stage.".into(),
        }
    } else {
        RecordedStage {
            value: None,
            availability: DataAvailability::Unavailable,
            explanation: "Recorded stage selection: unavailable. Current project settings: excluded from this historical record."
                .into(),
        }
    };

    let mut limits = Vec::new();
    for task in &run.engine_runs {
        match task.task_kind {
            EngineTaskKind::BuiltInLocalhostTcp {
                port,
                timeout_ms,
                payload_bytes,
            } if task.task_kind.is_exact_built_in_localhost_tcp_contract() => {
                limits.push(RequestedLimit {
                    name: "endpoint".into(),
                    value: format!("127.0.0.1:{port}"),
                    source: RequestedLimitSource::FrozenTaskContract,
                });
                limits.push(RequestedLimit {
                    name: "connection timeout".into(),
                    value: format!("{timeout_ms} ms"),
                    source: RequestedLimitSource::FrozenTaskContract,
                });
                limits.push(RequestedLimit {
                    name: "application payload".into(),
                    value: format!("{payload_bytes} bytes"),
                    source: RequestedLimitSource::FrozenTaskContract,
                });
            }
            EngineTaskKind::CatalogEngine => {
                if let Some(seconds) = task.execution_timeout_seconds {
                    limits.push(RequestedLimit {
                        name: format!("{} execution timeout", task.engine_id),
                        value: format!("{seconds} seconds"),
                        source: RequestedLimitSource::FrozenTaskContract,
                    });
                }
            }
            EngineTaskKind::BuiltInLocalhostTcp { .. } => {}
        }
    }
    for grant in &run.scope_grant_snapshots {
        let Some(external) = grant.external_scope.as_ref() else {
            continue;
        };
        limits.extend([
            RequestedLimit {
                name: format!("{} authorized network target", grant.asset_id),
                value: external.target.canonical_text(),
                source: RequestedLimitSource::FrozenScopeGrant,
            },
            RequestedLimit {
                name: format!("{} approved ports", grant.asset_id),
                value: external
                    .ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                source: RequestedLimitSource::FrozenScopeGrant,
            },
            RequestedLimit {
                name: format!("{} request rate", grant.asset_id),
                value: format!(
                    "{} per second, concurrency {}",
                    external.rate_policy.requests_per_second, external.rate_policy.concurrency
                ),
                source: RequestedLimitSource::FrozenScopeGrant,
            },
            RequestedLimit {
                name: format!("{} network timeout", grant.asset_id),
                value: format!("{} seconds", external.rate_policy.timeout_seconds),
                source: RequestedLimitSource::FrozenScopeGrant,
            },
        ]);
    }
    limits.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.value.cmp(&right.value))
    });
    limits.dedup();
    debug_assert_limits_are_translatable(&limits);

    let mut unavailable_dimensions = Vec::new();
    if stage.availability == DataAvailability::Unavailable {
        unavailable_dimensions.push(UnavailableDimension {
            dimension: "requested scan stage".into(),
            explanation: stage.explanation.clone(),
        });
    }
    if limits.is_empty() && !run.is_terminal_no_checks() {
        unavailable_dimensions.push(UnavailableDimension {
            dimension: "requested limits".into(),
            explanation: "No exact per-run limits were retained. Current project settings are not substituted for historical requested limits."
                .into(),
        });
    }
    let reductions_availability = if exact_localhost_only || all_naabu_plans_valid {
        DataAvailability::Recorded
    } else if !network_stage_applies {
        DataAvailability::NotApplicable
    } else {
        unavailable_dimensions.push(UnavailableDimension {
            dimension: "automatic scope reductions or truncations".into(),
            explanation: "This run did not retain an exact reduction record. An empty list therefore cannot be interpreted as proof that no requested dimension was reduced."
                .into(),
        });
        DataAvailability::Unavailable
    };
    if targets.iter().any(|target| {
        target.label_availability != DataAvailability::Recorded
            || target.asset_kind_availability != DataAvailability::Recorded
    }) {
        unavailable_dimensions.push(UnavailableDimension {
            dimension: "run-frozen target label or type".into(),
            explanation: "At least one target identifier is frozen with the run, but its displayed label or type comes from current project data or is unavailable. The report labels that provenance and does not call it historical fact."
                .into(),
        });
    }

    RequestedCoverage {
        targets,
        stage,
        limits,
        requested_check_ids: requested_check_ids.into_iter().collect(),
        request_outcome_code,
        automatic_reductions: Vec::new(),
        reductions_availability,
        unavailable_dimensions,
    }
}

fn project_requested_target(case: &AssessmentCase, run: &ScanRun, asset_id: Id) -> RequestedTarget {
    // A model check is bound to the frozen full endpoint and model, rather
    // than the website origin inferred from its HTTPS network grant.
    if let Some(snapshot) = run.report_asset_snapshots.iter().find(|snapshot| {
        snapshot.asset.id == asset_id && snapshot.asset.kind == AssetKind::AiModelEndpoint
    }) {
        return RequestedTarget {
            asset_id,
            label: Some(snapshot.asset.name.clone()),
            asset_kind: Some(AssetKind::AiModelEndpoint),
            label_availability: DataAvailability::Recorded,
            asset_kind_availability: DataAvailability::Recorded,
        };
    }
    if let Some(port) = run
        .engine_runs
        .iter()
        .find_map(|task| match task.task_kind {
            EngineTaskKind::BuiltInLocalhostTcp { port, .. }
                if task.task_kind.is_exact_built_in_localhost_tcp_contract()
                    && task.asset_ids.len() == 1
                    && task.asset_ids[0] == asset_id =>
            {
                Some(port)
            }
            _ => None,
        })
    {
        return RequestedTarget {
            asset_id,
            label: Some(format!("127.0.0.1:{port}")),
            asset_kind: Some(AssetKind::WebService),
            label_availability: DataAvailability::Recorded,
            asset_kind_availability: DataAvailability::Recorded,
        };
    }

    if let Some(external) = run
        .scope_grant_snapshots
        .iter()
        .find(|grant| grant.asset_id == asset_id)
        .and_then(|grant| grant.external_scope.as_ref())
    {
        if let Some(profile) = exact_frozen_internal_endpoint_profile(run, &asset_id) {
            let scheme = match profile {
                DeclaredNetworkServiceScanProfile::InternalEndpointSsh => "ssh",
                DeclaredNetworkServiceScanProfile::InternalEndpointRdpTls => "rdp",
                DeclaredNetworkServiceScanProfile::InternalEndpointVnc => "vnc",
                DeclaredNetworkServiceScanProfile::InternalEndpointSmtp => "smtp",
                DeclaredNetworkServiceScanProfile::InternalEndpointTelnet => "telnet",
            };
            if let Some(endpoint) = frozen_network_service_endpoint(external, scheme) {
                return RequestedTarget {
                    asset_id,
                    label: Some(endpoint),
                    asset_kind: Some(AssetKind::Host),
                    label_availability: DataAvailability::Recorded,
                    asset_kind_availability: DataAvailability::Recorded,
                };
            }
        }
        if let Some(origin) = frozen_web_service_origin(external) {
            return RequestedTarget {
                asset_id,
                label: Some(origin),
                asset_kind: Some(AssetKind::WebService),
                label_availability: DataAvailability::Recorded,
                asset_kind_availability: DataAvailability::Recorded,
            };
        }
        let frozen_kind = match &external.target {
            crate::external_scope::CanonicalTarget::Hostname(_) => AssetKind::Domain,
            crate::external_scope::CanonicalTarget::Address(_)
            | crate::external_scope::CanonicalTarget::Network(_) => AssetKind::IpAddress,
        };
        return RequestedTarget {
            asset_id,
            label: Some(external.target.canonical_text()),
            asset_kind: Some(frozen_kind),
            label_availability: DataAvailability::Recorded,
            asset_kind_availability: DataAvailability::Recorded,
        };
    }

    if let Some(snapshot) = run
        .report_asset_snapshots
        .iter()
        .find(|snapshot| snapshot.asset.id == asset_id)
    {
        return RequestedTarget {
            asset_id,
            label: Some(snapshot.asset.name.clone()),
            asset_kind: Some(snapshot.asset.kind.clone()),
            label_availability: DataAvailability::Recorded,
            asset_kind_availability: DataAvailability::Recorded,
        };
    }

    let current_asset = case.assets.iter().find(|asset| asset.id == asset_id);
    RequestedTarget {
        asset_id,
        label: current_asset.map(|asset| asset.name.clone()),
        asset_kind: current_asset.map(|asset| asset.kind.clone()),
        label_availability: if current_asset.is_some() {
            DataAvailability::CurrentCaseFallback
        } else {
            DataAvailability::Unavailable
        },
        asset_kind_availability: if current_asset.is_some() {
            DataAvailability::CurrentCaseFallback
        } else {
            DataAvailability::Unavailable
        },
    }
}

fn frozen_network_service_endpoint(
    external: &crate::external_scope::ExternalScopeGrant,
    scheme: &str,
) -> Option<String> {
    if external.protocol != crate::external_scope::TransportProtocol::Tcp
        || external.ports.len() != 1
    {
        return None;
    }
    let port = *external.ports.iter().next()?;
    let host = match &external.target {
        crate::external_scope::CanonicalTarget::Hostname(host) => host.clone(),
        crate::external_scope::CanonicalTarget::Address(IpAddr::V6(address)) => {
            format!("[{address}]")
        }
        crate::external_scope::CanonicalTarget::Address(address) => address.to_string(),
        crate::external_scope::CanonicalTarget::Network(_) => return None,
    };
    Some(format!("{scheme}://{host}:{port}"))
}

fn frozen_web_service_origin(
    external: &crate::external_scope::ExternalScopeGrant,
) -> Option<String> {
    let scheme = match external.protocol {
        crate::external_scope::TransportProtocol::Http => "http",
        crate::external_scope::TransportProtocol::Https => "https",
        crate::external_scope::TransportProtocol::Tcp
        | crate::external_scope::TransportProtocol::Udp
        | crate::external_scope::TransportProtocol::Tls => return None,
    };
    if external.ports.len() != 1 {
        return None;
    }
    let port = *external.ports.iter().next()?;
    let host = match &external.target {
        crate::external_scope::CanonicalTarget::Hostname(host) => host.clone(),
        crate::external_scope::CanonicalTarget::Address(IpAddr::V6(address)) => {
            format!("[{address}]")
        }
        crate::external_scope::CanonicalTarget::Address(address) => address.to_string(),
        crate::external_scope::CanonicalTarget::Network(_) => return None,
    };
    Some(format!("{scheme}://{host}:{port}"))
}

struct ActualCoverageProjection {
    actual: ActualCoverage,
    gaps: Vec<CoverageGap>,
    data_quality_warnings: Vec<String>,
    useful_task_ids: BTreeSet<Id>,
    exact_complete_task_ids: BTreeSet<Id>,
}

fn project_actual_coverage(case: &AssessmentCase, run: &ScanRun) -> ActualCoverageProjection {
    let mut checks = Vec::new();
    let mut network_scopes = Vec::new();
    let mut gaps = Vec::new();
    let mut unavailable_dimensions = Vec::new();
    let mut observed_times = Vec::new();
    let mut data_quality_warnings = Vec::new();
    let mut useful_task_ids = BTreeSet::new();
    let mut exact_complete_task_ids = BTreeSet::new();

    for task in &run.engine_runs {
        observed_times.extend(task.started_at);
        observed_times.extend(task.finished_at);
        if let Some(observation) = task.localhost_tcp_observation.as_ref() {
            observed_times.push(observation.observed_at);
        }

        let mut tested_dimensions = Vec::new();
        let mut status = actual_status(task);
        let mut task_gap_already_projected = false;
        let mut exact_complete = false;
        let mut useful_result = false;
        match task.task_kind {
            EngineTaskKind::BuiltInLocalhostTcp {
                port,
                timeout_ms,
                payload_bytes,
            } if task.task_kind.is_exact_built_in_localhost_tcp_contract() => {
                if let Some(observation) = task.localhost_tcp_observation.as_ref() {
                    tested_dimensions.push(TestedDimension {
                        dimension: "TCP reachability".into(),
                        value: format!("127.0.0.1:{port}"),
                        observation: localhost_observation_text(&observation.outcome).into(),
                        observed_at: Some(observation.observed_at),
                    });
                    tested_dimensions.push(TestedDimension {
                        dimension: "bounded connection contract".into(),
                        value: format!(
                            "one connection attempt; {timeout_ms} ms timeout; {payload_bytes} application-payload bytes"
                        ),
                        observation: "The native task only observed whether the endpoint accepted, refused, or timed out during the bounded connection attempt. It did not perform a vulnerability test."
                            .into(),
                        observed_at: Some(observation.observed_at),
                    });
                    useful_result = true;
                }
                exact_complete = exactly_completed_without_known_gap(task);
            }
            EngineTaskKind::CatalogEngine
                if task.engine_id == NAABU_ENGINE_ID
                    && (task.naabu_work_plan.is_some()
                        || !task.naabu_attempt_requests.is_empty()
                        || !task.naabu_attempt_results.is_empty()) =>
            {
                let reduced = task.naabu_work_plan.as_ref().map_or_else(
                    || Err("saved work plan is missing"),
                    |plan| {
                        reduce_naabu_attempt_coverage(
                            plan,
                            &task.naabu_attempt_requests,
                            &task.naabu_attempt_results,
                        )
                        .map_err(|_| "saved work-unit history is inconsistent")
                    },
                );
                match reduced {
                    Ok(coverage) => {
                        status = naabu_coverage_status(task, &coverage);
                        append_naabu_tested_dimensions(task, &coverage, &mut tested_dimensions);
                        append_naabu_coverage_gaps(task, &coverage, &mut gaps);
                        network_scopes.extend(project_naabu_network_scopes(task, &coverage));
                        useful_result = coverage.summary.has_usable_results;
                        exact_complete =
                            task.status == EngineRunStatus::Completed && coverage.fully_complete;
                        task_gap_already_projected = true;
                    }
                    Err(_) => {
                        status = untrusted_naabu_history_status(task);
                        gaps.push(CoverageGap {
                            unattributed: None,
                            kind: CoverageGapKind::Unavailable,
                            class: CoverageGapKind::Unavailable.default_class(),
                            task_id: Some(task.id.clone()),
                            target_asset_ids: task.asset_ids.clone(),
                            dimension: format!("{} saved scan-batch coverage", check_id(task)),
                            reason: "This check's own record of what it scanned is unusable, so it cannot be shown as complete."
                                .into(),
                            next_action_code: NextActionCode::RetryCheck,
                            next_action: "Run this check again to get a usable record.".into(),
                        });
                        data_quality_warnings
                            .push("One check has incomplete coverage history.".into());
                        task_gap_already_projected = true;
                    }
                }
            }
            EngineTaskKind::CatalogEngine if task.status == EngineRunStatus::Completed => {
                let unproven_nuclei_asset_ids = task
                    .asset_ids
                    .iter()
                    .filter(|asset_id| {
                        task.engine_id == NUCLEI_ENGINE_ID
                            && !crate::coverage::engine_run_has_security_template_execution(
                                task, asset_id,
                            )
                    })
                    .cloned()
                    .collect::<BTreeSet<_>>();
                for asset_id in &task.asset_ids {
                    if unproven_nuclei_asset_ids.contains(asset_id) {
                        continue;
                    }
                    tested_dimensions.push(TestedDimension {
                        dimension: "completed check-to-target coordinate".into(),
                        value: format!("{} on asset {asset_id}", task.engine_id),
                        observation: "The durable task reached completed state for this target binding. More granular executed dimensions were not frozen in this case record."
                            .into(),
                        observed_at: task.finished_at,
                    });
                }
                append_internal_device_tls_dimensions(run, task, &mut tested_dimensions);
                append_nuclei_website_dimensions(run, task, &mut tested_dimensions);
                append_internal_host_greenbone_dimensions(run, task, &mut tested_dimensions);
                append_internal_endpoint_ssh_dimensions(run, task, &mut tested_dimensions);
                append_internal_endpoint_rdp_tls_dimensions(run, task, &mut tested_dimensions);
                append_internal_endpoint_vnc_dimensions(run, task, &mut tested_dimensions);
                append_internal_endpoint_smtp_dimensions(case, run, task, &mut tested_dimensions);
                append_internal_endpoint_telnet_dimensions(run, task, &mut tested_dimensions);
                // The completed check-to-target coordinate pushed just above
                // already tells the reader, for this same engine and asset,
                // that more granular executed dimensions were not frozen. A
                // second copy as an unavailable dimension became a coverage-gap
                // row that fired for every completed task without exception, so
                // it carried no per-run information and grew with the number of
                // engines: on a 21-engine run it filled 16 of the 25 rows a
                // beginner reads to learn what was not tested, ahead of the
                // dead host and the checks that actually failed.
                let meaningful_completed_profile = task.engine_id != GREENBONE_ENGINE_ID
                    || task_has_exact_frozen_greenbone_vulnerability_profile(run, task);
                if !meaningful_completed_profile {
                    // A generic Greenbone task coordinate proves that a
                    // process completed, not that a reviewed vulnerability
                    // profile ran. Only exact frozen device/endpoint profiles
                    // may produce a no-problem security result.
                    status = CoverageDimensionStatus::NotTested;
                    gaps.push(CoverageGap {
                        unattributed: None,
                        kind: CoverageGapKind::NotTested,
                        class: CoverageGapKind::NotTested.default_class(),
                        task_id: Some(task.id.clone()),
                        target_asset_ids: task.asset_ids.clone(),
                        dimension: format!(
                            "{}: vulnerability profile evidence",
                            check_id(task)
                        ),
                        reason: "The Greenbone process completed, but this run does not retain one exact reviewed vulnerability profile for every bound asset. Process completion is not counted as a vulnerability result."
                            .into(),
                        next_action_code: NextActionCode::PreserveVisibleLimitation,
                        next_action: "Start a new scan for a fresh result.".into(),
                    });
                    task_gap_already_projected = true;
                }
                let smtp_tls_coverage_unproven =
                    task_has_unproven_smtp_tls_coverage(case, run, task);
                if meaningful_completed_profile && smtp_tls_coverage_unproven {
                    // A completed task proves that the exact fixed profile was
                    // attempted. It does not prove STARTTLS was available or
                    // that every TLS-dependent VT ran. Keep this check partial
                    // until selected-run evidence identifies every TLS OID.
                    status = CoverageDimensionStatus::TestedPartial;
                    task_gap_already_projected = true;
                }
                useful_result = meaningful_completed_profile && !tested_dimensions.is_empty();
                exact_complete = meaningful_completed_profile
                    && !smtp_tls_coverage_unproven
                    && exactly_completed_without_known_gap(task);

                for asset_id in &unproven_nuclei_asset_ids {
                    gaps.push(CoverageGap {
                        unattributed: None,
                        kind: CoverageGapKind::Unavailable,
                        class: CoverageGapKind::Unavailable.default_class(),
                        task_id: Some(task.id.clone()),
                        target_asset_ids: vec![asset_id.clone()],
                        dimension: format!("{}: website execution evidence", check_id(task)),
                        reason: "Website security-template evidence unavailable. This website cannot be shown as tested."
                            .into(),
                        next_action_code: NextActionCode::PreserveVisibleLimitation,
                        next_action: "Start a new scan for a fresh result.".into(),
                    });
                }
                if !unproven_nuclei_asset_ids.is_empty() {
                    status = if unproven_nuclei_asset_ids.len() == task.asset_ids.len() {
                        CoverageDimensionStatus::NotTested
                    } else {
                        CoverageDimensionStatus::TestedPartial
                    };
                    exact_complete = false;
                    task_gap_already_projected = true;
                }

                let bound_asset_ids = task.asset_ids.iter().cloned().collect::<BTreeSet<_>>();
                let dead_host_asset_ids = task
                    .unevaluated_targets
                    .iter()
                    .filter(|target| {
                        target.cause == UnevaluatedTargetCause::TargetDidNotRespond
                            && bound_asset_ids.contains(&target.asset_id)
                    })
                    .map(|target| target.asset_id.clone())
                    .collect::<BTreeSet<_>>();
                let no_service_asset_ids = task
                    .unevaluated_targets
                    .iter()
                    .filter(|target| {
                        target.cause == UnevaluatedTargetCause::NoServiceIdentified
                            && bound_asset_ids.contains(&target.asset_id)
                            && !dead_host_asset_ids.contains(&target.asset_id)
                    })
                    .map(|target| target.asset_id.clone())
                    .collect::<BTreeSet<_>>();
                let scanner_error_asset_ids = task
                    .unevaluated_targets
                    .iter()
                    .filter(|target| {
                        target.cause == UnevaluatedTargetCause::ScannerError
                            && bound_asset_ids.contains(&target.asset_id)
                            && !dead_host_asset_ids.contains(&target.asset_id)
                            && !no_service_asset_ids.contains(&target.asset_id)
                    })
                    .map(|target| target.asset_id.clone())
                    .collect::<BTreeSet<_>>();

                for asset_id in &dead_host_asset_ids {
                    tested_dimensions
                        .retain(|dimension| !tested_dimension_refers_to_asset(dimension, asset_id));
                    gaps.push(CoverageGap {
                        unattributed: None,
                        kind: CoverageGapKind::Failed,
                        class: CoverageGapKind::Failed.default_class(),
                        task_id: Some(task.id.clone()),
                        target_asset_ids: vec![asset_id.clone()],
                        dimension: format!("{}: target response", check_id(task)),
                        reason: "Host response unavailable. Vulnerability checks did not complete."
                            .into(),
                        next_action_code: NextActionCode::ReviewScopeAndRetry,
                        next_action: "Confirm the host is powered on and reachable from this computer on the approved ports, then run this check again."
                            .into(),
                    });
                }
                for asset_id in &no_service_asset_ids {
                    tested_dimensions
                        .retain(|dimension| !tested_dimension_refers_to_asset(dimension, asset_id));
                    gaps.push(CoverageGap {
                        unattributed: None,
                        kind: CoverageGapKind::NotTested,
                        class: CoverageGapKind::NotTested.default_class(),
                        task_id: Some(task.id.clone()),
                        target_asset_ids: vec![asset_id.clone()],
                        dimension: format!("{}: service identification", check_id(task)),
                        reason: "No service identified on the approved ports. Vulnerability checks did not run for this host."
                            .into(),
                        next_action_code: NextActionCode::ChooseCompatibleCheck,
                        next_action: "If this host serves a web page, add its full address as a website, then start a new scan."
                            .into(),
                    });
                }
                for asset_id in &scanner_error_asset_ids {
                    gaps.push(CoverageGap {
                        unattributed: None,
                        kind: CoverageGapKind::Failed,
                        class: CoverageGapKind::Failed.default_class(),
                        task_id: Some(task.id.clone()),
                        target_asset_ids: vec![asset_id.clone()],
                        dimension: format!("{}: scanner errors", check_id(task)),
                        reason: "Greenbone reported errors for this host, so its checks cannot be shown as complete."
                            .into(),
                        next_action_code: NextActionCode::PreserveVisibleLimitation,
                        next_action: "Start a new scan for a fresh result.".into(),
                    });
                }
                if !dead_host_asset_ids.is_empty()
                    || !no_service_asset_ids.is_empty()
                    || !scanner_error_asset_ids.is_empty()
                {
                    status = CoverageDimensionStatus::TestedPartial;
                    exact_complete = false;
                    task_gap_already_projected = true;
                }
                if !bound_asset_ids.is_empty()
                    && bound_asset_ids
                        .iter()
                        .all(|asset_id| dead_host_asset_ids.contains(asset_id))
                {
                    status = CoverageDimensionStatus::Failed;
                    tested_dimensions.clear();
                    useful_result = false;
                } else if !bound_asset_ids.is_empty()
                    && bound_asset_ids.iter().all(|asset_id| {
                        dead_host_asset_ids.contains(asset_id)
                            || no_service_asset_ids.contains(asset_id)
                    })
                {
                    status = CoverageDimensionStatus::NotTested;
                    tested_dimensions.clear();
                    useful_result = false;
                }
            }
            EngineTaskKind::CatalogEngine => {
                // Older adapters did not freeze granular executed dimensions.
                // Their durable PartiallyCompleted state remains the only
                // available coarse proof that some usable result arrived.
                useful_result = status == CoverageDimensionStatus::TestedPartial;
            }
            EngineTaskKind::BuiltInLocalhostTcp { .. } => {}
        }

        if task.error_code.as_deref() == Some("local_input_profile_unsupported") {
            status = CoverageDimensionStatus::NotTested;
            tested_dimensions.clear();
            useful_result = false;
            exact_complete = false;
            gaps.push(CoverageGap {
                unattributed: None,
                kind: CoverageGapKind::NotTested,
                class: CoverageGapKind::NotTested.default_class(),
                task_id: Some(task.id.clone()),
                target_asset_ids: task.asset_ids.clone(),
                dimension: format!("{}: unsupported target input", check_id(task)),
                reason: "This check's packaged scanner cannot read this kind of target, so nothing was tested by it."
                    .into(),
                next_action_code: NextActionCode::PreserveVisibleLimitation,
                next_action: "Update the app, then retry these checks.".into(),
            });
            task_gap_already_projected = true;
        }

        if status == CoverageDimensionStatus::TestedComplete && tested_dimensions.is_empty() {
            status = CoverageDimensionStatus::NotTested;
        }
        if status == CoverageDimensionStatus::TestedComplete
            && task.finished_at.is_none()
            && task.localhost_tcp_observation.is_none()
        {
            unavailable_dimensions.push(UnavailableDimension {
                dimension: format!("{} completed-check time", check_id(task)),
                explanation:
                    "Completed-check time: unavailable. Finish and bounded observation times are absent."
                        .into(),
            });
        }

        if !task_gap_already_projected {
            append_task_gap(task, status, &mut gaps);
        }
        append_unevaluated_controls_gap(task, status, &mut gaps);
        if useful_result {
            useful_task_ids.insert(task.id.clone());
        }
        if exact_complete {
            exact_complete_task_ids.insert(task.id.clone());
        }
        debug_assert_tested_dimensions_are_translatable(&tested_dimensions);
        checks.push(ActualCheck {
            task_id: task.id.clone(),
            check_id: check_id(task),
            result_kind: Some(task_result_kind(task)),
            target_asset_ids: task.asset_ids.clone(),
            status,
            started_at: task.started_at,
            finished_at: task.finished_at,
            tested_dimensions,
        });
    }

    checks.sort_by(|left, right| left.task_id.cmp(&right.task_id));
    network_scopes.sort_by(|left, right| {
        left.task_id
            .cmp(&right.task_id)
            .then_with(|| left.work_unit_id.cmp(&right.work_unit_id))
    });
    unavailable_dimensions.sort_by(|left, right| left.dimension.cmp(&right.dimension));
    unavailable_dimensions.dedup();
    observed_times.sort();
    let observed_from = observed_times.first().copied();
    let observed_until = observed_times.last().copied();
    ActualCoverageProjection {
        actual: ActualCoverage {
            observed_from,
            observed_until,
            checks,
            network_scopes,
            unavailable_dimensions,
        },
        gaps,
        data_quality_warnings,
        useful_task_ids,
        exact_complete_task_ids,
    }
}

fn naabu_coverage_status(
    task: &EngineRun,
    coverage: &CumulativeNaabuCoverage,
) -> CoverageDimensionStatus {
    if task.status == EngineRunStatus::Completed && coverage.fully_complete {
        return CoverageDimensionStatus::TestedComplete;
    }
    if coverage.summary.has_usable_results {
        return CoverageDimensionStatus::TestedPartial;
    }
    if coverage.summary.failed > 0 || task.status == EngineRunStatus::Failed {
        return CoverageDimensionStatus::Failed;
    }
    if coverage.summary.timed_out > 0 || stable_timeout_marker(task) {
        return CoverageDimensionStatus::TimedOut;
    }
    if coverage.summary.cancelled > 0 || task.status == EngineRunStatus::Cancelled {
        return CoverageDimensionStatus::Cancelled;
    }
    CoverageDimensionStatus::NotTested
}

fn untrusted_naabu_history_status(task: &EngineRun) -> CoverageDimensionStatus {
    if stable_timeout_marker(task) {
        return CoverageDimensionStatus::TimedOut;
    }
    match task.status {
        EngineRunStatus::Failed => CoverageDimensionStatus::Failed,
        EngineRunStatus::Cancelled => CoverageDimensionStatus::Cancelled,
        EngineRunStatus::NotExecuted
        | EngineRunStatus::Completed
        | EngineRunStatus::PartiallyCompleted => CoverageDimensionStatus::NotTested,
        EngineRunStatus::Queued
        | EngineRunStatus::Preparing
        | EngineRunStatus::Running
        | EngineRunStatus::Paused => unreachable!("active task passed the final-report gate"),
    }
}

/// Tested-dimension values name their target as `... on asset {asset_id}`,
/// sometimes followed by more words. The whole identifier must match so that
/// `host-1` cannot stand in for `host-10`.
fn tested_dimension_refers_to_asset(dimension: &TestedDimension, asset_id: &str) -> bool {
    dimension.value.split(" on asset ").skip(1).any(|rest| {
        rest.strip_prefix(asset_id)
            .is_some_and(|tail| tail.is_empty() || tail.starts_with(' '))
    })
}

fn append_naabu_tested_dimensions(
    task: &EngineRun,
    coverage: &CumulativeNaabuCoverage,
    tested_dimensions: &mut Vec<TestedDimension>,
) {
    let total = coverage.summary.requested;
    if coverage.summary.tested_complete > 0 {
        tested_dimensions.push(TestedDimension {
            dimension: "completed planned scan batches".into(),
            value: format!("{} of {total}", coverage.summary.tested_complete),
            observation: "These exact frozen scan batches have validated completed outcomes across all saved attempts. A completed network check reports reachability; it is not a security pass."
                .into(),
            observed_at: task.finished_at,
        });
    }
    if coverage.summary.tested_partial > 0 {
        tested_dimensions.push(TestedDimension {
            dimension: "partly completed planned scan batches".into(),
            value: format!("{} of {total}", coverage.summary.tested_partial),
            observation: "Scan-batch status: Partial. Planned operations remain unfinished.".into(),
            observed_at: task.finished_at,
        });
    }
}

fn project_naabu_network_scopes(
    task: &EngineRun,
    coverage: &CumulativeNaabuCoverage,
) -> Vec<NetworkScopeCoverage> {
    let Some(plan) = task.naabu_work_plan.as_ref() else {
        return Vec::new();
    };
    coverage
        .work_units
        .iter()
        .filter_map(|covered| {
            let unit = plan
                .work_units
                .iter()
                .find(|unit| unit.unit_id == covered.unit_id)?;
            let grant = plan
                .frozen_grants
                .get(usize::try_from(unit.grant_index).ok()?)?;
            let address_start = usize::try_from(unit.address_start).ok()?;
            let address_end = address_start.checked_add(usize::try_from(unit.address_len).ok()?)?;
            let port_start = usize::try_from(unit.port_start).ok()?;
            let port_end = port_start.checked_add(usize::try_from(unit.port_len).ok()?)?;
            let addresses = grant.addresses.get(address_start..address_end)?;
            let ports = grant.ports.get(port_start..port_end)?;
            Some(NetworkScopeCoverage {
                task_id: task.id.clone(),
                check_id: check_id(task),
                work_unit_id: unit.unit_id.clone(),
                target_asset_id: grant.asset_id.clone(),
                target: grant.target.canonical_text(),
                address_ranges: compact_ip_ranges(addresses),
                port_ranges: compact_port_ranges(ports),
                transport: "tcp".into(),
                stage: match unit.stage {
                    NaabuWorkStage::QuickDiscovery => ReportScanStage::QuickDiscovery,
                    NaabuWorkStage::FullInventory => ReportScanStage::Inventory,
                },
                outcome: covered.outcome,
                observed_at: covered.outcome_execution_attempt.and(task.finished_at),
            })
        })
        .collect()
}

fn compact_ip_ranges(addresses: &[IpAddr]) -> Vec<String> {
    let Some(first) = addresses.first().copied() else {
        return Vec::new();
    };
    let mut ranges = Vec::new();
    let mut start = first;
    let mut previous = first;
    for address in addresses.iter().copied().skip(1) {
        if ip_addresses_are_adjacent(previous, address) {
            previous = address;
            continue;
        }
        ranges.push(format_ip_range(start, previous));
        start = address;
        previous = address;
    }
    ranges.push(format_ip_range(start, previous));
    ranges
}

fn ip_addresses_are_adjacent(left: IpAddr, right: IpAddr) -> bool {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => {
            u32::from(left).checked_add(1) == Some(u32::from(right))
        }
        (IpAddr::V6(left), IpAddr::V6(right)) => {
            u128::from(left).checked_add(1) == Some(u128::from(right))
        }
        _ => false,
    }
}

fn format_ip_range(start: IpAddr, end: IpAddr) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

fn compact_port_ranges(ports: &[u16]) -> Vec<String> {
    let Some(first) = ports.first().copied() else {
        return Vec::new();
    };
    let mut ranges = Vec::new();
    let mut start = first;
    let mut previous = first;
    for port in ports.iter().copied().skip(1) {
        if previous.checked_add(1) == Some(port) {
            previous = port;
            continue;
        }
        ranges.push(format_port_range(start, previous));
        start = port;
        previous = port;
    }
    ranges.push(format_port_range(start, previous));
    ranges
}

fn format_port_range(start: u16, end: u16) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

fn append_naabu_coverage_gaps(
    task: &EngineRun,
    coverage: &CumulativeNaabuCoverage,
    gaps: &mut Vec<CoverageGap>,
) {
    const TARGETED_RESUME_ACTIONS: [&str; 5] = [
        "Retry only the unfinished work.",
        "Retry only the failed work.",
        "Retry only the timed-out work.",
        "Retry the work without a tested outcome.",
        "Restart the cancelled work.",
    ];
    const WHOLE_CHECK_RETRY_ACTIONS: [&str; 1] = ["Run this check again to confirm the result."];

    let summary = &coverage.summary;
    let task_id = Some(task.id.clone());
    let targets = task.asset_ids.clone();
    // Computed before the closure so `push` keeps capturing the pre-cloned
    // ids rather than `task`. False when Progress has no per-check Resume.
    let retry_available = task_retry_control_is_available(task);
    let mut push = |kind: CoverageGapKind,
                    dimension: String,
                    reason: String,
                    next_action_code: NextActionCode,
                    next_action: &str| {
        if next_action_code == NextActionCode::RetryCheck {
            debug_assert!(
                TARGETED_RESUME_ACTIONS.contains(&next_action)
                    || WHOLE_CHECK_RETRY_ACTIONS.contains(&next_action),
                "unclassified retry sentence in append_naabu_coverage_gaps: {next_action}"
            );
        }
        // These five sentences tell the reader to resume exactly the units
        // that did not finish. That is the per-check Resume control. When it
        // is absent, run-level Start is a new scan.
        let (next_action_code, next_action) = if next_action_code == NextActionCode::RetryCheck
            && TARGETED_RESUME_ACTIONS.contains(&next_action)
            && !retry_available
        {
            (
                NextActionCode::StartNewScan,
                "Start a new scan for a fresh result.",
            )
        } else {
            (next_action_code, next_action)
        };
        gaps.push(CoverageGap {
            unattributed: None,
            kind,
            class: kind.default_class(),
            task_id: task_id.clone(),
            target_asset_ids: targets.clone(),
            dimension,
            reason,
            next_action_code,
            next_action: next_action.into(),
        });
    };

    if summary.tested_partial > 0 {
        push(
            CoverageGapKind::NotTested,
            format!(
                "{} partly completed scan batches ({})",
                check_id(task),
                summary.tested_partial
            ),
            "Usable results were saved for these batches, but the rest of their planned addresses and ports were not tested."
                .into(),
            NextActionCode::RetryCheck,
            "Retry only the unfinished work.",
        );
    }
    if summary.failed > 0 {
        push(
            CoverageGapKind::Failed,
            format!(
                "{} failed scan batches ({})",
                check_id(task),
                summary.failed
            ),
            "These planned scan batches stopped before establishing completed coverage.".into(),
            NextActionCode::RetryCheck,
            "Retry only the failed work.",
        );
    }
    if summary.timed_out > 0 {
        push(
            CoverageGapKind::TimedOut,
            format!(
                "{} timed-out scan batches ({})",
                check_id(task),
                summary.timed_out
            ),
            "These planned scan batches reached their bounded time limit before completed coverage was recorded."
                .into(),
            NextActionCode::RetryCheck,
            "Retry only the timed-out work.",
        );
    }
    if summary.cancelled > 0 {
        push(
            CoverageGapKind::Cancelled,
            format!(
                "{} cancelled scan batches ({})",
                check_id(task),
                summary.cancelled
            ),
            "These planned scan batches were cancelled before completed coverage was recorded."
                .into(),
            NextActionCode::RetryCheck,
            "Restart the cancelled work.",
        );
    }
    if summary.not_tested > 0 {
        push(
            CoverageGapKind::NotTested,
            format!(
                "{} not-tested scan batches ({})",
                check_id(task),
                summary.not_tested
            ),
            "These frozen scan batches have no validated tested outcome in any saved attempt."
                .into(),
            NextActionCode::RetryCheck,
            "Retry the work without a tested outcome.",
        );
    }
    if !coverage.all_validated_final_artifacts_normalized {
        push(
            CoverageGapKind::Unavailable,
            format!("{} saved result processing", check_id(task)),
            "Some of this check's results could not be read, so findings from it may be missing."
                .into(),
            NextActionCode::PreserveVisibleLimitation,
            "Start a new scan for a fresh result.",
        );
    }

    if coverage.fully_complete && task.status != EngineRunStatus::Completed {
        let (kind, code, action, reason) = if stable_timeout_marker(task) {
            (
                CoverageGapKind::TimedOut,
                NextActionCode::RetryCheck,
                "Run this check again to confirm the result.",
                "All of this check's planned work produced evidence, but the check timed out before it finished.",
            )
        } else if task.status == EngineRunStatus::Failed {
            (
                CoverageGapKind::Failed,
                NextActionCode::RetryCheck,
                "Run this check again to confirm the result.",
                "All of this check's planned work produced evidence, but the check ended in failure.",
            )
        } else if task.status == EngineRunStatus::Cancelled {
            (
                CoverageGapKind::Cancelled,
                NextActionCode::RetryCheck,
                "Run this check again to confirm the result.",
                "All of this check's planned work produced evidence, but the check was cancelled before it finished.",
            )
        } else {
            (
                CoverageGapKind::Unavailable,
                NextActionCode::RetryCheck,
                "Run this check again to confirm the result.",
                "All of this check's planned work produced evidence, but the check never recorded that it finished.",
            )
        };
        push(
            kind,
            format!("{} final-state reconciliation", check_id(task)),
            reason.into(),
            code,
            action,
        );
    }

    // Usable unit evidence never erases the task's terminal outcome. Avoid a
    // duplicate when the cumulative unit projection already carries the same
    // failure category.
    if !coverage.fully_complete {
        if stable_timeout_marker(task) && summary.timed_out == 0 {
            push(
                CoverageGapKind::TimedOut,
                format!("{} ended after its time limit", check_id(task)),
                if summary.has_usable_results {
                    "The check reached its time limit after saving some usable results."
                } else {
                    "The check reached its time limit before saving a tested outcome."
                }
                .into(),
                NextActionCode::RetryCheck,
                "Retry only the unfinished work.",
            );
        } else if task.status == EngineRunStatus::Failed && summary.failed == 0 {
            push(
                CoverageGapKind::Failed,
                format!("{} stopped before finishing", check_id(task)),
                if summary.has_usable_results {
                    "The check stopped after saving some usable results."
                } else {
                    "The check stopped before saving a tested outcome."
                }
                .into(),
                NextActionCode::RetryCheck,
                "Retry only the unfinished work.",
            );
        } else if task.status == EngineRunStatus::Cancelled && summary.cancelled == 0 {
            push(
                CoverageGapKind::Cancelled,
                format!("{} was cancelled before finishing", check_id(task)),
                if summary.has_usable_results {
                    "The check was cancelled after saving some usable results."
                } else {
                    "The check was cancelled before saving a tested outcome."
                }
                .into(),
                NextActionCode::RetryCheck,
                "Retry only the unfinished work.",
            );
        }
    }
}

/// Error codes for which `engineRecoveryAction` returns `"none"`.
const TASK_RETRY_UNAVAILABLE_ERROR_CODES: [&str; 5] = [
    "resume_release_incompatible",
    "resume_work_plan_invalid",
    "runtime_cleanup_identity_unavailable",
    "coverage_incomplete_after_bounded_retries",
    "cancelled_after_partial_results",
];

/// Phases that force recovery action `"none"` before `engineRecoveryAction`.
const TASK_RETRY_UNAVAILABLE_PHASES: [&str; 2] = [
    "cleanup_identity_unavailable",
    "interrupted_restart_cleanup_identity_unavailable",
];

/// `stage` values `parseCheckpoint` accepts. Any other stage leaves no Resume control.
const TASK_RETRY_CHECKPOINT_STAGES: [&str; 11] = [
    "planned",
    "preflight",
    "pulling_image",
    "running",
    "capturing_artifacts",
    "adapting_artifacts",
    "captured_awaiting_adapter",
    "cleanup_pending",
    "completed",
    "cancelled",
    "failed",
];

/// Mirrors `engineRecoveryAction` in `src/services/nativeAdapter.ts`: true when
/// the Progress page renders a per-check Resume/Retry control for this task.
/// Kept in sync by `retry_control_blocklist_matches_the_progress_adapter`.
///
/// A resume token counts only when `parseCheckpoint` would accept it: non-empty
/// JSON whose `engine_run_id`, `engine_id`, numeric `attempt`, and `stage`
/// match this task. `PartiallyCompleted` is the wire status `partial`.
fn task_retry_control_is_available(task: &EngineRun) -> bool {
    let blocked_code = task
        .error_code
        .as_deref()
        .is_some_and(|code| TASK_RETRY_UNAVAILABLE_ERROR_CODES.contains(&code));
    let blocked_phase = TASK_RETRY_UNAVAILABLE_PHASES
        .iter()
        .any(|phase| *phase == task.phase);
    if blocked_code || blocked_phase {
        return false;
    }
    matches!(
        task.status,
        EngineRunStatus::Paused
            | EngineRunStatus::Failed
            | EngineRunStatus::PartiallyCompleted
            | EngineRunStatus::Cancelled,
    ) && progress_resume_checkpoint_is_accepted(task)
}

fn progress_resume_checkpoint_is_accepted(task: &EngineRun) -> bool {
    let Some(token) = task
        .resume_token
        .as_deref()
        .filter(|token| !token.is_empty())
    else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(token) else {
        return false;
    };
    let Some(checkpoint) = value.as_object() else {
        return false;
    };
    checkpoint
        .get("engine_run_id")
        .and_then(serde_json::Value::as_str)
        == Some(task.id.as_str())
        && checkpoint
            .get("engine_id")
            .and_then(serde_json::Value::as_str)
            == Some(task.engine_id.as_str())
        && checkpoint
            .get("attempt")
            .is_some_and(serde_json::Value::is_number)
        && checkpoint
            .get("stage")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|stage| TASK_RETRY_CHECKPOINT_STAGES.contains(&stage))
}

fn append_task_gap(task: &EngineRun, status: CoverageDimensionStatus, gaps: &mut Vec<CoverageGap>) {
    let (not_tested_code, not_tested_action) = not_tested_next_action(task);
    let (kind, dimension, reason, next_action_code, next_action) = match status {
        CoverageDimensionStatus::TestedComplete => return,
        CoverageDimensionStatus::TestedPartial => (
            CoverageGapKind::NotTested,
            "remaining requested dimensions",
            "This check did not reach a confirmed complete result.",
            NextActionCode::RetryCheck,
            "Retry this check for a confirmed result.",
        ),
        CoverageDimensionStatus::TimedOut => (
            CoverageGapKind::TimedOut,
            "timed-out check dimension",
            "The bounded check reached its time limit, so it cannot be treated as tested complete.",
            NextActionCode::RetryCheck,
            "Retry the timed-out work.",
        ),
        CoverageDimensionStatus::Failed => (
            CoverageGapKind::Failed,
            "failed check dimension",
            "This check failed, so it cannot be shown as tested.",
            NextActionCode::RetryCheck,
            "Retry this check.",
        ),
        CoverageDimensionStatus::Cancelled => (
            CoverageGapKind::Cancelled,
            "cancelled check dimension",
            "This check was cancelled before completed coverage was recorded.",
            NextActionCode::RetryCheck,
            "Retry this check to complete the missing coverage.",
        ),
        CoverageDimensionStatus::NotTested => (
            CoverageGapKind::NotTested,
            "not-tested check dimension",
            "This check did not start, so it is not a pass.",
            not_tested_code,
            not_tested_action,
        ),
    };
    // Only these four arms name the per-check Resume control. `NotTested`
    // keeps the sentence from `not_tested_next_action`, including automatic
    // setup. A recorded localhost observation is retried from its own control.
    let (next_action_code, next_action) = if matches!(
        status,
        CoverageDimensionStatus::TestedPartial
            | CoverageDimensionStatus::TimedOut
            | CoverageDimensionStatus::Failed
            | CoverageDimensionStatus::Cancelled,
    ) && next_action_code == NextActionCode::RetryCheck
        && task.localhost_tcp_observation.is_none()
        && !task_retry_control_is_available(task)
    {
        (
            NextActionCode::StartNewScan,
            "Start a new scan for a fresh result.",
        )
    } else {
        (next_action_code, next_action)
    };
    gaps.push(CoverageGap {
        unattributed: None,
        kind,
        class: kind.default_class(),
        task_id: Some(task.id.clone()),
        target_asset_ids: task.asset_ids.clone(),
        dimension: format!("{}: {dimension}", check_id(task)),
        reason: stable_task_reason(task, reason),
        next_action_code,
        next_action: next_action.into(),
    });
}

fn append_request_outcome_gaps(
    run: &ScanRun,
    use_request_outcome: bool,
    gaps: &mut Vec<CoverageGap>,
) {
    if !use_request_outcome || !run.is_terminal_no_checks() {
        return;
    }
    let Some(ScanRequestOutcome::NoChecksCompleted {
        code,
        requested_asset_ids,
        requested_engine_ids,
        explanation,
    }) = run.request_outcome.as_ref()
    else {
        return;
    };
    let (next_action_code, next_action) = match code {
        ScanRequestOutcomeCode::EffectiveScopeRequired => (
            NextActionCode::ReviewScopeAndRetry,
            "Review the exact target and permission, then start the scan again.",
        ),
        ScanRequestOutcomeCode::OwnershipConfirmationRequired => (
            NextActionCode::ReviewScopeAndRetry,
            "Choose a target you control, then start the scan again.",
        ),
        ScanRequestOutcomeCode::NoApplicableChecks => (
            NextActionCode::ChooseCompatibleCheck,
            "Finish target setup or add a supported input, then start a new scan.",
        ),
    };
    if requested_engine_ids.is_empty() {
        gaps.push(CoverageGap {
            unattributed: None,
            kind: CoverageGapKind::NotTested,
            class: CoverageGapKind::NotTested.default_class(),
            task_id: None,
            target_asset_ids: requested_asset_ids.clone(),
            dimension: "requested checks".into(),
            reason: explanation.clone(),
            next_action_code,
            next_action: next_action.into(),
        });
    } else {
        for engine_id in requested_engine_ids {
            gaps.push(CoverageGap {
                unattributed: None,
                kind: CoverageGapKind::NotTested,
                class: CoverageGapKind::NotTested.default_class(),
                task_id: None,
                target_asset_ids: requested_asset_ids.clone(),
                dimension: format!("requested check {engine_id}"),
                reason: explanation.clone(),
                next_action_code,
                next_action: next_action.into(),
            });
        }
    }
}

fn append_engine_admission_gaps(run: &ScanRun, gaps: &mut Vec<CoverageGap>) {
    if run.engine_admission_issues.is_empty() {
        return;
    }
    let catalog_list_unavailable = run
        .engine_admission_issues
        .iter()
        .any(|issue| issue.code == "catalog_container_invalid");
    gaps.push(CoverageGap {
        unattributed: None,
        kind: CoverageGapKind::NotTested,
        class: CoverageGapKind::NotTested.default_class(),
        task_id: None,
        // Catalog admission failed before applicability could be trusted, so
        // this gap must not fabricate either a scanner or target binding.
        target_asset_ids: Vec::new(),
        dimension: "additional packaged checks".into(),
        reason: if catalog_list_unavailable {
            "Packaged check list unavailable. Additional checks: not tested.".into()
        } else {
            "Some packaged checks could not be loaded. Additional checks: not tested.".into()
        },
        next_action_code: NextActionCode::PreserveVisibleLimitation,
        next_action: "Update the app, then run these checks again.".into(),
    });
}

/// One gap per identifier an engine reported on that nothing authorized claims.
///
/// Without this the run is honest but useless: it shows "Partly completed" and
/// an empty findings list, and the sentence naming the account lives only in a
/// collapsed technical block on another page. A person cannot act on a report
/// that does not tell them which identifier is missing.
fn append_unattributed_gaps(run: &ScanRun, gaps: &mut Vec<CoverageGap>) {
    for task in &run.engine_runs {
        for unattributed in &task.unattributed {
            let count = unattributed.discarded_results;
            let identifier = &unattributed.identifier;
            let provider = &unattributed.provider;
            gaps.push(CoverageGap {
                kind: CoverageGapKind::Unattributed,
                class: CoverageGapKind::Unattributed.default_class(),
                task_id: Some(task.id.clone()),
                // The results belong to an identifier none of these assets
                // claims, so naming them as the target would assert the
                // attribution the adapter just refused to make.
                target_asset_ids: Vec::new(),
                dimension: format!("{}: results for {provider} {identifier}", task.engine_id),
                reason: format!(
                    "{} reported {count} result(s) for {provider} identifier {identifier}. No authorized asset carries that identifier, so none of them were attributed and none appear in this report."
                ,
                    task.engine_id
                ),
                next_action_code: NextActionCode::AddAssetIdentifier,
                // No article before {provider}: "a aws identifier" is wrong and
                // the right one depends on a value read from the artifact.
                next_action: format!(
                    "Add {identifier} to the asset you authorized as its {provider} identifier, then scan again."
                ),
                unattributed: Some(unattributed.clone()),
            });
        }
    }
}

/// One coverage row per gateway refusal kind on a task.
///
/// `unauthorized_client` stays in the cleanup record: a client that was not
/// this engine is not a coverage claim. `None` is a legacy or gateway-less
/// run and stays silent.
fn append_gateway_refusal_gaps(run: &ScanRun, gaps: &mut Vec<CoverageGap>) {
    const RATE_REASON: &str = "The approved rate limit refused some of this check's connections, so part of the check never reached the target.";
    const DESTINATION_REASON: &str =
        "Connections this check attempted outside the approved scope were refused.";
    const UNAVAILABLE_REASON: &str =
        "Whether any of this check's connections were refused was not recorded.";
    for task in &run.engine_runs {
        let Some(record) = task.gateway_refusals else {
            continue;
        };
        match record {
            GatewayRefusalRecord::Counted {
                rate, destination, ..
            } => {
                if rate > 0 {
                    // The retry sentence names the per-check Resume control,
                    // which Progress renders only for a resumable task. A check
                    // that finished after its refusals is not resumable, so it
                    // is sent to the Start control that does render there.
                    let (next_action_code, next_action) = if task_retry_control_is_available(task) {
                        (NextActionCode::RetryCheck, "Retry this check.")
                    } else {
                        (
                            NextActionCode::StartNewScan,
                            "Start a new scan for a fresh result.",
                        )
                    };
                    gaps.push(CoverageGap {
                        kind: CoverageGapKind::Truncated,
                        class: CoverageGapClass::CoverageLoss,
                        task_id: Some(task.id.clone()),
                        target_asset_ids: task.asset_ids.clone(),
                        dimension: format!(
                            "{}: connections refused by the rate limit",
                            check_id(task)
                        ),
                        reason: format!("{RATE_REASON} Refused connections: {rate}."),
                        next_action_code,
                        next_action: next_action.into(),
                        unattributed: None,
                    });
                }
                if destination > 0 {
                    gaps.push(CoverageGap {
                        kind: CoverageGapKind::NotTested,
                        class: CoverageGapClass::RecordNote,
                        task_id: Some(task.id.clone()),
                        target_asset_ids: task.asset_ids.clone(),
                        dimension: format!(
                            "{}: destination outside the approved scope",
                            check_id(task)
                        ),
                        reason: format!("{DESTINATION_REASON} Refused connections: {destination}."),
                        next_action_code: NextActionCode::NoActionUnlessScopeChanges,
                        next_action: "No action for the current scope.".into(),
                        unattributed: None,
                    });
                }
            }
            GatewayRefusalRecord::Unavailable => {
                gaps.push(CoverageGap {
                    kind: CoverageGapKind::Unavailable,
                    class: CoverageGapClass::RecordNote,
                    task_id: Some(task.id.clone()),
                    target_asset_ids: task.asset_ids.clone(),
                    dimension: format!("{}: unrecorded connection refusals", check_id(task)),
                    reason: UNAVAILABLE_REASON.into(),
                    next_action_code: NextActionCode::PreserveVisibleLimitation,
                    next_action: "Start a new scan for a fresh result.".into(),
                    unattributed: None,
                });
            }
        }
    }
}

/// One visible coverage item per Maester control whose upstream verdict is
/// `Investigate`. The check ran, but the missing verdict remains a coverage
/// gap and must not disappear.
fn append_manual_review_gaps(run: &ScanRun, gaps: &mut Vec<CoverageGap>) {
    const REASON: &str =
        "Maester evaluated this control but did not return a pass or fail verdict.";
    for task in &run.engine_runs {
        for control in &task.manual_review_controls {
            let reason = control.detail.as_ref().map_or_else(
                || REASON.to_owned(),
                |detail| format!("{REASON} Upstream detail: {detail}"),
            );
            gaps.push(CoverageGap {
                kind: CoverageGapKind::ManualReview,
                class: CoverageGapKind::ManualReview.default_class(),
                task_id: Some(task.id.clone()),
                target_asset_ids: vec![control.asset_id.clone()],
                dimension: format!(
                    "{}: no verdict for {} — {}",
                    task.engine_id, control.rule_id, control.title
                ),
                reason,
                next_action_code: NextActionCode::ReviewManualControl,
                next_action:
                    "Review the upstream detail and record a human decision for this control."
                        .into(),
                unattributed: None,
            });
        }
    }
}

/// Fails a debug build if this file writes a sentence no reader in Traditional
/// Chinese can be shown.
///
/// The census lives here, at the producer, rather than in a test that reads
/// this file for string literals. A regex over the source misses the ones
/// composed in a local `push` closure, assembled from a conditional, or copied
/// from an upstream struct -- which between them is most of them -- and reports
/// full coverage while doing it. Every existing test that builds a report runs
/// this instead, so a new sentence fails the test that exercises its own path.
///
/// An excluded area carries the words a person typed about their own case.
/// There is nothing to look up and a fixed label would discard what they wrote.
fn debug_assert_coverage_prose_is_translatable(gaps: &[CoverageGap]) {
    if cfg!(debug_assertions) {
        for gap in gaps {
            if gap.kind == CoverageGapKind::Excluded || gap.unattributed.is_some() {
                continue;
            }
            // A request-outcome gap prints an explanation stored in the case
            // file. This build writes three of them and translates all three,
            // but the field is validated only for length and control
            // characters, so a case written by another build may hold anything.
            // Asserting on it would panic on a legitimate record.
            if !gap.dimension.starts_with("requested check") {
                debug_assert!(
                    crate::finding_narrative::coverage_gap_prose_zh_hant(&gap.reason).is_some(),
                    "no Traditional Chinese for the coverage gap reason: {}",
                    gap.reason
                );
            }
            debug_assert!(
                crate::finding_narrative::coverage_gap_prose_zh_hant(&gap.next_action).is_some(),
                "no Traditional Chinese for the coverage gap next action: {}",
                gap.next_action
            );
        }
    }
}

/// Every limit name this build writes has a Traditional Chinese form in
/// `finding_narrative.rs`. Same discipline as the coverage prose above: the
/// whole Rust suite is the census, so a limit added to a producer here fails
/// the test that exercises its own path rather than reaching a Chinese reader
/// of the shared report as English.
fn debug_assert_limits_are_translatable(limits: &[RequestedLimit]) {
    if cfg!(debug_assertions) {
        for limit in limits {
            debug_assert!(
                crate::finding_narrative::recognized_requested_limit_name_zh_hant(&limit.name)
                    .is_some(),
                "no Traditional Chinese for the requested limit name: {}",
                limit.name
            );
            if limit.value.bytes().any(|byte| byte.is_ascii_alphabetic()) {
                debug_assert!(
                    crate::finding_narrative::recognized_requested_limit_value_zh_hant(
                        &limit.name,
                        &limit.value
                    )
                    .is_some(),
                    "no Traditional Chinese for the requested limit value: {} = {}",
                    limit.name,
                    limit.value
                );
            }
        }
    }
}

/// The tested dimensions share the coverage-name vocabulary, and every fixed
/// observation this build writes has a Traditional Chinese form.
fn debug_assert_tested_dimensions_are_translatable(dimensions: &[TestedDimension]) {
    if cfg!(debug_assertions) {
        for dimension in dimensions {
            debug_assert!(
                crate::finding_narrative::recognized_coverage_dimension_zh_hant(
                    &dimension.dimension
                )
                .is_some(),
                "no Traditional Chinese for the tested dimension: {}",
                dimension.dimension
            );
            debug_assert!(
                crate::finding_narrative::tested_observation_zh_hant(&dimension.observation)
                    .is_some(),
                "no Traditional Chinese for the tested dimension observation: {}",
                dimension.observation
            );
            debug_assert!(
                crate::finding_narrative::tested_value_zh_hant(
                    &dimension.dimension,
                    &dimension.value
                )
                .is_some(),
                "no Traditional Chinese for the tested dimension value: {} = {}",
                dimension.dimension,
                dimension.value
            );
        }
    }
}

fn declared_internal_device_profile(asset: &Asset) -> Option<DeclaredWebServiceScanProfile> {
    serde_json::from_value::<DeclaredWebServiceInput>(
        asset.metadata.get("declared_web_service")?.clone(),
    )
    .ok()?
    .scan_profile
}

fn expected_internal_device_template_ids(
    profile: DeclaredWebServiceScanProfile,
) -> BTreeSet<&'static str> {
    match profile {
        DeclaredWebServiceScanProfile::InternalDeviceHttps => {
            INTERNAL_DEVICE_TLS_VULNERABILITY_OIDS
                .iter()
                .copied()
                .collect()
        }
    }
}

fn exact_frozen_internal_device_profile(
    run: &ScanRun,
    asset_id: &str,
) -> Option<DeclaredWebServiceScanProfile> {
    let mut matching_grants = run
        .scope_grant_snapshots
        .iter()
        .filter(|grant| grant.asset_id == asset_id && grant.external_scope.is_some());
    let grant = matching_grants.next()?;
    if matching_grants.next().is_some()
        || grant.permission != crate::domain::ScanPermission::ActiveExternalTesting
    {
        return None;
    }
    let scope = grant.external_scope.as_ref()?;
    let policy = &scope.template_policy;
    if scope.case_id != run.case_id
        || scope.asset_id != asset_id
        || scope.protocol != crate::external_scope::TransportProtocol::Https
        || scope.activity != crate::external_scope::ExternalActivity::ActiveExternal
        || scope.ports.len() != 1
        || scope.ports.contains(&0)
        || scope.rate_policy.requests_per_second != 2
        || scope.rate_policy.concurrency != 1
        || scope.rate_policy.timeout_seconds != 15
        || policy.revision != INTERNAL_DEVICE_TEMPLATE_REVISION
        || policy.allow_headless
        || policy.allow_out_of_band
        || policy.allow_fuzzing
        || policy.allow_file_upload
        || policy.allow_denial_of_service
        || policy.allow_credential_attacks
    {
        return None;
    }
    let actual_ids = policy
        .allowed_template_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_ids.len() != policy.allowed_template_ids.len() {
        return None;
    }
    let profile = DeclaredWebServiceScanProfile::InternalDeviceHttps;
    (actual_ids == expected_internal_device_template_ids(profile)).then_some(profile)
}

fn current_internal_device_profile(
    case: &AssessmentCase,
    asset_id: &str,
) -> Option<DeclaredWebServiceScanProfile> {
    case.assets
        .iter()
        .find(|asset| asset.id == asset_id)
        .and_then(declared_internal_device_profile)
}

fn append_internal_device_tls_dimensions(
    run: &ScanRun,
    task: &EngineRun,
    dimensions: &mut Vec<TestedDimension>,
) {
    if task.engine_id != GREENBONE_ENGINE_ID || task.status != EngineRunStatus::Completed {
        return;
    }
    for asset_id in &task.asset_ids {
        if exact_frozen_internal_device_profile(run, asset_id).is_none() {
            continue;
        }
        dimensions.push(TestedDimension {
            dimension: "internal-device TLS vulnerability checks".into(),
            value: format!(
                "{} frozen Greenbone TLS tests on asset {asset_id}",
                INTERNAL_DEVICE_TLS_VULNERABILITY_OIDS.len()
            ),
            observation: "The completed Greenbone task retained a frozen allowlist containing the profile's TLS protocol, cipher, and certificate vulnerability checks."
                .into(),
            observed_at: task.finished_at,
        });
    }
}

fn declared_internal_endpoint_profile(asset: &Asset) -> Option<DeclaredNetworkServiceScanProfile> {
    serde_json::from_value::<DeclaredNetworkServiceMetadata>(
        asset.metadata.get("declared_network_service")?.clone(),
    )
    .ok()
    .map(|service| service.scan_profile)
}

fn exact_frozen_internal_endpoint_profile(
    run: &ScanRun,
    asset_id: &str,
) -> Option<DeclaredNetworkServiceScanProfile> {
    let mut matching_grants = run
        .scope_grant_snapshots
        .iter()
        .filter(|grant| grant.asset_id == asset_id && grant.external_scope.is_some());
    let grant = matching_grants.next()?;
    if matching_grants.next().is_some()
        || grant.permission != crate::domain::ScanPermission::ActiveExternalTesting
    {
        return None;
    }
    let scope = grant.external_scope.as_ref()?;
    let policy = &scope.template_policy;
    if scope.case_id != run.case_id
        || scope.asset_id != asset_id
        || scope.protocol != crate::external_scope::TransportProtocol::Tcp
        || scope.activity != crate::external_scope::ExternalActivity::ActiveExternal
        || matches!(
            &scope.target,
            crate::external_scope::CanonicalTarget::Network(_)
        )
        || scope.ports.len() != 1
        || scope.ports.contains(&0)
        || scope.rate_policy.requests_per_second != 2
        || scope.rate_policy.concurrency != 1
        || scope.rate_policy.timeout_seconds != 15
        || policy.revision != INTERNAL_DEVICE_TEMPLATE_REVISION
        || policy.allow_headless
        || policy.allow_out_of_band
        || policy.allow_fuzzing
        || policy.allow_file_upload
        || policy.allow_denial_of_service
        || policy.allow_credential_attacks
    {
        return None;
    }
    let actual_ids = policy
        .allowed_template_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_ids.len() != policy.allowed_template_ids.len() {
        return None;
    }
    [
        (
            DeclaredNetworkServiceScanProfile::InternalEndpointSsh,
            INTERNAL_ENDPOINT_SSH_VULNERABILITY_OIDS.as_slice(),
        ),
        (
            DeclaredNetworkServiceScanProfile::InternalEndpointRdpTls,
            INTERNAL_ENDPOINT_RDP_TLS_VULNERABILITY_OIDS.as_slice(),
        ),
        (
            DeclaredNetworkServiceScanProfile::InternalEndpointVnc,
            INTERNAL_ENDPOINT_VNC_VULNERABILITY_OIDS.as_slice(),
        ),
        (
            DeclaredNetworkServiceScanProfile::InternalEndpointSmtp,
            INTERNAL_ENDPOINT_SMTP_VULNERABILITY_OIDS.as_slice(),
        ),
        (
            DeclaredNetworkServiceScanProfile::InternalEndpointTelnet,
            INTERNAL_ENDPOINT_TELNET_VULNERABILITY_OIDS.as_slice(),
        ),
    ]
    .into_iter()
    .find_map(|(profile, expected_oids)| {
        (actual_ids == expected_oids.iter().copied().collect::<BTreeSet<_>>()).then_some(profile)
    })
}

fn exact_frozen_internal_endpoint_ssh_profile(run: &ScanRun, asset_id: &str) -> bool {
    exact_frozen_internal_endpoint_profile(run, asset_id)
        == Some(DeclaredNetworkServiceScanProfile::InternalEndpointSsh)
}

fn exact_frozen_internal_endpoint_rdp_tls_profile(run: &ScanRun, asset_id: &str) -> bool {
    exact_frozen_internal_endpoint_profile(run, asset_id)
        == Some(DeclaredNetworkServiceScanProfile::InternalEndpointRdpTls)
}

fn exact_frozen_internal_endpoint_vnc_profile(run: &ScanRun, asset_id: &str) -> bool {
    exact_frozen_internal_endpoint_profile(run, asset_id)
        == Some(DeclaredNetworkServiceScanProfile::InternalEndpointVnc)
}

fn exact_frozen_internal_endpoint_smtp_profile(run: &ScanRun, asset_id: &str) -> bool {
    exact_frozen_internal_endpoint_profile(run, asset_id)
        == Some(DeclaredNetworkServiceScanProfile::InternalEndpointSmtp)
}

/// Exact TLS VTs that produced frozen finding evidence for this SMTP asset in
/// this engine task. A completed task, a current canonical finding, or evidence
/// from another task is deliberately insufficient: none proves which
/// negotiation-dependent VTs ran in the selected run.
fn selected_run_evidenced_smtp_tls_oids(
    case: &AssessmentCase,
    run: &ScanRun,
    task: &EngineRun,
    asset_id: &str,
) -> BTreeSet<String> {
    if case.id != run.case_id || task.engine_id != GREENBONE_ENGINE_ID {
        return BTreeSet::new();
    }
    case.finding_observations
        .iter()
        .filter(|observation| {
            observation.run_id == run.id
                && observation.asset_ids.iter().any(|id| id == asset_id)
                && observation
                    .engine_ids
                    .iter()
                    .any(|engine_id| engine_id == GREENBONE_ENGINE_ID)
        })
        .filter_map(|observation| {
            let snapshot = observation.finding_snapshot.as_ref()?;
            (snapshot.id == observation.finding_id
                && snapshot.fingerprint == observation.fingerprint
                && snapshot.case_id == case.id
                && snapshot.asset_ids.iter().any(|id| id == asset_id))
            .then_some((observation, snapshot))
        })
        .flat_map(|(observation, snapshot)| {
            snapshot.evidence.iter().filter_map(move |evidence| {
                let source_rule = evidence.source_rule.as_deref()?;
                (evidence.finding_id == snapshot.id
                    && evidence.run_id == run.id
                    && evidence.engine_run_id.as_deref() == Some(task.id.as_str())
                    && evidence.engine_id == GREENBONE_ENGINE_ID
                    && observation
                        .evidence_hashes
                        .iter()
                        .any(|hash| hash == &evidence.artifact_sha256)
                    && INTERNAL_ENDPOINT_SMTP_TLS_VULNERABILITY_OIDS.contains(&source_rule))
                .then(|| source_rule.to_owned())
            })
        })
        .collect()
}

fn task_has_unproven_smtp_tls_coverage(
    case: &AssessmentCase,
    run: &ScanRun,
    task: &EngineRun,
) -> bool {
    task.asset_ids.iter().any(|asset_id| {
        exact_frozen_internal_endpoint_smtp_profile(run, asset_id)
            && selected_run_evidenced_smtp_tls_oids(case, run, task, asset_id).len()
                < INTERNAL_ENDPOINT_SMTP_TLS_VULNERABILITY_OIDS.len()
    })
}

fn exact_frozen_internal_endpoint_telnet_profile(run: &ScanRun, asset_id: &str) -> bool {
    exact_frozen_internal_endpoint_profile(run, asset_id)
        == Some(DeclaredNetworkServiceScanProfile::InternalEndpointTelnet)
}

fn task_has_exact_frozen_greenbone_vulnerability_profile(run: &ScanRun, task: &EngineRun) -> bool {
    !task.asset_ids.is_empty()
        && task.asset_ids.iter().all(|asset_id| {
            exact_frozen_internal_host_scope(run, asset_id).is_some()
                || exact_frozen_internal_device_profile(run, asset_id).is_some()
                || exact_frozen_internal_endpoint_profile(run, asset_id).is_some()
        })
}

fn exact_frozen_nuclei_website_scope<'a>(
    run: &'a ScanRun,
    asset_id: &str,
) -> Option<&'a crate::external_scope::ExternalScopeGrant> {
    let mut matching_grants = run
        .scope_grant_snapshots
        .iter()
        .filter(|grant| grant.asset_id == asset_id && grant.external_scope.is_some());
    let grant = matching_grants.next()?;
    if matching_grants.next().is_some()
        || grant.permission != crate::domain::ScanPermission::ActiveExternalTesting
    {
        return None;
    }
    let scope = grant.external_scope.as_ref()?;
    let policy = &scope.template_policy;
    (scope.case_id == run.case_id
        && scope.asset_id == asset_id
        && matches!(
            scope.protocol,
            crate::external_scope::TransportProtocol::Http
                | crate::external_scope::TransportProtocol::Https
        )
        && scope.activity == crate::external_scope::ExternalActivity::ActiveExternal
        && !matches!(
            &scope.target,
            crate::external_scope::CanonicalTarget::Network(_)
        )
        && scope.ports.len() == 1
        && !scope.ports.contains(&0)
        && scope.rate_policy.requests_per_second == 10
        && scope.rate_policy.concurrency == 5
        && scope.rate_policy.timeout_seconds == 10
        && policy.revision == NUCLEI_TEMPLATE_REVISION
        && policy.allowed_template_ids.is_empty()
        && policy.profile_id.as_deref() == Some(NUCLEI_WEB_SAFE_PROFILE_ID)
        && !policy.allow_headless
        && !policy.allow_out_of_band
        && !policy.allow_fuzzing
        && !policy.allow_file_upload
        && !policy.allow_denial_of_service
        && !policy.allow_credential_attacks)
        .then_some(scope)
}

fn append_nuclei_website_dimensions(
    run: &ScanRun,
    task: &EngineRun,
    dimensions: &mut Vec<TestedDimension>,
) {
    if task.engine_id != NUCLEI_ENGINE_ID || task.status != EngineRunStatus::Completed {
        return;
    }
    for asset_id in &task.asset_ids {
        if exact_frozen_nuclei_website_scope(run, asset_id).is_none()
            || !crate::coverage::engine_run_has_security_template_execution(task, asset_id)
        {
            continue;
        }
        dimensions.push(TestedDimension {
            dimension: "Nuclei upstream website scan".into(),
            value: format!(
                "technology-aware upstream profile on exact website origin for asset {asset_id}"
            ),
            observation: "Nuclei completed the pinned upstream automatic web profile on the displayed origin. Applied checks: templates selected by upstream technology detection. Eligible-template execution completeness: unavailable."
                .into(),
            observed_at: task.finished_at,
        });
    }
}

fn exact_frozen_internal_host_scope<'a>(
    run: &'a ScanRun,
    asset_id: &str,
) -> Option<&'a crate::external_scope::ExternalScopeGrant> {
    let mut matching_grants = run
        .scope_grant_snapshots
        .iter()
        .filter(|grant| grant.asset_id == asset_id && grant.external_scope.is_some());
    let grant = matching_grants.next()?;
    if matching_grants.next().is_some()
        || grant.permission != crate::domain::ScanPermission::ActiveExternalTesting
    {
        return None;
    }
    let scope = grant.external_scope.as_ref()?;
    let policy = &scope.template_policy;
    (scope.case_id == run.case_id
        && scope.asset_id == asset_id
        && scope.protocol == crate::external_scope::TransportProtocol::Tcp
        && scope.activity == crate::external_scope::ExternalActivity::ActiveExternal
        && !matches!(
            &scope.target,
            crate::external_scope::CanonicalTarget::Network(_)
        )
        && !scope.ports.is_empty()
        && scope.ports.len() <= 64
        && !scope.ports.contains(&0)
        && scope.rate_policy.requests_per_second == 2
        && scope.rate_policy.concurrency == 1
        && scope.rate_policy.timeout_seconds == 15
        && policy.revision == INTERNAL_DEVICE_TEMPLATE_REVISION
        && policy.allowed_template_ids.is_empty()
        && policy.profile_id.as_deref() == Some(GREENBONE_REMOTE_SAFE_PROFILE_ID)
        && !policy.allow_headless
        && !policy.allow_out_of_band
        && !policy.allow_fuzzing
        && !policy.allow_file_upload
        && !policy.allow_denial_of_service
        && !policy.allow_credential_attacks)
        .then_some(scope)
}

fn append_internal_host_greenbone_dimensions(
    run: &ScanRun,
    task: &EngineRun,
    dimensions: &mut Vec<TestedDimension>,
) {
    if task.engine_id != GREENBONE_ENGINE_ID || task.status != EngineRunStatus::Completed {
        return;
    }
    for asset_id in &task.asset_ids {
        let Some(scope) = exact_frozen_internal_host_scope(run, asset_id) else {
            continue;
        };
        dimensions.push(TestedDimension {
            dimension: "Greenbone remote vulnerability scan".into(),
            value: format!(
                "applicability-driven upstream profile on asset {asset_id} across {} approved TCP ports",
                scope.ports.len()
            ),
            observation: "Greenbone completed the frozen remote-safe profile on the displayed host and ports. Applied checks: feed checks selected by upstream service and product prerequisites. Scheduled-VT execution completeness: unavailable."
                .into(),
            observed_at: task.finished_at,
        });
    }
}

fn append_internal_endpoint_ssh_dimensions(
    run: &ScanRun,
    task: &EngineRun,
    dimensions: &mut Vec<TestedDimension>,
) {
    if task.engine_id != GREENBONE_ENGINE_ID || task.status != EngineRunStatus::Completed {
        return;
    }
    for asset_id in &task.asset_ids {
        if !exact_frozen_internal_endpoint_ssh_profile(run, asset_id) {
            continue;
        }
        dimensions.push(TestedDimension {
            dimension: "SSH service vulnerability checks".into(),
            value: format!(
                "{} frozen upstream Greenbone SSH tests on asset {asset_id}",
                INTERNAL_ENDPOINT_SSH_VULNERABILITY_OIDS.len()
            ),
            observation: "The completed Greenbone task retained the exact reviewed SSH profile for deprecated protocol, known or static host key, and weak MAC, encryption, host-key, key-size, or key-exchange choices."
                .into(),
            observed_at: task.finished_at,
        });
    }
}

fn append_internal_endpoint_rdp_tls_dimensions(
    run: &ScanRun,
    task: &EngineRun,
    dimensions: &mut Vec<TestedDimension>,
) {
    if task.engine_id != GREENBONE_ENGINE_ID || task.status != EngineRunStatus::Completed {
        return;
    }
    for asset_id in &task.asset_ids {
        if !exact_frozen_internal_endpoint_rdp_tls_profile(run, asset_id) {
            continue;
        }
        dimensions.push(TestedDimension {
            dimension: "RDP transport security checks".into(),
            value: format!(
                "{} frozen upstream Greenbone RDP transport tests on asset {asset_id}",
                INTERNAL_ENDPOINT_RDP_TLS_VULNERABILITY_OIDS.len()
            ),
            observation: "The completed Greenbone task retained the exact reviewed RDP transport profile: ten TLS protocol, cipher, and certificate checks plus one check for the legacy fixed private key used by RDP 5.2 or earlier."
                .into(),
            observed_at: task.finished_at,
        });
    }
}

fn append_internal_endpoint_vnc_dimensions(
    run: &ScanRun,
    task: &EngineRun,
    dimensions: &mut Vec<TestedDimension>,
) {
    if task.engine_id != GREENBONE_ENGINE_ID || task.status != EngineRunStatus::Completed {
        return;
    }
    for asset_id in &task.asset_ids {
        if !exact_frozen_internal_endpoint_vnc_profile(run, asset_id) {
            continue;
        }
        dimensions.push(TestedDimension {
            dimension: "VNC transport security check".into(),
            value: format!(
                "{} frozen upstream Greenbone VNC transport test on asset {asset_id}",
                INTERNAL_ENDPOINT_VNC_VULNERABILITY_OIDS.len()
            ),
            observation: "The completed Greenbone task retained the exact reviewed VNC transport profile containing one check for an unencrypted VNC connection."
                .into(),
            observed_at: task.finished_at,
        });
    }
}

fn append_internal_endpoint_smtp_dimensions(
    case: &AssessmentCase,
    run: &ScanRun,
    task: &EngineRun,
    dimensions: &mut Vec<TestedDimension>,
) {
    if task.engine_id != GREENBONE_ENGINE_ID || task.status != EngineRunStatus::Completed {
        return;
    }
    for asset_id in &task.asset_ids {
        if !exact_frozen_internal_endpoint_smtp_profile(run, asset_id) {
            continue;
        }
        dimensions.push(TestedDimension {
            dimension: "SMTP fixed security profile attempt".into(),
            value: format!(
                "exact {}-check upstream Greenbone SMTP profile on asset {asset_id}",
                INTERNAL_ENDPOINT_SMTP_VULNERABILITY_OIDS.len()
            ),
            observation: "The completed Greenbone task retained and attempted the exact SMTP profile: one check reads the banner, sends EHLO, tries STARTTLS when offered, and reviews advertised AUTH for cleartext-login risk; ten more checks depend on TLS. TLS-check execution: evidenced by selected-run source OIDs. Credentials and mail: not sent."
                .into(),
            observed_at: task.finished_at,
        });
        let evidenced_tls_oids = selected_run_evidenced_smtp_tls_oids(case, run, task, asset_id);
        if !evidenced_tls_oids.is_empty() {
            dimensions.push(TestedDimension {
                dimension: "SMTP TLS checks with selected-run evidence".into(),
                value: format!(
                    "{} of {} selected TLS checks on asset {asset_id}",
                    evidenced_tls_oids.len(),
                    INTERNAL_ENDPOINT_SMTP_TLS_VULNERABILITY_OIDS.len()
                ),
                observation: "Counted coverage: exact TLS source OIDs in selected-run finding evidence. Each OID evidences only its own check."
                    .into(),
                observed_at: task.finished_at,
            });
        }
    }
}

fn append_internal_endpoint_telnet_dimensions(
    run: &ScanRun,
    task: &EngineRun,
    dimensions: &mut Vec<TestedDimension>,
) {
    if task.engine_id != GREENBONE_ENGINE_ID || task.status != EngineRunStatus::Completed {
        return;
    }
    for asset_id in &task.asset_ids {
        if !exact_frozen_internal_endpoint_telnet_profile(run, asset_id) {
            continue;
        }
        dimensions.push(TestedDimension {
            dimension: "Telnet cleartext-login security check".into(),
            value: format!(
                "{} frozen upstream Greenbone Telnet check on asset {asset_id}",
                INTERNAL_ENDPOINT_TELNET_VULNERABILITY_OIDS.len()
            ),
            observation: "The completed Greenbone task retained the exact reviewed Telnet profile, which observes whether a login or password prompt is offered without TLS. No username or password was sent and no login was attempted."
                .into(),
            observed_at: task.finished_at,
        });
    }
}

fn append_internal_endpoint_profile_gaps(
    case: &AssessmentCase,
    run: &ScanRun,
    gaps: &mut Vec<CoverageGap>,
) {
    for task in run
        .engine_runs
        .iter()
        .filter(|task| task.engine_id == GREENBONE_ENGINE_ID)
    {
        for asset_id in &task.asset_ids {
            let current_profile = case
                .assets
                .iter()
                .find(|asset| asset.id == *asset_id)
                .and_then(declared_internal_endpoint_profile);
            let frozen_profile = exact_frozen_internal_endpoint_profile(run, asset_id);
            if frozen_profile.is_none() {
                if let Some(current_profile) = current_profile {
                    let (dimension, reason, next_action) = match current_profile {
                        DeclaredNetworkServiceScanProfile::InternalEndpointSsh => (
                            "SSH endpoint scan-profile coverage",
                            "This run does not retain the exact fixed SSH profile for this asset. Current project metadata is not used to claim historical SSH vulnerability coverage.",
                            "Run this SSH profile again to create a complete coverage record.",
                        ),
                        DeclaredNetworkServiceScanProfile::InternalEndpointRdpTls => (
                            "RDP transport endpoint scan-profile coverage",
                            "This run does not retain the exact fixed RDP transport profile for this asset. Current project metadata is not used to claim historical RDP transport security coverage.",
                            "Run this RDP profile again to create a complete coverage record.",
                        ),
                        DeclaredNetworkServiceScanProfile::InternalEndpointVnc => (
                            "VNC transport endpoint scan-profile coverage",
                            "This run does not retain the exact fixed VNC transport profile for this asset. Current project metadata is not used to claim historical VNC transport security coverage.",
                            "Run this VNC profile again to create a complete coverage record.",
                        ),
                        DeclaredNetworkServiceScanProfile::InternalEndpointSmtp => (
                            "SMTP endpoint scan-profile coverage",
                            "This run does not retain the exact fixed SMTP profile for this asset. Current project metadata is not used to claim historical SMTP security coverage.",
                            "Run this SMTP profile again to create a complete coverage record.",
                        ),
                        DeclaredNetworkServiceScanProfile::InternalEndpointTelnet => (
                            "Telnet endpoint scan-profile coverage",
                            "This run does not retain the exact fixed Telnet profile for this asset. Current project metadata is not used to claim historical Telnet security coverage.",
                            "Run this Telnet profile again to create a complete coverage record.",
                        ),
                    };
                    gaps.push(CoverageGap {
                        unattributed: None,
                        kind: CoverageGapKind::Unavailable,
                        class: CoverageGapKind::Unavailable.default_class(),
                        task_id: Some(task.id.clone()),
                        target_asset_ids: vec![asset_id.clone()],
                        dimension: dimension.into(),
                        reason: reason.into(),
                        next_action_code: NextActionCode::PreserveVisibleLimitation,
                        next_action: next_action.into(),
                    });
                }
                continue;
            }
            if matches!(
                frozen_profile.as_ref(),
                Some(DeclaredNetworkServiceScanProfile::InternalEndpointSmtp)
            ) && selected_run_evidenced_smtp_tls_oids(case, run, task, asset_id).len()
                < INTERNAL_ENDPOINT_SMTP_TLS_VULNERABILITY_OIDS.len()
            {
                let reason = if task.status == EngineRunStatus::Completed {
                    "The SMTP profile ran, but this scan did not record every one of its TLS checks. Which TLS checks ran is shown only by each finding's source OID."
                } else {
                    "This check did not complete, so its SMTP TLS checks cannot be shown as run. Which TLS checks ran is shown only by each finding's source OID."
                };
                gaps.push(CoverageGap {
                    unattributed: None,
                    kind: CoverageGapKind::NotTested,
                    class: CoverageGapKind::NotTested.default_class(),
                    task_id: Some(task.id.clone()),
                    target_asset_ids: vec![asset_id.clone()],
                    dimension: "SMTP TLS negotiation-dependent coverage".into(),
                    reason: reason.into(),
                    next_action_code: NextActionCode::PreserveVisibleLimitation,
                    next_action:
                        "Run a separately approved TLS assessment for complete SMTP TLS coverage."
                            .into(),
                });
            }
            let (dimension, reason, next_action) = match frozen_profile {
                Some(DeclaredNetworkServiceScanProfile::InternalEndpointSsh) => (
                    "endpoint operating-system, package, application, and local-configuration coverage",
                    "The unauthenticated SSH service profile does not inspect operating-system patch level, installed packages or applications, or local host configuration.",
                    "Use an approved endpoint inventory or local snapshot for host-level checks.",
                ),
                Some(DeclaredNetworkServiceScanProfile::InternalEndpointRdpTls) => (
                    "RDP implementation, authentication/NLA, and endpoint host coverage",
                    "The unauthenticated RDP transport profile checks one legacy RDP 5.2-or-earlier fixed-private-key issue, but does not inspect broader or current RDP implementation CVEs, authentication or Network Level Authentication (NLA), Windows patch level, installed packages or applications, or local host configuration.",
                    "Run a separately approved host or RDP-authentication assessment for those checks.",
                ),
                Some(DeclaredNetworkServiceScanProfile::InternalEndpointVnc) => (
                    "VNC implementation, authentication, and endpoint host coverage",
                    "The unauthenticated VNC transport profile checks whether the VNC connection is encrypted. It does not inspect VNC implementation CVEs, authentication strength, operating-system patch level, installed packages or applications, or local host configuration. No login or desktop session was attempted.",
                    "Use an approved endpoint inventory or run a separate authorized VNC assessment.",
                ),
                Some(DeclaredNetworkServiceScanProfile::InternalEndpointSmtp) => (
                    "SMTP server behavior, implementation, and endpoint host coverage",
                    "The unauthenticated SMTP profile reads the banner, issues EHLO, negotiates STARTTLS when offered, and checks advertised AUTH for an unencrypted cleartext-login risk. Its TLS checks apply only when TLS can be negotiated. It does not send credentials or mail, test relay or delivery, authentication enforcement or bypass, anti-spam behavior, general mail-server implementation CVEs, operating-system patches, installed software, or local configuration.",
                    "Run a separately approved mail-server assessment or use endpoint inventory.",
                ),
                Some(DeclaredNetworkServiceScanProfile::InternalEndpointTelnet) => (
                    "Telnet authentication, implementation, and endpoint host coverage",
                    "The unauthenticated Telnet profile observes whether a login or password prompt is offered without TLS. It sends no username or password and does not log in; it does not test default credentials, authentication bypass, Telnet implementation CVEs, operating-system patches, installed software, or local configuration.",
                    "Run a separately approved authentication assessment or use endpoint inventory.",
                ),
                None => unreachable!("the missing profile returned above"),
            };
            gaps.push(CoverageGap {
                unattributed: None,
                kind: CoverageGapKind::NotTested,
                class: CoverageGapKind::NotTested.default_class(),
                task_id: Some(task.id.clone()),
                target_asset_ids: vec![asset_id.clone()],
                dimension: dimension.into(),
                reason: reason.into(),
                next_action_code: NextActionCode::PreserveVisibleLimitation,
                next_action: next_action.into(),
            });
        }
    }
}

/// What the cloud and Microsoft 365 launchers leave out, as (dimension,
/// reason, next action). Each profile is fixed in its launcher: Prowler runs
/// the IAM service on AWS and Azure and four IAM checks on Google Cloud,
/// ScoutSuite runs its IAM service, Cloudsplaining reads IAM policies,
/// ScubaGear runs the `aad` product and Maester its Entra tests.
const AWS_SCOPE_LIMIT: (&str, &str, &str) = (
    "AWS services other than IAM",
    "This scan checked identity and access (IAM) settings only. Other AWS services, such as S3, EC2, RDS, CloudTrail and GuardDuty, were not checked.",
    "Run a full Prowler scan of this account.",
);
const AZURE_SCOPE_LIMIT: (&str, &str, &str) = (
    "Azure services other than IAM",
    "This scan checked identity and access (IAM) role settings only. Other Azure services, such as Microsoft Entra ID, Storage, Virtual Machines, networking, Key Vault and Microsoft Defender for Cloud, were not checked.",
    "Run a full Prowler scan of this subscription.",
);
const GCP_SCOPE_LIMIT: (&str, &str, &str) = (
    "Google Cloud settings other than four IAM checks",
    "This scan ran four identity and access (IAM) checks only: audit logging, service-account roles granted at the project level, and separation of duties for KMS and service-account roles. Other IAM settings and other Google Cloud services were not checked.",
    "Run a full Prowler scan of this Google Cloud project.",
);
const MICROSOFT_365_SCOPE_LIMIT: (&str, &str, &str) = (
    "Microsoft 365 products other than Entra ID",
    "This scan checked Microsoft Entra ID only. Other Microsoft 365 products, such as Exchange Online, Defender for Office 365, SharePoint and OneDrive, and Teams, were not checked.",
    "Run ScubaGear with all products for this tenant.",
);

/// The dimensions `append_cloud_scope_gaps` writes. An asset row with no
/// problems names its gap, in the app and in the saved report alike.
pub const CLOUD_SCOPE_LIMIT_DIMENSIONS: [&str; 4] = [
    AWS_SCOPE_LIMIT.0,
    AZURE_SCOPE_LIMIT.0,
    GCP_SCOPE_LIMIT.0,
    MICROSOFT_365_SCOPE_LIMIT.0,
];

fn cloud_scope_limit(
    engine_id: &str,
    asset_kind: Option<&AssetKind>,
) -> Option<(&'static str, &'static str, &'static str)> {
    match (engine_id, asset_kind) {
        ("prowler", Some(AssetKind::CloudAccount)) | ("scoutsuite" | "cloudsplaining", _) => {
            Some(AWS_SCOPE_LIMIT)
        }
        ("prowler", Some(AssetKind::Subscription)) => Some(AZURE_SCOPE_LIMIT),
        ("prowler", Some(AssetKind::Project)) => Some(GCP_SCOPE_LIMIT),
        ("scubagear" | "maester", _) => Some(MICROSOFT_365_SCOPE_LIMIT),
        _ => None,
    }
}

/// A cloud check that completed with no findings reads as a clean account,
/// while it looked at identity and access alone. One row per asset says what
/// the rest of the account did not get, however many of these checks ran on
/// it: the limit is the asset's, not any one scanner's.
fn append_cloud_scope_gaps(
    targets: &[RequestedTarget],
    actual: &ActualCoverage,
    gaps: &mut Vec<CoverageGap>,
) {
    let mut limits = BTreeSet::new();
    for check in actual.checks.iter().filter(|check| {
        matches!(
            check.status,
            CoverageDimensionStatus::TestedComplete | CoverageDimensionStatus::TestedPartial
        )
    }) {
        for asset_id in &check.target_asset_ids {
            let asset_kind = targets
                .iter()
                .find(|target| &target.asset_id == asset_id)
                .and_then(|target| target.asset_kind.as_ref());
            if let Some(limit) = cloud_scope_limit(&check.check_id, asset_kind) {
                limits.insert((asset_id.clone(), limit));
            }
        }
    }
    for (asset_id, (dimension, reason, next_action)) in limits {
        gaps.push(CoverageGap {
            unattributed: None,
            kind: CoverageGapKind::NotTested,
            class: CoverageGapKind::NotTested.default_class(),
            task_id: None,
            target_asset_ids: vec![asset_id],
            dimension: dimension.into(),
            reason: reason.into(),
            next_action_code: NextActionCode::PreserveVisibleLimitation,
            next_action: next_action.into(),
        });
    }
}

/// Microsoft 365 checks pass over some controls: ScubaGear leaves some for a
/// person to check, Maester skips tests whose prerequisites are missing, and
/// either can fail to evaluate one. The adapter discloses the count as a run
/// warning, which only Progress shows, so with no findings the report read as
/// a clean tenant. This carries the count to the report.
fn append_unevaluated_controls_gap(
    task: &EngineRun,
    status: CoverageDimensionStatus,
    gaps: &mut Vec<CoverageGap>,
) {
    if !matches!(
        status,
        CoverageDimensionStatus::TestedComplete | CoverageDimensionStatus::TestedPartial
    ) {
        return;
    }
    let Some(items) = task.warnings.iter().find_map(|warning| {
        crate::adapters::disclosed_unevaluated_controls(warning)
            .filter(|(engine, _)| engine.eq_ignore_ascii_case(&task.engine_id))
            .map(|(_, items)| items)
    }) else {
        return;
    };
    // An older build named ScubaGear's manual controls differently.
    let items = items
        .iter()
        .map(|item| {
            item.replace(
                "reserved for manual review",
                "left without an automated verdict",
            )
        })
        .collect::<Vec<_>>();
    gaps.push(CoverageGap {
        unattributed: None,
        kind: CoverageGapKind::NotTested,
        class: CoverageGapKind::NotTested.default_class(),
        task_id: Some(task.id.clone()),
        target_asset_ids: task.asset_ids.clone(),
        dimension: format!("{}: controls not evaluated", check_id(task)),
        reason: format!(
            "Some controls in scope were not evaluated, so their state is unknown. Not evaluated: {}.",
            items.join(", ")
        ),
        next_action_code: NextActionCode::PreserveVisibleLimitation,
        next_action: "Check these controls by hand.".into(),
    });
}

fn append_report_asset_snapshot_gaps(run: &ScanRun, gaps: &mut Vec<CoverageGap>) {
    for snapshot in run
        .report_asset_snapshots
        .iter()
        .filter(|snapshot| snapshot.disposition == ReportAssetDisposition::NoSupportedProfile)
    {
        gaps.push(CoverageGap {
            unattributed: None,
            kind: CoverageGapKind::NotTested,
            class: CoverageGapKind::NotTested.default_class(),
            task_id: None,
            target_asset_ids: vec![snapshot.asset.id.clone()],
            dimension: "supported vulnerability profile".into(),
            reason:
                "Supported service-specific vulnerability profile unavailable. Outcome: not tested."
                    .into(),
            next_action_code: NextActionCode::PreserveVisibleLimitation,
            next_action: "Start a new scan and add each exact host under Internal systems.".into(),
        });
    }
}

fn append_internal_device_profile_gaps(
    case: &AssessmentCase,
    run: &ScanRun,
    gaps: &mut Vec<CoverageGap>,
) {
    for task in run
        .engine_runs
        .iter()
        .filter(|task| task.engine_id == GREENBONE_ENGINE_ID)
    {
        for asset_id in &task.asset_ids {
            let Some(profile) = exact_frozen_internal_device_profile(run, asset_id) else {
                if current_internal_device_profile(case, asset_id).is_some() {
                    gaps.push(CoverageGap {
                        unattributed: None,
                        kind: CoverageGapKind::Unavailable,
                        class: CoverageGapKind::Unavailable.default_class(),
                        task_id: Some(task.id.clone()),
                        target_asset_ids: vec![asset_id.clone()],
                        dimension: "internal-device scan-profile coverage".into(),
                        reason: "This run does not retain one exact frozen HTTPS management-service profile for this asset. Current project metadata is not used to claim historical TLS coverage."
                            .into(),
                        next_action_code: NextActionCode::PreserveVisibleLimitation,
                        next_action: "Run the HTTPS management-service profile again to create a complete coverage record."
                            .into(),
                    });
                }
                continue;
            };
            let (dimension, reason) = match profile {
                DeclaredWebServiceScanProfile::InternalDeviceHttps => (
                    "device product and firmware vulnerability coverage",
                    if task.status == EngineRunStatus::Completed {
                        "This HTTPS management-service profile contains no device product or firmware vulnerability checks. TLS protocol, cipher, and certificate checks are reported separately."
                    } else {
                        "This HTTPS management-service profile contains no device product or firmware vulnerability checks."
                    },
                ),
            };
            gaps.push(CoverageGap {
                unattributed: None,
                kind: CoverageGapKind::NotTested,
                class: CoverageGapKind::NotTested.default_class(),
                task_id: Some(task.id.clone()),
                target_asset_ids: vec![asset_id.clone()],
                dimension: dimension.into(),
                reason: reason.into(),
                next_action_code: NextActionCode::PreserveVisibleLimitation,
                next_action: "Run a separately approved device firmware assessment or use endpoint inventory."
                    .into(),
            });
        }
    }
}

fn append_case_exclusions(case: &AssessmentCase, run: &ScanRun, gaps: &mut Vec<CoverageGap>) {
    for entry in case.coverage.iter().filter(|entry| {
        entry.last_run_id.as_deref() == Some(run.id.as_str())
            && matches!(entry.status, crate::domain::CoverageStatus::NotApplicable)
    }) {
        gaps.push(CoverageGap {
            unattributed: None,
            kind: CoverageGapKind::Excluded,
            class: CoverageGapKind::Excluded.default_class(),
            task_id: None,
            target_asset_ids: entry.asset_id.iter().cloned().collect(),
            dimension: entry.label.clone(),
            reason: entry.explanation.clone(),
            next_action_code: NextActionCode::NoActionUnlessScopeChanges,
            next_action: "No action for the current scope.".into(),
        });
    }
}

fn selected_run_observations<'a>(
    case: &'a AssessmentCase,
    run: &ScanRun,
) -> BTreeMap<Id, &'a FindingObservation> {
    let mut selected = BTreeMap::<Id, &FindingObservation>::new();
    for observation in case
        .finding_observations
        .iter()
        .filter(|observation| observation.run_id == run.id)
    {
        selected
            .entry(observation.finding_id.clone())
            .and_modify(|current| {
                if observation.observed_at > current.observed_at {
                    *current = observation;
                }
            })
            .or_insert(observation);
    }
    selected
}

/// One distinct `package:` tag from a frozen selected-run snapshot.
///
/// Zero tags, or more than one, contribute nothing. The tag value is already
/// the scanner's lowercased package name.
fn package_tags_from_observations(
    selected: &BTreeMap<Id, &FindingObservation>,
) -> BTreeMap<Id, String> {
    let mut packages = BTreeMap::new();
    for (finding_id, observation) in selected {
        let Some(snapshot) = observation.finding_snapshot.as_ref() else {
            continue;
        };
        let mut names = BTreeSet::new();
        for tag in &snapshot.tags {
            let Some(name) = tag.strip_prefix("package:") else {
                continue;
            };
            if !name.is_empty() {
                names.insert(name.to_owned());
            }
        }
        if names.len() == 1 {
            packages.insert(finding_id.clone(), names.into_iter().next().unwrap());
        }
    }
    packages
}

fn project_findings(
    case: &AssessmentCase,
    run: &ScanRun,
    selected: &BTreeMap<Id, &FindingObservation>,
) -> (Vec<BeginnerFinding>, Vec<String>) {
    let canonical = case
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    // Built once so `project_finding` can check a finding's target assets
    // without walking `case.assets` per finding.
    let asset_kinds = case
        .assets
        .iter()
        .map(|asset| (asset.id.as_str(), asset.kind.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut warnings = Vec::new();
    let mut findings = selected
        .values()
        .map(|observation| {
            let (source, details) = if let Some(snapshot) = observation.finding_snapshot.as_ref() {
                (FindingSnapshotSource::FrozenSelectedRun, Some(snapshot))
            } else if let Some(current) = canonical.get(observation.finding_id.as_str()) {
                warnings.push(format!(
                    "Finding {} selected-run presentation snapshot: unavailable. Display wording: current canonical text.",
                    observation.finding_id
                ));
                (
                    FindingSnapshotSource::CurrentCanonicalLegacyFallback,
                    Some(*current),
                )
            } else {
                warnings.push(format!(
                    "Finding {} presentation detail: unavailable. Retained run observation: available.",
                    observation.finding_id
                ));
                (FindingSnapshotSource::ObservationOnly, None)
            };
            project_finding(observation, source, details, run, &asset_kinds)
        })
        .collect::<Vec<_>>();

    findings.sort_by(|left, right| {
        right
            .priority
            .unwrap_or(0)
            .cmp(&left.priority.unwrap_or(0))
            .then_with(|| severity_rank(&right.severity).cmp(&severity_rank(&left.severity)))
            .then_with(|| {
                confidence_rank(&right.confidence).cmp(&confidence_rank(&left.confidence))
            })
            .then_with(|| left.finding_id.cmp(&right.finding_id))
    });
    (findings, warnings)
}

fn project_finding_groups(
    case: &AssessmentCase,
    findings: &[BeginnerFinding],
) -> Vec<BeginnerFindingGroup> {
    let observed_finding_ids = findings
        .iter()
        .map(|finding| finding.finding_id.as_str())
        .collect::<BTreeSet<_>>();

    case.finding_groups
        .iter()
        .filter(|group| {
            group
                .finding_ids
                .iter()
                .any(|finding_id| observed_finding_ids.contains(finding_id.as_str()))
        })
        .map(|group| BeginnerFindingGroup {
            group_id: group.id.clone(),
            presentation_scope: FindingGroupPresentationScope::CurrentCasePresentation,
            title: group.title.clone(),
            rationale: group.rationale.clone(),
            actor: group.grouped_by.clone(),
            created_at: group.created_at,
            members: group
                .finding_ids
                .iter()
                .map(|finding_id| BeginnerFindingGroupMember {
                    finding_id: finding_id.clone(),
                    observed_in_selected_run: observed_finding_ids.contains(finding_id.as_str()),
                })
                .collect(),
        })
        .collect()
}

/// Trivy and Grype check both project folders and container assets. Choose
/// the specialist from the selected run's evidence and target asset kind so
/// reports remain accurate with either the old or new adapter default.
fn package_finding_expert(
    observation: &FindingObservation,
    details: Option<&Finding>,
    run: &ScanRun,
    asset_kinds: &BTreeMap<&str, AssetKind>,
) -> Option<&'static str> {
    let mut run_evidence = details
        .into_iter()
        .flat_map(|finding| finding.evidence.iter())
        .filter(|evidence| evidence.run_id == run.id)
        .peekable();
    run_evidence.peek()?;
    if !run_evidence.all(|evidence| matches!(evidence.engine_id.as_str(), "trivy" | "grype")) {
        return None;
    }
    let asset_expert = |asset_id: &Id| match asset_kinds.get(asset_id.as_str())? {
        AssetKind::Repository | AssetKind::FileSystem | AssetKind::IacProject => {
            Some("Software supply-chain engineer")
        }
        AssetKind::ContainerImage | AssetKind::ContainerRegistry => {
            Some("Container security engineer")
        }
        _ => None,
    };
    let first = asset_expert(observation.asset_ids.first()?)?;
    observation
        .asset_ids
        .iter()
        .all(|asset_id| asset_expert(asset_id) == Some(first))
        .then_some(first)
}

fn project_finding(
    observation: &FindingObservation,
    snapshot_source: FindingSnapshotSource,
    details: Option<&Finding>,
    run: &ScanRun,
    asset_kinds: &BTreeMap<&str, AssetKind>,
) -> BeginnerFinding {
    let evidence_details_frozen = snapshot_source == FindingSnapshotSource::FrozenSelectedRun;
    let evidence_references = details
        .map(|finding| {
            finding
                .evidence
                .iter()
                .filter(|evidence| evidence.run_id == run.id)
                .map(|evidence| FindingEvidenceReference {
                    evidence_id: evidence.id.clone(),
                    engine_id: evidence.engine_id.clone(),
                    details_frozen: evidence_details_frozen,
                    source_rule: evidence_details_frozen
                        .then(|| evidence.source_rule.clone())
                        .flatten(),
                    scanner_details: evidence_details_frozen
                        .then(|| evidence.scanner_details.clone())
                        .flatten(),
                    summary: evidence_details_frozen.then(|| evidence.summary.clone()),
                    kind: evidence_details_frozen.then(|| evidence.kind.clone()),
                    engine_run_id: evidence_details_frozen
                        .then(|| evidence.engine_run_id.clone())
                        .flatten(),
                    artifact_id: evidence_details_frozen.then(|| evidence.artifact_id.clone()),
                    redacted: evidence_details_frozen.then_some(evidence.redacted),
                    artifact_sha256: evidence.artifact_sha256.clone(),
                    observed_at: evidence.observed_at,
                    location: evidence.location.clone(),
                    pointer: evidence_details_frozen
                        .then(|| evidence.pointer.clone())
                        .flatten(),
                })
                .collect()
        })
        .unwrap_or_default();
    let framework_references = if snapshot_source == FindingSnapshotSource::FrozenSelectedRun {
        details
            .map(|finding| {
                finding
                    .control_references
                    .iter()
                    .map(|reference| FrameworkReference {
                        framework: reference.framework.clone(),
                        framework_version: reference.framework_version.clone(),
                        control_id: reference.control_id.clone(),
                        title: reference.title.clone(),
                        relationship: reference.relationship.clone(),
                        rationale: reference.rationale.clone(),
                        mapping_version: reference.mapping_version.clone(),
                        mapping_provenance: reference.mapping_provenance.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let observation_details = details
        .filter(|finding| {
            finding
                .severity_basis_code
                .is_some_and(|code| code.is_exposure_observation())
        })
        .map(|finding| {
            finding
                .tags
                .iter()
                .filter(|tag| {
                    tag.starts_with("port:")
                        || tag.starts_with("protocol:")
                        || tag.starts_with("http-status:")
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let exposure_observation = details.is_some_and(|finding| {
        finding
            .severity_basis_code
            .is_some_and(|code| code.is_exposure_observation())
    });
    let aws_iam_policy = details.and_then(|finding| {
        finding.evidence.iter().find_map(|evidence| {
            evidence
                .scanner_details
                .as_ref()
                .and_then(|details| details.aws_iam_policy.as_ref())
        })
    });
    BeginnerFinding {
        finding_id: observation.finding_id.clone(),
        fingerprint: observation.fingerprint.clone(),
        snapshot_source,
        title: details
            .map(|finding| finding.title.clone())
            .unwrap_or_else(|| "Finding details unavailable for this legacy run".into()),
        plain_language_risk: if exposure_observation {
            crate::finding_narrative::EXPOSURE_OBSERVATION_RISK.into()
        } else {
            details
                .map(|finding| {
                    crate::finding_narrative::summary_english(
                        &finding.plain_language_summary,
                        finding.family,
                    )
                })
                .unwrap_or_else(|| {
                    "A retained observation exists, but this older run did not save its full plain-language description."
                        .into()
                })
        },
        possible_impact: if exposure_observation {
            crate::finding_narrative::EXPOSURE_OBSERVATION_IMPACT.into()
        } else {
            details
                .map(|finding| {
                    crate::finding_narrative::impact_english(
                        &finding.possible_impact,
                        finding.family,
                        &finding.context_factors,
                    )
                })
                .unwrap_or_else(|| "The historical impact description is unavailable.".into())
        },
        severity: observation.severity.clone(),
        confidence: observation.confidence.clone(),
        priority: if exposure_observation {
            None
        } else {
            details.map(|finding| finding.priority)
        },
        priority_reasons: if exposure_observation {
            Vec::new()
        } else {
            details
                .map(|finding| {
                    finding
                        .priority_reasons
                        .iter()
                        .filter(|reason| {
                            !crate::finding_narrative::is_evidence_only_priority_reason(reason)
                        })
                        .map(|reason| crate::finding_narrative::priority_reason_english(reason))
                        .collect()
                })
                .unwrap_or_default()
        },
        target_asset_ids: observation.asset_ids.clone(),
        next_step: if exposure_observation {
            crate::finding_narrative::EXPOSURE_OBSERVATION_NEXT_STEP.into()
        } else {
            details
                .map(|finding| {
                    crate::finding_narrative::action_english(
                        &finding.recommendation,
                        finding.family,
                        aws_iam_policy,
                    )
                })
                .unwrap_or_else(|| "Review the retained observation and evidence.".into())
        },
        recommended_expert_type: if exposure_observation {
            crate::finding_narrative::EXPOSURE_OBSERVATION_OWNER.into()
        } else if let Some(expert) = package_finding_expert(observation, details, run, asset_kinds)
        {
            expert.into()
        } else {
            details
                .map(|finding| finding.recommended_expert_type.clone())
                .unwrap_or_else(|| "Security professional".into())
        },
        evidence_references,
        official_references: if snapshot_source == FindingSnapshotSource::FrozenSelectedRun {
            details.map(|finding| finding.official_references.clone())
        } else {
            None
        },
        framework_references,
        family: details.and_then(|finding| finding.family),
        severity_basis_code: details.and_then(|finding| finding.severity_basis_code),
        confidence_basis_code: details.and_then(|finding| finding.confidence_basis_code),
        observation_details,
        context_factors: if exposure_observation {
            Vec::new()
        } else {
            details
                .map(|finding| finding.context_factors.clone())
                .unwrap_or_default()
        },
        rollback_considerations: if exposure_observation {
            None
        } else {
            details.and_then(|finding| {
                finding
                    .rollback_considerations
                    .as_ref()
                    .map(|text| crate::finding_narrative::rollback_english(text))
            })
        },
        verification_guidance: if exposure_observation {
            Some(crate::finding_narrative::EXPOSURE_OBSERVATION_VERIFICATION.into())
        } else {
            details
                .map(|finding| {
                    crate::finding_narrative::verification_english(
                        &finding.verification_guidance,
                        None,
                    )
                })
                .filter(|guidance| !guidance.trim().is_empty())
        },
    }
}

/// Why a finding-derived step is on the list: the finding's own title, then
/// the two ratings the reader is asked to weigh.
///
/// The words are chosen here rather than taken from `{:?}`. A `Debug` rendering
/// is the Rust variant name, which happens to read as English today and stops
/// doing so the day a variant is renamed. The shared report composes the
/// Chinese form of this sentence from the finding the step points at, not by
/// parsing this one back, so the two never have to agree on a shape -- but the
/// English still has to be a deliberate one.
pub(crate) fn finding_step_reason(
    title: &str,
    severity: &Severity,
    confidence: &Confidence,
    confidence_basis_code: Option<crate::domain::ConfidenceBasisCode>,
    priority_reasons: &[String],
) -> String {
    let confidence = crate::finding_narrative::confidence_presentation_english(
        &format!("{} confidence", confidence_word(confidence)),
        confidence_basis_code,
        priority_reasons,
    );
    format!(
        "{title} — {} severity, {confidence}",
        severity_word(severity),
    )
}

/// The typed Cloudsplaining policy record a finding's instruction is composed
/// from, when it has one.
pub(crate) fn finding_aws_iam_policy(
    finding: &BeginnerFinding,
) -> Option<&crate::domain::AwsIamPolicyFindingDetails> {
    finding
        .evidence_references
        .iter()
        .filter(|reference| reference.details_frozen && reference.engine_id == "cloudsplaining")
        .find_map(|reference| {
            reference
                .scanner_details
                .as_ref()
                .and_then(|details| details.aws_iam_policy.as_ref())
        })
}

fn check_produced_observations(status: CoverageDimensionStatus) -> bool {
    matches!(
        status,
        CoverageDimensionStatus::TestedComplete | CoverageDimensionStatus::TestedPartial
    )
}

/// True when every evidence reference points at a check this report does not
/// classify as having produced observations. Unknowns fail closed: missing
/// engine-run ids, ids absent from `actual.checks`, and findings with no
/// evidence at all are unconfirmed. Reachability inventory keeps its own
/// next-step path and is not this state.
pub(crate) fn finding_unconfirmed_by_coverage(
    finding: &BeginnerFinding,
    actual: &ActualCoverage,
) -> bool {
    if finding
        .severity_basis_code
        .is_some_and(|code| code.is_exposure_observation())
    {
        return false;
    }
    finding.evidence_references.iter().all(|reference| {
        let Some(engine_run_id) = reference.engine_run_id.as_ref() else {
            return true;
        };
        actual
            .checks
            .iter()
            .find(|check| check.task_id == *engine_run_id)
            .is_none_or(|check| !check_produced_observations(check.status))
    })
}

fn apply_coverage_constrained_finding_actions(
    findings: &mut [BeginnerFinding],
    actual: &ActualCoverage,
) {
    for finding in findings {
        if finding_unconfirmed_by_coverage(finding, actual) {
            finding.next_step = crate::finding_narrative::INCOMPLETE_CHECK_CONFIRM_ACTION.into();
        }
    }
}

fn severity_word(severity: &Severity) -> &'static str {
    match severity {
        // Not "informational" and not "low": the source gave no recognized
        // rating, and the report says so.
        Severity::Unknown => "Unknown",
        Severity::Informational => "Informational",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

fn confidence_word(confidence: &Confidence) -> &'static str {
    match confidence {
        Confidence::Unknown => "Unknown",
        Confidence::Low => "Low",
        Confidence::Medium => "Medium",
        Confidence::High => "High",
        Confidence::Confirmed => "Confirmed",
    }
}

fn project_next_steps(
    findings: &[BeginnerFinding],
    gaps: &[CoverageGap],
    actual: &ActualCoverage,
    problem_groups: &[crate::report_problem_groups::ReportProblemGroup],
) -> Vec<BeginnerNextStep> {
    // Keyed on the sentences the reader actually sees rather than on the
    // stored `next_step`: a Cloudsplaining finding's instruction is composed
    // from its typed policy record and ignores the stored text entirely, so
    // two findings can store the same string and still be told to do two
    // different things. Rendering both locales here keeps a step that reads
    // as one instruction in English from being two in Chinese.
    let mut step_at: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    let mut steps: Vec<BeginnerNextStep> = Vec::new();
    for finding in findings.iter().filter(|finding| {
        !finding
            .severity_basis_code
            .is_some_and(|code| code.is_exposure_observation())
    }) {
        let policy = finding_aws_iam_policy(finding);
        let exposed_secret = problem_groups.iter().any(|group| {
            group.kind == crate::report_problem_groups::ReportProblemKind::ExposedSecret
                && group
                    .finding_ids
                    .iter()
                    .any(|finding_id| finding_id == &finding.finding_id)
        });
        let family = if exposed_secret {
            Some(FindingFamily::Secret)
        } else {
            finding.family
        };
        let expert = if exposed_secret {
            "Secrets-response specialist".to_owned()
        } else {
            finding.recommended_expert_type.clone()
        };
        let unconfirmed = finding_unconfirmed_by_coverage(finding, actual);
        let key = (
            crate::finding_narrative::finding_next_action_english(
                &finding.next_step,
                family,
                policy,
                unconfirmed,
            ),
            crate::finding_narrative::finding_next_action_zh_hant(
                &finding.next_step,
                &expert,
                family,
                policy,
                unconfirmed,
            ),
            expert.clone(),
        );
        if let Some(&at) = step_at.get(&key) {
            steps[at].also_resolves.push(finding.finding_id.clone());
            continue;
        }
        step_at.insert(key, steps.len());
        steps.push(BeginnerNextStep {
            unattributed: None,
            priority: steps.len() as u16,
            code: if unconfirmed {
                NextActionCode::ConfirmFindingAfterIncompleteCheck
            } else {
                NextActionCode::ReviewFinding
            },
            action: finding.next_step.clone(),
            reason: finding_step_reason(
                &finding.title,
                &finding.severity,
                &finding.confidence,
                finding.confidence_basis_code,
                &finding.priority_reasons,
            ),
            finding_id: Some(finding.finding_id.clone()),
            task_id: None,
            recommended_expert_type: Some(expert),
            family,
            also_resolves: Vec::new(),
            shared_fix: policy.is_some() && !unconfirmed,
        });
    }

    let mut seen_gap_actions = BTreeSet::new();
    for gap in gaps {
        // A gap needing no action is disclosed under what was not tested, not
        // listed as a step here: no user action can change its outcome.
        if gap.next_action_code == NextActionCode::NoActionUnlessScopeChanges {
            continue;
        }
        if seen_gap_actions.insert(gap.next_action.clone()) {
            steps.push(BeginnerNextStep {
                also_resolves: Vec::new(),
                family: None,
                priority: 100 + gap_rank(gap.kind) as u16,
                code: gap.next_action_code,
                action: gap.next_action.clone(),
                reason: gap.reason.clone(),
                finding_id: None,
                task_id: gap.task_id.clone(),
                recommended_expert_type: if gap.kind == CoverageGapKind::TimedOut {
                    Some("Network or system administrator".into())
                } else {
                    None
                },
                unattributed: gap.unattributed.clone(),
                shared_fix: false,
            });
        }
    }

    if steps.is_empty() {
        let (code, action, reason) = if actual.checks.iter().any(is_closed_localhost_check) {
            (
                NextActionCode::StartExpectedServiceAndRetry,
                "Start the expected service, then run this check again.",
                "The port refused the bounded TCP connection at the recorded time; this is not a security pass or failure.",
            )
        } else {
            (
                NextActionCode::ReviewCoverage,
                "Review what was tested before deciding whether you need a broader scan.",
                "Actionable findings in completed checks: 0.",
            )
        };
        steps.push(BeginnerNextStep {
            also_resolves: Vec::new(),
            unattributed: None,
            family: None,
            priority: 0,
            code,
            action: action.into(),
            reason: reason.into(),
            finding_id: None,
            task_id: None,
            recommended_expert_type: None,
            shared_fix: false,
        });
    }
    steps.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.action.cmp(&right.action))
    });
    steps
}

/// Which version line a reader sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScannerVersionForm {
    /// First-layer line: the release and a 7-character commit.
    Short,
    /// Technical detail: the release and the full `source@` commit.
    Exact,
}

/// The version text for one scanner.
///
/// `engine_version` and `reported_version` are trimmed first. When the trimmed
/// engine version is `source@` plus 7 to 64 lowercase hex digits, the short
/// form is `{reported} (source {first 7})` in English and
/// `{reported}（source {first 7}）` in Traditional Chinese, or
/// `source {first 7}` when no release was recorded. The exact form is
/// `{reported} (source@{commit})` / `{reported}（source@{commit}）`, or the
/// stored `source@` value when no release was recorded. Any other engine
/// version is shown as stored, and `reported_version` is ignored.
pub(crate) fn scanner_version_label(
    engine_version: &str,
    reported_version: Option<&str>,
    form: ScannerVersionForm,
    zh_hant: bool,
) -> String {
    let engine_version = engine_version.trim();
    let reported = reported_version
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(commit) = source_built_commit(engine_version) else {
        return engine_version.to_owned();
    };
    let short_commit = &commit[..7];
    match (form, reported, zh_hant) {
        (ScannerVersionForm::Short, Some(reported), true) => {
            format!("{reported}（source {short_commit}）")
        }
        (ScannerVersionForm::Short, Some(reported), false) => {
            format!("{reported} (source {short_commit})")
        }
        (ScannerVersionForm::Short, None, _) => format!("source {short_commit}"),
        (ScannerVersionForm::Exact, Some(reported), true) => {
            format!("{reported}（source@{commit}）")
        }
        (ScannerVersionForm::Exact, Some(reported), false) => {
            format!("{reported} (source@{commit})")
        }
        (ScannerVersionForm::Exact, None, _) => engine_version.to_owned(),
    }
}

fn source_built_commit(engine_version: &str) -> Option<&str> {
    let commit = engine_version.strip_prefix("source@")?;
    let lowercase_hex = (7..=64).contains(&commit.len())
        && commit
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    lowercase_hex.then_some(commit)
}

fn project_technical_details(case: &AssessmentCase, run: &ScanRun) -> TechnicalDetails {
    let mut tasks = run
        .engine_runs
        .iter()
        .map(|task| {
            let mut evidence_sha256 = case
                .raw_artifacts
                .iter()
                .filter(|artifact| artifact.run_id == run.id && artifact.engine_run_id == task.id)
                .map(|artifact| artifact.sha256.clone())
                .collect::<Vec<_>>();
            evidence_sha256.sort();
            evidence_sha256.dedup();
            let execution = match task.task_kind {
                EngineTaskKind::CatalogEngine => TechnicalExecution::CatalogEngine {
                    engine_id: task.engine_id.clone(),
                    engine_version: task.engine_version.clone(),
                    reported_version: task.reported_version.clone(),
                    image_digest: task.image_digest.clone(),
                    command_sha256: task.command_sha256.clone(),
                    runtime_provider: task.runtime_provider.clone(),
                    runtime_version: task.runtime_version.clone(),
                    runtime_security_options: task.runtime_security_options.clone(),
                    distribution_mode: task.distribution_mode.clone(),
                    image_repository: task.image_repository.clone(),
                    adapter_version: task.adapter_version.clone(),
                    rule_version: task.rule_version.clone(),
                    knowledge_date: task
                        .knowledge_input
                        .as_ref()
                        .and_then(|input| input.knowledge_date.clone()),
                },
                EngineTaskKind::BuiltInLocalhostTcp {
                    port,
                    timeout_ms,
                    payload_bytes,
                } if task.task_kind.is_exact_built_in_localhost_tcp_contract() => {
                    TechnicalExecution::BuiltInLocalhostTcp {
                        endpoint: format!("127.0.0.1:{port}"),
                        timeout_ms,
                        payload_bytes,
                        observation: task.localhost_tcp_observation.clone(),
                        contract: "One desktop-host TCP connection attempt; no application payload; reachability observation only."
                            .into(),
                    }
                }
                EngineTaskKind::BuiltInLocalhostTcp { .. } => {
                    TechnicalExecution::InvalidBuiltInTask {
                        explanation:
                            "Stored localhost task contract: unsupported. Endpoint observation: unavailable."
                                .into(),
                    }
                }
            };
            TechnicalTaskDetails {
                task_id: task.id.clone(),
                target_asset_ids: task.asset_ids.clone(),
                status: task.status.clone(),
                phase: task.phase.clone(),
                progress_percent: task.progress_percent,
                started_at: task.started_at,
                finished_at: task.finished_at,
                exit_code: task.exit_code,
                cleanup_removed: task.cleanup_removed,
                cleanup_detail: UnavailableTechnicalValue {
                    availability: DataAvailability::Unavailable,
                    value: None,
                    explanation: "Cleanup detail: unavailable. Structured cleanup outcome shown."
                        .into(),
                },
                error_code: task.error_code.clone(),
                redacted_scanner_message: UnavailableTechnicalValue {
                    availability: DataAvailability::Unavailable,
                    value: None,
                    explanation:
                        "Scanner message: available in the redacted diagnostic export.".into(),
                },
                redacted_diagnostic_log: UnavailableTechnicalValue {
                    availability: DataAvailability::Unavailable,
                    value: None,
                    explanation:
                        "Run-bound diagnostic log: unavailable. Redacted diagnostic export: separate."
                            .into(),
                },
                evidence_sha256,
                execution,
            }
        })
        .collect::<Vec<_>>();
    tasks.sort_by(|left, right| left.task_id.cmp(&right.task_id));
    TechnicalDetails {
        collapsed_by_default: true,
        tasks,
    }
}

fn coverage_counts(actual: &ActualCoverage, gaps: &[CoverageGap]) -> CoverageCounts {
    let mut counts = CoverageCounts::default();
    for check in &actual.checks {
        match check.status {
            CoverageDimensionStatus::TestedComplete => counts.tested_complete += 1,
            CoverageDimensionStatus::TestedPartial => counts.tested_partial += 1,
            CoverageDimensionStatus::Failed => counts.failed += 1,
            CoverageDimensionStatus::TimedOut => counts.timed_out += 1,
            CoverageDimensionStatus::Cancelled => counts.cancelled += 1,
            CoverageDimensionStatus::NotTested => counts.not_tested += 1,
        }
    }
    for gap in gaps {
        match gap.class {
            CoverageGapClass::CoverageLoss => {}
            CoverageGapClass::RecordNote => continue,
        }
        let task_state_already_counted = gap.task_id.as_ref().is_some_and(|task_id| {
            actual.checks.iter().any(|check| {
                check.task_id.as_str() == task_id.as_str()
                    && matches!(
                        (gap.kind, check.status),
                        (CoverageGapKind::Failed, CoverageDimensionStatus::Failed)
                            | (CoverageGapKind::TimedOut, CoverageDimensionStatus::TimedOut)
                            | (
                                CoverageGapKind::Cancelled,
                                CoverageDimensionStatus::Cancelled
                            )
                            | (
                                CoverageGapKind::NotTested,
                                CoverageDimensionStatus::NotTested
                            )
                    )
            })
        });
        match gap.kind {
            // A task-level state was already counted above. Gap-only records
            // (request outcomes/exclusions/unavailable dimensions) add counts.
            CoverageGapKind::Failed if task_state_already_counted => {}
            CoverageGapKind::TimedOut if task_state_already_counted => {}
            CoverageGapKind::Cancelled if task_state_already_counted => {}
            CoverageGapKind::NotTested if task_state_already_counted => {}
            CoverageGapKind::Failed => counts.failed += 1,
            CoverageGapKind::TimedOut => counts.timed_out += 1,
            CoverageGapKind::Cancelled => counts.cancelled += 1,
            CoverageGapKind::NotTested => counts.not_tested += 1,
            CoverageGapKind::Excluded => counts.excluded += 1,
            CoverageGapKind::Truncated => counts.truncated += 1,
            CoverageGapKind::Unavailable => counts.unavailable += 1,
            // Deliberately its own count. The check ran and produced results,
            // so calling it "not tested" understates what happened and calling
            // it "unavailable" describes the wrong thing; the results exist and
            // nothing here claims them.
            CoverageGapKind::Unattributed => counts.unattributed += 1,
            // The check already contributes its tested-complete count. Keep a
            // separate visible count without inflating an incomplete state.
            CoverageGapKind::ManualReview => counts.manual_review += 1,
        }
    }
    counts
}

fn actual_status(task: &EngineRun) -> CoverageDimensionStatus {
    if matches!(
        task.localhost_tcp_observation,
        Some(LocalhostTcpObservation {
            outcome: LocalhostTcpOutcome::TimedOut,
            ..
        })
    ) || stable_timeout_marker(task)
    {
        return CoverageDimensionStatus::TimedOut;
    }
    match task.status {
        EngineRunStatus::Completed => CoverageDimensionStatus::TestedComplete,
        EngineRunStatus::PartiallyCompleted => CoverageDimensionStatus::TestedPartial,
        EngineRunStatus::Failed => CoverageDimensionStatus::Failed,
        EngineRunStatus::Cancelled => CoverageDimensionStatus::Cancelled,
        EngineRunStatus::NotExecuted => CoverageDimensionStatus::NotTested,
        EngineRunStatus::Queued
        | EngineRunStatus::Preparing
        | EngineRunStatus::Running
        | EngineRunStatus::Paused => unreachable!("active task passed the final-report gate"),
    }
}

fn task_is_active(task: &EngineRun) -> bool {
    matches!(
        task.status,
        EngineRunStatus::Queued
            | EngineRunStatus::Preparing
            | EngineRunStatus::Running
            | EngineRunStatus::Paused
    )
}

pub(crate) fn run_is_authoritatively_final(run: &ScanRun) -> bool {
    if run.is_terminal_no_checks() {
        return true;
    }
    if run.engine_runs.is_empty() {
        return run.completed_at.is_some();
    }
    run.engine_runs.iter().all(|task| !task_is_active(task))
}

fn exactly_completed_without_known_gap(task: &EngineRun) -> bool {
    if task.engine_id == NAABU_ENGINE_ID
        && matches!(task.task_kind, EngineTaskKind::CatalogEngine)
        && let Some(plan) = task.naabu_work_plan.as_ref()
    {
        return task.status == EngineRunStatus::Completed
            && reduce_naabu_attempt_coverage(
                plan,
                &task.naabu_attempt_requests,
                &task.naabu_attempt_results,
            )
            .is_ok_and(|coverage| coverage.fully_complete);
    }
    if task.status != EngineRunStatus::Completed {
        return false;
    }
    match task.task_kind {
        EngineTaskKind::BuiltInLocalhostTcp { .. } => {
            task.task_kind.is_exact_built_in_localhost_tcp_contract()
                && matches!(
                    task.localhost_tcp_observation,
                    Some(LocalhostTcpObservation {
                        outcome: LocalhostTcpOutcome::Reachable | LocalhostTcpOutcome::Closed,
                        ..
                    })
                )
        }
        EngineTaskKind::CatalogEngine => true,
    }
}

fn stable_timeout_marker(task: &EngineRun) -> bool {
    task.error_code.as_deref().is_some_and(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("timed_out") || value.contains("timeout")
    }) || {
        let phase = task.phase.to_ascii_lowercase();
        phase == "timed_out" || phase == "timeout"
    } || {
        // The product's own deadline is the ordinary way a check runs out of
        // time, and it never reached the two markers above: the recorded
        // error reconciles to one generic code and the phase becomes the
        // failure stage, so a timed-out check was reported as a check that
        // failed. The sentence is an exact product-owned constant and is
        // matched as one; a cleanup-pending record can carry it alongside a
        // later error, so it is searched for rather than compared.
        task.error_message.as_deref().is_some_and(|message| {
            message.contains(crate::container_runtime::CONTAINER_EXECUTION_TIMEOUT_ERROR)
        })
    }
}

/// Product-owned next step for a check that never started, keyed on the
/// planner skip code stored as `error_code`.
fn not_tested_next_action(task: &EngineRun) -> (NextActionCode, &'static str) {
    match task.error_code.as_deref() {
        Some("mcp_configuration_absent") => (
            NextActionCode::NoActionUnlessScopeChanges,
            "This project has no MCP configuration to check. Continue with the other checks.",
        ),
        Some("mcp_configuration_unselected") => (
            NextActionCode::ReviewScopeAndRetry,
            "Return to scan setup and choose which MCP configuration to check.",
        ),
        Some("agentic_framework_unselected") => (
            NextActionCode::ReviewScopeAndRetry,
            "Return to scan setup and choose the AI workflow framework for inventory.",
        ),
        Some("mcp_configuration_discovery_incomplete") => (
            NextActionCode::NoActionUnlessScopeChanges,
            "MCP configuration discovery did not finish. Continue with the other checks.",
        ),
        Some(
            "engine_release_unavailable" | "engine_deprecated" | "research_only" | "license_review",
        ) => (
            NextActionCode::NoActionUnlessScopeChanges,
            "This version of the app does not include this check.",
        ),
        Some(
            "manifest_unavailable"
            | "adapter_unavailable"
            | "adapter_version_mismatch"
            | "runtime_image_unavailable"
            | "runtime_image_unpinned"
            | "command_unavailable"
            | "external_executable_unsupported"
            | "engine_execution_contract_invalid",
        ) => (
            NextActionCode::RetryCheck,
            "Retry this check; scan-tool setup is automatic.",
        ),
        Some(
            "no_compatible_authorized_assets"
            | "no_effective_scope_grants"
            | "no_ownership_confirmed_targets"
            | "no_compatible_authorized_targets"
            | "workspace_snapshot_unavailable",
        ) => (
            NextActionCode::ReviewScopeAndRetry,
            "Return to scan setup, choose the intended target, and confirm it once.",
        ),
        Some(
            "provider_connection_required"
            | "provider_capability_required"
            | "provider_review_required"
            | "provider_source_required"
            | "provider_capability_unavailable"
            | "provider_source_ambiguous"
            | "provider_authorization_binding_mismatch"
            | "provider_target_binding_mismatch"
            | "provider_preflight_unavailable",
        ) => (
            NextActionCode::ReviewScopeAndRetry,
            "Return to scan setup and reconnect or review the cloud account.",
        ),
        Some(
            "direct_network_protocol_mismatch"
            | "direct_network_target_kind_mismatch"
            | "external_scope_missing"
            | "authorization_reference_empty",
        ) => (
            NextActionCode::ChooseCompatibleCheck,
            "Open the skipped check's technical records and match this check to the approved protocol or target form.",
        ),
        _ => (
            NextActionCode::ReviewScopeAndRetry,
            "Review the target and try this check again.",
        ),
    }
}

fn check_id(task: &EngineRun) -> String {
    match task.task_kind {
        EngineTaskKind::BuiltInLocalhostTcp { port, .. } => {
            format!("native localhost TCP check on 127.0.0.1:{port}")
        }
        EngineTaskKind::CatalogEngine => task.engine_id.clone(),
    }
}

/// The generic code every recorded execution error is reconciled to.
///
/// It is set from `last_error.is_some()` and nothing else, so it is the same
/// string for a host deadline, a rejected adapter result, and an unfinished
/// cleanup. Printed after a sentence that already says the check failed, it
/// reads as a diagnosis and is not one.
const RECONCILED_EXECUTION_ERROR_CODE: &str = "execution_failed";

fn stable_task_reason(task: &EngineRun, fallback: &str) -> String {
    task.error_code
        .as_deref()
        .filter(|code| *code != RECONCILED_EXECUTION_ERROR_CODE)
        .map(|code| format!("{fallback} Diagnostic code: {code}."))
        .unwrap_or_else(|| fallback.into())
}

fn localhost_observation_text(outcome: &LocalhostTcpOutcome) -> &'static str {
    match outcome {
        LocalhostTcpOutcome::Reachable => "The port accepted the bounded TCP connection.",
        LocalhostTcpOutcome::Closed => "The port refused the bounded TCP connection.",
        LocalhostTcpOutcome::TimedOut => {
            "The bounded TCP connection attempt timed out; reachability was not established."
        }
    }
}

fn selected_run_last_durable_update(case: &AssessmentCase, run: &ScanRun) -> DateTime<Utc> {
    let mut times = vec![run.created_at];
    times.extend(run.completed_at);
    for task in &run.engine_runs {
        times.extend(task.started_at);
        times.extend(task.finished_at);
        if let Some(observation) = task.localhost_tcp_observation.as_ref() {
            times.push(observation.observed_at);
        }
    }
    times.extend(
        case.finding_observations
            .iter()
            .filter(|observation| observation.run_id == run.id)
            .map(|observation| observation.observed_at),
    );
    times.extend(
        case.raw_artifacts
            .iter()
            .filter(|artifact| artifact.run_id == run.id)
            .map(|artifact| artifact.created_at),
    );
    times.into_iter().max().unwrap_or(run.created_at)
}

fn task_result_kind(task: &EngineRun) -> CheckResultKind {
    match task.task_kind {
        EngineTaskKind::BuiltInLocalhostTcp { .. } => CheckResultKind::Connectivity,
        EngineTaskKind::CatalogEngine
            if matches!(
                task.engine_id.to_ascii_lowercase().as_str(),
                "cloudquery" | "steampipe" | "syft" | "naabu" | "httpx" | "agentic-radar"
            ) =>
        {
            CheckResultKind::Inventory
        }
        EngineTaskKind::CatalogEngine => CheckResultKind::SecurityCheck,
    }
}

fn legacy_check_result_kind(check_id: &str) -> CheckResultKind {
    let normalized = check_id.trim().to_ascii_lowercase();
    if normalized.starts_with("native localhost tcp check on ") {
        return CheckResultKind::Connectivity;
    }
    if [
        "cloudquery",
        "steampipe",
        "syft",
        "naabu",
        "httpx",
        "agentic-radar",
    ]
    .iter()
    .any(|engine| normalized == *engine || normalized.starts_with(&format!("{engine}-")))
    {
        return CheckResultKind::Inventory;
    }
    CheckResultKind::SecurityCheck
}

pub(crate) fn run_is_non_security_only(run: &ScanRun) -> bool {
    !run.engine_runs.is_empty()
        && run
            .engine_runs
            .iter()
            .all(|task| task_result_kind(task) != CheckResultKind::SecurityCheck)
}

fn non_security_only_explanation(run: &ScanRun) -> String {
    let has_inventory = run
        .engine_runs
        .iter()
        .any(|task| task_result_kind(task) == CheckResultKind::Inventory);
    let has_connectivity = run
        .engine_runs
        .iter()
        .any(|task| task_result_kind(task) == CheckResultKind::Connectivity);
    let work = match (has_inventory, has_connectivity) {
        (true, true) => "inventory and connectivity",
        (true, false) => "inventory",
        (false, true) => "connectivity",
        (false, false) => "non-security",
    };
    format!(
        "This run contained only {work} work. No vulnerability, configuration, code, or secret security check completed. Inventory and connectivity observations are not a no-problems security result."
    )
}

fn state_explanation(summary: BeginnerReportSummary) -> &'static str {
    match summary {
        BeginnerReportSummary::Complete => {
            "Every requested dimension retained by this run has a final outcome."
        }
        BeginnerReportSummary::NoChecksCompleted => {
            "The scan ended before any security check completed. Open the coverage gaps and retry."
        }
        BeginnerReportSummary::Partial => {
            "The scan completed with one or more coverage gaps. Completed sibling checks are included."
        }
    }
}

fn is_closed_localhost_check(check: &ActualCheck) -> bool {
    check
        .tested_dimensions
        .iter()
        .any(|dimension| dimension.observation == "The port refused the bounded TCP connection.")
}

fn gap_rank(kind: CoverageGapKind) -> u8 {
    match kind {
        CoverageGapKind::Failed => 0,
        CoverageGapKind::TimedOut => 1,
        CoverageGapKind::Cancelled => 2,
        CoverageGapKind::NotTested => 3,
        CoverageGapKind::Truncated => 4,
        CoverageGapKind::Unavailable => 5,
        CoverageGapKind::Excluded => 6,
        // Above Excluded: this one is actionable and the reader is the only
        // person who can resolve it.
        CoverageGapKind::Unattributed => 3,
        CoverageGapKind::ManualReview => 3,
    }
}

pub(crate) fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Informational => 0,
        Severity::Unknown => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

fn confidence_rank(confidence: &Confidence) -> u8 {
    match confidence {
        Confidence::Unknown => 0,
        Confidence::Low => 1,
        Confidence::Medium => 2,
        Confidence::High => 3,
        Confidence::Confirmed => 4,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #[test]
    fn legacy_coverage_gap_without_class_defaults_to_conservative_coverage_loss() {
        let legacy = serde_json::json!({
            "kind": "unavailable",
            "task_id": null,
            "target_asset_ids": [],
            "dimension": "legacy saved limitation",
            "reason": "The old record did not classify this row.",
            "next_action_code": "preserve_visible_limitation",
            "next_action": "Keep the limitation visible."
        });

        let gap: super::CoverageGap = serde_json::from_value(legacy).unwrap();

        assert_eq!(gap.class, super::CoverageGapClass::CoverageLoss);
    }

    #[test]
    fn every_coverage_gap_kind_has_an_exhaustive_default_classification() {
        for kind in [
            super::CoverageGapKind::NotTested,
            super::CoverageGapKind::Failed,
            super::CoverageGapKind::TimedOut,
            super::CoverageGapKind::Cancelled,
            super::CoverageGapKind::Excluded,
            super::CoverageGapKind::Truncated,
            super::CoverageGapKind::Unavailable,
            super::CoverageGapKind::Unattributed,
            super::CoverageGapKind::ManualReview,
        ] {
            assert_eq!(kind.default_class(), super::CoverageGapClass::CoverageLoss);
        }
    }

    #[test]
    fn a_finding_step_names_its_ratings_in_words() {
        assert_eq!(
            super::finding_step_reason(
                "Exposed key",
                &super::Severity::Unknown,
                &super::Confidence::Confirmed,
                None,
                &[],
            ),
            "Exposed key — Unknown severity, Confirmed confidence"
        );
        assert_eq!(
            super::finding_step_reason(
                "Exposed key",
                &super::Severity::Informational,
                &super::Confidence::Low,
                None,
                &[],
            ),
            "Exposed key — Informational severity, Low confidence"
        );
        assert_eq!(
            super::finding_step_reason(
                "Policy failure",
                &super::Severity::High,
                &super::Confidence::High,
                Some(crate::domain::ConfidenceBasisCode::DeterministicPolicyEvaluation),
                &[],
            ),
            "Policy failure — High severity, High confidence — this product's rating from a deterministic policy or configuration evaluation"
        );
        assert_eq!(
            super::finding_step_reason(
                "Greenbone result",
                &super::Severity::High,
                &super::Confidence::Unknown,
                Some(crate::domain::ConfidenceBasisCode::MissingDetectionQualityScore),
                &[],
            ),
            "Greenbone result — High severity, Unknown confidence — scanner did not report detection quality"
        );
        assert!(
            super::confidence_rank(&super::Confidence::Unknown)
                < super::confidence_rank(&super::Confidence::Low)
        );
    }

    use super::*;
    use crate::domain::{
        AssessmentIntent, Asset, AssetIdentifier,
        BUILT_IN_LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE,
        BUILT_IN_LOCALHOST_TCP_AUTHORIZATION_REFERENCE, BUILT_IN_LOCALHOST_TCP_ENGINE_ID,
        CaseStatus, ControlReference, CoverageEntry, CoverageStatus, DataClass,
        EngineKnowledgeInput, EngineRun, Evidence, EvidenceKind, FindingGroup, FindingStatus,
        GatewayRefusalRecord, KnowledgeInputKind, KnowledgePinState, ManualReviewControl,
        NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION, NAABU_ATTEMPT_RESULT_SCHEMA_VERSION,
        NaabuAttemptRequest, NaabuAttemptResult, OrganizationProfile, RawArtifact,
        ReportAssetSnapshot, ScopeGrant, SecurityTemplateExecution, SourceKind, new_id,
    };
    use crate::execution_coverage::{
        ExecutionCoverageSummary, FinalArtifactIdentity, IncompleteReason,
        LAUNCHER_V2_JOURNAL_SCHEMA_VERSION, ValidatedArtifactBinding, ValidatedExecutionCoverage,
        WorkUnitAttempt, WorkUnitCoverage,
    };
    use crate::external_scope::{
        CanonicalTarget, ExternalActivity, ExternalScopeGrant, RatePolicy, ResolutionSnapshot,
        ResolvedExternalPlan, TemplatePolicy, TransportProtocol,
    };
    use crate::naabu_work_plan::{NaabuWorkPlanIdentity, build_naabu_work_plan};
    use chrono::{Duration, TimeZone};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn unknown_severity_sorts_after_known_low_but_before_informational() {
        assert!(severity_rank(&Severity::Low) > severity_rank(&Severity::Unknown));
        assert!(severity_rank(&Severity::Unknown) > severity_rank(&Severity::Informational));
    }

    fn instant(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_788_000_000 + seconds, 0).unwrap()
    }

    fn empty_case() -> AssessmentCase {
        let mut case = AssessmentCase::new(
            "Beginner report test".into(),
            OrganizationProfile {
                organization_name: "Home lab".into(),
                employee_range: "1".into(),
                data_classes: vec![DataClass::General],
                notes: None,
            },
        );
        case.id = "case-1".into();
        case.status = CaseStatus::Scanning;
        case.created_at = instant(0);
        case.updated_at = instant(100);
        case
    }

    fn localhost_case(
        outcome: LocalhostTcpOutcome,
        status: EngineRunStatus,
        terminal: bool,
    ) -> AssessmentCase {
        let mut case = empty_case();
        case.assets.push(Asset {
            id: "localhost-asset".into(),
            kind: AssetKind::WebService,
            name: "127.0.0.1:9001".into(),
            provider: None,
            region: None,
            identifiers: vec![AssetIdentifier {
                namespace: BUILT_IN_LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE.into(),
                value: "127.0.0.1:9001".into(),
            }],
            discovered_from: vec!["source-1".into()],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(false),
            contains_sensitive_data: Some(false),
            metadata: BTreeMap::new(),
        });
        let run_id = "run-1".to_string();
        case.scan_runs.push(ScanRun {
            id: run_id.clone(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: instant(10),
            completed_at: terminal.then(|| instant(20)),
            request_outcome: None,
            report_asset_snapshots: Vec::new(),
            knowledge_cutoff: instant(10),
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec!["grant-1".into()],
            scope_grant_snapshots: vec![ScopeGrant {
                id: "grant-1".into(),
                asset_id: "localhost-asset".into(),
                permission: crate::domain::ScanPermission::LowImpactExternalConnection,
                confirmed_by: "local user".into(),
                confirmed_at: instant(9),
                expires_at: None,
                authorization_reference: Some(
                    BUILT_IN_LOCALHOST_TCP_AUTHORIZATION_REFERENCE.into(),
                ),
                notes: None,
                external_scope: None,
            }],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![EngineRun {
                unattributed: Vec::new(),
                unevaluated_targets: Vec::new(),
                security_template_executions: Vec::new(),
                manual_review_controls: Vec::new(),
                id: "task-1".into(),
                scan_run_id: run_id,
                engine_id: BUILT_IN_LOCALHOST_TCP_ENGINE_ID.into(),
                task_kind: EngineTaskKind::built_in_localhost_tcp(9_001),
                localhost_tcp_observation: Some(LocalhostTcpObservation {
                    outcome,
                    observed_at: instant(16),
                }),
                asset_ids: vec!["localhost-asset".into()],
                status,
                progress_percent: 100,
                phase: "completed".into(),
                started_at: Some(instant(15)),
                finished_at: terminal.then(|| instant(16)),
                resume_token: None,
                last_execution_report_sha256: None,
                engine_version: None,
                reported_version: None,
                image_digest: None,
                rule_version: None,
                adapter_version: "native".into(),
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
                cleanup_removed: Some(true),
                cleanup_detail: Some("No disposable runtime was created.".into()),
                gateway_refusals: None,
                warnings: vec![],
                raw_artifact_ids: vec![],
                error_code: None,
                error_message: None,
            }],
        });
        case
    }

    pub(crate) fn aws_grouping_case() -> AssessmentCase {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        let asset = &mut case.assets[0];
        asset.kind = AssetKind::CloudAccount;
        asset.name = "Example AWS account".into();
        asset.provider = Some("aws".into());
        asset.identifiers = vec![AssetIdentifier {
            namespace: "aws_account_id".into(),
            value: "123456789012".into(),
        }];
        case.scan_runs[0].report_asset_snapshots = vec![ReportAssetSnapshot {
            asset: asset.clone(),
            disposition: crate::domain::ReportAssetDisposition::RequestedForScan,
        }];
        case.scan_runs[0].engine_runs = ["prowler", "scoutsuite", "cloudsplaining"]
            .into_iter()
            .map(|engine| {
                let mut task = catalog_task(engine, EngineRunStatus::Completed);
                task.engine_id = engine.into();
                task.asset_ids = vec!["localhost-asset".into()];
                task
            })
            .collect();
        case
    }

    fn catalog_task(id: &str, status: EngineRunStatus) -> EngineRun {
        EngineRun {
            unattributed: Vec::new(),
            unevaluated_targets: Vec::new(),
            security_template_executions: Vec::new(),
            manual_review_controls: Vec::new(),
            id: id.into(),
            scan_run_id: "run-1".into(),
            engine_id: format!("engine-{id}"),
            task_kind: EngineTaskKind::CatalogEngine,
            localhost_tcp_observation: None,
            asset_ids: vec!["asset-1".into()],
            status,
            progress_percent: 25,
            phase: "test".into(),
            started_at: Some(instant(12)),
            finished_at: Some(instant(14)),
            resume_token: None,
            last_execution_report_sha256: None,
            engine_version: Some("1.0.0".into()),
            reported_version: None,
            image_digest: Some("sha256:test".into()),
            rule_version: Some("rules-1".into()),
            adapter_version: "adapter-1".into(),
            manifest_schema_version: Some("2.0.0".into()),
            source_revision: Some("revision".into()),
            repository_url: Some("https://example.invalid/engine".into()),
            distribution_mode: Some(DistributionMode::PullPinnedImage),
            image_repository: Some("example.invalid/engine".into()),
            command_sha256: Some("command".into()),
            execution_timeout_seconds: Some(60),
            knowledge_input: None,
            scope_contract_sha256: Some("scope".into()),
            comparison_scope_sha256: None,
            execution_scope_grant_ids: None,
            naabu_work_plan: None,
            naabu_attempt_requests: Vec::new(),
            naabu_attempt_results: Vec::new(),
            mapping_version: None,
            mapping_provenance: None,
            fingerprint_schema_version: Some("finding-v2".into()),
            runtime_provider: Some("managed_local".into()),
            runtime_version: Some("1".into()),
            runtime_security_options: Some("read_only".into()),
            exit_code: Some(1),
            cleanup_removed: Some(true),
            cleanup_detail: Some("done".into()),
            gateway_refusals: None,
            warnings: vec![],
            raw_artifact_ids: vec![],
            error_code: None,
            error_message: Some("untrusted target text must not be exposed".into()),
        }
    }

    fn case_with_catalog_tasks(tasks: Vec<EngineRun>, terminal: bool) -> AssessmentCase {
        let mut case = empty_case();
        case.assets.push(Asset {
            id: "asset-1".into(),
            kind: AssetKind::Repository,
            name: "sample repository".into(),
            provider: None,
            region: None,
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
            created_at: instant(10),
            completed_at: terminal.then(|| instant(20)),
            request_outcome: None,
            report_asset_snapshots: Vec::new(),
            knowledge_cutoff: instant(10),
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec![],
            scope_grant_snapshots: vec![],
            engine_admission_issues: Vec::new(),
            engine_runs: tasks,
        });
        case
    }

    /// Checkpoint JSON `parseCheckpoint` accepts: matching ids, a numeric attempt, a known stage.
    fn progress_resume_token(task: &EngineRun, stage: &str) -> String {
        serde_json::json!({
            "engine_run_id": task.id,
            "engine_id": task.engine_id,
            "attempt": 1,
            "stage": stage,
        })
        .to_string()
    }

    fn task_gap(task: &EngineRun, status: CoverageDimensionStatus) -> CoverageGap {
        let mut gaps = Vec::new();
        append_task_gap(task, status, &mut gaps);
        assert_eq!(gaps.len(), 1, "{status:?}");
        gaps.pop().expect("one task gap")
    }

    /// One check on two assets is two rows under one name. They follow the
    /// order the report lists its targets in; the task ids that used to
    /// decide it appear nowhere in the report.
    #[test]
    fn one_check_on_two_assets_lists_its_rows_in_target_order() {
        let mut first = catalog_task("task-b", EngineRunStatus::Failed);
        first.engine_id = "gitleaks".into();
        let mut second = catalog_task("task-a", EngineRunStatus::Failed);
        second.engine_id = "gitleaks".into();
        second.asset_ids = vec!["asset-2".into()];
        let mut case = case_with_catalog_tasks(vec![first, second], true);
        let mut other = case.assets[0].clone();
        other.id = "asset-2".into();
        other.name = "second repository".into();
        case.assets.push(other);

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let targets = report
            .requested
            .targets
            .iter()
            .map(|target| target.asset_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(targets, ["asset-1", "asset-2"]);
        let rows = report
            .coverage_gaps
            .iter()
            .filter(|gap| gap.dimension == "gitleaks: failed check dimension")
            .map(|gap| gap.target_asset_ids.as_slice())
            .collect::<Vec<_>>();
        assert_eq!(rows, [["asset-1".to_owned()], ["asset-2".to_owned()]]);
    }

    #[test]
    fn bounded_naabu_retry_exhaustion_on_the_task_gap_asks_for_a_new_scan() {
        let mut task = catalog_task("naabu-exhausted", EngineRunStatus::PartiallyCompleted);
        task.engine_id = NAABU_ENGINE_ID.into();
        task.phase = "results_partial".into();
        task.error_code = Some("coverage_incomplete_after_bounded_retries".into());
        task.resume_token = Some(progress_resume_token(&task, "captured_awaiting_adapter"));

        let gap = task_gap(&task, CoverageDimensionStatus::TestedPartial);

        assert_eq!(gap.next_action_code, NextActionCode::StartNewScan);
        assert_eq!(gap.next_action, "Start a new scan for a fresh result.");
        assert_eq!(
            gap.reason,
            "This check did not reach a confirmed complete result. Diagnostic code: coverage_incomplete_after_bounded_retries."
        );
    }

    #[test]
    fn a_failed_check_with_a_resume_checkpoint_still_asks_to_retry() {
        let mut task = catalog_task("failed-resumable", EngineRunStatus::Failed);
        task.error_code = Some(RECONCILED_EXECUTION_ERROR_CODE.into());
        task.phase = "failed".into();
        task.resume_token = Some(progress_resume_token(&task, "failed"));

        let gap = task_gap(&task, CoverageDimensionStatus::Failed);

        assert_eq!(gap.next_action_code, NextActionCode::RetryCheck);
        assert_eq!(gap.next_action, "Retry this check.");
        assert_eq!(
            gap.reason,
            "This check failed, so it cannot be shown as tested."
        );
    }

    #[test]
    fn a_cleanup_identity_phase_asks_for_a_new_scan_even_with_a_resume_checkpoint() {
        let mut task = catalog_task("cleanup-blocked", EngineRunStatus::Failed);
        task.phase = "cleanup_identity_unavailable".into();
        task.error_code = None;
        task.resume_token = Some(progress_resume_token(&task, "failed"));

        let gap = task_gap(&task, CoverageDimensionStatus::Failed);

        assert_eq!(gap.next_action_code, NextActionCode::StartNewScan);
        assert_eq!(gap.next_action, "Start a new scan for a fresh result.");
        assert_eq!(
            gap.reason,
            "This check failed, so it cannot be shown as tested."
        );
    }

    #[test]
    fn a_failed_check_without_a_resume_token_asks_for_a_new_scan() {
        let task = catalog_task("no-token", EngineRunStatus::Failed);
        assert!(task.resume_token.is_none());

        for status in [
            CoverageDimensionStatus::TestedPartial,
            CoverageDimensionStatus::TimedOut,
            CoverageDimensionStatus::Failed,
            CoverageDimensionStatus::Cancelled,
        ] {
            let gap = task_gap(&task, status);
            assert_eq!(
                gap.next_action_code,
                NextActionCode::StartNewScan,
                "{status:?}"
            );
            assert_eq!(
                gap.next_action, "Start a new scan for a fresh result.",
                "{status:?}"
            );
        }
    }

    #[test]
    fn an_unreadable_resume_token_asks_for_a_new_scan() {
        let mut garbage = catalog_task("garbage-token", EngineRunStatus::Failed);
        garbage.resume_token = Some("not-a-checkpoint".into());
        let gap = task_gap(&garbage, CoverageDimensionStatus::Failed);
        assert_eq!(gap.next_action_code, NextActionCode::StartNewScan);
        assert_eq!(gap.next_action, "Start a new scan for a fresh result.");

        let mut foreign = catalog_task("foreign-token", EngineRunStatus::Cancelled);
        foreign.resume_token = Some(progress_resume_token(&foreign, "cancelled"));
        foreign.id = "different-task".into();
        let gap = task_gap(&foreign, CoverageDimensionStatus::Cancelled);
        assert_eq!(gap.next_action_code, NextActionCode::StartNewScan);
        assert_eq!(gap.next_action, "Start a new scan for a fresh result.");
    }

    #[test]
    fn not_executed_manifest_unavailable_keeps_the_automatic_setup_retry() {
        let mut task = catalog_task("manifest", EngineRunStatus::NotExecuted);
        task.error_code = Some("manifest_unavailable".into());

        let report =
            build_beginner_master_report(&case_with_catalog_tasks(vec![task], true), "run-1")
                .unwrap();
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension.contains("not-tested check dimension"))
            .expect("not-tested task gap");

        assert_eq!(gap.next_action_code, NextActionCode::RetryCheck);
        assert_eq!(
            gap.next_action,
            "Retry this check; scan-tool setup is automatic."
        );
    }

    #[test]
    fn timed_out_localhost_without_a_resume_token_still_asks_to_retry() {
        let case = localhost_case(
            LocalhostTcpOutcome::TimedOut,
            EngineRunStatus::PartiallyCompleted,
            true,
        );
        let task = &case.scan_runs[0].engine_runs[0];
        assert!(task.resume_token.is_none());
        assert!(task.localhost_tcp_observation.is_some());

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.kind == CoverageGapKind::TimedOut)
            .expect("timed-out localhost gap");

        assert_eq!(gap.next_action_code, NextActionCode::RetryCheck);
        assert_eq!(gap.next_action, "Retry the timed-out work.");
    }

    fn quoted_strings(source: &str) -> Vec<&str> {
        let mut found = Vec::new();
        let mut rest = source;
        while let Some(open) = rest.find('"') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('"') else {
                break;
            };
            found.push(&after[..close]);
            rest = &after[close + 1..];
        }
        found
    }

    fn quoted_array_before<'a>(source: &'a str, marker: &str) -> Vec<&'a str> {
        let at = source
            .find(marker)
            .unwrap_or_else(|| panic!("Progress adapter is missing {marker}"));
        let start = source[..at]
            .rfind('[')
            .unwrap_or_else(|| panic!("no array opens before {marker}"));
        quoted_strings(&source[start..at])
    }

    fn quoted_strings_between<'a>(
        source: &'a str,
        start_marker: &str,
        end_marker: &str,
    ) -> Vec<&'a str> {
        let start = source
            .find(start_marker)
            .unwrap_or_else(|| panic!("Progress adapter is missing {start_marker}"));
        let from = start + start_marker.len();
        let end_rel = source[from..]
            .find(end_marker)
            .unwrap_or_else(|| panic!("Progress adapter is missing {end_marker}"));
        quoted_strings(&source[from..from + end_rel])
    }

    fn assert_same_strings(label: &str, expected: &[&str], mut actual: Vec<&str>) {
        let mut expected = expected.to_vec();
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected, "{label}");
    }

    #[test]
    fn retry_control_blocklist_matches_the_progress_adapter() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../src/services/nativeAdapter.ts");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("reading {} failed: {error}", path.display()));

        assert_same_strings(
            "error codes",
            &TASK_RETRY_UNAVAILABLE_ERROR_CODES,
            quoted_array_before(&source, "].includes(errorCode ?? \"\")"),
        );
        assert_same_strings(
            "phases",
            &TASK_RETRY_UNAVAILABLE_PHASES,
            quoted_array_before(&source, "].includes(engineRun.phase)"),
        );
        assert_same_strings(
            "checkpoint stages",
            &TASK_RETRY_CHECKPOINT_STAGES,
            quoted_strings_between(&source, "const checkpointStages = new Set([", "]);"),
        );
        assert!(
            source
                .contains("[\"paused\", \"failed\", \"partial\", \"cancelled\"].includes(status)"),
            "Progress resumable statuses drifted"
        );
    }

    #[test]
    fn not_tested_next_action_follows_the_recorded_skip_reason() {
        let mut mcp = catalog_task("mcp", EngineRunStatus::NotExecuted);
        mcp.engine_id = "mcp-armor".into();
        mcp.error_code = Some("mcp_configuration_absent".into());
        let mcp_report =
            build_beginner_master_report(&case_with_catalog_tasks(vec![mcp], true), "run-1")
                .unwrap();
        let mcp_gap = mcp_report
            .coverage_gaps
            .iter()
            .find(|gap| gap.kind == CoverageGapKind::NotTested)
            .expect("mcp not-tested gap");
        assert_eq!(
            mcp_gap.next_action_code,
            NextActionCode::NoActionUnlessScopeChanges
        );
        assert_eq!(
            mcp_gap.next_action,
            "This project has no MCP configuration to check. Continue with the other checks."
        );
        assert!(mcp_gap.reason.contains("mcp_configuration_absent"));
        assert!(!mcp_report.next_steps.iter().any(|step| {
            step.action
                == "This project has no MCP configuration to check. Continue with the other checks."
        }));

        let mut radar = catalog_task("radar", EngineRunStatus::NotExecuted);
        radar.engine_id = "agentic-radar".into();
        radar.error_code = Some("engine_release_unavailable".into());
        let radar_report =
            build_beginner_master_report(&case_with_catalog_tasks(vec![radar], true), "run-1")
                .unwrap();
        let radar_gap = radar_report
            .coverage_gaps
            .iter()
            .find(|gap| gap.kind == CoverageGapKind::NotTested)
            .expect("radar not-tested gap");
        assert_eq!(
            radar_gap.next_action_code,
            NextActionCode::NoActionUnlessScopeChanges
        );
        assert_eq!(
            radar_gap.next_action,
            "This version of the app does not include this check."
        );
        assert!(radar_gap.reason.contains("engine_release_unavailable"));
        assert!(
            !radar_report.next_steps.iter().any(|step| {
                step.action == "This version of the app does not include this check."
            })
        );

        let mut unknown = catalog_task("unknown", EngineRunStatus::NotExecuted);
        unknown.error_code = None;
        let mut gaps = Vec::new();
        append_task_gap(&unknown, CoverageDimensionStatus::NotTested, &mut gaps);
        assert_eq!(
            gaps[0].next_action_code,
            NextActionCode::ReviewScopeAndRetry
        );
        assert_eq!(
            gaps[0].next_action,
            "Review the target and try this check again."
        );
    }

    #[test]
    fn every_planner_skip_reason_has_a_specific_not_tested_next_action() {
        for code in crate::case_service::PLANNER_NOT_EXECUTED_REASON_CODES {
            let mut task = catalog_task(code, EngineRunStatus::NotExecuted);
            task.error_code = Some(code.to_string());
            let (next_code, next_action) = not_tested_next_action(&task);
            assert_ne!(
                (next_code, next_action),
                (
                    NextActionCode::ReviewScopeAndRetry,
                    "Review the target and try this check again."
                ),
                "{code} kept the generic not-tested next action"
            );
        }
    }

    #[test]
    fn every_settled_skip_reason_is_a_planner_reason_that_needs_no_action() {
        for code in crate::case_service::SETTLED_SKIP_REASON_CODES {
            assert!(
                crate::case_service::PLANNER_NOT_EXECUTED_REASON_CODES.contains(code),
                "{code} is missing from PLANNER_NOT_EXECUTED_REASON_CODES"
            );
            let mut task = catalog_task(code, EngineRunStatus::NotExecuted);
            task.error_code = Some(code.to_string());
            let (next_code, _) = not_tested_next_action(&task);
            assert_eq!(
                next_code,
                NextActionCode::NoActionUnlessScopeChanges,
                "{code} did not resolve to NoActionUnlessScopeChanges"
            );
        }
    }

    #[test]
    fn settled_skips_beside_a_completed_check_ask_for_no_action_and_keep_their_gaps() {
        let mut done = catalog_task("done", EngineRunStatus::Completed);
        done.engine_id = "trivy".into();
        done.error_code = None;

        let mut mcp = catalog_task("mcp", EngineRunStatus::NotExecuted);
        mcp.engine_id = "mcp-armor".into();
        mcp.error_code = Some("mcp_configuration_absent".into());

        let mut radar = catalog_task("radar", EngineRunStatus::NotExecuted);
        radar.engine_id = "agentic-radar".into();
        radar.error_code = Some("engine_release_unavailable".into());

        let report = build_beginner_master_report(
            &case_with_catalog_tasks(vec![done, mcp, radar], true),
            "run-1",
        )
        .unwrap();

        assert!(
            report
                .next_steps
                .iter()
                .all(|step| step.code != NextActionCode::NoActionUnlessScopeChanges)
        );
        assert!(report.next_steps.iter().all(|step| {
            step.action
                != "This project has no MCP configuration to check. Continue with the other checks."
                && step.action != "This version of the app does not include this check."
        }));
        assert_eq!(
            report
                .coverage_gaps
                .iter()
                .filter(|gap| gap.kind == CoverageGapKind::NotTested)
                .count(),
            2
        );
    }

    #[test]
    fn reachable_localhost_is_exact_complete_and_never_engine_provenance() {
        let case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Complete);
        assert_eq!(report.state.lifecycle, ReportLifecycle::Final);
        assert_eq!(
            report.requested.stage.value,
            Some(ReportScanStage::ConnectionDiagnostic)
        );
        assert_eq!(
            report.requested.targets[0].label_availability,
            DataAvailability::Recorded
        );
        assert_eq!(
            report.requested.reductions_availability,
            DataAvailability::Recorded
        );
        assert!(report.coverage_gaps.is_empty());
        assert_eq!(report.coverage_counts.tested_complete, 1);
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedComplete
        );
        assert_eq!(
            report.actual.checks[0].tested_dimensions[0].value,
            "127.0.0.1:9001"
        );
        assert!(matches!(
            report.technical_details.tasks[0].execution,
            TechnicalExecution::BuiltInLocalhostTcp {
                timeout_ms: 3_000,
                payload_bytes: 0,
                ..
            }
        ));
        let encoded = serde_json::to_value(&report.technical_details.tasks[0].execution).unwrap();
        assert_eq!(encoded["kind"], "built_in_localhost_tcp");
        assert!(encoded.get("engine_version").is_none());
        assert!(encoded.get("image_digest").is_none());
        assert!(encoded.get("runtime_provider").is_none());
    }

    #[test]
    fn refused_localhost_connection_is_a_completed_observation_not_a_security_verdict() {
        let case = localhost_case(
            LocalhostTcpOutcome::Closed,
            EngineRunStatus::Completed,
            true,
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Complete);
        assert!(
            report.actual.checks[0].tested_dimensions[0]
                .observation
                .contains("refused")
        );
        assert_eq!(
            report.next_steps[0].action,
            "Start the expected service, then run this check again."
        );
        assert!(
            serde_json::to_string(&report)
                .unwrap()
                .contains("not a security pass or failure")
        );
    }

    #[test]
    fn timed_out_localhost_is_partial_with_an_explicit_gap() {
        let case = localhost_case(
            LocalhostTcpOutcome::TimedOut,
            EngineRunStatus::PartiallyCompleted,
            true,
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TimedOut
        );
        assert_eq!(report.coverage_counts.timed_out, 1);
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.kind == CoverageGapKind::TimedOut)
        );

        // A timeout is the one gap this report blames on the network rather
        // than on security, and it names that role deliberately. The name is
        // written here and translated in `finding_narrative`, so changing it on
        // this side alone silently downgrades the Chinese reader to the generic
        // "some security or IT professional" -- the very misdirection naming
        // the role was meant to avoid.
        let expert = report
            .next_steps
            .iter()
            .find(|step| step.code == NextActionCode::RetryCheck)
            .and_then(|step| step.recommended_expert_type.as_deref())
            .expect("the timed-out gap contributed no next step naming an expert");
        assert_eq!(expert, "Network or system administrator");
        assert_eq!(
            crate::finding_narrative::expert_type_zh_hant(expert),
            "網路或系統管理員",
            "the timed-out gap names a role no localized surface can render"
        );
    }

    #[test]
    fn completed_native_state_without_observation_is_no_checks_completed_not_green() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        case.scan_runs[0].engine_runs[0].localhost_tcp_observation = None;
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::NotTested
        );
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.kind == CoverageGapKind::NotTested)
        );
    }

    #[test]
    fn partial_task_counts_both_saved_partial_work_and_remaining_gap() {
        let case = case_with_catalog_tasks(
            vec![catalog_task("partial", EngineRunStatus::PartiallyCompleted)],
            true,
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        assert_eq!(report.coverage_counts.tested_partial, 1);
        assert_eq!(report.coverage_counts.not_tested, 1);
    }

    #[test]
    fn network_master_report_names_the_exact_tested_and_untested_ports() {
        let frozen_at = instant(10);
        let address = "192.168.50.10".parse().expect("fixture address");
        let resolved = ResolvedExternalPlan {
            grant_id: "grant-1".into(),
            case_id: "case-1".into(),
            asset_id: "asset-1".into(),
            target: CanonicalTarget::Address(address),
            resolution: ResolutionSnapshot {
                hostname: None,
                addresses: BTreeSet::from([address]),
                resolved_at: frozen_at,
            },
            ports: BTreeSet::from([80, 443]),
            protocol: TransportProtocol::Tcp,
            activity: ExternalActivity::LowImpactExternal,
            rate_policy: RatePolicy {
                requests_per_second: 25,
                concurrency: 10,
                timeout_seconds: 3,
            },
            template_policy: TemplatePolicy::conservative("not_applicable", Vec::new()),
            frozen_at,
            expires_at: frozen_at + Duration::hours(1),
            allow_sensitive_networks: true,
        };
        let plan = build_naabu_work_plan(
            NaabuWorkPlanIdentity::new("case-1", "run-1", "task-network", frozen_at),
            &[resolved],
            None,
        )
        .expect("exact two-port plan");
        assert_eq!(
            plan.work_units.len(),
            2,
            "fixture requires one unit per port"
        );

        let requested_unit_ids = plan
            .work_units
            .iter()
            .map(|unit| unit.unit_id.clone())
            .collect::<Vec<_>>();
        let selected = requested_unit_ids.iter().cloned().collect::<BTreeSet<_>>();
        let launcher = plan
            .launcher_plan_v3(1, Some(&selected))
            .expect("current compact launcher plan");
        let request = NaabuAttemptRequest {
            schema_version: NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION,
            execution_attempt: 1,
            requested_unit_ids,
            launcher_plan_sha256: hex::encode(Sha256::digest(
                serde_json::to_vec(&launcher).expect("launcher JSON"),
            )),
        };

        let mut tested_complete = 0;
        let mut not_tested = 0;
        let mut work_units = Vec::new();
        let mut bindings = Vec::new();
        for unit in &plan.work_units {
            let grant = &plan.frozen_grants[usize::try_from(unit.grant_index).unwrap()];
            let port = grant.ports[usize::try_from(unit.port_start).unwrap()];
            let (outcome, final_artifact) = if port == 80 {
                tested_complete += 1;
                let identity = FinalArtifactIdentity {
                    engine_run_id: plan.identity.engine_run_id.clone(),
                    unit_id: unit.unit_id.clone(),
                    scope_sha256: unit.scope_sha256.clone(),
                    attempt: 1,
                    relative_path: format!("attempt-1/{}.jsonl", unit.unit_id),
                    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        .into(),
                    byte_length: 0,
                };
                bindings.push(ValidatedArtifactBinding {
                    raw_artifact_id: "raw-port-80".into(),
                    identity: identity.clone(),
                });
                (WorkUnitOutcome::TestedComplete, Some(identity))
            } else {
                not_tested += 1;
                (WorkUnitOutcome::NotTested, None)
            };
            work_units.push(WorkUnitCoverage {
                unit_id: unit.unit_id.clone(),
                scope_sha256: unit.scope_sha256.clone(),
                outcome,
                attempts: vec![WorkUnitAttempt {
                    attempt: 1,
                    outcome,
                    incomplete_reason: None,
                    final_artifact,
                }],
            });
        }
        assert_eq!((tested_complete, not_tested), (1, 1));
        let result = NaabuAttemptResult {
            schema_version: NAABU_ATTEMPT_RESULT_SCHEMA_VERSION,
            execution_attempt: 1,
            journal_raw_artifact_id: "raw-journal-1".into(),
            coverage: ValidatedExecutionCoverage {
                schema_version: LAUNCHER_V2_JOURNAL_SCHEMA_VERSION,
                engine_run_id: plan.identity.engine_run_id.clone(),
                execution_attempt: 1,
                recovered_trailing_record: false,
                validated_artifact_bindings: bindings,
                unreferenced_final_artifacts: Vec::new(),
                work_units,
                summary: ExecutionCoverageSummary {
                    requested: 2,
                    tested_complete: 1,
                    tested_partial: 0,
                    failed: 0,
                    timed_out: 0,
                    cancelled: 0,
                    not_tested: 1,
                    partial: true,
                    has_usable_results: true,
                },
            },
            normalization_complete: true,
        };

        let mut task = catalog_task("network", EngineRunStatus::PartiallyCompleted);
        task.id = "task-network".into();
        task.engine_id = NAABU_ENGINE_ID.into();
        task.progress_percent = 50;
        task.error_message = None;
        task.naabu_work_plan = Some(plan);
        task.naabu_attempt_requests = vec![request];
        task.naabu_attempt_results = vec![result];
        let mut case = case_with_catalog_tasks(vec![task], true);
        case.assets[0].kind = AssetKind::IpAddress;
        case.assets[0].name = address.to_string();

        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        let port_80 = report
            .actual
            .network_scopes
            .iter()
            .find(|scope| scope.port_ranges == ["80"])
            .expect("port 80 scope");
        let port_443 = report
            .actual
            .network_scopes
            .iter()
            .find(|scope| scope.port_ranges == ["443"])
            .expect("port 443 scope");
        assert_eq!(port_80.address_ranges, [address.to_string()]);
        assert_eq!(port_80.target, address.to_string());
        assert_eq!(port_80.outcome, WorkUnitOutcome::TestedComplete);
        assert_eq!(port_443.address_ranges, [address.to_string()]);
        assert_eq!(port_443.outcome, WorkUnitOutcome::NotTested);
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        assert_eq!(report.coverage_counts.tested_partial, 1);
        assert_eq!(report.coverage_counts.not_tested, 1);
    }

    /// Every planned unit has completed evidence. `normalization_complete` is
    /// the only switch: false leaves saved artifacts unread.
    fn naabu_case_with_complete_unit_evidence(
        task_id: &str,
        status: EngineRunStatus,
        normalization_complete: bool,
    ) -> AssessmentCase {
        let frozen_at = instant(10);
        let address = "192.168.50.10".parse().expect("fixture address");
        let resolved = ResolvedExternalPlan {
            grant_id: "grant-1".into(),
            case_id: "case-1".into(),
            asset_id: "asset-1".into(),
            target: CanonicalTarget::Address(address),
            resolution: ResolutionSnapshot {
                hostname: None,
                addresses: BTreeSet::from([address]),
                resolved_at: frozen_at,
            },
            ports: BTreeSet::from([80, 443]),
            protocol: TransportProtocol::Tcp,
            activity: ExternalActivity::LowImpactExternal,
            rate_policy: RatePolicy {
                requests_per_second: 25,
                concurrency: 10,
                timeout_seconds: 3,
            },
            template_policy: TemplatePolicy::conservative("not_applicable", Vec::new()),
            frozen_at,
            expires_at: frozen_at + Duration::hours(1),
            allow_sensitive_networks: true,
        };
        let plan = build_naabu_work_plan(
            NaabuWorkPlanIdentity::new("case-1", "run-1", task_id, frozen_at),
            &[resolved],
            None,
        )
        .expect("exact two-port plan");
        assert_eq!(
            plan.work_units.len(),
            2,
            "fixture requires one unit per port"
        );

        let requested_unit_ids = plan
            .work_units
            .iter()
            .map(|unit| unit.unit_id.clone())
            .collect::<Vec<_>>();
        let selected = requested_unit_ids.iter().cloned().collect::<BTreeSet<_>>();
        let launcher = plan
            .launcher_plan_v3(1, Some(&selected))
            .expect("current compact launcher plan");
        let request = NaabuAttemptRequest {
            schema_version: NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION,
            execution_attempt: 1,
            requested_unit_ids,
            launcher_plan_sha256: hex::encode(Sha256::digest(
                serde_json::to_vec(&launcher).expect("launcher JSON"),
            )),
        };

        let mut work_units = Vec::new();
        let mut bindings = Vec::new();
        for (index, unit) in plan.work_units.iter().enumerate() {
            let identity = FinalArtifactIdentity {
                engine_run_id: plan.identity.engine_run_id.clone(),
                unit_id: unit.unit_id.clone(),
                scope_sha256: unit.scope_sha256.clone(),
                attempt: 1,
                relative_path: format!("attempt-1/{}.jsonl", unit.unit_id),
                sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                byte_length: 0,
            };
            bindings.push(ValidatedArtifactBinding {
                raw_artifact_id: format!("raw-complete-{index}"),
                identity: identity.clone(),
            });
            work_units.push(WorkUnitCoverage {
                unit_id: unit.unit_id.clone(),
                scope_sha256: unit.scope_sha256.clone(),
                outcome: WorkUnitOutcome::TestedComplete,
                attempts: vec![WorkUnitAttempt {
                    attempt: 1,
                    outcome: WorkUnitOutcome::TestedComplete,
                    incomplete_reason: None,
                    final_artifact: Some(identity),
                }],
            });
        }
        let requested = plan.work_units.len();
        let result = NaabuAttemptResult {
            schema_version: NAABU_ATTEMPT_RESULT_SCHEMA_VERSION,
            execution_attempt: 1,
            journal_raw_artifact_id: "raw-journal-1".into(),
            coverage: ValidatedExecutionCoverage {
                schema_version: LAUNCHER_V2_JOURNAL_SCHEMA_VERSION,
                engine_run_id: plan.identity.engine_run_id.clone(),
                execution_attempt: 1,
                recovered_trailing_record: false,
                validated_artifact_bindings: bindings,
                unreferenced_final_artifacts: Vec::new(),
                work_units,
                summary: ExecutionCoverageSummary {
                    requested,
                    tested_complete: requested,
                    tested_partial: 0,
                    failed: 0,
                    timed_out: 0,
                    cancelled: 0,
                    not_tested: 0,
                    partial: false,
                    has_usable_results: true,
                },
            },
            normalization_complete,
        };

        let mut task = catalog_task(task_id, status);
        task.engine_id = NAABU_ENGINE_ID.into();
        task.progress_percent = 100;
        task.error_code = None;
        task.error_message = None;
        task.phase = "test".into();
        task.naabu_work_plan = Some(plan);
        task.naabu_attempt_requests = vec![request];
        task.naabu_attempt_results = vec![result];
        let mut case = case_with_catalog_tasks(vec![task], true);
        case.assets[0].kind = AssetKind::IpAddress;
        case.assets[0].name = address.to_string();
        case
    }

    /// One planned unit is `TestedPartial` and the other is complete, so the
    /// report writes the unfinished-work row and no failed, timed-out,
    /// cancelled, or not-tested unit row.
    fn naabu_case_with_one_partial_unit(task_id: &str, status: EngineRunStatus) -> AssessmentCase {
        let mut case = naabu_case_with_complete_unit_evidence(task_id, status, true);
        let task = &mut case.scan_runs[0].engine_runs[0];
        let coverage = &mut task.naabu_attempt_results[0].coverage;
        let unit = &mut coverage.work_units[0];
        unit.outcome = WorkUnitOutcome::TestedPartial;
        let attempt = &mut unit.attempts[0];
        attempt.outcome = WorkUnitOutcome::TestedPartial;
        attempt.incomplete_reason = Some(IncompleteReason::Failed);
        let artifact = attempt
            .final_artifact
            .as_mut()
            .expect("partial evidence has a final artifact");
        artifact.byte_length = 1;
        let path = artifact.relative_path.clone();
        let binding = coverage
            .validated_artifact_bindings
            .iter_mut()
            .find(|binding| binding.identity.relative_path == path)
            .expect("partial evidence binding");
        binding.identity.byte_length = 1;
        let summary = &mut coverage.summary;
        assert!(
            summary.tested_complete >= 1,
            "fixture needs a unit to demote"
        );
        summary.tested_complete -= 1;
        summary.tested_partial = 1;
        summary.partial = true;
        summary.has_usable_results = true;
        case
    }

    fn assert_reported_gap(
        report: &BeginnerMasterReport,
        dimension: &str,
        kind: CoverageGapKind,
        code: NextActionCode,
        reason: &str,
        next_action: &str,
    ) {
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == dimension)
            .unwrap_or_else(|| panic!("report is missing the {dimension} coverage gap"));
        assert_eq!(gap.kind, kind);
        assert_eq!(gap.next_action_code, code);
        assert_eq!(gap.reason, reason);
        assert_eq!(gap.next_action, next_action);
    }

    #[test]
    fn a_naabu_check_with_an_unusable_scan_record_cannot_be_shown_as_complete() {
        let reason = "This check's own record of what it scanned is unusable, so it cannot be shown as complete.";
        let next_action = "Run this check again to get a usable record.";
        let dimension = format!("{NAABU_ENGINE_ID} saved scan-batch coverage");

        // The saved work plan is missing, so this arm never calls the reducer.
        let mut missing_plan = catalog_task("missing-plan", EngineRunStatus::Completed);
        missing_plan.engine_id = NAABU_ENGINE_ID.into();
        missing_plan.naabu_work_plan = None;
        missing_plan.naabu_attempt_requests = vec![NaabuAttemptRequest {
            schema_version: NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION,
            execution_attempt: 1,
            requested_unit_ids: vec!["unit-1".into()],
            launcher_plan_sha256: "unused".into(),
        }];
        let missing_report = build_beginner_master_report(
            &case_with_catalog_tasks(vec![missing_plan], true),
            "run-1",
        )
        .expect("beginner report");
        assert_reported_gap(
            &missing_report,
            &dimension,
            CoverageGapKind::Unavailable,
            NextActionCode::RetryCheck,
            reason,
            next_action,
        );

        // Present plan whose saved attempts do not reduce.
        let mut inconsistent = naabu_case_with_complete_unit_evidence(
            "task-inconsistent",
            EngineRunStatus::Failed,
            true,
        );
        {
            let task = &mut inconsistent.scan_runs[0].engine_runs[0];
            task.naabu_attempt_requests[0].execution_attempt = 2;
            assert!(
                reduce_naabu_attempt_coverage(
                    task.naabu_work_plan.as_ref().expect("saved work plan"),
                    &task.naabu_attempt_requests,
                    &task.naabu_attempt_results,
                )
                .is_err(),
                "attempt history must fail to reduce"
            );
        }
        let inconsistent_report =
            build_beginner_master_report(&inconsistent, "run-1").expect("beginner report");
        assert_reported_gap(
            &inconsistent_report,
            &dimension,
            CoverageGapKind::Unavailable,
            NextActionCode::RetryCheck,
            reason,
            next_action,
        );
    }

    #[test]
    fn a_naabu_check_whose_results_could_not_be_read_says_findings_may_be_missing() {
        let case = naabu_case_with_complete_unit_evidence(
            "task-unreadable",
            EngineRunStatus::Completed,
            false,
        );
        let task = &case.scan_runs[0].engine_runs[0];
        let coverage = reduce_naabu_attempt_coverage(
            task.naabu_work_plan.as_ref().expect("saved work plan"),
            &task.naabu_attempt_requests,
            &task.naabu_attempt_results,
        )
        .expect("saved work-unit history");
        assert!(!coverage.all_validated_final_artifacts_normalized);
        assert!(!coverage.fully_complete);

        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        assert_reported_gap(
            &report,
            &format!("{NAABU_ENGINE_ID} saved result processing"),
            CoverageGapKind::Unavailable,
            NextActionCode::PreserveVisibleLimitation,
            "Some of this check's results could not be read, so findings from it may be missing.",
            "Start a new scan for a fresh result.",
        );
        assert!(report.coverage_gaps.iter().all(|gap| {
            gap.dimension != format!("{NAABU_ENGINE_ID} final-state reconciliation")
        }));
    }

    #[test]
    fn naabu_complete_evidence_that_timed_out_says_the_check_timed_out() {
        let mut case =
            naabu_case_with_complete_unit_evidence("task-timed-out", EngineRunStatus::Failed, true);
        {
            let task = &mut case.scan_runs[0].engine_runs[0];
            task.phase = "timed_out".into();
            task.error_code = Some("execution_timeout".into());
            assert!(stable_timeout_marker(task));
        }
        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        assert_reported_gap(
            &report,
            &format!("{NAABU_ENGINE_ID} final-state reconciliation"),
            CoverageGapKind::TimedOut,
            NextActionCode::RetryCheck,
            "All of this check's planned work produced evidence, but the check timed out before it finished.",
            "Run this check again to confirm the result.",
        );
    }

    #[test]
    fn naabu_complete_evidence_that_failed_says_the_check_ended_in_failure() {
        let mut case =
            naabu_case_with_complete_unit_evidence("task-failed", EngineRunStatus::Failed, true);
        {
            let task = &mut case.scan_runs[0].engine_runs[0];
            task.phase = "failed".into();
            task.error_code = Some("execution_failed".into());
            assert!(!stable_timeout_marker(task));
        }
        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        assert_reported_gap(
            &report,
            &format!("{NAABU_ENGINE_ID} final-state reconciliation"),
            CoverageGapKind::Failed,
            NextActionCode::RetryCheck,
            "All of this check's planned work produced evidence, but the check ended in failure.",
            "Run this check again to confirm the result.",
        );
    }

    #[test]
    fn naabu_complete_evidence_that_was_cancelled_says_the_check_was_cancelled() {
        let mut case = naabu_case_with_complete_unit_evidence(
            "task-cancelled",
            EngineRunStatus::Cancelled,
            true,
        );
        {
            let task = &mut case.scan_runs[0].engine_runs[0];
            task.phase = "cancelled".into();
            assert!(!stable_timeout_marker(task));
        }
        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        assert_reported_gap(
            &report,
            &format!("{NAABU_ENGINE_ID} final-state reconciliation"),
            CoverageGapKind::Cancelled,
            NextActionCode::RetryCheck,
            "All of this check's planned work produced evidence, but the check was cancelled before it finished.",
            "Run this check again to confirm the result.",
        );
    }

    #[test]
    fn naabu_work_finished_without_a_completed_final_state_asks_for_a_retry() {
        let case = naabu_case_with_complete_unit_evidence(
            "task-finished",
            EngineRunStatus::PartiallyCompleted,
            true,
        );
        let task = &case.scan_runs[0].engine_runs[0];
        let coverage = reduce_naabu_attempt_coverage(
            task.naabu_work_plan.as_ref().expect("saved work plan"),
            &task.naabu_attempt_requests,
            &task.naabu_attempt_results,
        )
        .expect("saved work-unit history");
        assert!(coverage.fully_complete);
        assert_eq!(task.status, EngineRunStatus::PartiallyCompleted);
        assert!(!stable_timeout_marker(task));

        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        assert_reported_gap(
            &report,
            &format!("{NAABU_ENGINE_ID} final-state reconciliation"),
            CoverageGapKind::Unavailable,
            NextActionCode::RetryCheck,
            "All of this check's planned work produced evidence, but the check never recorded that it finished.",
            "Run this check again to confirm the result.",
        );
    }

    fn partial_unit_count(case: &AssessmentCase) -> usize {
        let task = &case.scan_runs[0].engine_runs[0];
        reduce_naabu_attempt_coverage(
            task.naabu_work_plan.as_ref().expect("saved work plan"),
            &task.naabu_attempt_requests,
            &task.naabu_attempt_results,
        )
        .expect("saved work-unit history")
        .summary
        .tested_partial
    }

    #[test]
    fn bounded_naabu_retry_exhaustion_asks_for_a_new_scan() {
        let mut case =
            naabu_case_with_one_partial_unit("task-exhausted", EngineRunStatus::PartiallyCompleted);
        {
            let task = &mut case.scan_runs[0].engine_runs[0];
            task.phase = "results_partial".into();
            task.error_code = Some("coverage_incomplete_after_bounded_retries".into());
            let token = progress_resume_token(task, "captured_awaiting_adapter");
            task.resume_token = Some(token);
            assert!(
                !task_retry_control_is_available(task),
                "the bounded-retry code removes Resume even with a checkpoint"
            );
        }
        assert!(
            partial_unit_count(&case) > 0,
            "the unfinished-work row is the one this case writes"
        );

        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        assert_reported_gap(
            &report,
            &format!("{NAABU_ENGINE_ID} partly completed scan batches (1)"),
            CoverageGapKind::NotTested,
            NextActionCode::StartNewScan,
            "Usable results were saved for these batches, but the rest of their planned addresses and ports were not tested.",
            "Start a new scan for a fresh result.",
        );
    }

    #[test]
    fn a_completed_naabu_check_with_unfinished_units_asks_for_a_new_scan() {
        let mut case =
            naabu_case_with_one_partial_unit("task-completed-partial", EngineRunStatus::Completed);
        {
            let task = &mut case.scan_runs[0].engine_runs[0];
            task.phase = "completed".into();
            assert!(task.resume_token.is_none());
            assert_eq!(task.error_code, None);
            assert!(
                !task_retry_control_is_available(task),
                "a completed check has no Resume control"
            );
        }
        assert!(partial_unit_count(&case) > 0);

        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        assert_reported_gap(
            &report,
            &format!("{NAABU_ENGINE_ID} partly completed scan batches (1)"),
            CoverageGapKind::NotTested,
            NextActionCode::StartNewScan,
            "Usable results were saved for these batches, but the rest of their planned addresses and ports were not tested.",
            "Start a new scan for a fresh result.",
        );
    }

    #[test]
    fn a_non_resumable_naabu_check_with_cancelled_units_asks_for_a_new_scan() {
        let mut case = naabu_case_with_complete_unit_evidence(
            "task-cancelled-unit",
            EngineRunStatus::Cancelled,
            true,
        );
        {
            let task = &mut case.scan_runs[0].engine_runs[0];
            task.phase = "cancelled".into();
            assert!(task.resume_token.is_none());
            assert!(!task_retry_control_is_available(task));

            let coverage = &mut task.naabu_attempt_results[0].coverage;
            let unit = &mut coverage.work_units[0];
            unit.outcome = WorkUnitOutcome::Cancelled;
            let attempt = &mut unit.attempts[0];
            attempt.outcome = WorkUnitOutcome::Cancelled;
            let artifact = attempt.final_artifact.take().expect("complete artifact");
            coverage
                .validated_artifact_bindings
                .retain(|binding| binding.identity.relative_path != artifact.relative_path);
            coverage.summary.tested_complete -= 1;
            coverage.summary.cancelled = 1;
            coverage.summary.partial = true;

            let coverage = reduce_naabu_attempt_coverage(
                task.naabu_work_plan.as_ref().expect("saved work plan"),
                &task.naabu_attempt_requests,
                &task.naabu_attempt_results,
            )
            .expect("saved work-unit history");
            assert_eq!(coverage.summary.cancelled, 1);
        }

        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        assert_reported_gap(
            &report,
            &format!("{NAABU_ENGINE_ID} cancelled scan batches (1)"),
            CoverageGapKind::Cancelled,
            NextActionCode::StartNewScan,
            "These planned scan batches were cancelled before completed coverage was recorded.",
            "Start a new scan for a fresh result.",
        );
    }

    #[test]
    fn a_non_resumable_naabu_check_with_failed_units_asks_for_a_new_scan() {
        let mut case = naabu_case_with_complete_unit_evidence(
            "task-failed-unit",
            EngineRunStatus::PartiallyCompleted,
            true,
        );
        {
            let task = &mut case.scan_runs[0].engine_runs[0];
            task.phase = "results_partial".into();
            task.error_code = Some("coverage_incomplete_after_bounded_retries".into());
            task.resume_token = Some(progress_resume_token(task, "captured_awaiting_adapter"));
            assert!(!task_retry_control_is_available(task));

            let coverage = &mut task.naabu_attempt_results[0].coverage;
            let unit = &mut coverage.work_units[0];
            unit.outcome = WorkUnitOutcome::Failed;
            let attempt = &mut unit.attempts[0];
            attempt.outcome = WorkUnitOutcome::Failed;
            let artifact = attempt.final_artifact.take().expect("complete artifact");
            coverage
                .validated_artifact_bindings
                .retain(|binding| binding.identity.relative_path != artifact.relative_path);
            coverage.summary.tested_complete -= 1;
            coverage.summary.failed = 1;
            coverage.summary.partial = true;

            let coverage = reduce_naabu_attempt_coverage(
                task.naabu_work_plan.as_ref().expect("saved work plan"),
                &task.naabu_attempt_requests,
                &task.naabu_attempt_results,
            )
            .expect("saved work-unit history");
            assert_eq!(coverage.summary.failed, 1);
        }

        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        assert_reported_gap(
            &report,
            &format!("{NAABU_ENGINE_ID} failed scan batches (1)"),
            CoverageGapKind::Failed,
            NextActionCode::StartNewScan,
            "These planned scan batches stopped before establishing completed coverage.",
            "Start a new scan for a fresh result.",
        );
    }

    #[test]
    fn a_non_resumable_naabu_check_with_timed_out_units_asks_for_a_new_scan() {
        let mut case = naabu_case_with_complete_unit_evidence(
            "task-timed-out-unit",
            EngineRunStatus::PartiallyCompleted,
            true,
        );
        {
            let task = &mut case.scan_runs[0].engine_runs[0];
            task.phase = "results_partial".into();
            task.error_code = Some("coverage_incomplete_after_bounded_retries".into());
            task.resume_token = Some(progress_resume_token(task, "captured_awaiting_adapter"));
            assert!(!task_retry_control_is_available(task));

            let coverage = &mut task.naabu_attempt_results[0].coverage;
            let unit = &mut coverage.work_units[0];
            unit.outcome = WorkUnitOutcome::TimedOut;
            let attempt = &mut unit.attempts[0];
            attempt.outcome = WorkUnitOutcome::TimedOut;
            let artifact = attempt.final_artifact.take().expect("complete artifact");
            coverage
                .validated_artifact_bindings
                .retain(|binding| binding.identity.relative_path != artifact.relative_path);
            coverage.summary.tested_complete -= 1;
            coverage.summary.timed_out = 1;
            coverage.summary.partial = true;

            let coverage = reduce_naabu_attempt_coverage(
                task.naabu_work_plan.as_ref().expect("saved work plan"),
                &task.naabu_attempt_requests,
                &task.naabu_attempt_results,
            )
            .expect("saved work-unit history");
            assert_eq!(coverage.summary.timed_out, 1);
        }

        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        assert_reported_gap(
            &report,
            &format!("{NAABU_ENGINE_ID} timed-out scan batches (1)"),
            CoverageGapKind::TimedOut,
            NextActionCode::StartNewScan,
            "These planned scan batches reached their bounded time limit before completed coverage was recorded.",
            "Start a new scan for a fresh result.",
        );
    }

    #[test]
    fn a_resumable_naabu_check_still_retries_only_the_unfinished_work() {
        let mut case = naabu_case_with_one_partial_unit("task-resumable", EngineRunStatus::Failed);
        {
            let task = &mut case.scan_runs[0].engine_runs[0];
            task.phase = "failed".into();
            task.error_code = None;
            let token = progress_resume_token(task, "failed");
            task.resume_token = Some(token);
            assert!(
                task_retry_control_is_available(task),
                "Failed with a matching checkpoint and no blocklisted code is resumable"
            );
        }
        assert!(partial_unit_count(&case) > 0);

        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        assert_reported_gap(
            &report,
            &format!("{NAABU_ENGINE_ID} partly completed scan batches (1)"),
            CoverageGapKind::NotTested,
            NextActionCode::RetryCheck,
            "Usable results were saved for these batches, but the rest of their planned addresses and ports were not tested.",
            "Retry only the unfinished work.",
        );
        assert_reported_gap(
            &report,
            &format!("{NAABU_ENGINE_ID} stopped before finishing"),
            CoverageGapKind::Failed,
            NextActionCode::RetryCheck,
            "The check stopped after saving some usable results.",
            "Retry only the unfinished work.",
        );
    }

    #[test]
    fn a_whole_check_rerun_stays_a_retry_when_resume_is_unavailable() {
        let mut case = naabu_case_with_complete_unit_evidence(
            "task-confirm",
            EngineRunStatus::PartiallyCompleted,
            true,
        );
        {
            let task = &mut case.scan_runs[0].engine_runs[0];
            task.phase = "results_partial".into();
            task.error_code = Some("coverage_incomplete_after_bounded_retries".into());
            let token = progress_resume_token(task, "captured_awaiting_adapter");
            task.resume_token = Some(token);
            let coverage = reduce_naabu_attempt_coverage(
                task.naabu_work_plan.as_ref().expect("saved work plan"),
                &task.naabu_attempt_requests,
                &task.naabu_attempt_results,
            )
            .expect("saved work-unit history");
            assert!(coverage.fully_complete);
            assert!(
                !task_retry_control_is_available(task),
                "the bounded-retry code removes Resume"
            );
        }

        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        assert_reported_gap(
            &report,
            &format!("{NAABU_ENGINE_ID} final-state reconciliation"),
            CoverageGapKind::Unavailable,
            NextActionCode::RetryCheck,
            "All of this check's planned work produced evidence, but the check never recorded that it finished.",
            "Run this check again to confirm the result.",
        );
    }

    #[test]
    fn failed_and_cancelled_tasks_are_no_checks_completed_with_separate_gaps() {
        let mut failed = catalog_task("failed", EngineRunStatus::Failed);
        failed.error_code = Some("execution_failed".into());
        let cancelled = catalog_task("cancelled", EngineRunStatus::Cancelled);
        let case = case_with_catalog_tasks(vec![failed, cancelled], true);
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.kind == CoverageGapKind::Failed)
        );
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.kind == CoverageGapKind::Cancelled)
        );
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("untrusted target text"));
    }

    #[test]
    fn a_check_that_cannot_read_the_target_is_not_tested_and_never_retried() {
        let mut unsupported = catalog_task("unsupported-input", EngineRunStatus::Failed);
        unsupported.error_code = Some("local_input_profile_unsupported".into());
        let case = case_with_catalog_tasks(vec![unsupported], true);

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let check = report
            .actual
            .checks
            .iter()
            .find(|check| check.task_id == "unsupported-input")
            .expect("projected check");
        assert_eq!(check.status, CoverageDimensionStatus::NotTested);

        let task_gaps = report
            .coverage_gaps
            .iter()
            .filter(|gap| gap.task_id.as_deref() == Some("unsupported-input"))
            .collect::<Vec<_>>();
        assert_eq!(task_gaps.len(), 1);
        assert_eq!(task_gaps[0].kind, CoverageGapKind::NotTested);
        assert_eq!(
            task_gaps[0].next_action_code,
            NextActionCode::PreserveVisibleLimitation
        );
        assert_eq!(
            task_gaps[0].reason,
            "This check's packaged scanner cannot read this kind of target, so nothing was tested by it."
        );
        assert_eq!(
            task_gaps[0].next_action,
            "Update the app, then retry these checks."
        );
        assert!(!report.coverage_gaps.iter().any(|gap| {
            gap.task_id.as_deref() == Some("unsupported-input")
                && gap.next_action_code == NextActionCode::RetryCheck
        }));
        assert_eq!(report.coverage_counts.not_tested, 1);
        assert_eq!(report.coverage_counts.failed, 0);
    }

    #[test]
    fn a_check_that_cannot_read_the_target_does_not_tell_the_reader_their_actions_are_pointless() {
        let mut unsupported = catalog_task("unsupported-input", EngineRunStatus::Failed);
        unsupported.error_code = Some("local_input_profile_unsupported".into());
        let case = case_with_catalog_tasks(vec![unsupported], true);
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.task_id.as_deref() == Some("unsupported-input"))
            .expect("unsupported-input gap");
        assert_eq!(
            gap.reason,
            "This check's packaged scanner cannot read this kind of target, so nothing was tested by it."
        );
        assert!(!gap.reason.contains("not a setup problem"));
        assert!(!gap.reason.contains("not a failed scan"));
        assert!(!gap.reason.contains("cannot fix it"));
        assert_eq!(gap.next_action, "Update the app, then retry these checks.");
    }

    fn knowledge_dated(knowledge_date: &str, support_until: &str) -> EngineKnowledgeInput {
        EngineKnowledgeInput {
            kind: KnowledgeInputKind::Embedded,
            identifier: "embedded".into(),
            version: None,
            acquisition_source: None,
            pin_state: KnowledgePinState::PinnedOrNotApplicable,
            knowledge_date: Some(knowledge_date.into()),
            support_until: Some(support_until.into()),
        }
    }

    fn gap_mentions_scanner_age(gap: &CoverageGap) -> bool {
        let text = format!("{} {}", gap.dimension, gap.reason).to_ascii_lowercase();
        text.contains("knowledge") || text.contains("support") || text.contains("expir")
    }

    #[test]
    fn a_completed_check_on_old_knowledge_stays_complete_without_an_expiry_gap() {
        // support_until is years before the run. That date is maintenance
        // metadata; it does not open a coverage gap or make the report incomplete.
        let mut old = catalog_task("old-knowledge", EngineRunStatus::Completed);
        old.knowledge_input = Some(knowledge_dated("2023-01-10", "2023-04-10"));
        let report =
            build_beginner_master_report(&case_with_catalog_tasks(vec![old], true), "run-1")
                .unwrap();
        assert!(
            report
                .coverage_gaps
                .iter()
                .all(|gap| !gap_mentions_scanner_age(gap)),
            "scanner age became a coverage gap: {:#?}",
            report
                .coverage_gaps
                .iter()
                .filter(|gap| gap_mentions_scanner_age(gap))
                .collect::<Vec<_>>()
        );
        assert_eq!(report.state.summary, BeginnerReportSummary::Complete);
        assert_eq!(report.coverage_counts.tested_complete, 1);
        assert_eq!(report.coverage_counts.not_tested, 0);
    }

    #[test]
    fn technical_execution_records_the_knowledge_date_from_the_knowledge_input() {
        let mut dated = catalog_task("dated", EngineRunStatus::Completed);
        dated.knowledge_input = Some(knowledge_dated("2023-01-10", "2023-04-10"));
        let report =
            build_beginner_master_report(&case_with_catalog_tasks(vec![dated], true), "run-1")
                .unwrap();
        match &report.technical_details.tasks[0].execution {
            TechnicalExecution::CatalogEngine { knowledge_date, .. } => {
                assert_eq!(knowledge_date.as_deref(), Some("2023-01-10"));
            }
            other => panic!("expected a catalog execution, got {other:?}"),
        }

        let undated = build_beginner_master_report(
            &case_with_catalog_tasks(
                vec![catalog_task("undated", EngineRunStatus::Completed)],
                true,
            ),
            "run-1",
        )
        .unwrap();
        match &undated.technical_details.tasks[0].execution {
            TechnicalExecution::CatalogEngine { knowledge_date, .. } => {
                assert_eq!(knowledge_date, &None);
            }
            other => panic!("expected a catalog execution, got {other:?}"),
        }
    }

    #[test]
    fn a_report_saved_before_knowledge_date_still_deserializes() {
        let mut dated = catalog_task("dated", EngineRunStatus::Completed);
        dated.knowledge_input = Some(knowledge_dated("2023-01-10", "2023-04-10"));
        let report =
            build_beginner_master_report(&case_with_catalog_tasks(vec![dated], true), "run-1")
                .unwrap();
        let mut value = serde_json::to_value(&report).unwrap();
        let execution = value["technical_details"]["tasks"][0]["execution"]
            .as_object_mut()
            .expect("catalog execution object");
        assert_eq!(execution["knowledge_date"], "2023-01-10");
        execution.remove("knowledge_date");
        let restored: BeginnerMasterReport = serde_json::from_value(value).unwrap();
        match &restored.technical_details.tasks[0].execution {
            TechnicalExecution::CatalogEngine { knowledge_date, .. } => {
                assert_eq!(knowledge_date, &None);
            }
            other => panic!("expected a catalog execution, got {other:?}"),
        }
    }

    #[test]
    fn scanner_version_label_pairs_a_source_commit_with_the_reported_release() {
        const COMMIT: &str = "3ab759fef4bb5935d4fe9ac68b503d05346b8364";
        let source = format!("source@{COMMIT}");
        let short = super::ScannerVersionForm::Short;
        let exact = super::ScannerVersionForm::Exact;
        let label = |engine: &str, reported: Option<&str>, form, zh_hant| {
            super::scanner_version_label(engine, reported, form, zh_hant)
        };

        assert_eq!(
            label(&source, Some("3.97.0"), short, false),
            "3.97.0 (source 3ab759f)"
        );
        assert_eq!(
            label(&source, Some(" 3.97.0 "), short, true),
            "3.97.0（source 3ab759f）"
        );
        assert_eq!(label(&source, None, short, false), "source 3ab759f");
        assert_eq!(label(&source, Some("  "), short, true), "source 3ab759f");
        assert_eq!(
            label(&source, Some("3.97.0"), exact, false),
            format!("3.97.0 (source@{COMMIT})")
        );
        assert_eq!(
            label(&source, Some("3.97.0"), exact, true),
            format!("3.97.0（source@{COMMIT}）")
        );
        assert_eq!(label(&source, None, exact, false), source);
        assert_eq!(label(&source, None, exact, true), source);
        assert_eq!(
            label(&format!("  {source}  "), Some("3.97.0"), short, false),
            "3.97.0 (source 3ab759f)"
        );

        assert_eq!(label("1.6.10", Some("9.9.9"), short, false), "1.6.10");
        assert_eq!(label("1.6.10", Some("9.9.9"), exact, true), "1.6.10");
        assert_eq!(
            label("source@xyz", Some("3.97.0"), short, false),
            "source@xyz"
        );
        assert_eq!(
            label("source@xyz", Some("3.97.0"), exact, true),
            "source@xyz"
        );
        assert_eq!(
            label("source@3AB759F", Some("3.97.0"), short, false),
            "source@3AB759F"
        );
        assert_eq!(
            label("source@abc123", Some("1.0.0"), exact, false),
            "source@abc123"
        );
        assert_eq!(
            label("source@3ab759f", Some("3.97.0"), short, false),
            "3.97.0 (source 3ab759f)"
        );
    }

    #[test]
    fn technical_execution_carries_the_reported_version_from_the_task() {
        let mut task = catalog_task("trufflehog", EngineRunStatus::Completed);
        task.engine_version = Some("source@3ab759fef4bb5935d4fe9ac68b503d05346b8364".into());
        task.reported_version = Some("3.97.0".into());
        let report =
            build_beginner_master_report(&case_with_catalog_tasks(vec![task], true), "run-1")
                .unwrap();
        match &report.technical_details.tasks[0].execution {
            TechnicalExecution::CatalogEngine {
                engine_version,
                reported_version,
                ..
            } => {
                assert_eq!(
                    engine_version.as_deref(),
                    Some("source@3ab759fef4bb5935d4fe9ac68b503d05346b8364")
                );
                assert_eq!(reported_version.as_deref(), Some("3.97.0"));
            }
            other => panic!("expected a catalog execution, got {other:?}"),
        }

        let plain = build_beginner_master_report(
            &case_with_catalog_tasks(
                vec![catalog_task("plain", EngineRunStatus::Completed)],
                true,
            ),
            "run-1",
        )
        .unwrap();
        match &plain.technical_details.tasks[0].execution {
            TechnicalExecution::CatalogEngine {
                reported_version, ..
            } => assert_eq!(reported_version, &None),
            other => panic!("expected a catalog execution, got {other:?}"),
        }
    }

    #[test]
    fn catalog_engine_execution_without_reported_version_deserializes_to_none() {
        let report = build_beginner_master_report(
            &case_with_catalog_tasks(
                vec![catalog_task("dated", EngineRunStatus::Completed)],
                true,
            ),
            "run-1",
        )
        .unwrap();
        let mut value = serde_json::to_value(&report).unwrap();
        let execution = value["technical_details"]["tasks"][0]["execution"]
            .as_object_mut()
            .expect("catalog execution object");
        assert_eq!(execution["kind"], "catalog_engine");
        assert!(execution.get("reported_version").is_some());
        execution.remove("reported_version");
        let restored: BeginnerMasterReport = serde_json::from_value(value).unwrap();
        match &restored.technical_details.tasks[0].execution {
            TechnicalExecution::CatalogEngine {
                reported_version, ..
            } => assert_eq!(reported_version, &None),
            other => panic!("expected a catalog execution, got {other:?}"),
        }
    }

    #[test]
    fn the_reconciled_error_code_stays_out_of_the_reason_and_a_real_one_stays_in() {
        // Every recorded execution error reconciles to one constant, so
        // printing it after "This check failed" is a diagnosis-shaped
        // sentence that says only what the sentence before it already said.
        // The constant is still in the technical record either way.
        let mut generic = catalog_task("generic", EngineRunStatus::Failed);
        generic.error_code = Some(RECONCILED_EXECUTION_ERROR_CODE.into());
        let generic_report =
            build_beginner_master_report(&case_with_catalog_tasks(vec![generic], true), "run-1")
                .unwrap();
        let generic_gap = generic_report
            .coverage_gaps
            .iter()
            .find(|gap| gap.kind == CoverageGapKind::Failed)
            .expect("failed gap");
        assert_eq!(
            generic_gap.reason,
            "This check failed, so it cannot be shown as tested."
        );
        assert!(
            generic_report
                .technical_details
                .tasks
                .iter()
                .any(|task| task.error_code.as_deref() == Some(RECONCILED_EXECUTION_ERROR_CODE)),
            "the code stays available as technical detail"
        );

        let mut named = catalog_task("named", EngineRunStatus::Failed);
        named.error_code = Some("image_pull_denied".into());
        let named_report =
            build_beginner_master_report(&case_with_catalog_tasks(vec![named], true), "run-1")
                .unwrap();
        assert_eq!(
            named_report
                .coverage_gaps
                .iter()
                .find(|gap| gap.kind == CoverageGapKind::Failed)
                .expect("failed gap")
                .reason,
            "This check failed, so it cannot be shown as tested. Diagnostic code: image_pull_denied."
        );
    }

    #[test]
    fn the_host_deadline_is_a_timed_out_check_not_a_failed_one() {
        // A host-deadline timeout ends the task as a failure and reconciles
        // its error to the same generic code as every other error, so the two
        // stable markers never saw it. Classifying it as timed out is what
        // asks the reader to retry the timed-out work.
        let mut timed_out = catalog_task("timed-out", EngineRunStatus::Failed);
        timed_out.error_code = Some(RECONCILED_EXECUTION_ERROR_CODE.into());
        timed_out.error_message = Some(format!(
            "{}; container cleanup completed",
            crate::container_runtime::CONTAINER_EXECUTION_TIMEOUT_ERROR
        ));
        // A recorded host-deadline failure keeps the checkpoint Progress uses for Resume.
        timed_out.resume_token = Some(progress_resume_token(&timed_out, "failed"));
        let report =
            build_beginner_master_report(&case_with_catalog_tasks(vec![timed_out], true), "run-1")
                .unwrap();

        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TimedOut
        );
        assert_eq!(report.coverage_counts.timed_out, 1);
        assert_eq!(report.coverage_counts.failed, 0);
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.kind == CoverageGapKind::TimedOut)
            .expect("timed-out gap");
        assert_eq!(
            gap.reason,
            "The bounded check reached its time limit, so it cannot be treated as tested complete."
        );
        assert!(
            report.next_steps.iter().any(|step| {
                step.action == "Retry the timed-out work."
                    && step.code == NextActionCode::RetryCheck
            }),
            "a timed-out check retries the timed-out work"
        );
        // Not a pass, either way it is classified.
        assert_eq!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );

        // An ordinary failure keeps its own classification.
        let mut failed = catalog_task("failed", EngineRunStatus::Failed);
        failed.error_code = Some(RECONCILED_EXECUTION_ERROR_CODE.into());
        failed.error_message = Some("adapter rejected the captured result".into());
        let failed_report =
            build_beginner_master_report(&case_with_catalog_tasks(vec![failed], true), "run-1")
                .unwrap();
        assert_eq!(
            failed_report.actual.checks[0].status,
            CoverageDimensionStatus::Failed
        );
        assert_eq!(failed_report.coverage_counts.timed_out, 0);
    }

    #[test]
    fn valid_terminal_no_check_outcome_is_not_failure_or_success() {
        let mut case = empty_case();
        case.assets.push(Asset {
            id: "asset-1".into(),
            kind: AssetKind::Domain,
            name: "example.invalid".into(),
            provider: None,
            region: None,
            identifiers: vec![],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(true),
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        });
        case.scan_runs.push(ScanRun {
            id: "run-1".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: instant(10),
            completed_at: Some(instant(11)),
            request_outcome: Some(
                ScanRequestOutcome::no_checks_completed(
                    ScanRequestOutcomeCode::NoApplicableChecks,
                    vec!["asset-1".into()],
                    vec!["missing-check".into()],
                    "No available check supports the requested target.",
                )
                .unwrap(),
            ),
            report_asset_snapshots: Vec::new(),
            knowledge_cutoff: instant(10),
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec![],
            scope_grant_snapshots: vec![],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![],
        });

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );
        assert_eq!(
            report.requested.request_outcome_code,
            Some(ScanRequestOutcomeCode::NoApplicableChecks)
        );
        assert_eq!(report.state.lifecycle, ReportLifecycle::Final);
        assert!(report.actual.checks.is_empty());
        assert_eq!(report.requested.targets[0].asset_id, "asset-1");
        assert_eq!(report.requested.requested_check_ids, vec!["missing-check"]);
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.kind == CoverageGapKind::NotTested)
        );
    }

    #[test]
    fn terminal_no_checks_stage_is_unavailable_only_when_naabu_was_requested() {
        let mut case = empty_case();
        case.assets.push(Asset {
            id: "asset-1".into(),
            kind: AssetKind::Domain,
            name: "example.invalid".into(),
            provider: None,
            region: None,
            identifiers: vec![],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(true),
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        });
        case.scan_runs.push(ScanRun {
            id: "run-1".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: instant(10),
            completed_at: Some(instant(11)),
            request_outcome: Some(
                ScanRequestOutcome::no_checks_completed(
                    ScanRequestOutcomeCode::NoApplicableChecks,
                    vec!["asset-1".into()],
                    vec![NAABU_ENGINE_ID.into()],
                    "No available check supports the requested target.",
                )
                .unwrap(),
            ),
            report_asset_snapshots: Vec::new(),
            knowledge_cutoff: instant(10),
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec![],
            scope_grant_snapshots: vec![],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![],
        });

        // The terminal request named Naabu, so a network-discovery stage was
        // sought and never produced: the report must still say so.
        let naabu_report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(naabu_report.requested.stage.value, None);
        assert_eq!(
            naabu_report.requested.stage.availability,
            DataAvailability::Unavailable
        );
        assert!(
            naabu_report
                .requested
                .unavailable_dimensions
                .iter()
                .any(|dimension| dimension.dimension == "requested scan stage"),
            "a terminal run whose request named Naabu must keep the stage note"
        );
        assert!(
            naabu_report
                .coverage_gaps
                .iter()
                .any(|gap| gap.dimension == "requested scan stage")
        );

        // The same terminal shape, but the request never named Naabu: there
        // was never a network-discovery stage to fail to record.
        case.scan_runs[0].request_outcome = Some(
            ScanRequestOutcome::no_checks_completed(
                ScanRequestOutcomeCode::NoApplicableChecks,
                vec!["asset-1".into()],
                vec!["missing-check".into()],
                "No available check supports the requested target.",
            )
            .unwrap(),
        );
        let non_naabu_report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(non_naabu_report.requested.stage.value, None);
        assert_eq!(
            non_naabu_report.requested.stage.availability,
            DataAvailability::NotApplicable
        );
        assert!(
            !non_naabu_report
                .requested
                .unavailable_dimensions
                .iter()
                .any(|dimension| dimension.dimension == "requested scan stage"),
            "the same request without Naabu must not carry the stage note"
        );
        assert!(
            !non_naabu_report
                .coverage_gaps
                .iter()
                .any(|gap| gap.dimension == "requested scan stage")
        );
    }

    #[test]
    fn completed_non_naabu_catalog_run_has_no_applicable_network_stage() {
        let task = catalog_task("gitleaks-like", EngineRunStatus::Completed);
        let case = case_with_catalog_tasks(vec![task], true);

        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.requested.stage.value, None);
        assert_eq!(
            report.requested.stage.availability,
            DataAvailability::NotApplicable
        );
        assert_eq!(
            report.requested.reductions_availability,
            DataAvailability::NotApplicable
        );
        for dimension in [
            "requested scan stage",
            "automatic scope reductions or truncations",
        ] {
            assert!(
                !report
                    .requested
                    .unavailable_dimensions
                    .iter()
                    .any(|entry| entry.dimension == dimension),
                "{dimension} must not be an unavailable dimension for a non-network run"
            );
            assert!(
                !report
                    .coverage_gaps
                    .iter()
                    .any(|gap| gap.dimension == dimension),
                "{dimension} must not be a coverage gap for a non-network run"
            );
        }
    }

    #[test]
    fn active_run_has_no_beginner_report() {
        let mut task = catalog_task("active", EngineRunStatus::Running);
        task.finished_at = None;
        task.started_at = Some(instant(30));
        let case = case_with_catalog_tasks(vec![task], false);
        assert_eq!(
            build_beginner_master_report(&case, "run-1").unwrap_err(),
            BeginnerReportError::RunInProgress {
                run_id: "run-1".into()
            }
        );
    }

    #[test]
    fn frozen_web_origins_keep_same_host_services_distinct_in_terminal_report() {
        let mut case = empty_case();
        case.assets = vec![
            Asset {
                id: "website-asset".into(),
                kind: AssetKind::Domain,
                name: "mutable website label".into(),
                provider: None,
                region: None,
                identifiers: vec![],
                discovered_from: vec![],
                candidate: false,
                owner_confirmed: true,
                internet_exposed: Some(true),
                contains_sensitive_data: None,
                metadata: BTreeMap::new(),
            },
            Asset {
                id: "device-asset".into(),
                kind: AssetKind::IpAddress,
                name: "mutable device label".into(),
                provider: None,
                region: None,
                identifiers: vec![],
                discovered_from: vec![],
                candidate: false,
                owner_confirmed: true,
                internet_exposed: Some(false),
                contains_sensitive_data: None,
                metadata: BTreeMap::new(),
            },
        ];

        let case_id = case.id.clone();
        let frozen_grant = |id: &str, asset_id: &str, port: u16| {
            let external = ExternalScopeGrant {
                id: format!("external-{id}"),
                case_id: case_id.clone(),
                asset_id: asset_id.into(),
                target: CanonicalTarget::Hostname("shared.example.test".into()),
                ports: BTreeSet::from([port]),
                protocol: TransportProtocol::Https,
                activity: ExternalActivity::ActiveExternal,
                rate_policy: RatePolicy {
                    requests_per_second: 2,
                    concurrency: 1,
                    timeout_seconds: 15,
                },
                template_policy: TemplatePolicy::conservative(
                    "templates@0123456789abcdef0123456789abcdef01234567",
                    vec!["safe-check".into()],
                ),
                asserted_authority: "Approved exact origin".into(),
                approved_by: "Target owner".into(),
                approved_at: instant(9),
                expires_at: instant(3_609),
                allow_sensitive_networks: false,
            };
            ScopeGrant {
                id: id.into(),
                asset_id: asset_id.into(),
                permission: crate::domain::ScanPermission::ActiveExternalTesting,
                confirmed_by: "Target owner".into(),
                confirmed_at: instant(9),
                expires_at: Some(instant(3_609)),
                authorization_reference: Some("Approved exact origin".into()),
                notes: None,
                external_scope: Some(external),
            }
        };
        let mut website_task = catalog_task("website", EngineRunStatus::Completed);
        website_task.engine_id = "nuclei".into();
        website_task.asset_ids = vec!["website-asset".into()];
        let mut device_task = catalog_task("device", EngineRunStatus::Completed);
        device_task.engine_id = GREENBONE_ENGINE_ID.into();
        device_task.asset_ids = vec!["device-asset".into()];
        case.scan_runs.push(ScanRun {
            id: "run-1".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: instant(10),
            completed_at: None,
            request_outcome: None,
            report_asset_snapshots: Vec::new(),
            knowledge_cutoff: instant(10),
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec!["grant-website".into(), "grant-device".into()],
            scope_grant_snapshots: vec![
                frozen_grant("grant-website", "website-asset", 443),
                frozen_grant("grant-device", "device-asset", 8_443),
            ],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![website_task, device_task],
        });

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.state.lifecycle, ReportLifecycle::Final);
        let target = |asset_id: &str| {
            report
                .requested
                .targets
                .iter()
                .find(|target| target.asset_id == asset_id)
                .expect("frozen requested target")
        };
        assert_eq!(
            target("website-asset").label.as_deref(),
            Some("https://shared.example.test:443")
        );
        assert_eq!(
            target("device-asset").label.as_deref(),
            Some("https://shared.example.test:8443")
        );
        assert_eq!(
            target("website-asset").asset_kind,
            Some(AssetKind::WebService)
        );
        assert_eq!(
            target("device-asset").asset_kind,
            Some(AssetKind::WebService)
        );
        assert_eq!(
            target("website-asset").label_availability,
            DataAvailability::Recorded
        );
        assert_eq!(
            target("device-asset").asset_kind_availability,
            DataAvailability::Recorded
        );

        let reopened: AssessmentCase =
            serde_json::from_slice(&serde_json::to_vec(&case).unwrap()).unwrap();
        assert_eq!(
            build_beginner_master_report(&reopened, "run-1").unwrap(),
            report,
            "reopening must preserve each frozen origin and web-service kind"
        );
        assert_eq!(
            crate::export::beginner_report_for_export(
                &reopened,
                "run-1",
                crate::export::RedactionProfile::None,
            )
            .unwrap(),
            report
        );
    }

    #[test]
    fn stale_completion_time_cannot_turn_an_active_check_into_a_final_report() {
        let mut task = catalog_task("active", EngineRunStatus::Running);
        task.finished_at = None;
        task.started_at = Some(instant(30));
        let case = case_with_catalog_tasks(vec![task], true);
        assert_eq!(
            build_beginner_master_report(&case, "run-1").unwrap_err(),
            BeginnerReportError::RunInProgress {
                run_id: "run-1".into()
            }
        );
    }

    #[test]
    fn terminal_check_states_survive_a_missing_run_completion_event() {
        let case = case_with_catalog_tasks(
            vec![catalog_task("completed", EngineRunStatus::Completed)],
            false,
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Complete);
        assert_eq!(report.state.lifecycle, ReportLifecycle::Final);
    }

    #[test]
    fn completed_checks_with_only_record_notes_report_zero_coverage_gaps_and_keep_explanations() {
        let tasks = (1..=8)
            .map(|number| catalog_task(&format!("completed-{number}"), EngineRunStatus::Completed))
            .collect();
        let case = case_with_catalog_tasks(tasks, true);

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let coverage_loss = report
            .coverage_gaps
            .iter()
            .filter(|gap| gap.class == CoverageGapClass::CoverageLoss)
            .count();
        let record_notes = report
            .coverage_gaps
            .iter()
            .filter(|gap| gap.class == CoverageGapClass::RecordNote)
            .collect::<Vec<_>>();

        assert_eq!(report.coverage_counts.tested_complete, 8);
        assert_eq!(report.coverage_counts.not_tested, 0);
        assert_eq!(report.coverage_counts.unavailable, 0);
        assert_eq!(coverage_loss, 0);
        assert!(!record_notes.is_empty());
        assert!(record_notes.iter().all(|note| !note.reason.is_empty()));
        assert_eq!(report.state.summary, BeginnerReportSummary::Complete);
    }

    #[test]
    fn packaged_scanner_limitation_prevents_a_complete_claim_without_exposing_internals() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        case.scan_runs[0]
            .engine_admission_issues
            .push(crate::domain::EngineAdmissionIssue {
                engine_id: Some("gitleaks".into()),
                code: "engine_contract_invalid".into(),
                detail: "technical fixture detail".into(),
            });
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "additional packaged checks")
            .expect("catalog limitation gap");
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert!(gap.target_asset_ids.is_empty());
        assert!(!gap.reason.contains("gitleaks"));
        assert!(!gap.reason.contains("engine_contract_invalid"));
        assert_eq!(report.coverage_counts.not_tested, 1);
    }

    #[test]
    fn rejected_present_catalog_entry_says_the_checks_could_not_be_loaded() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        case.scan_runs[0]
            .engine_admission_issues
            .push(crate::domain::EngineAdmissionIssue {
                engine_id: Some("gitleaks".into()),
                code: "engine_contract_invalid".into(),
                detail: "technical fixture detail".into(),
            });
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "additional packaged checks")
            .expect("catalog limitation gap");

        assert_eq!(
            gap.reason,
            "Some packaged checks could not be loaded. Additional checks: not tested."
        );
        assert!(!gap.reason.contains("information unavailable"));
        assert_eq!(
            gap.next_action,
            "Update the app, then run these checks again."
        );
        assert!(!gap.next_action.contains("Restore"));
    }

    #[test]
    fn unreadable_packaged_check_list_never_invents_a_check_count() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        case.scan_runs[0]
            .engine_admission_issues
            .push(crate::domain::EngineAdmissionIssue {
                engine_id: None,
                code: "catalog_container_invalid".into(),
                detail: "test-only root detail".into(),
            });
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "additional packaged checks")
            .expect("catalog-list limitation gap");

        assert_eq!(
            gap.reason,
            "Packaged check list unavailable. Additional checks: not tested."
        );
        assert!(!gap.reason.chars().any(|character| character.is_numeric()));
        assert!(!gap.reason.contains("One additional"));
    }

    #[test]
    fn contradictory_request_outcome_is_a_record_note_not_missing_coverage() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        case.scan_runs[0].request_outcome = Some(
            ScanRequestOutcome::no_checks_completed(
                ScanRequestOutcomeCode::NoApplicableChecks,
                vec!["different-asset".into()],
                vec!["different-check".into()],
                "Contradictory old state.",
            )
            .unwrap(),
        );

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.state.summary, BeginnerReportSummary::Complete);
        assert_ne!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );
        assert_eq!(report.requested.targets[0].asset_id, "localhost-asset");
        assert!(
            !report
                .requested
                .requested_check_ids
                .contains(&"different-check".into())
        );
        let note = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "saved run summary")
            .expect("saved run summary note");
        assert_eq!(note.class, CoverageGapClass::RecordNote);
        assert_eq!(note.next_action_code, NextActionCode::RetryCheck);
        assert!(!note.target_asset_ids.is_empty());
    }

    #[test]
    fn mismatched_summary_and_unfrozen_wording_stay_beginner_record_notes() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        case.scan_runs[0].request_outcome = Some(
            ScanRequestOutcome::no_checks_completed(
                ScanRequestOutcomeCode::NoApplicableChecks,
                vec!["different-asset".into()],
                vec!["different-check".into()],
                "Contradictory old state.",
            )
            .unwrap(),
        );
        let finding = frozen_finding(&case, "finding-legacy", 10, Severity::Low);
        let mut observed = observation(&finding, "run-1", instant(17));
        observed.finding_snapshot = None;
        case.findings.push(finding);
        case.finding_observations.push(observed);

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let saved_summary = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "saved run summary")
            .expect("saved run summary note");
        assert_eq!(
            saved_summary.reason,
            "The saved summary did not match this run's checks, so the report follows the checks."
        );
        assert!(!saved_summary.reason.contains("durable task state"));
        assert!(!saved_summary.reason.contains("presentation snapshot"));
        assert!(!saved_summary.reason.contains("legacy finding observation"));
        assert_eq!(
            saved_summary.next_action,
            "Retry this scan to create a consistent coverage record."
        );

        let recorded_wording = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "recorded finding wording")
            .expect("recorded finding wording note");
        assert_eq!(
            recorded_wording.reason,
            "Some findings are shown without the wording this scan recorded."
        );
        assert!(!recorded_wording.reason.contains("durable task state"));
        assert!(!recorded_wording.reason.contains("presentation snapshot"));
        assert!(
            !recorded_wording
                .reason
                .contains("legacy finding observation")
        );
        assert_eq!(
            recorded_wording.next_action,
            "Rerun the scan to create a fully frozen result."
        );
    }

    #[test]
    fn selected_run_snapshot_drives_priority_and_frameworks_without_catalog_lookup() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        let low = frozen_finding(&case, "finding-low", 10, Severity::Low);
        let mut high = frozen_finding(&case, "finding-high", 90, Severity::High);
        high.confidence_basis_code =
            Some(crate::domain::ConfidenceBasisCode::DeterministicPolicyEvaluation);
        high.official_references = vec!["https://example.test/frozen-rule".into()];
        high.evidence[0].scanner_details = Some(crate::domain::ScannerFindingDetails {
            description: Some("Frozen scanner description".into()),
            remediation: Some("Frozen scanner remediation".into()),
            installed_version: Some("1.0.0".into()),
            fixed_version: Some("1.0.1".into()),
            aws_iam_policy: None,
            cwe_ids: Vec::new(),
            cvss: Vec::new(),
            benchmarks: Vec::new(),
            advisory_aliases: Vec::new(),
        });
        case.findings = vec![low.clone(), high.clone()];
        case.finding_observations = vec![
            observation(&low, "run-1", instant(17)),
            observation(&high, "run-1", instant(18)),
        ];
        // The current projection is re-normalized after the selected run. The
        // historical report must keep the frozen rating and wording rather
        // than rewriting prior evidence to today's normalization semantics.
        case.findings[1].title = "Later mutable title".into();
        case.findings[1].severity = Severity::Unknown;
        case.findings[1].priority = 20;

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.findings[0].finding_id, "finding-high");
        assert_eq!(report.findings[0].title, "Frozen finding-high");
        assert_eq!(report.findings[0].severity, Severity::High);
        assert_eq!(report.findings[0].priority, Some(90));
        assert_eq!(
            report.findings[0].snapshot_source,
            FindingSnapshotSource::FrozenSelectedRun
        );
        assert_eq!(report.findings[0].framework_references.len(), 1);
        assert_eq!(
            report.findings[0].evidence_references[0]
                .location
                .as_deref(),
            Some("src/config.ts:42")
        );
        assert_eq!(
            report.findings[0].evidence_references[0]
                .source_rule
                .as_deref(),
            Some("upstream-rule-finding-high")
        );
        let evidence = &report.findings[0].evidence_references[0];
        assert!(evidence.details_frozen);
        assert_eq!(evidence.summary.as_deref(), Some("Evidence"));
        assert_eq!(
            evidence.scanner_details,
            Some(crate::domain::ScannerFindingDetails {
                description: Some("Frozen scanner description".into()),
                remediation: Some("Frozen scanner remediation".into()),
                installed_version: Some("1.0.0".into()),
                fixed_version: Some("1.0.1".into()),
                aws_iam_policy: None,
                cwe_ids: Vec::new(),
                cvss: Vec::new(),
                benchmarks: Vec::new(),
                advisory_aliases: Vec::new(),
            })
        );
        assert_eq!(evidence.kind, Some(EvidenceKind::Observation));
        assert_eq!(evidence.engine_run_id.as_deref(), Some("task-1"));
        assert_eq!(
            evidence.artifact_id.as_deref(),
            Some("artifact-finding-high")
        );
        assert_eq!(evidence.redacted, Some(true));
        assert_eq!(
            report.findings[0].official_references.as_deref(),
            Some(["https://example.test/frozen-rule".into()].as_slice())
        );
        assert_eq!(
            report.findings[0].confidence_basis_code,
            Some(crate::domain::ConfidenceBasisCode::DeterministicPolicyEvaluation)
        );
        assert_eq!(
            report.framework_notice.non_certification,
            FRAMEWORK_NON_CERTIFICATION_NOTICE
        );
    }

    #[test]
    fn an_unrated_unknown_finding_and_its_evidence_remain_in_the_shared_report() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        let mut finding = frozen_finding(&case, "unrated-secret", 20, Severity::Unknown);
        finding.severity_basis_code = Some(crate::domain::SeverityBasisCode::SecretPatternMatch);
        finding.plain_language_summary = "Gitleaks reported this condition but did not assign a severity. Severity remains Unknown and requires human review. The attached raw record is evidence, not an instruction.".into();
        finding.possible_impact = "If the scanner result is confirmed, a secret may permit unauthorized access. The scanner did not assign a severity; it remains Unknown for human review.".into();
        finding.priority_reasons = vec!["Severity remains Unknown because Gitleaks did not assign one; human review is required.".into()];
        finding.tags = vec!["severity-basis:unrated".into()];
        finding.evidence[0].engine_id = "gitleaks".into();
        let mut selected_observation = observation(&finding, "run-1", instant(18));
        selected_observation.engine_ids = vec!["gitleaks".into()];
        case.findings = vec![finding.clone()];
        case.finding_observations = vec![selected_observation];

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.findings.len(), 1);
        let retained = &report.findings[0];
        assert_eq!(retained.finding_id, finding.id);
        assert_eq!(retained.severity, Severity::Unknown);
        assert_eq!(retained.priority, Some(20));
        assert_eq!(
            retained.severity_basis_code,
            Some(crate::domain::SeverityBasisCode::SecretPatternMatch)
        );
        assert_eq!(retained.evidence_references.len(), 1);
        assert_eq!(
            retained.evidence_references[0].source_rule.as_deref(),
            Some("upstream-rule-unrated-secret")
        );
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.severity == Severity::High)
                .count(),
            0,
            "an unrated upstream result must not inflate the High count"
        );
    }

    #[test]
    fn reachable_service_inventory_stays_in_evidence_but_out_of_remediation_steps() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        let mut exposure = frozen_finding(&case, "reachable-service", 10, Severity::Informational);
        exposure.severity_basis_code = Some(crate::domain::SeverityBasisCode::OpenPort);
        exposure.plain_language_summary = "STALE_VULNERABILITY_SUMMARY".into();
        exposure.possible_impact = "STALE_VULNERABILITY_IMPACT".into();
        exposure.priority = 99;
        exposure.priority_reasons = vec!["STALE_VULNERABILITY_PRIORITY".into()];
        exposure.recommendation = "STALE_VULNERABILITY_REMEDIATION".into();
        exposure.verification_guidance = "STALE_VULNERABILITY_VERIFICATION".into();
        exposure.rollback_considerations = Some("STALE_VULNERABILITY_ROLLBACK".into());
        exposure.tags = vec!["port:443".into(), "protocol:tcp".into()];
        let problem = frozen_finding(&case, "actual-problem", 80, Severity::High);
        case.findings = vec![exposure.clone(), problem.clone()];
        case.finding_observations = vec![
            observation(&exposure, "run-1", instant(17)),
            observation(&problem, "run-1", instant(18)),
        ];

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let retained_exposure = report
            .findings
            .iter()
            .find(|finding| finding.finding_id == exposure.id)
            .expect("the inventory observation remains available");
        assert_eq!(
            retained_exposure.observation_details,
            ["port:443", "protocol:tcp"]
        );
        assert_eq!(retained_exposure.priority, None);
        assert!(retained_exposure.priority_reasons.is_empty());
        assert_eq!(
            retained_exposure.plain_language_risk,
            crate::finding_narrative::EXPOSURE_OBSERVATION_RISK
        );
        assert_eq!(
            retained_exposure.possible_impact,
            crate::finding_narrative::EXPOSURE_OBSERVATION_IMPACT
        );
        assert_eq!(
            retained_exposure.next_step,
            crate::finding_narrative::EXPOSURE_OBSERVATION_NEXT_STEP
        );
        assert!(retained_exposure.rollback_considerations.is_none());
        assert_eq!(
            retained_exposure.severity_basis_code,
            Some(crate::domain::SeverityBasisCode::OpenPort)
        );
        assert_eq!(
            retained_exposure.recommended_expert_type,
            crate::finding_narrative::EXPOSURE_OBSERVATION_OWNER
        );
        assert!(!retained_exposure.evidence_references.is_empty());
        let encoded = serde_json::to_string(retained_exposure).unwrap();
        assert!(!encoded.contains("STALE_VULNERABILITY"));
        assert!(
            report
                .next_steps
                .iter()
                .all(|step| { step.finding_id.as_deref() != Some(exposure.id.as_str()) })
        );
        assert!(
            report
                .next_steps
                .iter()
                .any(|step| { step.finding_id.as_deref() == Some(problem.id.as_str()) })
        );
    }

    /// A minimal terminal case carrying exactly one asset of the given kind,
    /// with no engine runs of its own: the dependency-routing tests below
    /// only need `build_beginner_master_report` to accept the run and to
    /// resolve one finding's target asset, not a full scan history.
    fn case_with_single_asset(kind: AssetKind, asset_id: &str) -> AssessmentCase {
        let mut case = empty_case();
        case.assets.push(Asset {
            id: asset_id.into(),
            kind,
            name: "Fixture asset".into(),
            provider: None,
            region: None,
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
            created_at: instant(10),
            completed_at: Some(instant(20)),
            request_outcome: None,
            report_asset_snapshots: Vec::new(),
            knowledge_cutoff: instant(10),
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec![],
            scope_grant_snapshots: vec![],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![],
        });
        case
    }

    /// A finding targeting one asset, carrying one evidence record per given
    /// engine ID. The old adapter default is retained here to test reports
    /// created before the package specialist change.
    fn dependency_finding(
        case: &AssessmentCase,
        id: &str,
        asset_id: &str,
        engine_ids: &[&str],
    ) -> Finding {
        let mut finding = frozen_finding(case, id, 80, Severity::Critical);
        finding.asset_ids = vec![asset_id.into()];
        finding.recommended_expert_type = "Container security engineer".into();
        let template = finding.evidence[0].clone();
        finding.evidence = engine_ids
            .iter()
            .enumerate()
            .map(|(index, engine_id)| {
                let mut evidence = template.clone();
                evidence.id = format!("evidence-{id}-{index}");
                evidence.engine_id = (*engine_id).into();
                evidence
            })
            .collect();
        finding
    }

    #[test]
    fn trivy_and_grype_dependency_findings_on_a_repository_name_the_supply_chain_engineer() {
        for engine_id in ["trivy", "grype"] {
            let mut case = case_with_single_asset(AssetKind::Repository, "repo-asset");
            let finding = dependency_finding(&case, "dep-finding", "repo-asset", &[engine_id]);
            case.finding_observations
                .push(observation(&finding, "run-1", instant(18)));
            case.findings.push(finding);

            let report = build_beginner_master_report(&case, "run-1").unwrap();
            assert_eq!(report.findings.len(), 1);
            assert_eq!(
                report.findings[0].recommended_expert_type, "Software supply-chain engineer",
                "a {engine_id} dependency finding on a repository must name the supply-chain engineer, not the container engineer its adapter stamped"
            );
        }
    }

    #[test]
    fn trivy_and_grype_dependency_findings_on_a_container_asset_keep_the_container_engineer() {
        for kind in [AssetKind::ContainerImage, AssetKind::ContainerRegistry] {
            for engine_id in ["trivy", "grype"] {
                for stored_expert in [
                    "Container security engineer",
                    "Software supply-chain engineer",
                ] {
                    let mut case = case_with_single_asset(kind.clone(), "image-asset");
                    let mut finding =
                        dependency_finding(&case, "dep-finding", "image-asset", &[engine_id]);
                    finding.recommended_expert_type = stored_expert.into();
                    case.finding_observations
                        .push(observation(&finding, "run-1", instant(18)));
                    case.findings.push(finding);

                    let report = build_beginner_master_report(&case, "run-1").unwrap();
                    assert_eq!(report.findings.len(), 1);
                    assert_eq!(
                        report.findings[0].recommended_expert_type, "Container security engineer",
                        "a {engine_id} finding on a {kind:?} asset is still a container question with stored expert {stored_expert}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_dependency_finding_with_non_trivy_grype_evidence_keeps_its_stored_expert() {
        let mut case = case_with_single_asset(AssetKind::Repository, "repo-asset");
        let finding =
            dependency_finding(&case, "dep-finding", "repo-asset", &["trivy", "gitleaks"]);
        case.finding_observations
            .push(observation(&finding, "run-1", instant(18)));
        case.findings.push(finding);

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].recommended_expert_type, "Container security engineer",
            "evidence from an engine other than Trivy or Grype must not move the finding off its stored expert"
        );
    }

    fn timed_out_httpx_task(id: &str) -> EngineRun {
        let mut task = catalog_task(id, EngineRunStatus::PartiallyCompleted);
        task.engine_id = "httpx".into();
        task.error_code = Some("TARGET_TIMEOUT".into());
        task.error_message = Some("One synthetic target timed out.".into());
        task
    }

    fn completed_httpx_task(id: &str) -> EngineRun {
        let mut task = catalog_task(id, EngineRunStatus::Completed);
        task.engine_id = "httpx".into();
        task.error_code = None;
        task.error_message = None;
        task.exit_code = Some(0);
        task
    }

    fn rated_network_finding(
        case: &AssessmentCase,
        finding_id: &str,
        engine_run_id: Option<&str>,
    ) -> Finding {
        let mut finding = frozen_finding(case, finding_id, 58, Severity::Informational);
        finding.family = Some(FindingFamily::NetworkExposure);
        finding.confidence = Confidence::Medium;
        finding.title = "The synthetic public site's HSTS status remains unconfirmed".into();
        finding.recommendation =
            "Have a network or system administrator review the TLS/HSTS settings.".into();
        finding.verification_guidance = "Rerun httpx with the same scope after the change and confirm that source rule hsts is no longer reported.".into();
        finding.recommended_expert_type = "Network or system administrator".into();
        finding.asset_ids = vec!["asset-1".into()];
        finding.evidence[0].engine_id = "httpx".into();
        finding.evidence[0].engine_run_id = engine_run_id.map(str::to_owned);
        finding.evidence[0].summary =
            "Synthetic timeout record proving the check was incomplete, not that HSTS was absent."
                .into();
        finding
    }

    fn case_with_rated_network_finding(
        task: EngineRun,
        engine_run_id: Option<&str>,
    ) -> AssessmentCase {
        let mut case = case_with_catalog_tasks(vec![task], true);
        let finding = rated_network_finding(&case, "hsts-unconfirmed", engine_run_id);
        let retained = observation(&finding, "run-1", instant(18));
        case.findings.push(finding);
        case.finding_observations.push(retained);
        case
    }

    fn assert_confirm_first_action(report: &BeginnerMasterReport) {
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.finding_id == "hsts-unconfirmed")
            .expect("the rated finding remains visible");
        assert_eq!(
            finding.next_step,
            crate::finding_narrative::INCOMPLETE_CHECK_CONFIRM_ACTION
        );
        assert_eq!(
            finding.severity,
            Severity::Informational,
            "coverage does not change the finding's rating"
        );
        assert_eq!(finding.confidence, Confidence::Medium);
        assert_eq!(finding.priority, Some(58));
        let unconfirmed = finding_unconfirmed_by_coverage(finding, &report.actual);
        assert!(unconfirmed);
        assert_eq!(
            crate::finding_narrative::finding_next_action_english(
                &finding.next_step,
                finding.family,
                None,
                unconfirmed,
            ),
            crate::finding_narrative::INCOMPLETE_CHECK_CONFIRM_ACTION
        );
        assert_eq!(
            crate::finding_narrative::finding_next_action_zh_hant(
                &finding.next_step,
                &finding.recommended_expert_type,
                finding.family,
                None,
                unconfirmed,
            ),
            crate::finding_narrative::INCOMPLETE_CHECK_CONFIRM_ACTION_ZH_HANT
        );
        let step = report
            .next_steps
            .iter()
            .find(|step| step.finding_id.as_deref() == Some("hsts-unconfirmed"))
            .expect("the rated finding still has a next step");
        assert_eq!(
            step.code,
            NextActionCode::ConfirmFindingAfterIncompleteCheck
        );
        assert_eq!(
            step.action,
            crate::finding_narrative::INCOMPLETE_CHECK_CONFIRM_ACTION
        );
        assert_ne!(step.code, NextActionCode::ReviewFinding);
    }

    #[test]
    fn timed_out_check_does_not_tell_the_reader_to_correct_the_service() {
        let case = case_with_rated_network_finding(timed_out_httpx_task("task-1"), Some("task-1"));
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TimedOut
        );
        assert_confirm_first_action(&report);
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.next_step.contains("Correct the service"))
        );
    }

    #[test]
    fn completed_check_keeps_the_family_remedy() {
        let case = case_with_rated_network_finding(completed_httpx_task("task-1"), Some("task-1"));
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedComplete
        );
        let finding = &report.findings[0];
        assert!(!finding_unconfirmed_by_coverage(finding, &report.actual));
        assert_eq!(
            finding.next_step,
            "Correct the service or configuration named by this check."
        );
        let step = report
            .next_steps
            .iter()
            .find(|step| step.finding_id.as_deref() == Some("hsts-unconfirmed"))
            .expect("the confirmed finding keeps a next step");
        assert_eq!(step.code, NextActionCode::ReviewFinding);
        assert_eq!(
            step.action,
            "Correct the service or configuration named by this check."
        );
        assert_eq!(
            crate::finding_narrative::finding_next_action_zh_hant(
                &finding.next_step,
                &finding.recommended_expert_type,
                finding.family,
                None,
                false,
            ),
            "調整這項檢查所指出的服務或設定。"
        );
    }

    #[test]
    fn missing_engine_run_id_is_unconfirmed_by_coverage() {
        let case = case_with_rated_network_finding(completed_httpx_task("task-1"), None);
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(
            report.findings[0].evidence_references[0].engine_run_id,
            None
        );
        assert_confirm_first_action(&report);
    }

    #[test]
    fn evidence_naming_an_absent_run_is_unconfirmed_by_coverage() {
        let case =
            case_with_rated_network_finding(completed_httpx_task("task-1"), Some("missing-task"));
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(
            report.findings[0].evidence_references[0]
                .engine_run_id
                .as_deref(),
            Some("missing-task")
        );
        assert!(
            report
                .actual
                .checks
                .iter()
                .all(|check| check.task_id != "missing-task")
        );
        assert_confirm_first_action(&report);
    }

    #[test]
    fn a_finding_with_no_evidence_is_unconfirmed_by_coverage() {
        let mut case =
            case_with_rated_network_finding(completed_httpx_task("task-1"), Some("task-1"));
        case.findings[0].evidence.clear();
        case.finding_observations[0].finding_snapshot = Some(case.findings[0].clone());
        case.finding_observations[0].evidence_hashes.clear();
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert!(report.findings[0].evidence_references.is_empty());
        assert_confirm_first_action(&report);
    }

    #[test]
    fn mixed_complete_and_timed_out_evidence_keeps_the_family_remedy() {
        let mut case = case_with_catalog_tasks(
            vec![
                completed_httpx_task("task-complete"),
                timed_out_httpx_task("task-timeout"),
            ],
            true,
        );
        let mut finding = rated_network_finding(&case, "hsts-mixed", Some("task-complete"));
        let mut timeout_evidence = finding.evidence[0].clone();
        timeout_evidence.id = "evidence-timeout".into();
        timeout_evidence.engine_run_id = Some("task-timeout".into());
        timeout_evidence.artifact_id = "artifact-timeout".into();
        timeout_evidence.artifact_sha256 = "hash-timeout".into();
        finding.evidence.push(timeout_evidence);
        let retained = observation(&finding, "run-1", instant(18));
        case.findings.push(finding);
        case.finding_observations.push(retained);

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.findings[0].evidence_references.len(), 2);
        assert!(report.actual.checks.iter().any(|check| {
            check.task_id == "task-complete"
                && check.status == CoverageDimensionStatus::TestedComplete
        }));
        assert!(report.actual.checks.iter().any(|check| {
            check.task_id == "task-timeout" && check.status == CoverageDimensionStatus::TimedOut
        }));
        let finding = &report.findings[0];
        assert!(!finding_unconfirmed_by_coverage(finding, &report.actual));
        assert_eq!(
            finding.next_step,
            "Correct the service or configuration named by this check."
        );
        let step = report
            .next_steps
            .iter()
            .find(|step| step.finding_id.as_deref() == Some("hsts-mixed"))
            .expect("the mixed-evidence finding keeps a next step");
        assert_eq!(step.code, NextActionCode::ReviewFinding);
        assert_eq!(
            step.action,
            "Correct the service or configuration named by this check."
        );
    }

    #[test]
    fn same_stored_action_with_different_experts_stays_two_steps() {
        let mut case = case_with_catalog_tasks(vec![completed_httpx_task("task-1")], true);
        let shared_recommendation = "Have the recommended specialist review the affected asset and the source rule's official guidance, then plan and approve a correction of the named service.";
        let mut vulnerability_manager = rated_network_finding(&case, "finding-a", Some("task-1"));
        vulnerability_manager.recommended_expert_type = "Vulnerability manager".into();
        vulnerability_manager.recommendation = shared_recommendation.into();
        let mut application_security = rated_network_finding(&case, "finding-b", Some("task-1"));
        application_security.recommended_expert_type = "Application security engineer".into();
        application_security.recommendation = shared_recommendation.into();
        case.findings.push(vulnerability_manager.clone());
        case.findings.push(application_security.clone());
        case.finding_observations
            .push(observation(&vulnerability_manager, "run-1", instant(18)));
        case.finding_observations
            .push(observation(&application_security, "run-1", instant(18)));

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let same_text_different_expert = report
            .next_steps
            .iter()
            .filter(|step| {
                step.action == "Correct the service or configuration named by this check."
            })
            .map(|step| step.recommended_expert_type.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            same_text_different_expert,
            [
                Some("Vulnerability manager".to_string()),
                Some("Application security engineer".to_string())
            ],
            "one stored sentence, two experts, two steps"
        );
        assert!(
            report
                .next_steps
                .iter()
                .filter(|step| {
                    step.action == "Correct the service or configuration named by this check."
                })
                .all(|step| step.also_resolves.is_empty())
        );
    }

    #[test]
    fn a_shared_family_remedy_is_not_one_fix_and_a_typed_policy_action_is() {
        let mut case = case_with_catalog_tasks(vec![completed_httpx_task("task-1")], true);
        let first = rated_network_finding(&case, "finding-a", Some("task-1"));
        let mut second = rated_network_finding(&case, "finding-b", Some("task-1"));
        second.title = "A different service setting remains open".into();
        case.findings.push(first.clone());
        case.findings.push(second.clone());
        case.finding_observations
            .push(observation(&first, "run-1", instant(18)));
        case.finding_observations
            .push(observation(&second, "run-1", instant(18)));

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let family_steps = report
            .next_steps
            .iter()
            .filter(|step| {
                step.action == "Correct the service or configuration named by this check."
            })
            .collect::<Vec<_>>();
        assert_eq!(family_steps.len(), 1, "one family remedy, one step");
        assert_eq!(family_steps[0].also_resolves.len(), 1);
        assert!(!family_steps[0].shared_fix);

        let mut encoded = serde_json::to_value(family_steps[0]).unwrap();
        assert!(
            encoded.get("shared_fix").is_none(),
            "a false flag is omitted so an older reader still opens the step"
        );
        encoded.as_object_mut().unwrap().remove("shared_fix");
        let decoded: BeginnerNextStep = serde_json::from_value(encoded).unwrap();
        assert!(!decoded.shared_fix);

        // No existing beginner-report fixture merges Cloudsplaining findings
        // (the assertion above this test keeps two experts apart). Two findings
        // that carry the same typed policy record do, and that record is the
        // one change the step names.
        let mut cloud =
            case_with_catalog_tasks(vec![completed_engine_task("cloudsplaining")], true);
        let policy = crate::domain::AwsIamPolicyFindingDetails {
            policy_source: crate::domain::AwsIamPolicySource::AwsManaged,
            policy_name: "IAMFullAccess".into(),
            finding_identity: "PrivilegeEscalation".into(),
            actions: vec!["iam:CreateAccessKey".into()],
            actions_complete: true,
            attached_to: crate::domain::AwsIamAttachedTo {
                roles: Vec::new(),
                groups: vec!["AdminGroup".into()],
                users: Vec::new(),
                complete: true,
            },
        };
        let mut lead = rated_network_finding(&cloud, "iam-a", Some("cloudsplaining"));
        let mut follow = rated_network_finding(&cloud, "iam-b", Some("cloudsplaining"));
        for finding in [&mut lead, &mut follow] {
            finding.family = Some(FindingFamily::CloudIdentity);
            finding.recommended_expert_type = "Cloud identity specialist".into();
            finding.evidence[0].engine_id = "cloudsplaining".into();
            finding.evidence[0].scanner_details = Some(crate::domain::ScannerFindingDetails {
                description: None,
                remediation: None,
                installed_version: None,
                fixed_version: None,
                aws_iam_policy: Some(policy.clone()),
                cwe_ids: Vec::new(),
                cvss: Vec::new(),
                benchmarks: Vec::new(),
                advisory_aliases: Vec::new(),
            });
        }
        follow.title = "A second privilege path in the same policy".into();
        follow.evidence[0].id = "evidence-iam-b".into();
        cloud.findings.push(lead.clone());
        cloud.findings.push(follow.clone());
        cloud
            .finding_observations
            .push(observation(&lead, "run-1", instant(18)));
        cloud
            .finding_observations
            .push(observation(&follow, "run-1", instant(18)));

        let report = build_beginner_master_report(&cloud, "run-1").unwrap();
        let policy_steps = report
            .next_steps
            .iter()
            .filter(|step| step.action.contains("IAMFullAccess"))
            .collect::<Vec<_>>();
        assert_eq!(policy_steps.len(), 1, "one typed policy action, one step");
        assert_eq!(policy_steps[0].also_resolves.len(), 1);
        assert!(policy_steps[0].shared_fix);
        assert!(policy_steps[0].action.contains("group AdminGroup"));
        let encoded = serde_json::to_value(policy_steps[0]).unwrap();
        assert_eq!(encoded["shared_fix"], true);
    }

    #[test]
    fn project_next_steps_never_returns_an_empty_vector() {
        let empty_actual = ActualCoverage {
            observed_from: None,
            observed_until: None,
            checks: Vec::new(),
            network_scopes: Vec::new(),
            unavailable_dimensions: Vec::new(),
        };
        let fallback = project_next_steps(&[], &[], &empty_actual, &[]);
        assert_eq!(fallback.len(), 1);
        assert_eq!(fallback[0].code, NextActionCode::ReviewCoverage);
        assert_eq!(
            fallback[0].action,
            "Review what was tested before deciding whether you need a broader scan."
        );

        let case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert!(report.findings.is_empty());
        assert!(report.coverage_gaps.is_empty());
        assert!(
            !report.next_steps.is_empty(),
            "a complete run with no findings and no coverage gaps still names a next step"
        );
        assert_ne!(
            report.next_steps[0].action,
            "No additional action is required unless broader coverage is wanted."
        );
    }

    #[test]
    fn httpx_only_run_says_it_is_inventory_not_security_checks() {
        let mut task = catalog_task("completed", EngineRunStatus::Completed);
        task.engine_id = "httpx".into();
        let case = case_with_catalog_tasks(vec![task], true);

        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.state.summary, BeginnerReportSummary::Complete);
        assert!(run_is_non_security_only(&case.scan_runs[0]));
        assert!(
            report.state.explanation.contains(
                "No vulnerability, configuration, code, or secret security check completed"
            )
        );
        assert!(
            !report
                .state
                .explanation
                .contains("Every exact requested dimension")
        );
        assert_eq!(
            report.actual.checks[0].effective_result_kind(),
            CheckResultKind::Inventory
        );
    }

    #[test]
    fn inventory_engines_are_not_completed_security_checks() {
        for engine_id in [
            "cloudquery",
            "steampipe",
            "syft",
            "naabu",
            "httpx",
            "agentic-radar",
        ] {
            let mut task = catalog_task("completed", EngineRunStatus::Completed);
            task.engine_id = engine_id.into();
            let case = case_with_catalog_tasks(vec![task], true);

            let report = build_beginner_master_report(&case, "run-1").unwrap();

            assert_eq!(
                report.actual.checks[0].result_kind,
                Some(CheckResultKind::Inventory),
                "{engine_id} must remain inventory"
            );
            assert!(run_is_non_security_only(&case.scan_runs[0]));
            assert!(report.state.explanation.contains(
                "No vulnerability, configuration, code, or secret security check completed"
            ));
            assert!(!report.state.explanation.contains("no problems"));
        }
    }

    #[test]
    fn mixed_inventory_and_security_tasks_keep_each_result_kind() {
        let mut syft = catalog_task("syft-completed", EngineRunStatus::Completed);
        syft.engine_id = "syft".into();
        let mut trivy = catalog_task("trivy-completed", EngineRunStatus::Completed);
        trivy.engine_id = "trivy".into();
        let case = case_with_catalog_tasks(vec![syft, trivy], true);

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let kinds = report
            .actual
            .checks
            .iter()
            .map(|check| (check.check_id.as_str(), check.result_kind))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(kinds.get("syft"), Some(&Some(CheckResultKind::Inventory)));
        assert_eq!(
            kinds.get("trivy"),
            Some(&Some(CheckResultKind::SecurityCheck))
        );
        assert!(!run_is_non_security_only(&case.scan_runs[0]));
        assert!(!report.state.explanation.contains("only inventory"));
    }

    #[test]
    fn maester_manual_review_is_visible_without_becoming_a_finding_or_new_incomplete_state() {
        let mut task = catalog_task("maester", EngineRunStatus::Completed);
        task.engine_id = "maester".into();
        task.progress_percent = 100;
        task.phase = "completed".into();
        task.exit_code = Some(0);
        task.error_message = None;
        let baseline_case = case_with_catalog_tasks(vec![task.clone()], true);
        let baseline = build_beginner_master_report(&baseline_case, "run-1").unwrap();
        task.manual_review_controls = vec![ManualReviewControl {
            asset_id: "asset-1".into(),
            rule_id: "MT.1003".into(),
            title: "Legacy multifactor authentication methods need review".into(),
            detail: Some(
                "Confirm whether the remaining legacy methods are assigned to active users.".into(),
            ),
        }];
        let case = case_with_catalog_tasks(vec![task], true);

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(
            report.state.summary, baseline.state.summary,
            "manual review must not change the run's existing completion state"
        );
        assert_eq!(report.findings.len(), 0);
        assert_eq!(report.actual.checks.len(), 1);
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedComplete
        );
        assert_eq!(report.coverage_counts.tested_complete, 1);
        assert_eq!(report.coverage_counts.manual_review, 1);
        assert_eq!(
            report.coverage_counts.not_tested,
            baseline.coverage_counts.not_tested
        );
        assert_eq!(
            report.coverage_counts.failed,
            baseline.coverage_counts.failed
        );
        assert_eq!(
            report.coverage_counts.unavailable,
            baseline.coverage_counts.unavailable
        );
        assert_eq!(
            report.coverage_gaps.len(),
            baseline.coverage_gaps.len() + 1,
            "the review item must add only its own visible row"
        );
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.kind == CoverageGapKind::ManualReview)
            .expect("manual-review control disappeared from the beginner report");
        assert_eq!(gap.target_asset_ids, ["asset-1"]);
        assert!(gap.dimension.contains("MT.1003"));
        assert!(gap.reason.contains("remaining legacy methods"));
        assert_eq!(gap.next_action_code, NextActionCode::ReviewManualControl);
        assert!(
            report
                .next_steps
                .iter()
                .any(|step| step.task_id.as_deref() == Some("maester")
                    && step.action.contains(
                        "Review the upstream detail and record a human decision for this control."
                    ))
        );

        let reopened: AssessmentCase =
            serde_json::from_slice(&serde_json::to_vec(&case).unwrap()).unwrap();
        assert_eq!(
            build_beginner_master_report(&reopened, "run-1").unwrap(),
            report,
            "reopening the case must preserve the manual-review coverage item"
        );
    }

    fn completed_engine_task(engine_id: &str) -> EngineRun {
        let mut task = catalog_task(engine_id, EngineRunStatus::Completed);
        task.engine_id = engine_id.into();
        task.progress_percent = 100;
        task.phase = "completed".into();
        task.exit_code = Some(0);
        task.error_message = None;
        task
    }

    fn cloud_case(tasks: Vec<EngineRun>, kind: AssetKind) -> AssessmentCase {
        let mut case = case_with_catalog_tasks(tasks, true);
        case.assets[0].kind = kind;
        case.assets[0].name = "cloud target".into();
        case
    }

    fn cloud_scope_rows(report: &BeginnerMasterReport) -> Vec<&CoverageGap> {
        report
            .coverage_gaps
            .iter()
            .filter(|gap| CLOUD_SCOPE_LIMIT_DIMENSIONS.contains(&gap.dimension.as_str()))
            .collect()
    }

    #[test]
    fn a_clean_cloud_account_says_which_services_its_checks_left_out() {
        let case = cloud_case(
            vec![
                completed_engine_task("prowler"),
                completed_engine_task("scoutsuite"),
                completed_engine_task("cloudsplaining"),
            ],
            AssetKind::CloudAccount,
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert!(report.findings.is_empty());
        assert!(
            report
                .actual
                .checks
                .iter()
                .all(|check| check.status == CoverageDimensionStatus::TestedComplete),
            "the checks themselves completed"
        );
        assert_eq!(
            report.state.summary,
            BeginnerReportSummary::Partial,
            "identity and access alone is not the whole account"
        );
        // Three checks, one account, one row: the limit is the account's.
        let rows = cloud_scope_rows(&report);
        assert_eq!(rows.len(), 1);
        let row = rows[0];
        assert_eq!(row.dimension, "AWS services other than IAM");
        assert_eq!(row.kind, CoverageGapKind::NotTested);
        assert_eq!(row.class, CoverageGapClass::CoverageLoss);
        assert_eq!(row.task_id, None);
        assert_eq!(row.target_asset_ids, ["asset-1"]);
        assert!(
            row.reason
                .contains("S3, EC2, RDS, CloudTrail and GuardDuty")
        );
        assert_eq!(
            crate::finding_narrative::coverage_dimension_zh_hant(&row.dimension),
            "IAM 以外的 AWS 服務"
        );
        assert!(report.next_steps.iter().any(|step| step.action
            == "Run a full Prowler scan of this account."
            && step.task_id.is_none()));
        assert_eq!(report.coverage_counts.not_tested, 1);
    }

    #[test]
    fn each_cloud_profile_names_its_own_limit_once_a_check_has_run() {
        for (engine, kind, dimension, action) in [
            (
                "prowler",
                AssetKind::CloudAccount,
                "AWS services other than IAM",
                "Run a full Prowler scan of this account.",
            ),
            (
                "prowler",
                AssetKind::Subscription,
                "Azure services other than IAM",
                "Run a full Prowler scan of this subscription.",
            ),
            (
                "prowler",
                AssetKind::Project,
                "Google Cloud settings other than four IAM checks",
                "Run a full Prowler scan of this Google Cloud project.",
            ),
            (
                "scubagear",
                AssetKind::Tenant,
                "Microsoft 365 products other than Entra ID",
                "Run ScubaGear with all products for this tenant.",
            ),
            (
                "maester",
                AssetKind::Tenant,
                "Microsoft 365 products other than Entra ID",
                "Run ScubaGear with all products for this tenant.",
            ),
        ] {
            let case = cloud_case(vec![completed_engine_task(engine)], kind.clone());
            let report = build_beginner_master_report(&case, "run-1").unwrap();
            let rows = cloud_scope_rows(&report)
                .into_iter()
                .map(|gap| (gap.dimension.as_str(), gap.next_action.as_str()))
                .collect::<Vec<_>>();
            assert_eq!(rows, [(dimension, action)], "{engine} on {kind:?}");
        }

        // A failed check tested nothing, and its own row already says so.
        let mut failed = completed_engine_task("prowler");
        failed.status = EngineRunStatus::Failed;
        let report = build_beginner_master_report(
            &cloud_case(vec![failed], AssetKind::CloudAccount),
            "run-1",
        )
        .unwrap();
        assert!(cloud_scope_rows(&report).is_empty());
        // Inventory is not a security check, so it has no clean result to qualify.
        let report = build_beginner_master_report(
            &cloud_case(
                vec![completed_engine_task("cloudquery")],
                AssetKind::CloudAccount,
            ),
            "run-1",
        )
        .unwrap();
        assert!(cloud_scope_rows(&report).is_empty());
    }

    /// The scope rows describe what each launcher runs. A launcher that runs
    /// more must change its row too, or the report understates the scan.
    #[test]
    fn the_cloud_scope_rows_describe_what_the_launchers_run() {
        let cloud = include_str!("../../engines/images/cloud-launcher/main.go");
        for invocation in [
            r#""aws", "--service", "iam", "--region", "us-east-1""#,
            r#""--subscription-ids", providerTarget, "--service", "iam","#,
            r#""--checks", "iam_audit_logs_enabled", "iam_no_service_roles_at_project_level","#,
            r#""iam_role_kms_enforce_separation_of_duties", "iam_role_sa_enforce_separation_of_duties","#,
            r#""aws", "--services", "iam", "--no-browser", "--force","#,
        ] {
            assert_eq!(cloud.matches(invocation).count(), 1, "{invocation}");
        }
        let scubagear = include_str!("../../engines/images/scubagear/run-scubagear.ps1");
        assert!(scubagear.contains("-ProductNames @('aad')"));
        let maester = include_str!("../../engines/images/maester/run-maester.ps1");
        assert!(maester.contains("-Path '/opt/ai-security-scanner/maester-tests/Maester/Entra'"));
    }

    #[test]
    fn controls_a_tenant_check_did_not_evaluate_reach_the_report() {
        let mut task = completed_engine_task("scubagear");
        // Written by an older build, which named manual controls differently.
        task.warnings = vec![
            "ScubaGear did not evaluate every control in scope (20 reserved for manual review, 5 omitted by configuration); those controls are absent from findings and this run does not establish their state".into(),
        ];
        let case = cloud_case(vec![task], AssetKind::Tenant);
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedComplete
        );
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "scubagear: controls not evaluated")
            .expect("the unevaluated controls reach the report");
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert_eq!(gap.task_id.as_deref(), Some("scubagear"));
        assert_eq!(gap.target_asset_ids, ["asset-1"]);
        assert_eq!(
            gap.reason,
            "Some controls in scope were not evaluated, so their state is unknown. Not evaluated: 20 left without an automated verdict, 5 omitted by configuration."
        );
        assert_eq!(
            crate::finding_narrative::coverage_gap_prose_zh_hant(&gap.reason).as_deref(),
            Some(
                "範圍內有部分控制項未經評估，因此狀態未知。未評估：20 未回傳自動判定、5 依設定略過。"
            )
        );
        assert_eq!(
            crate::finding_narrative::coverage_dimension_zh_hant(&gap.dimension),
            "scubagear 的未評估控制項"
        );
        assert_eq!(gap.next_action, "Check these controls by hand.");
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);

        // Another engine's disclosure is not this task's to report.
        let mut other = completed_engine_task("maester");
        other.warnings = case.scan_runs[0].engine_runs[0].warnings.clone();
        let report =
            build_beginner_master_report(&cloud_case(vec![other], AssetKind::Tenant), "run-1")
                .unwrap();
        assert!(
            !report
                .coverage_gaps
                .iter()
                .any(|gap| gap.dimension.ends_with(": controls not evaluated"))
        );
    }

    #[test]
    fn typed_inventory_is_selected_run_only_and_deduplicates_native_identities() {
        let mut task = catalog_task("completed", EngineRunStatus::Completed);
        task.engine_id = "naabu".into();
        let mut case = case_with_catalog_tasks(vec![task], true);
        let service = InventoryObservationKind::Service {
            endpoint: "10.0.0.5".into(),
            port: Some(443),
            transport: Some("tcp".into()),
            scheme: None,
            http_status: None,
            tls: None,
        };
        let observation = |id: &str,
                           run_id: &str,
                           engine_id: &str,
                           kind: InventoryObservationKind,
                           asset_id: &str| InventoryObservation {
            id: id.into(),
            case_id: case.id.clone(),
            run_id: run_id.into(),
            engine_run_id: format!("{engine_id}-task"),
            asset_id: asset_id.into(),
            engine_id: engine_id.into(),
            kind,
            artifact_id: format!("artifact-{id}"),
            artifact_sha256: id.repeat(64).chars().take(64).collect(),
            pointer: format!("/records/{id}"),
            observed_at: instant(18),
        };
        case.inventory_observations = vec![
            observation("a", "run-1", "naabu", service.clone(), "asset-1"),
            observation(
                "b",
                "run-1",
                "httpx",
                InventoryObservationKind::Service {
                    endpoint: "10.0.0.5".into(),
                    port: Some(443),
                    transport: Some("tcp".into()),
                    scheme: Some("https".into()),
                    http_status: Some(200),
                    tls: Some(true),
                },
                "asset-1",
            ),
            observation(
                "c",
                "run-1",
                "syft",
                InventoryObservationKind::SoftwareComponent {
                    name: "openssl".into(),
                    version: Some("3.0.0".into()),
                    package_type: Some("deb".into()),
                    purl: Some("pkg:deb/openssl@3.0.0".into()),
                },
                "asset-1",
            ),
            observation(
                "c2",
                "run-1",
                "syft-second-source",
                InventoryObservationKind::SoftwareComponent {
                    name: "openssl renamed by another scanner".into(),
                    version: Some("3.0.0".into()),
                    package_type: Some("deb".into()),
                    purl: Some("pkg:deb/openssl@3.0.0".into()),
                },
                "asset-1",
            ),
            observation(
                "d",
                "run-1",
                "cloudquery",
                InventoryObservationKind::CloudResource {
                    resource_type: "aws_s3_bucket".into(),
                    native_id: Some("bucket-1".into()),
                    display_name: Some("uploads".into()),
                },
                "asset-2",
            ),
            observation(
                "d2",
                "run-1",
                "cloudquery-second-source",
                InventoryObservationKind::CloudResource {
                    resource_type: "aws_s3_bucket".into(),
                    native_id: Some("bucket-1".into()),
                    display_name: Some("uploads-renamed".into()),
                },
                "asset-2",
            ),
            observation(
                "e",
                "run-1",
                "syft",
                InventoryObservationKind::SoftwareComponent {
                    name: "curl".into(),
                    version: Some("8.0.0".into()),
                    package_type: Some("deb".into()),
                    purl: Some("pkg:deb/curl@8.0.0".into()),
                },
                "asset-2",
            ),
            observation(
                "newer",
                "run-newer",
                "syft",
                InventoryObservationKind::SoftwareComponent {
                    name: "must-not-drift".into(),
                    version: None,
                    package_type: None,
                    purl: None,
                },
                "asset-1",
            ),
        ];

        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.inventory.total, 4);
        assert_eq!(report.inventory.counts.services, 1);
        assert_eq!(report.inventory.counts.software_components, 2);
        assert_eq!(report.inventory.counts.cloud_resources, 1);
        assert_eq!(report.inventory.asset_ids, ["asset-1", "asset-2"]);
        assert_eq!(report.inventory.representative_sample.len(), 3);
        assert_eq!(report.inventory.by_asset.len(), 2);
        let service = report
            .inventory
            .items
            .iter()
            .find(|item| matches!(item.details, BeginnerInventoryItemKind::Service { .. }))
            .unwrap();
        assert_eq!(service.sources.len(), 2);
        assert_eq!(
            service
                .sources
                .iter()
                .map(|source| source.engine_id.as_str())
                .collect::<Vec<_>>(),
            ["naabu", "httpx"]
        );
        let openssl = report
            .inventory
            .items
            .iter()
            .find(|item| {
                matches!(
                    &item.details,
                    BeginnerInventoryItemKind::SoftwareComponent { purl: Some(purl), .. }
                        if purl == "pkg:deb/openssl@3.0.0"
                )
            })
            .unwrap();
        assert_eq!(openssl.sources.len(), 2);
        let cloud = report
            .inventory
            .items
            .iter()
            .find(|item| {
                matches!(
                    item.details,
                    BeginnerInventoryItemKind::CloudResource { .. }
                )
            })
            .unwrap();
        assert_eq!(cloud.sources.len(), 2);
        assert!(
            !serde_json::to_string(&report.inventory)
                .unwrap()
                .contains("must-not-drift")
        );
    }

    #[test]
    fn legacy_result_kind_is_conservative_for_known_non_security_checks() {
        for check_id in [
            "cloudquery",
            "cloudquery-aws",
            "steampipe",
            "steampipe-aws",
            "syft",
            "syft-repository",
            "naabu",
            "httpx-service",
        ] {
            assert_eq!(
                legacy_check_result_kind(check_id),
                CheckResultKind::Inventory,
                "legacy {check_id} must not become a clean security result"
            );
        }
        assert_eq!(
            legacy_check_result_kind("native localhost TCP check on 127.0.0.1:9001"),
            CheckResultKind::Connectivity
        );
        assert_eq!(
            legacy_check_result_kind("trivy"),
            CheckResultKind::SecurityCheck
        );
    }

    #[test]
    fn derived_confidence_orders_tied_findings_by_evidence_strength() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        let mut low = frozen_finding(&case, "finding-a-low", 80, Severity::High);
        low.confidence = Confidence::Low;
        low.confidence_basis_code =
            Some(crate::domain::ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch);
        let mut medium = frozen_finding(&case, "finding-m-medium", 80, Severity::High);
        medium.confidence = Confidence::Medium;
        medium.confidence_basis_code = Some(crate::domain::ConfidenceBasisCode::TemplateMatcher);
        let mut high = frozen_finding(&case, "finding-z-high", 80, Severity::High);
        high.confidence_basis_code =
            Some(crate::domain::ConfidenceBasisCode::DeterministicPolicyEvaluation);
        case.findings = vec![low.clone(), medium.clone(), high.clone()];
        case.finding_observations = vec![
            observation(&low, "run-1", instant(17)),
            observation(&medium, "run-1", instant(18)),
            observation(&high, "run-1", instant(18)),
        ];

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.findings[0].finding_id, "finding-z-high");
        assert_eq!(report.findings[0].confidence, Confidence::High);
        assert_eq!(report.findings[1].finding_id, "finding-m-medium");
        assert_eq!(report.findings[1].confidence, Confidence::Medium);
        assert_eq!(report.findings[2].finding_id, "finding-a-low");
        assert_eq!(report.findings[2].confidence, Confidence::Low);
    }

    #[test]
    fn active_groups_project_selected_and_historical_members_without_changing_run_results() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        let selected = frozen_finding(&case, "finding-selected", 90, Severity::High);
        let historical = frozen_finding(&case, "finding-historical", 40, Severity::Medium);
        let other_historical = frozen_finding(&case, "finding-other-historical", 10, Severity::Low);
        case.findings = vec![
            selected.clone(),
            historical.clone(),
            other_historical.clone(),
        ];
        case.finding_observations = vec![observation(&selected, "run-1", instant(18))];

        let without_groups = build_beginner_master_report(&case, "run-1").unwrap();
        case.finding_groups = vec![
            FindingGroup {
                id: "group-mixed".into(),
                case_id: case.id.clone(),
                title: "Related observations".into(),
                finding_ids: vec![selected.id.clone(), historical.id.clone()],
                rationale: "Review the shared path together.".into(),
                grouped_by: "Human reviewer".into(),
                created_at: instant(19),
            },
            FindingGroup {
                id: "group-history-only".into(),
                case_id: case.id.clone(),
                title: "Historical observations".into(),
                finding_ids: vec![historical.id.clone(), other_historical.id.clone()],
                rationale: "This group has no selected-run observation.".into(),
                grouped_by: "Human reviewer".into(),
                created_at: instant(20),
            },
        ];

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.schema_version, "1.1.0");
        assert_eq!(report.finding_groups.len(), 1);
        let group = &report.finding_groups[0];
        assert_eq!(group.group_id, "group-mixed");
        assert_eq!(
            group.presentation_scope,
            FindingGroupPresentationScope::CurrentCasePresentation
        );
        assert_eq!(group.title, "Related observations");
        assert_eq!(group.rationale, "Review the shared path together.");
        assert_eq!(group.actor, "Human reviewer");
        assert_eq!(group.created_at, instant(19));
        assert_eq!(
            group.members,
            vec![
                BeginnerFindingGroupMember {
                    finding_id: "finding-selected".into(),
                    observed_in_selected_run: true,
                },
                BeginnerFindingGroupMember {
                    finding_id: "finding-historical".into(),
                    observed_in_selected_run: false,
                },
            ]
        );
        let report_json = serde_json::to_value(&report).unwrap();
        assert_eq!(
            report_json.pointer("/finding_groups/0/presentation_scope"),
            Some(&serde_json::json!("current_case_presentation"))
        );

        assert_eq!(report.findings, without_groups.findings);
        assert_eq!(report.requested, without_groups.requested);
        assert_eq!(report.actual, without_groups.actual);
        assert_eq!(report.coverage_gaps, without_groups.coverage_gaps);
        assert_eq!(report.coverage_counts, without_groups.coverage_counts);
        assert_eq!(report.next_steps, without_groups.next_steps);
    }

    #[test]
    fn legacy_report_without_group_projection_deserializes_with_an_empty_projection() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        let finding = frozen_finding(&case, "finding-legacy", 50, Severity::Medium);
        case.findings.push(finding.clone());
        case.finding_observations
            .push(observation(&finding, "run-1", instant(18)));
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let mut legacy = serde_json::to_value(report).unwrap();
        let legacy = legacy.as_object_mut().unwrap();
        legacy.insert("schema_version".into(), serde_json::json!("1.0.0"));
        legacy.remove("finding_groups");
        legacy.remove("inventory");
        legacy
            .get_mut("actual")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|actual| actual.get_mut("checks"))
            .and_then(serde_json::Value::as_array_mut)
            .and_then(|checks| checks.first_mut())
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .remove("result_kind");
        let legacy_finding = legacy
            .get_mut("findings")
            .and_then(serde_json::Value::as_array_mut)
            .and_then(|findings| findings.first_mut())
            .and_then(serde_json::Value::as_object_mut)
            .unwrap();
        legacy_finding.remove("official_references");
        let legacy_evidence = legacy_finding
            .get_mut("evidence_references")
            .and_then(serde_json::Value::as_array_mut)
            .and_then(|references| references.first_mut())
            .and_then(serde_json::Value::as_object_mut)
            .unwrap();
        for field in [
            "details_frozen",
            "source_rule",
            "scanner_details",
            "summary",
            "kind",
            "engine_run_id",
            "artifact_id",
            "redacted",
        ] {
            legacy_evidence.remove(field);
        }

        let decoded: BeginnerMasterReport =
            serde_json::from_value(serde_json::Value::Object(legacy.clone())).unwrap();
        assert_eq!(decoded.schema_version, "1.0.0");
        assert!(decoded.finding_groups.is_empty());
        assert_eq!(decoded.inventory, BeginnerInventory::default());
        assert_eq!(decoded.actual.checks[0].result_kind, None);
        assert_eq!(
            decoded.actual.checks[0].effective_result_kind(),
            CheckResultKind::Connectivity
        );
        let decoded_finding = &decoded.findings[0];
        assert!(decoded_finding.official_references.is_none());
        let decoded_evidence = &decoded_finding.evidence_references[0];
        assert!(!decoded_evidence.details_frozen);
        assert!(decoded_evidence.source_rule.is_none());
        assert!(decoded_evidence.scanner_details.is_none());
        assert!(decoded_evidence.summary.is_none());
        assert!(decoded_evidence.kind.is_none());
        assert!(decoded_evidence.engine_run_id.is_none());
        assert!(decoded_evidence.artifact_id.is_none());
        assert!(decoded_evidence.redacted.is_none());
    }

    pub(crate) fn frozen_finding(
        case: &AssessmentCase,
        id: &str,
        priority: u8,
        severity: Severity,
    ) -> Finding {
        Finding {
            family: None,
            severity_basis_code: None,
            confidence_basis_code: None,
            context_factors: Vec::new(),
            id: id.into(),
            case_id: case.id.clone(),
            first_seen_run_id: "run-1".into(),
            last_seen_run_id: "run-1".into(),
            fingerprint: format!("fingerprint-{id}"),
            title: format!("Frozen {id}"),
            plain_language_summary: "Plain-language risk".into(),
            possible_impact: "Possible impact".into(),
            severity,
            confidence: Confidence::High,
            priority,
            priority_reasons: vec!["exposed".into()],
            asset_ids: vec!["localhost-asset".into()],
            evidence: vec![Evidence {
                id: format!("evidence-{id}"),
                finding_id: id.into(),
                run_id: "run-1".into(),
                engine_run_id: Some("task-1".into()),
                kind: EvidenceKind::Observation,
                engine_id: BUILT_IN_LOCALHOST_TCP_ENGINE_ID.into(),
                scanner_details: None,
                source_rule: Some(format!("upstream-rule-{id}")),
                result_pointer_sha256: None,
                observed_at: instant(17),
                summary: "Evidence".into(),
                location: Some("src/config.ts:42".into()),
                artifact_id: format!("artifact-{id}"),
                artifact_sha256: format!("hash-{id}"),
                pointer: None,
                redacted: true,
            }],
            control_references: vec![ControlReference {
                framework: "NIST CSF".into(),
                framework_version: "2.0".into(),
                control_id: "ID.AM-01".into(),
                title: "Assets inventoried".into(),
                relationship: "related".into(),
                rationale: "Navigation only".into(),
                mapping_version: "test-map".into(),
                mapping_provenance: None,
            }],
            recommendation: "Review this finding.".into(),
            verification_guidance: "Scan again after review.".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Security engineer".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![],
        }
    }

    pub(crate) fn observation(
        finding: &Finding,
        run_id: &str,
        observed_at: DateTime<Utc>,
    ) -> FindingObservation {
        FindingObservation {
            id: new_id(),
            run_id: run_id.into(),
            finding_id: finding.id.clone(),
            fingerprint: finding.fingerprint.clone(),
            asset_ids: finding.asset_ids.clone(),
            engine_ids: vec![BUILT_IN_LOCALHOST_TCP_ENGINE_ID.into()],
            severity: finding.severity.clone(),
            confidence: finding.confidence.clone(),
            evidence_hashes: finding
                .evidence
                .iter()
                .map(|evidence| evidence.artifact_sha256.clone())
                .collect(),
            observed_at,
            finding_snapshot: Some(finding.clone()),
        }
    }

    fn add_nuclei_record(
        case: &mut AssessmentCase,
        finding_id: &str,
        asset_id: &str,
        engine_run_id: &str,
    ) {
        let mut finding = frozen_finding(case, finding_id, 70, Severity::Medium);
        finding.asset_ids = vec![asset_id.into()];
        finding.evidence[0].engine_run_id = Some(engine_run_id.into());
        finding.evidence[0].engine_id = NUCLEI_ENGINE_ID.into();
        finding.evidence[0].kind = EvidenceKind::ExternalValidation;
        finding.evidence[0].source_rule = Some("upstream-nuclei-template".into());
        let mut retained = observation(&finding, "run-1", instant(18));
        retained.asset_ids = vec![asset_id.into()];
        retained.engine_ids = vec![NUCLEI_ENGINE_ID.into()];
        case.findings.push(finding);
        case.finding_observations.push(retained);
        let task = case.scan_runs[0]
            .engine_runs
            .iter_mut()
            .find(|task| task.id == engine_run_id)
            .expect("Nuclei task");
        if !task
            .security_template_executions
            .iter()
            .any(|execution| execution.asset_id == asset_id)
        {
            task.security_template_executions
                .push(SecurityTemplateExecution {
                    asset_id: asset_id.into(),
                    result_count: 1,
                });
        }
    }

    fn internal_device_case(profile: DeclaredWebServiceScanProfile) -> AssessmentCase {
        let profile_name = match profile {
            DeclaredWebServiceScanProfile::InternalDeviceHttps => "internal_device_https",
        };
        let mut case = empty_case();
        case.assets.push(Asset {
            id: "device-asset".into(),
            kind: AssetKind::WebService,
            name: "Internal management endpoint".into(),
            provider: None,
            region: None,
            identifiers: vec![AssetIdentifier {
                namespace: "web_origin".into(),
                value: "https://10.20.0.9:443".into(),
            }],
            discovered_from: vec!["questionnaire".into()],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(false),
            contains_sensitive_data: None,
            metadata: BTreeMap::from([(
                "declared_web_service".into(),
                serde_json::json!({
                    "protocol": "https",
                    "port": 443,
                    "path": "/",
                    "scan_profile": profile_name,
                }),
            )]),
        });

        let allowed_template_ids = INTERNAL_DEVICE_TLS_VULNERABILITY_OIDS
            .iter()
            .map(|oid| (*oid).to_owned())
            .collect::<Vec<_>>();
        let external_scope = ExternalScopeGrant {
            id: "external-device-grant".into(),
            case_id: case.id.clone(),
            asset_id: "device-asset".into(),
            target: CanonicalTarget::Address("10.20.0.9".parse().unwrap()),
            ports: BTreeSet::from([443]),
            protocol: TransportProtocol::Https,
            activity: ExternalActivity::ActiveExternal,
            rate_policy: RatePolicy {
                requests_per_second: 2,
                concurrency: 1,
                timeout_seconds: 15,
            },
            template_policy: TemplatePolicy::conservative(
                INTERNAL_DEVICE_TEMPLATE_REVISION,
                allowed_template_ids,
            ),
            asserted_authority: "Approved internal endpoint".into(),
            approved_by: "Target owner".into(),
            approved_at: instant(9),
            expires_at: instant(3_609),
            allow_sensitive_networks: true,
        };
        let mut task = catalog_task("device", EngineRunStatus::Completed);
        task.engine_id = GREENBONE_ENGINE_ID.into();
        task.asset_ids = vec!["device-asset".into()];
        task.progress_percent = 100;
        task.phase = "completed".into();
        task.exit_code = Some(0);
        task.error_message = None;

        case.scan_runs.push(ScanRun {
            id: "run-1".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: instant(10),
            completed_at: Some(instant(20)),
            request_outcome: None,
            report_asset_snapshots: Vec::new(),
            knowledge_cutoff: instant(10),
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec!["grant-device".into()],
            scope_grant_snapshots: vec![ScopeGrant {
                id: "grant-device".into(),
                asset_id: "device-asset".into(),
                permission: crate::domain::ScanPermission::ActiveExternalTesting,
                confirmed_by: "Target owner".into(),
                confirmed_at: instant(9),
                expires_at: Some(instant(3_609)),
                authorization_reference: Some("Approved internal endpoint".into()),
                notes: None,
                external_scope: Some(external_scope),
            }],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![task],
        });
        case
    }

    fn internal_host_case() -> AssessmentCase {
        let mut case = empty_case();
        case.assets.push(Asset {
            id: "host-asset".into(),
            kind: AssetKind::Host,
            name: "10.20.0.50".into(),
            provider: None,
            region: None,
            identifiers: vec![AssetIdentifier {
                namespace: "ip_address".into(),
                value: "10.20.0.50".into(),
            }],
            discovered_from: vec!["questionnaire".into()],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(false),
            contains_sensitive_data: None,
            metadata: BTreeMap::from([(
                "declared_host_scan".into(),
                serde_json::json!({
                    "target": "10.20.0.50",
                    "protocol": "tcp",
                    "ports": [22, 443],
                    "profile": GREENBONE_REMOTE_SAFE_PROFILE_ID,
                }),
            )]),
        });

        let external_scope = ExternalScopeGrant {
            id: "external-host-grant".into(),
            case_id: case.id.clone(),
            asset_id: "host-asset".into(),
            target: CanonicalTarget::Address("10.20.0.50".parse().unwrap()),
            ports: BTreeSet::from([22, 443]),
            protocol: TransportProtocol::Tcp,
            activity: ExternalActivity::ActiveExternal,
            rate_policy: RatePolicy {
                requests_per_second: 2,
                concurrency: 1,
                timeout_seconds: 15,
            },
            template_policy: TemplatePolicy::conservative_profile(
                INTERNAL_DEVICE_TEMPLATE_REVISION,
                GREENBONE_REMOTE_SAFE_PROFILE_ID,
            ),
            asserted_authority: "Approved internal host".into(),
            approved_by: "Target owner".into(),
            approved_at: instant(9),
            expires_at: instant(3_609),
            allow_sensitive_networks: true,
        };
        let mut task = catalog_task("host", EngineRunStatus::Completed);
        task.engine_id = GREENBONE_ENGINE_ID.into();
        task.asset_ids = vec!["host-asset".into()];
        task.progress_percent = 100;
        task.phase = "completed".into();
        task.exit_code = Some(0);
        task.error_message = None;

        case.scan_runs.push(ScanRun {
            id: "run-1".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: instant(10),
            completed_at: Some(instant(20)),
            request_outcome: None,
            report_asset_snapshots: vec![ReportAssetSnapshot {
                asset: case.assets[0].clone(),
                disposition: ReportAssetDisposition::RequestedForScan,
            }],
            knowledge_cutoff: instant(10),
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec!["grant-host".into()],
            scope_grant_snapshots: vec![ScopeGrant {
                id: "grant-host".into(),
                asset_id: "host-asset".into(),
                permission: crate::domain::ScanPermission::ActiveExternalTesting,
                confirmed_by: "Target owner".into(),
                confirmed_at: instant(9),
                expires_at: Some(instant(3_609)),
                authorization_reference: Some("Approved internal host".into()),
                notes: None,
                external_scope: Some(external_scope),
            }],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![task],
        });
        case
    }

    fn nuclei_website_case() -> AssessmentCase {
        let mut case = internal_host_case();
        case.assets[0].id = "website-asset".into();
        case.assets[0].kind = AssetKind::WebService;
        case.assets[0].name = "https://app.example.test:443".into();
        case.assets[0].identifiers = vec![AssetIdentifier {
            namespace: "web_origin".into(),
            value: "https://app.example.test:443".into(),
        }];
        case.assets[0].internet_exposed = Some(true);
        case.assets[0].metadata = BTreeMap::from([(
            "declared_web_service".into(),
            serde_json::json!({
                "protocol": "https",
                "port": 443,
                "path": "/",
            }),
        )]);

        let run = &mut case.scan_runs[0];
        run.report_asset_snapshots[0].asset = case.assets[0].clone();
        run.scope_grant_snapshots[0].asset_id = "website-asset".into();
        let scope = run.scope_grant_snapshots[0]
            .external_scope
            .as_mut()
            .expect("website scope");
        scope.asset_id = "website-asset".into();
        scope.target = CanonicalTarget::Hostname("app.example.test".into());
        scope.ports = BTreeSet::from([443]);
        scope.protocol = TransportProtocol::Https;
        scope.rate_policy = RatePolicy {
            requests_per_second: 10,
            concurrency: 5,
            timeout_seconds: 10,
        };
        scope.template_policy = TemplatePolicy::conservative_profile(
            NUCLEI_TEMPLATE_REVISION,
            NUCLEI_WEB_SAFE_PROFILE_ID,
        );
        scope.allow_sensitive_networks = false;
        run.engine_runs[0].engine_id = NUCLEI_ENGINE_ID.into();
        run.engine_runs[0].asset_ids = vec!["website-asset".into()];
        case
    }

    fn internal_endpoint_ssh_case() -> AssessmentCase {
        let mut case = empty_case();
        case.assets.push(Asset {
            id: "ssh-asset".into(),
            kind: AssetKind::Host,
            name: "tcp://10.20.0.11:2222".into(),
            provider: None,
            region: None,
            identifiers: vec![
                AssetIdentifier {
                    namespace: "network_service_endpoint".into(),
                    value: "tcp://10.20.0.11:2222".into(),
                },
                AssetIdentifier {
                    namespace: "ip_address".into(),
                    value: "10.20.0.11".into(),
                },
            ],
            discovered_from: vec!["questionnaire".into()],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(false),
            contains_sensitive_data: None,
            metadata: BTreeMap::from([(
                "declared_network_service".into(),
                serde_json::json!({
                    "target": "10.20.0.11",
                    "protocol": "tcp",
                    "port": 2222,
                    "scan_profile": "internal_endpoint_ssh",
                }),
            )]),
        });

        let external_scope = ExternalScopeGrant {
            id: "external-ssh-grant".into(),
            case_id: case.id.clone(),
            asset_id: "ssh-asset".into(),
            target: CanonicalTarget::Address("10.20.0.11".parse().unwrap()),
            ports: BTreeSet::from([2222]),
            protocol: TransportProtocol::Tcp,
            activity: ExternalActivity::ActiveExternal,
            rate_policy: RatePolicy {
                requests_per_second: 2,
                concurrency: 1,
                timeout_seconds: 15,
            },
            template_policy: TemplatePolicy::conservative(
                INTERNAL_DEVICE_TEMPLATE_REVISION,
                INTERNAL_ENDPOINT_SSH_VULNERABILITY_OIDS
                    .iter()
                    .map(|oid| (*oid).to_owned())
                    .collect(),
            ),
            asserted_authority: "Approved SSH endpoint".into(),
            approved_by: "Target owner".into(),
            approved_at: instant(9),
            expires_at: instant(3_609),
            allow_sensitive_networks: true,
        };
        let mut task = catalog_task("ssh", EngineRunStatus::Completed);
        task.engine_id = GREENBONE_ENGINE_ID.into();
        task.asset_ids = vec!["ssh-asset".into()];
        task.progress_percent = 100;
        task.phase = "completed".into();
        task.exit_code = Some(0);
        task.error_message = None;

        case.scan_runs.push(ScanRun {
            id: "run-1".into(),
            case_id: case.id.clone(),
            sequence: 1,
            created_at: instant(10),
            completed_at: Some(instant(20)),
            request_outcome: None,
            report_asset_snapshots: Vec::new(),
            knowledge_cutoff: instant(10),
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec!["grant-ssh".into()],
            scope_grant_snapshots: vec![ScopeGrant {
                id: "grant-ssh".into(),
                asset_id: "ssh-asset".into(),
                permission: crate::domain::ScanPermission::ActiveExternalTesting,
                confirmed_by: "Target owner".into(),
                confirmed_at: instant(9),
                expires_at: Some(instant(3_609)),
                authorization_reference: Some("Approved SSH endpoint".into()),
                notes: None,
                external_scope: Some(external_scope),
            }],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![task],
        });
        case
    }

    fn internal_endpoint_rdp_tls_case() -> AssessmentCase {
        let mut case = internal_endpoint_ssh_case();
        let asset = &mut case.assets[0];
        asset.id = "rdp-asset".into();
        asset.name = "tcp://10.20.0.12:3389".into();
        asset.identifiers = vec![
            AssetIdentifier {
                namespace: "network_service_endpoint".into(),
                value: "tcp://10.20.0.12:3389".into(),
            },
            AssetIdentifier {
                namespace: "ip_address".into(),
                value: "10.20.0.12".into(),
            },
        ];
        asset.metadata = BTreeMap::from([(
            "declared_network_service".into(),
            serde_json::json!({
                "target": "10.20.0.12",
                "protocol": "tcp",
                "port": 3389,
                "scan_profile": "internal_endpoint_rdp_tls",
            }),
        )]);

        let run = &mut case.scan_runs[0];
        run.scope_grant_ids = vec!["grant-rdp".into()];
        let grant = &mut run.scope_grant_snapshots[0];
        grant.id = "grant-rdp".into();
        grant.asset_id = "rdp-asset".into();
        grant.authorization_reference = Some("Approved RDP endpoint".into());
        let external = grant.external_scope.as_mut().unwrap();
        external.id = "external-rdp-grant".into();
        external.asset_id = "rdp-asset".into();
        external.target = CanonicalTarget::Address("10.20.0.12".parse().unwrap());
        external.ports = BTreeSet::from([3389]);
        external.template_policy = TemplatePolicy::conservative(
            INTERNAL_DEVICE_TEMPLATE_REVISION,
            INTERNAL_ENDPOINT_RDP_TLS_VULNERABILITY_OIDS
                .iter()
                .map(|oid| (*oid).to_owned())
                .collect(),
        );
        external.asserted_authority = "Approved RDP endpoint".into();

        let task = &mut run.engine_runs[0];
        task.id = "rdp-tls".into();
        task.asset_ids = vec!["rdp-asset".into()];
        case
    }

    fn internal_endpoint_vnc_case() -> AssessmentCase {
        let mut case = internal_endpoint_ssh_case();
        let asset = &mut case.assets[0];
        asset.id = "vnc-asset".into();
        asset.name = "tcp://vnc.example.test:5900".into();
        asset.identifiers = vec![
            AssetIdentifier {
                namespace: "network_service_endpoint".into(),
                value: "tcp://vnc.example.test:5900".into(),
            },
            AssetIdentifier {
                namespace: "hostname".into(),
                value: "vnc.example.test".into(),
            },
        ];
        asset.metadata = BTreeMap::from([(
            "declared_network_service".into(),
            serde_json::json!({
                "target": "vnc.example.test",
                "protocol": "tcp",
                "port": 5900,
                "scan_profile": "internal_endpoint_vnc",
            }),
        )]);

        let run = &mut case.scan_runs[0];
        run.scope_grant_ids = vec!["grant-vnc".into()];
        let grant = &mut run.scope_grant_snapshots[0];
        grant.id = "grant-vnc".into();
        grant.asset_id = "vnc-asset".into();
        grant.authorization_reference = Some("Approved VNC endpoint".into());
        let external = grant.external_scope.as_mut().unwrap();
        external.id = "external-vnc-grant".into();
        external.asset_id = "vnc-asset".into();
        external.target = CanonicalTarget::Hostname("vnc.example.test".into());
        external.ports = BTreeSet::from([5900]);
        external.template_policy = TemplatePolicy::conservative(
            INTERNAL_DEVICE_TEMPLATE_REVISION,
            INTERNAL_ENDPOINT_VNC_VULNERABILITY_OIDS
                .iter()
                .map(|oid| (*oid).to_owned())
                .collect(),
        );
        external.asserted_authority = "Approved VNC endpoint".into();

        let task = &mut run.engine_runs[0];
        task.id = "vnc-transport".into();
        task.asset_ids = vec!["vnc-asset".into()];
        case
    }

    fn internal_endpoint_smtp_case() -> AssessmentCase {
        let mut case = internal_endpoint_ssh_case();
        let asset = &mut case.assets[0];
        asset.id = "smtp-asset".into();
        asset.name = "tcp://smtp.example.test:25".into();
        asset.identifiers = vec![
            AssetIdentifier {
                namespace: "network_service_endpoint".into(),
                value: "tcp://smtp.example.test:25".into(),
            },
            AssetIdentifier {
                namespace: "hostname".into(),
                value: "smtp.example.test".into(),
            },
        ];
        asset.metadata = BTreeMap::from([(
            "declared_network_service".into(),
            serde_json::json!({
                "target": "smtp.example.test",
                "protocol": "tcp",
                "port": 25,
                "scan_profile": "internal_endpoint_smtp",
            }),
        )]);

        let run = &mut case.scan_runs[0];
        run.scope_grant_ids = vec!["grant-smtp".into()];
        let grant = &mut run.scope_grant_snapshots[0];
        grant.id = "grant-smtp".into();
        grant.asset_id = "smtp-asset".into();
        grant.authorization_reference = Some("Approved SMTP endpoint".into());
        let external = grant.external_scope.as_mut().unwrap();
        external.id = "external-smtp-grant".into();
        external.asset_id = "smtp-asset".into();
        external.target = CanonicalTarget::Hostname("smtp.example.test".into());
        external.ports = BTreeSet::from([25]);
        external.template_policy = TemplatePolicy::conservative(
            INTERNAL_DEVICE_TEMPLATE_REVISION,
            INTERNAL_ENDPOINT_SMTP_VULNERABILITY_OIDS
                .iter()
                .map(|oid| (*oid).to_owned())
                .collect(),
        );
        external.asserted_authority = "Approved SMTP endpoint".into();

        let task = &mut run.engine_runs[0];
        task.id = "smtp-transport".into();
        task.asset_ids = vec!["smtp-asset".into()];
        case
    }

    fn add_smtp_tls_finding_evidence(case: &mut AssessmentCase, oid: &str, suffix: &str) {
        let mut finding = frozen_finding(case, &format!("smtp-tls-{suffix}"), 70, Severity::Medium);
        finding.asset_ids = vec!["smtp-asset".into()];
        let evidence = &mut finding.evidence[0];
        evidence.run_id = "run-1".into();
        evidence.engine_run_id = Some("smtp-transport".into());
        evidence.engine_id = GREENBONE_ENGINE_ID.into();
        evidence.source_rule = Some(oid.into());
        evidence.artifact_sha256 = format!("smtp-artifact-{suffix}");

        let mut retained = observation(&finding, "run-1", instant(18));
        retained.engine_ids = vec![GREENBONE_ENGINE_ID.into()];
        case.findings.push(finding);
        case.finding_observations.push(retained);
    }

    fn internal_endpoint_telnet_case() -> AssessmentCase {
        let mut case = internal_endpoint_ssh_case();
        let asset = &mut case.assets[0];
        asset.id = "telnet-asset".into();
        asset.name = "tcp://10.20.0.23:23".into();
        asset.identifiers = vec![
            AssetIdentifier {
                namespace: "network_service_endpoint".into(),
                value: "tcp://10.20.0.23:23".into(),
            },
            AssetIdentifier {
                namespace: "ip_address".into(),
                value: "10.20.0.23".into(),
            },
        ];
        asset.metadata = BTreeMap::from([(
            "declared_network_service".into(),
            serde_json::json!({
                "target": "10.20.0.23",
                "protocol": "tcp",
                "port": 23,
                "scan_profile": "internal_endpoint_telnet",
            }),
        )]);

        let run = &mut case.scan_runs[0];
        run.scope_grant_ids = vec!["grant-telnet".into()];
        let grant = &mut run.scope_grant_snapshots[0];
        grant.id = "grant-telnet".into();
        grant.asset_id = "telnet-asset".into();
        grant.authorization_reference = Some("Approved Telnet endpoint".into());
        let external = grant.external_scope.as_mut().unwrap();
        external.id = "external-telnet-grant".into();
        external.asset_id = "telnet-asset".into();
        external.target = CanonicalTarget::Address("10.20.0.23".parse().unwrap());
        external.ports = BTreeSet::from([23]);
        external.template_policy = TemplatePolicy::conservative(
            INTERNAL_DEVICE_TEMPLATE_REVISION,
            INTERNAL_ENDPOINT_TELNET_VULNERABILITY_OIDS
                .iter()
                .map(|oid| (*oid).to_owned())
                .collect(),
        );
        external.asserted_authority = "Approved Telnet endpoint".into();

        let task = &mut run.engine_runs[0];
        task.id = "telnet-transport".into();
        task.asset_ids = vec!["telnet-asset".into()];
        case
    }

    #[test]
    fn exact_completed_ssh_profile_is_meaningful_but_keeps_host_level_limits_visible() {
        let case = internal_endpoint_ssh_case();
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.requested.targets.len(), 1);
        assert_eq!(
            report.requested.targets[0].label.as_deref(),
            Some("ssh://10.20.0.11:2222")
        );
        assert_eq!(
            report.requested.targets[0].asset_kind,
            Some(AssetKind::Host)
        );
        assert_eq!(
            report.requested.targets[0].label_availability,
            DataAvailability::Recorded
        );
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedComplete
        );
        assert!(
            report.actual.checks[0]
                .tested_dimensions
                .iter()
                .any(|dimension| dimension.dimension == "SSH service vulnerability checks")
        );
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension.contains("operating-system"))
            .expect("host-level SSH exclusions remain visible");
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert_eq!(gap.target_asset_ids, ["ssh-asset"]);
        assert!(
            report
                .coverage_gaps
                .iter()
                .filter(|gap| gap.kind == CoverageGapKind::Unavailable)
                .all(|gap| gap.target_asset_ids.is_empty()),
            "missing run metadata stays visible without turning every asset into a failed check"
        );
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
    }

    #[test]
    fn exact_completed_rdp_tls_profile_is_meaningful_but_keeps_rdp_and_host_limits_visible() {
        let case = internal_endpoint_rdp_tls_case();
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.requested.targets.len(), 1);
        assert_eq!(
            report.requested.targets[0].label.as_deref(),
            Some("rdp://10.20.0.12:3389")
        );
        assert_eq!(
            report.requested.targets[0].asset_kind,
            Some(AssetKind::Host)
        );
        assert_eq!(
            report.requested.targets[0].label_availability,
            DataAvailability::Recorded
        );
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedComplete
        );
        let tested = report.actual.checks[0]
            .tested_dimensions
            .iter()
            .find(|dimension| dimension.dimension == "RDP transport security checks")
            .expect("the exact frozen RDP transport profile is meaningful coverage");
        assert!(tested.value.starts_with("11 frozen upstream Greenbone"));
        assert!(tested.observation.contains("ten TLS"));
        assert!(tested.observation.contains("RDP 5.2 or earlier"));
        assert!(
            report.actual.checks[0]
                .tested_dimensions
                .iter()
                .all(|dimension| dimension.dimension != "SSH service vulnerability checks")
        );
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension.contains("authentication/NLA"))
            .expect("RDP and host-level exclusions remain visible");
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert_eq!(gap.task_id.as_deref(), Some("rdp-tls"));
        assert_eq!(gap.target_asset_ids, ["rdp-asset"]);
        for exclusion in [
            "Windows patch level",
            "broader or current RDP implementation CVEs",
            "authentication",
            "Network Level Authentication (NLA)",
            "installed packages or applications",
            "local host configuration",
        ] {
            assert!(gap.reason.contains(exclusion), "missing {exclusion}");
        }
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);

        let mut later_project_edit = case.clone();
        later_project_edit.assets[0]
            .metadata
            .get_mut("declared_network_service")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .insert(
                "scan_profile".into(),
                serde_json::json!("internal_endpoint_ssh"),
            );
        later_project_edit.assets[0].name = "Changed after the run".into();
        assert_eq!(
            report,
            build_beginner_master_report(&later_project_edit, "run-1").unwrap(),
            "the frozen RDP grant must win over mutable project metadata"
        );
    }

    #[test]
    fn completed_rdp_process_with_a_mismatched_allowlist_remains_not_tested() {
        let mut case = internal_endpoint_rdp_tls_case();
        case.scan_runs[0].scope_grant_snapshots[0]
            .external_scope
            .as_mut()
            .unwrap()
            .template_policy
            .allowed_template_ids
            .retain(|oid| oid != "1.3.6.1.4.1.25623.1.0.902658");

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::NotTested
        );
        assert!(
            report.actual.checks[0]
                .tested_dimensions
                .iter()
                .all(|dimension| dimension.dimension != "RDP transport security checks")
        );
        assert_eq!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );
        assert!(report.coverage_gaps.iter().any(|gap| {
            gap.target_asset_ids == ["rdp-asset"]
                && gap.dimension == "RDP transport endpoint scan-profile coverage"
        }));
    }

    #[test]
    fn exact_completed_vnc_profile_is_meaningful_but_keeps_vnc_and_host_limits_visible() {
        let case = internal_endpoint_vnc_case();
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.requested.targets.len(), 1);
        assert_eq!(
            report.requested.targets[0].label.as_deref(),
            Some("vnc://vnc.example.test:5900")
        );
        assert_eq!(
            report.requested.targets[0].asset_kind,
            Some(AssetKind::Host)
        );
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedComplete
        );
        let tested = report.actual.checks[0]
            .tested_dimensions
            .iter()
            .find(|dimension| dimension.dimension == "VNC transport security check")
            .expect("the exact frozen VNC transport profile is meaningful coverage");
        assert!(tested.value.starts_with("1 frozen upstream Greenbone"));
        assert!(tested.observation.contains("unencrypted VNC connection"));
        assert!(
            report.actual.checks[0]
                .tested_dimensions
                .iter()
                .all(|dimension| dimension.dimension != "RDP transport security checks")
        );

        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension.contains("VNC implementation"))
            .expect("VNC and host-level exclusions remain visible");
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert_eq!(gap.task_id.as_deref(), Some("vnc-transport"));
        assert_eq!(gap.target_asset_ids, ["vnc-asset"]);
        for exclusion in [
            "VNC implementation CVEs",
            "authentication strength",
            "operating-system patch level",
            "installed packages or applications",
            "local host configuration",
            "No login or desktop session was attempted",
        ] {
            assert!(gap.reason.contains(exclusion), "missing {exclusion}");
        }
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);

        let mut later_project_edit = case.clone();
        later_project_edit.assets[0]
            .metadata
            .get_mut("declared_network_service")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .insert(
                "scan_profile".into(),
                serde_json::json!("internal_endpoint_rdp_tls"),
            );
        later_project_edit.assets[0].name = "Changed after the run".into();
        assert_eq!(
            report,
            build_beginner_master_report(&later_project_edit, "run-1").unwrap(),
            "the frozen VNC grant must win over mutable project metadata"
        );
    }

    #[test]
    fn completed_vnc_process_with_a_mismatched_allowlist_remains_not_tested() {
        let mut case = internal_endpoint_vnc_case();
        case.scan_runs[0].scope_grant_snapshots[0]
            .external_scope
            .as_mut()
            .unwrap()
            .template_policy
            .allowed_template_ids
            .push("1.3.6.1.4.1.25623.1.0.111012".into());

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::NotTested
        );
        assert!(
            report.actual.checks[0]
                .tested_dimensions
                .iter()
                .all(|dimension| dimension.dimension != "VNC transport security check")
        );
        assert_eq!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );
        assert!(report.coverage_gaps.iter().any(|gap| {
            gap.target_asset_ids == ["vnc-asset"]
                && gap.dimension == "VNC transport endpoint scan-profile coverage"
        }));
    }

    #[test]
    fn exact_completed_smtp_profile_is_partial_without_tls_execution_evidence() {
        let case = internal_endpoint_smtp_case();
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(
            report.requested.targets[0].label.as_deref(),
            Some("smtp://smtp.example.test:25")
        );
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedPartial
        );
        let tested = report.actual.checks[0]
            .tested_dimensions
            .iter()
            .find(|dimension| dimension.dimension == "SMTP fixed security profile attempt")
            .expect("the exact frozen SMTP profile attempt remains visible");
        assert!(
            tested
                .value
                .starts_with("exact 11-check upstream Greenbone")
        );
        for detail in ["banner", "EHLO", "STARTTLS", "advertised AUTH"] {
            assert!(tested.observation.contains(detail), "missing {detail}");
        }
        assert!(
            tested
                .observation
                .contains("Credentials and mail: not sent")
        );
        assert!(
            tested
                .observation
                .contains("evidenced by selected-run source OIDs")
        );

        let tls_gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "SMTP TLS negotiation-dependent coverage")
            .expect("unproven TLS execution must remain visibly not tested");
        assert_eq!(tls_gap.kind, CoverageGapKind::NotTested);
        assert_eq!(tls_gap.task_id.as_deref(), Some("smtp-transport"));
        assert_eq!(tls_gap.target_asset_ids, ["smtp-asset"]);
        assert_eq!(
            tls_gap.reason,
            "The SMTP profile ran, but this scan did not record every one of its TLS checks. Which TLS checks ran is shown only by each finding's source OID."
        );

        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension.contains("SMTP server behavior"))
            .expect("SMTP application and host exclusions remain visible");
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert_eq!(gap.task_id.as_deref(), Some("smtp-transport"));
        assert_eq!(gap.target_asset_ids, ["smtp-asset"]);
        for exclusion in [
            "relay or delivery",
            "authentication enforcement or bypass",
            "anti-spam behavior",
            "general mail-server implementation CVEs",
            "operating-system patches",
            "installed software",
            "local configuration",
        ] {
            assert!(gap.reason.contains(exclusion), "missing {exclusion}");
        }
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);

        let mut later_project_edit = case.clone();
        later_project_edit.assets[0]
            .metadata
            .get_mut("declared_network_service")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .insert(
                "scan_profile".into(),
                serde_json::json!("internal_endpoint_telnet"),
            );
        later_project_edit.assets[0].name = "Changed after the run".into();
        assert_eq!(
            report,
            build_beginner_master_report(&later_project_edit, "run-1").unwrap(),
            "the frozen SMTP grant must win over mutable project metadata"
        );
    }

    #[test]
    fn one_smtp_tls_finding_evidences_only_its_exact_oid() {
        let mut case = internal_endpoint_smtp_case();
        add_smtp_tls_finding_evidence(
            &mut case,
            INTERNAL_ENDPOINT_SMTP_TLS_VULNERABILITY_OIDS[0],
            "one",
        );

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedPartial
        );
        let evidenced = report.actual.checks[0]
            .tested_dimensions
            .iter()
            .find(|dimension| dimension.dimension == "SMTP TLS checks with selected-run evidence")
            .expect("the exact selected-run TLS finding is visible");
        assert!(evidenced.value.starts_with("1 of 10 selected TLS checks"));
        assert!(
            evidenced
                .observation
                .contains("Each OID evidences only its own check")
        );
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.dimension == "SMTP TLS negotiation-dependent coverage")
        );
    }

    #[test]
    fn smtp_tls_coverage_completes_only_with_evidence_for_every_selected_oid() {
        let mut case = internal_endpoint_smtp_case();
        for (index, oid) in INTERNAL_ENDPOINT_SMTP_TLS_VULNERABILITY_OIDS
            .iter()
            .enumerate()
        {
            add_smtp_tls_finding_evidence(&mut case, oid, &index.to_string());
        }

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedComplete
        );
        let evidenced = report.actual.checks[0]
            .tested_dimensions
            .iter()
            .find(|dimension| dimension.dimension == "SMTP TLS checks with selected-run evidence")
            .expect("all exact selected-run TLS findings are visible");
        assert!(evidenced.value.starts_with("10 of 10 selected TLS checks"));
        assert!(
            report
                .coverage_gaps
                .iter()
                .all(|gap| gap.dimension != "SMTP TLS negotiation-dependent coverage")
        );
    }

    #[test]
    fn completed_smtp_profile_with_incomplete_tls_evidence_says_the_profile_ran() {
        let case = internal_endpoint_smtp_case();
        assert_eq!(
            case.scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Completed
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "SMTP TLS negotiation-dependent coverage")
            .expect("incomplete SMTP TLS evidence stays visible");
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert_eq!(
            gap.next_action_code,
            NextActionCode::PreserveVisibleLimitation
        );
        assert_eq!(
            gap.next_action,
            "Run a separately approved TLS assessment for complete SMTP TLS coverage."
        );
        assert_eq!(
            gap.reason,
            "The SMTP profile ran, but this scan did not record every one of its TLS checks. Which TLS checks ran is shown only by each finding's source OID."
        );
    }

    #[test]
    fn not_executed_smtp_profile_does_not_claim_its_tls_checks_ran() {
        let mut case = internal_endpoint_smtp_case();
        case.scan_runs[0].engine_runs[0].status = EngineRunStatus::NotExecuted;
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "SMTP TLS negotiation-dependent coverage")
            .expect("incomplete SMTP TLS evidence stays visible");
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert_eq!(
            gap.next_action_code,
            NextActionCode::PreserveVisibleLimitation
        );
        assert_eq!(
            gap.next_action,
            "Run a separately approved TLS assessment for complete SMTP TLS coverage."
        );
        assert_eq!(
            gap.reason,
            "This check did not complete, so its SMTP TLS checks cannot be shown as run. Which TLS checks ran is shown only by each finding's source OID."
        );
    }

    #[test]
    fn exact_completed_telnet_profile_is_meaningful_but_keeps_auth_and_host_limits_visible() {
        let case = internal_endpoint_telnet_case();
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(
            report.requested.targets[0].label.as_deref(),
            Some("telnet://10.20.0.23:23")
        );
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedComplete
        );
        let tested = report.actual.checks[0]
            .tested_dimensions
            .iter()
            .find(|dimension| dimension.dimension == "Telnet cleartext-login security check")
            .expect("the exact frozen Telnet profile is meaningful coverage");
        assert!(tested.value.starts_with("1 frozen upstream Greenbone"));
        assert!(tested.observation.contains("login or password prompt"));
        assert!(
            tested
                .observation
                .contains("No username or password was sent")
        );

        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension.contains("Telnet authentication"))
            .expect("Telnet authentication and host exclusions remain visible");
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert_eq!(gap.task_id.as_deref(), Some("telnet-transport"));
        assert_eq!(gap.target_asset_ids, ["telnet-asset"]);
        for exclusion in [
            "default credentials",
            "authentication bypass",
            "Telnet implementation CVEs",
            "operating-system patches",
            "installed software",
            "local configuration",
        ] {
            assert!(gap.reason.contains(exclusion), "missing {exclusion}");
        }
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
    }

    #[test]
    fn smtp_and_telnet_processes_with_mismatched_allowlists_remain_not_tested() {
        for (mut case, asset_id, dimension) in [
            (
                internal_endpoint_smtp_case(),
                "smtp-asset",
                "SMTP endpoint scan-profile coverage",
            ),
            (
                internal_endpoint_telnet_case(),
                "telnet-asset",
                "Telnet endpoint scan-profile coverage",
            ),
        ] {
            case.scan_runs[0].scope_grant_snapshots[0]
                .external_scope
                .as_mut()
                .unwrap()
                .template_policy
                .allowed_template_ids
                .push("1.3.6.1.4.1.25623.1.0.108094".into());

            let report = build_beginner_master_report(&case, "run-1").unwrap();
            assert_eq!(
                report.actual.checks[0].status,
                CoverageDimensionStatus::NotTested
            );
            assert_eq!(
                report.state.summary,
                BeginnerReportSummary::NoChecksCompleted
            );
            assert!(
                report.coverage_gaps.iter().any(|gap| {
                    gap.target_asset_ids == [asset_id] && gap.dimension == dimension
                })
            );
        }
    }

    #[test]
    fn mixed_environment_report_keeps_each_frozen_asset_and_marks_inventory_only_not_tested() {
        let mut case = internal_endpoint_ssh_case();
        case.assessment_intent = Some(AssessmentIntent::InternalItEnvironment);
        let inventory_asset = Asset {
            id: "inventory-only-asset".into(),
            kind: AssetKind::IpAddress,
            name: "Office inventory 10.20.0.50".into(),
            provider: None,
            region: None,
            identifiers: vec![AssetIdentifier {
                namespace: "ip_address".into(),
                value: "10.20.0.50".into(),
            }],
            discovered_from: vec!["questionnaire".into()],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(false),
            contains_sensitive_data: None,
            metadata: BTreeMap::from([(
                "questionnaire_kind".into(),
                serde_json::json!("external_target"),
            )]),
        };
        case.assets.push(inventory_asset.clone());
        case.scan_runs[0].report_asset_snapshots = vec![
            ReportAssetSnapshot {
                asset: case.assets[0].clone(),
                disposition: ReportAssetDisposition::RequestedForScan,
            },
            ReportAssetSnapshot {
                asset: inventory_asset,
                disposition: ReportAssetDisposition::NoSupportedProfile,
            },
        ];

        case.assets
            .iter_mut()
            .find(|asset| asset.id == "inventory-only-asset")
            .unwrap()
            .name = "Changed after the run".into();

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.requested.targets.len(), 2);
        let inventory_target = report
            .requested
            .targets
            .iter()
            .find(|target| target.asset_id == "inventory-only-asset")
            .unwrap();
        assert_eq!(
            inventory_target.label.as_deref(),
            Some("Office inventory 10.20.0.50")
        );
        assert_eq!(
            inventory_target.label_availability,
            DataAvailability::Recorded
        );
        let inventory_gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "supported vulnerability profile")
            .unwrap();
        assert_eq!(inventory_gap.kind, CoverageGapKind::NotTested);
        assert_eq!(inventory_gap.target_asset_ids, ["inventory-only-asset"]);
        assert_eq!(
            inventory_gap.reason,
            "Supported service-specific vulnerability profile unavailable. Outcome: not tested."
        );
        assert_eq!(
            inventory_gap.next_action,
            "Start a new scan and add each exact host under Internal systems."
        );
        assert_eq!(
            inventory_gap.next_action_code,
            NextActionCode::PreserveVisibleLimitation
        );

        let reopened: AssessmentCase =
            serde_json::from_str(&serde_json::to_string(&case).unwrap()).unwrap();
        assert_eq!(
            build_beginner_master_report(&reopened, "run-1").unwrap(),
            report
        );
    }

    #[test]
    fn partially_completed_check_with_no_saved_results_does_not_claim_durable_work() {
        let mut case = internal_host_case();
        {
            let task = &mut case.scan_runs[0].engine_runs[0];
            task.status = EngineRunStatus::PartiallyCompleted;
            task.phase = "cleanup_pending".into();
            // Cleanup-pending work keeps a checkpoint, and Progress offers Resume for it.
            let token = progress_resume_token(task, "cleanup_pending");
            task.resume_token = Some(token);
        }

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert!(report.findings.is_empty());
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension.contains("remaining requested dimensions"))
            .expect("partial check keeps a remaining-dimensions gap");
        assert_eq!(
            gap.reason,
            "This check did not reach a confirmed complete result."
        );
        assert!(!gap.reason.contains("durable work"), "{}", gap.reason);
        assert_eq!(gap.next_action, "Retry this check for a confirmed result.");
    }

    #[test]
    fn completed_generic_greenbone_host_profile_is_a_meaningful_upstream_scan() {
        let case = internal_host_case();
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedComplete
        );
        let tested = report.actual.checks[0]
            .tested_dimensions
            .iter()
            .find(|dimension| dimension.dimension == "Greenbone remote vulnerability scan")
            .expect("the frozen generic Greenbone profile is meaningful coverage");
        assert!(tested.value.contains("2 approved TCP ports"));
        assert!(
            tested
                .observation
                .contains("selected by upstream service and product prerequisites")
        );
        assert!(
            tested
                .observation
                .contains("Scheduled-VT execution completeness: unavailable")
        );
    }

    #[test]
    fn tested_dimension_asset_match_requires_the_whole_identifier() {
        let dimension = |value: &str| TestedDimension {
            dimension: "completed check-to-target coordinate".into(),
            value: value.into(),
            observation: String::new(),
            observed_at: None,
        };
        assert!(tested_dimension_refers_to_asset(
            &dimension("greenbone on asset host-1"),
            "host-1"
        ));
        assert!(tested_dimension_refers_to_asset(
            &dimension(
                "applicability-driven upstream profile on asset host-1 across 3 approved TCP ports"
            ),
            "host-1"
        ));
        assert!(!tested_dimension_refers_to_asset(
            &dimension("greenbone on asset host-10"),
            "host-1"
        ));
        assert!(!tested_dimension_refers_to_asset(
            &dimension("greenbone on asset host-1"),
            "host-10"
        ));
    }

    #[test]
    fn greenbone_dead_host_is_failed_untested_coverage_for_that_asset() {
        let mut case = internal_host_case();
        case.scan_runs[0].engine_runs[0].unevaluated_targets =
            vec![crate::domain::UnevaluatedTarget {
                asset_id: "host-asset".into(),
                cause: UnevaluatedTargetCause::TargetDidNotRespond,
                result_count: 1,
            }];

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let check = &report.actual.checks[0];
        assert_eq!(check.status, CoverageDimensionStatus::Failed);
        assert!(check.tested_dimensions.is_empty());
        let gaps = report
            .coverage_gaps
            .iter()
            .filter(|gap| gap.dimension == "greenbone: target response")
            .collect::<Vec<_>>();
        assert_eq!(gaps.len(), 1);
        let gap = gaps[0];
        assert_eq!(gap.kind, CoverageGapKind::Failed);
        assert_eq!(gap.task_id.as_deref(), Some("host"));
        assert_eq!(gap.target_asset_ids, ["host-asset"]);
        assert_eq!(
            gap.reason,
            "Host response unavailable. Vulnerability checks did not complete."
        );
        assert_eq!(gap.next_action_code, NextActionCode::ReviewScopeAndRetry);
        assert_eq!(
            gap.next_action,
            "Confirm the host is powered on and reachable from this computer on the approved ports, then run this check again."
        );
        assert_eq!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );
    }

    #[test]
    fn greenbone_scanner_errors_keep_completed_dimensions_and_mark_partial_coverage() {
        let mut case = internal_host_case();
        case.scan_runs[0].engine_runs[0].unevaluated_targets =
            vec![crate::domain::UnevaluatedTarget {
                asset_id: "host-asset".into(),
                cause: UnevaluatedTargetCause::ScannerError,
                result_count: 2,
            }];

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let check = &report.actual.checks[0];
        assert_eq!(check.status, CoverageDimensionStatus::TestedPartial);
        assert!(
            check
                .tested_dimensions
                .iter()
                .any(|dimension| dimension.dimension == "Greenbone remote vulnerability scan")
        );
        let gaps = report
            .coverage_gaps
            .iter()
            .filter(|gap| gap.dimension == "greenbone: scanner errors")
            .collect::<Vec<_>>();
        assert_eq!(gaps.len(), 1);
        let gap = gaps[0];
        assert_eq!(gap.kind, CoverageGapKind::Failed);
        assert_eq!(gap.task_id.as_deref(), Some("host"));
        assert_eq!(gap.target_asset_ids, ["host-asset"]);
        assert_eq!(
            gap.reason,
            "Greenbone reported errors for this host, so its checks cannot be shown as complete."
        );
        assert_eq!(
            gap.next_action_code,
            NextActionCode::PreserveVisibleLimitation
        );
        assert_eq!(gap.next_action, "Start a new scan for a fresh result.");
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
    }

    #[test]
    fn greenbone_host_without_an_identified_service_is_not_tested() {
        let mut case = internal_host_case();
        case.scan_runs[0].engine_runs[0].unevaluated_targets = vec![
            crate::domain::UnevaluatedTarget {
                asset_id: "host-asset".into(),
                cause: UnevaluatedTargetCause::ScannerError,
                result_count: 1,
            },
            crate::domain::UnevaluatedTarget {
                asset_id: "host-asset".into(),
                cause: UnevaluatedTargetCause::NoServiceIdentified,
                result_count: 0,
            },
        ];

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let check = &report.actual.checks[0];
        assert_eq!(check.status, CoverageDimensionStatus::NotTested);
        assert!(check.tested_dimensions.is_empty());
        let host_gaps = report
            .coverage_gaps
            .iter()
            .filter(|gap| gap.target_asset_ids == ["host-asset"])
            .collect::<Vec<_>>();
        assert_eq!(host_gaps.len(), 1, "one gap per host: {host_gaps:?}");
        let gap = host_gaps[0];
        assert_eq!(gap.dimension, "greenbone: service identification");
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert_eq!(gap.task_id.as_deref(), Some("host"));
        assert_eq!(
            gap.reason,
            "No service identified on the approved ports. Vulnerability checks did not run for this host."
        );
        assert_eq!(gap.next_action_code, NextActionCode::ChooseCompatibleCheck);
        assert_eq!(
            gap.next_action,
            "If this host serves a web page, add its full address as a website, then start a new scan."
        );
        assert_eq!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );
    }

    #[test]
    fn greenbone_unevaluated_target_not_bound_to_the_task_is_ignored() {
        let mut case = internal_host_case();
        let unchanged = build_beginner_master_report(&case, "run-1").unwrap();
        case.scan_runs[0].engine_runs[0].unevaluated_targets =
            vec![crate::domain::UnevaluatedTarget {
                asset_id: "unbound-asset".into(),
                cause: UnevaluatedTargetCause::TargetDidNotRespond,
                result_count: 1,
            }];

        assert_eq!(
            build_beginner_master_report(&case, "run-1").unwrap(),
            unchanged
        );
    }

    #[test]
    fn greenbone_dead_host_coverage_does_not_erase_a_retained_finding() {
        let mut case = internal_host_case();
        case.scan_runs[0].engine_runs[0].unevaluated_targets =
            vec![crate::domain::UnevaluatedTarget {
                asset_id: "host-asset".into(),
                cause: UnevaluatedTargetCause::TargetDidNotRespond,
                result_count: 1,
            }];
        let mut finding = frozen_finding(&case, "greenbone-alarm", 80, Severity::High);
        finding.asset_ids = vec!["host-asset".into()];
        finding.evidence[0].engine_run_id = Some("host".into());
        finding.evidence[0].engine_id = GREENBONE_ENGINE_ID.into();
        let mut retained = observation(&finding, "run-1", instant(18));
        retained.asset_ids = vec!["host-asset".into()];
        retained.engine_ids = vec![GREENBONE_ENGINE_ID.into()];
        case.findings.push(finding);
        case.finding_observations.push(retained);

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].finding_id, "greenbone-alarm");
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::Failed
        );
        assert!(report.coverage_gaps.iter().any(|gap| {
            gap.target_asset_ids == ["host-asset"] && gap.dimension == "greenbone: target response"
        }));
    }

    #[test]
    fn nuclei_unproven_website_coverage_does_not_erase_a_retained_finding() {
        let mut case = nuclei_website_case();
        let mut finding = frozen_finding(&case, "nuclei-alarm", 80, Severity::High);
        finding.asset_ids = vec!["website-asset".into()];
        // `nuclei_website_case` builds `catalog_task("host", ...)`; naming it here
        // is what makes the finding belong to the task this gap is about.
        finding.evidence[0].engine_run_id = Some("host".into());
        finding.evidence[0].engine_id = NUCLEI_ENGINE_ID.into();
        let mut retained = observation(&finding, "run-1", instant(18));
        retained.asset_ids = vec!["website-asset".into()];
        retained.engine_ids = vec![NUCLEI_ENGINE_ID.into()];
        case.findings.push(finding);
        case.finding_observations.push(retained);

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.findings.len(), 1);
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "nuclei: website execution evidence")
            .expect("missing Nuclei execution evidence must remain visible");
        assert_eq!(
            gap.reason,
            "Website security-template evidence unavailable. This website cannot be shown as tested."
        );
        assert!(
            !gap.reason.contains("Outcome: not tested"),
            "{}",
            gap.reason
        );
    }

    #[test]
    fn completed_nuclei_without_a_record_is_visible_as_unproven_not_tested_coverage() {
        let case = nuclei_website_case();
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::NotTested
        );
        assert!(report.actual.checks[0].tested_dimensions.iter().all(
            |dimension| dimension.dimension != "Nuclei upstream website scan"
                && !tested_dimension_refers_to_asset(dimension, "website-asset")
        ));
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "nuclei: website execution evidence")
            .expect("missing Nuclei execution evidence must remain visible");
        assert_eq!(gap.kind, CoverageGapKind::Unavailable);
        assert_eq!(gap.target_asset_ids, ["website-asset"]);
        assert_eq!(
            gap.reason,
            "Website security-template evidence unavailable. This website cannot be shown as tested."
        );
        assert_eq!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );
    }

    #[test]
    fn completed_nuclei_without_execution_evidence_records_a_visible_limitation() {
        // `nuclei_website_case` is already a completed catalog task with no
        // security-template execution record, so this is the Unavailable gap
        // inside the Completed arm and needs no extra fixture mutation.
        let case = nuclei_website_case();
        let task = &case.scan_runs[0].engine_runs[0];
        assert_eq!(task.status, EngineRunStatus::Completed);
        assert!(matches!(task.task_kind, EngineTaskKind::CatalogEngine));
        assert_eq!(task.engine_id, NUCLEI_ENGINE_ID);

        let projected = project_actual_coverage(&case, &case.scan_runs[0]);
        let gap = projected
            .gaps
            .iter()
            .find(|gap| gap.dimension == "nuclei: website execution evidence")
            .expect("missing Nuclei execution evidence gap");
        assert_eq!(gap.kind, CoverageGapKind::Unavailable);
        assert_eq!(gap.next_action, "Start a new scan for a fresh result.");
        assert_eq!(
            gap.next_action_code,
            NextActionCode::PreserveVisibleLimitation
        );

        let report = build_beginner_master_report(&case, "run-1").expect("beginner report");
        let reported = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "nuclei: website execution evidence")
            .expect("report carries the missing Nuclei execution evidence gap");
        assert_eq!(reported.kind, gap.kind);
        assert_eq!(reported.next_action_code, gap.next_action_code);
        assert_eq!(reported.next_action, gap.next_action);
    }

    #[test]
    fn completed_nuclei_record_keeps_the_tested_dimension_and_finding() {
        let mut case = nuclei_website_case();
        add_nuclei_record(&mut case, "nuclei-result", "website-asset", "host");
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].finding_id, "nuclei-result");
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedComplete
        );
        let tested = report.actual.checks[0]
            .tested_dimensions
            .iter()
            .find(|dimension| dimension.dimension == "Nuclei upstream website scan")
            .expect("the frozen automatic Nuclei profile is meaningful website coverage");
        assert!(tested.value.contains("technology-aware upstream profile"));
        assert!(
            tested
                .observation
                .contains("templates selected by upstream technology detection")
        );
        assert!(
            tested
                .observation
                .contains("Eligible-template execution completeness: unavailable")
        );
        assert!(
            report
                .coverage_gaps
                .iter()
                .all(|gap| { gap.dimension != "nuclei: website execution evidence" })
        );
    }

    #[test]
    fn completed_nuclei_non_match_evidence_is_a_clean_tested_result() {
        let mut case = nuclei_website_case();
        case.scan_runs[0].engine_runs[0]
            .security_template_executions
            .push(SecurityTemplateExecution {
                asset_id: "website-asset".into(),
                result_count: 7,
            });

        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert!(report.findings.is_empty());
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::TestedComplete
        );
        assert!(
            report.actual.checks[0]
                .tested_dimensions
                .iter()
                .any(|dimension| {
                    dimension.dimension == "Nuclei upstream website scan"
                        && dimension.value.ends_with("for asset website-asset")
                })
        );
        assert!(
            report
                .coverage_gaps
                .iter()
                .all(|gap| gap.dimension != "nuclei: website execution evidence")
        );
    }

    #[test]
    fn completed_nuclei_finding_without_execution_evidence_stays_unproven() {
        let mut case = nuclei_website_case();
        add_nuclei_record(&mut case, "nuclei-result", "website-asset", "host");
        case.scan_runs[0].engine_runs[0]
            .security_template_executions
            .clear();

        let report = build_beginner_master_report(&case, "run-1").unwrap();

        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::NotTested
        );
        assert!(report.coverage_gaps.iter().any(|gap| {
            gap.dimension == "nuclei: website execution evidence"
                && gap.target_asset_ids == ["website-asset"]
        }));
    }

    #[test]
    fn completed_nuclei_multi_asset_run_keeps_only_the_record_backed_website_tested() {
        let mut case = nuclei_website_case();
        let mut sibling = case.assets[0].clone();
        sibling.id = "website-sibling".into();
        sibling.name = "https://sibling.example.test:443".into();
        sibling.identifiers[0].value = "https://sibling.example.test:443".into();
        case.assets.push(sibling.clone());

        let run = &mut case.scan_runs[0];
        run.report_asset_snapshots.push(ReportAssetSnapshot {
            asset: sibling,
            disposition: ReportAssetDisposition::RequestedForScan,
        });
        let mut sibling_grant = run.scope_grant_snapshots[0].clone();
        sibling_grant.id = "grant-sibling".into();
        sibling_grant.asset_id = "website-sibling".into();
        let sibling_scope = sibling_grant
            .external_scope
            .as_mut()
            .expect("sibling website scope");
        sibling_scope.id = "external-sibling-grant".into();
        sibling_scope.asset_id = "website-sibling".into();
        sibling_scope.target = CanonicalTarget::Hostname("sibling.example.test".into());
        run.scope_grant_ids.push("grant-sibling".into());
        run.scope_grant_snapshots.push(sibling_grant);
        run.engine_runs[0].asset_ids.push("website-sibling".into());
        add_nuclei_record(&mut case, "nuclei-result", "website-asset", "host");

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let check = &report.actual.checks[0];
        assert_eq!(check.status, CoverageDimensionStatus::TestedPartial);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].target_asset_ids, ["website-asset"]);
        assert!(check.tested_dimensions.iter().any(|dimension| {
            dimension.dimension == "Nuclei upstream website scan"
                && dimension.value.ends_with("for asset website-asset")
        }));
        assert!(check.tested_dimensions.iter().all(|dimension| {
            !tested_dimension_refers_to_asset(dimension, "website-sibling")
                && !dimension.value.ends_with("for asset website-sibling")
        }));
        let gaps = report
            .coverage_gaps
            .iter()
            .filter(|gap| gap.dimension == "nuclei: website execution evidence")
            .collect::<Vec<_>>();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].target_asset_ids, ["website-sibling"]);
        assert_eq!(gaps[0].kind, CoverageGapKind::Unavailable);
    }

    #[test]
    fn completed_greenbone_host_process_with_a_changed_profile_is_not_a_clean_result() {
        let mut case = internal_host_case();
        case.scan_runs[0].scope_grant_snapshots[0]
            .external_scope
            .as_mut()
            .unwrap()
            .template_policy
            .profile_id = Some("greenbone_remote_safe_v2".into());

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::NotTested
        );
        assert!(
            report.actual.checks[0]
                .tested_dimensions
                .iter()
                .all(|dimension| dimension.dimension != "Greenbone remote vulnerability scan")
        );
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| {
                gap.target_asset_ids == ["host-asset"]
                    && gap.dimension == "greenbone: vulnerability profile evidence"
            })
            .expect("vulnerability profile evidence gap");
        assert_eq!(gap.next_action, "Start a new scan for a fresh result.");
        assert_eq!(
            gap.next_action_code,
            NextActionCode::PreserveVisibleLimitation
        );
    }

    #[test]
    fn completed_greenbone_process_without_exact_security_profile_is_not_a_clean_result() {
        let mut case = internal_endpoint_ssh_case();
        case.scan_runs[0].scope_grant_snapshots[0]
            .external_scope
            .as_mut()
            .unwrap()
            .template_policy
            .allowed_template_ids
            .pop();

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(
            report.actual.checks[0].status,
            CoverageDimensionStatus::NotTested
        );
        assert!(
            report.actual.checks[0]
                .tested_dimensions
                .iter()
                .all(|dimension| dimension.dimension != "SSH service vulnerability checks")
        );
        assert_eq!(
            report.state.summary,
            BeginnerReportSummary::NoChecksCompleted
        );
        assert!(report.coverage_gaps.iter().any(|gap| {
            gap.target_asset_ids == ["ssh-asset"]
                && gap.dimension == "SSH endpoint scan-profile coverage"
        }));
    }

    #[test]
    fn completed_https_management_profile_keeps_device_limits_beside_tested_tls() {
        let case = internal_device_case(DeclaredWebServiceScanProfile::InternalDeviceHttps);

        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert!(
            report.actual.checks[0]
                .tested_dimensions
                .iter()
                .any(|tested| { tested.dimension == "internal-device TLS vulnerability checks" })
        );
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "device product and firmware vulnerability coverage")
            .expect("device product and firmware coverage limits stay visible");
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert_eq!(gap.task_id.as_deref(), Some("device"));
        assert_eq!(gap.target_asset_ids, vec!["device-asset"]);
        assert!(gap.reason.contains("no device product or firmware"));
        assert!(gap.reason.contains("TLS protocol"));
        assert_eq!(
            gap.next_action,
            "Run a separately approved device firmware assessment or use endpoint inventory."
        );
        assert_eq!(
            gap.next_action_code,
            NextActionCode::PreserveVisibleLimitation
        );
        assert_eq!(report.coverage_counts.not_tested, 1);
        assert_eq!(report.coverage_counts.tested_complete, 1);
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);

        let mut later_project_edit = case.clone();
        later_project_edit.assets[0]
            .metadata
            .get_mut("declared_web_service")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .insert(
                "scan_profile".into(),
                serde_json::json!("internal_device_unknown"),
            );
        assert_eq!(
            report,
            build_beginner_master_report(&later_project_edit, "run-1").unwrap(),
            "the frozen run allowlist must win over a later asset-profile edit"
        );

        let reopened: AssessmentCase =
            serde_json::from_slice(&serde_json::to_vec(&case).unwrap()).unwrap();
        assert_eq!(
            report,
            build_beginner_master_report(&reopened, "run-1").unwrap(),
            "reopening the durable case must not change the shared report"
        );
    }

    #[test]
    fn completed_https_management_profile_names_the_separate_tls_checks() {
        let case = internal_device_case(DeclaredWebServiceScanProfile::InternalDeviceHttps);
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "device product and firmware vulnerability coverage")
            .expect("device product and firmware coverage limits stay visible");
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert_eq!(
            gap.next_action_code,
            NextActionCode::PreserveVisibleLimitation
        );
        assert_eq!(
            gap.next_action,
            "Run a separately approved device firmware assessment or use endpoint inventory."
        );
        assert_eq!(
            gap.reason,
            "This HTTPS management-service profile contains no device product or firmware vulnerability checks. TLS protocol, cipher, and certificate checks are reported separately."
        );
        assert!(report.actual.checks.iter().any(|check| {
            check
                .tested_dimensions
                .iter()
                .any(|tested| tested.dimension == "internal-device TLS vulnerability checks")
        }));
    }

    #[test]
    fn failed_https_management_profile_does_not_promise_separate_tls_checks() {
        let mut case = internal_device_case(DeclaredWebServiceScanProfile::InternalDeviceHttps);
        case.scan_runs[0].engine_runs[0].status = EngineRunStatus::Failed;
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.dimension == "device product and firmware vulnerability coverage")
            .expect("device product and firmware coverage limits stay visible");
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert_eq!(
            gap.next_action_code,
            NextActionCode::PreserveVisibleLimitation
        );
        assert_eq!(
            gap.next_action,
            "Run a separately approved device firmware assessment or use endpoint inventory."
        );
        assert_eq!(
            gap.reason,
            "This HTTPS management-service profile contains no device product or firmware vulnerability checks."
        );
        assert!(report.actual.checks.iter().all(|check| {
            check
                .tested_dimensions
                .iter()
                .all(|tested| tested.dimension != "internal-device TLS vulnerability checks")
        }));
    }

    #[test]
    fn device_coverage_requires_one_exact_frozen_production_profile() {
        let base = internal_device_case(DeclaredWebServiceScanProfile::InternalDeviceHttps);
        let mut extra_oid = base.clone();
        extra_oid.scan_runs[0].scope_grant_snapshots[0]
            .external_scope
            .as_mut()
            .unwrap()
            .template_policy
            .allowed_template_ids
            .push("1.3.6.1.4.1.25623.1.0.999999".into());
        let mut wrong_revision = base.clone();
        wrong_revision.scan_runs[0].scope_grant_snapshots[0]
            .external_scope
            .as_mut()
            .unwrap()
            .template_policy
            .revision = "816c24126e0375d32c667b78d20342ce7c58ec58".into();
        let mut wrong_rate = base.clone();
        wrong_rate.scan_runs[0].scope_grant_snapshots[0]
            .external_scope
            .as_mut()
            .unwrap()
            .rate_policy
            .requests_per_second = 3;
        let mut duplicate_grant = base.clone();
        let mut second = duplicate_grant.scan_runs[0].scope_grant_snapshots[0].clone();
        second.id = "grant-device-2".into();
        duplicate_grant.scan_runs[0]
            .scope_grant_snapshots
            .push(second);
        let mut no_frozen_grant = base;
        no_frozen_grant.scan_runs[0].scope_grant_snapshots.clear();

        for case in [
            extra_oid,
            wrong_revision,
            wrong_rate,
            duplicate_grant,
            no_frozen_grant,
        ] {
            let report = build_beginner_master_report(&case, "run-1").unwrap();
            assert!(
                report.actual.checks[0]
                    .tested_dimensions
                    .iter()
                    .all(|tested| tested.dimension != "internal-device TLS vulnerability checks")
            );
            assert!(
                report.coverage_gaps.iter().all(
                    |gap| gap.dimension != "device product and firmware vulnerability coverage"
                ),
                "an inexact or absent frozen profile cannot claim the reviewed HTTPS profile"
            );
            let unknown = report
                .coverage_gaps
                .iter()
                .find(|gap| gap.dimension == "internal-device scan-profile coverage")
                .expect("current metadata may only expose an unknown historical profile");
            assert_eq!(unknown.kind, CoverageGapKind::Unavailable);
            assert_eq!(unknown.target_asset_ids, vec!["device-asset"]);
        }
    }

    #[test]
    fn missing_and_active_runs_are_the_only_construction_errors() {
        let case = empty_case();
        assert_eq!(
            build_beginner_master_report(&case, "missing").unwrap_err(),
            BeginnerReportError::RunNotFound {
                run_id: "missing".into()
            }
        );
    }

    #[test]
    fn exclusions_are_explicit_and_do_not_disappear() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        case.coverage.push(CoverageEntry {
            id: "coverage-1".into(),
            scope_key: "optional-cloud".into(),
            label: "Optional cloud account".into(),
            source_kind: SourceKind::AwsOrganization,
            asset_id: None,
            status: CoverageStatus::NotApplicable,
            explanation: "The user deliberately excluded this source area.".into(),
            last_run_id: Some("run-1".into()),
            observed_at: Some(instant(15)),
        });
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        assert!(
            report
                .coverage_gaps
                .iter()
                .any(|gap| gap.kind == CoverageGapKind::Excluded)
        );
    }

    #[test]
    fn selected_run_time_ignores_later_unrelated_case_update() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::Completed,
            true,
        );
        case.updated_at = instant(10_000);
        case.raw_artifacts.push(RawArtifact {
            id: "artifact".into(),
            case_id: case.id.clone(),
            run_id: "run-1".into(),
            engine_run_id: "task-1".into(),
            relative_path: "raw/test.json".into(),
            media_type: "application/json".into(),
            sha256: "hash".into(),
            byte_length: 1,
            created_at: instant(19),
            contains_sensitive_data: false,
        });
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.state.last_durable_update, instant(20));
        assert_eq!(
            report.technical_details.tasks[0].evidence_sha256,
            vec!["hash"]
        );
    }

    /// The whole point of carrying the identifier as data.
    ///
    /// The check ran, produced results, and none of them reached the report.
    /// Before this the run showed "Partly completed" with an empty findings
    /// list and nothing anywhere a beginner looks said which identifier was
    /// missing -- the only sentence that did was English prose inside a
    /// collapsed technical block on a different page.
    #[test]
    fn results_tied_to_no_authorized_asset_become_a_gap_naming_the_identifier() {
        let mut case = localhost_case(
            LocalhostTcpOutcome::Reachable,
            EngineRunStatus::PartiallyCompleted,
            true,
        );
        // The same case without the attribution gap. Compared against rather
        // than asserted absolutely, so the fixture's own unrelated gaps cannot
        // be mistaken for this one.
        let baseline = build_beginner_master_report(&case, "run-1").unwrap();
        assert!(
            !baseline
                .coverage_gaps
                .iter()
                .any(|gap| gap.kind == CoverageGapKind::Unattributed)
        );

        case.scan_runs[0].engine_runs[0].unattributed = vec![crate::domain::UnattributedResults {
            provider: "aws".into(),
            identifier: "123456789012".into(),
            discarded_results: 42,
        }];
        let report = build_beginner_master_report(&case, "run-1").unwrap();

        let gap = report
            .coverage_gaps
            .iter()
            .find(|gap| gap.kind == CoverageGapKind::Unattributed)
            .expect("no gap explained the empty findings list");
        let payload = gap
            .unattributed
            .as_ref()
            .expect("the gap carries prose but not the data a reader composes from");
        assert_eq!(payload.identifier, "123456789012");
        assert_eq!(payload.provider, "aws");
        assert_eq!(payload.discarded_results, 42);
        assert_eq!(gap.next_action_code, NextActionCode::AddAssetIdentifier);
        // Both sentences have to name the identifier: it is the fix, and the
        // English is what an unlocalized surface falls back to.
        assert!(gap.reason.contains("123456789012"), "{}", gap.reason);
        assert!(
            gap.next_action.contains("123456789012"),
            "{}",
            gap.next_action
        );
        assert!(gap.reason.contains("42"), "{}", gap.reason);

        // Counted as its own state. The check ran, so "not tested" understates
        // it, and the results exist, so "unavailable" describes the wrong thing.
        assert_eq!(report.coverage_counts.unattributed, 1);
        assert_eq!(baseline.coverage_counts.unattributed, 0);
        // It landed in its own bucket rather than inflating an existing one.
        assert_eq!(
            report.coverage_counts.not_tested,
            baseline.coverage_counts.not_tested
        );
        assert_eq!(
            report.coverage_counts.unavailable,
            baseline.coverage_counts.unavailable
        );
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);

        // Naming the authorized assets as targets would assert the very
        // attribution the adapter refused to make.
        assert!(gap.target_asset_ids.is_empty());
    }

    /// Naabu runs behind the managed gateway, so its task is where a refusal
    /// record really arrives. The completed check offers no per-check Resume.
    fn case_with_gateway_refusals(record: Option<GatewayRefusalRecord>) -> AssessmentCase {
        let mut case = naabu_case_with_complete_unit_evidence(
            "task-gateway",
            EngineRunStatus::Completed,
            true,
        );
        case.scan_runs[0].engine_runs[0].gateway_refusals = record;
        case
    }

    fn refusal_gaps(case: &AssessmentCase) -> Vec<CoverageGap> {
        build_beginner_master_report(case, "run-1")
            .unwrap()
            .coverage_gaps
            .into_iter()
            .filter(|gap| {
                gap.dimension
                    .contains("connections refused by the rate limit")
                    || gap
                        .dimension
                        .contains("destination outside the approved scope")
                    || gap.dimension.contains("unrecorded connection refusals")
            })
            .collect()
    }

    #[test]
    fn a_rate_refusal_is_lost_coverage_on_the_task_assets() {
        let baseline =
            build_beginner_master_report(&case_with_gateway_refusals(None), "run-1").unwrap();
        assert_eq!(baseline.coverage_counts.truncated, 0);
        assert_eq!(baseline.state.summary, BeginnerReportSummary::Complete);

        let case = case_with_gateway_refusals(Some(GatewayRefusalRecord::Counted {
            rate: 4,
            destination: 0,
            unauthorized_client: 9,
        }));
        let task = &case.scan_runs[0].engine_runs[0];
        assert!(!task_retry_control_is_available(task));
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let gaps = refusal_gaps(&case);
        assert_eq!(gaps.len(), 1);
        let gap = &gaps[0];
        assert_eq!(gap.kind, CoverageGapKind::Truncated);
        assert_eq!(gap.class, CoverageGapClass::CoverageLoss);
        assert_eq!(gap.task_id.as_deref(), Some(task.id.as_str()));
        assert_eq!(gap.target_asset_ids, task.asset_ids);
        // The check finished after its refusals, so Progress has no Resume
        // for it. Naming one would send the reader to a control that is not
        // there.
        assert_eq!(gap.next_action_code, NextActionCode::StartNewScan);
        assert_eq!(gap.next_action, "Start a new scan for a fresh result.");
        // The rate count alone: the unauthorized-client count is not folded in.
        assert!(
            gap.reason.ends_with(" Refused connections: 4."),
            "{}",
            gap.reason
        );
        assert_eq!(report.coverage_counts.truncated, 1);
        assert_eq!(report.state.summary, BeginnerReportSummary::Partial);
        assert_eq!(
            crate::finding_narrative::coverage_gap_prose_zh_hant(&gap.reason).as_deref(),
            Some(
                "核准的速率限制拒絕了這項檢查的部分連線，因此部分檢查未能送達目標。拒絕的連線：4。"
            )
        );
    }

    #[test]
    fn a_rate_refusal_on_a_resumable_check_names_its_retry() {
        let mut case = naabu_case_with_one_partial_unit("task-gateway", EngineRunStatus::Failed);
        {
            let task = &mut case.scan_runs[0].engine_runs[0];
            task.phase = "failed".into();
            task.error_code = None;
            let token = progress_resume_token(task, "failed");
            task.resume_token = Some(token);
            task.gateway_refusals = Some(GatewayRefusalRecord::Counted {
                rate: 2,
                destination: 0,
                unauthorized_client: 0,
            });
            assert!(task_retry_control_is_available(task));
        }
        let gaps = refusal_gaps(&case);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].kind, CoverageGapKind::Truncated);
        assert_eq!(gaps[0].next_action_code, NextActionCode::RetryCheck);
        assert_eq!(gaps[0].next_action, "Retry this check.");
    }

    #[test]
    fn a_destination_refusal_is_a_record_note_not_lost_coverage() {
        let baseline =
            build_beginner_master_report(&case_with_gateway_refusals(None), "run-1").unwrap();
        let case = case_with_gateway_refusals(Some(GatewayRefusalRecord::Counted {
            rate: 0,
            destination: 2,
            unauthorized_client: 0,
        }));
        let task = &case.scan_runs[0].engine_runs[0];
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let gaps = refusal_gaps(&case);
        assert_eq!(gaps.len(), 1);
        let gap = &gaps[0];
        assert_eq!(gap.kind, CoverageGapKind::NotTested);
        assert_eq!(gap.class, CoverageGapClass::RecordNote);
        assert_eq!(gap.target_asset_ids, task.asset_ids);
        assert_eq!(
            gap.next_action_code,
            NextActionCode::NoActionUnlessScopeChanges
        );
        assert_eq!(gap.next_action, "No action for the current scope.");
        assert!(
            gap.reason.ends_with(" Refused connections: 2."),
            "{}",
            gap.reason
        );
        assert_eq!(report.coverage_counts, baseline.coverage_counts);
        assert_eq!(report.state.summary, baseline.state.summary);
    }

    #[test]
    fn an_unauthorized_client_refusal_alone_adds_no_coverage_row() {
        let unauthorized = refusal_gaps(&case_with_gateway_refusals(Some(
            GatewayRefusalRecord::Counted {
                rate: 0,
                destination: 0,
                unauthorized_client: 6,
            },
        )));
        assert!(unauthorized.is_empty());
        let quiet = refusal_gaps(&case_with_gateway_refusals(Some(
            GatewayRefusalRecord::Counted {
                rate: 0,
                destination: 0,
                unauthorized_client: 0,
            },
        )));
        assert!(quiet.is_empty());
    }

    #[test]
    fn a_legacy_run_without_a_refusal_record_adds_no_coverage_row() {
        let case = case_with_gateway_refusals(None);
        let mut json = serde_json::to_value(&case).unwrap();
        json["scan_runs"][0]["engine_runs"][0]
            .as_object_mut()
            .unwrap()
            .remove("gateway_refusals")
            .expect("the field is written");
        let legacy: AssessmentCase = serde_json::from_value(json).unwrap();
        assert!(
            legacy.scan_runs[0].engine_runs[0]
                .gateway_refusals
                .is_none()
        );
        assert!(refusal_gaps(&legacy).is_empty());
    }

    #[test]
    fn an_unreadable_gateway_record_is_a_note_and_not_a_coverage_loss() {
        let baseline =
            build_beginner_master_report(&case_with_gateway_refusals(None), "run-1").unwrap();
        let case = case_with_gateway_refusals(Some(GatewayRefusalRecord::Unavailable));
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let gaps = refusal_gaps(&case);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].kind, CoverageGapKind::Unavailable);
        assert_eq!(gaps[0].class, CoverageGapClass::RecordNote);
        assert_eq!(
            gaps[0].next_action_code,
            NextActionCode::PreserveVisibleLimitation
        );
        assert_eq!(gaps[0].next_action, "Start a new scan for a fresh result.");
        assert_eq!(
            gaps[0].target_asset_ids,
            case.scan_runs[0].engine_runs[0].asset_ids
        );
        assert_eq!(report.coverage_counts, baseline.coverage_counts);
        assert_eq!(report.state.summary, baseline.state.summary);
    }

    #[test]
    fn rate_and_destination_refusals_are_one_row_each() {
        let case = case_with_gateway_refusals(Some(GatewayRefusalRecord::Counted {
            rate: 8,
            destination: 1,
            unauthorized_client: 5,
        }));
        let gaps = refusal_gaps(&case);
        assert_eq!(gaps.len(), 2);
        assert!(gaps.iter().any(|gap| {
            gap.kind == CoverageGapKind::Truncated && gap.class == CoverageGapClass::CoverageLoss
        }));
        assert!(gaps.iter().any(|gap| {
            gap.kind == CoverageGapKind::NotTested && gap.class == CoverageGapClass::RecordNote
        }));
    }
}
