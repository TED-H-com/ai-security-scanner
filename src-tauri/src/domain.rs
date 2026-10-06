use crate::execution_coverage::ValidatedExecutionCoverage;
use crate::external_scope::{
    DirectNetworkTargetKind, ExternalScopeGrant, ExternalScopeRequest, TransportProtocol,
};
use crate::naabu_work_plan::NaabuWorkPlanV1;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub type Id = String;

pub fn new_id() -> Id {
    Uuid::new_v4().to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Draft,
    Discovering,
    ScopeReview,
    Ready,
    Scanning,
    NeedsAttention,
    ReadyForHandoff,
    Verifying,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    General,
    PersonallyIdentifiableInformation,
    ProtectedHealthInformation,
    PaymentCardInformation,
    Financial,
    CredentialsAndSecrets,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationProfile {
    pub organization_name: String,
    pub employee_range: String,
    pub data_classes: Vec<DataClass>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    AwsOrganization,
    AzureTenant,
    GcpOrganization,
    Microsoft365Tenant,
    Dns,
    CertificateTransparency,
    Billing,
    GitRepository,
    TerraformState,
    KubernetesCluster,
    ContainerRegistry,
    FileSystem,
    UserDeclared,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceConnectionStatus {
    NotConnected,
    Connecting,
    Connected,
    NeedsReauthorization,
    Failed,
    /// The user explicitly declared this source area outside the current case.
    /// A reason is retained in source metadata; this is never inferred from a
    /// failed connection or an empty discovery result.
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSource {
    pub id: Id,
    pub kind: SourceKind,
    pub label: String,
    pub status: SourceConnectionStatus,
    pub connected_at: Option<DateTime<Utc>>,
    pub last_discovered_at: Option<DateTime<Utc>>,
    pub read_only: bool,
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    CloudOrganization,
    CloudAccount,
    Subscription,
    Project,
    Tenant,
    Domain,
    IpAddress,
    Host,
    WebService,
    CloudResource,
    Identity,
    Repository,
    FileSystem,
    IacProject,
    ContainerImage,
    ContainerRegistry,
    KubernetesCluster,
    /// One deployed AI model reachable over an endpoint, as its own kind
    /// rather than a web service: an adversarial probe suite is bound to the
    /// model behind the URL, and routing it at every approved website because
    /// they share a scheme is exactly the widening a scope grant exists to
    /// prevent.
    AiModelEndpoint,
    Other,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalInputProfile {
    #[default]
    RepositoryWorkingTree,
    IacWorkingTree,
    ContainerImageOciLayout,
    KubernetesManifests,
    KubernetesNodeSnapshot,
}

impl LocalInputProfile {
    pub fn is_repository(&self) -> bool {
        matches!(self, Self::RepositoryWorkingTree)
    }

    pub fn asset_kind(self) -> AssetKind {
        match self {
            Self::RepositoryWorkingTree => AssetKind::Repository,
            Self::IacWorkingTree => AssetKind::IacProject,
            Self::ContainerImageOciLayout => AssetKind::ContainerImage,
            Self::KubernetesManifests => AssetKind::KubernetesCluster,
            Self::KubernetesNodeSnapshot => AssetKind::Host,
        }
    }

    pub fn source_kind(self) -> SourceKind {
        match self {
            Self::RepositoryWorkingTree => SourceKind::GitRepository,
            _ => SourceKind::FileSystem,
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::RepositoryWorkingTree => "repository working tree",
            Self::IacWorkingTree => "infrastructure-as-code working tree",
            Self::ContainerImageOciLayout => "OCI image layout",
            Self::KubernetesManifests => "Kubernetes manifest tree",
            Self::KubernetesNodeSnapshot => "Kubernetes node configuration snapshot",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineInputContract {
    pub asset_kind: AssetKind,
    pub input_profile: LocalInputProfile,
    /// Optional complete static argv for this exact typed local input. When
    /// absent, the manifest's top-level command remains the execution command.
    /// The registry and container runtime both reject dynamic or shell-shaped
    /// values before dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetIdentifier {
    pub namespace: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: Id,
    pub kind: AssetKind,
    pub name: String,
    pub provider: Option<String>,
    pub region: Option<String>,
    pub identifiers: Vec<AssetIdentifier>,
    pub discovered_from: Vec<Id>,
    pub candidate: bool,
    pub owner_confirmed: bool,
    pub internet_exposed: Option<bool>,
    pub contains_sensitive_data: Option<bool>,
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    Contains,
    HostedBy,
    ResolvesTo,
    Exposes,
    UsesIdentity,
    BuiltFrom,
    DeployedTo,
    References,
    Related,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRelation {
    pub id: Id,
    pub from_asset_id: Id,
    pub to_asset_id: Id,
    pub kind: RelationKind,
    pub evidence_ids: Vec<Id>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanPermission {
    InventoryRead,
    ConfigurationRead,
    LocalArtifactRead,
    PassiveExternalDiscovery,
    LowImpactExternalConnection,
    ActiveExternalTesting,
}

/// Questionnaire intent only. These values help retain what the user wants to
/// assess, but are deliberately separate from `ScanPermission`: recording an
/// activity can never create a scope grant or authorize an engine run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentActivity {
    ConfigurationAssessment,
    LocalArtifactAnalysis,
    LowImpactExternalChecks,
    ActiveExternalVulnerabilityTests,
}

/// The plain-language goal selected when the case was created. This only
/// chooses the guided setup recipe; it never grants permission or widens a
/// target. Older and advanced cases may legitimately have no recorded intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentIntent {
    DeployedWebsite,
    ExternalIpOrDomain,
    InternalItEnvironment,
    AiApplication,
    SourceCode,
    InfrastructureAsCode,
    CloudAccount,
    ContainerImage,
    Kubernetes,
}

/// The explicit answer to the case-creation question about whether selected
/// code was generated or materially changed by AI. `Unknown` is deliberately
/// distinct from `No`: legacy cases and unanswered questions must fail closed
/// instead of acquiring AI-generated-artifact control references.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AiGeneratedArtifactAnswer {
    Yes,
    No,
    #[default]
    Unknown,
}

/// Frozen answer to whether the selected scan is about an AI system. This is
/// separate from the historical boolean so an explicit non-AI answer is not
/// confused with an unanswered or legacy value.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AiSystemApplicabilityAnswer {
    Applicable,
    NotApplicable,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeGrant {
    pub id: Id,
    pub asset_id: Id,
    pub permission: ScanPermission,
    pub confirmed_by: String,
    pub confirmed_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub authorization_reference: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub external_scope: Option<ExternalScopeGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    DiscoveredAuthorizedScanned,
    DiscoveredNotAuthorized,
    AuthorizedScanIncomplete,
    SourceConnectedNothingDiscovered,
    SourceNotConnectedUnknown,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageEntry {
    pub id: Id,
    pub scope_key: String,
    pub label: String,
    pub source_kind: SourceKind,
    pub asset_id: Option<Id>,
    pub status: CoverageStatus,
    pub explanation: String,
    pub last_run_id: Option<Id>,
    pub observed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngineCategory {
    CloudInventory,
    CloudConfiguration,
    IdentityAndAccess,
    Microsoft365,
    ExternalAttackSurface,
    CodeAndSecrets,
    InfrastructureAsCode,
    ContainerAndSbom,
    Kubernetes,
    Host,
    SchemaAndExport,
    AiModelEndpoint,
    AiAgentFramework,
    AiMcpConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DistributionMode {
    BundledImage,
    PullPinnedImage,
    BuildFromPinnedSource,
    ExternalExecutable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageReference {
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
    pub signature_identity: Option<String>,
}

/// Release-time compatibility is an executable safety contract, not display metadata.
/// An engine remains unavailable until this record and the rest of its manifest agree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineCompatibility {
    pub knowledge_date: String,
    pub support_until: String,
    pub maintenance_owner: String,
    pub update_procedure: String,
    pub runnable: bool,
    pub artifact_state: EngineArtifactState,
    pub blocked_by: Vec<String>,
    pub knowledge_input: EngineKnowledgeInput,
    pub wrapper: EngineWrapper,
    pub packaging_plan: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngineArtifactState {
    VerifiedUpstreamImage,
    ManagedBuildPlan,
    MultiComponentPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineKnowledgeInput {
    pub kind: KnowledgeInputKind,
    pub identifier: String,
    pub version: Option<String>,
    pub acquisition_source: Option<String>,
    pub pin_state: KnowledgePinState,
    /// Optional for backward compatibility with case records created before
    /// per-engine knowledge windows were made durable.
    #[serde(default)]
    pub knowledge_date: Option<String>,
    /// Optional for backward compatibility with historical case records.
    #[serde(default)]
    pub support_until: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeInputKind {
    Embedded,
    ExternalPinned,
    ExternalPinRequired,
    NotApplicable,
    RuntimeLive,
    RuntimeBound,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgePinState {
    AwaitingPin,
    RuntimeLive,
    RuntimeBound,
    PinnedOrNotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineWrapper {
    pub required: bool,
    pub strategy: String,
    pub entrypoint: Option<String>,
}

pub const MIN_ENGINE_EXECUTION_TIMEOUT_SECONDS: u64 = 30;
pub const MAX_ENGINE_EXECUTION_TIMEOUT_SECONDS: u64 = 86_400;
pub const DEFAULT_ENGINE_EXECUTION_TIMEOUT_SECONDS: u64 = 3_600;
pub const MIN_ENGINE_EXECUTION_CPU_MILLIS: u32 = 100;
pub const MAX_ENGINE_EXECUTION_CPU_MILLIS: u32 = 16_000;
pub const DEFAULT_ENGINE_EXECUTION_CPU_MILLIS: u32 = 1_000;

/// The host-enforced portion of the reviewed engine execution contract.
/// Older saved cases predate this field, so `EngineManifest::execution` is
/// optional while the built-in release catalog is required to provide it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineExecutionContract {
    pub resources: EngineExecutionResources,
    /// Optional reviewed launcher-journal wire version. It is absent for
    /// legacy aggregate engines. Version 2 is currently valid only for the
    /// immutable Naabu image/command that contains the matching launcher.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher_journal_version: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineExecutionResources {
    pub timeout_seconds: u64,
    /// Reviewed CPU allowance for the engine container. Saved plans that
    /// predate this field keep the earlier one-CPU limit.
    #[serde(default = "default_engine_execution_cpu_millis")]
    pub cpu_millis: u32,
}

fn default_engine_execution_cpu_millis() -> u32 {
    DEFAULT_ENGINE_EXECUTION_CPU_MILLIS
}

impl Default for EngineCompatibility {
    fn default() -> Self {
        Self {
            knowledge_date: "1970-01-01".into(),
            support_until: "1970-01-01".into(),
            maintenance_owner: "test fixture owner".into(),
            update_procedure: "docs/engine-maintenance.md".into(),
            runnable: false,
            artifact_state: EngineArtifactState::ManagedBuildPlan,
            blocked_by: vec!["test_manifest_not_released".into()],
            knowledge_input: EngineKnowledgeInput {
                kind: KnowledgeInputKind::NotApplicable,
                identifier: "test fixture".into(),
                version: None,
                acquisition_source: None,
                pin_state: KnowledgePinState::PinnedOrNotApplicable,
                knowledge_date: None,
                support_until: None,
            },
            wrapper: EngineWrapper {
                required: false,
                strategy: "test fixture".into(),
                entrypoint: None,
            },
            packaging_plan: "engines/images/test/plan.json".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineManifest {
    pub schema_version: String,
    pub id: String,
    pub display_name: String,
    pub category: EngineCategory,
    pub description: String,
    pub repository_url: String,
    pub homepage_url: Option<String>,
    pub license_spdx: String,
    pub distribution_mode: DistributionMode,
    pub image: Option<ImageReference>,
    pub source_revision: Option<String>,
    pub engine_version: Option<String>,
    /// Release version the built scanner binary reports about itself.
    /// Recorded for an engine whose `engine_version` is `source@<commit>`.
    /// Absent when `engine_version` is already that release version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_version: Option<String>,
    pub rule_version: Option<String>,
    pub adapter_version: String,
    /// Exact provider identifiers accepted by this release. An empty list
    /// means the engine is provider-agnostic; a non-empty list requires an
    /// exact `Asset.provider` match and never guesses a missing provider.
    pub supported_providers: Vec<String>,
    pub supported_asset_kinds: Vec<AssetKind>,
    #[serde(default)]
    pub input_contracts: Vec<EngineInputContract>,
    /// Provider-specific execution closure for a multi-provider engine. A
    /// contract binds one exact provider/asset-kind pair to the product-owned
    /// launcher profile and the only provider endpoints that profile may use.
    /// Single-provider and provider-agnostic manifests may leave this empty.
    #[serde(default)]
    pub provider_execution_contracts: Vec<ProviderExecutionContract>,
    /// Exact structured grant shapes accepted by a direct-network launcher.
    /// This prevents planning a run that the engine wrapper must later reject.
    #[serde(default)]
    pub direct_network_contract: Option<DirectNetworkExecutionContract>,
    pub required_permissions: Vec<ScanPermission>,
    pub active_external: bool,
    pub default_enabled: bool,
    pub estimated_memory_mb: u32,
    pub estimated_disk_mb: u32,
    pub network_destinations: Vec<String>,
    pub output_formats: Vec<String>,
    pub command: Vec<String>,
    pub status: ManifestStatus,
    pub notices: Vec<String>,
    pub compatibility: EngineCompatibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<EngineExecutionContract>,
}

/// One packaged engine-catalog problem that was isolated from otherwise
/// usable product work. `engine_id == None` means no exact engine coordinate
/// could be recovered; `catalog_container_invalid` specifically identifies a
/// catalog-wide decode failure. These records are safe to expose and freeze
/// with a scan run; they never authorize a target or claim applicability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineAdmissionIssue {
    pub engine_id: Option<String>,
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectNetworkExecutionContract {
    pub target_kinds: Vec<DirectNetworkTargetKind>,
    pub protocols: Vec<TransportProtocol>,
}

impl DirectNetworkExecutionContract {
    pub fn supports(&self, scope: &ExternalScopeGrant) -> bool {
        self.target_kinds.contains(&scope.target.kind()) && self.protocols.contains(&scope.protocol)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderExecutionContract {
    pub provider: String,
    pub asset_kind: AssetKind,
    pub profile: String,
    pub network_destinations: Vec<String>,
}

impl EngineManifest {
    pub fn execution_timeout_seconds(&self) -> u64 {
        self.execution
            .as_ref()
            .map(|execution| execution.resources.timeout_seconds)
            .unwrap_or(DEFAULT_ENGINE_EXECUTION_TIMEOUT_SECONDS)
    }

    pub fn execution_cpu_millis(&self) -> u32 {
        self.execution
            .as_ref()
            .map(|execution| execution.resources.cpu_millis)
            .unwrap_or(DEFAULT_ENGINE_EXECUTION_CPU_MILLIS)
    }

    /// Whether the supplied grants contain every permission declared by this
    /// release. `active_external` describes execution behavior; it does not
    /// silently add `ActiveExternalTesting` to the manifest's explicit
    /// permission contract.
    pub fn required_permissions_satisfied_by<'a>(
        &self,
        permissions: impl IntoIterator<Item = &'a ScanPermission>,
    ) -> bool {
        let permissions = permissions.into_iter().collect::<Vec<_>>();
        self.required_permissions
            .iter()
            .all(|required| permissions.contains(&required))
    }

    /// Empty means provider-agnostic. Provider-bound releases require an exact
    /// provider identity on the asset; missing or differently cased values are
    /// not inferred from asset kind, source kind, or upstream capabilities.
    pub fn supports_provider(&self, asset_provider: Option<&str>) -> bool {
        self.supported_providers.is_empty()
            || asset_provider.is_some_and(|provider| {
                self.supported_providers
                    .iter()
                    .any(|supported| supported == provider)
            })
    }

    /// Returns the exact provider execution contract for one asset. When a
    /// manifest declares contracts, provider and asset kind are a pair rather
    /// than two independent allowlists; this prevents, for example, treating
    /// an Azure subscription profile as an AWS cloud-account profile.
    pub fn provider_execution_contract(
        &self,
        asset_provider: Option<&str>,
        asset_kind: &AssetKind,
    ) -> Option<&ProviderExecutionContract> {
        let provider = asset_provider?;
        self.provider_execution_contracts
            .iter()
            .find(|contract| contract.provider == provider && contract.asset_kind == *asset_kind)
    }

    pub fn supports_asset(&self, asset: &Asset) -> bool {
        self.supported_asset_kinds.contains(&asset.kind)
            && self.supports_provider(asset.provider.as_deref())
            && (self.provider_execution_contracts.is_empty()
                || self
                    .provider_execution_contract(asset.provider.as_deref(), &asset.kind)
                    .is_some())
    }

    /// Returns the release-contract reason that prevents this manifest from being dispatched.
    /// Runtime callers must still validate the image, command, scope, and credentials.
    pub fn release_blocker(&self) -> Option<String> {
        if !self.compatibility.runnable {
            let blockers = if self.compatibility.blocked_by.is_empty() {
                "the compatibility record is not runnable".into()
            } else {
                self.compatibility.blocked_by.join(", ")
            };
            return Some(format!("engine release is not runnable: {blockers}"));
        }
        if self.status != ManifestStatus::Integrated {
            return Some("only integrated engine releases may be dispatched".into());
        }
        if !self.compatibility.blocked_by.is_empty() {
            return Some(format!(
                "runnable engine release still declares blockers: {}",
                self.compatibility.blocked_by.join(", ")
            ));
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    Integrated,
    Experimental,
    ResearchOnly,
    Deprecated,
    LicenseReview,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngineRunStatus {
    NotExecuted,
    Queued,
    Preparing,
    Running,
    Paused,
    Completed,
    PartiallyCompleted,
    Failed,
    Cancelled,
}

/// The immutable kind of work represented by an [`EngineRun`].
///
/// Historical case files predate this discriminator, so a missing value must
/// remain a catalog-backed engine run. Product-owned bounded tasks use an
/// explicit variant instead of inventing catalog metadata such as an image or
/// manifest identity.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineTaskKind {
    #[default]
    CatalogEngine,
    BuiltInLocalhostTcp {
        port: u16,
        timeout_ms: u64,
        payload_bytes: u64,
    },
}

pub const BUILT_IN_LOCALHOST_TCP_TIMEOUT_MS: u64 = 3_000;
pub const BUILT_IN_LOCALHOST_TCP_PAYLOAD_BYTES: u64 = 0;
pub const BUILT_IN_LOCALHOST_TCP_ENGINE_ID: &str = "built-in-localhost-tcp";
pub const BUILT_IN_LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE: &str = "localhost_tcp_endpoint";
pub const BUILT_IN_LOCALHOST_TCP_AUTHORIZATION_REFERENCE: &str =
    "user_started_exact_localhost_tcp_check";

impl EngineTaskKind {
    /// Freeze the only currently supported localhost quick-task contract: one
    /// connection to the selected loopback port, bounded to three seconds,
    /// with no application payload.
    pub fn built_in_localhost_tcp(port: u16) -> Self {
        Self::BuiltInLocalhostTcp {
            port,
            timeout_ms: BUILT_IN_LOCALHOST_TCP_TIMEOUT_MS,
            payload_bytes: BUILT_IN_LOCALHOST_TCP_PAYLOAD_BYTES,
        }
    }

    pub fn is_exact_built_in_localhost_tcp_contract(&self) -> bool {
        matches!(
            self,
            Self::BuiltInLocalhostTcp {
                port: 1..=u16::MAX,
                timeout_ms: BUILT_IN_LOCALHOST_TCP_TIMEOUT_MS,
                payload_bytes: BUILT_IN_LOCALHOST_TCP_PAYLOAD_BYTES,
            }
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalhostTcpOutcome {
    Reachable,
    Closed,
    TimedOut,
}

/// A durable observation from the built-in localhost TCP task. It records
/// reachability only and must never be interpreted as a vulnerability or
/// security verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalhostTcpObservation {
    pub outcome: LocalhostTcpOutcome,
    pub observed_at: DateTime<Utc>,
}

/// Historical request records bind the legacy full-corpus launcher schema 2.
/// Current request records bind the compact launcher schema 3. Both remain
/// readable so saved evidence can be verified and an otherwise compatible
/// historical attempt can be regenerated without changing its digest. This
/// does not promise cross-release execution when the exact engine or runtime
/// identity is unavailable.
pub const LEGACY_NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION: u32 = 1;
pub const NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION: u32 = 2;
/// A work plan contains at most 512 units and automatic execution gives each
/// unit at most two attempts. Keeping the full 1,024-entry worst case prevents
/// the history bound from starving later units when only one fits per batch.
pub const MAX_NAABU_ATTEMPT_REQUESTS: usize = 1_024;
pub const NAABU_ATTEMPT_RESULT_SCHEMA_VERSION: u32 = 1;
pub const MAX_NAABU_ATTEMPT_RESULTS: usize = MAX_NAABU_ATTEMPT_REQUESTS;
/// Keeps a corrupt or adversarial case from multiplying the per-attempt
/// launcher limit into an unreasonably large in-memory history. Eight full
/// 512-unit result sets still fit; ordinary retries consume far less.
pub const MAX_NAABU_ATTEMPT_RESULT_WORK_UNITS: usize = 4_096;

/// Immutable, target-free record of the exact launcher work requested before
/// one Naabu attempt can contact a target. The referenced work-unit identities
/// remain meaningful only together with the adjacent immutable work plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NaabuAttemptRequest {
    pub schema_version: u32,
    pub execution_attempt: u32,
    pub requested_unit_ids: Vec<String>,
    pub launcher_plan_sha256: String,
}

/// Durable host binding for one already validated launcher-v2 journal.
///
/// The journal itself remains a raw artifact. This record contains only its
/// durable ID and the target-free coverage derived from it; it cannot replace
/// the immutable request that authorized the attempt. `normalization_complete`
/// means every validated final artifact in this attempt was handed through
/// the result adapter, not that the requested work was fully tested.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NaabuAttemptResult {
    pub schema_version: u32,
    pub execution_attempt: u32,
    pub journal_raw_artifact_id: Id,
    pub coverage: ValidatedExecutionCoverage,
    pub normalization_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineRun {
    pub id: Id,
    pub scan_run_id: Id,
    pub engine_id: String,
    #[serde(default)]
    pub task_kind: EngineTaskKind,
    #[serde(default)]
    pub localhost_tcp_observation: Option<LocalhostTcpObservation>,
    pub asset_ids: Vec<Id>,
    pub status: EngineRunStatus,
    pub progress_percent: u8,
    pub phase: String,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub resume_token: Option<String>,
    /// SHA-256 commitment to the complete most-recent scanner report applied
    /// to this task. It makes exact replay byte-for-byte complete instead of
    /// inferring equality from a subset of projected fields. Missing values
    /// identify legacy tasks and never authorize an idempotent replay.
    #[serde(default)]
    pub last_execution_report_sha256: Option<String>,
    pub engine_version: Option<String>,
    /// Release version the scanner binary reports, frozen from the catalog
    /// when the run was planned. Absent for engines with a release version
    /// and for runs planned before it was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_version: Option<String>,
    pub image_digest: Option<String>,
    pub rule_version: Option<String>,
    pub adapter_version: String,
    #[serde(default)]
    pub manifest_schema_version: Option<String>,
    #[serde(default)]
    pub source_revision: Option<String>,
    #[serde(default)]
    pub repository_url: Option<String>,
    #[serde(default)]
    pub distribution_mode: Option<DistributionMode>,
    #[serde(default)]
    pub image_repository: Option<String>,
    #[serde(default)]
    pub command_sha256: Option<String>,
    /// Exact host-side active execution deadline frozen when the run was
    /// planned. Missing values identify legacy runs that used the historical
    /// default deadline.
    #[serde(default)]
    pub execution_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub knowledge_input: Option<EngineKnowledgeInput>,
    /// SHA-256 of the canonical, execution-relevant asset, target, permission,
    /// and external-policy contract. The canonical document deliberately
    /// excludes approval timestamps and other non-behavioural metadata so a
    /// semantically identical re-approval remains comparable.
    #[serde(default)]
    pub scope_contract_sha256: Option<String>,
    /// The scope contract without the local-copy content hashes, used only to
    /// decide whether two runs' coordinates are comparable. Execution and
    /// resume keep using `scope_contract_sha256`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison_scope_sha256: Option<String>,
    /// Exact grants bound to a per-grant Greenbone or ZAP execution. Other engines
    /// and legacy runs retain their original combined grant contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_scope_grant_ids: Option<Vec<Id>>,
    /// Exact host-frozen Naabu work units persisted before the first target
    /// contact. Missing values identify legacy, non-Naabu, or not-yet-frozen
    /// executions and never imply complete work-unit coverage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub naabu_work_plan: Option<NaabuWorkPlanV1>,
    /// Append-only launcher requests persisted atomically with the immutable
    /// Naabu work plan and before their corresponding target contact. Missing
    /// values in legacy cases deserialize as an empty history.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_naabu_attempt_requests"
    )]
    pub naabu_attempt_requests: Vec<NaabuAttemptRequest>,
    /// Target-free results for validated launcher-v2 journals. Attempt
    /// identity and coverage are append-only; the host may only promote an
    /// existing result's normalization flag from false to true after all exact
    /// bindings are adapted. Legacy and dormant launcher-v1 runs deserialize
    /// with no invented coverage.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_naabu_attempt_results"
    )]
    pub naabu_attempt_results: Vec<NaabuAttemptResult>,
    /// Exact project-authored control-mapping catalog used while adapting this
    /// run. Missing values identify legacy runs and fail closed during diffing.
    #[serde(default)]
    pub mapping_version: Option<String>,
    /// Exact mapping catalog provenance frozen with the execution. `None`
    /// identifies a legacy run; a matching version string alone is not enough
    /// to establish an exact relationship mapping identity.
    #[serde(default)]
    pub mapping_provenance: Option<ControlMappingProvenance>,
    /// Exact fingerprint algorithm/schema identity used by the adapter.
    /// Future migrations must be explicitly allowlisted before differently
    /// versioned fingerprints can be compared.
    #[serde(default)]
    pub fingerprint_schema_version: Option<String>,
    #[serde(default)]
    pub runtime_provider: Option<String>,
    #[serde(default)]
    pub runtime_version: Option<String>,
    #[serde(default)]
    pub runtime_security_options: Option<String>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub cleanup_removed: Option<bool>,
    #[serde(default)]
    pub cleanup_detail: Option<String>,
    /// Managed-gateway refusal counts for this attempt.
    ///
    /// `None` means no managed gateway ran, the gateway that ran does not
    /// record refusals, or the case file predates this field. An old case
    /// file cannot tell those apart, so the report stays silent for `None`.
    /// Do not synthesize a record for a legacy run: historical absence is
    /// not a claim that the gateway refused nothing.
    #[serde(default)]
    pub gateway_refusals: Option<GatewayRefusalRecord>,
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Identifiers this run reported results for that no authorized asset
    /// claims. Kept structurally beside `warnings` because the warning is
    /// English prose in a collapsed technical block, and the reader who needs
    /// this is the one looking at an empty findings list.
    #[serde(default)]
    pub unattributed: Vec<UnattributedResults>,
    #[serde(default)]
    pub unevaluated_targets: Vec<UnevaluatedTarget>,
    /// Per-target proof that at least one applicable upstream security
    /// template completed. Kept separate from findings so a zero-match result
    /// can prove execution without inventing an issue, and legacy empty values
    /// never imply that a check ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_template_executions: Vec<SecurityTemplateExecution>,
    /// Controls the engine evaluated but left for a person to decide. These
    /// are coverage data, never findings or passing results.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub manual_review_controls: Vec<ManualReviewControl>,
    pub raw_artifact_ids: Vec<Id>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

fn deserialize_naabu_attempt_requests<'de, D>(
    deserializer: D,
) -> Result<Vec<NaabuAttemptRequest>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let requests = Vec::<NaabuAttemptRequest>::deserialize(deserializer)?;
    if requests.len() > MAX_NAABU_ATTEMPT_REQUESTS {
        return Err(serde::de::Error::custom(format!(
            "Naabu attempt-request history exceeds {MAX_NAABU_ATTEMPT_REQUESTS} entries"
        )));
    }
    Ok(requests)
}

fn deserialize_naabu_attempt_results<'de, D>(
    deserializer: D,
) -> Result<Vec<NaabuAttemptResult>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let results = Vec::<NaabuAttemptResult>::deserialize(deserializer)?;
    if results.len() > MAX_NAABU_ATTEMPT_RESULTS {
        return Err(serde::de::Error::custom(format!(
            "Naabu attempt-result history exceeds {MAX_NAABU_ATTEMPT_RESULTS} entries"
        )));
    }
    let work_units = results.iter().try_fold(0_usize, |total, result| {
        total.checked_add(result.coverage.work_units.len())
    });
    if work_units.is_none_or(|total| total > MAX_NAABU_ATTEMPT_RESULT_WORK_UNITS) {
        return Err(serde::de::Error::custom(format!(
            "Naabu attempt-result history exceeds {MAX_NAABU_ATTEMPT_RESULT_WORK_UNITS} cumulative work-unit entries"
        )));
    }
    Ok(results)
}

/// Closed reason codes for a scan request that reached a durable terminal
/// state before any check contacted a target.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanRequestOutcomeCode {
    #[serde(rename = "no_effective_scope_grants")]
    EffectiveScopeRequired,
    #[serde(rename = "no_ownership_confirmed_targets")]
    OwnershipConfirmationRequired,
    NoApplicableChecks,
}

pub const MAX_SCAN_REQUEST_EXPLANATION_CHARS: usize = 1_000;
pub const MAX_SCAN_REQUEST_ASSET_IDS: usize = 10_000;
pub const MAX_SCAN_REQUEST_ENGINE_IDS: usize = 1_000;
const MAX_SCAN_REQUEST_ID_CHARS: usize = 512;

/// A durable request-level outcome. Keeping `no_checks_completed` as the
/// tagged variant prevents an empty plan from looking queued, successful, or
/// equivalent to a scan with zero findings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ScanRequestOutcome {
    NoChecksCompleted {
        code: ScanRequestOutcomeCode,
        #[serde(deserialize_with = "deserialize_scan_request_asset_ids")]
        requested_asset_ids: Vec<Id>,
        #[serde(deserialize_with = "deserialize_scan_request_engine_ids")]
        requested_engine_ids: Vec<String>,
        #[serde(deserialize_with = "deserialize_scan_request_explanation")]
        explanation: String,
    },
}

impl ScanRequestOutcome {
    pub fn no_checks_completed(
        code: ScanRequestOutcomeCode,
        requested_asset_ids: Vec<Id>,
        requested_engine_ids: Vec<String>,
        explanation: impl Into<String>,
    ) -> Result<Self, String> {
        let explanation = explanation.into();
        validate_scan_request_explanation(&explanation)?;
        let requested_asset_ids =
            normalize_scan_request_ids(requested_asset_ids, MAX_SCAN_REQUEST_ASSET_IDS, "asset")?;
        let requested_engine_ids = normalize_scan_request_ids(
            requested_engine_ids,
            MAX_SCAN_REQUEST_ENGINE_IDS,
            "engine",
        )?;
        Ok(Self::NoChecksCompleted {
            code,
            requested_asset_ids,
            requested_engine_ids,
            explanation,
        })
    }

    pub fn is_no_checks_completed(&self) -> bool {
        matches!(self, Self::NoChecksCompleted { .. })
    }
}

fn normalize_scan_request_ids(
    values: Vec<String>,
    maximum: usize,
    kind: &str,
) -> Result<Vec<String>, String> {
    if values.len() > maximum {
        return Err(format!(
            "scan request exceeds {maximum} requested {kind} identifiers"
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        if value.is_empty()
            || value != value.trim()
            || value.chars().count() > MAX_SCAN_REQUEST_ID_CHARS
            || value.chars().any(char::is_control)
        {
            return Err(format!(
                "scan request contains an invalid {kind} identifier"
            ));
        }
        if seen.insert(value.clone()) {
            normalized.push(value);
        }
    }
    Ok(normalized)
}

fn deserialize_scan_request_asset_ids<'de, D>(deserializer: D) -> Result<Vec<Id>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    normalize_scan_request_ids(values, MAX_SCAN_REQUEST_ASSET_IDS, "asset")
        .map_err(serde::de::Error::custom)
}

fn deserialize_scan_request_engine_ids<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    normalize_scan_request_ids(values, MAX_SCAN_REQUEST_ENGINE_IDS, "engine")
        .map_err(serde::de::Error::custom)
}

fn validate_scan_request_explanation(value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err("scan request explanation must not be empty".into());
    }
    if value != value.trim() {
        return Err("scan request explanation must not have surrounding whitespace".into());
    }
    if value.chars().count() > MAX_SCAN_REQUEST_EXPLANATION_CHARS {
        return Err(format!(
            "scan request explanation exceeds {MAX_SCAN_REQUEST_EXPLANATION_CHARS} characters"
        ));
    }
    if value.chars().any(char::is_control) {
        return Err("scan request explanation must be one plain-text line".into());
    }
    Ok(())
}

fn deserialize_scan_request_explanation<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_scan_request_explanation(&value).map_err(serde::de::Error::custom)?;
    Ok(value)
}

/// One mixed-environment run can route at most 10,000 asset references and a
/// case questionnaire can add at most 200 explicit inventory-only targets.
/// Keep that exact combined upper bound when reading durable case data.
pub const MAX_SCAN_RUN_REPORT_ASSET_SNAPSHOTS: usize = 10_200;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportAssetDisposition {
    /// Selected for this run at plan time. Completion remains authoritative in
    /// the corresponding engine run; this value never means a check finished.
    RequestedForScan,
    /// Explicitly added to the IT environment, but no supported website,
    /// network-service, or local-input profile was selected for this run.
    NoSupportedProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportAssetSnapshot {
    pub asset: Asset,
    pub disposition: ReportAssetDisposition,
}

fn validate_report_asset_snapshots(snapshots: &[ReportAssetSnapshot]) -> Result<(), String> {
    if snapshots.len() > MAX_SCAN_RUN_REPORT_ASSET_SNAPSHOTS {
        return Err(format!(
            "scan run exceeds {MAX_SCAN_RUN_REPORT_ASSET_SNAPSHOTS} frozen report assets"
        ));
    }
    let mut asset_ids = std::collections::BTreeSet::new();
    for snapshot in snapshots {
        let asset_id = snapshot.asset.id.as_str();
        if asset_id.is_empty()
            || asset_id != asset_id.trim()
            || asset_id.chars().count() > MAX_SCAN_REQUEST_ID_CHARS
            || asset_id.chars().any(char::is_control)
        {
            return Err("scan run contains an invalid frozen report asset identifier".into());
        }
        if !asset_ids.insert(asset_id) {
            return Err(format!(
                "scan run repeats frozen report asset identifier {asset_id}"
            ));
        }
    }
    Ok(())
}

fn deserialize_report_asset_snapshots<'de, D>(
    deserializer: D,
) -> Result<Vec<ReportAssetSnapshot>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let snapshots = Vec::<ReportAssetSnapshot>::deserialize(deserializer)?;
    validate_report_asset_snapshots(&snapshots).map_err(serde::de::Error::custom)?;
    Ok(snapshots)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRun {
    pub id: Id,
    pub case_id: Id,
    pub sequence: u32,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    /// Terminal request-level outcome for a plan that contacted no target.
    /// Missing means a legacy or ordinarily planned run, never implicit
    /// success. New terminal zero-contact runs set this together with
    /// `completed_at` and contain no queued engine runs.
    #[serde(default)]
    pub request_outcome: Option<ScanRequestOutcome>,
    /// The assets a run was asked to scan, frozen at planning time, plus the
    /// explicitly added inventory-only assets of an IT-environment run. Full
    /// assets prevent later case edits from silently relabeling historical
    /// results. Empty means a legacy run, a run that requested no asset, or a
    /// request too large to freeze, never that the current case should be
    /// substituted.
    #[serde(
        default,
        deserialize_with = "deserialize_report_asset_snapshots",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub report_asset_snapshots: Vec<ReportAssetSnapshot>,
    pub knowledge_cutoff: DateTime<Utc>,
    /// Historical framework-classification context frozen when the run was
    /// planned. It never grants scan permission or changes scanner execution.
    /// For compatibility, only a legacy `true` upgrades to `Applicable`;
    /// legacy `false` remains `Unknown` rather than claiming non-applicability.
    #[serde(default)]
    pub ai_system_applicable: bool,
    /// Tri-state framework context frozen for new runs. Runs written before
    /// this field existed deserialize as `Unknown`; their historical `true`
    /// boolean is upgraded conservatively by `frozen_ai_system_applicability`,
    /// while historical `false` remains unknown.
    #[serde(default)]
    pub ai_system_applicability: AiSystemApplicabilityAnswer,
    /// Exact case-creation answer frozen with this run. Legacy runs and
    /// unanswered cases deserialize as `Unknown`, which never enables an
    /// AI-generated-artifact control reference.
    #[serde(default)]
    pub ai_generated_artifact: AiGeneratedArtifactAnswer,
    /// Durable verification intent. Older case files omit this field and are
    /// treated as ordinary scans rather than verification runs.
    #[serde(default)]
    pub verification_baseline_run_id: Option<Id>,
    pub scope_grant_ids: Vec<Id>,
    /// Immutable copies of the grants effective when this run was planned.
    /// `scope_grant_ids` alone is insufficient because live grants may later
    /// expire or be replaced. Empty means a legacy run with unknown history.
    #[serde(default)]
    pub scope_grant_snapshots: Vec<ScopeGrant>,
    /// Packaged catalog limitations frozen when this run was planned. They
    /// are reportable `not tested` gaps with unknown applicability, not
    /// synthetic engine executions and not product-wide start gates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub engine_admission_issues: Vec<EngineAdmissionIssue>,
    pub engine_runs: Vec<EngineRun>,
}

impl ScanRun {
    pub fn is_terminal_no_checks(&self) -> bool {
        self.completed_at.is_some()
            && self.engine_runs.is_empty()
            && self
                .request_outcome
                .as_ref()
                .is_some_and(ScanRequestOutcome::is_no_checks_completed)
    }

    pub fn frozen_ai_system_applicability(&self) -> AiSystemApplicabilityAnswer {
        match self.ai_system_applicability {
            AiSystemApplicabilityAnswer::Unknown if self.ai_system_applicable => {
                AiSystemApplicabilityAnswer::Applicable
            }
            answer => answer,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// The source did not provide a recognized impact rating. This is not an
    /// informational or low-severity assertion and remains explicitly unknown.
    Unknown,
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Unknown,
    Low,
    Medium,
    High,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Configuration,
    Observation,
    ExternalValidation,
    SourceCode,
    PackageInventory,
    UserDeclaration,
    RawToolOutput,
}

/// Where AWS says an IAM policy is managed.
///
/// This is scanner-reported context, not a product verdict. Keeping it typed
/// matters because an AWS-managed policy must be replaced or detached while a
/// customer-managed or inline policy can be narrowed by the account owner.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AwsIamPolicySource {
    AwsManaged,
    CustomerManaged,
    Inline,
}

/// Bounded principal names from Cloudsplaining's upstream `AttachedTo` field.
///
/// `complete` is false when the upstream field was missing, malformed, or
/// exceeded the adapter's presentation bound. The raw artifact remains the
/// authoritative full record in that case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AwsIamAttachedTo {
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub complete: bool,
}

/// Exact, bounded AWS IAM policy context retained from one scanner result.
///
/// The shared report layer uses `policy_source` to give the user the right
/// kind of next action. It never changes the scanner's finding, rating, or
/// attachment relationship.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AwsIamPolicyFindingDetails {
    pub policy_source: AwsIamPolicySource,
    pub policy_name: String,
    pub finding_identity: String,
    #[serde(default)]
    pub actions: Vec<String>,
    /// False when actions were sanitized or exceeded the bounded report view.
    /// The raw artifact remains the complete upstream record.
    #[serde(default)]
    pub actions_complete: bool,
    pub attached_to: AwsIamAttachedTo,
}

/// One benchmark item a scanner says its rule checks, exactly as the scanner
/// named it.
///
/// Scanner-reported provenance and untrusted text, never a product claim of
/// conformance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BenchmarkReference {
    pub name: String,
    pub version: String,
    pub reference: String,
}

/// Bounded fields reported by the scanner for one exact result.
///
/// These strings are retained as untrusted evidence. They are not product
/// instructions and must never be executed automatically. Keeping them
/// separate from [`Finding::recommendation`] preserves upstream meaning while
/// leaving the product-owned next action safe and beginner-readable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScannerFindingDetails {
    /// Scanner- or rule-provided explanation, excluding raw secret values and
    /// target response bodies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Scanner- or rule-provided remediation text. A reader must review and
    /// approve it before making any change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Version the scanner identified on the affected component, when the
    /// scanner exposes one as a distinct field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    /// Fixed version or bounded list of fixed versions reported by the
    /// scanner, without product-side version inference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_version: Option<String>,
    /// Cloudsplaining's bounded upstream policy and principal context. The
    /// strings remain untrusted evidence and are never executed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_iam_policy: Option<AwsIamPolicyFindingDetails>,
    /// CWE identifiers the scanner assigned to this result, normalized to
    /// `CWE-<digits>` and deduplicated, in the scanner's own order.
    ///
    /// The scanner's classification, not this product's. Kept here rather than
    /// on the finding because a finding merged from two engines carries each
    /// engine's classification separately: Trivy and Grype disagreeing about a
    /// package's weakness class is information, and flattening it to one list
    /// would silently pick a winner.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe_ids: Vec<String>,
    /// CVSS scores the scanner reported, one per scoring source it published.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cvss: Vec<CvssScore>,
    /// Benchmark items the scanner says this rule checks, exactly as it named
    /// them. Scanner-reported provenance and untrusted text, never a product
    /// claim of conformance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub benchmarks: Vec<BenchmarkReference>,
    /// Identifiers the scanner itself says name the same vulnerability as this result, as it reported them. Never derived from references, URLs, titles, or descriptions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advisory_aliases: Vec<String>,
}

/// One CVSS score exactly as a scanner published it.
///
/// The base score stays a string because it is the scanner's own printed
/// value: parsing it into a float and printing it back is how `9.8` becomes
/// `9.800000000000001` in a report. Adapters validate that it reads as a
/// number in 0.0-10.0 and otherwise drop it, so a reader can trust the digits
/// without this product having reformatted them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct CvssScore {
    /// CVSS specification version the scanner scored against, e.g. `3.1`.
    pub version: String,
    /// Full vector string when the scanner published one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector: Option<String>,
    /// Base score verbatim, e.g. `9.8`.
    pub base_score: String,
    /// Who scored it, as the scanner named them, e.g. `nvd` or `redhat`.
    /// Falls back to the engine's own id when the format publishes only one
    /// unattributed score.
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Id,
    pub finding_id: Id,
    pub run_id: Id,
    /// Exact producing engine execution. `None` is retained only for cases
    /// written before engine-run evidence provenance was persisted.
    #[serde(default)]
    pub engine_run_id: Option<Id>,
    pub kind: EvidenceKind,
    pub engine_id: String,
    /// Structured scanner text for this exact evidence record. It remains
    /// untrusted data even when it originated in an embedded upstream rule
    /// pack; interfaces label it as scanner-provided detail rather than a
    /// product recommendation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanner_details: Option<ScannerFindingDetails>,
    /// Exact normalized scanner rule that produced this evidence. New adapter
    /// records bind this value into the evidence ID. `None` identifies legacy
    /// evidence and can never support a verified-current catalog claim.
    #[serde(default)]
    pub source_rule: Option<String>,
    /// SHA-256 of the exact bounded result pointer used by the adapter. This
    /// lets redacted exports verify the v2 evidence identity without exposing
    /// the original pointer. Missing values identify legacy evidence.
    #[serde(default)]
    pub result_pointer_sha256: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub summary: String,
    /// Scanner-reported location after adapter redaction. Keeping this
    /// structured avoids making a user interface parse an English sentence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub artifact_id: Id,
    pub artifact_sha256: String,
    pub pointer: Option<String>,
    pub redacted: bool,
}

/// One inventory fact emitted by an upstream scanner for an exact run and
/// authorized asset.
///
/// Inventory observations are durable, untrusted scanner data. They are kept
/// separate from [`Finding`] because a reachable service, installed component,
/// or cloud resource does not by itself establish a security weakness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InventoryObservation {
    pub id: Id,
    pub case_id: Id,
    pub run_id: Id,
    pub engine_run_id: Id,
    pub asset_id: Id,
    pub engine_id: String,
    pub kind: InventoryObservationKind,
    pub artifact_id: Id,
    pub artifact_sha256: String,
    /// Bounded pointer into the exact raw artifact. This remains untrusted data
    /// and is never interpreted as an instruction or local filesystem path.
    pub pointer: String,
    pub observed_at: DateTime<Utc>,
}

/// Scanner-neutral inventory semantics. Vendor-specific JSON paths belong only
/// in adapters; durable storage and report code consume these typed facts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InventoryObservationKind {
    Service {
        endpoint: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        http_status: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tls: Option<bool>,
    },
    SoftwareComponent {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        package_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purl: Option<String>,
    },
    CloudResource {
        resource_type: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        native_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display_name: Option<String>,
    },
    WorkflowComponent {
        component_type: String,
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        is_guardrail: Option<bool>,
    },
    WorkflowRelationship {
        source: String,
        target: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        condition: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawArtifact {
    pub id: Id,
    pub case_id: Id,
    pub run_id: Id,
    pub engine_run_id: Id,
    pub relative_path: String,
    pub media_type: String,
    pub sha256: String,
    pub byte_length: u64,
    pub created_at: DateTime<Utc>,
    pub contains_sensitive_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlReference {
    pub framework: String,
    pub framework_version: String,
    pub control_id: String,
    pub title: String,
    pub relationship: String,
    pub rationale: String,
    pub mapping_version: String,
    /// Catalog identity frozen into the finding at adaptation time. `None`
    /// identifies a legacy relationship whose mapping provenance is
    /// unavailable; exporters must say so explicitly.
    #[serde(default)]
    pub mapping_provenance: Option<ControlMappingProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlMappingProvenance {
    pub mapping_version: String,
    pub reviewed_at: String,
    pub review_process: String,
    pub catalog_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Unreviewed,
    #[serde(alias = "sent_for_review")]
    ExpertReviewRequested,
    Confirmed,
    FalsePositive,
    #[serde(
        alias = "remediation_planned",
        alias = "remediated_pending_verification"
    )]
    RemediationReported,
    #[serde(alias = "closed")]
    VerifiedResolved,
}

/// Immutable human handling history. Workflow decisions never replace scanner
/// evidence or observations, and an expiry is recorded explicitly rather than
/// silently changing the underlying finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingWorkflowEvent {
    pub id: Id,
    pub case_id: Id,
    pub finding_id: Id,
    pub from_status: FindingStatus,
    pub to_status: FindingStatus,
    pub decided_by: String,
    pub decided_at: DateTime<Utc>,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
}

/// The kind of problem a finding reports, carried as a code rather than only as
/// the English sentence composed from it.
///
/// Every sentence this product writes about a finding — what it could mean,
/// what to do about it — is composed from this and the severity. Storing only
/// the composed prose is what produced Chinese headings over English paragraphs
/// in the zh-Hant report and the zh-TW findings pane: by the time a locale is
/// known, the sentence is already written and frozen into the case. The engine's
/// own `title` is deliberately not covered — that is the engine's wording, and
/// restating it in another language would be this product speaking for it.
///
/// Finer-grained than the impact text needs: `SourceCode` and `Secret` share a
/// consequence but not a remedy, and the remedy is the half that is urgent.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingFamily {
    CloudPosture,
    CloudIdentity,
    Microsoft365,
    NetworkExposure,
    SourceCode,
    Secret,
    InfrastructureAsCode,
    VulnerableComponent,
    Kubernetes,
    /// A deployed model answered an adversarial prompt the way the probe was
    /// trying to make it answer. Nothing is misconfigured, unpatched or leaked,
    /// so every other family's consequence and remedy would send the reader to
    /// the wrong place: the thing to change is what the model is allowed to say.
    ModelBehavior,
    /// MCP configuration text contains a credential pattern. Its first action
    /// is rotation and removal from the configuration, not a generic code fix.
    McpSecret,
    /// A static MCP configuration grants a server command or tool broader
    /// capabilities than it needs. This is neither cloud IAM nor IaC: the
    /// corrective action belongs in the MCP client/server configuration.
    McpConfiguration,
}

/// Why a finding has no scanner-supplied severity.
///
/// Present only when the engine reported no severity of its own; its absence
/// means the rating is the engine's. Current missing values stay `Unknown`.
/// Older frozen findings may retain a product-derived level beside this code,
/// so readers use both fields when explaining provenance.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SeverityBasisCode {
    OpenPort,
    ReachableHttpService,
    SecretPatternMatch,
    UnverifiedCredentialDetector,
    IacPolicyCheck,
    CisKubernetesBenchmark,
    CloudControlQuery,
    CloudsplainingIamPolicyFinding,
    UnratedVulnerabilityTestAlarm,
    /// An adversarial probe suite reported how many of its attempts a detector
    /// judged as failures. The rate is the whole result; garak publishes no
    /// severity for it, and one probe failing is not by itself a rated weakness.
    AdversarialProbeFailureRate,
}

impl SeverityBasisCode {
    /// Reachability records are useful inventory, but they are not evidence of
    /// a weakness. Keeping this distinction on the durable product-owned code
    /// prevents Naabu/httpx observations from being counted or presented as
    /// problems merely because they share the finding storage pipeline.
    pub fn is_exposure_observation(self) -> bool {
        matches!(self, Self::OpenPort | Self::ReachableHttpService)
    }
}

/// Why this product assigned confidence when the engine supplied no confidence
/// rating of its own.
///
/// Present only for a derived confidence. Its absence is deliberately not, by
/// itself, proof that an old persisted finding carried an engine rating: cases
/// written before this field existed keep their stored presentation unchanged.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceBasisCode {
    DeterministicPolicyEvaluation,
    AdvisoryVersionMatch,
    UnverifiedPatternOrDetectorMatch,
    ObservedResponse,
    TemplateMatcher,
    MissingDetectionQualityScore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Id,
    pub case_id: Id,
    pub first_seen_run_id: Id,
    pub last_seen_run_id: Id,
    pub fingerprint: String,
    pub title: String,
    pub plain_language_summary: String,
    pub possible_impact: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub priority: u8,
    pub priority_reasons: Vec<String>,
    pub asset_ids: Vec<Id>,
    pub evidence: Vec<Evidence>,
    pub control_references: Vec<ControlReference>,
    pub recommendation: String,
    pub verification_guidance: String,
    pub rollback_considerations: Option<String>,
    pub official_references: Vec<String>,
    pub recommended_expert_type: String,
    pub status: FindingStatus,
    pub tags: Vec<String>,
    /// Defaulted so cases written before this field existed still load. A
    /// legacy finding has no code, and a client that cannot compose its own
    /// sentence falls back to the English prose beside it rather than showing
    /// nothing.
    #[serde(default)]
    pub family: Option<FindingFamily>,
    #[serde(default)]
    pub severity_basis_code: Option<SeverityBasisCode>,
    /// Present only when this product, rather than the source engine, assigned
    /// the confidence. Defaulted so older case files continue to load and keep
    /// the presentation they already stored.
    #[serde(default)]
    pub confidence_basis_code: Option<ConfidenceBasisCode>,
    /// Why this case raised the finding's priority above what the scanner's own
    /// rating would give it. `apply_case_context` appends a sentence to
    /// `possible_impact` and a reason to `priority_reasons` for each of these.
    ///
    /// Carried as codes because a surface that composes its own impact sentence
    /// replaces the prose those appendices live in, and would otherwise drop
    /// them: the reader sees a priority raised by ten points and is told
    /// nothing about why, while a reader in the other language is told exactly
    /// why. Empty for a legacy finding and for a case with no such context.
    #[serde(default)]
    pub context_factors: Vec<ContextFactor>,
}

/// A case-specific reason this product raised a finding's priority.
///
/// Never a scanner verdict. Each one requires the affected asset to carry the
/// attribute independently, with all retained source attribution for that asset
/// Results an engine reported against an identifier no authorized asset claims.
///
/// The adapter refuses to guess which asset these belong to, which is right --
/// attributing a cloud finding to the wrong account is worse than not
/// attributing it. But the refusal is invisible: the findings list is simply
/// empty. Carried as data rather than as prose so the reader is told, in their
/// own language, which identifier to add.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnattributedResults {
    /// Normalized provider the engine reported under, e.g. `aws`.
    pub provider: String,
    /// The identifier itself. Reproduced verbatim for the reader to copy: it
    /// is the engine's own string and the whole point is to paste it onto the
    /// asset.
    pub identifier: String,
    /// How many results were discarded for this identifier.
    pub discarded_results: usize,
}

/// Managed-gateway refusal counts.
///
/// Carried as data (not prose) so the report can say, in the reader's
/// language, which check was cut short and why. The English cleanup line
/// stays in the technical record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GatewayRefusalRecord {
    Counted {
        rate: u64,
        destination: u64,
        unauthorized_client: u64,
    },
    /// The gateway ran but its status document could not be read at cleanup.
    /// Not the same as refusing nothing: the report must not claim complete
    /// coverage from a record it never read.
    Unavailable,
}

/// An authorized target an engine reported it could not evaluate, or could
/// only partly evaluate. Carried as data (not prose) so the report can say,
/// in the reader's language, which asset was not checked and why.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnevaluatedTarget {
    pub asset_id: Id,
    pub cause: UnevaluatedTargetCause,
    /// Upstream result records that carried this cause (saturating count).
    pub result_count: usize,
}

/// Bounded aggregate of genuine upstream per-template result records for one
/// authorized target. Exact template IDs remain in the raw artifact; this
/// durable projection only proves that the target had at least one completed
/// applicable security-template execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecurityTemplateExecution {
    pub asset_id: Id,
    /// Number of qualifying upstream per-template result records, saturating
    /// during normalization. A stored value must always be greater than zero.
    pub result_count: usize,
}

/// An authorized control the engine evaluated but did not give a pass/fail
/// verdict. Carried as coverage data (not a finding) so the report can show
/// the human-review requirement without claiming a vulnerability or a pass.
///
/// `detail` is bounded, untrusted upstream text for display only. It must never
/// be interpreted as an instruction or a filesystem path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ManualReviewControl {
    pub asset_id: Id,
    pub rule_id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum UnevaluatedTargetCause {
    /// Upstream `dead_host`: the scanner reported the host did not respond,
    /// so none of its vulnerability tests ran.
    TargetDidNotRespond,
    /// Upstream `error`: the scanner reported one or more errors while
    /// evaluating this target, so some of its checks did not finish.
    ScannerError,
    /// No upstream result proved that an applicable security template reached
    /// a completed evaluation for this target. Technology discovery and a
    /// successful process exit are not security-check execution evidence.
    NoSecurityTemplateExecutionEvidence,
    /// Greenbone returned no result on any approved port of this target. Its
    /// service-dependent checks run only after it identifies a service, so
    /// host-level results such as a route or an OS guess do not show that any
    /// approved port was checked.
    NoServiceIdentified,
}

/// being non-questionnaire, so answering a questionnaire alone cannot conjure
/// one. See `prioritization::apply_case_context`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ContextFactor {
    InternetExposedAsset,
    SensitiveDataAsset,
}

/// A reversible, user-facing collection of related canonical findings. The
/// member findings and their evidence remain independent records; grouping
/// never merges fingerprints or discards scanner output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingGroup {
    pub id: Id,
    pub case_id: Id,
    pub title: String,
    pub finding_ids: Vec<Id>,
    pub rationale: String,
    pub grouped_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingGroupAction {
    Created,
    Removed,
}

/// Immutable grouping history keeps a removed group reconstructable without
/// retaining it as an active presentation object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingGroupEvent {
    pub id: Id,
    pub case_id: Id,
    pub group_id: Id,
    pub action: FindingGroupAction,
    pub title: String,
    pub finding_ids: Vec<Id>,
    pub rationale: String,
    pub actor: String,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingObservation {
    pub id: Id,
    pub run_id: Id,
    pub finding_id: Id,
    pub fingerprint: String,
    pub asset_ids: Vec<Id>,
    pub engine_ids: Vec<String>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence_hashes: Vec<String>,
    pub observed_at: DateTime<Utc>,
    /// Immutable normalized finding content for this exact run. Legacy cases
    /// may omit it and fall back to the latest canonical projection.
    #[serde(default)]
    pub finding_snapshot: Option<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingDiffStatus {
    Resolved,
    StillPresent,
    NewlyObserved,
    Changed,
    UnableToVerify,
}

/// Machine-readable reason for a finding comparison result. These reasons are
/// additive detail and intentionally do not create extra top-level statuses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingDiffReasonCode {
    CoordinateNotCompleted,
    ComparisonIdentityMissing,
    ScopeContractChanged,
    ManifestSchemaChanged,
    EngineVersionChanged,
    ImageChanged,
    RuleVersionChanged,
    KnowledgeInputChanged,
    AdapterVersionChanged,
    SourceRevisionChanged,
    RepositoryChanged,
    DistributionModeChanged,
    CommandChanged,
    MappingVersionChanged,
    FingerprintSchemaChanged,
    SeverityChanged,
    ConfidenceChanged,
    EvidenceChanged,
    AffectedAssetsChanged,
    ObservingEnginesChanged,
    LocationMoved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingDiffReason {
    pub code: FindingDiffReasonCode,
    #[serde(default)]
    pub engine_id: Option<String>,
    #[serde(default)]
    pub asset_id: Option<Id>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingDiff {
    pub fingerprint: String,
    pub baseline_finding_id: Option<Id>,
    pub current_finding_id: Option<Id>,
    pub status: FindingDiffStatus,
    pub explanation: String,
    /// Actual run-specific severities, rather than the mutable canonical
    /// finding's latest severity. Missing means the finding was not observed.
    #[serde(default)]
    pub baseline_severity: Option<Severity>,
    #[serde(default)]
    pub current_severity: Option<Severity>,
    /// Evidence changes are independent of `Changed`: severity, assets, or
    /// observing engines can change while evidence hashes remain identical.
    #[serde(default)]
    pub evidence_changed: bool,
    #[serde(default)]
    pub reasons: Vec<FindingDiffReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationComparison {
    pub id: Id,
    pub case_id: Id,
    pub baseline_run_id: Id,
    pub current_run_id: Id,
    pub created_at: DateTime<Utc>,
    pub diffs: Vec<FindingDiff>,
    /// True only when every planned engine/asset coordinate completed with an
    /// exactly comparable immutable execution identity in both runs.
    #[serde(default)]
    pub complete: bool,
    /// Run/coordinate-level uncertainty remains visible even when neither run
    /// produced a finding and the fingerprint diff is therefore empty.
    #[serde(default)]
    pub completeness_issues: Vec<FindingDiffReason>,
    /// Workspace copies compared for assets both runs completed. Empty when a
    /// run did not freeze a workspace snapshot.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_input_changes: Vec<LocalInputChange>,
}

/// One local folder whose earlier scan copy and current copy were compared.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalInputChange {
    pub asset_id: Id,
    pub baseline_sha256: String,
    pub current_sha256: String,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseExport {
    pub id: Id,
    pub case_id: Id,
    pub run_id: Id,
    pub created_at: DateTime<Utc>,
    /// Exact backend-selected format. `None` is retained only when loading a
    /// record written by an older release that did not persist this field.
    #[serde(default)]
    pub format: Option<String>,
    pub path: String,
    pub sha256: String,
    /// Findings-only formats cannot carry the run coverage ledger in their
    /// native schema. New records therefore persist the mandatory companion
    /// manifest instead of disabling those exports for partial runs.
    #[serde(default)]
    pub coverage_manifest_path: Option<String>,
    #[serde(default)]
    pub coverage_manifest_sha256: Option<String>,
    pub signature: Option<String>,
    pub public_key: Option<String>,
    pub redaction_profile: String,
    /// Exact raw-file inclusion accounting. `None` means that a legacy record
    /// cannot truthfully answer the question; it must never be inferred from
    /// the redaction profile or filename.
    #[serde(default)]
    pub raw_artifacts_included: Option<usize>,
    #[serde(default)]
    pub raw_artifacts_omitted: Option<usize>,
    pub integrity_only_notice: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentCase {
    #[serde(skip)]
    pub(crate) storage_revision: i64,
    pub id: Id,
    pub title: String,
    pub profile: OrganizationProfile,
    pub status: CaseStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub knowledge_cutoff: Option<DateTime<Utc>>,
    pub is_demo: bool,
    #[serde(default)]
    pub assessment_intent: Option<AssessmentIntent>,
    #[serde(default)]
    pub ai_generated_artifact: AiGeneratedArtifactAnswer,
    #[serde(default)]
    pub requested_activities: Vec<AssessmentActivity>,
    pub data_sources: Vec<DataSource>,
    pub assets: Vec<Asset>,
    pub asset_relations: Vec<AssetRelation>,
    pub scope_grants: Vec<ScopeGrant>,
    pub coverage: Vec<CoverageEntry>,
    pub scan_runs: Vec<ScanRun>,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub finding_groups: Vec<FindingGroup>,
    #[serde(default)]
    pub finding_group_events: Vec<FindingGroupEvent>,
    #[serde(default)]
    pub finding_workflow_events: Vec<FindingWorkflowEvent>,
    pub finding_observations: Vec<FindingObservation>,
    #[serde(default)]
    pub inventory_observations: Vec<InventoryObservation>,
    pub raw_artifacts: Vec<RawArtifact>,
    pub exports: Vec<CaseExport>,
    pub comparisons: Vec<VerificationComparison>,
}

impl AssessmentCase {
    pub fn new(title: String, profile: OrganizationProfile) -> Self {
        let now = Utc::now();
        Self {
            storage_revision: 0,
            id: new_id(),
            title,
            profile,
            status: CaseStatus::Draft,
            created_at: now,
            updated_at: now,
            knowledge_cutoff: None,
            is_demo: false,
            assessment_intent: None,
            ai_generated_artifact: AiGeneratedArtifactAnswer::Unknown,
            requested_activities: Vec::new(),
            data_sources: Vec::new(),
            assets: Vec::new(),
            asset_relations: Vec::new(),
            scope_grants: Vec::new(),
            coverage: Vec::new(),
            scan_runs: Vec::new(),
            findings: Vec::new(),
            finding_groups: Vec::new(),
            finding_group_events: Vec::new(),
            finding_workflow_events: Vec::new(),
            finding_observations: Vec::new(),
            inventory_observations: Vec::new(),
            raw_artifacts: Vec::new(),
            exports: Vec::new(),
            comparisons: Vec::new(),
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    /// Projects time-bounded workflow decisions without deleting or rewriting
    /// their immutable audit events. An expired false-positive suppression
    /// returns to the status it temporarily replaced.
    pub(crate) fn apply_effective_finding_statuses(&mut self, now: DateTime<Utc>) {
        for finding in &mut self.findings {
            let latest = self
                .finding_workflow_events
                .iter()
                .filter(|event| event.finding_id == finding.id)
                .max_by(|left, right| {
                    left.decided_at
                        .cmp(&right.decided_at)
                        .then_with(|| left.id.cmp(&right.id))
                });
            let Some(latest) = latest else {
                continue;
            };
            finding.status = if latest.to_status == FindingStatus::FalsePositive
                && latest
                    .expires_at
                    .is_some_and(|expires_at| expires_at <= now)
            {
                latest.from_status.clone()
            } else {
                latest.to_status.clone()
            };
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaseProductIdentity {
    LocalhostQuickScan { port: u16 },
}

fn case_product_identity(value: &AssessmentCase) -> Option<CaseProductIdentity> {
    if value.scan_runs.is_empty() {
        return None;
    }

    let mut bound_port = None;
    for run in &value.scan_runs {
        let [engine_run] = run.engine_runs.as_slice() else {
            return None;
        };
        if engine_run.engine_id != BUILT_IN_LOCALHOST_TCP_ENGINE_ID
            || !engine_run
                .task_kind
                .is_exact_built_in_localhost_tcp_contract()
        {
            return None;
        }
        let EngineTaskKind::BuiltInLocalhostTcp { port, .. } = &engine_run.task_kind else {
            return None;
        };
        if bound_port.is_some_and(|expected| expected != *port) {
            return None;
        }
        bound_port = Some(*port);
    }

    bound_port.map(|port| CaseProductIdentity::LocalhostQuickScan { port })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseSummary {
    pub id: Id,
    pub title: String,
    pub organization_name: String,
    pub employee_range: String,
    pub data_classes: Vec<DataClass>,
    #[serde(default)]
    pub requested_activities: Vec<AssessmentActivity>,
    #[serde(default)]
    pub assessment_intent: Option<AssessmentIntent>,
    #[serde(default)]
    pub ai_generated_artifact: AiGeneratedArtifactAnswer,
    pub source_kinds: Vec<SourceKind>,
    /// Source areas that are part of this case, excluding questionnaire-only
    /// `not_applicable` placeholders. Kept separate from `source_kinds` so
    /// existing API consumers retain the complete coverage-coordinate list.
    #[serde(default)]
    pub applicable_source_kinds: Vec<SourceKind>,
    pub notes: Option<String>,
    pub status: CaseStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_demo: bool,
    pub asset_count: usize,
    pub finding_count: usize,
    pub latest_run_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_identity: Option<CaseProductIdentity>,
}

impl From<&AssessmentCase> for CaseSummary {
    fn from(value: &AssessmentCase) -> Self {
        let mut source_kinds = Vec::new();
        let mut applicable_source_kinds = Vec::new();
        for source in &value.data_sources {
            if !source_kinds.contains(&source.kind) {
                source_kinds.push(source.kind.clone());
            }
            if source.status != SourceConnectionStatus::NotApplicable
                && !applicable_source_kinds.contains(&source.kind)
            {
                applicable_source_kinds.push(source.kind.clone());
            }
        }
        Self {
            id: value.id.clone(),
            title: value.title.clone(),
            organization_name: value.profile.organization_name.clone(),
            employee_range: value.profile.employee_range.clone(),
            data_classes: value.profile.data_classes.clone(),
            requested_activities: value.requested_activities.clone(),
            assessment_intent: value.assessment_intent.clone(),
            ai_generated_artifact: value.ai_generated_artifact,
            source_kinds,
            applicable_source_kinds,
            notes: value.profile.notes.clone(),
            status: value.status.clone(),
            created_at: value.created_at,
            updated_at: value.updated_at,
            is_demo: value.is_demo,
            asset_count: value.assets.len(),
            finding_count: value.findings.len(),
            latest_run_id: value
                .scan_runs
                .iter()
                .max_by(|left, right| {
                    left.sequence
                        .cmp(&right.sequence)
                        .then_with(|| left.created_at.cmp(&right.created_at))
                        .then_with(|| left.id.cmp(&right.id))
                })
                .map(|run| run.id.clone()),
            product_identity: case_product_identity(value),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeHealth {
    pub provider: String,
    pub available: bool,
    pub phase: String,
    pub version: Option<String>,
    pub prerequisite: Option<String>,
    pub detail: String,
}

/// Secret-free, durable reminder that database deletion intentionally left a
/// case-scoped evidence directory behind for a separately confirmed action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactCleanupObligation {
    pub case_id: Id,
    pub exact_path: String,
    pub exists: bool,
    pub requires_explicit_confirmation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSnapshot {
    pub product_name: String,
    pub product_version: String,
    pub storage_path: String,
    pub cases: Vec<CaseSummary>,
    pub selected_case: Option<AssessmentCase>,
    pub runtime: RuntimeHealth,
    pub artifact_cleanup_obligations: Vec<ArtifactCleanupObligation>,
    pub engine_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCaseRequest {
    pub title: String,
    pub organization_name: String,
    pub employee_range: String,
    /// Plain-language guided setup choice. It selects UI and validation
    /// recipes only; it never authorizes a target.
    #[serde(default)]
    pub assessment_intent: Option<AssessmentIntent>,
    /// Plain-language answer used only to decide whether result references
    /// specific to AI-generated artifacts are applicable. It never changes
    /// scope, scanner selection, or permission.
    #[serde(default)]
    pub ai_generated_artifact: AiGeneratedArtifactAnswer,
    #[serde(default)]
    pub data_classes: Vec<DataClass>,
    /// Desired assessment activities from the questionnaire. This field is
    /// informational and must never be treated as target authorization.
    #[serde(default)]
    pub requested_activities: Vec<AssessmentActivity>,
    /// Expected environments establish unknown coverage coordinates only;
    /// they do not connect a source or authorize any scanner.
    #[serde(default)]
    pub source_kinds: Vec<SourceKind>,
    /// Source areas the user explicitly excluded in the questionnaire. These
    /// become reasoned `not_applicable` coverage records, never green records.
    #[serde(default)]
    pub not_applicable_source_kinds: Vec<SourceKind>,
    /// User-entered coordinates become source-attributed candidate assets.
    /// They do not prove ownership or create a scope grant.
    #[serde(default)]
    pub declared_assets: Vec<DeclaredAssetInput>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredAssetKind {
    ExternalTarget,
    Repository,
    IacProject,
    ContainerImage,
    KubernetesCluster,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeclaredAssetInput {
    pub kind: DeclaredAssetKind,
    pub value: String,
    /// Questionnaire intent only. Private targets still require an explicit
    /// sensitive-network scope grant before any network execution.
    #[serde(default)]
    pub internet_exposed: Option<bool>,
    /// Optional website context used only to prefill a later explicit scope
    /// decision. It never creates a scope grant.
    #[serde(default)]
    pub web_service: Option<DeclaredWebServiceInput>,
    /// Optional non-web network-service context used to select one fixed,
    /// service-aware endpoint profile. This is deliberately separate from a
    /// website origin: it never gives a TCP service HTTP path semantics.
    #[serde(default)]
    pub network_service: Option<DeclaredNetworkServiceInput>,
    /// Optional exact-host vulnerability scan driven by one upstream scanner
    /// profile across the reviewed TCP ports. It is mutually exclusive with
    /// website and single-service context.
    #[serde(default)]
    pub host_scan: Option<DeclaredHostScanInput>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredWebProtocol {
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredWebServiceScanProfile {
    InternalDeviceHttps,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeclaredWebServiceInput {
    pub protocol: DeclaredWebProtocol,
    pub port: u16,
    pub path: String,
    /// Absent preserves the existing website quick-scan intent. A present
    /// value is a closed, product-owned internal-device profile selector.
    #[serde(default)]
    pub scan_profile: Option<DeclaredWebServiceScanProfile>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredNetworkProtocol {
    Tcp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredHostScanProfile {
    GreenboneRemoteSafeV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeclaredHostScanInput {
    pub protocol: DeclaredNetworkProtocol,
    pub ports: Vec<u16>,
    pub profile: DeclaredHostScanProfile,
}

/// Canonical, durable exact-host profile metadata derived by the backend.
/// Sorting and deduplicating the ports makes the reviewed execution contract
/// stable across persistence and later authorization checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeclaredHostScanMetadata {
    pub target: String,
    pub protocol: DeclaredNetworkProtocol,
    pub ports: BTreeSet<u16>,
    pub profile: DeclaredHostScanProfile,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
// The variant names are the persisted snake_case profile identifiers, so the
// shared prefix is part of the stored contract rather than naming noise.
#[allow(clippy::enum_variant_names)]
pub enum DeclaredNetworkServiceScanProfile {
    InternalEndpointSsh,
    InternalEndpointRdpTls,
    InternalEndpointVnc,
    InternalEndpointSmtp,
    InternalEndpointTelnet,
}

/// The service-specific part of a declared endpoint. The exact hostname or
/// address remains the enclosing `DeclaredAssetInput.value`, so callers
/// cannot supply two competing target identities in one request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeclaredNetworkServiceInput {
    pub protocol: DeclaredNetworkProtocol,
    pub port: u16,
    pub scan_profile: DeclaredNetworkServiceScanProfile,
}

/// Canonical, durable endpoint profile metadata derived by the backend. It
/// binds the normalized target and service profile used later to reject a
/// modified authorization request before any scanner plan is persisted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeclaredNetworkServiceMetadata {
    pub target: String,
    pub protocol: DeclaredNetworkProtocol,
    pub port: u16,
    pub scan_profile: DeclaredNetworkServiceScanProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeDecision {
    pub asset_id: Id,
    pub permissions: Vec<ScanPermission>,
    pub confirmed_by: String,
    pub authorization_reference: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub external_scope: Option<ExternalScopeRequest>,
}

/// Provider-native identifiers are part of the executable security boundary,
/// so discovery, planning, credential checkout, and the managed launcher use
/// the same canonical syntax rather than merely accepting parseable values.
pub fn valid_azure_subscription_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .ok()
        .is_some_and(|parsed| parsed.to_string() == value)
}

pub fn valid_gcp_project_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (6..=30).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_native_identifiers_require_canonical_exact_syntax() {
        assert!(valid_azure_subscription_id(
            "11111111-2222-3333-4444-555555555555"
        ));
        assert!(!valid_azure_subscription_id(
            "11111111-2222-3333-4444-55555555555A"
        ));
        assert!(valid_gcp_project_id("audit-project-123"));
        assert!(!valid_gcp_project_id("-audit-project"));
        assert!(!valid_gcp_project_id("audit-project-"));
        assert!(!valid_gcp_project_id("A-project"));
    }

    #[test]
    fn new_case_is_local_draft_without_implicit_coverage() {
        let case = AssessmentCase::new(
            "Initial assessment".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "1-10".into(),
                data_classes: vec![DataClass::General],
                notes: None,
            },
        );

        assert_eq!(case.status, CaseStatus::Draft);
        assert!(case.coverage.is_empty());
        assert!(case.findings.is_empty());
        assert!(!case.is_demo);
        assert_eq!(
            case.ai_generated_artifact,
            AiGeneratedArtifactAnswer::Unknown
        );
    }

    #[test]
    fn coverage_unknown_is_distinct_from_connected_and_empty() {
        assert_ne!(
            CoverageStatus::SourceNotConnectedUnknown,
            CoverageStatus::SourceConnectedNothingDiscovered
        );
    }

    #[test]
    fn scan_run_without_verification_link_remains_backward_compatible() {
        let run: ScanRun = serde_json::from_value(serde_json::json!({
            "id": "run-1",
            "case_id": "case-1",
            "sequence": 1,
            "created_at": "2026-08-24T12:00:00Z",
            "completed_at": "2026-08-24T12:01:00Z",
            "knowledge_cutoff": "2026-08-24T12:00:00Z",
            "scope_grant_ids": [],
            "engine_runs": []
        }))
        .unwrap();

        assert!(run.verification_baseline_run_id.is_none());
        assert!(run.request_outcome.is_none());
        assert!(run.report_asset_snapshots.is_empty());
        assert!(run.engine_admission_issues.is_empty());
        assert!(!run.ai_system_applicable);
        assert_eq!(
            run.frozen_ai_system_applicability(),
            AiSystemApplicabilityAnswer::Unknown
        );
        assert_eq!(
            run.ai_generated_artifact,
            AiGeneratedArtifactAnswer::Unknown
        );

        let legacy_true: ScanRun = serde_json::from_value(serde_json::json!({
            "id": "run-2",
            "case_id": "case-1",
            "sequence": 2,
            "created_at": "2026-08-24T12:00:00Z",
            "completed_at": "2026-08-24T12:01:00Z",
            "knowledge_cutoff": "2026-08-24T12:00:00Z",
            "ai_system_applicable": true,
            "scope_grant_ids": [],
            "engine_runs": []
        }))
        .unwrap();
        assert_eq!(
            legacy_true.frozen_ai_system_applicability(),
            AiSystemApplicabilityAnswer::Applicable
        );
    }

    #[test]
    fn frozen_report_asset_snapshots_reject_duplicate_ids_and_the_hard_limit() {
        let snapshot = ReportAssetSnapshot {
            asset: Asset {
                id: "asset-1".into(),
                kind: AssetKind::Host,
                name: "tcp://ssh.example.test:22".into(),
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
            disposition: ReportAssetDisposition::RequestedForScan,
        };
        assert!(validate_report_asset_snapshots(std::slice::from_ref(&snapshot)).is_ok());
        assert!(validate_report_asset_snapshots(&[snapshot.clone(), snapshot.clone()]).is_err());
        assert!(
            validate_report_asset_snapshots(&vec![
                snapshot.clone();
                MAX_SCAN_RUN_REPORT_ASSET_SNAPSHOTS + 1
            ])
            .is_err()
        );

        let mut encoded = serde_json::json!({
            "id": "run-duplicate-assets",
            "case_id": "case-1",
            "sequence": 1,
            "created_at": "2026-08-24T12:00:00Z",
            "completed_at": "2026-08-24T12:01:00Z",
            "knowledge_cutoff": "2026-08-24T12:00:00Z",
            "scope_grant_ids": [],
            "engine_runs": []
        });
        encoded["report_asset_snapshots"] = serde_json::json!([snapshot, snapshot]);
        assert!(serde_json::from_value::<ScanRun>(encoded).is_err());
    }

    #[test]
    fn terminal_no_checks_request_outcome_round_trips_without_becoming_queued_work() {
        let now = Utc::now();
        let outcome = ScanRequestOutcome::no_checks_completed(
            ScanRequestOutcomeCode::NoApplicableChecks,
            vec!["asset-1".into(), "asset-1".into()],
            vec!["engine-a".into(), "engine-b".into(), "engine-a".into()],
            "No selected check can inspect the requested target.",
        )
        .unwrap();
        let run = ScanRun {
            id: "run-no-checks".into(),
            case_id: "case-1".into(),
            sequence: 1,
            created_at: now,
            completed_at: Some(now),
            request_outcome: Some(outcome.clone()),
            report_asset_snapshots: Vec::new(),
            knowledge_cutoff: now,
            ai_system_applicable: false,
            ai_system_applicability: Default::default(),
            ai_generated_artifact: Default::default(),
            verification_baseline_run_id: None,
            scope_grant_ids: vec![],
            scope_grant_snapshots: vec![],
            engine_admission_issues: Vec::new(),
            engine_runs: vec![],
        };

        assert!(run.is_terminal_no_checks());
        assert!(run.engine_runs.is_empty());
        let encoded = serde_json::to_value(&run).unwrap();
        assert_eq!(encoded["request_outcome"]["status"], "no_checks_completed");
        assert_eq!(encoded["request_outcome"]["code"], "no_applicable_checks");
        assert_eq!(
            encoded["request_outcome"]["requested_asset_ids"][0],
            "asset-1"
        );
        assert_eq!(
            encoded["request_outcome"]["requested_engine_ids"],
            serde_json::json!(["engine-a", "engine-b"])
        );

        let decoded: ScanRun = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.request_outcome, Some(outcome));
        assert!(decoded.is_terminal_no_checks());

        let mut contradictory = decoded;
        contradictory.engine_runs.push(
            serde_json::from_value(serde_json::json!({
                "id": "engine-run-1",
                "scan_run_id": "run-no-checks",
                "engine_id": "inventory",
                "asset_ids": ["asset-1"],
                "status": "completed",
                "progress_percent": 100,
                "phase": "complete",
                "started_at": "2026-08-24T12:00:00Z",
                "finished_at": "2026-08-24T12:00:01Z",
                "resume_token": null,
                "engine_version": "1.0.0",
                "image_digest": null,
                "rule_version": null,
                "adapter_version": "1",
                "raw_artifact_ids": [],
                "error_code": null,
                "error_message": null
            }))
            .unwrap(),
        );
        assert!(!contradictory.is_terminal_no_checks());
    }

    #[test]
    fn no_checks_explanation_is_bounded_plain_language() {
        assert!(
            ScanRequestOutcome::no_checks_completed(
                ScanRequestOutcomeCode::EffectiveScopeRequired,
                vec![],
                vec![],
                ""
            )
            .is_err()
        );
        assert!(
            ScanRequestOutcome::no_checks_completed(
                ScanRequestOutcomeCode::OwnershipConfirmationRequired,
                vec![],
                vec![],
                "A line with\na hidden second line."
            )
            .is_err()
        );
        assert!(
            ScanRequestOutcome::no_checks_completed(
                ScanRequestOutcomeCode::NoApplicableChecks,
                vec![],
                vec![],
                "x".repeat(MAX_SCAN_REQUEST_EXPLANATION_CHARS + 1)
            )
            .is_err()
        );

        let oversized = serde_json::json!({
            "status": "no_checks_completed",
            "code": "no_applicable_checks",
            "requested_asset_ids": [],
            "requested_engine_ids": [],
            "explanation": "x".repeat(MAX_SCAN_REQUEST_EXPLANATION_CHARS + 1)
        });
        assert!(serde_json::from_value::<ScanRequestOutcome>(oversized).is_err());

        assert!(
            ScanRequestOutcome::no_checks_completed(
                ScanRequestOutcomeCode::NoApplicableChecks,
                vec!["asset-1".into(); MAX_SCAN_REQUEST_ASSET_IDS + 1],
                vec![],
                "No requested check was applicable."
            )
            .is_err()
        );
        assert!(
            ScanRequestOutcome::no_checks_completed(
                ScanRequestOutcomeCode::NoApplicableChecks,
                vec![" asset-1".into()],
                vec![],
                "No requested check was applicable."
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_engine_run_defaults_to_catalog_task_without_an_observation() {
        let run: EngineRun = serde_json::from_value(serde_json::json!({
            "id": "engine-run-1",
            "scan_run_id": "run-1",
            "engine_id": "inventory",
            "asset_ids": ["asset-1"],
            "status": "completed",
            "progress_percent": 100,
            "phase": "complete",
            "started_at": "2026-08-24T12:00:00Z",
            "finished_at": "2026-08-24T12:00:01Z",
            "resume_token": null,
            "engine_version": "1.0.0",
            "image_digest": null,
            "rule_version": null,
            "adapter_version": "1",
            "raw_artifact_ids": [],
            "error_code": null,
            "error_message": null
        }))
        .unwrap();

        assert_eq!(run.task_kind, EngineTaskKind::CatalogEngine);
        assert!(run.localhost_tcp_observation.is_none());
        assert!(run.naabu_attempt_results.is_empty());
    }

    #[test]
    fn localhost_task_and_observation_round_trip_as_typed_data() {
        let observed_at = Utc::now();
        let task = EngineTaskKind::built_in_localhost_tcp(9_001);
        assert!(task.is_exact_built_in_localhost_tcp_contract());
        assert!(
            !EngineTaskKind::built_in_localhost_tcp(0).is_exact_built_in_localhost_tcp_contract()
        );

        let encoded = serde_json::to_value(&task).unwrap();
        assert_eq!(encoded["kind"], "built_in_localhost_tcp");
        assert_eq!(encoded["port"], 9_001);
        assert_eq!(encoded["timeout_ms"], 3_000);
        assert_eq!(encoded["payload_bytes"], 0);
        assert_eq!(
            serde_json::from_value::<EngineTaskKind>(encoded).unwrap(),
            task
        );

        let observation = LocalhostTcpObservation {
            outcome: LocalhostTcpOutcome::TimedOut,
            observed_at,
        };
        assert_eq!(
            serde_json::from_value::<LocalhostTcpObservation>(
                serde_json::to_value(&observation).unwrap()
            )
            .unwrap(),
            observation
        );
    }

    #[test]
    fn case_summary_preserves_questionnaire_and_selects_latest_run_deterministically() {
        let mut case = AssessmentCase::new(
            "Assessment".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "50-249".into(),
                data_classes: vec![DataClass::CredentialsAndSecrets],
                notes: Some("Local note".into()),
            },
        );
        case.requested_activities = vec![AssessmentActivity::LocalArtifactAnalysis];
        case.data_sources = vec![
            DataSource {
                id: "source-1".into(),
                kind: SourceKind::GitRepository,
                label: "Repository".into(),
                status: SourceConnectionStatus::NotConnected,
                connected_at: None,
                last_discovered_at: None,
                read_only: true,
                metadata: BTreeMap::new(),
            },
            DataSource {
                id: "source-2".into(),
                kind: SourceKind::GitRepository,
                label: "Repository duplicate".into(),
                status: SourceConnectionStatus::NotConnected,
                connected_at: None,
                last_discovered_at: None,
                read_only: true,
                metadata: BTreeMap::new(),
            },
            DataSource {
                id: "source-3".into(),
                kind: SourceKind::AwsOrganization,
                label: "AWS not used".into(),
                status: SourceConnectionStatus::NotApplicable,
                connected_at: None,
                last_discovered_at: None,
                read_only: true,
                metadata: BTreeMap::new(),
            },
            DataSource {
                id: "source-4".into(),
                kind: SourceKind::KubernetesCluster,
                label: "Kubernetes snapshot".into(),
                status: SourceConnectionStatus::Connected,
                connected_at: Some(Utc::now()),
                last_discovered_at: None,
                read_only: true,
                metadata: BTreeMap::new(),
            },
        ];
        let now = Utc::now();
        for (id, sequence) in [("newer", 2), ("older-vector-tail", 1)] {
            case.scan_runs.push(ScanRun {
                id: id.into(),
                case_id: case.id.clone(),
                sequence,
                created_at: now,
                completed_at: None,
                request_outcome: None,
                report_asset_snapshots: Vec::new(),
                knowledge_cutoff: now,
                ai_system_applicable: false,
                ai_system_applicability: Default::default(),
                ai_generated_artifact: Default::default(),
                verification_baseline_run_id: None,
                scope_grant_ids: vec![],
                scope_grant_snapshots: vec![],
                engine_admission_issues: Vec::new(),
                engine_runs: vec![],
            });
        }

        let summary = CaseSummary::from(&case);
        assert_eq!(summary.employee_range, "50-249");
        assert_eq!(summary.data_classes, [DataClass::CredentialsAndSecrets]);
        assert_eq!(
            summary.requested_activities,
            [AssessmentActivity::LocalArtifactAnalysis]
        );
        assert_eq!(
            summary.source_kinds,
            [
                SourceKind::GitRepository,
                SourceKind::AwsOrganization,
                SourceKind::KubernetesCluster,
            ]
        );
        assert_eq!(
            summary.applicable_source_kinds,
            [SourceKind::GitRepository, SourceKind::KubernetesCluster]
        );
        assert_eq!(summary.notes.as_deref(), Some("Local note"));
        assert_eq!(summary.created_at, case.created_at);
        assert_eq!(summary.latest_run_id.as_deref(), Some("newer"));
        assert_eq!(summary.product_identity, None);
    }

    #[test]
    fn case_summary_exposes_only_canonical_localhost_quick_scan_identity() {
        fn localhost_engine_run(scan_run_id: &str, port: u16) -> EngineRun {
            serde_json::from_value(serde_json::json!({
                "id": format!("engine-{scan_run_id}"),
                "scan_run_id": scan_run_id,
                "engine_id": BUILT_IN_LOCALHOST_TCP_ENGINE_ID,
                "task_kind": {
                    "kind": "built_in_localhost_tcp",
                    "port": port,
                    "timeout_ms": BUILT_IN_LOCALHOST_TCP_TIMEOUT_MS,
                    "payload_bytes": BUILT_IN_LOCALHOST_TCP_PAYLOAD_BYTES
                },
                "asset_ids": ["localhost-asset"],
                "status": "completed",
                "progress_percent": 100,
                "phase": "completed",
                "started_at": "2026-08-30T12:00:00Z",
                "finished_at": "2026-08-30T12:00:01Z",
                "resume_token": null,
                "engine_version": null,
                "image_digest": null,
                "rule_version": null,
                "adapter_version": "",
                "raw_artifact_ids": [],
                "error_code": null,
                "error_message": null
            }))
            .unwrap()
        }

        fn localhost_scan_run(case_id: &str, id: &str, sequence: u32, port: u16) -> ScanRun {
            let now = "2026-08-30T12:00:00Z".parse().unwrap();
            ScanRun {
                id: id.into(),
                case_id: case_id.into(),
                sequence,
                created_at: now,
                completed_at: Some(now),
                request_outcome: None,
                report_asset_snapshots: Vec::new(),
                knowledge_cutoff: now,
                ai_system_applicable: false,
                ai_system_applicability: Default::default(),
                ai_generated_artifact: Default::default(),
                verification_baseline_run_id: None,
                scope_grant_ids: vec![],
                scope_grant_snapshots: vec![],
                engine_admission_issues: Vec::new(),
                engine_runs: vec![localhost_engine_run(id, port)],
            }
        }

        let mut case = AssessmentCase::new(
            "Persisted display name".into(),
            OrganizationProfile {
                organization_name: "Persisted organization".into(),
                employee_range: "1-10".into(),
                data_classes: vec![],
                notes: None,
            },
        );
        case.scan_runs = vec![
            localhost_scan_run(&case.id, "run-a", 1, 9_001),
            localhost_scan_run(&case.id, "run-b", 2, 9_001),
        ];

        let summary = CaseSummary::from(&case);
        assert_eq!(
            summary.product_identity,
            Some(CaseProductIdentity::LocalhostQuickScan { port: 9_001 })
        );
        let encoded = serde_json::to_value(&summary).unwrap();
        assert_eq!(encoded["product_identity"]["kind"], "localhost_quick_scan");
        assert_eq!(encoded["product_identity"]["port"], 9_001);

        case.scan_runs[1].engine_runs[0].engine_id = "lookalike-localhost".into();
        assert_eq!(CaseSummary::from(&case).product_identity, None);

        case.scan_runs[1] = localhost_scan_run(&case.id, "run-b", 2, 9_002);
        assert_eq!(CaseSummary::from(&case).product_identity, None);
    }
}
