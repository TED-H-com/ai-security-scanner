import type { InternalDeviceScanProfile } from "./internalDeviceProfile";
import type { InternalEndpointScanProfile } from "./internalEndpointProfile";
import type { InternalHostScanProfile } from "./internalHostProfile";

export type AppMode = "native" | "demo";

export type PageId =
  | "start"
  | "cases"
  | "coverage"
  | "progress"
  | "findings"
  | "export"
  | "settings"
  | "verification";

export type CloudPlatform =
  | "aws"
  | "azure"
  | "gcp"
  | "m365"
  | "external"
  | "code"
  | "container"
  | "kubernetes";

export type CompanySize = "unknown" | "solo" | "small" | "medium" | "large";
export type DataClass = "pii" | "phi" | "payment" | "credentials" | "none";
/** Exact `DataClass` values serialized by the native Rust domain. */
export type DataClassWire =
  | "general"
  | "personally_identifiable_information"
  | "protected_health_information"
  | "payment_card_information"
  | "financial"
  | "credentials_and_secrets"
  | "other";

export type AssessmentActivity =
  | "configuration_assessment"
  | "local_artifact_analysis"
  | "low_impact_external_checks"
  | "active_external_vulnerability_tests";

/** Exact `AssessmentIntent` values serialized by the native Rust domain. */
export type AssessmentIntent =
  | "deployed_website"
  | "external_ip_or_domain"
  | "internal_it_environment"
  | "ai_application"
  | "source_code"
  | "infrastructure_as_code"
  | "cloud_account"
  | "container_image"
  | "kubernetes";

/** The saved answer to whether selected code was generated or materially changed by AI. */
export type AiGeneratedArtifactAnswer = "yes" | "no" | "unknown";

/** Exact `CaseStatus` values serialized by the native Rust domain. */
export type CaseStatusWire =
  | "draft"
  | "discovering"
  | "scope_review"
  | "ready"
  | "scanning"
  | "needs_attention"
  | "ready_for_handoff"
  | "verifying"
  | "archived";

export type CasePhase =
  | "draft"
  | "discovering"
  | "scope_review"
  | "ready"
  | "scanning"
  | "needs_attention"
  | "ready_for_handoff"
  | "verifying"
  | "archived"
  | "complete"
  | "verification_due";

/** Exact product identity derived and serialized by the native Rust domain. */
export type CaseProductIdentity = {
  kind: "localhost_quick_scan";
  port: number;
};

export interface AssessmentCase {
  id: string;
  name: string;
  /** The plain-language route the user chose when creating this scan project. */
  assessmentIntent?: AssessmentIntent;
  aiGeneratedArtifact: AiGeneratedArtifactAnswer;
  organizationName: string;
  companySize: CompanySize;
  dataClasses: DataClass[];
  requestedActivities: AssessmentActivity[];
  platforms: CloudPlatform[];
  createdAt: string;
  updatedAt: string;
  phase: CasePhase;
  isDemo?: boolean;
  description?: string;
  latestRunId?: string;
  /** Present on list summaries without loading the full workspace. */
  assetCount?: number;
  /** Canonical finding count across the case, not a selected-run count. */
  findingCount?: number;
  /** Identity derived from a canonical product-owned native execution contract. */
  productIdentity?: CaseProductIdentity;
}

export interface CreateCaseInput {
  name: string;
  assessmentIntent?: AssessmentIntent;
  aiGeneratedArtifact: AiGeneratedArtifactAnswer;
  organizationName: string;
  companySize: CompanySize;
  dataClasses: DataClass[];
  requestedActivities: AssessmentActivity[];
  platforms: CloudPlatform[];
  knownAssets: KnownAssetInput[];
  description?: string;
}

export type KnownAssetKind =
  | "external_target"
  | "repository"
  | "iac_project"
  | "container_image"
  | "kubernetes_cluster";

export interface KnownAssetInput {
  kind: KnownAssetKind;
  value: string;
  /** Questionnaire intent only. It never authorizes private-network access. */
  internetExposure?: "public" | "internal";
  /** Website context only. It is a later scope-form preset, never authorization. */
  webService?: {
    protocol: "http" | "https";
    port: number;
    path: string;
    /** Selects an explicit internal-device vulnerability profile; absent means the website path. */
    scanProfile?: InternalDeviceScanProfile;
  };
  /** Exact unauthenticated internal service selected for a fixed vulnerability profile. */
  networkService?: {
    protocol: "tcp";
    port: number;
    scanProfile: InternalEndpointScanProfile;
  };
  /** One exact internal host using the pinned Greenbone remote-safe profile. */
  hostScan?: {
    protocol: "tcp";
    ports: number[];
    scanProfile: InternalHostScanProfile;
  };
}

export type LocalNetworkCandidateStatus =
  | "ready"
  | "none"
  | "ambiguous"
  | "unavailable"
  | "unsupported";

export interface LocalPrivateSubnetCandidate {
  id: string;
  target: string;
  kind: "local_ipv4_subnet";
  useCase: "internal_it_environment";
  internetExposure: "internal";
  addressCount: number;
  /** Detection only suggests this range; a person must explicitly add it. */
  requiresConfirmation: true;
}

export interface LocalNetworkCandidateInventory {
  status: LocalNetworkCandidateStatus;
  candidates: LocalPrivateSubnetCandidate[];
}

export type CoverageState =
  | "discovered_authorized_scanned"
  | "discovered_not_authorized"
  | "authorized_incomplete"
  | "source_connected_none"
  | "source_unavailable_unknown"
  | "not_applicable";

/** Exact `CoverageStatus` values serialized by the native Rust domain. */
export type CoverageStatusWire =
  | "discovered_authorized_scanned"
  | "discovered_not_authorized"
  | "authorized_scan_incomplete"
  | "source_connected_nothing_discovered"
  | "source_not_connected_unknown"
  | "not_applicable";

/** Exact `ScanPermission` values serialized by the native Rust domain. */
export type ScanPermissionWire =
  | "inventory_read"
  | "configuration_read"
  | "local_artifact_read"
  | "passive_external_discovery"
  | "low_impact_external_connection"
  | "active_external_testing";

export type SourceKind =
  | "aws_organization"
  | "azure_tenant"
  | "gcp_organization"
  | "microsoft365_tenant"
  | "dns"
  | "certificate_transparency"
  | "billing"
  | "git_repository"
  | "terraform_state"
  | "kubernetes_cluster"
  | "container_registry"
  | "file_system"
  | "user_declared";

export type SnapshotParserProfile =
  | "cloudquery"
  | "steampipe"
  | "prowler"
  | "scubagear"
  | "maester"
  | "dns-response"
  | "certificate-transparency-response"
  | "billing-export"
  | "git-manifest"
  | "terraform-state"
  | "kubernetes-manifest"
  | "container-registry-manifest"
  | "filesystem-manifest"
  | "user-declared-manifest";

export interface ConnectSourceSnapshotInput {
  caseId: string;
  sourceKind: SourceKind;
  label: string;
  profile: SnapshotParserProfile;
  selectedPath: string;
}

export type LocalInputProfile =
  | "repository_working_tree"
  | "iac_working_tree"
  | "container_image_oci_layout"
  | "kubernetes_manifests"
  | "kubernetes_node_snapshot";

export interface AttachWorkspaceSnapshotInput {
  caseId: string;
  label: string;
  selectedPath: string;
  inputProfile: LocalInputProfile;
}

export interface RefreshWorkspaceSnapshotInput {
  caseId: string;
  assetId: string;
  selectedPath: string;
}

export interface SelectMcpConfigurationInput {
  caseId: string;
  assetId: string;
  relativePath: string;
}

export type AgenticRadarFramework = "langgraph" | "crewai" | "n8n" | "openai-agents" | "autogen";

export interface SelectAgenticFrameworkInput {
  caseId: string;
  assetId: string;
  framework: AgenticRadarFramework | null;
}

export interface ModelEndpointInput {
  endpoint: string;
  model: string;
}

export interface StartModelCheckInput extends ModelEndpointInput {
  key: string;
  privateNetwork: boolean;
  confirmation: string;
}

export type ProviderSourceProfile =
  | "aws_organization_read_only_session"
  | "azure_tenant_read_only_access_token"
  | "gcp_organization_read_only_access_token"
  | "microsoft365_tenant_read_only_access_token";

export interface AwsNativeAuthorizationConfig {
  start_url: string;
  region: string;
  account_id: string;
  role_name: string;
  role_arn: string;
}

export interface MicrosoftNativeAuthorizationConfig {
  tenant_id: string;
  public_client_id: string;
  profile: ProviderSourceProfile;
  subscription_id: string | null;
}

export interface GcpNativeAuthorizationConfig {
  public_client_id: string;
  redirect_uri: string;
  organization_id: string;
}

export type ProviderAuthorizationConfig =
  | { provider: "aws"; config: AwsNativeAuthorizationConfig }
  | { provider: "azure"; config: MicrosoftNativeAuthorizationConfig }
  | { provider: "gcp"; config: GcpNativeAuthorizationConfig }
  | { provider: "microsoft365"; config: MicrosoftNativeAuthorizationConfig };

export interface BeginProviderAuthorizationInput {
  case_id: string;
  source_id: string;
  allowed_engine_ids: string[];
  max_checkouts: number;
  authorization: ProviderAuthorizationConfig;
}

export interface ProviderDevicePrompt {
  provider: "aws" | "azure" | "gcp" | "microsoft365";
  verification_uri: string;
  verification_uri_complete: string | null;
  user_code: string;
  expires_at: string;
  poll_interval_seconds: number;
  safety_notice: string;
}

export interface ProviderPkcePrompt {
  provider: "aws" | "azure" | "gcp" | "microsoft365";
  authorization_url: string;
  redirect_uri: string;
  expires_at: string;
  safety_notice: string;
}

export type ProviderAuthorizationPrompt =
  | { flow: "device"; session_id: string; prompt: ProviderDevicePrompt }
  | { flow: "pkce"; session_id: string; prompt: ProviderPkcePrompt };

export interface InstalledProviderAuthorization {
  schema_version: string;
  case_id: string;
  source_id: string;
  provider: "aws" | "azure" | "gcp" | "microsoft365";
  source_kind: SourceKind;
  profile: ProviderSourceProfile;
  credential_source: string;
  provider_identity: string;
  permissions: string[];
  expires_at: string;
  allowed_engine_ids: string[];
  max_checkouts: number;
  safety_notice: string;
}

export type ProviderAuthorizationProgress =
  | { status: "pending"; session_id: string; retry_after_seconds: number }
  | { status: "installed"; authorization: InstalledProviderAuthorization };

export type BootstrapOperatorConfig =
  | { provider: "aws"; administrator: AwsNativeAuthorizationConfig }
  | { provider: "azure"; authorization: MicrosoftNativeAuthorizationConfig }
  | { provider: "gcp"; authorization: GcpNativeAuthorizationConfig; project_id: string }
  | { provider: "microsoft365"; authorization: MicrosoftNativeAuthorizationConfig };

export interface BootstrapRequest {
  schema_version: "1.0.0";
  case_id: string;
  provider: "aws" | "azure" | "gcp" | "microsoft365";
  scan_identity_name: string;
  capabilities: Array<
    "inventory" | "configuration" | "identity_and_access" | "security_posture" | "audit_metadata"
  >;
  expires_at: string;
}

export interface ProviderBootstrapPlan {
  schema_version: string;
  case_id: string;
  provider: "aws" | "azure" | "gcp" | "microsoft365";
  scan_identity_name: string;
  capabilities: BootstrapRequest["capabilities"];
  provider_authentication_url: string;
  allowed_endpoint_hosts: string[];
  operations: Array<{
    operation_id: string;
    description: string;
    mutates_provider: boolean;
    provider_api_operations: string[];
  }>;
  template_media_type: string;
  template_sha256: string;
  template: string;
  expires_at: string;
  cleanup_obligations: Array<{ obligation_id: string; description: string; required: boolean }>;
  safety_notice: string;
}

export interface ExecuteProviderBootstrapInput {
  operationId: string;
  execution: {
    schema_version: "1.0.0";
    bootstrap: BootstrapRequest;
    operator: BootstrapOperatorConfig;
  };
  sourceId: string;
  allowedEngineIds: string[];
  maxCheckouts: number;
}

export interface ProviderBootstrapInstalled {
  operationId: string;
  authorization: InstalledProviderAuthorization;
  cleanupLedgerPath: string;
}

export type BootstrapCleanupStatus =
  | "pending"
  | "in_progress"
  | "retryable_failure"
  | "waiting_for_credential_expiry"
  | "completed";

export interface BootstrapCleanupObligationSummary {
  operationId: string;
  provider: "aws" | "azure" | "gcp" | "microsoft365";
  caseId: string;
  schemaVersion: "1.0.0" | "1.0.0-partial";
  status: BootstrapCleanupStatus;
  totalItems: number;
  pendingItems: number;
  inProgressItems: number;
  retryableItems: number;
  waitingItems: number;
  completedItems: number;
  createdAt: string;
}

export interface CaseArtifactDeletionPlan {
  caseId: string;
  exactPath: string;
  exists: boolean;
  requiresExplicitConfirmation: boolean;
}

export interface CaseDeletionResponse {
  accepted: boolean;
  message: string;
  databaseRecordDeleted: boolean;
  artifacts: CaseArtifactDeletionPlan;
}

export interface CaseArtifactCleanupInput {
  caseId: string;
  exactPath: string;
  confirmation: string;
}

export interface CaseArtifactCleanupResult {
  removed: boolean;
  exactPath: string;
  recoverable: false;
}

export interface CoverageRecord {
  id: string;
  label: string;
  platform: CloudPlatform;
  sourceKind: SourceKind;
  state: CoverageState;
  /** Present for asset-level coverage rows. */
  assetId?: string;
  assetCount: number;
  detail: string;
  lastCheckedAt?: string;
  /** False means permission is saved but no scan plan has included this asset yet. */
  scanAttempted?: boolean;
}

export type SourceConnectionStatus =
  | "not_connected"
  | "connecting"
  | "connected"
  | "needs_reauthorization"
  | "failed"
  | "not_applicable";

export interface ConnectedSource {
  id: string;
  kind: SourceKind;
  label: string;
  status: SourceConnectionStatus;
  readOnly: boolean;
  connectedAt?: string;
  lastDiscoveredAt?: string;
  /**
   * Whitelisted, non-secret provider coordinates retained after backend
   * verification. Raw source metadata is never exposed through this type.
   */
  providerBinding?: {
    profile: ProviderSourceProfile;
    resourceScope: string;
  };
}

export type SourceCapabilityProvider = "aws" | "azure" | "gcp" | "microsoft365";

export type SourceCapabilityDimension =
  | "inventory"
  | "identity_and_access"
  | "network_exposure"
  | "storage_exposure"
  | "logging"
  | "secret_and_configuration";

export type SourceCapabilityState = "supported" | "partial" | "unavailable" | "unknown";

export interface SourceCapabilityEngine {
  id: string;
  name: string;
  profile: string;
  version?: string;
  availability: "available" | "unavailable" | "unknown";
  /** Catalog knowledge date, YYYY-MM-DD, when the manifest declared one. */
  knowledgeDate?: string;
}

export interface SourceCapabilityCell {
  dimension: SourceCapabilityDimension;
  state: SourceCapabilityState;
  engines: SourceCapabilityEngine[];
  limitation: { en: string; zhTW: string };
}

export interface SourceCapabilityView {
  schemaVersion: "1.0.0";
  definitionVersion: string;
  provider: SourceCapabilityProvider;
  sourceId: string;
  sourceKind: SourceKind;
  resourceScope?: string;
  cells: SourceCapabilityCell[];
}

export type AssetType =
  | "cloud_account"
  | "subscription"
  | "project"
  | "tenant"
  | "domain"
  | "ip"
  | "repository"
  | "image"
  | "cluster"
  | "service"
  | "cloud_resource"
  | "identity"
  | "storage";

export type ScopeMode =
  | "inventory"
  | "configuration"
  | "local_artifact"
  | "public_data"
  | "low_impact_external"
  | "active_external"
  // Backward-compatible aliases accepted from early snapshots.
  | "passive"
  | "active";
export type AuthorizationState = "authorized" | "pending" | "excluded" | "unknown";

export interface AssetIdentifier {
  namespace: string;
  value: string;
}

export interface Asset {
  id: string;
  name: string;
  type: AssetType;
  platform: CloudPlatform;
  locator: string;
  identifiers?: AssetIdentifier[];
  /** Exact saved data sources that discovered this asset. Missing provenance is never authorization. */
  discoveredFromSourceIds?: string[];
  region?: string;
  owner?: string;
  internetExposed?: boolean;
  containsSensitiveData?: boolean;
  coverageState: CoverageState;
  authorizationState: AuthorizationState;
  allowedModes: ScopeMode[];
  findingCount: number;
  lastObservedAt?: string;
  /** False means permission is saved but no scan plan has included this asset yet. */
  scanAttempted?: boolean;
  tags?: string[];
  /** True only for a local item named in the questionnaire but not attached yet. */
  questionnairePlaceholder?: boolean;
  localInputProfile?: LocalInputProfile;
  /**
   * Read-only folder copy the scanners actually read. Present only when the
   * saved digest is a 64-character lowercase sha256.
   */
  localCopy?: {
    sha256: string;
    savedAt?: string;
    previousSha256?: string;
    change?: {
      changed: number;
      added: number;
      removed: number;
      unchanged: number;
    };
  };
  /** Bounded exact candidates discovered inside an immutable repository snapshot. */
  mcpConfigurationCandidates?: Array<{
    relativePath: string;
    sha256: string;
    byteLength: number;
  }>;
  /** The one candidate bound to MCP Armor, if selection is unambiguous. */
  selectedMcpConfiguration?: string;
  agenticRadarFramework?: AgenticRadarFramework;
  modelEndpoint?: ModelEndpointInput;
  declaredWebService?: {
    protocol: "http" | "https";
    port: number;
    path: string;
    scanProfile?: InternalDeviceScanProfile;
  };
  declaredNetworkService?: {
    protocol: "tcp";
    port: number;
    scanProfile: InternalEndpointScanProfile;
  };
  declaredHostScan?: {
    protocol: "tcp";
    ports: number[];
    scanProfile: InternalHostScanProfile;
  };
}

export type ExternalActivity = "passive_public_discovery" | "low_impact_external" | "active_external";
export type TransportProtocol = "tcp" | "udp" | "tls" | "http" | "https";
export type DirectNetworkTargetKind = "hostname" | "address" | "network";

export interface ExternalRatePolicy {
  requestsPerSecond: number;
  concurrency: number;
  timeoutSeconds: number;
}

export interface ExternalTemplatePolicy {
  revision: string;
  /** Backend-owned upstream profile; IDs remain empty when this is present. */
  profileId?: string;
  allowedTemplateIds: string[];
  allowHeadless: boolean;
  allowOutOfBand: boolean;
  allowFuzzing: boolean;
  allowFileUpload: boolean;
  allowDenialOfService: false;
  allowCredentialAttacks: false;
}

export interface ExternalScopeRequest {
  target: string;
  ports: number[];
  protocol: TransportProtocol;
  activity: ExternalActivity;
  ratePolicy: ExternalRatePolicy;
  templatePolicy: ExternalTemplatePolicy;
  assertedAuthority: string;
  allowSensitiveNetworks: boolean;
}

export interface FrozenExternalScope extends ExternalScopeRequest {
  id: string;
  caseId: string;
  assetId: string;
  targetKind: DirectNetworkTargetKind;
  approvedBy: string;
  approvedAt: string;
  expiresAt: string;
}

export interface ScopeGrant {
  id: string;
  assetId: string;
  modes: ScopeMode[];
  state: AuthorizationState;
  confirmedAt?: string;
  confirmedBy?: string;
  note?: string;
  externalScope?: FrozenExternalScope;
}

export type RunStatus =
  | "queued"
  | "running"
  | "paused"
  | "completed"
  | "no_checks_completed"
  | "partial"
  | "failed"
  | "cancelled";

/** Exact task status vocabulary serialized by Rust's domain::EngineRunStatus. */
export type EngineRunStatusWire =
  | "not_executed"
  | "queued"
  | "preparing"
  | "running"
  | "paused"
  | "completed"
  | "partially_completed"
  | "failed"
  | "cancelled";

export type EngineRunStatus =
  | "pending"
  | "running"
  | "paused"
  | "completed"
  | "partial"
  | "failed"
  | "not_executed"
  | "cancelled";

/** Exact immutable scanner distribution vocabulary serialized by Rust. */
export type DistributionMode =
  | "bundled_image"
  | "pull_pinned_image"
  | "build_from_pinned_source"
  | "external_executable";

export type EngineCategory =
  | "cloud_inventory"
  | "cloud_configuration"
  | "identity_and_access"
  | "microsoft365"
  | "external_attack_surface"
  | "code_and_secrets"
  | "infrastructure_as_code"
  | "container_and_sbom"
  | "kubernetes"
  | "host"
  | "schema_and_export"
  | "ai_model_endpoint"
  | "ai_agent_framework"
  | "ai_mcp_configuration";

export type EngineManifestStatusWire =
  | "integrated"
  | "experimental"
  | "research_only"
  | "deprecated"
  | "license_review";

export type KnowledgeInputKind =
  | "embedded"
  | "external_pinned"
  | "external_pin_required"
  | "not_applicable"
  | "runtime_live"
  | "runtime_bound";

export type KnowledgePinState =
  | "awaiting_pin"
  | "runtime_live"
  | "runtime_bound"
  | "pinned_or_not_applicable";

export type ExecutionStage =
  | "planned"
  | "preflight"
  | "pulling_image"
  | "running"
  | "capturing_artifacts"
  | "adapting_artifacts"
  | "captured_awaiting_adapter"
  | "cleanup_pending"
  | "completed"
  | "cancelled"
  | "failed";

export interface EngineCheckpoint {
  attempt: number;
  stage: ExecutionStage;
  artifactCount: number;
  cleanupCompleted: boolean;
  scopeBound: boolean;
  lastError?: string;
}

/** Product-controlled failure categories safe to use in first-layer copy and support logs. */
export type EngineFailureKind = "gateway_preparation_failed";

/**
 * What the backend will do when the person continues a terminal check.
 * A restart is deliberately distinct from continuing preserved results.
 */
export type EngineRecoveryAction =
  | "none"
  | "restart_check"
  | "continue_saved_results"
  | "finish_cleanup";

/** Exact `EngineTaskKind` tags and fields serialized by the native Rust domain. */
export type EngineTaskKindWire =
  | { kind: "catalog_engine" }
  | {
      kind: "built_in_localhost_tcp";
      port: number;
      timeoutMs: number;
      payloadBytes: number;
    };

/** The work contract the app can present without inventing scanner provenance. */
export type EngineTaskKind = EngineTaskKindWire | { kind: "invalid_task" };

export type LocalhostTcpOutcome = "reachable" | "closed" | "timed_out";

/**
 * One bounded TCP connection observation. This is reachability evidence only,
 * never a vulnerability or security verdict.
 */
export interface LocalhostTcpObservation {
  outcome: LocalhostTcpOutcome;
  observedAt: string;
}

export type ScanRequestOutcomeCode =
  | "no_effective_scope_grants"
  | "no_ownership_confirmed_targets"
  | "no_applicable_checks";

/** A durable terminal request that contacted no target and completed no checks. */
export interface ScanRequestOutcome {
  status: "no_checks_completed";
  code: ScanRequestOutcomeCode;
  requestedAssetIds: string[];
  requestedEngineIds: string[];
}

/** Exact closed Rust wire vocabulary for an authorized target the engine did not evaluate. */
export type UnevaluatedTargetCauseWire =
  | "target_did_not_respond"
  | "scanner_error"
  | "no_security_template_execution_evidence"
  | "no_service_identified";

/** Adds the fail-closed member the wire never sends. */
export type UnevaluatedTargetCause = UnevaluatedTargetCauseWire | "unknown";

export interface UnevaluatedTarget {
  assetId: string;
  cause: UnevaluatedTargetCause;
}

export interface EngineRun {
  id: string;
  engineId: string;
  engineName: string;
  category: EngineCategory | "built_in_localhost_tcp" | "unknown";
  /** Absent for product-owned tasks that do not use a catalog engine. */
  version?: string;
  /** Version the scanner binary reports about itself. Absent on runs planned before this field existed, and on product-owned tasks. */
  reportedVersion?: string;
  /** Absent for product-owned tasks that do not use a container image. */
  digest?: string;
  taskKind: EngineTaskKind;
  localhostTcpObservation?: LocalhostTcpObservation;
  ruleVersion?: string;
  adapterVersion?: string;
  manifestSchemaVersion?: string;
  sourceRevision?: string;
  repositoryUrl?: string;
  distributionMode?: DistributionMode;
  imageRepository?: string;
  commandSha256?: string;
  knowledgeInput?: {
    kind: KnowledgeInputKind;
    identifier: string;
    version?: string;
    acquisitionSource?: string;
    pinState: KnowledgePinState;
    knowledgeDate?: string;
    supportUntil?: string;
  };
  runtimeProvider?: string;
  runtimeVersion?: string;
  runtimeSecurityOptions?: string;
  exitCode?: number;
  cleanupRemoved?: boolean;
  cleanupDetail?: string;
  warnings: string[];
  /** Authorized targets the engine did not evaluate; absent when none were recorded. */
  unevaluatedTargets?: UnevaluatedTarget[];
  status: EngineRunStatus;
  progress: number;
  phase: string;
  startedAt?: string;
  finishedAt?: string;
  assetIds: string[];
  rawArtifactCount: number;
  /** Engine-produced raw result artifacts, excluding backend-owned stdout/stderr captures. */
  savedResultArtifactCount: number;
  findingCount: number;
  /** False only when legacy evidence lacks an exact engine-run identifier. */
  findingCountKnown?: boolean;
  message?: string;
  errorCode?: string;
  checkpoint?: EngineCheckpoint;
  /** True when the target and permission contract was frozen for this run. */
  scopeContractBound?: boolean;
  /** Safe product-owned classification; never copied from scanner output. */
  failureKind?: EngineFailureKind;
  recoveryAction?: EngineRecoveryAction;
  resumable: boolean;
}

export interface ScanRun {
  id: string;
  caseId: string;
  label: string;
  /** Canonical backend sequence used to present product-generated run labels. */
  sequence?: number;
  verificationBaselineRunId?: string;
  requestOutcome?: ScanRequestOutcome;
  status: RunStatus;
  progress: number;
  startedAt: string;
  finishedAt?: string;
  /** Most recent durable scan lifecycle update; never derived from scanner output. */
  lastProgressAt?: string;
  knowledgeDate: string;
  /** Technical-only packaged scanner diagnostics frozen with this run. */
  engineAdmissionIssues?: EngineAdmissionIssue[];
  engineRuns: EngineRun[];
  coveredAssetCount: number;
  totalAssetCount: number;
}

export interface EngineAdmissionIssue {
  engineId?: string;
  code: string;
  detail: string;
}

export type BeginnerReportSummary = "complete" | "partial" | "no_checks_completed";
export type BeginnerReportLifecycle = "final";
export type BeginnerReportDataAvailability =
  | "recorded"
  | "current_case_fallback"
  | "unavailable"
  | "not_applicable";
export type BeginnerReportStage = "connection_diagnostic" | "quick_discovery" | "inventory" | "deep";
export type BeginnerCoverageStatus =
  | "tested_complete"
  | "tested_partial"
  | "failed"
  | "timed_out"
  | "cancelled"
  | "not_tested";
export type BeginnerCoverageGapKind =
  | "not_tested"
  | "failed"
  | "timed_out"
  | "cancelled"
  | "excluded"
  | "truncated"
  | "unavailable"
  | "unattributed"
  | "manual_review";
export type BeginnerCoverageGapClass = "coverage_loss" | "record_note";
export type BeginnerNextActionCode =
  | "review_finding"
  | "confirm_finding_after_incomplete_check"
  | "retry_check"
  | "start_new_scan"
  | "review_scope_and_retry"
  | "choose_compatible_check"
  | "start_expected_service_and_retry"
  | "review_coverage"
  | "review_manual_control"
  | "preserve_visible_limitation"
  | "no_action_unless_scope_changes"
  | "add_asset_identifier";

/** Exact wire vocabulary serialized by Rust's domain::AssetKind. */
export type AssetKind =
  | "cloud_organization"
  | "cloud_account"
  | "subscription"
  | "project"
  | "tenant"
  | "domain"
  | "ip_address"
  | "host"
  | "web_service"
  | "cloud_resource"
  | "identity"
  | "repository"
  | "file_system"
  | "iac_project"
  | "container_image"
  | "container_registry"
  | "kubernetes_cluster"
  | "ai_model_endpoint"
  | "other";

export interface BeginnerRequestedTarget {
  assetId: string;
  label?: string;
  assetKind?: AssetKind;
  labelAvailability: BeginnerReportDataAvailability;
  assetKindAvailability: BeginnerReportDataAvailability;
}

/** Where a frozen report limit was recorded before execution. */
export type BeginnerRequestedLimitSource = "frozen_task_contract" | "frozen_scope_grant";

export interface BeginnerRequestedLimit {
  name: string;
  value: string;
  source: BeginnerRequestedLimitSource;
}

export interface BeginnerUnavailableDimension {
  dimension: string;
  explanation: string;
}

export interface BeginnerRequestedCoverage {
  targets: BeginnerRequestedTarget[];
  stage: {
    value?: BeginnerReportStage;
    availability: BeginnerReportDataAvailability;
    explanation: string;
  };
  limits: BeginnerRequestedLimit[];
  requestedCheckIds: string[];
  requestOutcomeCode?: ScanRequestOutcomeCode;
  automaticReductions: Array<{
    dimension: string;
    requested: string;
    executed: string;
    reason: string;
  }>;
  reductionsAvailability: BeginnerReportDataAvailability;
  unavailableDimensions: BeginnerUnavailableDimension[];
}

/** Exact check-result vocabulary serialized by the native Rust report. */
export type BeginnerCheckResultKindWire = "security_check" | "inventory" | "connectivity";
/** Product report semantics after the native boundary rejects unrecognized values. */
export type BeginnerCheckResultKind = BeginnerCheckResultKindWire | "unknown";

export interface BeginnerActualCheck {
  taskId: string;
  checkId: string;
  /** Absent only on reports saved before check-result semantics were frozen. */
  resultKind?: BeginnerCheckResultKind;
  targetAssetIds: string[];
  status: BeginnerCoverageStatus;
  startedAt?: string;
  finishedAt?: string;
  testedDimensions: Array<{
    dimension: string;
    value: string;
    observation: string;
    observedAt?: string;
  }>;
}

export interface BeginnerNetworkScopeCoverage {
  taskId: string;
  checkId: string;
  workUnitId: string;
  targetAssetId: string;
  target: string;
  addressRanges: string[];
  portRanges: string[];
  transport: string;
  stage: "quick_discovery" | "inventory" | "deep";
  outcome: "tested_complete" | "tested_partial" | "failed" | "timed_out" | "cancelled" | "not_tested";
  observedAt?: string;
}

export interface BeginnerActualCoverage {
  observedFrom?: string;
  observedUntil?: string;
  checks: BeginnerActualCheck[];
  networkScopes: BeginnerNetworkScopeCoverage[];
  unavailableDimensions: BeginnerUnavailableDimension[];
}

export interface BeginnerCoverageGap {
  kind: BeginnerCoverageGapKind;
  /**
   * Older saved reports omitted this field. Absence is coverage loss — the
   * same conservative historical meaning the backend default uses — and is
   * filled in by the adapter rather than left for each surface to guess.
   */
  class: BeginnerCoverageGapClass;
  taskId?: string;
  targetAssetIds: string[];
  dimension: string;
  reason: string;
  nextActionCode: BeginnerNextActionCode;
  nextAction: string;
  /**
   * Present only on an "unattributed" gap. The prose above is English composed
   * by the backend; this is what the reader's own sentence is rebuilt from, and
   * the identifier is what they have to copy onto the asset.
   */
  unattributed?: UnattributedResults;
}

export interface UnattributedResults {
  provider: string;
  identifier: string;
  discardedResults: number;
}

/** Where this report finding's reader-visible data came from. */
export type BeginnerFindingSnapshotSource =
  | "frozen_selected_run"
  | "current_canonical_legacy_fallback"
  | "observation_only";

export interface BeginnerReportFinding {
  findingId: string;
  fingerprint: string;
  snapshotSource: BeginnerFindingSnapshotSource;
  title: string;
  plainLanguageRisk: string;
  possibleImpact: string;
  severity: Severity;
  confidence: Confidence;
  priority?: number;
  priorityReasons: string[];
  targetAssetIds: string[];
  nextStep: string;
  recommendedExpertType: string;
  /**
   * The codes the three sentences above were composed from. The findings list
   * projects its rows from this frozen report rather than from the canonical
   * findings, so a localized surface can only rewrite those sentences if the
   * codes travel with them. Optional because a report frozen before they
   * existed carries prose and nothing else.
   */
  family?: FindingFamily;
  severityBasisCode?: SeverityBasisCode;
  confidenceBasisCode?: ConfidenceBasisCode;
  /** Useful reachability facts retained without claiming a vulnerability. */
  observationDetails?: string[];
  /** Empty unless this case raised the finding's priority. */
  contextFactors?: ContextFactor[];
  /** What to preserve before changing anything, and how to confirm the fix. */
  rollbackConsiderations?: string;
  verificationGuidance?: string;
  evidenceReferences: Array<{
    evidenceId: string;
    engineId: string;
    /** True only when the optional provenance came from this selected run. */
    detailsFrozen?: boolean;
    /** Exact normalized upstream rule or detector identifier, when retained. */
    sourceRule?: string;
    /** Scanner-authored, untrusted evidence detail; never a product action. */
    scannerDetails?: ScannerFindingDetails;
    summary?: string;
    kind?: EvidenceKind;
    engineRunId?: string;
    artifactId?: string;
    redacted?: boolean;
    artifactSha256: string;
    observedAt: string;
    /** Scanner-reported, product-redacted file, package, URL, or service location. */
    location?: string;
    /** Where inside the retained artifact this record sits, when one was kept. */
    pointer?: string;
  }>;
  /** Undefined only for reports that predate run-frozen official references. */
  officialReferences?: string[];
  frameworkReferences: Array<{
    framework: string;
    frameworkVersion: string;
    controlId: string;
    title: string;
    relationship: string;
    rationale: string;
    mappingVersion: string;
    /** Exact reviewed mapping-catalog identity frozen with this report row. */
    mappingProvenance?: ControlMappingProvenance;
  }>;
}

export type BeginnerFindingGroupPresentationScope = "current_case_presentation";

export interface BeginnerReportFindingGroup {
  groupId: string;
  presentationScope: BeginnerFindingGroupPresentationScope;
  title: string;
  rationale: string;
  actor: string;
  createdAt: string;
  members: Array<{
    findingId: string;
    observedInSelectedRun: boolean;
  }>;
}

export interface BeginnerUnavailableTechnicalValue {
  availability: BeginnerReportDataAvailability;
  value?: string;
  explanation: string;
}

export type BeginnerTechnicalExecution =
  | {
      kind: "catalog_engine";
      engineId: string;
      engineVersion?: string;
      /** Version the scanner binary reports about itself. Absent on reports saved before this field existed. */
      reportedVersion?: string;
      imageDigest?: string;
      commandSha256?: string;
      runtimeProvider?: string;
      runtimeVersion?: string;
      runtimeSecurityOptions?: string;
      distributionMode?: DistributionMode;
      imageRepository?: string;
      adapterVersion: string;
      ruleVersion?: string;
      /** Recorded knowledge input date, YYYY-MM-DD. Absent on older reports. */
      knowledgeDate?: string;
    }
  | {
      kind: "built_in_localhost_tcp";
      endpoint: string;
      timeoutMs: number;
      payloadBytes: number;
      observation?: LocalhostTcpObservation;
      contract: string;
    }
  | {
      kind: "invalid_built_in_task";
      explanation: string;
    };

export interface BeginnerTechnicalTaskDetails {
  taskId: string;
  targetAssetIds: string[];
  status: EngineRunStatus;
  phase: string;
  progressPercent: number;
  startedAt?: string;
  finishedAt?: string;
  exitCode?: number;
  cleanupRemoved?: boolean;
  cleanupDetail: BeginnerUnavailableTechnicalValue;
  errorCode?: string;
  redactedScannerMessage: BeginnerUnavailableTechnicalValue;
  redactedDiagnosticLog: BeginnerUnavailableTechnicalValue;
  evidenceSha256: string[];
  execution: BeginnerTechnicalExecution;
}

export interface BeginnerNextStep {
  priority: number;
  code: BeginnerNextActionCode;
  action: string;
  reason: string;
  findingId?: string;
  taskId?: string;
  recommendedExpertType?: string;
  family?: FindingFamily;
  unattributed?: UnattributedResults;
  /** Other findings the same instruction covers; `sharedFix` says whether one change fixes them all. */
  alsoResolves?: string[];
  /** True only when every covered finding is fixed by the one specific change the action names. */
  sharedFix?: boolean;
}

export interface BeginnerInventorySource {
  observationId: string;
  engineId: string;
  engineRunId: string;
  artifactId: string;
  artifactSha256: string;
  pointer: string;
  observedAt: string;
}

export type BeginnerInventoryItem = {
  assetId: string;
  sources: BeginnerInventorySource[];
} & ({
  kind: "service";
  endpoint: string;
  port?: number;
  transport?: string;
  schemes: string[];
  httpStatuses: number[];
  tlsObservations: boolean[];
} | {
  kind: "software_component";
  name: string;
  version?: string;
  packageType?: string;
  purl?: string;
} | {
  kind: "cloud_resource";
  resourceType: string;
  nativeId?: string;
  displayName?: string;
} | {
  kind: "workflow_component";
  componentType: string;
  name: string;
  model?: string;
  isGuardrail?: boolean;
} | {
  kind: "workflow_relationship";
  source: string;
  target: string;
  condition?: string;
});

export interface BeginnerInventoryCounts {
  services: number;
  softwareComponents: number;
  cloudResources: number;
  workflowComponents: number;
  workflowRelationships: number;
}

export interface BeginnerInventory {
  total: number;
  counts: BeginnerInventoryCounts;
  assetIds: string[];
  representativeSample: BeginnerInventoryItem[];
  items: BeginnerInventoryItem[];
  byAsset: Array<{
    assetId: string;
    total: number;
    counts: BeginnerInventoryCounts;
    representativeSample: BeginnerInventoryItem[];
  }>;
}

export interface BeginnerMasterReport {
  schemaVersion: string;
  caseId: string;
  runId: string;
  projectTitle: string;
  state: {
    summary: BeginnerReportSummary;
    lifecycle: BeginnerReportLifecycle;
    lastDurableUpdate: string;
    explanation: string;
  };
  requested: BeginnerRequestedCoverage;
  actual: BeginnerActualCoverage;
  coverageGaps: BeginnerCoverageGap[];
  coverageCounts: Record<
    | "testedComplete"
    | "testedPartial"
    | "failed"
    | "timedOut"
    | "cancelled"
    | "notTested"
    | "excluded"
    | "truncated"
    | "unavailable"
    | "unattributed"
    | "manualReview",
    number
  >;
  /** Absent only for reports created before typed inventory was projected. */
  inventory?: BeginnerInventory;
  findings: BeginnerReportFinding[];
  /** Current-case presentation groups projected onto this selected run. */
  findingGroups: BeginnerReportFindingGroup[];
  /** Selected-run related checks; original observations remain in findings. */
  problemGroups?: BeginnerReportProblemGroup[];
  nextSteps: BeginnerNextStep[];
  /** Expert-only, redacted execution records. The Results page keeps these collapsed. */
  technicalDetails: {
    collapsedByDefault: true;
    tasks: BeginnerTechnicalTaskDetails[];
  };
  frameworkNotice: {
    nonCertification: string;
    aidefendMappingStatus: string;
  };
  dataQualityWarnings: string[];
}

export interface BeginnerReportProblemGroup {
  groupId: string;
  ruleVersion: string;
  kind:
    | "iam_password_policy"
    | "root_account_usage"
    | "iam_policy_permissions"
    | "vulnerable_dependency"
    | "exposed_secret";
  title: string;
  targetAssetId: string;
  representativeFindingId: string;
  findingIds: string[];
  policyName?: string;
  packageName?: string;
  installedVersion?: string;
  advisoryIds?: string[];
  /** Set when this product orders some or all members lower than their severity. */
  lowerPriorityMembers?: "partial" | "all";
}

export type ScanReadinessState =
  | "ready"
  | "case_unavailable"
  | "scan_in_progress"
  | "scope_required"
  | "ownership_required"
  | "no_compatible_authorized_targets"
  | "no_runnable_authorized_targets"
  | "runtime_unavailable"
  | "provider_connection_required"
  | "provider_capability_required"
  | "provider_review_required"
  | "provider_check_unavailable"
  | "execution_input_unavailable"
  | "scanner_setup_required"
  | "execution_check_unavailable";

export type ScanReadinessBlocker =
  | "demo_case"
  | "archived_case"
  | "scan_already_active"
  | "no_effective_scope_grants"
  | "no_ownership_confirmed_targets"
  | "no_compatible_authorized_targets"
  | "no_runnable_authorized_targets"
  | "runtime_unavailable"
  | "provider_source_required"
  | "provider_capability_unavailable"
  | "provider_source_ambiguous"
  | "provider_authorization_binding_mismatch"
  | "provider_target_binding_mismatch"
  | "provider_preflight_unavailable"
  | "workspace_snapshot_unavailable"
  | "egress_gateway_unavailable"
  | "engine_execution_contract_invalid"
  | "passive_source_unavailable"
  | "captured_evidence_unavailable"
  | "execution_preflight_unavailable";

export type ScanReadinessNextStep = "cases" | "coverage" | "progress" | "scanner_setup" | "retry";

/** Authoritative, non-mutating backend preflight for the primary scan action. */
export interface ScanReadiness {
  caseId: string;
  /** Backend timestamp for this read-only readiness evaluation. */
  checkedAt: string;
  ready: boolean;
  state: ScanReadinessState;
  authorizedTargetCount: number;
  pendingTargetCount: number;
  compatibleEngineCount: number;
  runnableEngineCount: number;
  blockerCode?: ScanReadinessBlocker;
  nextStep?: ScanReadinessNextStep;
}

/** Exact wire vocabulary serialized by Rust's domain::Severity. */
export type SeverityWire = "unknown" | "informational" | "low" | "medium" | "high" | "critical";
/** Reader-facing vocabulary after the native adapter normalizes informational. */
export type Severity = "critical" | "high" | "medium" | "low" | "unknown" | "info";
/** Exact confidence vocabulary serialized by Rust's domain::Confidence. */
export type Confidence = "confirmed" | "high" | "medium" | "low" | "unknown";
/** Exact workflow vocabulary serialized by Rust's domain::FindingStatus. */
export type FindingStatusWire =
  | "unreviewed"
  | "expert_review_requested"
  | "confirmed"
  | "false_positive"
  | "remediation_reported"
  | "verified_resolved";

export type FindingWorkflowState =
  | "unreviewed"
  | "expert_review_requested"
  | "confirmed"
  | "unconfirmed"
  | "assigned"
  | "false_positive"
  | "remediation_reported"
  | "remediated_pending_verification"
  | "verified_resolved";

/** Exact evidence provenance vocabulary serialized by Rust's domain::EvidenceKind. */
export type EvidenceKind =
  | "configuration"
  | "observation"
  | "external_validation"
  | "source_code"
  | "package_inventory"
  | "user_declaration"
  | "raw_tool_output";

export interface Evidence {
  id: string;
  sourceEngine: string;
  /** Exact normalized upstream rule or detector identifier, when retained. */
  sourceRule?: string;
  /** Scanner-authored, untrusted evidence detail; never a product action. */
  scannerDetails?: ScannerFindingDetails;
  observedAt: string;
  summary: string;
  /** Scanner-reported location kept separate from explanatory prose. */
  location?: string;
  rawArtifactHash: string;
  rawArtifactPath?: string;
  kind?: EvidenceKind;
  runId?: string;
  engineRunId?: string;
  artifactId?: string;
  redacted?: boolean;
}

/**
 * A benchmark a scanner says its rule checks.
 * Scanner-reported and untrusted; never a product claim of conformance.
 */
export interface BenchmarkReference {
  name: string;
  version: string;
  reference: string;
}

export interface ScannerFindingDetails {
  description?: string;
  remediation?: string;
  installedVersion?: string;
  fixedVersion?: string;
  /** Bounded, untrusted AWS IAM policy context retained from Cloudsplaining. */
  awsIamPolicy?: AwsIamPolicyFindingDetails;
  /** Present only when the scanner reported at least one usable benchmark reference. */
  benchmarks?: BenchmarkReference[];
}

export type AwsIamPolicySource = "aws_managed" | "customer_managed" | "inline";

export interface AwsIamPolicyFindingDetails {
  policySource: AwsIamPolicySource;
  policyName: string;
  findingIdentity: string;
  actions: string[];
  actionsComplete: boolean;
  attachedTo: {
    roles: string[];
    groups: string[];
    users: string[];
    complete: boolean;
  };
}

export interface ControlReference {
  framework: string;
  version: string;
  controlId: string;
  relationship: "related";
  title?: string;
  rationale?: string;
  mappingVersion?: string;
  /** Exact reviewed mapping-catalog identity frozen with this relationship. */
  mappingProvenance?: ControlMappingProvenance;
  note?: string;
}

export interface ControlMappingProvenance {
  mappingVersion: string;
  reviewedAt: string;
  reviewProcess: string;
  catalogSha256: string;
}

/// The kind of problem a finding reports. The backend composes its English
/// `summary`, `impact` and `recommendation` from this plus `severity`; carrying
/// the code lets this side write the same sentences in the reader's language
/// instead of showing a translated heading over an English paragraph.
export type FindingFamily =
  | "cloud_posture"
  | "cloud_identity"
  | "microsoft365"
  | "network_exposure"
  | "source_code"
  | "secret"
  | "infrastructure_as_code"
  | "vulnerable_component"
  | "kubernetes"
  | "model_behavior"
  | "mcp_secret"
  | "mcp_configuration";

/**
 * Why this case raised a finding's priority above the scanner's own rating.
 *
 * The backend appends a sentence to `possibleImpact` for each of these. A
 * surface that composes its own impact sentence replaces that string, so it
 * has to put them back or the reader sees a raised priority with no reason.
 */
export type ContextFactor = "internet_exposed_asset" | "sensitive_data_asset";

/// Why this product derived a severity when the engine left it unrated. A
/// stored `unknown` with this code still has no scanner rating and must remain
/// pending human confirmation; historical derived High/Medium values retain
/// their existing attribution. Absent when the rating is the engine's own.
export type SeverityBasisCode =
  | "open_port"
  | "reachable_http_service"
  | "secret_pattern_match"
  | "unverified_credential_detector"
  | "iac_policy_check"
  | "cis_kubernetes_benchmark"
  | "cloud_control_query"
  | "cloudsplaining_iam_policy_finding"
  | "unrated_vulnerability_test_alarm"
  | "adversarial_probe_failure_rate";

/** Why this product assigned confidence when the engine supplied none. */
export type ConfidenceBasisCode =
  | "deterministic_policy_evaluation"
  | "advisory_version_match"
  | "unverified_pattern_or_detector_match"
  | "observed_response"
  | "template_matcher"
  | "missing_detection_quality_score";

export interface Finding {
  id: string;
  caseId?: string;
  fingerprint: string;
  assetId: string;
  assetIds?: string[];
  assetName: string;
  /** The engine's own wording, never restated in another language. */
  title: string;
  /**
   * Backend-composed English. Prefer the sentence built from `family` and
   * `severityBasisCode`; these remain the fallback for findings stored before
   * those codes existed.
   */
  summary: string;
  impact: string;
  recommendation: string;
  /** Absent on findings stored before the codes were carried. */
  family?: FindingFamily;
  severityBasisCode?: SeverityBasisCode;
  confidenceBasisCode?: ConfidenceBasisCode;
  /** Product-owned port/protocol/status facts for reachability observations. */
  observationDetails?: string[];
  /**
   * Why this case raised the priority. The backend appends a sentence to
   * `impact` for each; a composed impact sentence replaces that string, so
   * these have to be put back or the reason disappears.
   */
  contextFactors?: ContextFactor[];
  /** Report-ready view of Cloudsplaining's frozen structured evidence. */
  awsIamPolicy?: AwsIamPolicyFindingDetails;
  expertType: string;
  severity: Severity;
  confidence: Confidence;
  priority: number;
  priorityReasons?: string[];
  workflowState: FindingWorkflowState;
  evidence: Evidence[];
  controls: ControlReference[];
  officialReferences: string[];
  verificationGuidance?: string;
  rollbackConsiderations?: string;
  tags?: string[];
  firstSeenRunId?: string;
  lastSeenRunId?: string;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface FindingWorkflowEvent {
  id: string;
  findingId: string;
  fromStatus: FindingWorkflowState;
  toStatus: FindingWorkflowState;
  decidedBy: string;
  decidedAt: string;
  reason: string;
  expiresAt?: string;
}

export interface FindingGroup {
  id: string;
  caseId: string;
  title: string;
  findingIds: string[];
  rationale: string;
  groupedBy: string;
  createdAt: string;
}

export type FindingGroupAction = "created" | "removed";

export interface FindingGroupEvent {
  id: string;
  caseId: string;
  groupId: string;
  action: FindingGroupAction;
  title: string;
  findingIds: string[];
  /** Creation rationale for `created`; explicit removal reason for `removed`. */
  rationale: string;
  actor: string;
  occurredAt: string;
}

export interface FindingGroupInput {
  caseId: string;
  title: string;
  findingIds: string[];
  rationale: string;
  groupedBy: string;
}

export interface FindingUngroupInput {
  caseId: string;
  groupId: string;
  removedBy: string;
  reason: string;
}

/**
 * Whether agreement between engines is independent confirmation. Only
 * `not-established` exists today: the vulnerability-database provenance that
 * would prove independence is not retained, so two engines agreeing must never
 * be presented as two independent confirmations.
 */
export type CorroborationStatus = "not-established";

export interface FindingCorrelationSuggestion {
  /** Derived from the comparison key, so a dismissal survives recomputation. */
  id: string;
  caseId: string;
  comparisonKey: string;
  /** Version of the rule that produced `comparisonKey`. */
  keyVersion: string;
  /** The published identifier both engines named. */
  vulnerabilityId: string;
  /** The package both engines named. */
  package: string;
  /** Proposed group title, used as the default when the user accepts. */
  title: string;
  /**
   * Plain-language statement of exactly what matched, in English only. The UI
   * composes its own bilingual sentence from the structured fields instead of
   * rendering this, so a zh-TW reader is never handed English prose.
   */
  basis: string;
  /** What this suggestion does not establish. English only; see `basis`. */
  uncertainty: string;
  corroboration: CorroborationStatus;
  findingIds: string[];
  engineIds: string[];
}

/** Findings that share a vulnerability id but could not be compared. */
export interface UnverifiableCorrelation {
  caseId: string;
  vulnerabilityId: string;
  findingIds: string[];
  /** Which coordinate was missing or inconsistent. */
  reason: string;
}

export interface CorrelationReport {
  keyVersion: string;
  suggestions: FindingCorrelationSuggestion[];
  unverifiable: UnverifiableCorrelation[];
  /** Suggestions dropped by the backend's cap. Never silently zero. */
  truncatedSuggestions: number;
}

export interface FindingWorkflowUpdateInput {
  caseId: string;
  findingId: string;
  status: "unreviewed" | "expert_review_requested" | "confirmed" | "false_positive" | "remediation_reported" | "verified_resolved";
  decidedBy: string;
  reason: string;
  expiresAt?: string;
}

/** Exact comparison status serialized by Rust's domain::FindingDiffStatus. */
export type FindingDiffStatus =
  | "resolved"
  | "still_present"
  | "newly_observed"
  | "changed"
  | "unable_to_verify";

/** Machine-readable comparison reasons serialized by Rust's domain::FindingDiffReasonCode. */
export type FindingDiffReasonCode =
  | "coordinate_not_completed"
  | "comparison_identity_missing"
  | "scope_contract_changed"
  | "manifest_schema_changed"
  | "engine_version_changed"
  | "image_changed"
  | "rule_version_changed"
  | "knowledge_input_changed"
  | "adapter_version_changed"
  | "source_revision_changed"
  | "repository_changed"
  | "distribution_mode_changed"
  | "command_changed"
  | "mapping_version_changed"
  | "fingerprint_schema_changed"
  | "severity_changed"
  | "confidence_changed"
  | "evidence_changed"
  | "affected_assets_changed"
  | "observing_engines_changed"
  | "location_moved";

export type DiffState = "resolved" | "persistent" | "new" | "unverifiable";

export interface VerificationDiff {
  id: string;
  findingId?: string;
  title: string;
  assetName: string;
  state: DiffState;
  /** Native five-way status retained so presentation can distinguish changed from unchanged. */
  comparisonStatus?: FindingDiffStatus;
  beforeSeverity?: Severity;
  afterSeverity?: Severity;
  explanation: string;
  evidenceChanged: boolean;
  changeReasons?: Array<{
    code: FindingDiffReasonCode;
    engineId?: string;
    assetId?: string;
    detail: string;
  }>;
}

export interface VerificationSummary {
  baselineRunId: string;
  comparisonRunId: string;
  baselineAt: string;
  comparisonAt: string;
  complete?: boolean;
  completenessIssues?: Array<{
    code: FindingDiffReasonCode;
    engineId?: string;
    assetId?: string;
    detail: string;
  }>;
  diffs: VerificationDiff[];
  /** Folder copies the comparison actually read. Omitted when the run had none. */
  localInputChanges?: Array<{
    assetId: string;
    baselineSha256: string;
    currentSha256: string;
    changed: boolean;
  }>;
}

export type ExportFormat =
  | "case_bundle"
  | "json"
  | "framework_report"
  | "ocsf"
  | "oscal"
  | "html";

/** Exact `RedactionProfile` values serialized by the native export layer. */
export type RedactionProfile = "standard" | "none";

export interface CaseExport {
  id: string;
  caseId: string;
  /** Immutable scan-run coordinate captured when this export was created. */
  runId: string;
  /** Missing only for a record written before exact export metadata existed. */
  format?: ExportFormat;
  createdAt: string;
  fileName: string;
  sha256: string;
  coverageManifestPath?: string;
  coverageManifestSha256?: string;
  signatureState: "unsigned" | "local_integrity";
  includesRawEvidence?: boolean;
  rawArtifactsIncluded?: number;
  rawArtifactsOmitted?: number;
  path?: string;
  isDemo?: boolean;
}

export interface ExportPreview {
  caseId: string;
  runId: string;
  /** Presentation locale bound to this exact preview coordinate. */
  locale: ReportLocale;
  format: ExportFormat;
  redactionProfile: RedactionProfile;
  includeRawEvidence: boolean;
  dataSourceCount: number;
  coverageEntryCount: number;
  assetCount: number;
  candidateAssetCount: number;
  canonicalFindingCount: number;
  selectedRunFindingCount: number;
  evidenceIndexCount: number;
  selectedRunEvidenceCount: number;
  scanRunCount: number;
  selectedEngineRunCount: number;
  externalScopeGrantCount: number;
  incompleteEngineRunCount: number;
  notExecutedEngineRunCount: number;
  unknownSourceCount: number;
  connectedNoAssetCount: number;
  rawArtifactCount: number;
  rawArtifactsIncluded: number;
  rawArtifactsOmitted: number;
  sensitiveRawArtifactsOmitted: number;
  sensitiveDataWarning: string;
  coverageManifestIncluded: boolean;
}

export interface EngineManifest {
  id: string;
  name: string;
  category: EngineCategory | "unknown";
  version: string;
  imageDigest: string;
  license: string;
  redistribution: "bundled" | "on_demand" | "external" | "unknown";
  platforms: CloudPlatform[];
  supportedProviders: CloudPlatform[];
  status: "ready" | "not_downloaded" | "unsupported" | "outdated";
  /** Exact release-contract availability, distinct from local runtime setup. */
  runnable?: boolean;
  /** Release blockers are used only to classify this engine's capability cells. */
  blockedBy: string[];
  /** False means the compatibility payload was malformed or contradictory. */
  compatibilityValid: boolean;
  providerExecutionProfiles: Array<{
    provider: SourceCapabilityProvider;
    assetKind: string;
    profile: string;
  }>;
  knowledgeDate?: string;
}

export interface CaseWorkspace {
  case: AssessmentCase;
  sources: ConnectedSource[];
  coverage: CoverageRecord[];
  assets: Asset[];
  scopeGrants: ScopeGrant[];
  runs: ScanRun[];
  findings: Finding[];
  findingGroups: FindingGroup[];
  findingGroupEvents: FindingGroupEvent[];
  workflowEvents: FindingWorkflowEvent[];
  exports: CaseExport[];
  /** One backend-derived report per terminal run. */
  beginnerReports?: BeginnerMasterReport[];
  verification?: VerificationSummary;
}

export interface AppSnapshot {
  cases: AssessmentCase[];
  selectedCaseId?: string;
  workspace?: CaseWorkspace;
  engineManifests: EngineManifest[];
  generatedAt: string;
  provenance: "native" | "demo";
  productName?: string;
  productVersion?: string;
  storagePath?: string;
  runtime?: {
    provider: string;
    available: boolean;
    phase: string;
    version?: string;
    prerequisite?: string;
    detail: string;
  };
  artifactCleanupObligations?: CaseArtifactDeletionPlan[];
  /** Saved projects that were preserved but could not be opened in this snapshot. */
  caseRecoveryDiagnostics?: CaseRecoveryDiagnostic[];
  /** Technical-only current packaged scanner diagnostics. */
  engineAdmissionIssues?: EngineAdmissionIssue[];
  engineCount?: number;
}

export interface CaseRecoveryDiagnostic {
  caseId: string;
  title: string;
  updatedAt: string;
  revision: number;
  documentBytes: number;
  code: string;
  message: string;
  preserved: boolean;
}

export type ManagedRuntimeSetupPhase =
  | "idle"
  | "install"
  | "prerequisite"
  | "download"
  | "recovery"
  | "init"
  | "start"
  | "verify"
  | "completed"
  | "failed"
  | "cancelled";

export type ManagedRuntimeSetupFailureReason =
  | "windows_wsl_not_installed"
  | "windows_wsl_optional_feature_disabled"
  | "windows_wsl_update_required"
  | "windows_restart_required"
  | "windows_wsl_command_failed"
  | "packaged_runtime_missing"
  | "packaged_runtime_verification_failed"
  | "developer_build_without_packaged_runtime"
  | "developer_build_packaged_runtime_verification_failed";

export type ManagedRuntimeSetupNextAction =
  | "install_wsl"
  | "enable_wsl_optional_features"
  | "update_wsl"
  | "restart_windows"
  | "retry_wsl_check";

export interface ManagedRuntimeSetupStatus {
  phase: ManagedRuntimeSetupPhase;
  active: boolean;
  prerequisiteRepairActive: boolean;
  /** Backend identity for the current or most recently completed operation. */
  operationId?: string;
  startedAt?: string;
  lastHeartbeatAt?: string;
  /** Computed by the backend after authoritative reconciliation, never by a UI timer. */
  stale?: boolean;
  cancelRequested: boolean;
  receivedBytes: number;
  totalBytes?: number;
  progressPercent?: number;
  resumedFromBytes: number;
  canCancel: boolean;
  canRetry: boolean;
  failureReason?: ManagedRuntimeSetupFailureReason;
  nextAction?: ManagedRuntimeSetupNextAction;
  detail: string;
}

export interface ServiceResult<T> {
  data: T;
  mode: AppMode;
  notice?: string;
}

export interface ExportCaseInput {
  caseId: string;
  runId: string;
  locale: ReportLocale;
  format: ExportFormat;
  includeRawEvidence: boolean;
  redactSensitiveValues: boolean;
  destination?: string;
}

export type ReportLocale = "en" | "zh-Hant";

export interface ToastMessage {
  id: number;
  tone: "info" | "success" | "warning" | "danger";
  title: string;
  detail?: string;
}
