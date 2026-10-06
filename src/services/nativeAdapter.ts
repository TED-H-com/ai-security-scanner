import { agenticRadarFramework } from "../agenticRadarProfile";
import { validatedModelEndpoint } from "../garakProfile";
import type {
  AppSnapshot,
  AssessmentCase,
  AssessmentActivity,
  AiGeneratedArtifactAnswer,
  AwsIamPolicyFindingDetails,
  BenchmarkReference,
  Asset,
  AssetKind,
  AssetType,
  BeginnerCheckResultKind,
  BeginnerCheckResultKindWire,
  BeginnerCoverageGapClass,
  BeginnerCoverageGapKind,
  BeginnerFindingGroupPresentationScope,
  BeginnerInventoryItem,
  BeginnerMasterReport,
  BeginnerTechnicalExecution,
  CaseExport,
  CaseProductIdentity,
  ContextFactor,
  ExportPreview,
  ReportLocale,
  CasePhase,
  CaseStatusWire,
  CaseWorkspace,
  CloudPlatform,
  CompanySize,
  Confidence,
  ConfidenceBasisCode,
  ConnectedSource,
  ControlMappingProvenance,
  CoverageRecord,
  CoverageState,
  CoverageStatusWire,
  DataClass,
  DataClassWire,
  DiffState,
  DirectNetworkTargetKind,
  DistributionMode,
  EngineCategory,
  EngineManifest,
  EngineManifestStatusWire,
  EngineCheckpoint,
  EngineFailureKind,
  EngineRecoveryAction,
  EngineRun,
  EngineRunStatus,
  EngineRunStatusWire,
  EngineTaskKind,
  EvidenceKind,
  ExternalActivity,
  FrozenExternalScope,
  ExportFormat,
  Finding,
  FindingDiffReasonCode,
  FindingDiffStatus,
  FindingFamily,
  FindingGroup,
  FindingGroupAction,
  FindingGroupEvent,
  FindingStatusWire,
  FindingWorkflowState,
  LocalInputProfile,
  LocalhostTcpObservation,
  LocalNetworkCandidateInventory,
  LocalNetworkCandidateStatus,
  LocalPrivateSubnetCandidate,
  ManagedRuntimeSetupFailureReason,
  ManagedRuntimeSetupNextAction,
  ManagedRuntimeSetupPhase,
  ManagedRuntimeSetupStatus,
  KnowledgeInputKind,
  KnowledgePinState,
  ProviderSourceProfile,
  RunStatus,
  ScanRequestOutcome,
  ScanPermissionWire,
  ScopeGrant,
  ScopeMode,
  ScannerFindingDetails,
  Severity,
  SeverityWire,
  SourceKind,
  SourceConnectionStatus,
  SourceCapabilityProvider,
  TransportProtocol,
  VerificationSummary,
  SeverityBasisCode,
  UnattributedResults,
  UnevaluatedTarget,
  UnevaluatedTargetCause,
  UnevaluatedTargetCauseWire,
} from "../types";
import { getActiveLocale } from "../i18n/core";
import { explicitTargetRequiresSensitiveNetworkAllowance } from "../caseForm";
import { declaredHostScanProfileByWire } from "../internalHostProfile";
import {
  isExactBuiltInLocalhostQuickScanEngine,
  isExactBuiltInLocalhostQuickScanRun,
} from "../localhostQuickScan";
import { scanRunOverallProgress } from "../scanRunProgress";
import { isSettledSkippedCheck } from "../settledSkippedChecks";
import { useCaseById } from "../useCases";
import type { UseCaseId } from "../useCases";

const adapterText = (en: string, zhTW: string): string =>
  getActiveLocale() === "en" ? en : zhTW;

const localizedList = (values: string[]): string =>
  values.join(getActiveLocale() === "en" ? ", " : "、");

/** Snake-case DTOs emitted by src-tauri/src/domain.rs. */
export interface NativeCaseSummary {
  id: string;
  title: string;
  assessment_intent?: string | null;
  ai_generated_artifact?: string | null;
  organization_name: string;
  employee_range: string;
  data_classes: string[];
  requested_activities: string[];
  source_kinds: string[];
  /** Absent snapshots retain the legacy source list. */
  applicable_source_kinds?: string[];
  notes: string | null;
  status: string;
  created_at: string;
  updated_at: string;
  is_demo: boolean;
  asset_count: number;
  finding_count: number;
  latest_run_id: string | null;
  product_identity?: CaseProductIdentity | null;
}

interface NativeDataSource {
  id: string;
  kind: string;
  label: string;
  status: string;
  connected_at: string | null;
  last_discovered_at: string | null;
  read_only: boolean;
  metadata?: Record<string, unknown>;
}

interface NativeAsset {
  id: string;
  kind: string;
  name: string;
  provider: string | null;
  region: string | null;
  identifiers: Array<{ namespace: string; value: string }>;
  discovered_from: string[];
  candidate: boolean;
  owner_confirmed: boolean;
  internet_exposed?: boolean | null;
  contains_sensitive_data?: boolean | null;
  metadata?: Record<string, unknown>;
}

interface NativeExternalScope {
  id: string;
  case_id: string;
  asset_id: string;
  target: { kind: DirectNetworkTargetKind; value: string };
  ports: number[];
  protocol: TransportProtocol;
  activity: ExternalActivity;
  rate_policy: {
    requests_per_second: number;
    concurrency: number;
    timeout_seconds: number;
  };
  template_policy: {
    revision: string;
    profile_id?: string | null;
    allowed_template_ids: string[];
    allow_headless: boolean;
    allow_out_of_band: boolean;
    allow_fuzzing: boolean;
    allow_file_upload: boolean;
    allow_denial_of_service: false;
    allow_credential_attacks: false;
  };
  asserted_authority: string;
  approved_by: string;
  approved_at: string;
  expires_at: string;
  allow_sensitive_networks: boolean;
}

interface NativeScopeGrant {
  id: string;
  asset_id: string;
  permission: string;
  confirmed_by: string;
  confirmed_at: string;
  notes: string | null;
  external_scope?: NativeExternalScope | null;
}

interface NativeCoverageEntry {
  id: string;
  label: string;
  source_kind: string;
  asset_id: string | null;
  status: string;
  explanation: string;
  last_run_id?: string | null;
  observed_at: string | null;
}

interface NativeEngineRun {
  id: string;
  engine_id: string;
  task_kind?: {
    kind: string;
    port?: unknown;
    timeout_ms?: unknown;
    payload_bytes?: unknown;
  };
  localhost_tcp_observation?: {
    outcome: string;
    observed_at: string;
  } | null;
  asset_ids: string[];
  status: EngineRunStatusWire;
  progress_percent: number;
  phase: string;
  started_at: string | null;
  finished_at: string | null;
  resume_token: string | null;
  engine_version: string | null;
  /** Absent on runs planned before the field existed. */
  reported_version?: string | null;
  image_digest: string | null;
  rule_version: string | null;
  adapter_version?: string;
  manifest_schema_version?: string | null;
  source_revision?: string | null;
  repository_url?: string | null;
  distribution_mode?: string | null;
  image_repository?: string | null;
  command_sha256?: string | null;
  scope_contract_sha256?: string | null;
  knowledge_input?: {
    kind: string;
    identifier: string;
    version: string | null;
    acquisition_source: string | null;
    pin_state: string;
    knowledge_date?: string | null;
    support_until?: string | null;
  } | null;
  runtime_provider?: string | null;
  runtime_version?: string | null;
  runtime_security_options?: string | null;
  exit_code?: number | null;
  cleanup_removed?: boolean | null;
  cleanup_detail?: string | null;
  warnings?: string[];
  unevaluated_targets?: Array<{ asset_id?: string | null; cause?: string | null; result_count?: number | null }> | null;
  raw_artifact_ids?: string[];
  error_code: string | null;
  error_message: string | null;
}

interface NativeScanRun {
  id: string;
  case_id: string;
  sequence: number;
  created_at: string;
  completed_at: string | null;
  knowledge_cutoff: string;
  verification_baseline_run_id?: string | null;
  request_outcome?: {
    status: string;
    code: string;
    requested_asset_ids: string[];
    requested_engine_ids: string[];
    explanation: string;
  } | null;
  engine_admission_issues?: NativeEngineAdmissionIssue[];
  engine_runs: NativeEngineRun[];
}

interface NativeRawArtifact {
  id?: unknown;
  relative_path?: unknown;
}

interface NativeEngineAdmissionIssue {
  engine_id: string | null;
  code: string;
  detail: string;
}

type NativeBeginnerInventoryItem = {
  asset_id: string;
  sources: Array<{
    observation_id: string;
    engine_id: string;
    engine_run_id: string;
    artifact_id: string;
    artifact_sha256: string;
    pointer: string;
    observed_at: string;
  }>;
} & ({
  kind: "service";
  endpoint: string;
  port: number | null;
  transport: string | null;
  schemes: string[];
  http_statuses: number[];
  tls_observations: boolean[];
} | {
  kind: "software_component";
  name: string;
  version: string | null;
  package_type: string | null;
  purl: string | null;
} | {
  kind: "cloud_resource";
  resource_type: string;
  native_id: string | null;
  display_name: string | null;
} | {
  kind: "workflow_component";
  component_type: string;
  name: string;
  model: string | null;
  is_guardrail: boolean | null;
} | {
  kind: "workflow_relationship";
  source: string;
  target: string;
  condition: string | null;
});

interface NativeBeginnerInventory {
  total: number;
  counts: {
    services: number;
    software_components: number;
    cloud_resources: number;
    workflow_components?: number;
    workflow_relationships?: number;
  };
  asset_ids: string[];
  representative_sample: NativeBeginnerInventoryItem[];
  items: NativeBeginnerInventoryItem[];
  by_asset: Array<{
    asset_id: string;
    total: number;
    counts: NativeBeginnerInventory["counts"];
    representative_sample: NativeBeginnerInventoryItem[];
  }>;
}

type NativeBeginnerTechnicalExecution =
  | {
      kind: "catalog_engine";
      engine_id: string;
      engine_version: string | null;
      /** Absent on reports saved before the field existed. */
      reported_version?: string | null;
      image_digest: string | null;
      command_sha256: string | null;
      runtime_provider: string | null;
      runtime_version: string | null;
      runtime_security_options: string | null;
      distribution_mode: DistributionMode | null;
      image_repository: string | null;
      adapter_version: string;
      rule_version: string | null;
      /** Absent on reports saved before the field existed. */
      knowledge_date?: string | null;
    }
  | {
      kind: "built_in_localhost_tcp";
      endpoint: string;
      timeout_ms: number;
      payload_bytes: number;
      observation: {
        outcome: LocalhostTcpObservation["outcome"];
        observed_at: string;
      } | null;
      contract: string;
    }
  | {
      kind: "invalid_built_in_task";
      explanation: string;
    };

export interface NativeBeginnerMasterReport {
  schema_version: string;
  case_id: string;
  run_id: string;
  project_title: string;
  state: {
    summary: BeginnerMasterReport["state"]["summary"];
    lifecycle: BeginnerMasterReport["state"]["lifecycle"];
    last_durable_update: string;
    explanation: string;
  };
  requested: {
    targets: Array<{
      asset_id: string;
      label: string | null;
      asset_kind: AssetKind | null;
      label_availability: BeginnerMasterReport["requested"]["targets"][number]["labelAvailability"];
      asset_kind_availability: BeginnerMasterReport["requested"]["targets"][number]["assetKindAvailability"];
    }>;
    stage: {
      value: BeginnerMasterReport["requested"]["stage"]["value"] | null;
      availability: BeginnerMasterReport["requested"]["stage"]["availability"];
      explanation: string;
    };
    limits: Array<{
      name: string;
      value: string;
      source: BeginnerMasterReport["requested"]["limits"][number]["source"];
    }>;
    requested_check_ids: string[];
    request_outcome_code: BeginnerMasterReport["requested"]["requestOutcomeCode"] | null;
    automatic_reductions: Array<{
      dimension: string;
      requested: string;
      executed: string;
      reason: string;
    }>;
    reductions_availability: BeginnerMasterReport["requested"]["reductionsAvailability"];
    unavailable_dimensions: Array<{ dimension: string; explanation: string }>;
  };
  actual: {
    observed_from: string | null;
    observed_until: string | null;
    checks: Array<{
      task_id: string;
      check_id: string;
      result_kind?: string | null;
      target_asset_ids: string[];
      status: BeginnerMasterReport["actual"]["checks"][number]["status"];
      started_at: string | null;
      finished_at: string | null;
      tested_dimensions: Array<{
        dimension: string;
        value: string;
        observation: string;
        observed_at: string | null;
      }>;
    }>;
    network_scopes?: Array<{
      task_id: string;
      check_id: string;
      work_unit_id: string;
      target_asset_id: string;
      target: string;
      address_ranges: string[];
      port_ranges: string[];
      transport: string;
      stage: "quick_discovery" | "inventory" | "deep";
      outcome: "tested_complete" | "tested_partial" | "failed" | "timed_out" | "cancelled" | "not_tested";
      observed_at: string | null;
    }>;
    unavailable_dimensions: Array<{ dimension: string; explanation: string }>;
  };
  coverage_gaps: Array<{
    kind: string;
    class?: unknown;
    task_id: string | null;
    target_asset_ids: string[];
    dimension: string;
    reason: string;
    next_action_code: BeginnerMasterReport["coverageGaps"][number]["nextActionCode"];
    next_action: string;
    unattributed?: {
      provider?: unknown;
      identifier?: unknown;
      discarded_results?: unknown;
    } | null;
  }>;
  coverage_counts: {
    tested_complete: number;
    tested_partial: number;
    failed: number;
    timed_out: number;
    cancelled: number;
    not_tested: number;
    excluded: number;
    truncated: number;
    unavailable: number;
    unattributed?: number;
    manual_review?: number;
  };
  inventory?: NativeBeginnerInventory | null;
  findings: Array<{
    finding_id: string;
    fingerprint: string;
    snapshot_source: BeginnerMasterReport["findings"][number]["snapshotSource"];
    title: string;
    plain_language_risk: string;
    possible_impact: string;
    // The native wire uses "informational"; the reader-facing union uses
    // "info". Keep this DTO exact and normalize only at the adapter boundary.
    severity: SeverityWire;
    confidence: string;
    priority: number | null;
    priority_reasons: string[];
    target_asset_ids: string[];
    next_step: string;
    recommended_expert_type: string;
    family?: string | null;
    severity_basis_code?: string | null;
    confidence_basis_code?: string | null;
    observation_details?: string[] | null;
    context_factors?: string[] | null;
    rollback_considerations?: string | null;
    verification_guidance?: string | null;
    evidence_references: Array<{
      evidence_id: string;
      engine_id: string;
      details_frozen?: boolean;
      source_rule?: string | null;
      scanner_details?: NativeScannerFindingDetails | null;
      summary?: string | null;
      kind?: EvidenceKind | null;
      engine_run_id?: string | null;
      artifact_id?: string | null;
      redacted?: boolean | null;
      artifact_sha256: string;
      observed_at: string;
      location?: string | null;
      pointer?: string | null;
    }>;
    official_references?: string[] | null;
    framework_references: Array<{
      framework: string;
      framework_version: string;
      control_id: string;
      title: string;
      relationship: string;
      rationale: string;
      mapping_version: string;
      mapping_provenance?: NativeControlMappingProvenance | null;
    }>;
  }>;
  finding_groups?: Array<{
    group_id: string;
    presentation_scope: BeginnerFindingGroupPresentationScope;
    title: string;
    rationale: string;
    actor: string;
    created_at: string;
    members: Array<{
      finding_id: string;
      observed_in_selected_run: boolean;
    }>;
  }>;
  problem_groups?: Array<{
    group_id: string;
    rule_version: string;
    kind:
      | "iam_password_policy"
      | "root_account_usage"
      | "iam_policy_permissions"
      | "vulnerable_dependency"
      | "exposed_secret";
    title: string;
    target_asset_id: string;
    representative_finding_id: string;
    finding_ids: string[];
    policy_name?: string | null;
    lower_priority_members?: unknown;
    package_name?: string | null;
    installed_version?: string | null;
    advisory_ids?: string[] | null;
  }>;
  next_steps: Array<{
    priority: number;
    code: BeginnerMasterReport["nextSteps"][number]["code"];
    action: string;
    reason: string;
    finding_id: string | null;
    task_id: string | null;
    recommended_expert_type: string | null;
    family?: string | null;
    unattributed?: {
      provider?: unknown;
      identifier?: unknown;
      discarded_results?: unknown;
    } | null;
    also_resolves?: string[];
    shared_fix?: boolean;
  }>;
  technical_details: {
    collapsed_by_default: true;
    tasks: Array<{
      task_id: string;
      target_asset_ids: string[];
      status: EngineRunStatusWire;
      phase: string;
      progress_percent: number;
      started_at: string | null;
      finished_at: string | null;
      exit_code: number | null;
      cleanup_removed: boolean | null;
      cleanup_detail: {
        availability: BeginnerMasterReport["technicalDetails"]["tasks"][number]["cleanupDetail"]["availability"];
        value: string | null;
        explanation: string;
      };
      error_code: string | null;
      redacted_scanner_message: {
        availability: BeginnerMasterReport["technicalDetails"]["tasks"][number]["redactedScannerMessage"]["availability"];
        value: string | null;
        explanation: string;
      };
      redacted_diagnostic_log: {
        availability: BeginnerMasterReport["technicalDetails"]["tasks"][number]["redactedDiagnosticLog"]["availability"];
        value: string | null;
        explanation: string;
      };
      evidence_sha256: string[];
      execution: NativeBeginnerTechnicalExecution;
    }>;
  };
  framework_notice: {
    non_certification: string;
    aidefend_mapping_status: string;
  };
  data_quality_warnings: string[];
}

interface NativeEvidence {
  id: string;
  finding_id?: string;
  run_id?: string;
  engine_run_id?: string | null;
  kind?: EvidenceKind;
  engine_id: string;
  source_rule?: string | null;
  scanner_details?: NativeScannerFindingDetails | null;
  observed_at: string;
  summary: string;
  location?: string | null;
  artifact_sha256: string;
  artifact_id?: string;
  pointer: string | null;
  redacted?: boolean;
}

interface NativeScannerFindingDetails {
  description?: string | null;
  remediation?: string | null;
  installed_version?: string | null;
  fixed_version?: string | null;
  aws_iam_policy?: {
    policy_source?: unknown;
    policy_name?: unknown;
    finding_identity?: unknown;
    actions?: unknown;
    actions_complete?: unknown;
    attached_to?: {
      roles?: unknown;
      groups?: unknown;
      users?: unknown;
      complete?: unknown;
    } | null;
  } | null;
  benchmarks?: unknown;
}

interface NativeControlMappingProvenance {
  mapping_version: string;
  reviewed_at: string;
  review_process: string;
  catalog_sha256: string;
}

interface NativeControlReference {
  framework: string;
  framework_version: string;
  control_id: string;
  title: string;
  relationship: string;
  rationale: string;
  mapping_version: string;
  mapping_provenance?: NativeControlMappingProvenance | null;
}

interface NativeFinding {
  id: string;
  case_id?: string;
  first_seen_run_id?: string;
  last_seen_run_id?: string;
  fingerprint: string;
  title: string;
  plain_language_summary: string;
  possible_impact: string;
  severity: SeverityWire;
  confidence: string;
  priority: number;
  priority_reasons?: string[];
  asset_ids: string[];
  evidence: NativeEvidence[];
  control_references: NativeControlReference[];
  recommendation: string;
  verification_guidance?: string;
  rollback_considerations?: string | null;
  official_references: string[];
  recommended_expert_type: string;
  status: FindingStatusWire;
  tags?: string[];
  family?: string | null;
  severity_basis_code?: string | null;
  confidence_basis_code?: string | null;
  context_factors?: string[] | null;
}

interface NativeFindingWorkflowEvent {
  id: string;
  finding_id: string;
  from_status: FindingStatusWire;
  to_status: FindingStatusWire;
  decided_by: string;
  decided_at: string;
  reason: string;
  expires_at: string | null;
}

export interface NativeCaseExport {
  id: string;
  case_id: string;
  run_id: string;
  created_at: string;
  format?: string | null;
  path: string;
  sha256: string;
  coverage_manifest_path?: string | null;
  coverage_manifest_sha256?: string | null;
  signature: string | null;
  redaction_profile: string;
  raw_artifacts_included?: number | null;
  raw_artifacts_omitted?: number | null;
}

export interface NativeExportPreview {
  case_id: string;
  run_id: string;
  locale: string;
  format: string;
  redaction_profile: string;
  include_raw_evidence: boolean;
  data_source_count: number;
  coverage_entry_count: number;
  asset_count: number;
  candidate_asset_count: number;
  canonical_finding_count: number;
  selected_run_finding_count: number;
  evidence_index_count: number;
  selected_run_evidence_count: number;
  scan_run_count: number;
  selected_engine_run_count: number;
  external_scope_grant_count: number;
  incomplete_engine_run_count: number;
  not_executed_engine_run_count: number;
  unknown_source_count: number;
  connected_no_asset_count: number;
  raw_artifact_count: number;
  raw_artifacts_included: number;
  raw_artifacts_omitted: number;
  sensitive_raw_artifacts_omitted: number;
  sensitive_data_warning: string;
  coverage_manifest_included: boolean;
}

const adaptNativeReportLocale = (value: string): ReportLocale => {
  if (value === "en" || value === "zh-Hant") return value;
  throw new Error(`Unsupported report locale returned by the native service: ${value}`);
};

interface NativeDiffReason {
  code: FindingDiffReasonCode;
  engine_id?: string | null;
  asset_id?: string | null;
  detail: string;
}

interface NativeFindingDiff {
  fingerprint: string;
  baseline_finding_id: string | null;
  current_finding_id: string | null;
  status: FindingDiffStatus;
  explanation: string;
  baseline_severity?: SeverityWire | null;
  current_severity?: SeverityWire | null;
  evidence_changed?: boolean;
  reasons?: NativeDiffReason[];
}

interface NativeFindingGroup {
  id: string;
  case_id: string;
  title: string;
  finding_ids: string[];
  rationale: string;
  grouped_by: string;
  created_at: string;
}

interface NativeFindingGroupEvent {
  id: string;
  case_id: string;
  group_id: string;
  action: FindingGroupAction;
  title: string;
  finding_ids: string[];
  rationale: string;
  actor: string;
  occurred_at: string;
}

interface NativeComparison {
  id: string;
  baseline_run_id: string;
  current_run_id: string;
  created_at: string;
  diffs: NativeFindingDiff[];
  complete?: boolean;
  completeness_issues?: NativeDiffReason[];
  local_input_changes?: Array<{
    asset_id: string;
    baseline_sha256: string;
    current_sha256: string;
    changed: boolean;
  }>;
}

export interface NativeAssessmentCase {
  id: string;
  title: string;
  assessment_intent?: string | null;
  ai_generated_artifact?: string | null;
  profile: {
    organization_name: string;
    employee_range: string;
    data_classes: string[];
    notes: string | null;
  };
  status: string;
  created_at: string;
  updated_at: string;
  is_demo: boolean;
  requested_activities?: string[];
  data_sources: NativeDataSource[];
  assets: NativeAsset[];
  scope_grants: NativeScopeGrant[];
  coverage: NativeCoverageEntry[];
  scan_runs: NativeScanRun[];
  raw_artifacts?: NativeRawArtifact[] | null;
  findings: NativeFinding[];
  finding_groups?: NativeFindingGroup[];
  finding_group_events?: NativeFindingGroupEvent[];
  finding_workflow_events?: NativeFindingWorkflowEvent[];
  exports: NativeCaseExport[];
  comparisons: NativeComparison[];
}

export interface NativeEngineManifest {
  id: string;
  display_name: string;
  category: string;
  distribution_mode: string;
  image: { digest: string | null } | null;
  engine_version: string | null;
  rule_version: string | null;
  license_spdx: string;
  supported_providers: string[];
  supported_asset_kinds: string[];
  provider_execution_contracts?: Array<{
    provider: string;
    asset_kind: string;
    profile: string;
  }>;
  status: string;
  compatibility?: {
    knowledge_date?: string;
    support_until?: string;
    runnable?: boolean;
    blocked_by?: unknown[];
  };
}

export interface NativeAppSnapshot {
  product_name: string;
  product_version: string;
  storage_path: string;
  cases: NativeCaseSummary[];
  selected_case: NativeAssessmentCase | null;
  runtime: {
    provider: string;
    available: boolean;
    phase: string;
    version: string | null;
    prerequisite: string | null;
    detail: string;
  };
  artifact_cleanup_obligations: Array<{
    case_id: string;
    exact_path: string;
    exists: boolean;
    requires_explicit_confirmation: boolean;
  }>;
  engine_count: number;
  /** Technical-only packaged scanner diagnostics; absent in older snapshots. */
  engine_admission_issues?: NativeEngineAdmissionIssue[];
  /** Added in v0.1.8. Older development snapshots may omit this projection. */
  beginner_reports?: NativeBeginnerMasterReport[];
  /** Added in v0.1.8. Unreadable project bytes are preserved instead of aborting startup. */
  case_recovery_diagnostics?: Array<{
    case_id: string;
    title: string;
    updated_at: string;
    revision: number;
    document_bytes: number;
    code: string;
    message: string;
    preserved: boolean;
  }>;
}

export interface NativeManagedRuntimeSetupStatus {
  phase: ManagedRuntimeSetupPhase;
  active: boolean;
  prerequisite_repair_active: boolean;
  operation_id?: string | null;
  started_at?: string | null;
  last_heartbeat_at?: string | null;
  stale?: boolean;
  cancel_requested: boolean;
  received_bytes: number;
  total_bytes: number | null;
  progress_percent: number | null;
  resumed_from_bytes: number;
  can_cancel: boolean;
  can_retry: boolean;
  failure_reason: ManagedRuntimeSetupFailureReason | null;
  next_action: ManagedRuntimeSetupNextAction | null;
  detail: string;
}

const managedRuntimeRecoveryActions: Partial<
  Record<ManagedRuntimeSetupFailureReason, ManagedRuntimeSetupNextAction>
> = {
  windows_wsl_not_installed: "install_wsl",
  windows_wsl_optional_feature_disabled: "enable_wsl_optional_features",
  windows_wsl_update_required: "update_wsl",
  windows_restart_required: "restart_windows",
  windows_wsl_command_failed: "retry_wsl_check",
};

const managedRuntimeNonRetryableFailures = new Set<ManagedRuntimeSetupFailureReason>([
  "packaged_runtime_missing",
  "packaged_runtime_verification_failed",
  "developer_build_without_packaged_runtime",
  "developer_build_packaged_runtime_verification_failed",
]);

const managedRuntimeSetupPhases = new Set<ManagedRuntimeSetupPhase>([
  "idle",
  "install",
  "prerequisite",
  "download",
  "recovery",
  "init",
  "start",
  "verify",
  "completed",
  "failed",
  "cancelled",
]);

const managedRuntimeSetupFailureReasons = new Set<ManagedRuntimeSetupFailureReason>([
  "windows_wsl_not_installed",
  "windows_wsl_optional_feature_disabled",
  "windows_wsl_update_required",
  "windows_restart_required",
  "windows_wsl_command_failed",
  "packaged_runtime_missing",
  "packaged_runtime_verification_failed",
  "developer_build_without_packaged_runtime",
  "developer_build_packaged_runtime_verification_failed",
]);

const managedRuntimeSetupNextActions = new Set<ManagedRuntimeSetupNextAction>([
  "install_wsl",
  "enable_wsl_optional_features",
  "update_wsl",
  "restart_windows",
  "retry_wsl_check",
]);

const boundedRuntimeOperationField = (
  value: string | null | undefined,
  maximumLength: number,
): string | undefined => typeof value === "string"
  && value.length > 0
  && value.length <= maximumLength
  && !/[\0\u2028\u2029]/u.test(value)
  ? value
  : undefined;

const boundedRuntimeTimestamp = (value: string | null | undefined): string | undefined => {
  const bounded = boundedRuntimeOperationField(value, 64);
  return bounded && Number.isFinite(Date.parse(bounded)) ? bounded : undefined;
};

/**
 * Adapts the snake-case Tauri DTO and enforces its terminal-failure contract.
 * Unknown, missing, or mismatched recovery values are hidden rather than
 * presenting the user with an instruction the product cannot stand behind.
 */
export const adaptManagedRuntimeSetupStatus = (
  status: NativeManagedRuntimeSetupStatus,
): ManagedRuntimeSetupStatus => {
  const phase = managedRuntimeSetupPhases.has(status.phase) ? status.phase : "failed";
  const active = exactBoolean(status.active) === true;
  const canCancel = exactBoolean(status.can_cancel) === true;
  const canRetry = exactBoolean(status.can_retry) === true;
  const failureReason = typeof status.failure_reason === "string"
    && managedRuntimeSetupFailureReasons.has(status.failure_reason)
    ? status.failure_reason
    : null;
  const nextAction = typeof status.next_action === "string"
    && managedRuntimeSetupNextActions.has(status.next_action)
    ? status.next_action
    : null;
  const hasValidRecovery = phase === "failed"
    && failureReason !== null
    && nextAction !== null
    && managedRuntimeRecoveryActions[failureReason] === nextAction;
  const hasValidNonRetryableFailure = phase === "failed"
    && exactBoolean(status.can_retry) === false
    && failureReason !== null
    && managedRuntimeNonRetryableFailures.has(failureReason)
    && status.next_action === null;
  const operationId = boundedRuntimeOperationField(status.operation_id, 128);
  const startedAt = boundedRuntimeTimestamp(status.started_at);
  const lastHeartbeatAt = boundedRuntimeTimestamp(status.last_heartbeat_at);
  return {
    phase,
    active,
    prerequisiteRepairActive: status.prerequisite_repair_active,
    ...(operationId ? { operationId } : {}),
    ...(startedAt ? { startedAt } : {}),
    ...(lastHeartbeatAt ? { lastHeartbeatAt } : {}),
    ...(status.stale !== undefined ? { stale: status.stale === true } : {}),
    cancelRequested: status.cancel_requested,
    receivedBytes: status.received_bytes,
    totalBytes: status.total_bytes ?? undefined,
    progressPercent: status.progress_percent ?? undefined,
    resumedFromBytes: status.resumed_from_bytes,
    canCancel,
    canRetry,
    failureReason: hasValidRecovery || hasValidNonRetryableFailure
      ? failureReason ?? undefined
      : undefined,
    nextAction: hasValidRecovery ? nextAction ?? undefined : undefined,
    detail: status.detail,
  };
};

const unavailableLocalNetworkInventory = (): LocalNetworkCandidateInventory => ({
  status: "unavailable",
  candidates: [],
});

const localNetworkCandidateStatuses = new Set<LocalNetworkCandidateStatus>([
  "ready",
  "none",
  "ambiguous",
  "unavailable",
  "unsupported",
]);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Untrusted IPC may send a truthy stand-in; only an exact boolean may stand as a claim. */
const exactBoolean = (value: unknown): boolean | undefined =>
  typeof value === "boolean" ? value : undefined;

/** Untrusted IPC may send a truthy stand-in; only an exact non-empty string may stand as a retained identifier. */
const exactNonEmptyString = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;

/** A missing, null, or whitespace-only reported scanner version stays absent. */
const reportedScannerVersion = (value: string | null | undefined): string | undefined => {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
};

const canonicalPrivateIpv4Cidr = (value: unknown): { target: string; addressCount: number } | undefined => {
  if (typeof value !== "string" || value.length > 18) return undefined;
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/u.exec(value);
  if (!match) return undefined;
  const octets = match.slice(1, 5).map(Number);
  const prefix = Number(match[5]);
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return undefined;
  if (!Number.isInteger(prefix) || prefix < 20 || prefix > 30) return undefined;
  const first = octets[0] ?? -1;
  const second = octets[1] ?? -1;
  const isPrivate = first === 10
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168);
  if (!isPrivate) return undefined;

  const address = octets.reduce((result, octet) => ((result * 256) + octet) >>> 0, 0);
  const hostBits = 32 - prefix;
  const mask = (0xffff_ffff << hostBits) >>> 0;
  if ((address & mask) >>> 0 !== address) return undefined;
  return { target: value, addressCount: 2 ** hostBits };
};

const adaptLocalPrivateSubnetCandidate = (value: unknown): LocalPrivateSubnetCandidate | undefined => {
  if (!isRecord(value)) return undefined;
  const cidr = canonicalPrivateIpv4Cidr(value.target);
  if (
    !cidr
    || typeof value.id !== "string"
    || !/^local-ipv4-[a-f0-9]{64}$/u.test(value.id)
    || value.kind !== "local_ipv4_subnet"
    || value.useCase !== "internal_it_environment"
    || value.internetExposure !== "internal"
    || value.addressCount !== cidr.addressCount
    || value.requiresConfirmation !== true
  ) return undefined;
  return {
    id: value.id,
    target: cidr.target,
    kind: "local_ipv4_subnet",
    useCase: "internal_it_environment",
    internetExposure: "internal",
    addressCount: cidr.addressCount,
    requiresConfirmation: true,
  };
};

/**
 * Fail closed if the native detector ever returns a widened, public, malformed,
 * or ambiguous target. Only one canonical RFC1918 /20-/30 can reach the UI.
 */
export const adaptLocalNetworkCandidateInventory = (
  value: unknown,
): LocalNetworkCandidateInventory => {
  if (!isRecord(value) || !localNetworkCandidateStatuses.has(value.status as LocalNetworkCandidateStatus)) {
    return unavailableLocalNetworkInventory();
  }
  const status = value.status as LocalNetworkCandidateStatus;
  if (!Array.isArray(value.candidates)) return unavailableLocalNetworkInventory();
  if (status !== "ready") {
    return value.candidates.length === 0
      ? { status, candidates: [] }
      : unavailableLocalNetworkInventory();
  }
  if (value.candidates.length !== 1) return unavailableLocalNetworkInventory();
  const candidate = adaptLocalPrivateSubnetCandidate(value.candidates[0]);
  return candidate
    ? { status: "ready", candidates: [candidate] }
    : unavailableLocalNetworkInventory();
};

const unique = <T,>(values: T[]): T[] => [...new Set(values)];

const uniquePlatforms = (values: Array<CloudPlatform | undefined>): CloudPlatform[] =>
  unique(values.filter((value): value is CloudPlatform => value !== undefined));

const assessmentIntents: readonly UseCaseId[] = [
  "deployed_website",
  "external_ip_or_domain",
  "internal_it_environment",
  "ai_application",
  "source_code",
  "infrastructure_as_code",
  "cloud_account",
  "container_image",
  "kubernetes",
];

const mapAssessmentIntent = (value: string | null | undefined): UseCaseId | undefined =>
  assessmentIntents.includes(value as UseCaseId) ? value as UseCaseId : undefined;

const mapAiGeneratedArtifact = (
  value: string | null | undefined,
): AiGeneratedArtifactAnswer =>
  value === "yes" || value === "no" ? value : "unknown";

const suggestedPlatformsForIntent = (intent: UseCaseId | undefined): CloudPlatform[] =>
  intent ? [...useCaseById(intent).suggestedPlatforms] : [];

const withDraftIntentFallback = (
  platforms: CloudPlatform[],
  intent: UseCaseId | undefined,
  status: string,
  assetCount: number,
): CloudPlatform[] =>
  platforms.length === 0 && status === "draft" && assetCount === 0
    ? suggestedPlatformsForIntent(intent)
    : platforms;

const phaseMap: Record<CaseStatusWire, CasePhase> = {
  draft: "draft",
  discovering: "discovering",
  scope_review: "scope_review",
  ready: "ready",
  scanning: "scanning",
  needs_attention: "needs_attention",
  ready_for_handoff: "ready_for_handoff",
  verifying: "verifying",
  archived: "archived",
};

const mapPhase = (status: string): CasePhase =>
  Object.prototype.hasOwnProperty.call(phaseMap, status)
    ? phaseMap[status as CaseStatusWire]
    : "needs_attention";

const mapCompanySize = (value: string): CompanySize => {
  if (!value.trim() || /not provided|unknown|unspecified|not sure/i.test(value)) return "unknown";
  if (/250|500|1000|large/i.test(value)) return "large";
  if (/50|100|249|medium/i.test(value)) return "medium";
  if (/^1$|solo/i.test(value)) return "solo";
  return "small";
};

const dataClassByWire: Record<DataClassWire, DataClass> = {
  general: "none",
  personally_identifiable_information: "pii",
  protected_health_information: "phi",
  payment_card_information: "payment",
  financial: "payment",
  credentials_and_secrets: "credentials",
  other: "none",
};

export const mapDataClasses = (values: string[]): DataClass[] => {
  const mapped = values.map((value): DataClass =>
    Object.prototype.hasOwnProperty.call(dataClassByWire, value)
      ? dataClassByWire[value as DataClassWire]
      : "none",
  );
  const concrete = unique(mapped.filter((value) => value !== "none"));
  return concrete.length > 0 ? concrete : ["none"];
};

const SOURCE_KIND_PLATFORMS: Record<SourceKind, CloudPlatform> = {
  aws_organization: "aws",
  azure_tenant: "azure",
  gcp_organization: "gcp",
  microsoft365_tenant: "m365",
  dns: "external",
  certificate_transparency: "external",
  billing: "external",
  git_repository: "code",
  terraform_state: "code",
  kubernetes_cluster: "kubernetes",
  container_registry: "container",
  file_system: "code",
  user_declared: "external",
};

const ASSET_KIND_PLATFORMS: Record<AssetKind, CloudPlatform> = {
  cloud_organization: "external",
  cloud_account: "external",
  subscription: "azure",
  project: "gcp",
  tenant: "m365",
  domain: "external",
  ip_address: "external",
  host: "external",
  web_service: "external",
  cloud_resource: "external",
  identity: "external",
  repository: "code",
  file_system: "code",
  iac_project: "code",
  container_image: "container",
  container_registry: "container",
  kubernetes_cluster: "kubernetes",
  ai_model_endpoint: "external",
  other: "external",
};

// Known kinds may group as external. An unrecognized kind cannot establish a scan platform.
const platformFromSource = (kind: string): CloudPlatform | undefined =>
  Object.prototype.hasOwnProperty.call(SOURCE_KIND_PLATFORMS, kind)
    ? SOURCE_KIND_PLATFORMS[kind as SourceKind]
    : undefined;

const platformFromAsset = (asset: NativeAsset): CloudPlatform | undefined => {
  const provider = asset.provider?.toLowerCase() ?? "";
  if (provider.includes("aws") || provider.includes("amazon")) return "aws";
  if (provider.includes("azure")) return "azure";
  if (provider.includes("gcp") || provider.includes("google")) return "gcp";
  if (provider === "microsoft365" || provider.includes("m365") || provider.includes("microsoft 365")) return "m365";
  return Object.prototype.hasOwnProperty.call(ASSET_KIND_PLATFORMS, asset.kind)
    ? ASSET_KIND_PLATFORMS[asset.kind as AssetKind]
    : undefined;
};

const mapAssetType = (kind: string): AssetType => {
  const types: Record<string, AssetType> = {
    cloud_organization: "cloud_account",
    cloud_account: "cloud_account",
    subscription: "subscription",
    project: "project",
    tenant: "tenant",
    domain: "domain",
    ip_address: "ip",
    host: "service",
    web_service: "service",
    cloud_resource: "cloud_resource",
    identity: "identity",
    repository: "repository",
    file_system: "repository",
    iac_project: "repository",
    container_image: "image",
    container_registry: "image",
    kubernetes_cluster: "cluster",
  };
  return types[kind] ?? "service";
};

const localInputProfiles: LocalInputProfile[] = [
  "repository_working_tree",
  "iac_working_tree",
  "container_image_oci_layout",
  "kubernetes_manifests",
  "kubernetes_node_snapshot",
];

const localInputProfileFromAsset = (asset: NativeAsset): LocalInputProfile | undefined => {
  const profile = asset.metadata?.local_input_profile;
  if (typeof profile === "string" && localInputProfiles.includes(profile as LocalInputProfile)) {
    return profile as LocalInputProfile;
  }
  return asset.kind === "repository" && typeof asset.metadata?.workspace_snapshot_id === "string"
    ? "repository_working_tree"
    : undefined;
};

const workspaceSnapshotSha256 = /^[0-9a-f]{64}$/u;

const nonNegativeInteger = (value: unknown): value is number =>
  typeof value === "number" && Number.isInteger(value) && value >= 0;

const localCopyFromMetadata = (metadata: Record<string, unknown> | undefined): Asset["localCopy"] | undefined => {
  if (!metadata) return undefined;
  const sha256 = metadata.workspace_snapshot_sha256;
  if (typeof sha256 !== "string" || !workspaceSnapshotSha256.test(sha256)) return undefined;
  const savedAt = typeof metadata.workspace_snapshot_saved_at === "string"
    ? metadata.workspace_snapshot_saved_at
    : undefined;
  const previousSha256 = typeof metadata.workspace_snapshot_previous_sha256 === "string"
    ? metadata.workspace_snapshot_previous_sha256
    : undefined;
  const rawChange = metadata.workspace_snapshot_change;
  const changed = isRecord(rawChange) ? rawChange.changed : undefined;
  const added = isRecord(rawChange) ? rawChange.added : undefined;
  const removed = isRecord(rawChange) ? rawChange.removed : undefined;
  const unchanged = isRecord(rawChange) ? rawChange.unchanged : undefined;
  const change = nonNegativeInteger(changed)
    && nonNegativeInteger(added)
    && nonNegativeInteger(removed)
    && nonNegativeInteger(unchanged)
    ? { changed, added, removed, unchanged }
    : undefined;
  return {
    sha256,
    ...(savedAt !== undefined ? { savedAt } : {}),
    ...(previousSha256 !== undefined ? { previousSha256 } : {}),
    ...(change ? { change } : {}),
  };
};

const localInputChangesFromComparison = (
  value: unknown,
): NonNullable<VerificationSummary["localInputChanges"]> => {
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry) => {
    if (!isRecord(entry)) return [];
    const assetId = entry.asset_id;
    const baselineSha256 = entry.baseline_sha256;
    const currentSha256 = entry.current_sha256;
    const changed = entry.changed;
    if (
      typeof assetId !== "string"
      || typeof baselineSha256 !== "string"
      || typeof currentSha256 !== "string"
      || typeof changed !== "boolean"
    ) return [];
    return [{ assetId, baselineSha256, currentSha256, changed }];
  });
};

const mcpConfigurationsFromAsset = (asset: NativeAsset): NonNullable<Asset["mcpConfigurationCandidates"]> => {
  const raw = asset.metadata?.mcp_configuration_candidates;
  if (!Array.isArray(raw) || asset.metadata?.mcp_configuration_discovery_complete !== true) return [];
  return raw.flatMap((value) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return [];
    const candidate = value as Record<string, unknown>;
    return typeof candidate.relative_path === "string"
      && typeof candidate.sha256 === "string"
      && typeof candidate.byte_length === "number"
      ? [{
        relativePath: candidate.relative_path,
        sha256: candidate.sha256,
        byteLength: candidate.byte_length,
      }]
      : [];
  });
};

// A new DeclaredAssetKind must be classified here or left out (like
// external_target). Do not derive this set from the Rust enum.
export const localQuestionnaireKinds = new Set(["repository", "iac_project", "container_image", "kubernetes_cluster"]);

export const adaptDeclaredWebServiceMetadata = (
  metadata: Record<string, unknown> | undefined,
): Asset["declaredWebService"] | undefined => {
  const raw = metadata?.declared_web_service;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const candidate = raw as Record<string, unknown>;
  const protocol = candidate.protocol;
  const port = candidate.port;
  const path = candidate.path;
  const scanProfile = candidate.scan_profile;
  if (
    (protocol !== "http" && protocol !== "https")
    || !Number.isInteger(port)
    || (port as number) < 1
    || (port as number) > 65_535
    || typeof path !== "string"
    || path.length > 2_048
    || !path.startsWith("/")
    || /[?#\u0000-\u001f\u007f]/u.test(path)
    || (
      scanProfile !== undefined
      && scanProfile !== "internal_device_https"
    )
  ) return undefined;
  return {
    protocol,
    port: port as number,
    path,
    ...(scanProfile === undefined ? {} : { scanProfile }),
  };
};

export const adaptDeclaredNetworkServiceMetadata = (
  metadata: Record<string, unknown> | undefined,
): Asset["declaredNetworkService"] | undefined => {
  const raw = metadata?.declared_network_service;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const candidate = raw as Record<string, unknown>;
  const { protocol, port } = candidate;
  const scanProfile = candidate.scan_profile;
  const acceptedScanProfile = scanProfile === "internal_endpoint_ssh"
    || scanProfile === "internal_endpoint_rdp_tls"
    || scanProfile === "internal_endpoint_vnc"
    || scanProfile === "internal_endpoint_smtp"
    || scanProfile === "internal_endpoint_telnet"
    ? scanProfile
    : undefined;
  if (
    protocol !== "tcp"
    || !Number.isInteger(port)
    || (port as number) < 1
    || (port as number) > 65_535
    || acceptedScanProfile === undefined
  ) return undefined;
  return {
    protocol,
    port: port as number,
    scanProfile: acceptedScanProfile,
  };
};

export const adaptDeclaredHostScanMetadata = (
  metadata: Record<string, unknown> | undefined,
): Asset["declaredHostScan"] | undefined => {
  const raw = metadata?.declared_host_scan;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const candidate = raw as Record<string, unknown>;
  const { protocol, ports } = candidate;
  const profile = candidate.profile;
  const scanProfile = typeof profile === "string"
    && Object.prototype.hasOwnProperty.call(declaredHostScanProfileByWire, profile)
    ? declaredHostScanProfileByWire[profile as keyof typeof declaredHostScanProfileByWire]
    : undefined;
  if (
    protocol !== "tcp"
    || scanProfile === undefined
    || !Array.isArray(ports)
    || ports.length === 0
    || ports.length > 64
    || ports.some((port) => !Number.isInteger(port) || Number(port) < 1 || Number(port) > 65_535)
  ) return undefined;
  const normalizedPorts = [...new Set(ports.map(Number))].sort((left, right) => left - right);
  if (normalizedPorts.length !== ports.length) return undefined;
  return { protocol, ports: normalizedPorts, scanProfile };
};

const mapCoverageState = (status: string): CoverageState => {
  const states: Record<CoverageStatusWire, CoverageState> = {
    discovered_authorized_scanned: "discovered_authorized_scanned",
    discovered_not_authorized: "discovered_not_authorized",
    authorized_scan_incomplete: "authorized_incomplete",
    source_connected_nothing_discovered: "source_connected_none",
    source_not_connected_unknown: "source_unavailable_unknown",
    not_applicable: "not_applicable",
  };
  return Object.prototype.hasOwnProperty.call(states, status)
    ? states[status as CoverageStatusWire]
    : "source_unavailable_unknown";
};

const mapSourceKind = (kind: string): SourceKind => {
  const sourceKinds: SourceKind[] = [
    "aws_organization",
    "azure_tenant",
    "gcp_organization",
    "microsoft365_tenant",
    "dns",
    "certificate_transparency",
    "billing",
    "git_repository",
    "terraform_state",
    "kubernetes_cluster",
    "container_registry",
    "file_system",
    "user_declared",
  ];
  return sourceKinds.includes(kind as SourceKind) ? kind as SourceKind : "user_declared";
};

const mapSourceConnectionStatus = (status: string): SourceConnectionStatus => {
  const statuses: SourceConnectionStatus[] = [
    "not_connected",
    "connecting",
    "connected",
    "needs_reauthorization",
    "failed",
    "not_applicable",
  ];
  return statuses.includes(status as SourceConnectionStatus)
    ? status as SourceConnectionStatus
    : "not_connected";
};

const providerBindingContracts: Partial<Record<SourceKind, {
  profile: ProviderSourceProfile;
  resourceScope: RegExp;
}>> = {
  aws_organization: {
    profile: "aws_organization_read_only_session",
    resourceScope: /^aws-account:[0-9]{12}$/u,
  },
  azure_tenant: {
    profile: "azure_tenant_read_only_access_token",
    resourceScope: /^azure-subscription:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iu,
  },
  gcp_organization: {
    profile: "gcp_organization_read_only_access_token",
    resourceScope: /^gcp-organization:[0-9]{1,32}$/u,
  },
  microsoft365_tenant: {
    profile: "microsoft365_tenant_read_only_access_token",
    resourceScope: /^microsoft365-tenant:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iu,
  },
};

/** Project only the two non-secret, exact provider coordinates used by the UI. */
export const adaptNativeProviderBinding = (
  sourceKind: SourceKind,
  metadata: Record<string, unknown> | undefined,
): ConnectedSource["providerBinding"] => {
  const contract = providerBindingContracts[sourceKind];
  const profile = metadata?.provider_profile;
  const resourceScope = metadata?.provider_resource_scope;
  if (
    !contract
    || profile !== contract.profile
    || typeof resourceScope !== "string"
    || !contract.resourceScope.test(resourceScope)
  ) return undefined;
  return { profile: contract.profile, resourceScope };
};

const mapScopeMode = (permission: string): ScopeMode | undefined => {
  const modes: Record<ScanPermissionWire, ScopeMode> = {
    inventory_read: "inventory",
    configuration_read: "configuration",
    local_artifact_read: "local_artifact",
    passive_external_discovery: "public_data",
    low_impact_external_connection: "low_impact_external",
    active_external_testing: "active_external",
  };
  return Object.prototype.hasOwnProperty.call(modes, permission)
    ? modes[permission as ScanPermissionWire]
    : undefined;
};

const DIRECT_NETWORK_TARGET_KINDS: readonly DirectNetworkTargetKind[] = ["hostname", "address", "network"];
const TRANSPORT_PROTOCOLS: readonly TransportProtocol[] = ["tcp", "udp", "tls", "http", "https"];
const EXTERNAL_ACTIVITIES: readonly ExternalActivity[] = [
  "passive_public_discovery",
  "low_impact_external",
  "active_external",
];

const adaptExternalScope = (scope: NativeExternalScope): FrozenExternalScope | undefined => {
  // A corrupted saved approval is dropped rather than becoming a different scope or blocking the case.
  if (
    !isRecord(scope.target)
    || !DIRECT_NETWORK_TARGET_KINDS.includes(scope.target.kind as DirectNetworkTargetKind)
    || !TRANSPORT_PROTOCOLS.includes(scope.protocol as TransportProtocol)
    || !EXTERNAL_ACTIVITIES.includes(scope.activity as ExternalActivity)
    || exactBoolean(scope.template_policy?.allow_headless) === undefined
    || exactBoolean(scope.template_policy?.allow_out_of_band) === undefined
    || exactBoolean(scope.template_policy?.allow_fuzzing) === undefined
    || exactBoolean(scope.template_policy?.allow_file_upload) === undefined
    || scope.template_policy?.allow_denial_of_service !== false
    || scope.template_policy?.allow_credential_attacks !== false
    || exactBoolean(scope.allow_sensitive_networks) === undefined
  ) {
    return undefined;
  }
  return {
    id: scope.id,
    caseId: scope.case_id,
    assetId: scope.asset_id,
    target: scope.target.value,
    targetKind: scope.target.kind,
    ports: scope.ports,
    protocol: scope.protocol,
    activity: scope.activity,
    ratePolicy: {
      requestsPerSecond: scope.rate_policy.requests_per_second,
      concurrency: scope.rate_policy.concurrency,
      timeoutSeconds: scope.rate_policy.timeout_seconds,
    },
    templatePolicy: {
      revision: scope.template_policy.revision,
      ...(typeof scope.template_policy.profile_id === "string"
        ? { profileId: scope.template_policy.profile_id }
        : {}),
      allowedTemplateIds: scope.template_policy.allowed_template_ids,
      allowHeadless: scope.template_policy.allow_headless,
      allowOutOfBand: scope.template_policy.allow_out_of_band,
      allowFuzzing: scope.template_policy.allow_fuzzing,
      allowFileUpload: scope.template_policy.allow_file_upload,
      allowDenialOfService: scope.template_policy.allow_denial_of_service,
      allowCredentialAttacks: scope.template_policy.allow_credential_attacks,
    },
    assertedAuthority: scope.asserted_authority,
    approvedBy: scope.approved_by,
    approvedAt: scope.approved_at,
    expiresAt: scope.expires_at,
    allowSensitiveNetworks: scope.allow_sensitive_networks,
  };
};

const mapSeverity = (severity: string): Severity => {
  const normalized = severity.trim().toLowerCase();
  if (normalized === "informational" || normalized === "info") return "info";
  return (["critical", "high", "medium", "low", "unknown"].includes(normalized)
    ? normalized
    : "unknown") as Severity;
};

const FINDING_FAMILIES: readonly FindingFamily[] = [
  "cloud_posture",
  "cloud_identity",
  "microsoft365",
  "network_exposure",
  "source_code",
  "secret",
  "infrastructure_as_code",
  "vulnerable_component",
  "kubernetes",
];

const SEVERITY_BASIS_CODES: readonly SeverityBasisCode[] = [
  "open_port",
  "reachable_http_service",
  "secret_pattern_match",
  "unverified_credential_detector",
  "iac_policy_check",
  "cis_kubernetes_benchmark",
  "cloud_control_query",
  "cloudsplaining_iam_policy_finding",
  "unrated_vulnerability_test_alarm",
];

const CONFIDENCE_BASIS_CODES: readonly ConfidenceBasisCode[] = [
  "deterministic_policy_evaluation",
  "advisory_version_match",
  "unverified_pattern_or_detector_match",
  "observed_response",
  "template_matcher",
  "missing_detection_quality_score",
];

// A code this build does not know is dropped rather than passed through. The
// only thing downstream does with it is pick a sentence, and there is no
// sentence for a value that was added after this build; the English prose beside
// it is still correct, so falling back to that beats rendering a raw enum name.
const mapFindingFamily = (value: string | null | undefined): FindingFamily | undefined =>
  FINDING_FAMILIES.find((family) => family === value);

const mapSeverityBasisCode = (value: string | null | undefined): SeverityBasisCode | undefined =>
  SEVERITY_BASIS_CODES.find((code) => code === value);

const mapConfidenceBasisCode = (
  value: string | null | undefined,
): ConfidenceBasisCode | undefined => CONFIDENCE_BASIS_CODES.find((code) => code === value);

const mapAwsIamPolicyDetails = (
  value: NativeScannerFindingDetails["aws_iam_policy"],
): AwsIamPolicyFindingDetails | undefined => {
  if (!value) return undefined;
  const source = value.policy_source;
  if (source !== "aws_managed" && source !== "customer_managed" && source !== "inline") return undefined;
  const validText = (item: unknown): item is string => typeof item === "string"
    && item.length > 0
    && [...item].length <= 512
    && !/[\u0000-\u001f\u007f-\u009f]/u.test(item);
  if (!validText(value.policy_name) || !validText(value.finding_identity)) return undefined;
  const attached = value.attached_to;
  if (!attached || typeof attached !== "object") return undefined;
  const strings = (values: unknown): string[] | undefined => {
    if (!Array.isArray(values) || values.length > 32 || values.some((item) => !validText(item))) {
      return undefined;
    }
    return [...values] as string[];
  };
  const actions = strings(value.actions);
  const roles = strings(attached.roles);
  const groups = strings(attached.groups);
  const users = strings(attached.users);
  if (!actions || !roles || !groups || !users) return undefined;
  return {
    policySource: source,
    policyName: value.policy_name,
    findingIdentity: value.finding_identity,
    actions,
    actionsComplete: value.actions_complete === true,
    attachedTo: {
      roles,
      groups,
      users,
      complete: attached.complete === true,
    },
  };
};

/** Keep scanner-reported benchmark rows whose three fields are non-empty after trim. */
const mapBenchmarkReferences = (value: unknown): BenchmarkReference[] | undefined => {
  if (!Array.isArray(value)) return undefined;
  const benchmarks: BenchmarkReference[] = [];
  for (const entry of value) {
    if (!entry || typeof entry !== "object") continue;
    const record = entry as { name?: unknown; version?: unknown; reference?: unknown };
    const name = typeof record.name === "string" ? record.name.trim() : "";
    const version = typeof record.version === "string" ? record.version.trim() : "";
    const reference = typeof record.reference === "string" ? record.reference.trim() : "";
    if (!name || !version || !reference) continue;
    benchmarks.push({ name, version, reference });
  }
  return benchmarks.length > 0 ? benchmarks : undefined;
};

const mapScannerFindingDetails = (
  details: NativeScannerFindingDetails | null | undefined,
  engineId: string,
): ScannerFindingDetails | undefined => {
  if (!details) return undefined;
  const mapped: ScannerFindingDetails = {
    description: details.description ?? undefined,
    remediation: details.remediation ?? undefined,
    installedVersion: details.installed_version ?? undefined,
    fixedVersion: details.fixed_version ?? undefined,
  };
  const awsIamPolicy = engineId === "cloudsplaining"
    ? mapAwsIamPolicyDetails(details.aws_iam_policy)
    : undefined;
  const benchmarks = mapBenchmarkReferences(details.benchmarks);
  if (awsIamPolicy) mapped.awsIamPolicy = awsIamPolicy;
  if (benchmarks) mapped.benchmarks = benchmarks;
  return mapped;
};

const mapControlMappingProvenance = (
  provenance: NativeControlMappingProvenance | null | undefined,
): ControlMappingProvenance | undefined => provenance ? {
  mappingVersion: provenance.mapping_version,
  reviewedAt: provenance.reviewed_at,
  reviewProcess: provenance.review_process,
  catalogSha256: provenance.catalog_sha256,
} : undefined;

const CONTEXT_FACTORS: readonly ContextFactor[] = ["internet_exposed_asset", "sensitive_data_asset"];

/**
 * The identifier an engine reported on that no authorized asset claims.
 *
 * Both strings come from the scanned artifact, so they are checked rather than
 * asserted. A malformed payload yields undefined and the surface falls back to
 * the backend's English prose, which is worse to read and still true.
 */
const mapUnattributed = (
  value: { provider?: unknown; identifier?: unknown; discarded_results?: unknown } | null | undefined,
): UnattributedResults | undefined => {
  if (!value || typeof value !== "object") return undefined;
  const { provider, identifier, discarded_results: discarded } = value;
  if (typeof provider !== "string" || typeof identifier !== "string") return undefined;
  if (!provider || !identifier) return undefined;
  return {
    provider,
    identifier,
    discardedResults: typeof discarded === "number" && Number.isFinite(discarded) ? discarded : 0,
  };
};

const mapContextFactors = (values: string[] | null | undefined): ContextFactor[] =>
  (values ?? []).flatMap((value) => CONTEXT_FACTORS.filter((factor) => factor === value));

const mapConfidence = (confidence: string): Confidence => {
  return (["confirmed", "high", "medium", "low", "unknown"].includes(confidence) ? confidence : "unknown") as Confidence;
};

const mapWorkflow = (status: string): FindingWorkflowState => {
  const canonicalStates: Record<FindingStatusWire, FindingWorkflowState> = {
    unreviewed: "unreviewed",
    expert_review_requested: "expert_review_requested",
    confirmed: "confirmed",
    false_positive: "false_positive",
    remediation_reported: "remediation_reported",
    verified_resolved: "verified_resolved",
  };
  const compatibilityStates: Record<string, FindingWorkflowState> = {
    sent_for_review: "expert_review_requested",
    remediation_planned: "assigned",
    remediated_pending_verification: "remediated_pending_verification",
    closed: "verified_resolved",
  };
  return canonicalStates[status as FindingStatusWire] ?? compatibilityStates[status] ?? "unreviewed";
};

const mapEngineStatus = (status: string): EngineRunStatus => {
  const states: Record<EngineRunStatusWire, EngineRunStatus> = {
    not_executed: "not_executed",
    queued: "pending",
    preparing: "running",
    running: "running",
    paused: "paused",
    completed: "completed",
    partially_completed: "partial",
    failed: "failed",
    cancelled: "cancelled",
  };
  return states[status as EngineRunStatusWire] ?? "not_executed";
};

const DISTRIBUTION_MODES: readonly DistributionMode[] = [
  "bundled_image",
  "pull_pinned_image",
  "build_from_pinned_source",
  "external_executable",
];

const mapDistributionMode = (
  value: string | null | undefined,
): DistributionMode | undefined => DISTRIBUTION_MODES.includes(value as DistributionMode)
  ? value as DistributionMode
  : undefined;

const KNOWLEDGE_INPUT_KINDS: readonly KnowledgeInputKind[] = [
  "embedded",
  "external_pinned",
  "external_pin_required",
  "not_applicable",
  "runtime_live",
  "runtime_bound",
];

const KNOWLEDGE_PIN_STATES: readonly KnowledgePinState[] = [
  "awaiting_pin",
  "runtime_live",
  "runtime_bound",
  "pinned_or_not_applicable",
];

const mapEngineKnowledgeInput = (
  input: NativeEngineRun["knowledge_input"],
): EngineRun["knowledgeInput"] => {
  if (!input
    || !KNOWLEDGE_INPUT_KINDS.includes(input.kind as KnowledgeInputKind)
    || !KNOWLEDGE_PIN_STATES.includes(input.pin_state as KnowledgePinState)) return undefined;
  return {
    kind: input.kind as KnowledgeInputKind,
    identifier: input.identifier,
    version: input.version ?? undefined,
    acquisitionSource: input.acquisition_source ?? undefined,
    pinState: input.pin_state as KnowledgePinState,
    knowledgeDate: input.knowledge_date ?? undefined,
    supportUntil: input.support_until ?? undefined,
  };
};

const mapEngineTaskKind = (taskKind: NativeEngineRun["task_kind"]): EngineTaskKind => {
  if (!taskKind || taskKind.kind === "catalog_engine") return { kind: "catalog_engine" };
  if (
    taskKind.kind !== "built_in_localhost_tcp"
    || !Number.isInteger(taskKind.port)
    || Number(taskKind.port) < 1
    || Number(taskKind.port) > 65_535
    || taskKind.timeout_ms !== 3_000
    || taskKind.payload_bytes !== 0
  ) return { kind: "invalid_task" };
  return {
    kind: "built_in_localhost_tcp",
    port: Number(taskKind.port),
    timeoutMs: taskKind.timeout_ms,
    payloadBytes: taskKind.payload_bytes,
  };
};

const mapLocalhostTcpObservation = (
  observation: NativeEngineRun["localhost_tcp_observation"],
): LocalhostTcpObservation | undefined => {
  if (!observation || !["reachable", "closed", "timed_out"].includes(observation.outcome)) {
    return undefined;
  }
  return {
    outcome: observation.outcome as LocalhostTcpObservation["outcome"],
    observedAt: observation.observed_at,
  };
};

const mapUnevaluatedTargetCause = (cause: unknown): UnevaluatedTargetCause => {
  const causes: Record<UnevaluatedTargetCauseWire, UnevaluatedTargetCause> = {
    target_did_not_respond: "target_did_not_respond",
    scanner_error: "scanner_error",
    no_security_template_execution_evidence: "no_security_template_execution_evidence",
    no_service_identified: "no_service_identified",
  };
  return causes[cause as UnevaluatedTargetCauseWire] ?? "unknown";
};

const mapUnevaluatedTargets = (
  targets: NativeEngineRun["unevaluated_targets"],
): UnevaluatedTarget[] | undefined => {
  if (!Array.isArray(targets)) return undefined;
  const recorded = targets.flatMap((target): UnevaluatedTarget[] => {
    if (!isRecord(target) || !exactNonEmptyString(target.asset_id)) return [];
    return [{
      assetId: target.asset_id,
      cause: mapUnevaluatedTargetCause(target.cause),
    }];
  });
  return recorded.length > 0 ? recorded : undefined;
};

const exactCompletedLocalhostBinding = (
  engineRun: EngineRun,
  assetId: string,
  nativeAssets: readonly NativeAsset[],
): boolean => {
  if (!isExactBuiltInLocalhostQuickScanEngine(engineRun)
    || engineRun.taskKind.kind !== "built_in_localhost_tcp") return false;
  const endpoint = `127.0.0.1:${engineRun.taskKind.port}`;
  const asset = nativeAssets.find((candidate) => candidate.id === assetId);
  const exactLoopbackAsset = asset?.kind === "web_service"
    && !asset.candidate
    && exactBoolean(asset.owner_confirmed) === true
    && asset.internet_exposed === false
    && asset.name === endpoint
    && asset.identifiers.length === 1
    && asset.identifiers.some((identifier) =>
      identifier.namespace === "localhost_tcp_endpoint"
        && identifier.value === endpoint
    );
  return Boolean(
    exactLoopbackAsset
    && engineRun.assetIds.length === 1
    && engineRun.assetIds[0] === assetId
    && engineRun.status === "completed"
    && Number.isInteger(engineRun.taskKind.port)
    && engineRun.taskKind.port >= 1
    && engineRun.taskKind.port <= 65_535
    && engineRun.taskKind.timeoutMs === 3_000
    && engineRun.taskKind.payloadBytes === 0
    && engineRun.localhostTcpObservation
    && Number.isFinite(Date.parse(engineRun.localhostTcpObservation.observedAt))
    && ["reachable", "closed"].includes(engineRun.localhostTcpObservation?.outcome ?? "")
  );
};

/** A target the engine recorded as unevaluated was not checked, whatever the run's own status says. */
const engineEvaluatedAsset = (engineRun: EngineRun, assetId: string): boolean =>
  !engineRun.unevaluatedTargets?.some(
    (target) => target.assetId === assetId && target.cause !== "unknown",
  );

const checkpointStages = new Set([
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
]);

const runtimeStreamCaptureFileNames = ["stdout.log", "stderr.log"] as const;
const runtimeStreamCaptureRawDirectory = "raw";
const runtimeStreamCaptureAttemptPrefix = "attempt-";

/** Mirrors Rust's is_runtime_stream_capture_path complete private-run layout check. */
const isRuntimeStreamCapturePath = (relativePath: string): boolean => {
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
};

const parseCheckpoint = (token: string | null, engineRun: NativeEngineRun): EngineCheckpoint | undefined => {
  if (!token) return undefined;
  try {
    const value = JSON.parse(token) as Record<string, unknown>;
    if (
      value.engine_run_id !== engineRun.id
      || value.engine_id !== engineRun.engine_id
      || typeof value.attempt !== "number"
      || typeof value.stage !== "string"
      || !checkpointStages.has(value.stage)
    ) return undefined;
    return {
      attempt: Math.max(1, Math.trunc(value.attempt)),
      stage: value.stage as EngineCheckpoint["stage"],
      artifactCount: Array.isArray(value.artifact_ids) ? value.artifact_ids.length : 0,
      cleanupCompleted: value.cleanup_completed === true,
      scopeBound: typeof value.scope_sha256 === "string" && value.scope_sha256.length > 0,
      lastError: typeof value.last_error === "string" ? value.last_error : undefined,
    };
  } catch {
    return undefined;
  }
};

const gatewayPreparationMarkers = [
  "pinned egress gateway image pull",
  "managed gateway uplink creation",
  "egress gateway container creation",
  "egress gateway container start",
  "egress gateway container exited",
  "egress gateway container did not report",
  "egress gateway container reported",
  "egress gateway internal-network attachment",
  "egress gateway exited before becoming ready",
  "egress gateway did not become ready",
  "egress gateway could not start",
] as const;

/**
 * Convert only exact product-owned gateway markers into a safe category. The
 * backend text itself may contain target-controlled data. After classification
 * the adapter replaces both the scanner message and checkpoint error with one
 * localized product message, so neither UI layer nor a shareable diagnostic
 * can reproduce the raw text.
 */
const engineFailureKind = (
  engineRun: NativeEngineRun,
  checkpoint: EngineCheckpoint | undefined,
): EngineFailureKind | undefined => {
  if (engineRun.error_code !== "execution_failed") return undefined;
  const technicalText = `${engineRun.error_message ?? ""}\n${checkpoint?.lastError ?? ""}`.toLowerCase();
  return gatewayPreparationMarkers.some((marker) => technicalText.includes(marker))
    ? "gateway_preparation_failed"
    : undefined;
};

const engineRecoveryAction = (
  status: EngineRunStatus,
  hasResumeToken: boolean,
  checkpoint: EngineCheckpoint | undefined,
  errorCode: string | null | undefined,
): EngineRecoveryAction => {
  if ([
    "resume_release_incompatible",
    "resume_work_plan_invalid",
    "runtime_cleanup_identity_unavailable",
    "coverage_incomplete_after_bounded_retries",
    "cancelled_after_partial_results",
  ].includes(errorCode ?? "")) {
    return "none";
  }
  if (!hasResumeToken || !checkpoint || !["paused", "failed", "partial", "cancelled"].includes(status)) {
    return "none";
  }
  if (checkpoint?.stage === "captured_awaiting_adapter" || checkpoint?.stage === "adapting_artifacts") {
    return "continue_saved_results";
  }
  if (checkpoint?.stage === "cleanup_pending") return "finish_cleanup";
  return "restart_check";
};

const runStatus = (runs: EngineRun[]): RunStatus => {
  if (runs.length === 0 || runs.every((run) => run.status === "pending")) return "queued";
  if (runs.some((run) => run.status === "running")) return "running";
  if (runs.some((run) => run.status === "paused")) return "paused";
  if (runs.some((run) => run.status === "pending")) return "queued";
  if (
    runs.every((run) => run.status === "completed" || isSettledSkippedCheck(run))
    && runs.some((run) => run.status === "completed")
  ) return "completed";
  if (runs.every((run) => run.status === "cancelled")) return "cancelled";
  if (runs.every((run) => run.status === "failed" || run.status === "not_executed")) return "failed";
  return "partial";
};

const mapScanRequestOutcome = (
  outcome: NativeScanRun["request_outcome"],
  completedAt: string | null,
  engineRunCount: number,
): ScanRequestOutcome | undefined => {
  if (
    outcome?.status !== "no_checks_completed"
    || !completedAt
    || engineRunCount !== 0
    || ![
      "no_effective_scope_grants",
      "no_ownership_confirmed_targets",
      "no_applicable_checks",
    ].includes(outcome.code)
  ) return undefined;
  return {
    status: "no_checks_completed",
    code: outcome.code as ScanRequestOutcome["code"],
    requestedAssetIds: [...outcome.requested_asset_ids],
    requestedEngineIds: [...outcome.requested_engine_ids],
  };
};

const storedExportFormat = (format?: string | null): ExportFormat | undefined =>
  ["case_bundle", "json", "framework_report", "ocsf", "oscal", "html"].includes(format ?? "")
    ? format as ExportFormat
    : undefined;

// STANDARD base64 of a 64-byte Ed25519 signature; anything else cannot claim local integrity.
const LOCAL_INTEGRITY_SIGNATURE = /^[A-Za-z0-9+/]{86}==$/u;
const hasLocalIntegritySignature = (signature: unknown): boolean =>
  typeof signature === "string" && LOCAL_INTEGRITY_SIGNATURE.test(signature);

export const adaptNativeExport = (item: NativeCaseExport): CaseExport => ({
  id: item.id,
  caseId: item.case_id,
  runId: item.run_id,
  format: storedExportFormat(item.format),
  createdAt: item.created_at,
  fileName: item.path.split(/[\\/]/).at(-1) ?? item.path,
  sha256: item.sha256,
  coverageManifestPath: item.coverage_manifest_path ?? undefined,
  coverageManifestSha256: item.coverage_manifest_sha256 ?? undefined,
  signatureState: hasLocalIntegritySignature(item.signature) ? "local_integrity" : "unsigned",
  includesRawEvidence: item.raw_artifacts_included == null
    ? undefined
    : item.raw_artifacts_included > 0,
  rawArtifactsIncluded: item.raw_artifacts_included ?? undefined,
  rawArtifactsOmitted: item.raw_artifacts_omitted ?? undefined,
  path: item.path,
});

const stableExportIdentityHash = (value: string): string => {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
};

/**
 * A filename-safe, deterministic run coordinate. The canonical sequence is
 * readable, while the hash distinguishes the immutable ID without copying an
 * imported or otherwise untrusted identifier into a suggested filename.
 */
export const exportRunFileIdentity = (
  run: Pick<CaseWorkspace["runs"][number], "id" | "sequence">,
): string => {
  const shortIdentity = stableExportIdentityHash(run.id);
  return Number.isSafeInteger(run.sequence) && (run.sequence ?? 0) > 0
    ? `scan-${run.sequence}-${shortIdentity}`
    : `run-${shortIdentity}`;
};

export const adaptNativeExportPreview = (item: NativeExportPreview): ExportPreview => ({
  caseId: item.case_id,
  runId: item.run_id,
  locale: adaptNativeReportLocale(item.locale),
  format: storedExportFormat(item.format) ?? "case_bundle",
  redactionProfile: item.redaction_profile === "none" ? "none" : "standard",
  includeRawEvidence: item.include_raw_evidence,
  dataSourceCount: item.data_source_count,
  coverageEntryCount: item.coverage_entry_count,
  assetCount: item.asset_count,
  candidateAssetCount: item.candidate_asset_count,
  canonicalFindingCount: item.canonical_finding_count,
  selectedRunFindingCount: item.selected_run_finding_count,
  evidenceIndexCount: item.evidence_index_count,
  selectedRunEvidenceCount: item.selected_run_evidence_count,
  scanRunCount: item.scan_run_count,
  selectedEngineRunCount: item.selected_engine_run_count,
  externalScopeGrantCount: item.external_scope_grant_count,
  incompleteEngineRunCount: item.incomplete_engine_run_count,
  notExecutedEngineRunCount: item.not_executed_engine_run_count,
  unknownSourceCount: item.unknown_source_count,
  connectedNoAssetCount: item.connected_no_asset_count,
  rawArtifactCount: item.raw_artifact_count,
  rawArtifactsIncluded: item.raw_artifacts_included,
  rawArtifactsOmitted: item.raw_artifacts_omitted,
  sensitiveRawArtifactsOmitted: item.sensitive_raw_artifacts_omitted,
  sensitiveDataWarning: item.sensitive_data_warning,
  coverageManifestIncluded: item.coverage_manifest_included,
});

const ENGINE_CATEGORIES: readonly EngineCategory[] = [
  "cloud_inventory",
  "cloud_configuration",
  "identity_and_access",
  "microsoft365",
  "external_attack_surface",
  "code_and_secrets",
  "infrastructure_as_code",
  "container_and_sbom",
  "kubernetes",
  "host",
  "schema_and_export",
  "ai_model_endpoint",
  "ai_agent_framework",
  "ai_mcp_configuration",
];

const mapEngineCategory = (value: string): EngineCategory | undefined =>
  ENGINE_CATEGORIES.includes(value as EngineCategory) ? value as EngineCategory : undefined;

const MANIFEST_STATUSES: Record<EngineManifestStatusWire, EngineManifest["status"]> = {
  integrated: "ready",
  experimental: "not_downloaded",
  research_only: "unsupported",
  deprecated: "outdated",
  license_review: "unsupported",
};

export const adaptNativeManifest = (manifest: NativeEngineManifest): EngineManifest => {
  const supportedProviders = manifest.supported_providers
    .map((provider): CloudPlatform | undefined => provider === "microsoft365" ? "m365" : ["aws", "azure", "gcp"].includes(provider) ? provider as CloudPlatform : undefined)
    .filter((provider): provider is CloudPlatform => Boolean(provider));
  const platforms = supportedProviders.length > 0 ? supportedProviders : uniquePlatforms(manifest.supported_asset_kinds.map((kind) =>
    platformFromAsset({ id: "", kind, name: "", provider: null, region: null, identifiers: [], discovered_from: [], candidate: false, owner_confirmed: false }),
  ));
  const distributionMode = mapDistributionMode(manifest.distribution_mode);
  const distributionByMode: Record<DistributionMode, EngineManifest["redistribution"]> = {
    bundled_image: "bundled",
    pull_pinned_image: "on_demand",
    build_from_pinned_source: "on_demand",
    external_executable: "external",
  };
  const distribution = distributionMode ? distributionByMode[distributionMode] : "unknown";
  const catalogStatus = MANIFEST_STATUSES[manifest.status as EngineManifestStatusWire] ?? "unsupported";
  const rawRunnable = manifest.compatibility?.runnable;
  const rawBlockedBy = manifest.compatibility?.blocked_by;
  const runnableShapeValid = rawRunnable === undefined || typeof rawRunnable === "boolean";
  const blockedByShapeValid = rawBlockedBy === undefined || (
    Array.isArray(rawBlockedBy)
    && rawBlockedBy.every((item) =>
      typeof item === "string"
      && item.length > 0
      && item.length <= 512
      && !/[\u0000-\u001f\u007f]/u.test(item),
    )
  );
  const blockedBy = blockedByShapeValid && Array.isArray(rawBlockedBy)
    ? rawBlockedBy as string[]
    : [];
  const compatibilityValid = runnableShapeValid
    && blockedByShapeValid
    && !(rawRunnable === true && blockedBy.length > 0);
  const runnable = compatibilityValid && typeof rawRunnable === "boolean"
    ? rawRunnable
    : undefined;
  const status: EngineManifest["status"] = catalogStatus === "ready"
    && (runnable === false || blockedBy.length > 0)
    ? "not_downloaded"
    : catalogStatus;
  const contractAssetKinds: Partial<Record<SourceCapabilityProvider, string>> = {
    aws: "cloud_account",
    azure: "subscription",
    gcp: "project",
    microsoft365: "tenant",
  };
  const providerExecutionProfiles = (Array.isArray(manifest.provider_execution_contracts)
    ? manifest.provider_execution_contracts
    : [])
    .flatMap((contract) => {
      if (!contract || typeof contract !== "object") return [];
      const provider = contract.provider;
      if (!(["aws", "azure", "gcp", "microsoft365"] as const).includes(provider as SourceCapabilityProvider)) return [];
      const safeProvider = provider as SourceCapabilityProvider;
      if (
        contract.asset_kind !== contractAssetKinds[safeProvider]
        || typeof contract.profile !== "string"
        || !/^[a-z0-9][a-z0-9_-]{2,95}$/u.test(contract.profile)
      ) return [];
      return [{ provider: safeProvider, assetKind: contract.asset_kind, profile: contract.profile }];
    })
    .filter((contract, index, values) =>
      values.findIndex((candidate) =>
        candidate.provider === contract.provider
        && candidate.assetKind === contract.assetKind
        && candidate.profile === contract.profile,
      ) === index,
    );
  const knowledgeDate = manifest.compatibility?.knowledge_date;
  return {
    id: manifest.id,
    name: manifest.display_name,
    category: mapEngineCategory(manifest.category) ?? "unknown",
    version: manifest.engine_version ?? manifest.rule_version ?? adapterText("Not reported", "未回報"),
    imageDigest: manifest.image?.digest ?? adapterText("No image digest", "未提供映像摘要"),
    license: manifest.license_spdx,
    redistribution: distribution,
    platforms,
    supportedProviders,
    status,
    runnable,
    blockedBy,
    compatibilityValid,
    providerExecutionProfiles,
    knowledgeDate,
  };
};

const adaptCaseProductIdentity = (
  identity: CaseProductIdentity | null | undefined,
): AssessmentCase["productIdentity"] => {
  if (
    identity?.kind !== "localhost_quick_scan" ||
    !Number.isInteger(identity.port) ||
    identity.port < 1 ||
    identity.port > 65_535
  ) {
    return undefined;
  }

  return { kind: identity.kind, port: identity.port };
};

const adaptSummary = (summary: NativeCaseSummary): AssessmentCase => {
  const assessmentIntent = mapAssessmentIntent(summary.assessment_intent);
  const sourceKinds = summary.applicable_source_kinds ?? summary.source_kinds;
  const platforms = withDraftIntentFallback(
    uniquePlatforms(sourceKinds.map(platformFromSource)),
    assessmentIntent,
    summary.status,
    summary.asset_count,
  );
  return {
    id: summary.id,
    name: summary.title,
    assessmentIntent,
    aiGeneratedArtifact: mapAiGeneratedArtifact(summary.ai_generated_artifact),
    organizationName: summary.organization_name,
    companySize: mapCompanySize(summary.employee_range),
    dataClasses: mapDataClasses(summary.data_classes),
    requestedActivities: summary.requested_activities.filter(
      (activity): activity is AssessmentActivity => [
        "configuration_assessment",
        "local_artifact_analysis",
        "low_impact_external_checks",
        "active_external_vulnerability_tests",
      ].includes(activity),
    ),
    platforms,
    createdAt: summary.created_at,
    updatedAt: summary.updated_at,
    phase: mapPhase(summary.status),
    isDemo: summary.is_demo,
    description: summary.notes ?? undefined,
    latestRunId: summary.latest_run_id ?? undefined,
    assetCount: summary.asset_count,
    findingCount: summary.finding_count,
    productIdentity: adaptCaseProductIdentity(summary.product_identity),
  };
};

export const adaptNativeCase = (
  nativeCase: NativeAssessmentCase,
  manifests: EngineManifest[] = [],
): CaseWorkspace => {
  const sources: ConnectedSource[] = nativeCase.data_sources.map((source) => {
    const kind = mapSourceKind(source.kind);
    return {
      id: source.id,
      kind,
      label: source.label,
      status: mapSourceConnectionStatus(source.status),
      readOnly: exactBoolean(source.read_only) ?? false,
      connectedAt: source.connected_at ?? undefined,
      lastDiscoveredAt: source.last_discovered_at ?? undefined,
      providerBinding: adaptNativeProviderBinding(kind, source.metadata),
    };
  });
  const scanAttemptedAssetIds = new Set(
    nativeCase.scan_runs.flatMap((run) => run.engine_runs.flatMap((engineRun) => {
      const status = mapEngineStatus(engineRun.status);
      const startedAt = typeof engineRun.started_at === "string" && Number.isFinite(Date.parse(engineRun.started_at));
      // A planned target is not attempted until a valid task has entered execution.
      return mapEngineTaskKind(engineRun.task_kind).kind !== "invalid_task"
        && !["pending", "not_executed"].includes(status)
        && startedAt
        ? engineRun.asset_ids
        : [];
    })),
  );
  const coverage: CoverageRecord[] = nativeCase.coverage.flatMap((entry) => {
    const platform = platformFromSource(entry.source_kind);
    if (platform === undefined) return [];
    return [{
      id: entry.id,
      label: entry.label,
      platform,
      sourceKind: mapSourceKind(entry.source_kind),
      state: mapCoverageState(entry.status),
      assetId: entry.asset_id ?? undefined,
      assetCount: entry.asset_id ? 1 : 0,
      detail: entry.explanation,
      lastCheckedAt: entry.observed_at ?? undefined,
      scanAttempted: entry.asset_id
        ? exactNonEmptyString(entry.last_run_id) || scanAttemptedAssetIds.has(entry.asset_id)
        : undefined,
    }];
  });
  const coverageByAsset = new Map(nativeCase.coverage.filter((entry) => entry.asset_id).map((entry) => [entry.asset_id, entry]));
  const grantsByAsset = new Map<string, NativeScopeGrant[]>();
  for (const grant of nativeCase.scope_grants) {
    grantsByAsset.set(grant.asset_id, [...(grantsByAsset.get(grant.asset_id) ?? []), grant]);
  }
  const findingCount = new Map<string, number>();
  for (const finding of nativeCase.findings) {
    for (const assetId of finding.asset_ids) findingCount.set(assetId, (findingCount.get(assetId) ?? 0) + 1);
  }
  const assets: Asset[] = nativeCase.assets.flatMap((asset) => {
    const platform = platformFromAsset(asset);
    if (platform === undefined) return [];
    const entry = coverageByAsset.get(asset.id);
    const grants = grantsByAsset.get(asset.id) ?? [];
    const allowedModes = unique(grants.flatMap((grant) => {
      const mode = mapScopeMode(grant.permission);
      return mode ? [mode] : [];
    }));
    const coverageState = entry
      ? mapCoverageState(entry.status)
      : asset.candidate ? "discovered_not_authorized" : exactBoolean(asset.owner_confirmed) === true ? "authorized_incomplete" : "source_unavailable_unknown";
    const localInputProfile = localInputProfileFromAsset(asset);
    const localCopy = localCopyFromMetadata(asset.metadata);
    const internetExposed = explicitTargetRequiresSensitiveNetworkAllowance(asset.name)
      ? false
      : asset.internet_exposed ?? undefined;
    return [{
      id: asset.id,
      name: asset.name,
      type: mapAssetType(asset.kind),
      platform,
      locator: asset.identifiers[0]?.value ?? asset.name,
      identifiers: asset.identifiers,
      discoveredFromSourceIds: [...asset.discovered_from],
      region: asset.region ?? undefined,
      internetExposed,
      containsSensitiveData: asset.contains_sensitive_data ?? undefined,
      coverageState,
      authorizationState: allowedModes.length > 0 ? "authorized" : asset.candidate ? "pending" : "unknown",
      allowedModes,
      findingCount: findingCount.get(asset.id) ?? 0,
      lastObservedAt: entry?.observed_at ?? undefined,
      scanAttempted: exactNonEmptyString(entry?.last_run_id) || scanAttemptedAssetIds.has(asset.id),
      questionnairePlaceholder: localQuestionnaireKinds.has(String(asset.metadata?.questionnaire_kind)) && !localInputProfile,
      localInputProfile,
      ...(localCopy ? { localCopy } : {}),
      mcpConfigurationCandidates: mcpConfigurationsFromAsset(asset),
      selectedMcpConfiguration: typeof asset.metadata?.mcp_configuration_selected === "string"
        ? asset.metadata.mcp_configuration_selected
        : undefined,
      agenticRadarFramework: agenticRadarFramework(asset.metadata?.agentic_radar_framework),
      modelEndpoint: asset.kind === "ai_model_endpoint"
        && typeof (asset.metadata?.model_endpoint as { endpoint?: unknown } | undefined)?.endpoint === "string"
        && typeof (asset.metadata?.model_endpoint as { model?: unknown } | undefined)?.model === "string"
        ? validatedModelEndpoint((asset.metadata!.model_endpoint as { endpoint: string }).endpoint,
            (asset.metadata!.model_endpoint as { model: string }).model)
        : undefined,
      declaredWebService: adaptDeclaredWebServiceMetadata(asset.metadata),
      declaredNetworkService: adaptDeclaredNetworkServiceMetadata(asset.metadata),
      declaredHostScan: adaptDeclaredHostScanMetadata(asset.metadata),
    }];
  });
  const assetById = new Map(assets.map((asset) => [asset.id, asset]));
  const manifestById = new Map(manifests.map((manifest) => [manifest.id, manifest]));
  const findings: Finding[] = nativeCase.findings.map((finding) => {
    const observations = finding.evidence.map((evidence) => evidence.observed_at).sort();
    const assetNames = finding.asset_ids.map((id) => assetById.get(id)?.name).filter((name): name is string => Boolean(name));
    const severityBasisCode = mapSeverityBasisCode(finding.severity_basis_code);
    return {
      id: finding.id,
      caseId: finding.case_id,
      fingerprint: finding.fingerprint,
      assetId: finding.asset_ids[0] ?? "unknown-asset",
      assetIds: finding.asset_ids,
      assetName: localizedList(assetNames) || adapterText("Unknown asset", "未知資產"),
      title: finding.title,
      summary: finding.plain_language_summary,
      impact: finding.possible_impact,
      recommendation: finding.recommendation,
      family: mapFindingFamily(finding.family),
      severityBasisCode,
      confidenceBasisCode: mapConfidenceBasisCode(finding.confidence_basis_code),
      observationDetails: severityBasisCode === "open_port" || severityBasisCode === "reachable_http_service"
        ? (finding.tags ?? []).filter((tag) =>
          tag.startsWith("port:")
          || tag.startsWith("protocol:")
          || tag.startsWith("http-status:"))
        : undefined,
      contextFactors: mapContextFactors(finding.context_factors),
      awsIamPolicy: finding.evidence
        .filter((evidence) => evidence.engine_id === "cloudsplaining")
        .map((evidence) => mapAwsIamPolicyDetails(evidence.scanner_details?.aws_iam_policy))
        .find((details): details is AwsIamPolicyFindingDetails => details !== undefined),
      expertType: finding.recommended_expert_type,
      severity: mapSeverity(finding.severity),
      confidence: mapConfidence(finding.confidence),
      priority: finding.priority,
      priorityReasons: finding.priority_reasons ?? [],
      workflowState: mapWorkflow(finding.status),
      evidence: finding.evidence.map((evidence) => ({
        id: evidence.id,
        sourceEngine: evidence.engine_id,
        sourceRule: evidence.source_rule ?? undefined,
        scannerDetails: mapScannerFindingDetails(evidence.scanner_details, evidence.engine_id),
        observedAt: evidence.observed_at,
        summary: evidence.summary,
        location: evidence.location ?? undefined,
        rawArtifactHash: evidence.artifact_sha256,
        rawArtifactPath: evidence.pointer ?? undefined,
        kind: evidence.kind,
        runId: evidence.run_id,
        engineRunId: evidence.engine_run_id ?? undefined,
        artifactId: evidence.artifact_id,
        redacted: exactBoolean(evidence.redacted),
      })),
      controls: finding.control_references.map((control) => ({
        framework: control.framework,
        version: control.framework_version,
        controlId: control.control_id,
        relationship: "related",
        title: control.title,
        rationale: control.rationale,
        mappingVersion: control.mapping_version,
        mappingProvenance: mapControlMappingProvenance(control.mapping_provenance),
        note: [control.title, control.rationale, `mapping ${control.mapping_version}`].filter(Boolean).join("；"),
      })),
      officialReferences: finding.official_references,
      verificationGuidance: finding.verification_guidance,
      rollbackConsiderations: finding.rollback_considerations ?? undefined,
      tags: finding.tags ?? [],
      firstSeenRunId: finding.first_seen_run_id,
      lastSeenRunId: finding.last_seen_run_id,
      firstSeenAt: observations[0] ?? nativeCase.created_at,
      lastSeenAt: observations.at(-1) ?? nativeCase.updated_at,
    };
  });
  const findingGroups: FindingGroup[] = (nativeCase.finding_groups ?? []).map((group) => ({
    id: group.id,
    caseId: group.case_id,
    title: group.title,
    findingIds: group.finding_ids,
    rationale: group.rationale,
    groupedBy: group.grouped_by,
    createdAt: group.created_at,
  }));
  const findingGroupEvents: FindingGroupEvent[] = (nativeCase.finding_group_events ?? []).map((event) => ({
    id: event.id,
    caseId: event.case_id,
    groupId: event.group_id,
    action: event.action,
    title: event.title,
    findingIds: event.finding_ids,
    rationale: event.rationale,
    actor: event.actor,
    occurredAt: event.occurred_at,
  }));
  const rawArtifactPathById = new Map<string, string>();
  if (Array.isArray(nativeCase.raw_artifacts)) {
    for (const artifact of nativeCase.raw_artifacts) {
      if (typeof artifact?.id === "string" && typeof artifact.relative_path === "string") {
        rawArtifactPathById.set(artifact.id, artifact.relative_path);
      }
    }
  }
  const runs = [...nativeCase.scan_runs].sort((left, right) =>
    right.sequence - left.sequence ||
    right.created_at.localeCompare(left.created_at) ||
    right.id.localeCompare(left.id)
  ).map((run, runIndex) => {
    const requestOutcome = mapScanRequestOutcome(
      run.request_outcome,
      run.completed_at,
      run.engine_runs.length,
    );
    const engineRuns: EngineRun[] = run.engine_runs.map((engineRun) => {
      const taskKind = mapEngineTaskKind(engineRun.task_kind);
      const builtInLocalhostTask = isExactBuiltInLocalhostQuickScanEngine({
        engineId: engineRun.engine_id,
        taskKind,
      }) && taskKind.kind === "built_in_localhost_tcp" ? taskKind : undefined;
      const isBuiltInLocalhostTcp = Boolean(builtInLocalhostTask);
      const manifest = isBuiltInLocalhostTcp ? undefined : manifestById.get(engineRun.engine_id);
      const status = taskKind.kind === "invalid_task"
        ? "not_executed"
        : mapEngineStatus(engineRun.status);
      const checkpoint = parseCheckpoint(engineRun.resume_token, engineRun);
      const releaseIncompatible = engineRun.error_code === "resume_release_incompatible";
      const savedWorkPlanUnavailable = engineRun.error_code === "resume_work_plan_invalid";
      const cleanupIdentityUnavailable = engineRun.error_code === "runtime_cleanup_identity_unavailable"
        || [
          "cleanup_identity_unavailable",
          "interrupted_restart_cleanup_identity_unavailable",
        ].includes(engineRun.phase);
      const staticFailure = releaseIncompatible || savedWorkPlanUnavailable || cleanupIdentityUnavailable;
      const failureKind = cleanupIdentityUnavailable ? undefined : engineFailureKind(engineRun, checkpoint);
      const publicErrorCode = cleanupIdentityUnavailable
        ? "runtime_cleanup_identity_unavailable"
        : engineRun.error_code;
      const publicCheckpoint = (failureKind === "gateway_preparation_failed" || staticFailure) && checkpoint
        ? { ...checkpoint, lastError: undefined }
        : checkpoint;
      const recoveryAction = staticFailure
        ? "none"
        : engineRecoveryAction(
          status,
          Boolean(engineRun.resume_token),
          checkpoint,
          publicErrorCode,
        );
      const exactFindingCount = nativeCase.findings.filter((finding) =>
        finding.evidence.some((evidence) => evidence.engine_run_id === engineRun.id)
      ).length;
      const hasLegacyUnattributedEvidence = nativeCase.findings.some((finding) =>
        finding.evidence.some((evidence) =>
          evidence.run_id === run.id &&
          evidence.engine_id === engineRun.engine_id &&
          !evidence.engine_run_id
        )
      );
      const savedResultArtifactCount = (engineRun.raw_artifact_ids ?? []).filter((artifactId) => {
        const relativePath = rawArtifactPathById.get(artifactId);
        // An absent or malformed artifact record cannot prove saved results. Fail closed so
        // the retry hint understates saved work instead of repeating the false claim fixed here.
        return relativePath !== undefined && !isRuntimeStreamCapturePath(relativePath);
      }).length;
      return {
        id: engineRun.id,
        engineId: engineRun.engine_id,
        engineName: isBuiltInLocalhostTcp
          ? `127.0.0.1:${builtInLocalhostTask!.port} TCP`
          : manifest?.name ?? engineRun.engine_id,
        category: isBuiltInLocalhostTcp ? "built_in_localhost_tcp" : manifest?.category ?? "unknown",
        version: isBuiltInLocalhostTcp
          ? undefined
          : engineRun.engine_version ?? manifest?.version ?? adapterText("Not reported", "未回報"),
        reportedVersion: isBuiltInLocalhostTcp
          ? undefined
          : reportedScannerVersion(engineRun.reported_version),
        digest: isBuiltInLocalhostTcp
          ? undefined
          : engineRun.image_digest ?? manifest?.imageDigest ?? adapterText("No image digest", "未提供映像摘要"),
        taskKind,
        localhostTcpObservation: isBuiltInLocalhostTcp
          ? mapLocalhostTcpObservation(engineRun.localhost_tcp_observation)
          : undefined,
        ruleVersion: isBuiltInLocalhostTcp ? undefined : engineRun.rule_version ?? undefined,
        adapterVersion: isBuiltInLocalhostTcp ? undefined : engineRun.adapter_version,
        manifestSchemaVersion: isBuiltInLocalhostTcp ? undefined : engineRun.manifest_schema_version ?? undefined,
        sourceRevision: isBuiltInLocalhostTcp ? undefined : engineRun.source_revision ?? undefined,
        repositoryUrl: isBuiltInLocalhostTcp ? undefined : engineRun.repository_url ?? undefined,
        distributionMode: isBuiltInLocalhostTcp
          ? undefined
          : mapDistributionMode(engineRun.distribution_mode),
        imageRepository: isBuiltInLocalhostTcp ? undefined : engineRun.image_repository ?? undefined,
        commandSha256: isBuiltInLocalhostTcp ? undefined : engineRun.command_sha256 ?? undefined,
        knowledgeInput: isBuiltInLocalhostTcp
          ? undefined
          : mapEngineKnowledgeInput(engineRun.knowledge_input),
        runtimeProvider: isBuiltInLocalhostTcp ? undefined : engineRun.runtime_provider ?? undefined,
        runtimeVersion: isBuiltInLocalhostTcp ? undefined : engineRun.runtime_version ?? undefined,
        runtimeSecurityOptions: isBuiltInLocalhostTcp ? undefined : engineRun.runtime_security_options ?? undefined,
        exitCode: isBuiltInLocalhostTcp ? undefined : engineRun.exit_code ?? undefined,
        cleanupRemoved: isBuiltInLocalhostTcp ? undefined : exactBoolean(engineRun.cleanup_removed),
        cleanupDetail: isBuiltInLocalhostTcp || staticFailure ? undefined : engineRun.cleanup_detail ?? undefined,
        warnings: staticFailure ? [] : engineRun.warnings ?? [],
        unevaluatedTargets: mapUnevaluatedTargets(engineRun.unevaluated_targets),
        status,
        progress: engineRun.progress_percent,
        phase: engineRun.phase,
        startedAt: engineRun.started_at ?? undefined,
        finishedAt: engineRun.finished_at ?? undefined,
        assetIds: engineRun.asset_ids,
        rawArtifactCount: engineRun.raw_artifact_ids?.length ?? 0,
        savedResultArtifactCount,
        findingCount: exactFindingCount,
        findingCountKnown: !hasLegacyUnattributedEvidence,
        message: releaseIncompatible
          ? adapterText(
            "This saved check was created by a different app release. Start a new scan with this release.",
            "這項已保存的檢查由不同版本的應用程式建立；請使用目前版本開始新的掃描。",
          )
          : savedWorkPlanUnavailable
          ? adapterText(
            "This saved check no longer matches its original target plan. Start a new scan.",
            "這項已保存的檢查已無法對應原本的目標計畫；請開始新的掃描。",
          )
          : cleanupIdentityUnavailable
          ? adapterText(
            "Start a new scan for fresh results.",
            "請開始新的掃描取得新結果。",
          )
          : failureKind === "gateway_preparation_failed"
          ? adapterText(
            "Private scan connection unavailable.",
            "專用掃描連線無法使用。",
          )
          : engineRun.error_message ?? (engineRun.error_code
            ? adapterText(`Error code: ${engineRun.error_code}`, `錯誤代碼：${engineRun.error_code}`)
            : engineRun.phase),
        errorCode: publicErrorCode ?? undefined,
        checkpoint: publicCheckpoint,
        scopeContractBound: typeof engineRun.scope_contract_sha256 === "string"
          && engineRun.scope_contract_sha256.length > 0,
        failureKind,
        recoveryAction,
        resumable: recoveryAction !== "none",
      };
    });
    const allAssetIds = unique([
      ...run.engine_runs.flatMap((engineRun) => engineRun.asset_ids),
      ...(requestOutcome?.requestedAssetIds ?? []),
    ]);
    const coveredAssetIds = allAssetIds.filter((assetId) => {
      // Settled skips neither block nor grant coverage: they have nothing to
      // check in this project, or this app version does not include them.
      const applicableRuns = engineRuns
        .filter((engineRun) => engineRun.assetIds.includes(assetId))
        .filter((engineRun) => !isSettledSkippedCheck(engineRun));
      return applicableRuns.length > 0 && applicableRuns.every((engineRun) =>
        engineRun.taskKind.kind === "built_in_localhost_tcp"
          ? exactCompletedLocalhostBinding(engineRun, assetId, nativeCase.assets)
          : engineRun.taskKind.kind === "catalog_engine"
            && engineRun.status === "completed"
            && engineEvaluatedAsset(engineRun, assetId)
      );
    });
    const status = requestOutcome ? "no_checks_completed" : runStatus(engineRuns);
    const lastEngineActivityAt = [...run.engine_runs]
      .flatMap((engineRun) => [engineRun.started_at, engineRun.finished_at])
      .filter((value): value is string => Boolean(value))
      .sort()
      .at(-1);
    return {
      id: run.id,
      caseId: run.case_id,
      label: adapterText(`Scan ${run.sequence}`, `第 ${run.sequence} 次掃描`),
      sequence: run.sequence,
      verificationBaselineRunId: run.verification_baseline_run_id ?? undefined,
      requestOutcome,
      status,
      progress: scanRunOverallProgress({ status, engineRuns }),
      startedAt: run.engine_runs.map((engineRun) => engineRun.started_at).filter((value): value is string => Boolean(value)).sort()[0] ?? run.created_at,
      finishedAt: run.completed_at ?? undefined,
      lastProgressAt: runIndex === 0 && ["queued", "running", "paused"].includes(status)
        ? nativeCase.updated_at
        : run.completed_at ?? lastEngineActivityAt ?? run.created_at,
      knowledgeDate: run.knowledge_cutoff,
      engineAdmissionIssues: (run.engine_admission_issues ?? []).map((issue) => ({
        engineId: issue.engine_id ?? undefined,
        code: issue.code,
        detail: issue.detail,
      })),
      engineRuns,
      coveredAssetCount: coveredAssetIds.length,
      totalAssetCount: allAssetIds.length,
    };
  });
  const scopeGrants: ScopeGrant[] = nativeCase.scope_grants.flatMap((grant) => {
    const mode = mapScopeMode(grant.permission);
    return mode ? [{
      id: grant.id,
      assetId: grant.asset_id,
      modes: [mode],
      state: "authorized" as const,
      confirmedAt: grant.confirmed_at,
      confirmedBy: grant.confirmed_by,
      note: grant.notes ?? undefined,
      externalScope: grant.external_scope ? adaptExternalScope(grant.external_scope) : undefined,
    }] : [];
  });
  const workflowEvents = (nativeCase.finding_workflow_events ?? []).map((event) => ({
    id: event.id,
    findingId: event.finding_id,
    fromStatus: mapWorkflow(event.from_status),
    toStatus: mapWorkflow(event.to_status),
    decidedBy: event.decided_by,
    decidedAt: event.decided_at,
    reason: event.reason,
    expiresAt: event.expires_at ?? undefined,
  }));
  const exports: CaseExport[] = nativeCase.exports.map((item) => ({
    ...adaptNativeExport(item),
    isDemo: nativeCase.is_demo,
  }));
  const comparison = nativeCase.comparisons.at(-1);
  let verification: VerificationSummary | undefined;
  if (comparison) {
    const nativeFindingById = new Map(nativeCase.findings.map((finding) => [finding.id, finding]));
    const runById = new Map(nativeCase.scan_runs.map((run) => [run.id, run]));
    const localInputChanges = localInputChangesFromComparison(comparison.local_input_changes);
    verification = {
      baselineRunId: comparison.baseline_run_id,
      comparisonRunId: comparison.current_run_id,
      baselineAt: runById.get(comparison.baseline_run_id)?.completed_at ?? runById.get(comparison.baseline_run_id)?.created_at ?? comparison.created_at,
      comparisonAt: runById.get(comparison.current_run_id)?.completed_at ?? runById.get(comparison.current_run_id)?.created_at ?? comparison.created_at,
      complete: comparison.complete ?? false,
      completenessIssues: (comparison.completeness_issues ?? []).map((reason) => ({
        code: reason.code,
        engineId: reason.engine_id ?? undefined,
        assetId: reason.asset_id ?? undefined,
        detail: reason.detail,
      })),
      diffs: comparison.diffs.map((diff, index) => {
        const sourceFinding = nativeFindingById.get(diff.current_finding_id ?? "") ?? nativeFindingById.get(diff.baseline_finding_id ?? "");
        const statusMap: Record<FindingDiffStatus, DiffState> = {
          resolved: "resolved",
          still_present: "persistent",
          newly_observed: "new",
          changed: "persistent",
          unable_to_verify: "unverifiable",
        };
        return {
          id: `${comparison.id}-${index}`,
          findingId: diff.current_finding_id ?? diff.baseline_finding_id ?? undefined,
          title: sourceFinding?.title ?? diff.fingerprint,
          assetName: localizedList(
            sourceFinding?.asset_ids
              .map((id) => assetById.get(id)?.name)
              .filter((name): name is string => Boolean(name)) ?? [],
          ) || adapterText("Unknown asset", "未知資產"),
          state: statusMap[diff.status] ?? "unverifiable",
          comparisonStatus: diff.status,
          beforeSeverity: diff.baseline_severity ? mapSeverity(diff.baseline_severity) : undefined,
          afterSeverity: diff.current_severity ? mapSeverity(diff.current_severity) : undefined,
          explanation: diff.explanation,
          evidenceChanged: diff.evidence_changed ?? false,
          changeReasons: (diff.reasons ?? []).map((reason) => ({
            code: reason.code,
            engineId: reason.engine_id ?? undefined,
            assetId: reason.asset_id ?? undefined,
            detail: reason.detail,
          })),
        };
      }),
      ...(localInputChanges.length > 0 ? { localInputChanges } : {}),
    };
  }
  const assessmentIntent = mapAssessmentIntent(nativeCase.assessment_intent);
  const platforms = withDraftIntentFallback(
    uniquePlatforms([
      ...assets.map((asset) => asset.platform),
      ...nativeCase.data_sources
        .filter((source) => source.status !== "not_applicable")
        .map((source) => platformFromSource(source.kind)),
    ]),
    assessmentIntent,
    nativeCase.status,
    nativeCase.assets.length,
  );
  const assessmentCase: AssessmentCase = {
    id: nativeCase.id,
    name: nativeCase.title,
    assessmentIntent,
    aiGeneratedArtifact: mapAiGeneratedArtifact(nativeCase.ai_generated_artifact),
    organizationName: nativeCase.profile.organization_name,
    companySize: mapCompanySize(nativeCase.profile.employee_range),
    dataClasses: mapDataClasses(nativeCase.profile.data_classes),
    requestedActivities: (nativeCase.requested_activities ?? []).filter(
      (activity): activity is AssessmentActivity => [
        "configuration_assessment",
        "local_artifact_analysis",
        "low_impact_external_checks",
        "active_external_vulnerability_tests",
      ].includes(activity),
    ),
    platforms,
    createdAt: nativeCase.created_at,
    updatedAt: nativeCase.updated_at,
    phase: mapPhase(nativeCase.status),
    isDemo: nativeCase.is_demo,
    description: nativeCase.profile.notes ?? undefined,
    latestRunId: runs[0]?.id,
    assetCount: nativeCase.assets.length,
    findingCount: nativeCase.findings.length,
    productIdentity: (() => {
      const productRuns = runs.filter(isExactBuiltInLocalhostQuickScanRun);
      if (productRuns.length === 0 || productRuns.length !== runs.length) return undefined;
      const ports = new Set(productRuns.map((run) => {
        const taskKind = run.engineRuns[0]?.taskKind;
        return taskKind?.kind === "built_in_localhost_tcp" ? taskKind.port : undefined;
      }));
      if (ports.size !== 1) return undefined;
      const port = [...ports][0];
      return typeof port === "number"
        ? { kind: "localhost_quick_scan" as const, port }
        : undefined;
    })(),
  };
  return { case: assessmentCase, sources, coverage, assets, scopeGrants, runs, findings, findingGroups, findingGroupEvents, workflowEvents, exports, verification };
};

export const adaptNativeSnapshot = (
  snapshot: NativeAppSnapshot,
  nativeManifests: NativeEngineManifest[],
): AppSnapshot => {
  const engineManifests = nativeManifests.map(adaptNativeManifest);
  const workspace = snapshot.selected_case ? adaptNativeCase(snapshot.selected_case, engineManifests) : undefined;
  if (workspace) {
    workspace.beginnerReports = (snapshot.beginner_reports ?? []).map(adaptBeginnerMasterReport);
  }
  const cases = snapshot.cases.map(adaptSummary);
  if (workspace) {
    const index = cases.findIndex((item) => item.id === workspace.case.id);
    if (index >= 0) cases[index] = workspace.case;
    else cases.unshift(workspace.case);
  }
  return {
    cases,
    selectedCaseId: workspace?.case.id,
    workspace,
    engineManifests,
    generatedAt: new Date().toISOString(),
    provenance: "native",
    productName: snapshot.product_name,
    productVersion: snapshot.product_version,
    storagePath: snapshot.storage_path,
    runtime: {
      provider: snapshot.runtime.provider,
      // Only the backend's exact boolean can make scan tools look ready.
      available: snapshot.runtime.available === true,
      phase: snapshot.runtime.phase,
      version: snapshot.runtime.version ?? undefined,
      prerequisite: snapshot.runtime.prerequisite ?? undefined,
      detail: snapshot.runtime.detail,
    },
    artifactCleanupObligations: snapshot.artifact_cleanup_obligations.map((obligation) => ({
      caseId: obligation.case_id,
      exactPath: obligation.exact_path,
      exists: obligation.exists,
      requiresExplicitConfirmation: obligation.requires_explicit_confirmation,
    })),
    caseRecoveryDiagnostics: (snapshot.case_recovery_diagnostics ?? []).map((diagnostic) => ({
      caseId: diagnostic.case_id,
      title: diagnostic.title,
      updatedAt: diagnostic.updated_at,
      revision: diagnostic.revision,
      documentBytes: diagnostic.document_bytes,
      code: diagnostic.code,
      message: diagnostic.message,
      preserved: exactBoolean(diagnostic.preserved) ?? false,
    })),
    engineAdmissionIssues: (snapshot.engine_admission_issues ?? []).map((issue) => ({
      engineId: issue.engine_id ?? undefined,
      code: issue.code,
      detail: issue.detail,
    })),
    engineCount: snapshot.engine_count,
  };
};

const adaptBeginnerInventoryItem = (
  item: NativeBeginnerInventoryItem,
): BeginnerInventoryItem | undefined => {
  const common = {
    assetId: item.asset_id,
    sources: item.sources.map((source) => ({
      observationId: source.observation_id,
      engineId: source.engine_id,
      engineRunId: source.engine_run_id,
      artifactId: source.artifact_id,
      artifactSha256: source.artifact_sha256,
      pointer: source.pointer,
      observedAt: source.observed_at,
    })),
  };
  if (item.kind === "service") return {
    ...common,
    kind: item.kind,
    endpoint: item.endpoint,
    port: item.port ?? undefined,
    transport: item.transport ?? undefined,
    schemes: [...item.schemes],
    httpStatuses: [...item.http_statuses],
    tlsObservations: [...item.tls_observations],
  };
  if (item.kind === "software_component") return {
    ...common,
    kind: item.kind,
    name: item.name,
    version: item.version ?? undefined,
    packageType: item.package_type ?? undefined,
    purl: item.purl ?? undefined,
  };
  if (item.kind === "workflow_component") return {
    ...common,
    kind: item.kind,
    componentType: item.component_type,
    name: item.name,
    model: item.model ?? undefined,
    isGuardrail: exactBoolean(item.is_guardrail),
  };
  if (item.kind === "workflow_relationship") return {
    ...common,
    kind: item.kind,
    source: item.source,
    target: item.target,
    condition: item.condition ?? undefined,
  };
  if (item.kind === "cloud_resource") return {
    ...common,
    kind: item.kind,
    resourceType: item.resource_type,
    nativeId: item.native_id ?? undefined,
    displayName: item.display_name ?? undefined,
  };
  // An unknown inventory tag cannot become a named observation of another type.
  return undefined;
};

const adaptBeginnerInventoryItems = (items: NativeBeginnerInventoryItem[]): BeginnerInventoryItem[] =>
  items.flatMap((item) => {
    const adapted = adaptBeginnerInventoryItem(item);
    return adapted ? [adapted] : [];
  });

const adaptBeginnerInventoryCounts = (counts: NativeBeginnerInventory["counts"]) => ({
  services: counts.services,
  softwareComponents: counts.software_components,
  cloudResources: counts.cloud_resources,
  workflowComponents: counts.workflow_components ?? 0,
  workflowRelationships: counts.workflow_relationships ?? 0,
});

const adaptBeginnerTechnicalExecution = (
  execution: NativeBeginnerTechnicalExecution,
): BeginnerTechnicalExecution => {
  if (execution.kind === "catalog_engine") return {
    kind: execution.kind,
    engineId: execution.engine_id,
    engineVersion: execution.engine_version ?? undefined,
    reportedVersion: reportedScannerVersion(execution.reported_version),
    imageDigest: execution.image_digest ?? undefined,
    commandSha256: execution.command_sha256 ?? undefined,
    runtimeProvider: execution.runtime_provider ?? undefined,
    runtimeVersion: execution.runtime_version ?? undefined,
    runtimeSecurityOptions: execution.runtime_security_options ?? undefined,
    distributionMode: execution.distribution_mode ?? undefined,
    imageRepository: execution.image_repository ?? undefined,
    adapterVersion: execution.adapter_version,
    ruleVersion: execution.rule_version ?? undefined,
    knowledgeDate: execution.knowledge_date ?? undefined,
  };
  if (execution.kind === "built_in_localhost_tcp") return {
    kind: execution.kind,
    endpoint: execution.endpoint,
    timeoutMs: execution.timeout_ms,
    payloadBytes: execution.payload_bytes,
    observation: execution.observation ? {
      outcome: execution.observation.outcome,
      observedAt: execution.observation.observed_at,
    } : undefined,
    contract: execution.contract,
  };
  return {
    kind: execution.kind,
    explanation: execution.explanation,
  };
};

const BEGINNER_CHECK_RESULT_KINDS: readonly BeginnerCheckResultKindWire[] = [
  "security_check",
  "inventory",
  "connectivity",
];

// Missing legacy values remain inferable from the stable check ID. A present
// value outside the closed wire vocabulary cannot become a security check.
const mapBeginnerCheckResultKind = (value: unknown): BeginnerCheckResultKind | undefined => {
  if (value === undefined || value === null) return undefined;
  return BEGINNER_CHECK_RESULT_KINDS.includes(value as BeginnerCheckResultKindWire)
    ? value as BeginnerCheckResultKindWire
    : "unknown";
};

const BEGINNER_COVERAGE_GAP_KINDS: readonly BeginnerCoverageGapKind[] = [
  "not_tested",
  "failed",
  "timed_out",
  "cancelled",
  "excluded",
  "truncated",
  "unavailable",
  "unattributed",
  "manual_review",
];

// An unrecognized gap still means the recorded coverage needs attention.
const mapBeginnerCoverageGapKind = (value: unknown): BeginnerCoverageGapKind =>
  BEGINNER_COVERAGE_GAP_KINDS.includes(value as BeginnerCoverageGapKind)
    ? value as BeginnerCoverageGapKind
    : "unavailable";

const BEGINNER_COVERAGE_GAP_CLASSES: readonly BeginnerCoverageGapClass[] = [
  "coverage_loss",
  "record_note",
];

// Absence is a report saved before the field existed and keeps the
// conservative historical meaning. An unrecognized present value is not
// absence: it still means the recorded coverage needs attention, the same
// way an unrecognized kind becomes unavailable.
const mapBeginnerCoverageGapClass = (value: unknown): BeginnerCoverageGapClass => {
  if (value === undefined || value === null) return "coverage_loss";
  return BEGINNER_COVERAGE_GAP_CLASSES.includes(value as BeginnerCoverageGapClass)
    ? value as BeginnerCoverageGapClass
    : "coverage_loss";
};

const BEGINNER_REPORT_DATA_AVAILABILITIES = [
  "recorded",
  "current_case_fallback",
  "unavailable",
  "not_applicable",
] as const;

// An unknown provenance value must expose the report dimension as unavailable.
const mapBeginnerReportDataAvailability = (
  value: unknown,
): BeginnerMasterReport["requested"]["stage"]["availability"] =>
  BEGINNER_REPORT_DATA_AVAILABILITIES.includes(value as typeof BEGINNER_REPORT_DATA_AVAILABILITIES[number])
    ? value as typeof BEGINNER_REPORT_DATA_AVAILABILITIES[number]
    : "unavailable";

export const adaptBeginnerMasterReport = (
  report: NativeBeginnerMasterReport,
): BeginnerMasterReport => ({
  schemaVersion: report.schema_version,
  caseId: report.case_id,
  runId: report.run_id,
  projectTitle: report.project_title,
  state: {
    summary: report.state.summary,
    lifecycle: report.state.lifecycle,
    lastDurableUpdate: report.state.last_durable_update,
    explanation: report.state.explanation,
  },
  requested: {
    targets: report.requested.targets.map((target) => ({
      assetId: target.asset_id,
      label: target.label ?? undefined,
      assetKind: target.asset_kind ?? undefined,
      labelAvailability: mapBeginnerReportDataAvailability(target.label_availability),
      assetKindAvailability: mapBeginnerReportDataAvailability(target.asset_kind_availability),
    })),
    stage: {
      value: report.requested.stage.value ?? undefined,
      availability: mapBeginnerReportDataAvailability(report.requested.stage.availability),
      explanation: report.requested.stage.explanation,
    },
    limits: report.requested.limits.map((limit) => ({ ...limit })),
    requestedCheckIds: [...report.requested.requested_check_ids],
    requestOutcomeCode: report.requested.request_outcome_code ?? undefined,
    automaticReductions: report.requested.automatic_reductions.map((reduction) => ({ ...reduction })),
    reductionsAvailability: report.requested.reductions_availability,
    unavailableDimensions: report.requested.unavailable_dimensions.map((dimension) => ({ ...dimension })),
  },
  actual: {
    observedFrom: report.actual.observed_from ?? undefined,
    observedUntil: report.actual.observed_until ?? undefined,
    checks: report.actual.checks.map((check) => ({
      taskId: check.task_id,
      checkId: check.check_id,
      resultKind: mapBeginnerCheckResultKind(check.result_kind),
      targetAssetIds: [...check.target_asset_ids],
      status: check.status,
      startedAt: check.started_at ?? undefined,
      finishedAt: check.finished_at ?? undefined,
      testedDimensions: check.tested_dimensions.map((dimension) => ({
        dimension: dimension.dimension,
        value: dimension.value,
        observation: dimension.observation,
        observedAt: dimension.observed_at ?? undefined,
      })),
    })),
    networkScopes: (report.actual.network_scopes ?? []).map((scope) => ({
      taskId: scope.task_id,
      checkId: scope.check_id,
      workUnitId: scope.work_unit_id,
      targetAssetId: scope.target_asset_id,
      target: scope.target,
      addressRanges: [...scope.address_ranges],
      portRanges: [...scope.port_ranges],
      transport: scope.transport,
      stage: scope.stage,
      outcome: scope.outcome,
      observedAt: scope.observed_at ?? undefined,
    })),
    unavailableDimensions: report.actual.unavailable_dimensions.map((dimension) => ({ ...dimension })),
  },
  coverageGaps: report.coverage_gaps.map((gap) => ({
    kind: mapBeginnerCoverageGapKind(gap.kind),
    class: mapBeginnerCoverageGapClass(gap.class),
    taskId: gap.task_id ?? undefined,
    targetAssetIds: [...gap.target_asset_ids],
    dimension: gap.dimension,
    reason: gap.reason,
    nextActionCode: gap.next_action_code,
    nextAction: gap.next_action,
    unattributed: mapUnattributed(gap.unattributed),
  })),
  coverageCounts: {
    testedComplete: report.coverage_counts.tested_complete,
    testedPartial: report.coverage_counts.tested_partial,
    failed: report.coverage_counts.failed,
    timedOut: report.coverage_counts.timed_out,
    cancelled: report.coverage_counts.cancelled,
    notTested: report.coverage_counts.not_tested,
    excluded: report.coverage_counts.excluded,
    truncated: report.coverage_counts.truncated,
    unavailable: report.coverage_counts.unavailable,
    // Absent from a report written before this count existed. Zero is the
    // honest reading: that build could not have discarded anything for a
    // reason it did not know about.
    unattributed: report.coverage_counts.unattributed ?? 0,
    // Older saved reports predate typed Maester review items.
    manualReview: report.coverage_counts.manual_review ?? 0,
  },
  inventory: report.inventory ? {
    total: report.inventory.total,
    counts: adaptBeginnerInventoryCounts(report.inventory.counts),
    assetIds: [...report.inventory.asset_ids],
    representativeSample: adaptBeginnerInventoryItems(report.inventory.representative_sample),
    items: adaptBeginnerInventoryItems(report.inventory.items),
    byAsset: report.inventory.by_asset.map((asset) => ({
      assetId: asset.asset_id,
      total: asset.total,
      counts: adaptBeginnerInventoryCounts(asset.counts),
      representativeSample: adaptBeginnerInventoryItems(asset.representative_sample),
    })),
  } : undefined,
  findings: report.findings.map((finding) => ({
    findingId: finding.finding_id,
    fingerprint: finding.fingerprint,
    snapshotSource: finding.snapshot_source,
    title: finding.title,
    plainLanguageRisk: finding.plain_language_risk,
    possibleImpact: finding.possible_impact,
    // Normalized exactly as the canonical mapper does. This report is what the
    // findings list renders from, so an un-normalized value here reaches every
    // `severityMeta[...]` lookup on that page.
    severity: mapSeverity(finding.severity),
    confidence: mapConfidence(finding.confidence),
    // The codes the localized surfaces compose their sentences from. Dropping
    // them left the zh-TW page on the English fallback, and left the summary
    // composer on its no-basis branch, which credits the engine with a rating
    // the engine did not give.
    family: mapFindingFamily(finding.family),
    severityBasisCode: mapSeverityBasisCode(finding.severity_basis_code),
    confidenceBasisCode: mapConfidenceBasisCode(finding.confidence_basis_code),
    observationDetails: finding.observation_details ? [...finding.observation_details] : undefined,
    contextFactors: mapContextFactors(finding.context_factors),
    rollbackConsiderations: finding.rollback_considerations ?? undefined,
    verificationGuidance: finding.verification_guidance ?? undefined,
    priority: finding.priority ?? undefined,
    priorityReasons: [...finding.priority_reasons],
    targetAssetIds: [...finding.target_asset_ids],
    nextStep: finding.next_step,
    recommendedExpertType: finding.recommended_expert_type,
    evidenceReferences: finding.evidence_references.map((evidence) => ({
      evidenceId: evidence.evidence_id,
      engineId: evidence.engine_id,
      detailsFrozen: evidence.details_frozen ?? false,
      sourceRule: evidence.source_rule ?? undefined,
      scannerDetails: mapScannerFindingDetails(evidence.scanner_details, evidence.engine_id),
      summary: evidence.summary ?? undefined,
      kind: evidence.kind ?? undefined,
      engineRunId: evidence.engine_run_id ?? undefined,
      artifactId: evidence.artifact_id ?? undefined,
      redacted: exactBoolean(evidence.redacted),
      artifactSha256: evidence.artifact_sha256,
      observedAt: evidence.observed_at,
      location: evidence.location ?? undefined,
      pointer: evidence.pointer ?? undefined,
    })),
    officialReferences: finding.official_references
      ? [...finding.official_references]
      : undefined,
    frameworkReferences: finding.framework_references.map((reference) => ({
      framework: reference.framework,
      frameworkVersion: reference.framework_version,
      controlId: reference.control_id,
      title: reference.title,
      relationship: reference.relationship,
      rationale: reference.rationale,
      mappingVersion: reference.mapping_version,
      mappingProvenance: mapControlMappingProvenance(reference.mapping_provenance),
    })),
  })),
  findingGroups: (report.finding_groups ?? []).map((group) => ({
    groupId: group.group_id,
    presentationScope: group.presentation_scope,
    title: group.title,
    rationale: group.rationale,
    actor: group.actor,
    createdAt: group.created_at,
    members: group.members.map((member) => ({
      findingId: member.finding_id,
      observedInSelectedRun: member.observed_in_selected_run,
    })),
  })),
  problemGroups: (report.problem_groups ?? []).map((group) => {
    const lowerPriorityMembers = group.lower_priority_members === "partial"
      || group.lower_priority_members === "all"
      ? group.lower_priority_members
      : undefined;
    return {
      groupId: group.group_id,
      ruleVersion: group.rule_version,
      kind: group.kind,
      title: group.title,
      targetAssetId: group.target_asset_id,
      representativeFindingId: group.representative_finding_id,
      findingIds: [...group.finding_ids],
      policyName: group.policy_name ?? undefined,
      ...(lowerPriorityMembers ? { lowerPriorityMembers } : {}),
      ...(group.package_name ? { packageName: group.package_name } : {}),
      ...(group.installed_version ? { installedVersion: group.installed_version } : {}),
      ...(group.advisory_ids && group.advisory_ids.length > 0
        ? { advisoryIds: [...group.advisory_ids] }
        : {}),
    };
  }),
  nextSteps: report.next_steps.map((step) => ({
    priority: step.priority,
    code: step.code,
    action: step.action,
    reason: step.reason,
    findingId: step.finding_id ?? undefined,
    taskId: step.task_id ?? undefined,
    recommendedExpertType: step.recommended_expert_type ?? undefined,
    family: mapFindingFamily(step.family),
    unattributed: mapUnattributed(step.unattributed),
    alsoResolves: step.also_resolves ? [...step.also_resolves] : undefined,
    // Absent and false are the same claim: this step is not one specific change.
    // `exactBoolean` would keep false, which this field does not mean.
    sharedFix: step.shared_fix === true ? true : undefined,
  })),
  technicalDetails: {
    collapsedByDefault: true,
    tasks: report.technical_details.tasks.map((task) => ({
      taskId: task.task_id,
      targetAssetIds: [...task.target_asset_ids],
      status: mapEngineStatus(task.status),
      phase: task.phase,
      progressPercent: task.progress_percent,
      startedAt: task.started_at ?? undefined,
      finishedAt: task.finished_at ?? undefined,
      exitCode: task.exit_code ?? undefined,
      cleanupRemoved: exactBoolean(task.cleanup_removed),
      cleanupDetail: {
        availability: task.cleanup_detail.availability,
        value: task.cleanup_detail.value ?? undefined,
        explanation: task.cleanup_detail.explanation,
      },
      errorCode: task.error_code ?? undefined,
      redactedScannerMessage: {
        availability: task.redacted_scanner_message.availability,
        value: task.redacted_scanner_message.value ?? undefined,
        explanation: task.redacted_scanner_message.explanation,
      },
      redactedDiagnosticLog: {
        availability: task.redacted_diagnostic_log.availability,
        value: task.redacted_diagnostic_log.value ?? undefined,
        explanation: task.redacted_diagnostic_log.explanation,
      },
      evidenceSha256: [...task.evidence_sha256],
      execution: adaptBeginnerTechnicalExecution(task.execution),
    })),
  },
  frameworkNotice: {
    nonCertification: report.framework_notice.non_certification,
    aidefendMappingStatus: report.framework_notice.aidefend_mapping_status,
  },
  dataQualityWarnings: [...report.data_quality_warnings],
});
