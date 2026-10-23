import { translateBilingualText } from "../i18n/core";
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";

import {
  createStoredDemoCase,
  deleteStoredDemoCase,
  getDemoNotice,
  getDemoSnapshot,
  getDemoWorkspace,
} from "../data/demo";
import { getActiveLocale } from "../i18n/core";
import { internalHostGreenboneProfile } from "../internalHostProfile";
import {
  DEFAULT_LOCALHOST_QUICK_SCAN_PORT,
  isValidLocalhostQuickScanPort,
} from "../localhostQuickScan";
import {
  deriveScanLifecycleDisposition,
  type ScanLifecycleDisposition,
} from "../scanLifecycleDisposition";
import type {
  AppSnapshot,
  AttachWorkspaceSnapshotInput,
  RefreshWorkspaceSnapshotInput,
  BeginProviderAuthorizationInput,
  BootstrapOperatorConfig,
  BootstrapRequest,
  AssessmentCase,
  CaseExport,
  CaseArtifactCleanupInput,
  CaseArtifactCleanupResult,
  CaseDeletionResponse,
  CaseWorkspace,
  CloudPlatform,
  ConnectSourceSnapshotInput,
  CorrelationReport,
  CreateCaseInput,
  DataClass,
  DataClassWire,
  EngineManifest,
  ExportCaseInput,
  ExportPreview,
  ExternalScopeRequest,
  ExecuteProviderBootstrapInput,
  FindingWorkflowUpdateInput,
  FindingGroupInput,
  FindingUngroupInput,
  ServiceResult,
  ScopeMode,
  ProviderAuthorizationProgress,
  ProviderAuthorizationPrompt,
  BootstrapCleanupObligationSummary,
  ProviderBootstrapInstalled,
  ProviderBootstrapPlan,
  InstalledProviderAuthorization,
  ManagedRuntimeSetupStatus,
  LocalNetworkCandidateInventory,
  ScanReadiness,
  SelectMcpConfigurationInput,
  SelectAgenticFrameworkInput,
  ModelEndpointInput,
} from "../types";
import { buildNativeExportCaseArguments } from "../exportRequest";
import { findRequestedExportRun } from "../exportRunSelection";
import {
  buildDemoExportPayload,
  normalizeDemoExportInput,
  projectDemoSelectedRun,
} from "../demoExportProjection";
import { subscribeBufferedEvents } from "./bufferedEventSubscription";
import {
  adaptLocalNetworkCandidateInventory,
  adaptManagedRuntimeSetupStatus,
  adaptNativeCase,
  adaptNativeExport,
  adaptNativeExportPreview,
  adaptNativeManifest,
  adaptNativeSnapshot,
  exportRunFileIdentity,
  type NativeAppSnapshot,
  type NativeAssessmentCase,
  type NativeCaseExport,
  type NativeExportPreview,
  type NativeEngineManifest,
  type NativeManagedRuntimeSetupStatus,
} from "./nativeAdapter";

export const COMMANDS = {
  getSnapshot: "get_app_snapshot",
  setupManagedRuntime: "setup_managed_runtime",
  getManagedRuntimeSetupStatus: "get_managed_runtime_setup_status",
  cancelManagedRuntimeSetup: "cancel_managed_runtime_setup",
  createCase: "create_case",
  selectCase: "select_case",
  seedDemoCase: "seed_demo_case",
  listEngineManifests: "list_engine_manifests",
  detectLocalPrivateSubnets: "detect_local_private_subnets",
  getScanReadiness: "get_scan_readiness",
  startDiscovery: "start_discovery",
  cancelDiscovery: "cancel_discovery",
  connectSourceSnapshot: "connect_source_snapshot",
  attachWorkspaceSnapshot: "attach_workspace_snapshot",
  refreshWorkspaceSnapshot: "refresh_workspace_snapshot",
  selectMcpConfiguration: "select_mcp_configuration",
  selectAgenticFramework: "select_agentic_framework",
  configureModelEndpoint: "configure_model_endpoint",
  setModelEndpointKey: "set_model_endpoint_key",
  approveScope: "approve_scope",
  updateFindingWorkflow: "update_finding_workflow",
  groupFindings: "group_findings",
  ungroupFindings: "ungroup_findings",
  suggestFindingCorrelations: "suggest_finding_correlations",
  startLocalhostQuickScan: "start_localhost_quick_scan",
  startScan: "start_scan",
  previewExternalScannerImport: "preview_external_scanner_import",
  importExternalScannerReports: "import_external_scanner_reports",
  pauseScan: "pause_scan",
  resumeScan: "resume_scan",
  cancelScan: "cancel_scan",
  previewExport: "preview_export",
  exportCase: "export_case",
  exportSelectedRunReport: "export_selected_run_report",
  verifyCaseExport: "verify_case_export",
  startRescan: "start_rescan",
  archiveCase: "archive_case",
  deleteCase: "delete_case",
  deleteCaseArtifacts: "delete_case_artifacts",
  beginProviderAuthorization: "begin_provider_authorization",
  pollProviderAuthorization: "poll_provider_authorization",
  cancelProviderAuthorization: "cancel_provider_authorization",
  providerAuthorizationStatus: "provider_authorization_status",
  revokeProviderAuthorization: "revoke_provider_authorization",
  planProviderBootstrap: "plan_provider_bootstrap",
  executeProviderBootstrap: "execute_provider_bootstrap",
  cleanupProviderBootstrap: "cleanup_provider_bootstrap",
  listProviderBootstrapCleanup: "list_provider_bootstrap_cleanup",
} as const;

export const EVENTS = {
  coverageChanged: "case://coverage-changed",
  runProgress: "scan://run-progress",
  runFinished: "scan://run-finished",
  exportProgress: "export://progress",
  bootstrapMessage: "provider://bootstrap-message",
} as const;

export type ScannerEventName = (typeof EVENTS)[keyof typeof EVENTS];

export interface ScannerEventEnvelope<T = unknown> {
  schemaVersion: "1.0.0";
  eventType: ScannerEventName;
  occurredAt: string;
  payload: T;
}

const packagedTauriPlatform = import.meta.env?.TAURI_ENV_PLATFORM?.trim();

const hasLiveTauriBridge = (): boolean =>
  typeof window !== "undefined" &&
  typeof (window as Window & {
    __TAURI_INTERNALS__?: { invoke?: unknown };
  }).__TAURI_INTERNALS__?.invoke === "function";

/**
 * Demo data belongs only to the explicit browser-development surface. A
 * packaged desktop build stays native even while its bridge is starting or
 * unavailable, so a bridge failure can never silently change real projects
 * into sample data.
 */
const isNativeSurface = (): boolean => Boolean(packagedTauriPlatform) || hasLiveTauriBridge();

const invoke = async <T,>(command: string, args?: Record<string, unknown>): Promise<T> => {
  if (!hasLiveTauriBridge()) {
    throw new Error(serviceText(
      "Desktop service unavailable. Restart ai-security-scanner.",
      "桌面服務無法使用；請重新啟動 ai-security-scanner。",
    ));
  }
  return tauriInvoke<T>(command, args);
};

const errorMessage = (error: unknown): string => {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  try {
    return JSON.stringify(error);
  } catch {
    return serviceText("Operation failed.", "操作失敗。");
  }
};

const serviceText = (en: string, zhTW: string): string =>
  translateBilingualText(getActiveLocale(), { en, zhTW });

const nativeResult = <T,>(data: T): ServiceResult<T> => ({ data, mode: "native" });

interface NativeScanReadiness {
  case_id: string;
  checked_at: string;
  ready: boolean;
  state: ScanReadiness["state"];
  authorized_target_count: number;
  pending_target_count: number;
  compatible_engine_count: number;
  runnable_engine_count: number;
  blocker_code: ScanReadiness["blockerCode"] | null;
  next_step: ScanReadiness["nextStep"] | null;
}

const adaptScanReadiness = (value: NativeScanReadiness): ScanReadiness => ({
  caseId: value.case_id,
  checkedAt: value.checked_at,
  ready: value.ready,
  state: value.state,
  authorizedTargetCount: value.authorized_target_count,
  pendingTargetCount: value.pending_target_count,
  compatibleEngineCount: value.compatible_engine_count,
  runnableEngineCount: value.runnable_engine_count,
  blockerCode: value.blocker_code ?? undefined,
  nextStep: value.next_step ?? undefined,
});

const demoResult = <T,>(data: T, reason?: string): ServiceResult<T> => {
  if (reason) console.warn("[ai-security-scanner] desktop service unavailable", reason);
  return { data, mode: "demo", notice: getDemoNotice() };
};

const demoRuntimeSetupStatus = (): ManagedRuntimeSetupStatus => ({
  phase: "idle",
  active: false,
  prerequisiteRepairActive: false,
  cancelRequested: false,
  receivedBytes: 0,
  resumedFromBytes: 0,
  canCancel: false,
  canRetry: true,
  detail: serviceText(
    "Open the desktop app to prepare the scan tools.",
    "請開啟桌面版準備掃描工具。",
  ),
});

const getNativeManifests = async (): Promise<NativeEngineManifest[]> => {
  try {
    return await invoke<NativeEngineManifest[]>(COMMANDS.listEngineManifests);
  } catch {
    // A usable case snapshot should stay native even if the optional registry view fails.
    return [];
  }
};

const actionResult = async (
  command: string,
  args: Record<string, unknown>,
  nativeMessage: string,
  demoMessage: string,
  returnWorkspace = false,
): Promise<ServiceResult<ActionResponse>> => {
  const runId = typeof args.runId === "string" ? args.runId : undefined;
  const lifecycleAction = command === COMMANDS.cancelScan
    ? "cancel"
    : command === COMMANDS.resumeScan
      ? "resume"
      : undefined;
  if (!isNativeSurface()) {
    return demoResult({ accepted: false, message: demoMessage });
  }
  try {
    const returnedCase = await invoke<NativeAssessmentCase & { cancel_requested_run_id?: string | null }>(command, args);
    // Mutation acknowledgement must never wait for the optional catalog read.
    // Events and the next bounded snapshot refresh can enrich engine metadata.
    const workspace = adaptNativeCase(returnedCase, []);
    const cancelRequestedRunId = lifecycleAction === "cancel"
      && returnedCase.cancel_requested_run_id === runId
      ? runId
      : undefined;
    return nativeResult({
      accepted: true,
      message: nativeMessage,
      workspace: returnWorkspace ? workspace : undefined,
      cancelRequestedRunId,
      lifecycleDisposition: lifecycleAction && runId
        ? deriveScanLifecycleDisposition(lifecycleAction, workspace, runId, cancelRequestedRunId)
        : undefined,
    });
  } catch (error) {
    return nativeResult({
      accepted: false,
      message: errorMessage(error),
      lifecycleDisposition: lifecycleAction && runId
        ? deriveScanLifecycleDisposition(lifecycleAction, undefined, runId)
        : undefined,
    });
  }
};

const employeeRanges: Record<CreateCaseInput["companySize"], string> = {
  unknown: "Not provided",
  solo: "1",
  small: "2-49",
  medium: "50-249",
  large: "250+",
};

export const nativeDataClasses: Record<DataClass, DataClassWire> = {
  pii: "personally_identifiable_information",
  phi: "protected_health_information",
  payment: "payment_card_information",
  credentials: "credentials_and_secrets",
  none: "general",
};

const platformSourceKinds: Record<CloudPlatform, ConnectSourceSnapshotInput["sourceKind"][]> = {
  aws: ["aws_organization"],
  azure: ["azure_tenant"],
  gcp: ["gcp_organization"],
  m365: ["microsoft365_tenant"],
  external: ["dns", "certificate_transparency"],
  code: ["git_repository", "terraform_state", "file_system"],
  container: ["container_registry"],
  kubernetes: ["kubernetes_cluster"],
};

export const plannedSourceKinds = (platforms: CloudPlatform[]): ConnectSourceSnapshotInput["sourceKind"][] =>
  [...new Set(platforms.flatMap((platform) => platformSourceKinds[platform]))];

const questionnaireSourceKinds = [...new Set(Object.values(platformSourceKinds).flat())];

export const plannedNotApplicableSourceKinds = (
  platforms: CloudPlatform[],
): ConnectSourceSnapshotInput["sourceKind"][] => {
  const applicable = new Set(plannedSourceKinds(platforms));
  return questionnaireSourceKinds.filter((kind) => !applicable.has(kind));
};

const exportFileTypes: Record<ExportCaseInput["format"], { suffix: string; extensions: string[]; label: string }> = {
  case_bundle: { suffix: "case.tar.gz", extensions: ["gz"], label: "ai-security-scanner case bundle" },
  json: { suffix: "json", extensions: ["json"], label: "Canonical JSON" },
  framework_report: {
    suffix: "frameworks.json",
    extensions: ["json"],
    label: "NIST, ISO, and AIDEFEND framework report",
  },
  ocsf: { suffix: "ocsf.json", extensions: ["json"], label: "OCSF JSON" },
  oscal: { suffix: "oscal.json", extensions: ["json"], label: "OSCAL JSON" },
  html: { suffix: "html", extensions: ["html"], label: "HTML report" },
};

export interface ActionResponse {
  accepted: boolean;
  message: string;
  snapshot?: AppSnapshot;
  workspace?: CaseWorkspace;
  lifecycleDisposition?: ScanLifecycleDisposition;
  cancelRequestedRunId?: string;
}

export type CaseExportVerificationResult =
  | { outcome: "verified"; message: string }
  | { outcome: "native_failed"; message: string }
  | { outcome: "demo_unavailable"; message: string };

export interface ScopeApprovalInput {
  caseId: string;
  assetIds: string[];
  modes: ScopeMode[];
  confirmation: string;
  externalScope?: ExternalScopeRequest;
}

/** An execution choice, kept separate from the user's authorization grant. */
export interface EngineAssetRoute {
  engineId: string;
  assetIds: string[];
}

export interface ExternalScannerImportPreview {
  source_sha256: string;
  source_format: string;
  engine_id: "strix";
  targets: string[];
  finding_count: number;
}

export interface ExternalScannerImportRequest {
  source_sha256: string;
  report_path: string;
  asset_id: string;
  upstream_target: string;
}

export interface SelectedRunReportExport {
  case_id: string;
  selected_run_ids: string[];
  format: "html" | "json";
  path: string;
  sha256: string;
  created_at: string;
  redaction_profile: "standard" | "none";
}

export interface StartScanInput {
  campaignId?: string;
  caseId: string;
  /** Legacy single-boundary form used by the single-target shortcuts. */
  authorization?: Omit<ScopeApprovalInput, "caseId">;
  /** Per-asset boundaries for one combined multi-target run. */
  authorizations?: Array<Omit<ScopeApprovalInput, "caseId">>;
  /** Legacy exact engine set. Omit when engineAssetRoutes is present. */
  engineIds?: string[];
  /** Exact engine-to-asset plan. It prevents one profile widening to every compatible asset. */
  engineAssetRoutes?: EngineAssetRoute[];
}

const nativeScopeDecisions = (input: ScopeApprovalInput) => {
  const permissionMap: Record<string, string> = {
    inventory: "inventory_read",
    configuration: "configuration_read",
    local_artifact: "local_artifact_read",
    public_data: "passive_external_discovery",
    passive: "passive_external_discovery",
    low_impact_external: "low_impact_external_connection",
    active_external: "active_external_testing",
    active: "active_external_testing",
  };
  const permissions = input.modes
    .map((mode) => permissionMap[mode])
    .filter((mode): mode is string => Boolean(mode));
  const needsReference = permissions.some((permission) =>
    permission === "low_impact_external_connection" || permission === "active_external_testing"
  );
  const externalScope = input.externalScope ? {
    target: input.externalScope.target,
    ports: input.externalScope.ports,
    protocol: input.externalScope.protocol,
    activity: input.externalScope.activity,
    rate_policy: {
      requests_per_second: input.externalScope.ratePolicy.requestsPerSecond,
      concurrency: input.externalScope.ratePolicy.concurrency,
      timeout_seconds: input.externalScope.ratePolicy.timeoutSeconds,
    },
    template_policy: {
      revision: input.externalScope.templatePolicy.revision,
      ...(input.externalScope.templatePolicy.profileId
        ? { profile_id: input.externalScope.templatePolicy.profileId }
        : {}),
      allowed_template_ids: input.externalScope.templatePolicy.allowedTemplateIds,
      allow_headless: input.externalScope.templatePolicy.allowHeadless,
      allow_out_of_band: input.externalScope.templatePolicy.allowOutOfBand,
      allow_fuzzing: input.externalScope.templatePolicy.allowFuzzing,
      allow_file_upload: input.externalScope.templatePolicy.allowFileUpload,
      allow_denial_of_service: input.externalScope.templatePolicy.allowDenialOfService,
      allow_credential_attacks: input.externalScope.templatePolicy.allowCredentialAttacks,
    },
    asserted_authority: input.externalScope.assertedAuthority,
    allow_sensitive_networks: input.externalScope.allowSensitiveNetworks,
  } : null;
  return input.assetIds.map((assetId) => ({
    asset_id: assetId,
    permissions,
    confirmed_by: serviceText("Local user", "本機使用者"),
    authorization_reference: needsReference || input.externalScope ? input.confirmation : null,
    notes: input.confirmation,
    external_scope: externalScope,
  }));
};

interface NativeCaseDeletionResult {
  database_record_deleted: boolean;
  artifacts: {
    case_id: string;
    exact_path: string;
    exists: boolean;
    requires_explicit_confirmation: boolean;
  };
}

interface NativeCaseArtifactCleanupResult {
  removed: boolean;
  exact_path: string;
  recoverable: boolean;
}

export const scannerService = {
  isNative: isNativeSurface,

  async getSnapshot(caseId?: string): Promise<ServiceResult<AppSnapshot>> {
    if (!isNativeSurface()) return demoResult(getDemoSnapshot(caseId));
    const nativeSnapshot = await invoke<NativeAppSnapshot>(COMMANDS.getSnapshot);
    const manifests = await getNativeManifests();
    return nativeResult(adaptNativeSnapshot(nativeSnapshot, manifests));
  },

  async setupManagedRuntime(): Promise<ServiceResult<ActionResponse>> {
    if (!isNativeSurface()) return demoResult({
      accepted: false,
      message: serviceText(
        "Open the desktop app to prepare the scan tools.",
        "請開啟桌面版準備掃描工具。",
      ),
    });
    const response = await invoke<{ accepted: boolean; message: string }>(COMMANDS.setupManagedRuntime);
    return nativeResult(response);
  },

  async getManagedRuntimeSetupStatus(): Promise<ServiceResult<ManagedRuntimeSetupStatus>> {
    if (!isNativeSurface()) return demoResult(demoRuntimeSetupStatus());
    const status = await invoke<NativeManagedRuntimeSetupStatus>(COMMANDS.getManagedRuntimeSetupStatus);
    return nativeResult(adaptManagedRuntimeSetupStatus(status));
  },

  async cancelManagedRuntimeSetup(): Promise<ServiceResult<ManagedRuntimeSetupStatus>> {
    if (!isNativeSurface()) return demoResult(demoRuntimeSetupStatus());
    const status = await invoke<NativeManagedRuntimeSetupStatus>(COMMANDS.cancelManagedRuntimeSetup);
    return nativeResult(adaptManagedRuntimeSetupStatus(status));
  },

  async createCase(input: CreateCaseInput): Promise<ServiceResult<AssessmentCase>> {
    if (!isNativeSurface()) return demoResult(createStoredDemoCase(input));
    const nativeCase = await invoke<NativeAssessmentCase>(COMMANDS.createCase, {
      request: {
        title: input.name,
        assessment_intent: input.assessmentIntent ?? null,
        ai_generated_artifact: input.aiGeneratedArtifact,
        organization_name: input.organizationName,
        employee_range: employeeRanges[input.companySize],
        data_classes: input.dataClasses.map((dataClass) => nativeDataClasses[dataClass]),
        requested_activities: input.requestedActivities,
        source_kinds: plannedSourceKinds(input.platforms),
        not_applicable_source_kinds: plannedNotApplicableSourceKinds(input.platforms),
        declared_assets: input.knownAssets.map(({ internetExposure, webService, networkService, hostScan, ...asset }) => ({
          ...asset,
          internet_exposed: internetExposure === undefined
            ? null
            : internetExposure === "public",
          web_service: webService
            ? {
              protocol: webService.protocol,
              port: webService.port,
              path: webService.path,
              scan_profile: webService.scanProfile ?? null,
            }
            : null,
          network_service: networkService
            ? {
              protocol: networkService.protocol,
              port: networkService.port,
              scan_profile: networkService.scanProfile,
            }
            : null,
          host_scan: hostScan
            ? {
              protocol: hostScan.protocol,
              ports: hostScan.ports,
              profile: internalHostGreenboneProfile.profileId,
            }
            : null,
        })),
        notes: input.description ?? null,
      },
    });
    return nativeResult(adaptNativeCase(nativeCase).case);
  },

  async seedDemoCase(): Promise<ServiceResult<AssessmentCase>> {
    if (!isNativeSurface()) {
      const snapshot = getDemoSnapshot();
      const demoCase = snapshot.cases.find(({ isDemo }) => isDemo) ?? snapshot.cases[0];
      if (!demoCase) throw new Error("The browser demonstration project is unavailable.");
      return demoResult(demoCase);
    }
    const nativeCase = await invoke<NativeAssessmentCase>(COMMANDS.seedDemoCase);
    return nativeResult(adaptNativeCase(nativeCase).case);
  },

  async selectCase(caseId: string): Promise<ServiceResult<CaseWorkspace>> {
    if (!isNativeSurface()) return demoResult(getDemoWorkspace(caseId));
    const nativeCase = await invoke<NativeAssessmentCase>(COMMANDS.selectCase, { caseId });
    const manifests = (await getNativeManifests()).map(adaptNativeManifest);
    return nativeResult(adaptNativeCase(nativeCase, manifests));
  },

  async listEngineManifests(): Promise<ServiceResult<EngineManifest[]>> {
    const demo = getDemoSnapshot().engineManifests;
    if (!isNativeSurface()) return demoResult(demo);
    return nativeResult((await getNativeManifests()).map(adaptNativeManifest));
  },

  async detectLocalPrivateSubnets(): Promise<ServiceResult<LocalNetworkCandidateInventory>> {
    const fallback: LocalNetworkCandidateInventory = {
      status: isNativeSurface() ? "unavailable" : "unsupported",
      candidates: [],
    };
    if (!isNativeSurface()) return demoResult(fallback);
    try {
      const inventory = await invoke<unknown>(COMMANDS.detectLocalPrivateSubnets);
      return nativeResult(adaptLocalNetworkCandidateInventory(inventory));
    } catch {
      // Interface detection is an optional convenience. Never expose native
      // details or turn a detection failure into a guessed scan target.
      return nativeResult(fallback);
    }
  },

  async getScanReadiness(caseId: string): Promise<ServiceResult<ScanReadiness>> {
    if (!isNativeSurface()) return demoResult({
      caseId,
      checkedAt: new Date().toISOString(),
      ready: false,
      state: "case_unavailable",
      authorizedTargetCount: 0,
      pendingTargetCount: 0,
      compatibleEngineCount: 0,
      runnableEngineCount: 0,
      blockerCode: "demo_case",
      nextStep: "cases",
    });
    return nativeResult(adaptScanReadiness(await invoke<NativeScanReadiness>(
      COMMANDS.getScanReadiness,
      { caseId },
    )));
  },

  async beginProviderAuthorization(
    request: BeginProviderAuthorizationInput,
  ): Promise<ServiceResult<ProviderAuthorizationPrompt>> {
    if (!isNativeSurface()) throw new Error("Provider authorization requires the native app.");
    return nativeResult(await invoke<ProviderAuthorizationPrompt>(COMMANDS.beginProviderAuthorization, { request }));
  },

  async pollProviderAuthorization(
    sessionId: string,
  ): Promise<ServiceResult<ProviderAuthorizationProgress>> {
    if (!isNativeSurface()) throw new Error("Provider authorization requires the native app.");
    return nativeResult(await invoke<ProviderAuthorizationProgress>(COMMANDS.pollProviderAuthorization, { sessionId }));
  },

  async cancelProviderAuthorization(sessionId: string): Promise<ServiceResult<boolean>> {
    if (!isNativeSurface()) return demoResult(false);
    return nativeResult(await invoke<boolean>(COMMANDS.cancelProviderAuthorization, { sessionId }));
  },

  async providerAuthorizationStatus(
    caseId: string,
    sourceId: string,
  ): Promise<ServiceResult<InstalledProviderAuthorization | null>> {
    if (!isNativeSurface()) return demoResult(null);
    return nativeResult(await invoke<InstalledProviderAuthorization | null>(COMMANDS.providerAuthorizationStatus, {
      caseId,
      sourceId,
    }));
  },

  async revokeProviderAuthorization(
    caseId: string,
    sourceId: string,
  ): Promise<ServiceResult<Record<string, unknown>>> {
    if (!isNativeSurface()) throw new Error("Provider authorization requires the native app.");
    return nativeResult(await invoke<Record<string, unknown>>(COMMANDS.revokeProviderAuthorization, {
      caseId,
      sourceId,
    }));
  },

  async planProviderBootstrap(request: BootstrapRequest): Promise<ServiceResult<ProviderBootstrapPlan>> {
    if (!isNativeSurface()) throw new Error("Provider bootstrap requires the native app.");
    return nativeResult(await invoke<ProviderBootstrapPlan>(COMMANDS.planProviderBootstrap, { request }));
  },

  async executeProviderBootstrap(
    input: ExecuteProviderBootstrapInput,
  ): Promise<ServiceResult<ProviderBootstrapInstalled>> {
    if (!isNativeSurface()) throw new Error("Provider bootstrap requires the native app.");
    return nativeResult(await invoke<ProviderBootstrapInstalled>(COMMANDS.executeProviderBootstrap, { input }));
  },

  async cleanupProviderBootstrap(
    caseId: string,
    operationId: string,
    operator: BootstrapOperatorConfig,
  ): Promise<ServiceResult<Record<string, unknown>>> {
    if (!isNativeSurface()) throw new Error("Provider cleanup requires the native app.");
    return nativeResult(await invoke<Record<string, unknown>>(COMMANDS.cleanupProviderBootstrap, {
      caseId,
      operationId,
      operator,
    }));
  },

  async listProviderBootstrapCleanup(
    caseId: string,
  ): Promise<ServiceResult<BootstrapCleanupObligationSummary[]>> {
    if (!isNativeSurface()) return demoResult([]);
    return nativeResult(await invoke<BootstrapCleanupObligationSummary[]>(
      COMMANDS.listProviderBootstrapCleanup,
      { caseId },
    ));
  },

  async startDiscovery(caseId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.startDiscovery,
      { caseId },
      serviceText("The case is now finding assets.", "案件已開始尋找資產。"),
      serviceText("Open the desktop app to inventory this source.", "請開啟桌面版盤點這個來源。"),
    );
  },

  async cancelDiscovery(caseId: string): Promise<ServiceResult<boolean>> {
    if (!isNativeSurface()) return demoResult(false, serviceText(
      "Open the desktop app to manage inventory work.",
      "請開啟桌面版管理盤點工作。",
    ));
    return nativeResult(await invoke<boolean>(COMMANDS.cancelDiscovery, { caseId }));
  },

  async chooseExternalScannerReport(): Promise<string | null> {
    if (!isNativeSurface()) return null;
    const selected = await open({ title: serviceText("Choose Strix vulnerabilities.json", "選擇 Strix vulnerabilities.json"),
      multiple: false, directory: false, filters: [{ name: "Strix JSON report", extensions: ["json"] }] });
    return typeof selected === "string" ? selected : null;
  },

  async previewExternalScannerImport(reportPath: string): Promise<ExternalScannerImportPreview> {
    if (!isNativeSurface()) throw new Error("Open the desktop app to import scanner results.");
    return invoke<ExternalScannerImportPreview>(COMMANDS.previewExternalScannerImport, { reportPath });
  },

  async importExternalScannerReports(caseId: string, requests: ExternalScannerImportRequest[]): Promise<ServiceResult<ActionResponse>> {
    return actionResult(COMMANDS.importExternalScannerReports, { caseId, requests },
      serviceText("Imported scanner results are ready in Results.", "匯入結果已整理至結果頁。"),
      serviceText("Open the desktop app to import scanner results.", "請開啟桌面版匯入掃描結果。"), true);
  },

  async chooseSourceSnapshot(): Promise<string | null> {
    if (!isNativeSurface()) return null;
    const selected = await open({
      title: serviceText("Choose a source JSON snapshot", "選擇一份來源 JSON 快照"),
      multiple: false,
      directory: false,
      filters: [{ name: "JSON snapshot", extensions: ["json"] }],
    });
    return typeof selected === "string" ? selected : null;
  },

  async connectSourceSnapshot(input: ConnectSourceSnapshotInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.connectSourceSnapshot,
      { ...input },
      serviceText(
        "The source snapshot was copied into the local case. Review its scan scope next.",
        "來源快照已複製進本機案件；下一步請檢查掃描範圍。",
      ),
      serviceText(
        "Open the desktop app to add this source snapshot.",
        "請開啟桌面版加入這份來源快照。",
      ),
    );
  },

  async chooseWorkspaceDirectory(): Promise<string | null> {
    if (!isNativeSurface()) return null;
    const selected = await open({
      title: serviceText(
        "Choose the folder to copy into a read-only scan snapshot",
        "選擇要複製成唯讀掃描快照的資料夾",
      ),
      multiple: false,
      directory: true,
    });
    return typeof selected === "string" ? selected : null;
  },

  async attachWorkspaceSnapshot(input: AttachWorkspaceSnapshotInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.attachWorkspaceSnapshot,
      { ...input },
      serviceText(
        "The bounded local snapshot is ready. Review its included checks next.",
        "有限範圍的本機快照已準備完成；下一步請檢查包含的掃描項目。",
      ),
      serviceText(
        "Open the desktop app to add this folder.",
        "請開啟桌面版加入這個資料夾。",
      ),
    );
  },

  async refreshWorkspaceSnapshot(input: RefreshWorkspaceSnapshotInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.refreshWorkspaceSnapshot,
      { ...input },
      serviceText(
        "The folder was copied again. Check fixes will read this copy.",
        "已重新複製資料夾；確認修復會讀取這份副本。",
      ),
      serviceText(
        "Open the desktop app to choose this folder again.",
        "請開啟桌面版重新選擇這個資料夾。",
      ),
    );
  },

  async selectMcpConfiguration(input: SelectMcpConfigurationInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.selectMcpConfiguration,
      { ...input },
      serviceText(
        "The selected MCP configuration is bound to the local scan.",
        "已將選定的 MCP 設定綁定到本機掃描。",
      ),
      serviceText(
        "Open the desktop app to select an MCP configuration.",
        "請開啟桌面版選擇 MCP 設定。",
      ),
      true,
    );
  },

  async selectAgenticFramework(input: SelectAgenticFrameworkInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.selectAgenticFramework,
      { ...input },
      serviceText("The AI workflow inventory selection is saved.", "已儲存 AI 工作流程盤點選項。"),
      serviceText("Open the desktop app to choose an AI workflow framework.", "請開啟桌面版選擇 AI 工作流程框架。"),
      true,
    );
  },

  async configureModelEndpoint(caseId: string, input: ModelEndpointInput, internetExposed: boolean): Promise<ServiceResult<ActionResponse>> {
    return actionResult(COMMANDS.configureModelEndpoint, { caseId, input: { endpoint: input.endpoint, model: input.model }, internetExposed },
      serviceText("Model coordinates saved for review.", "已保存模型座標，待確認掃描範圍。"),
      serviceText("Open the desktop app to configure a model check.", "請開啟桌面版設定模型檢查。"), true);
  },

  async setModelEndpointKey(caseId: string, assetId: string, key: string): Promise<ServiceResult<ActionResponse>> {
    if (!isNativeSurface()) return demoResult({ accepted: false, message: serviceText("Open the desktop app to enter a local model key.", "請開啟桌面版輸入本機模型金鑰。") });
    try {
      await invoke<void>(COMMANDS.setModelEndpointKey, { caseId, assetId, key });
      return nativeResult({ accepted: true, message: serviceText("The key is ready for one model check.", "金鑰已準備好，可用於一次模型檢查。") });
    } catch { return nativeResult({ accepted: false, message: serviceText("The local model key could not be prepared. Enter it again before starting.", "無法準備本機模型金鑰，請在開始前重新輸入。") }); }
  },

  async approveScope(input: ScopeApprovalInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.approveScope,
      {
        caseId: input.caseId,
        decisions: nativeScopeDecisions(input),
      },
      serviceText(
        "The selected target and permission boundary were recorded.",
        "已記錄選定目標與權限範圍。",
      ),
      serviceText(
        "Open the desktop app to save this scan permission.",
        "請開啟桌面版儲存這項掃描許可。",
      ),
    );
  },

  async startScan(input: StartScanInput): Promise<ServiceResult<ActionResponse>> {
    if (input.authorization && input.authorizations) {
      throw new Error("A scan request cannot mix singular and per-asset authorization inputs.");
    }
    if (input.engineIds && input.engineAssetRoutes) {
      throw new Error("A scan request cannot mix a global engine list with per-asset engine routes.");
    }
    const authorizations = input.authorizations
      ?? (input.authorization ? [input.authorization] : []);
    const decisions = authorizations.flatMap((authorization) =>
      nativeScopeDecisions({ caseId: input.caseId, ...authorization })
    );
    return actionResult(
      COMMANDS.startScan,
      {
        caseId: input.caseId,
        decisions,
        ...(input.campaignId ? { campaignId: input.campaignId } : {}),
        engineIds: input.engineIds ?? [],
        engineAssetRoutes: (input.engineAssetRoutes ?? []).map((route) => ({
          engine_id: route.engineId,
          asset_ids: [...route.assetIds],
        })),
      },
      serviceText(
        "The scan started with the saved targets and limits. Progress lists each check.",
        "掃描已使用保存的目標與限制開始；進度頁會列出每項檢查。",
      ),
      serviceText(
        "Open the desktop app to run this scan.",
        "請開啟桌面版執行這次掃描。",
      ),
      true,
    );
  },

  async startLocalhostQuickScan(
    port = DEFAULT_LOCALHOST_QUICK_SCAN_PORT,
  ): Promise<ServiceResult<ActionResponse>> {
    if (!isValidLocalhostQuickScanPort(port)) {
      const response = {
        accepted: false,
        message: serviceText(
          "Enter a whole-number local port from 1 to 65535.",
          "請輸入 1 到 65535 的整數本機連接埠。",
        ),
      };
      return isNativeSurface() ? nativeResult(response) : demoResult(response);
    }
    if (!isNativeSurface()) {
      return demoResult({
        accepted: false,
        message: serviceText(
          "Open the desktop app to run this local connection test.",
          "請開啟桌面版執行這項本機連線測試。",
        ),
      });
    }
    try {
      // The returned case contains only the product-owned localhost task, so it
      // needs no catalog context. Waiting for engine manifests here would put an
      // unrelated optional read back on the connection-utility path.
      const returnedCase = await invoke<NativeAssessmentCase>(COMMANDS.startLocalhostQuickScan, { port });
      return nativeResult({
        accepted: true,
        message: serviceText(
          "The local connection test was saved. Progress will show when the connection begins.",
          "本機連線測試已儲存；開始連線時會顯示在進度頁。",
        ),
        workspace: adaptNativeCase(returnedCase, []),
      });
    } catch (error) {
      return nativeResult({ accepted: false, message: errorMessage(error) });
    }
  },

  async updateFindingWorkflow(input: FindingWorkflowUpdateInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.updateFindingWorkflow,
      {
        caseId: input.caseId,
        request: {
          finding_id: input.findingId,
          status: input.status,
          decided_by: input.decidedBy,
          reason: input.reason,
          expires_at: input.expiresAt ?? null,
        },
      },
      serviceText(
        "The finding status was added to its history.",
        "問題狀態已加入歷程。",
      ),
      serviceText(
        "Open the desktop app to save this finding status.",
        "請開啟桌面版儲存這項問題狀態。",
      ),
    );
  },

  async groupFindings(input: FindingGroupInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.groupFindings,
      {
        caseId: input.caseId,
        request: {
          title: input.title,
          finding_ids: input.findingIds,
          rationale: input.rationale,
          grouped_by: input.groupedBy,
        },
      },
      serviceText(
        "The related findings were grouped for presentation.",
        "相關問題已建立呈現群組。",
      ),
      serviceText(
        "Open the desktop app to save this finding group.",
        "請開啟桌面版儲存這個問題群組。",
      ),
    );
  },

  async ungroupFindings(input: FindingUngroupInput): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.ungroupFindings,
      {
        caseId: input.caseId,
        request: {
          group_id: input.groupId,
          removed_by: input.removedBy,
          reason: input.reason,
        },
      },
      serviceText(
        "The presentation group was removed.",
        "呈現群組已移除。",
      ),
      serviceText("Open the desktop app to remove this finding group.", "請開啟桌面版移除這個問題群組。"),
    );
  },

  /**
   * Asks which findings from different engines look like one issue. Read-only:
   * it saves nothing and groups nothing. Acting on a suggestion is a separate
   * `groupFindings` call the user makes.
   *
   * Demo mode returns an empty report, and the caller must read `mode` before
   * treating that as "nothing is related" — the demo case was never compared.
   */
  async suggestFindingCorrelations(caseId: string): Promise<ServiceResult<CorrelationReport>> {
    if (!isNativeSurface()) {
      return demoResult({
        keyVersion: "",
        suggestions: [],
        unverifiable: [],
        truncatedSuggestions: 0,
      });
    }
    return nativeResult(await invoke<CorrelationReport>(
      COMMANDS.suggestFindingCorrelations,
      { caseId },
    ));
  },

  async pauseScan(caseId: string, runId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.pauseScan,
      { caseId, runId },
      serviceText("The selected scan was paused.", "選定的掃描已暫停。"),
      serviceText("Open the desktop app to pause this scan.", "請開啟桌面版暫停這次掃描。"),
      true,
    );
  },

  async resumeScan(caseId: string, runId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.resumeScan,
      { caseId, runId },
      serviceText("The latest saved scan state was returned.", "已傳回最新保存的掃描狀態。"),
      serviceText("Open the desktop app to continue this scan.", "請開啟桌面版繼續這次掃描。"),
      true,
    );
  },

  async cancelScan(caseId: string, runId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.cancelScan,
      { caseId, runId },
      serviceText(
        "The latest saved scan state was returned.",
        "已傳回最新保存的掃描狀態。",
      ),
      serviceText("Open the desktop app to stop this scan.", "請開啟桌面版停止這次掃描。"),
      true,
    );
  },

  async startRescan(caseId: string, baselineRunId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.startRescan,
      { caseId, baselineRunId },
      serviceText("The follow-up scan was created.", "後續確認掃描已建立。"),
      serviceText(
        "Open the desktop app to run this follow-up scan.",
        "請開啟桌面版執行這次後續確認掃描。",
      ),
      true,
    );
  },

  async archiveCase(caseId: string): Promise<ServiceResult<ActionResponse>> {
    return actionResult(
      COMMANDS.archiveCase,
      { caseId },
      serviceText(
        "The scan project was archived.",
        "掃描專案已封存。",
      ),
      serviceText("Open the desktop app to archive this scan project.", "請開啟桌面版封存這個掃描專案。"),
    );
  },

  async deleteCase(caseId: string, confirmation: string): Promise<ServiceResult<CaseDeletionResponse>> {
    if (!isNativeSurface()) {
      const deleted = deleteStoredDemoCase(caseId, confirmation);
      return demoResult({
        accepted: deleted,
        message: deleted
          ? serviceText(
            "The browser-saved preview project was removed.",
            "已移除瀏覽器儲存的預覽專案。",
          )
          : serviceText(
            "Only browser-created preview projects can be deleted here, after confirming the exact name.",
            "這裡只能在確認完整名稱後，刪除由瀏覽器建立的預覽專案。",
          ),
        databaseRecordDeleted: deleted,
        artifacts: {
          caseId,
          exactPath: "",
          exists: false,
          requiresExplicitConfirmation: false,
        },
      });
    }
    try {
      const response = await invoke<NativeCaseDeletionResult>(COMMANDS.deleteCase, { caseId, confirmation });
      const artifacts = {
        caseId: response.artifacts.case_id,
        exactPath: response.artifacts.exact_path,
        exists: response.artifacts.exists,
        requiresExplicitConfirmation: response.artifacts.requires_explicit_confirmation,
      };
      const artifactDetail = artifacts.exists
        ? serviceText(
          `The case record was deleted. Evidence remains at ${artifacts.exactPath} until you separately confirm cleanup.`,
          `案件紀錄已刪除；證據仍保留在 ${artifacts.exactPath}，必須另外確認才能清理。`,
        )
        : serviceText(
          "The case record was deleted. There is no remaining case evidence folder to clean up.",
          "案件紀錄已刪除；目前沒有需要清理的案件證據資料夾。",
        );
      return nativeResult({
        accepted: response.database_record_deleted,
        message: artifactDetail,
        databaseRecordDeleted: response.database_record_deleted,
        artifacts,
      });
    } catch (error) {
      return nativeResult({
        accepted: false,
        message: errorMessage(error),
        databaseRecordDeleted: false,
        artifacts: {
          caseId,
          exactPath: "",
          exists: false,
          requiresExplicitConfirmation: true,
        },
      });
    }
  },

  async deleteCaseArtifacts(input: CaseArtifactCleanupInput): Promise<ServiceResult<CaseArtifactCleanupResult>> {
    if (!isNativeSurface()) {
      return demoResult({ removed: false, exactPath: input.exactPath, recoverable: false });
    }
    const response = await invoke<NativeCaseArtifactCleanupResult>(COMMANDS.deleteCaseArtifacts, { ...input });
    if (response.recoverable) {
      throw new Error("The local service returned a result that violates the permanent-deletion contract.");
    }
    if (response.exact_path !== input.exactPath) {
      throw new Error("The evidence-cleanup path returned by the local service did not match the confirmed plan.");
    }
    return nativeResult({
      removed: response.removed,
      exactPath: response.exact_path,
      recoverable: false,
    });
  },

  async previewExport(
    input: ExportCaseInput,
    workspace: CaseWorkspace,
  ): Promise<ServiceResult<ExportPreview>> {
    const run = findRequestedExportRun(input, workspace);
    if (!run) throw new Error(serviceText(
      "The selected scan run is no longer available. Return to Problems found and choose a saved run again.",
      "選取的掃描紀錄已無法使用。請回到「發現的問題」並重新選擇已保存的掃描紀錄。",
    ));
    if (isNativeSurface()) {
      const preview = await invoke<NativeExportPreview>(COMMANDS.previewExport, { input });
      return nativeResult(adaptNativeExportPreview(preview));
    }
    const demoInput = normalizeDemoExportInput(input);
    const engineRuns = run.engineRuns;
    const projection = projectDemoSelectedRun(workspace, run);
    const evidence = projection.findings.flatMap((finding) => finding.evidence);
    const rawArtifactCount = engineRuns.reduce((total, engine) => total + engine.rawArtifactCount, 0);
    const rawArtifactsIncluded = 0;
    return demoResult({
      caseId: workspace.case.id,
      runId: run.id,
      locale: demoInput.locale,
      format: demoInput.format,
      redactionProfile: "none",
      includeRawEvidence: false,
      dataSourceCount: 0,
      coverageEntryCount: projection.coverage.length,
      assetCount: projection.assets.length,
      candidateAssetCount: projection.assets.filter((asset) => asset.authorizationState === "pending").length,
      canonicalFindingCount: projection.findings.length,
      selectedRunFindingCount: projection.findings.length,
      evidenceIndexCount: evidence.length,
      selectedRunEvidenceCount: evidence.length,
      scanRunCount: 1,
      selectedEngineRunCount: run.engineRuns.length,
      externalScopeGrantCount: 0,
      incompleteEngineRunCount: engineRuns.filter((engine) =>
        ["partial", "failed", "cancelled"].includes(engine.status)).length,
      notExecutedEngineRunCount: engineRuns.filter((engine) => engine.status === "not_executed").length,
      unknownSourceCount: 0,
      connectedNoAssetCount: 0,
      rawArtifactCount,
      rawArtifactsIncluded,
      rawArtifactsOmitted: rawArtifactCount - rawArtifactsIncluded,
      sensitiveRawArtifactsOmitted: 0,
      coverageManifestIncluded: false,
      sensitiveDataWarning: serviceText(
        "This selected-run-only demo preview omits mutable case-wide coverage and cross-run verification. A DEMO_ONLY_NOT_A_SCAN file is not a signed case package and contains no verifiable original evidence.",
        "這份僅限所選掃描紀錄的展示預覽，會略過可變動的案件整體涵蓋資料與跨掃描複驗。DEMO_ONLY_NOT_A_SCAN 檔不是正式案件包，也不含可驗證的原始證據。",
      ),
    });
  },

  async exportSelectedRunReport(input: {
    caseId: string;
    runIds: string[];
    locale: "en" | "zh-Hant";
    format: "html" | "json";
    redactSensitiveValues: boolean;
  }): Promise<ServiceResult<SelectedRunReportExport | null>> {
    if (!isNativeSurface()) throw new Error(serviceText(
      "Open the desktop app to combine saved scan results.",
      "請開啟桌面版整合已保存的掃描結果。",
    ));
    const destination = await save({
      title: serviceText("Save combined security report", "儲存整合資安報告"),
      defaultPath: `combined-security-report.${input.format}`,
      filters: [{ name: input.format === "html" ? "HTML report" : "JSON report", extensions: [input.format] }],
    });
    if (!destination) return nativeResult(null);
    return nativeResult(await invoke<SelectedRunReportExport>(COMMANDS.exportSelectedRunReport, {
      input: { ...input, runIds: [...input.runIds], destination },
    }));
  },

  async exportCase(input: ExportCaseInput, workspace: CaseWorkspace): Promise<ServiceResult<CaseExport | null>> {
    const run = findRequestedExportRun(input, workspace);
    if (!run) throw new Error(serviceText(
      "Selected scan run unavailable.",
      "選取的掃描紀錄無法使用。",
    ));
    if (isNativeSurface()) {
      const fileType = exportFileTypes[input.format];
      const safeName = workspace.case.name
        .normalize("NFKC")
        .replace(/[^\p{L}\p{N}-]+/gu, "-")
        .replace(/^-|-$/g, "")
        .slice(0, 80) || "assessment-case";
      const destination = await save({
        title: serviceText("Export ai-security-scanner case", "匯出 ai-security-scanner 案件"),
        defaultPath: `${safeName}-${exportRunFileIdentity(run)}.${fileType.suffix}`,
        filters: [{ name: fileType.label, extensions: fileType.extensions }],
      });
      if (!destination) return nativeResult(null);
      const exported = await invoke<NativeCaseExport>(
        COMMANDS.exportCase,
        buildNativeExportCaseArguments(input, destination),
      );
      return nativeResult(adaptNativeExport(exported));
    }

    const demoInput = normalizeDemoExportInput(input);
    const exported = createDemoExport(demoInput, workspace, run);
    downloadDemoExport(exported, workspace, demoInput, run);
    return demoResult(exported);
  },

  async verifyCaseExport(path: string): Promise<ServiceResult<CaseExportVerificationResult>> {
    if (!isNativeSurface()) return demoResult({
      outcome: "demo_unavailable",
      message: serviceText(
        "A demo file has no real local signature and cannot produce an integrity result.",
        "展示檔沒有正式本機簽章，不能視為完整性驗證結果。",
      ),
    });
    try {
      const response = await invoke<{ accepted: boolean; message?: string } | boolean>(COMMANDS.verifyCaseExport, { path });
      const accepted = typeof response === "boolean" ? response : response.accepted === true;
      return nativeResult({
        outcome: accepted ? "verified" : "native_failed",
        message: typeof response === "boolean"
          ? response
            ? serviceText("Integrity verification passed.", "完整性驗證通過。")
            : serviceText("Integrity verification failed.", "完整性驗證失敗。")
          : response.message ?? serviceText("Integrity verification finished.", "完整性驗證完成。"),
      });
    } catch (error) {
      return nativeResult({ outcome: "native_failed", message: errorMessage(error) });
    }
  },

  async chooseCaseBundle(): Promise<string | null> {
    if (!isNativeSurface()) return null;
    const selected = await open({
      title: serviceText(
        "Choose an ai-security-scanner case package to verify",
        "選擇要驗證的 ai-security-scanner 案件包",
      ),
      multiple: false,
      directory: false,
      filters: [{ name: "Signed case bundle", extensions: ["gz"] }],
    });
    return typeof selected === "string" ? selected : null;
  },

  async subscribeScanWorkspace(
    handler: (workspace: CaseWorkspace, eventName: ScannerEventName) => void,
  ): Promise<UnlistenFn> {
    if (!isNativeSurface()) return () => undefined;
    return subscribeBufferedEvents({
      eventNames: [EVENTS.runProgress, EVENTS.runFinished],
      loadContext: async () => (await getNativeManifests()).map(adaptNativeManifest),
      listen: (eventName, onEvent) =>
        listen<ScannerEventEnvelope<NativeAssessmentCase>>(eventName, (event) => onEvent(event.payload)),
      adapt: (
        event: ScannerEventEnvelope<NativeAssessmentCase>,
        manifests: EngineManifest[],
      ) => adaptNativeCase(event.payload, manifests),
      handle: handler,
    });
  },

  async subscribe(
    eventName: ScannerEventName,
    handler: (event: ScannerEventEnvelope) => void,
  ): Promise<UnlistenFn> {
    if (!isNativeSurface()) return () => undefined;
    return listen<ScannerEventEnvelope>(eventName, (event) => handler(event.payload));
  },
};

const createDemoExport = (
  input: ExportCaseInput,
  workspace: CaseWorkspace,
  run: CaseWorkspace["runs"][number],
): CaseExport => {
  const timestamp = new Date();
  const safeName = workspace.case.name
    .normalize("NFKC")
    .replace(/[^\p{L}\p{N}-]+/gu, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 80);
  return {
    id: `export-demo-${timestamp.getTime()}`,
    caseId: input.caseId,
    runId: input.runId,
    format: "json",
    createdAt: timestamp.toISOString(),
    fileName: `${safeName || "case"}-${exportRunFileIdentity(run)}-selected-run.demo.json`,
    sha256: "demo-export-has-no-cryptographic-signature",
    signatureState: "unsigned",
    includesRawEvidence: false,
    isDemo: true,
  };
};

const downloadDemoExport = (
  exported: CaseExport,
  workspace: CaseWorkspace,
  input: ExportCaseInput,
  run: CaseWorkspace["runs"][number],
): void => {
  const demoPayload = buildDemoExportPayload(workspace, input, run, getDemoNotice());
  const blob = new Blob([JSON.stringify(demoPayload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = exported.fileName;
  anchor.click();
  URL.revokeObjectURL(url);
};
