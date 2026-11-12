import type { BilingualText } from "./i18n";
import { isExplicitPreScannerInfrastructureFailure } from "./scanDiagnostics";
import { localhostTcpBeginnerSummary } from "./localhostTcpPresentation";
import { settledSkipReasonCodes } from "./settledSkippedChecks";
import type { EngineRun } from "./types";

export const catalogEngineIds = [
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
  "mcp-armor",
] as const;

export type CatalogEngineId = typeof catalogEngineIds[number];

/**
 * User-facing outcomes intentionally describe what somebody learns, not which
 * implementation produced it. Scanner identities stay in technical details.
 */
export const engineOutcomeCopy = {
  cloudquery: { en: "Cloud assets and services", zhTW: "雲端資產與服務" },
  steampipe: { en: "AWS IAM user inventory", zhTW: "AWS IAM 使用者盤點" },
  prowler: { en: "Cloud account security settings", zhTW: "雲端帳號安全設定" },
  scoutsuite: { en: "Cloud configuration risks", zhTW: "雲端設定風險" },
  cloudsplaining: { en: "Excessive cloud permissions", zhTW: "過大的雲端權限" },
  scubagear: { en: "Microsoft 365 security settings", zhTW: "Microsoft 365 安全設定" },
  maester: { en: "Microsoft 365 identity protection", zhTW: "Microsoft 365 身分保護" },
  naabu: { en: "Open network ports", zhTW: "開放的網路連接埠" },
  httpx: { en: "Reachable websites and services", zhTW: "可連線的網站與服務" },
  nuclei: { en: "Known website and service weaknesses", zhTW: "網站與服務的已知弱點" },
  greenbone: { en: "Network and system vulnerabilities", zhTW: "網路與系統弱點" },
  semgrep: { en: "Risky code patterns", zhTW: "程式碼中的危險寫法" },
  gitleaks: { en: "Exposed secrets in code", zhTW: "程式碼中暴露的秘密" },
  trufflehog: { en: "Exposed credentials and secrets", zhTW: "外洩的憑證與機密資料" },
  checkov: { en: "Risky infrastructure settings", zhTW: "基礎設施設定風險" },
  kics: { en: "Infrastructure-code mistakes", zhTW: "基礎設施程式碼錯誤" },
  trivy: { en: "Known package vulnerabilities", zhTW: "套件中的已知弱點" },
  grype: { en: "Known software vulnerabilities", zhTW: "軟體中的已知弱點" },
  syft: { en: "Software ingredients", zhTW: "軟體包含的元件" },
  kubescape: { en: "Kubernetes workload risks", zhTW: "Kubernetes 工作負載風險" },
  "kube-bench": { en: "Kubernetes hardening settings", zhTW: "Kubernetes 強化設定" },
  "mcp-armor": { en: "MCP configuration risks", zhTW: "MCP 設定風險" },
} as const satisfies Record<CatalogEngineId, BilingualText>;

const fallbackOutcome: BilingualText = {
  en: "Security check result",
  zhTW: "安全檢查結果",
};

const nextStepCopy = {
  waiting: {
    en: "This check is queued.",
    zhTW: "這項檢查已排入佇列。",
  },
  running: {
    en: "This check is running now.",
    zhTW: "這項檢查正在執行。",
  },
  paused: {
    en: "Select Continue unfinished work.",
    zhTW: "請選擇「繼續未完成的工作」。",
  },
  completedWithFindings: {
    en: "Review the problems found and start with the highest priority.",
    zhTW: "查看找到的問題，先處理優先順序最高的項目。",
  },
  completedClear: {
    en: "Continue with the other checks.",
    zhTW: "請繼續查看其他檢查。",
  },
  partial: {
    en: "Open the completed results, then continue this scan to finish the check.",
    zhTW: "請開啟已完成結果，再繼續掃描以完成這項檢查。",
  },
  boundedRetriesComplete: {
    en: "Open the completed results and untested items. Start a new scan to retry the remaining work.",
    zhTW: "請開啟已完成結果與未測試項目；開始新的掃描以重試剩餘工作。",
  },
  cancelledWithResults: {
    en: "Open the results captured before the stop. Start a new scan for the remaining items.",
    zhTW: "請開啟停止前擷取的結果；開始新的掃描以檢查剩餘項目。",
  },
  interrupted: {
    en: "Continue the original scan from its saved checkpoint.",
    zhTW: "從已保存的檢查點繼續原本的掃描。",
  },
  providerBusy: {
    en: "Provider rate limit reached. Continue this scan from its saved checkpoint.",
    zhTW: "雲端服務已達速率上限；從已保存的檢查點繼續這次掃描。",
  },
  targetSetup: {
    en: "Return to scan setup, choose the intended target, and confirm it once.",
    zhTW: "回到掃描設定，選擇正確目標並確認一次。",
  },
  toolSetup: {
    en: "Retry this check; scan-tool setup is automatic.",
    zhTW: "重試這項檢查；掃描工具會自動準備。",
  },
  executionStoppedWithResults: {
    en: "This check saved partial results before it stopped. Retry it to complete the missing work.",
    zhTW: "這項檢查在停止前已保存部分結果；請重試以完成缺少的工作。",
  },
  executionStopped: {
    en: "This check began but did not finish. Retry it; its error code is under Technical status and errors.",
    zhTW: "這項檢查已開始但沒有完成；請重試，錯誤代碼位於「技術狀態與錯誤」。",
  },
  executionUnknown: {
    en: "This check stopped. Retry it; its error code is under Technical status and errors.",
    zhTW: "這項檢查已停止；請重試，錯誤代碼位於「技術狀態與錯誤」。",
  },
  cleanupPending: {
    en: "Finish cleanup, then retry this check.",
    zhTW: "完成清理後，再重試這項檢查。",
  },
  providerSetup: {
    en: "Return to scan setup and reconnect or review the cloud account.",
    zhTW: "請回到掃描設定，重新連接或檢查雲端帳號。",
  },
  gatewayPreparation: {
    en: "Retry this check; private connection setup is automatic.",
    zhTW: "重試這項檢查；專用連線會自動準備。",
  },
  unavailableInRelease: {
    en: "This version of the app does not include this check.",
    zhTW: "這個版本的應用程式沒有提供這項檢查。",
  },
  releaseIncompatible: {
    en: "Start a new scan to run this check with the installed release.",
    zhTW: "請開始新的掃描，以目前安裝的版本執行這項檢查。",
  },
  savedPlanUnavailable: {
    en: "Start a new scan for this check.",
    zhTW: "請為這項檢查開始新的掃描。",
  },
  cleanupIdentityUnavailable: {
    en: "Start a new scan for fresh results.",
    zhTW: "請開始新的掃描取得新結果。",
  },
  mixedSkippedSetup: {
    en: "Finish the displayed target or cloud step, then retry the unfinished checks.",
    zhTW: "完成畫面上的目標或雲端步驟，再重試未完成的檢查。",
  },
  settledSkipped: {
    en: "These checks do not apply to this project or are not included in this version of the app.",
    zhTW: "這些檢查不適用於這個專案，或這個版本的應用程式沒有提供。",
  },
  skippedUnknown: {
    en: "Open the technical records for the skipped checks, finish the indicated setup, then start a new scan.",
    zhTW: "請展開未執行檢查的技術紀錄，完成其中指出的設定，再開始新的掃描。",
  },
  mcpConfigurationAbsent: {
    en: "This project has no MCP configuration to check. Continue with the other checks.",
    zhTW: "這個專案沒有可檢查的 MCP 設定；請繼續查看其他檢查。",
  },
  mcpConfigurationChoice: {
    en: "Return to scan setup and choose which MCP configuration to check.",
    zhTW: "回到掃描設定，選擇要檢查的 MCP 設定。",
  },
  agenticFrameworkChoice: {
    en: "Return to scan setup and choose the AI workflow framework for inventory.",
    zhTW: "回到掃描設定，選擇要盤點的 AI 工作流程框架。",
  },
  mcpConfigurationDiscoveryIncomplete: {
    en: "MCP configuration discovery did not finish. Continue with the other checks.",
    zhTW: "MCP 設定探索未完成；請繼續查看其他檢查。",
  },
  approvedScopeMismatch: {
    en: "Open the skipped check's technical records and match this check to the approved protocol or target form.",
    zhTW: "請展開未執行檢查的技術紀錄，讓這項檢查符合已核准的通訊協定或目標形式。",
  },
  retry: {
    en: "Retry this check. Its error code and scanner message are under Technical status and errors.",
    zhTW: "請重試這項檢查；錯誤代碼與掃描工具訊息位於「技術狀態與錯誤」。",
  },
  cancelled: {
    en: "Start a new scan to run this check again.",
    zhTW: "開始新的掃描，再次執行這項檢查。",
  },
  cancelledRetry: {
    en: "Retry this check to complete the missing coverage.",
    zhTW: "重新執行這項檢查以完成缺少的涵蓋範圍。",
  },
  hostDidNotRespond: {
    en: "Confirm the host is powered on and reachable from this computer on the approved ports, then run this check again.",
    zhTW: "請確認這台主機已開機，且本機能連到已核准的連接埠，然後再執行一次這項檢查。",
  },
  noServiceIdentified: {
    en: "If this host serves a web page, add its full address as a website, then start a new scan.",
    zhTW: "如果這台主機提供網頁，請把它的完整網址加入為網站，然後開始新的掃描。",
  },
  retryMissingWork: {
    en: "Retry this check to complete the missing work.",
    zhTW: "重新執行這項檢查以完成缺少的工作。",
  },
} as const satisfies Record<string, BilingualText>;

const targetSetupErrorCodes = new Set([
  "no_compatible_authorized_assets",
  "no_effective_scope_grants",
  "no_ownership_confirmed_targets",
  "no_compatible_authorized_targets",
  "workspace_snapshot_unavailable",
]);

const mcpConfigurationAbsentErrorCodes = new Set([
  "mcp_configuration_absent",
]);

const mcpConfigurationChoiceErrorCodes = new Set([
  "mcp_configuration_unselected",
]);

const mcpConfigurationDiscoveryErrorCodes = new Set([
  "mcp_configuration_discovery_incomplete",
]);

const approvedScopeMismatchErrorCodes = new Set([
  "direct_network_protocol_mismatch",
  "direct_network_target_kind_mismatch",
  "external_scope_missing",
  "authorization_reference_empty",
]);

const providerSetupErrorCodes = new Set([
  "provider_connection_required",
  "provider_capability_required",
  "provider_review_required",
  "provider_source_required",
  "provider_capability_unavailable",
  "provider_source_ambiguous",
  "provider_authorization_binding_mismatch",
  "provider_target_binding_mismatch",
  "provider_preflight_unavailable",
]);

const toolSetupErrorCodes = new Set([
  "manifest_unavailable",
  "adapter_unavailable",
  "adapter_version_mismatch",
  "runtime_image_unavailable",
  "runtime_image_unpinned",
  "command_unavailable",
  "external_executable_unsupported",
  "engine_execution_contract_invalid",
]);

const releaseUnavailableErrorCodes = new Set([
  "engine_release_unavailable",
  "engine_deprecated",
  "research_only",
  "license_review",
]);

/** Plain-language name of a check, by engine id, for surfaces that name a check before it runs. */
export const engineOutcomeForId = (engineId: string): BilingualText =>
  engineOutcomeCopy[engineId as CatalogEngineId] ?? fallbackOutcome;

export const engineOutcomeFor = (engine: EngineRun): BilingualText =>
  localhostTcpBeginnerSummary(engine)?.title ?? engineOutcomeForId(engine.engineId);

export const skippedChecksNextStepFor = (reasonCodes: readonly string[]): BilingualText => {
  const hasTargetIssue = reasonCodes.some((code) => targetSetupErrorCodes.has(code));
  const hasProviderIssue = reasonCodes.some((code) => providerSetupErrorCodes.has(code));
  const hasToolIssue = reasonCodes.some((code) => toolSetupErrorCodes.has(code));
  const hasReleaseIssue = reasonCodes.some((code) => releaseUnavailableErrorCodes.has(code));
  const hasApprovedScopeIssue = reasonCodes.some((code) => approvedScopeMismatchErrorCodes.has(code));
  const hasMcpAbsent = reasonCodes.some((code) => mcpConfigurationAbsentErrorCodes.has(code));
  const hasMcpChoice = reasonCodes.some((code) => mcpConfigurationChoiceErrorCodes.has(code));
  const hasAgenticChoice = reasonCodes.includes("agentic_framework_unselected");
  const hasMcpDiscoveryIssue = reasonCodes.some((code) => mcpConfigurationDiscoveryErrorCodes.has(code));
  const knownCount = Number(hasTargetIssue) + Number(hasProviderIssue) + Number(hasToolIssue) + Number(hasReleaseIssue) + Number(hasApprovedScopeIssue) + Number(hasMcpAbsent) + Number(hasMcpChoice) + Number(hasMcpDiscoveryIssue) + Number(hasAgenticChoice);

  if (knownCount > 1) {
    return reasonCodes.every((code) => settledSkipReasonCodes.has(code))
      ? nextStepCopy.settledSkipped
      : nextStepCopy.mixedSkippedSetup;
  }
  if (hasTargetIssue) return nextStepCopy.targetSetup;
  if (hasProviderIssue) return nextStepCopy.providerSetup;
  if (hasToolIssue) return nextStepCopy.toolSetup;
  if (hasReleaseIssue) return nextStepCopy.unavailableInRelease;
  if (hasApprovedScopeIssue) return nextStepCopy.approvedScopeMismatch;
  if (hasMcpAbsent) return nextStepCopy.mcpConfigurationAbsent;
  if (hasMcpChoice) return nextStepCopy.mcpConfigurationChoice;
  if (hasAgenticChoice) return nextStepCopy.agenticFrameworkChoice;
  if (hasMcpDiscoveryIssue) return nextStepCopy.mcpConfigurationDiscoveryIncomplete;
  return nextStepCopy.skippedUnknown;
};

const recoveryCopy = {
  restart_check: {
    en: "Retry this check from the beginning",
    zhTW: "從頭重試這項檢查",
  },
  continue_saved_results: {
    en: "Continue from saved results",
    zhTW: "從已保存的結果繼續",
  },
  finish_cleanup: {
    en: "Finish cleanup, then retry",
    zhTW: "完成清理後再重試",
  },
} as const satisfies Record<Exclude<NonNullable<EngineRun["recoveryAction"]>, "none">, BilingualText>;

/** A recorded dead host means the authorized target never answered, so no vulnerability test ran for it. */
const engineHostDidNotRespond = (engine: EngineRun): boolean =>
  (engine.status === "completed" || engine.status === "partial")
  && (engine.unevaluatedTargets?.some((target) => target.cause === "target_did_not_respond") ?? false);

/** No service identified on any approved port means none of the host's vulnerability checks ran; a retry would repeat that. */
const engineIdentifiedNoService = (engine: EngineRun): boolean =>
  (engine.status === "completed" || engine.status === "partial")
  && (engine.unevaluatedTargets?.some((target) => target.cause === "no_service_identified") ?? false);

/** A recorded unevaluated target means some authorized work has no result, whatever the check's own status says. */
export const engineRecordedUnevaluatedTarget = (engine: EngineRun): boolean =>
  (engine.status === "completed" || engine.status === "partial")
  && (engine.unevaluatedTargets?.some((target) => target.cause !== "unknown") ?? false);

export const engineNextStepFor = (engine: EngineRun): BilingualText => {
  const localhostSummary = localhostTcpBeginnerSummary(engine);
  if (localhostSummary) return localhostSummary.nextStep;
  if (engineHostDidNotRespond(engine)) return nextStepCopy.hostDidNotRespond;
  if (engineIdentifiedNoService(engine)) return nextStepCopy.noServiceIdentified;
  if (engineRecordedUnevaluatedTarget(engine)) return nextStepCopy.retryMissingWork;
  if (engine.status === "completed") {
    return engine.findingCount > 0
      ? nextStepCopy.completedWithFindings
      : nextStepCopy.completedClear;
  }
  if (engine.phase === "interrupted_restart" || engine.errorCode === "desktop_process_restarted") {
    return nextStepCopy.interrupted;
  }
  if (engine.failureKind === "gateway_preparation_failed") return nextStepCopy.gatewayPreparation;
  if (engine.errorCode === "provider_rate_limited") return nextStepCopy.providerBusy;
  if (engine.errorCode === "resume_release_incompatible") return nextStepCopy.releaseIncompatible;
  if (engine.errorCode === "resume_work_plan_invalid") return nextStepCopy.savedPlanUnavailable;
  if (engine.errorCode === "runtime_cleanup_identity_unavailable") {
    return nextStepCopy.cleanupIdentityUnavailable;
  }
  if (engine.errorCode === "coverage_incomplete_after_bounded_retries") {
    return nextStepCopy.boundedRetriesComplete;
  }
  if (engine.errorCode === "cancelled_after_partial_results") {
    return nextStepCopy.cancelledWithResults;
  }
  if (engine.status === "partial") return nextStepCopy.partial;
  if (targetSetupErrorCodes.has(engine.errorCode ?? "")) return nextStepCopy.targetSetup;
  if (providerSetupErrorCodes.has(engine.errorCode ?? "")) return nextStepCopy.providerSetup;

  switch (engine.status) {
    case "pending":
      return nextStepCopy.waiting;
    case "running":
      return nextStepCopy.running;
    case "paused": {
      const recovery = engine.recoveryAction ?? (engine.resumable ? "continue_saved_results" : "none");
      if (recovery === "restart_check") return recoveryCopy.restart_check;
      if (recovery === "continue_saved_results") return recoveryCopy.continue_saved_results;
      if (recovery === "finish_cleanup") return recoveryCopy.finish_cleanup;
      return nextStepCopy.paused;
    }
    case "not_executed":
      return skippedChecksNextStepFor(engine.errorCode ? [engine.errorCode] : []);
    case "cancelled": {
      const recovery = engine.recoveryAction ?? (engine.resumable ? "continue_saved_results" : "none");
      if (recovery === "restart_check") return nextStepCopy.cancelledRetry;
      if (recovery === "continue_saved_results") return recoveryCopy.continue_saved_results;
      if (recovery === "finish_cleanup") return recoveryCopy.finish_cleanup;
      return nextStepCopy.cancelled;
    }
    case "failed": {
      if (engine.errorCode === "runtime_cleanup_pending") return nextStepCopy.cleanupPending;
      if (engine.errorCode === "execution_failed") {
        if (isExplicitPreScannerInfrastructureFailure(engine)) return nextStepCopy.toolSetup;
        if (engine.savedResultArtifactCount > 0 || engine.findingCount > 0) {
          return nextStepCopy.executionStoppedWithResults;
        }
        if (engine.checkpoint?.scopeBound || engine.runtimeProvider || engine.exitCode !== undefined) {
          return nextStepCopy.executionStopped;
        }
        return nextStepCopy.executionUnknown;
      }
      if (toolSetupErrorCodes.has(engine.errorCode ?? "")) return nextStepCopy.toolSetup;
      if (releaseUnavailableErrorCodes.has(engine.errorCode ?? "")) return nextStepCopy.unavailableInRelease;
      return nextStepCopy.retry;
    }
  }
};

const recoveryModeCopy = {
  restart_check: {
    en: "Retrying starts this check over",
    zhTW: "重試時會從頭執行這項檢查",
  },
  continue_saved_results: {
    en: "Continuing picks up from its saved results",
    zhTW: "繼續時會從已保存的結果接著做",
  },
  finish_cleanup: {
    en: "Cleanup finishes before it runs again",
    zhTW: "再次執行前會先完成清理",
  },
} as const satisfies Record<Exclude<NonNullable<EngineRun["recoveryAction"]>, "none">, BilingualText>;

/**
 * Describes what the on-screen retry control will do for this check. Show it
 * only where that control renders (`canResume`).
 */
export const engineRecoveryModeFor = (engine: EngineRun): BilingualText | undefined => {
  const action = engine.recoveryAction ?? (engine.resumable ? "continue_saved_results" : "none");
  return action === "none" ? undefined : recoveryModeCopy[action];
};
