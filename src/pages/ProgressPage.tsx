import { useEffect, useMemo, useRef, useState } from "react";

import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, PageHeader, ProgressBar } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";
import { useI18n, type BilingualText } from "../i18n";
import { primaryScanTiming } from "../primaryScanTiming";
import { engineStatusMeta, executionStageMeta, runStatusMeta } from "../lib";
import {
  isExactBuiltInLocalhostQuickScanRun,
  isLocalhostQuickScanCancelRequested,
  isTerminalExactBuiltInLocalhostQuickScanRun,
} from "../localhostQuickScan";
import {
  localhostTcpBeginnerSummary,
  needsFreshLocalhostTcpAttempt,
} from "../localhostTcpPresentation";
import { scannerVersionLabel } from "../scannerVersionPresentation";
import { scanRequestOutcomeBeginnerSummary } from "../scanRequestOutcomePresentation";
import { scanRunIdentityPresentation } from "../scanRunIdentityPresentation";
import { scanRunOverallProgress } from "../scanRunProgress";
import {
  buildScanActivity,
  type ScanActivityEvent,
  type ScanActivityState,
} from "../scanActivity";
import {
  blockedRunSummary,
  buildReadinessDiagnostic,
  buildScanDiagnostic,
  sharedInfrastructureFailureSummary,
  skippedEngineRunSummary,
  type ScanDiagnosticContext,
} from "../scanDiagnostics";
import {
  engineNextStepFor,
  engineOutcomeFor,
  engineRecordedUnevaluatedTarget,
  engineRecoveryModeFor,
  skippedChecksNextStepFor,
} from "../scanPresentation";
import { isCapturedEvidenceBlocker, isProviderConfigurationBlocker } from "../scanReadiness";
import { isSettledSkippedCheck } from "../settledSkippedChecks";
import {
  canStartPreparedScan,
  findRunCreatedAfterStart,
  hasActiveScanWork,
  isNeverStartedScanRun,
  isUndispatchedScanPlan,
} from "../freshScanSelection";
import type { UseCaseId } from "../useCases";
import type { TerminalRunPage } from "../pageNavigation";
import type {
  Asset,
  BeginnerMasterReport,
  EngineRun,
  EngineRunStatus,
  ExecutionStage,
  Finding,
  ScanReadiness,
  ScanReadinessBlocker,
  ScanRun,
} from "../types";
import "./page-technical-details.css";
import { displayTechnicalDetail } from "./pageTechnicalDetails";
import { localizedEngineWarning } from "../engineWarningPresentation.ts";

interface ProgressPageProps {
  caseId?: string;
  assessmentIntent?: UseCaseId;
  assets: Asset[];
  report?: BeginnerMasterReport;
  runs: ScanRun[];
  findings: Finding[];
  selectedRunId?: string;
  requestedTerminalPage?: TerminalRunPage;
  terminalPageRequestCount?: number;
  readiness?: ScanReadiness;
  readinessCheckFailed?: boolean;
  diagnosticContext?: ScanDiagnosticContext;
  busy?: boolean;
  starting?: boolean;
  retryingLocalhostQuickScan?: boolean;
  onStart: () => Promise<void>;
  onRetryLocalhostQuickScan: (port: number) => Promise<void>;
  onFixSetup: () => void;
  onPause: (runId: string) => Promise<void>;
  onResume: (runId: string) => Promise<void>;
  onCancel: (runId: string) => Promise<void>;
  onSelectRun?: (runId: string) => void;
}

const PRODUCT_RELEASES = "https://github.com/TED-H-com/ai-security-scanner/releases";
const installerBlockers = new Set<ScanReadinessBlocker>([
  "no_runnable_authorized_targets",
  "egress_gateway_unavailable",
  "engine_execution_contract_invalid",
]);

const copy = {
  eyebrow: { en: "LIVE SCAN", zhTW: "即時掃描" },
  title: { en: "Follow your scan", zhTW: "掌握掃描進度" },
  description: {
    en: "See the current status and next action.",
    zhTW: "查看目前狀態與下一步。",
  },
  readinessDetails: { en: "Readiness details", zhTW: "準備狀態細節" },
  activityHistory: { en: "Activity history ({count})", zhTW: "活動記錄（{count}）" },
  runHistorySummary: { en: "Run history ({count})", zhTW: "掃描歷程（{count}）" },
  emptyTitle: { en: "No scans for this project", zhTW: "這個專案沒有掃描" },
  emptyDescription: {
    en: "Start the scan to follow every check here.",
    zhTW: "開始掃描後，即可在這裡查看每項檢查。",
  },
  startingTitle: { en: "Starting your scan…", zhTW: "正在開始掃描…" },
  startingDescription: {
    en: "Validating the saved target and permissions, then creating the scan.",
    zhTW: "正在驗證已保存的目標與許可，接著建立掃描。",
  },
  startingAction: { en: "Starting scan…", zhTW: "正在開始掃描…" },
  startingActivityTitle: { en: "Preparing the new scan", zhTW: "正在準備新的掃描" },
  startingActivityDescription: {
    en: "Creating the scan record.",
    zhTW: "正在建立掃描紀錄。",
  },
  startingNewTitle: { en: "Starting a new scan…", zhTW: "正在開始新的掃描…" },
  startingNewDescription: {
    en: "Validating the saved target and creating the new scan.",
    zhTW: "正在驗證已保存的目標並建立新的掃描。",
  },
  start: { en: "Start scan", zhTW: "開始掃描" },
  reconnectToScanAgain: { en: "Reconnect to scan again", zhTW: "重新連接後再掃描" },
  viewResults: { en: "View results", zhTW: "查看結果" },
  resultsWaitingTitle: { en: "Results are not open yet", zhTW: "「結果」尚未開啟" },
  exportWaitingTitle: { en: "Export is not open yet", zhTW: "「匯出」尚未開啟" },
  resultsWaitingDescription: {
    en: "This scan has not finished. Results open automatically when it reaches an outcome.",
    zhTW: "這輪掃描尚未完成；掃描有最終結果後會自動開啟「結果」。",
  },
  exportWaitingDescription: {
    en: "This scan has not finished. Export opens automatically when it reaches an outcome.",
    zhTW: "這輪掃描尚未完成；掃描有最終結果後會自動開啟「匯出」。",
  },
  startFreshScan: { en: "Start a new scan for fresh results", zhTW: "開始新的掃描取得新結果" },
  retryLocalhostQuickScan: { en: "Run this check again", zhTW: "重新執行這項檢查" },
  retryingLocalhostQuickScan: { en: "Starting a new attempt…", zhTW: "正在開始新的嘗試…" },
  retryLocalhostQuickScanTitle: {
    en: "Run another local connection test",
    zhTW: "再次執行本機連線測試",
  },
  retryLocalhostQuickScanDescription: {
    en: "Create a new connection-test attempt for 127.0.0.1:{port}.",
    zhTW: "為 127.0.0.1:{port} 建立新的連線測試嘗試。",
  },
  releaseIncompatibleTitle: {
    en: "Some saved checks need a new scan",
    zhTW: "部分已保存的檢查需要新的掃描",
  },
  releaseIncompatibleBody: {
    en: "These checks were created by a different app release. Start a new scan to run them with this release.",
    zhTW: "這些檢查由不同版本建立；請開始新的掃描，以目前版本執行。",
  },
  releaseIncompatibleActiveBody: {
    en: "Compatible checks continue in this run. Different-release checks require a new scan.",
    zhTW: "相容的檢查繼續在這一輪執行；不同版本的檢查需要新的掃描。",
  },
  releaseIncompatibleNotReadyBody: {
    en: "Readiness step required below. Different-release checks require a new scan.",
    zhTW: "需要完成下方的準備步驟；不同版本的檢查需要新的掃描。",
  },
  undispatchedPlanTitle: {
    en: "A scan plan is waiting and nothing is running",
    zhTW: "掃描計畫正在等候，目前沒有掃描在執行",
  },
  undispatchedPlanDescription: {
    en: "No scanner has started.",
    zhTW: "掃描工具尚未啟動。",
  },
  undispatchedPlanCancel: { en: "Cancel this plan", zhTW: "取消這份計畫" },
  checkingReady: { en: "Checking what is ready…", zhTW: "正在確認可以執行的檢查…" },
  readinessUnavailableTitle: { en: "Scan readiness unavailable", zhTW: "掃描準備狀態無法取得" },
  readinessUnavailableDescription: {
    en: "Check readiness again.",
    zhTW: "請重新檢查準備狀態。",
  },
  finishSetup: { en: "Finish scan setup", zhTW: "完成掃描設定" },
  setupTools: { en: "Set up scan tools for me", zhTW: "幫我準備掃描工具" },
  connectCloud: { en: "Connect cloud account", zhTW: "連接雲端帳號" },
  reconnectCloud: { en: "Reconnect account", zhTW: "重新連接帳號" },
  chooseConnection: { en: "Choose connection", zhTW: "選擇連線" },
  reviewConnection: { en: "Review connection", zhTW: "檢查連線" },
  reviewTarget: { en: "Review target", zhTW: "檢查目標" },
  chooseLocalInputAgain: { en: "Choose local input again", zhTW: "重新選擇本機輸入" },
  reconnectReadOnlySource: { en: "Reconnect read-only source", zhTW: "重新連接唯讀來源" },
  getLatestInstaller: { en: "Get the latest installer", zhTW: "取得最新安裝程式" },
  checkAgain: { en: "Check again", zhTW: "重新檢查" },
  chooseProject: { en: "Choose a scan project", zhTW: "選擇掃描專案" },
  runtimeEmptyTitle: { en: "One quick setup, then scan", zhTW: "先完成一次設定，就可以開始掃描" },
  runtimeEmptyDescription: {
    en: "Your target is ready. Let ai-security-scanner prepare its private scan tools on this computer.",
    zhTW: "目標已經準備好。讓 ai-security-scanner 在這台電腦上自動準備專用掃描工具。",
  },
  providerSourceTitle: { en: "Connect the cloud account you want to scan", zhTW: "請先連接你要掃描的雲端帳號" },
  providerSourceDescription: {
    en: "Choose the exact account, then return here to start the scan.",
    zhTW: "請選擇正確的帳號，再回到這裡開始掃描。",
  },
  providerCapabilityTitle: { en: "Your read-only connection is no longer available", zhTW: "唯讀連線已失效" },
  providerCapabilityDescription: {
    en: "Reconnect the same account, then return here to start the scan.",
    zhTW: "請重新連接同一個帳號，再回到這裡開始掃描。",
  },
  providerAmbiguousTitle: { en: "Choose the right cloud connection", zhTW: "請選擇正確的雲端連線" },
  providerAmbiguousDescription: {
    en: "More than one saved connection matches. Choose the exact one, then return here to start the scan.",
    zhTW: "有多個已保存的連線可能符合；請選擇正確的連線，再回到這裡開始掃描。",
  },
  providerAuthorizationTitle: { en: "Review this cloud connection", zhTW: "請檢查這個雲端連線" },
  providerAuthorizationDescription: {
    en: "The saved read-only access does not match the selected connection. Choose the matching connection.",
    zhTW: "已保存的唯讀權限與所選連線不一致；請選擇相符的連線。",
  },
  providerTargetTitle: { en: "Review the cloud target", zhTW: "請檢查雲端目標" },
  providerTargetDescription: {
    en: "The connected account does not match this scan target. Choose the intended target before scanning.",
    zhTW: "已連接的帳號與這次掃描目標不一致；請先選擇正確目標。",
  },
  providerCheckTitle: { en: "Check cloud readiness again", zhTW: "重新檢查雲端準備狀態" },
  providerCheckDescription: {
    en: "Cloud readiness check stopped.",
    zhTW: "雲端準備狀態檢查已停止。",
  },
  workspaceSnapshotTitle: { en: "Choose the local files again", zhTW: "請重新選擇本機檔案" },
  workspaceSnapshotDescription: {
    en: "The saved private copy is missing or changed. Choose the local project again before scanning.",
    zhTW: "掃描用的本機副本已遺失或有變更；請重新選擇本機專案後再掃描。",
  },
  egressGatewayTitle: { en: "Restore one installed scan component", zhTW: "恢復一項安裝元件" },
  egressGatewayDescription: {
    en: "Reinstall the newest release to restore the private connection component.",
    zhTW: "重新安裝最新版本，以恢復專用連線元件。",
  },
  engineContractTitle: { en: "Restore one installed scan component", zhTW: "恢復一項安裝元件" },
  engineContractDescription: {
    en: "A required scan component is missing or out of date. Reinstall the newest release.",
    zhTW: "必要的掃描元件已遺失或過期；請重新安裝最新版本。",
  },
  unavailableToolsTitle: { en: "Get the scan tools for this check", zhTW: "取得這項檢查需要的掃描工具" },
  unavailableToolsDescription: {
    en: "Install the newest release to get an applicable scan tool for this target.",
    zhTW: "安裝最新版本，以取得適用於這個目標的掃描工具。",
  },
  passiveSourceTitle: { en: "Reconnect the saved data source", zhTW: "請重新連接已保存的資料來源" },
  passiveSourceDescription: {
    en: "The read-only source used by this check is missing or changed. Reconnect it before scanning.",
    zhTW: "這項檢查使用的唯讀來源已遺失或有變更；請重新連接後再掃描。",
  },
  capturedEvidenceTitle: { en: "Open the saved results", zhTW: "開啟已保存的結果" },
  capturedEvidenceDescription: {
    en: "Saved results or evidence needed to continue are missing or changed. Start a new scan for a complete result.",
    zhTW: "續跑所需的已保存結果或證據已遺失或變更；請開始新的掃描取得完整結果。",
  },
  executionCheckTitle: { en: "Check readiness again", zhTW: "重新檢查準備狀態" },
  executionCheckDescription: {
    en: "Final readiness check stopped.",
    zhTW: "最後的準備狀態檢查已停止。",
  },
  readiness: {
    demo_case: { en: "Create or open a real scan project before starting.", zhTW: "請先建立或開啟真正的掃描專案。" },
    archived_case: { en: "This scan project is archived. Choose an active project to continue.", zhTW: "這個掃描專案已封存；請選擇仍在使用的專案。" },
    scan_already_active: { en: "A scan is already running or paused for this project.", zhTW: "這個專案已有正在執行或暫停中的掃描。" },
    no_effective_scope_grants: { en: "Choose the exact target you want to check, then confirm it once.", zhTW: "請選擇這次要檢查的目標，並確認一次即可。" },
    no_ownership_confirmed_targets: { en: "Target confirmation required. Return to setup and confirm it.", zhTW: "需要確認目標；請回到設定頁確認這次要掃描的目標。" },
    no_compatible_authorized_targets: { en: "Finish target setup for the current input.", zhTW: "請完成目前輸入的目標設定。" },
    no_runnable_authorized_targets: {
      en: "Install the newest release to get an applicable scan tool for this target.",
      zhTW: "安裝最新版本，以取得適用於這個目標的掃描工具。",
    },
    runtime_unavailable: {
      en: "Prepare the scan tools, then start the scan.",
      zhTW: "準備掃描工具，接著開始掃描。",
    },
    provider_source_required: {
      en: "Choose and connect the exact cloud account to scan.",
      zhTW: "選擇並連接要掃描的正確雲端帳號。",
    },
    provider_capability_unavailable: {
      en: "The saved read-only connection has expired or is no longer available. Reconnect the same account to continue.",
      zhTW: "已保存的唯讀連線已失效或無法繼續使用。請重新連接同一個帳號。",
    },
    provider_source_ambiguous: {
      en: "More than one saved cloud connection matches this target. Choose the exact connection before scanning.",
      zhTW: "有多個已保存的雲端連線可能符合這個目標；請先選擇正確連線。",
    },
    provider_authorization_binding_mismatch: {
      en: "The saved read-only access does not match this cloud connection. Review the connection before scanning.",
      zhTW: "已保存的唯讀權限與這個雲端連線不一致；請先檢查連線。",
    },
    provider_target_binding_mismatch: {
      en: "The connected cloud account does not match this scan target. Review the target before scanning.",
      zhTW: "已連接的雲端帳號與這次掃描目標不一致；請先檢查目標。",
    },
    provider_preflight_unavailable: {
      en: "Cloud readiness check stopped. Check again.",
      zhTW: "雲端準備狀態檢查已停止；請重新檢查。",
    },
    workspace_snapshot_unavailable: {
      en: "The saved local copy is missing or changed. Choose the local project again before scanning.",
      zhTW: "掃描用的本機副本已遺失或有變更；請重新選擇本機專案後再掃描。",
    },
    egress_gateway_unavailable: {
      en: "An installed scan component is missing or changed. Reinstall the newest release.",
      zhTW: "隨附的掃描元件已遺失或變更；請重新安裝最新版本。",
    },
    engine_execution_contract_invalid: {
      en: "A required scan component is missing or out of date. Reinstall the newest release.",
      zhTW: "必要的掃描元件已遺失或過期；請重新安裝最新版本。",
    },
    passive_source_unavailable: {
      en: "The saved read-only data source is missing or changed. Reconnect it before scanning.",
      zhTW: "已保存的唯讀資料來源已遺失或有變更；請重新連接後再掃描。",
    },
    captured_evidence_unavailable: {
      en: "Saved results or evidence needed to continue are missing or changed. Start a new scan.",
      zhTW: "續跑所需的已保存結果或證據已遺失或變更；請開始新的掃描。",
    },
    execution_preflight_unavailable: {
      en: "Final readiness check stopped. Check again.",
      zhTW: "最後的準備狀態檢查已停止；請重新檢查。",
    },
  } satisfies Record<ScanReadinessBlocker, BilingualText>,
  blockedTitle: { en: "Scan did not start", zhTW: "掃描沒有開始" },
  blockedNoTargets: {
    en: "Choose the website, system, account, or files you want to check, then start a new scan.",
    zhTW: "請選擇要檢查的網站、系統、帳號或檔案，再開始新的掃描。",
  },
  blockedNoChecks: {
    en: "Open scan setup, finish the step shown there, then start a new scan.",
    zhTW: "請開啟掃描設定，完成畫面上的步驟，再開始新的掃描。",
  },
  downloadLog: { en: "Download diagnostic log", zhTW: "下載診斷紀錄" },
  skippedTechnical: { en: "Technical records — skipped checks: {count}", zhTW: "{count} 項未執行檢查的技術紀錄" },
  skippedGroupTitle: { en: "Planned checks that did not start: {count}", zhTW: "{count} 項預定檢查沒有開始" },
  sharedFailureTitle: { en: "The private scan engine did not start", zhTW: "私有掃描引擎沒有啟動" },
  sharedFailureBody: {
    en: "A private connection problem stopped {count} checks. Retry them with a new connection.",
    zhTW: "專用連線問題讓 {count} 項檢查停止；請用新的連線重試。",
  },
  retryStoppedChecks: { en: "Try stopped checks again", zhTW: "再試一次已停止的檢查" },
  aggregateTechnical: { en: "Technical records — checks: {count}", zhTW: "{count} 項檢查的技術紀錄" },
  diagnosticPrivacy: {
    en: "The diagnostic log excludes target names, asset IDs, raw evidence, paths, and scanner messages.",
    zhTW: "診斷紀錄不包含目標名稱、資產 ID、原始證據、檔案路徑或掃描工具訊息。",
  },
  activityEyebrow: { en: "SCAN ACTIVITY", zhTW: "掃描動態" },
  activityTitle: { en: "See exactly where your scan is", zhTW: "清楚看見掃描進行到哪裡" },
  activityDescription: {
    en: "Saved scan steps in time order.",
    zhTW: "依時間順序排列的已保存掃描步驟。",
  },
  currentActivity: { en: "What is happening now", zhTW: "現在正在做什麼" },
  lastProgress: { en: "Last progress update", zhTW: "最後一次進度更新" },
  delayedProgress: {
    en: "Last saved progress: {count} minutes ago.",
    zhTW: "最後保存進度：{count} 分鐘前。",
  },
  activityLog: { en: "Event log", zhTW: "事件紀錄" },
  activityLogDescription: {
    en: "Plain-language lifecycle events only. Scanner output stays in technical details.",
    zhTW: "這裡只顯示白話的執行事件；掃描工具輸出會留在技術細節中。",
  },
  downloadTechnicalLog: { en: "Download redacted technical log", zhTW: "下載已遮蔽的技術紀錄" },
  activeScanTools: { en: "Current or next scan tool", zhTW: "目前或下一個掃描工具" },
  activeScanAsset: { en: "Asset in current or next check", zhTW: "目前或下一項檢查的資產" },
  activeScanAssets: { en: "Assets in current or next check", zhTW: "目前或下一項檢查的資產" },
  noRunActivityTitle: { en: "Event log before the scan starts", zhTW: "掃描前事件紀錄" },
  noRunActivityDescription: {
    en: "Readiness-check events for this scan.",
    zhTW: "這次掃描的準備狀態檢查事件。",
  },
  readinessChecked: { en: "Readiness checked", zhTW: "已檢查掃描準備狀態" },
  scanNotStartedEvent: { en: "Scan did not start", zhTW: "掃描沒有開始" },
  lastReadinessCheck: { en: "Last readiness check", zhTW: "最後一次準備狀態檢查" },
  noReadinessTimestamp: { en: "No completed check was recorded", zhTW: "沒有已完成的檢查時間" },
  technicalPreflight: { en: "Technical preflight record", zhTW: "技術準備檢查紀錄" },
  blockerCode: { en: "Blocker code", zhTW: "阻擋代碼" },
  readinessState: { en: "Readiness state", zhTW: "準備狀態" },
  nextStepCode: { en: "Next-step code", zhTW: "下一步代碼" },
  activityStates: {
    waiting_to_start: {
      title: { en: "Next check queued", zhTW: "下一項檢查已排入佇列" },
      body: { en: "The scan is queued for an available local scan tool.", zhTW: "掃描已排入本機掃描工具的執行佇列。" },
    },
    checking_readiness: {
      title: { en: "Checking the saved target and scan tool", zhTW: "正在確認已保存的目標與掃描工具" },
      body: { en: "The app is confirming the exact inputs needed before this check runs.", zhTW: "程式正在確認這項檢查執行前所需的輸入。" },
    },
    preparing_scanner: {
      title: { en: "Preparing the scan tool", zhTW: "正在準備掃描工具" },
      body: { en: "The private scan environment is getting the verified tool ready.", zhTW: "專用掃描環境正在準備已驗證的工具。" },
    },
    scanner_working: {
      title: { en: "Scan tool running", zhTW: "掃描工具執行中" },
      body: { en: "The check is running.", zhTW: "檢查正在執行。" },
    },
    preparing_results: {
      title: { en: "Saving and organizing the results", zhTW: "正在保存並整理結果" },
      body: { en: "The check has reported back, and the app is preparing the results you can review.", zhTW: "檢查已回報，程式正在整理成可以查看的結果。" },
    },
    closing_scanner: {
      title: { en: "Closing the private scan environment", zhTW: "正在關閉專用掃描環境" },
      body: { en: "Finishing local scan-environment cleanup.", zhTW: "正在完成本機掃描環境清理。" },
    },
    paused: {
      title: { en: "This scan is paused", zhTW: "這次掃描已暫停" },
      body: { en: "Continue or cancel this scan.", zhTW: "繼續或取消這次掃描。" },
    },
    completed: {
      title: { en: "This scan has finished", zhTW: "這次掃描已完成" },
      body: { en: "The results are saved and ready to review.", zhTW: "結果已保存，可以開始查看。" },
    },
    no_checks_completed: {
      title: { en: "No checks completed", zhTW: "沒有完成任何檢查" },
      body: {
        en: "Open the saved reason and next step below.",
        zhTW: "查看下方保存的原因與下一步。",
      },
    },
    gateway_preparation_failed: {
      title: { en: "The private scan connection did not start", zhTW: "專用掃描連線未能啟動" },
      body: {
        en: "Prepare a new private connection and retry the check.",
        zhTW: "準備新的專用連線並重試檢查。",
      },
    },
    partly_completed: {
      title: { en: "This scan partly completed", zhTW: "這次掃描部分完成" },
      body: {
        en: "Results from the completed checks are saved and ready to review. Open each unfinished check and follow its next action.",
        zhTW: "已完成檢查的結果已保存，可以開始查看；請開啟每項未完成的檢查並執行下一步。",
      },
    },
    failed: {
      title: { en: "This scan failed", zhTW: "這次掃描失敗" },
      body: { en: "Open each unfinished check and follow its next action.", zhTW: "開啟每項未完成的檢查並執行下一步。" },
    },
    stopped: {
      title: { en: "This scan has stopped", zhTW: "這次掃描已停止" },
      body: { en: "Open each unfinished check and follow its next action.", zhTW: "開啟每項未完成的檢查並執行下一步。" },
    },
  } satisfies Record<ScanActivityState, { title: BilingualText; body: BilingualText }>,
  activityEvents: {
    run_requested: { en: "Scan requested", zhTW: "已提出掃描要求" },
    check_attempts_started: { en: "{count} check attempts began", zhTW: "已有 {count} 項檢查開始嘗試" },
    progress_saved: { en: "Progress recorded at {percent}%", zhTW: "已記錄 {percent}% 的進度" },
    checks_completed: { en: "{count} checks completed", zhTW: "{count} 項檢查已完成" },
    checks_failed: { en: "{count} checks stopped before completion", zhTW: "{count} 項檢查在完成前停止" },
    checks_partly_completed: { en: "{count} checks ended with unfinished work", zhTW: "{count} 項檢查結束時仍有未完成工作" },
    checks_cancelled: { en: "{count} checks were cancelled", zhTW: "{count} 項檢查已取消" },
    checks_not_started: { en: "{count} planned checks did not start", zhTW: "{count} 項預定檢查沒有開始" },
    gateway_preparation_failed: {
      en: "Private scan connection failed",
      zhTW: "專用掃描連線失敗",
    },
    run_completed: { en: "Scan completed", zhTW: "掃描已完成" },
    run_no_checks_completed: { en: "No checks completed", zhTW: "沒有完成任何檢查" },
    run_partly_completed: { en: "Scan partly completed", zhTW: "掃描部分完成" },
    run_failed: { en: "Scan failed", zhTW: "掃描失敗" },
    run_stopped: { en: "Scan stopped", zhTW: "掃描已停止" },
    run_paused: { en: "Scan paused", zhTW: "掃描已暫停" },
  },
  activityEventSingular: {
    check_attempts_started: { en: "1 check attempt began", zhTW: "1 項檢查開始嘗試" },
    checks_completed: { en: "1 check completed", zhTW: "1 項檢查已完成" },
    checks_failed: { en: "1 check stopped before completion", zhTW: "1 項檢查在完成前停止" },
    checks_partly_completed: { en: "1 check ended with unfinished work", zhTW: "1 項檢查結束時仍有未完成工作" },
    checks_cancelled: { en: "1 check was cancelled", zhTW: "1 項檢查已取消" },
    checks_not_started: { en: "1 planned check did not start", zhTW: "1 項預定檢查沒有開始" },
  },
  pause: { en: "Pause", zhTW: "暫停" },
  resume: { en: "Continue unfinished work", zhTW: "繼續未完成的工作" },
  retry: { en: "Retry stopped checks", zhTW: "重試已停止的檢查" },
  recoverMixed: { en: "Continue or retry unfinished checks", zhTW: "繼續或重試未完成的檢查" },
  cancel: { en: "Cancel this run", zhTW: "取消這一輪" },
  stopping: { en: "Stopping…", zhTW: "正在停止…" },
  pauseAria: { en: "Pause scan run {id}", zhTW: "暫停掃描輪次 {id}" },
  resumeAria: { en: "Resume scan run {id}", zhTW: "續跑掃描輪次 {id}" },
  cancelAria: { en: "Cancel scan run {id}", zhTW: "取消掃描輪次 {id}" },
  stoppingAria: { en: "Stopping scan run {id}", zhTW: "正在停止掃描輪次 {id}" },
  cancelRequestedPhase: { en: "Stopping the connection", zhTW: "正在停止連線" },
  chooseRun: { en: "Choose a scan run", zhTW: "選擇掃描輪次" },
  viewRun: { en: "View run", zhTW: "查看輪次" },
  latest: { en: "Latest · ", zhTW: "最新 · " },
  interruptedTitle: {
    en: "Your scan paused when the app closed",
    zhTW: "應用程式關閉時，掃描已暫停",
  },
  interruptedBody: {
    en: "Checks queued: {count}. Available actions: Continue or Cancel.",
    zhTW: "已排入佇列的檢查：{count} 項。可用操作：繼續或取消。",
  },
  interruptedBodyContinue: {
    en: "Checks queued: {count}. Available action: Continue.",
    zhTW: "已排入佇列的檢查：{count} 項。可用操作：繼續。",
  },
  interruptedBodyCancel: {
    en: "Checks queued: {count}. Available action: Cancel.",
    zhTW: "已排入佇列的檢查：{count} 項。可用操作：取消。",
  },
  interruptedBodyNoAction: {
    en: "Checks needing attention: {count}.",
    zhTW: "需要處理的檢查：{count} 項。",
  },
  savedPlanTitle: {
    en: "Your scan plan was saved, but no checks started",
    zhTW: "掃描計畫已保存，但沒有檢查開始執行",
  },
  savedPlanBodyContinueStart: {
    en: "Checks ready to continue: {count}. Available actions: Continue or Start a new scan.",
    zhTW: "可繼續的檢查：{count} 項。可用操作：繼續或開始新的掃描。",
  },
  savedPlanBodyContinue: {
    en: "Checks ready to continue: {count}. Available action: Continue.",
    zhTW: "可繼續的檢查：{count} 項。可用操作：繼續。",
  },
  savedPlanBodyStart: {
    en: "No checks started. Available action: Start a new scan.",
    zhTW: "沒有檢查開始執行。可用操作：開始新的掃描。",
  },
  savedPlanBodyNoAction: {
    en: "No checks started.",
    zhTW: "沒有檢查開始執行。",
  },
  resumeOriginal: { en: "Continue the original scope", zhTW: "繼續原本的範圍" },
  startNewScan: { en: "Start a new scan", zhTW: "開始新的掃描" },
  cancelKeepRecord: { en: "Cancel and keep the record", zhTW: "取消並保留紀錄" },
  runIdTitle: { en: "Local scan run ID", zhTW: "本機掃描輪次 ID" },
  processed: { en: "{percent}% processed", zhTW: "已處理 {percent}%" },
  noChecksStarted: { en: "No checks started", zhTW: "沒有檢查開始執行" },
  savedPlanReady: { en: "The saved plan is ready for your next action.", zhTW: "已保存的計畫可進行下一步。" },
  runSummary: {
    en: "Selected assets: {total} · Started {started}",
    zhTW: "已選資產：{total} · 開始於 {started}",
  },
  progressCountsAria: { en: "Asset and check progress summary", zhTW: "資產與檢查進度摘要" },
  assetProgressCounts: {
    en: "Assets · Fully checked {completed} · Remaining {remaining} · Need attention {attention}",
    zhTW: "資產 · 已完整檢查 {completed} · 尚待完成 {remaining} · 需要處理 {attention}",
  },
  checkProgressCounts: {
    en: "Checks · Completed {completed} · Remaining {remaining} · Need attention {attention}",
    zhTW: "檢查 · 已完成 {completed} · 尚待完成 {remaining} · 需要處理 {attention}",
  },
  finished: { en: " · Ended {finished}", zhTW: " · 結束於 {finished}" },
  elapsed: { en: "Elapsed {time}", zhTW: "已執行 {time}" },
  elapsedUnderMinute: { en: "under 1 min", zhTW: "未滿 1 分鐘" },
  elapsedMinutes: { en: "{count} min", zhTW: "{count} 分鐘" },
  estimateUnavailable: { en: "Estimate unavailable", zhTW: "目前無可靠預估" },
  lastSaved: { en: "Last saved {time}", zhTW: "最後保存 {time}" },
  overallProgress: { en: "Overall scan progress", zhTW: "整體掃描進度" },
  scanTechnicalDetails: { en: "Scan details and versions", zhTW: "掃描細節與版本" },
  knowledgeTitle: { en: "Scanners last updated", zhTW: "掃描工具最後更新" },
  legacyKnowledge: { en: "Not recorded per scanner in this older case", zhTW: "舊版案件未逐一記錄" },
  caseSnapshot: { en: "Case snapshot {date}", zhTW: "案件快照 {date}" },
  metricsAria: { en: "Scan outcome summary", zhTW: "掃描結果摘要" },
  completed: { en: "Completed", zhTW: "已完成" },
  completedDetail: { en: "Results are ready to review", zhTW: "結果已準備好，可以查看" },
  partial: { en: "Needs attention", zhTW: "需要處理" },
  partialDetail: { en: "A check ended before completing all work", zhTW: "有檢查在完成全部工作前結束" },
  failedCancelled: { en: "Stopped", zhTW: "已停止" },
  failedCancelledDetail: { en: "A check stopped early or was cancelled", zhTW: "有檢查提早停止或已被取消" },
  notStartedStatus: { en: "Not started", zhTW: "未開始" },
  notRun: { en: "Not run", zhTW: "未執行" },
  notRunDetail: { en: "Finish setup before running these checks", zhTW: "完成設定後，才能執行這些檢查" },
  notRunTechnical: { en: "Status: not run.", zhTW: "狀態：未執行。" },
  ledgerAria: { en: "Counts for every scanner state", zhTW: "所有掃描工具狀態數量" },
  scannerStates: { en: "Scanner states", zhTW: "掃描工具狀態" },
  terminalCount: { en: "Final outcomes: {done} of {total}", zhTW: "{done}／{total} 個已有明確最終結果" },
  incompleteTitle: { en: "This run did not cover everything", zhTW: "這一輪沒有完整涵蓋" },
  incompleteBody: {
    en: "Some checks did not finish. Open each affected check below and complete or retry it.",
    zhTW: "有些檢查沒有完成。請打開下方受影響的檢查並完成或重試。",
  },
  untestedAssetsBody: {
    en: "Some selected assets were not tested. Each affected check below names its next step.",
    zhTW: "有些已選取的資產這次沒有實際檢查到。下方每項受影響的檢查都列出了下一步。",
  },
  workEyebrow: { en: "CHECKS", zhTW: "檢查項目" },
  workTitle: { en: "Checks", zhTW: "檢查項目" },
  workDescription: {
    en: "Result, current step, and next action for each check.",
    zhTW: "每項檢查的結果、目前進度與下一步。",
  },
  workCount: { en: "{count} checks", zhTW: "{count} 項檢查" },
  workCountOne: { en: "1 check", zhTW: "1 項檢查" },
  noWorkTitle: { en: "No checks ready", zhTW: "沒有可執行的檢查" },
  noWorkDescription: {
    en: "Return to scan setup, choose the assets, and start a new scan.",
    zhTW: "回到掃描設定，選擇資產並開始新的掃描。",
  },
  noRecordedCheckTitle: { en: "No check was recorded for this attempt", zhTW: "這次嘗試沒有留下檢查項目" },
  noRecordedCheckDescription: {
    en: "Finish scan setup, then start a new scan.",
    zhTW: "完成掃描設定，再開始新的掃描。",
  },
  notStarted: { en: "This check did not start", zhTW: "這項檢查沒有開始" },
  checkProgress: { en: "Check progress", zhTW: "檢查進度" },
  currentStep: { en: "Current step: ", zhTW: "目前步驟：" },
  interruptedPhase: { en: "Stopped when the desktop app restarted", zhTW: "桌面程式重新啟動時中斷" },
  queuedResumePhase: { en: "Queued to continue", zhTW: "已排入續跑佇列" },
  unknownPhase: { en: "Scanner-reported step", zhTW: "掃描工具回報的步驟" },
  checkpoint: { en: "Saved restart point", zhTW: "已保存的接續點" },
  attempt: { en: "Attempt", zhTW: "嘗試次數" },
  evidence: { en: "Evidence", zhTW: "證據" },
  evidenceCount: { en: "Files: {count}", zhTW: "{count} 份" },
  authorizationPlan: { en: "Target and permission plan", zhTW: "目標與權限計畫" },
  authorizationFrozen: { en: "Frozen for this run", zhTW: "已為這一輪固定" },
  authorizationUnknown: { en: "Not recorded in this older run", zhTW: "這個舊輪次未記錄" },
  runtimeScope: { en: "Scanner runtime scope", zhTW: "掃描執行環境範圍" },
  runtimeScopeCreated: { en: "Created", zhTW: "已建立" },
  runtimeScopeNotReached: { en: "Not reached", zhTW: "未進行到這一步" },
  cleanup: { en: "Cleanup", zhTW: "環境清理" },
  cleanupDone: { en: "Done", zhTW: "完成" },
  cleanupPending: { en: "Pending", zhTW: "待處理" },
  legacyFindingUnknown: { en: "Problem count unavailable", zhTW: "目前無法取得問題數量" },
  findingCount: { en: "Saved results: {count}", zhTW: "{count} 筆已保存結果" },
  targets: { en: "Targets", zhTW: "目標數" },
  rawEvidenceFiles: { en: "Raw evidence files", zhTW: "原始證據檔案" },
  technicalDetails: { en: "Technical status and errors", zhTW: "技術狀態與錯誤" },
  scannerName: { en: "Scanner name", zhTW: "掃描工具名稱" },
  builtInCheck: { en: "Built-in local TCP connection test", zhTW: "內建本機 TCP 連線測試" },
  taskId: { en: "Check job ID", zhTW: "檢查工作 ID" },
  endpoint: { en: "Exact endpoint", zhTW: "確切端點" },
  timeout: { en: "Maximum wait", zhTW: "最長等待時間" },
  payload: { en: "Application data sent", zhTW: "傳送的應用層資料" },
  bytes: { en: "{count} bytes", zhTW: "{count} 位元組" },
  observedOutcome: { en: "Observed outcome", zhTW: "觀察結果" },
  savedObservation: { en: "Saved observation code", zhTW: "已保存的觀察代碼" },
  observedAt: { en: "Observed at", zhTW: "觀察時間" },
  notIncluded: { en: "Not included", zhTW: "未包含" },
  taskMessage: { en: "Check message", zhTW: "檢查訊息" },
  reportedPhase: { en: "Reported phase", zhTW: "回報階段" },
  errorCode: { en: "Error code", zhTW: "錯誤代碼" },
  scannerMessage: { en: "Scanner message", zhTW: "掃描工具訊息" },
  checkpointError: { en: "Last checkpoint error", zhTW: "接續點最後錯誤" },
  noneReported: { en: "None reported", zhTW: "沒有回報" },
  provenance: { en: "Versions and technical execution record", zhTW: "版本與技術執行紀錄" },
  jobId: { en: "Scanner job ID", zhTW: "掃描工作 ID" },
  engineId: { en: "Scanner ID", zhTW: "掃描工具 ID" },
  categoryCode: { en: "Category code", zhTW: "類別代碼" },
  scannerVersion: { en: "Scanner version", zhTW: "掃描工具版本" },
  imageDigest: { en: "Image digest", zhTW: "映像摘要" },
  ruleVersion: { en: "Rule version", zhTW: "規則版本" },
  adapter: { en: "Result adapter", zhTW: "結果轉換器" },
  manifestSchema: { en: "Manifest schema", zhTW: "內容清單格式版本" },
  sourceRevision: { en: "Source revision", zhTW: "來源版本" },
  sourceRepository: { en: "Source repository", zhTW: "原始程式碼儲存庫" },
  distributionMode: { en: "Distribution mode", zhTW: "發佈模式" },
  imageRepository: { en: "Image repository", zhTW: "映像儲存庫" },
  commandDigest: { en: "Command digest", zhTW: "命令摘要" },
  knowledgeInput: { en: "Knowledge input", zhTW: "知識輸入" },
  noIndependentVersion: { en: "no separate version", zhTW: "沒有獨立版本" },
  knowledgeDate: { en: "Last updated", zhTW: "最後更新" },
  olderNotRecorded: { en: "Not recorded in this older case", zhTW: "舊版案件未記錄" },
  runtime: { en: "Runtime", zhTW: "執行環境" },
  unknownVersion: { en: "version not reported", zhTW: "版本未回報" },
  notRunYet: { en: "Not run", zhTW: "未執行" },
  runtimeSecurity: { en: "Runtime security options", zhTW: "執行環境安全選項" },
  exitCode: { en: "Exit code", zhTW: "結束代碼" },
  cleanupResult: { en: "Cleanup result", zhTW: "清理結果" },
  removed: { en: "Removed", zhTW: "已移除" },
  absentOrUnneeded: { en: "Already absent or did not need removal", zhTW: "已不存在或不需要移除" },
  started: { en: "Started", zhTW: "開始" },
  ended: { en: "Ended", zhTW: "結束" },
  warnings: { en: "Technical warnings", zhTW: "技術警告" },
  historyEyebrow: { en: "SCAN HISTORY", zhTW: "掃描紀錄" },
  historyTitle: { en: "Earlier scans", zhTW: "過往掃描" },
  historySnapshot: { en: "Case snapshot {date}", zhTW: "案件快照 {date}" },
  historyNotStarted: { en: "Not started", zhTW: "未開始" },
} as const;

const readinessPresentation: Partial<Record<ScanReadinessBlocker, {
  action: { en: string; zhTW: string };
  title: { en: string; zhTW: string };
  description: { en: string; zhTW: string };
}>> = {
  no_runnable_authorized_targets: {
    action: copy.getLatestInstaller,
    title: copy.unavailableToolsTitle,
    description: copy.unavailableToolsDescription,
  },
  provider_source_required: {
    action: copy.connectCloud,
    title: copy.providerSourceTitle,
    description: copy.providerSourceDescription,
  },
  provider_capability_unavailable: {
    action: copy.reconnectCloud,
    title: copy.providerCapabilityTitle,
    description: copy.providerCapabilityDescription,
  },
  provider_source_ambiguous: {
    action: copy.chooseConnection,
    title: copy.providerAmbiguousTitle,
    description: copy.providerAmbiguousDescription,
  },
  provider_authorization_binding_mismatch: {
    action: copy.reviewConnection,
    title: copy.providerAuthorizationTitle,
    description: copy.providerAuthorizationDescription,
  },
  provider_target_binding_mismatch: {
    action: copy.reviewTarget,
    title: copy.providerTargetTitle,
    description: copy.providerTargetDescription,
  },
  provider_preflight_unavailable: {
    action: copy.checkAgain,
    title: copy.providerCheckTitle,
    description: copy.providerCheckDescription,
  },
  workspace_snapshot_unavailable: {
    action: copy.chooseLocalInputAgain,
    title: copy.workspaceSnapshotTitle,
    description: copy.workspaceSnapshotDescription,
  },
  egress_gateway_unavailable: {
    action: copy.getLatestInstaller,
    title: copy.egressGatewayTitle,
    description: copy.egressGatewayDescription,
  },
  engine_execution_contract_invalid: {
    action: copy.getLatestInstaller,
    title: copy.engineContractTitle,
    description: copy.engineContractDescription,
  },
  passive_source_unavailable: {
    action: copy.reconnectReadOnlySource,
    title: copy.passiveSourceTitle,
    description: copy.passiveSourceDescription,
  },
  captured_evidence_unavailable: {
    action: copy.startFreshScan,
    title: copy.capturedEvidenceTitle,
    description: copy.capturedEvidenceDescription,
  },
  execution_preflight_unavailable: {
    action: copy.checkAgain,
    title: copy.executionCheckTitle,
    description: copy.executionCheckDescription,
  },
};

const engineStates: EngineRunStatus[] = [
  "pending",
  "running",
  "paused",
  "completed",
  "partial",
  "failed",
  "not_executed",
  "cancelled",
];

const terminalEngineStates: EngineRunStatus[] = ["completed", "partial", "failed", "not_executed", "cancelled"];
const terminalRunStatuses = new Set<ScanRun["status"]>([
  "completed",
  "no_checks_completed",
  "partial",
  "failed",
  "cancelled",
]);
const activeRunStatuses = new Set<ScanRun["status"]>(["queued", "running", "paused"]);
const currentOrNextEngineRuns = (run: ScanRun): EngineRun[] => {
  if (!activeRunStatuses.has(run.status)) return [];
  const running = run.engineRuns.filter((engine) => engine.status === "running");
  if (running.length > 0) return running;
  const paused = run.engineRuns.filter((engine) => engine.status === "paused");
  if (paused.length > 0) return paused;
  return run.engineRuns.filter((engine) => engine.status === "pending").slice(0, 1);
};
const primaryTimingTargets: Partial<Record<UseCaseId, BilingualText>> = {
  internal_it_environment: primaryScanTiming,
  deployed_website: primaryScanTiming,
  source_code: primaryScanTiming,
};

const isExecutionStage = (phase: string): phase is ExecutionStage =>
  Object.prototype.hasOwnProperty.call(executionStageMeta, phase);

const engineIcon = (engine: EngineRun) => {
  if (engine.status === "completed") return "check" as const;
  if (engine.status === "running") return "refresh" as const;
  if (engine.status === "paused") return "pause" as const;
  if (engine.status === "failed" || engine.status === "partial") return "warning" as const;
  if (engine.status === "cancelled") return "stop" as const;
  return "settings" as const;
};

export function ProgressPage({
  caseId,
  assessmentIntent,
  assets,
  report,
  runs,
  selectedRunId: controlledSelectedRunId,
  requestedTerminalPage,
  terminalPageRequestCount,
  readiness,
  readinessCheckFailed,
  diagnosticContext,
  busy,
  starting,
  retryingLocalhostQuickScan,
  onStart,
  onRetryLocalhostQuickScan,
  onFixSetup,
  onPause,
  onResume,
  onCancel,
  onSelectRun,
}: ProgressPageProps) {
  const { locale, text, formatDate, formatDateTime, formatNumber } = useI18n();
  const [localSelectedRunId, setLocalSelectedRunId] = useState(runs[0]?.id);
  const selectedRunId = controlledSelectedRunId ?? localSelectedRunId;
  const selectRun = (runId: string) => {
    setLocalSelectedRunId(runId);
    onSelectRun?.(runId);
  };
  const startRunIds = useRef<{ caseId?: string; ids: Set<string> } | undefined>(undefined);
  const selectedRun = runs.find((run) => run.id === selectedRunId) ?? runs[0];
  const selectedRunOverallProgress = selectedRun ? scanRunOverallProgress(selectedRun) : 0;
  const neverStartedRun = Boolean(selectedRun && isNeverStartedScanRun(selectedRun));
  const exactLocalhostQuickScan = Boolean(
    selectedRun && isExactBuiltInLocalhostQuickScanRun(selectedRun),
  );
  const terminalExactLocalhostQuickScan = Boolean(
    selectedRun && isTerminalExactBuiltInLocalhostQuickScanRun(selectedRun),
  );
  const terminalLocalhostSummary = terminalExactLocalhostQuickScan && selectedRun
    ? localhostTcpBeginnerSummary(selectedRun.engineRuns[0]!)
    : undefined;
  const canRetryLocalhostQuickScan = Boolean(
    terminalLocalhostSummary && (
      terminalLocalhostSummary.outcome === "closed"
      || terminalLocalhostSummary.outcome === "timed_out"
      || needsFreshLocalhostTcpAttempt(terminalLocalhostSummary.outcome)
    ),
  );
  const selectedRunReport = report?.runId === selectedRun?.id ? report : undefined;
  const showResultsAction = Boolean(
    selectedRun && terminalRunStatuses.has(selectedRun.status),
  );
  const waitingForTerminalPage = Boolean(
    requestedTerminalPage
    && selectedRun
    && activeRunStatuses.has(selectedRun.status),
  );
  const waitingNoticeRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!waitingForTerminalPage) return;
    waitingNoticeRef.current?.focus({ preventScroll: true });
    waitingNoticeRef.current?.scrollIntoView?.({ block: "nearest" });
  }, [waitingForTerminalPage, requestedTerminalPage, terminalPageRequestCount]);
  const scanWorkActive = hasActiveScanWork(runs);
  const undispatchedPlan = runs.find((run) => isUndispatchedScanPlan(run));
  const providerSetupRequired = !readinessCheckFailed
    && !scanWorkActive
    && isProviderConfigurationBlocker(readiness?.blockerCode);
  const canStart = !terminalExactLocalhostQuickScan
    && canStartPreparedScan(readiness, Boolean(readinessCheckFailed), runs)
    && !providerSetupRequired;
  const blockerPresentation = readiness?.blockerCode
    ? readinessPresentation[readiness.blockerCode]
    : undefined;
  const blockerDescription = readiness?.blockerCode
    ? copy.readiness[readiness.blockerCode] ?? copy.readinessUnavailableDescription
    : copy.readinessUnavailableDescription;
  const startFreshScan = !readinessCheckFailed && isCapturedEvidenceBlocker(readiness?.blockerCode);
  // A scan spends its cloud connection, so after one the next scan simply starts with a reconnect.
  const reconnectBeforeNextScan = providerSetupRequired
    && readiness?.blockerCode === "provider_capability_unavailable";
  const needsLatestInstaller = Boolean(
    !readinessCheckFailed
    && readiness?.blockerCode
    && installerBlockers.has(readiness.blockerCode),
  );
  const requestStart = () => {
    startRunIds.current = { caseId, ids: new Set(runs.map((run) => run.id)) };
    void onStart();
  };
  const runReadinessAction = () => {
    if (startFreshScan) {
      requestStart();
      return;
    }
    onFixSetup();
  };
  const fixActionLabel = readinessCheckFailed
    ? copy.checkAgain
    : blockerPresentation?.action
    ?? (readiness?.nextStep === "scanner_setup"
      ? copy.setupTools
      : readiness?.nextStep === "cases"
        ? copy.chooseProject
        : copy.finishSetup);
  const blockerTitle = blockerPresentation?.title ?? fixActionLabel;
  const emptyTitle = readinessCheckFailed
    ? copy.readinessUnavailableTitle
    : blockerPresentation?.title
    ?? (readiness?.blockerCode === "runtime_unavailable"
      ? copy.runtimeEmptyTitle
      : copy.emptyTitle);
  const emptyDescription = readinessCheckFailed
    ? copy.readinessUnavailableDescription
    : blockerPresentation?.description
    ?? (readiness?.blockerCode === "runtime_unavailable"
      ? copy.runtimeEmptyDescription
      : copy.emptyDescription);

  useEffect(() => {
    if (runs.some((run) => run.id === selectedRunId)) return;
    const nextRunId = runs[0]?.id;
    setLocalSelectedRunId(nextRunId);
    if (nextRunId) onSelectRun?.(nextRunId);
  }, [onSelectRun, runs, selectedRunId]);

  useEffect(() => {
    const baseline = startRunIds.current;
    if (!baseline || baseline.caseId !== caseId) return;
    const createdRunId = findRunCreatedAfterStart(runs, baseline.ids);
    if (createdRunId) {
      selectRun(createdRunId);
      startRunIds.current = undefined;
    } else if (!starting) {
      startRunIds.current = undefined;
    }
  }, [caseId, runs, starting]);

  const [activityClock, setActivityClock] = useState(() => new Date());
  useEffect(() => {
    if (!selectedRun || !["queued", "running", "paused"].includes(selectedRun.status)) return undefined;
    const interval = window.setInterval(() => setActivityClock(new Date()), 30_000);
    return () => window.clearInterval(interval);
  }, [selectedRun]);
  const activity = useMemo(
    () => selectedRun ? buildScanActivity(selectedRun, activityClock) : undefined,
    [activityClock, selectedRun],
  );
  const activeAssetNames = useMemo(() => {
    if (!selectedRun) return [];
    const assetNames = new Map(assets.map((asset) => [asset.id, asset.name]));
    for (const target of selectedRunReport?.requested.targets ?? []) {
      if (target.label) assetNames.set(target.assetId, target.label);
    }
    return [...new Set(
      currentOrNextEngineRuns(selectedRun)
        .flatMap((engine) => engine.assetIds)
        .map((assetId) => assetNames.get(assetId))
        .filter((name): name is string => Boolean(name)),
    )];
  }, [assets, selectedRun, selectedRunReport]);
  const elapsedMilliseconds = selectedRun
    ? Math.max(0, Date.parse(selectedRun.finishedAt ?? activityClock.toISOString()) - Date.parse(selectedRun.startedAt))
    : 0;
  const elapsedMinutes = Math.floor(elapsedMilliseconds / 60_000);
  const elapsedLabel = elapsedMinutes < 1
    ? text(copy.elapsedUnderMinute)
    : text(copy.elapsedMinutes, { count: formatNumber(elapsedMinutes) });
  const primaryTimingTarget = assessmentIntent
    ? primaryTimingTargets[assessmentIntent]
    : undefined;
  const activeTimingStatus = activity?.active
    ? primaryTimingTarget && !exactLocalhostQuickScan
      ? text(primaryTimingTarget)
      : text(copy.estimateUnavailable)
    : undefined;
  const stateCounts = useMemo(
    () => Object.fromEntries(
      engineStates.map((state) => [state, selectedRun?.engineRuns.filter((engine) => engine.status === state).length ?? 0]),
    ) as Record<EngineRunStatus, number>,
    [selectedRun],
  );
  const showDateTime = (value?: string): string => value ? formatDateTime(value) : text(copy.noneReported);
  const showPlainDate = (value: string): string => formatDate(`${value}T12:00:00`);
  const workCountLabel = (count: number): string => count === 1
    ? text(copy.workCountOne)
    : text(copy.workCount, { count: formatNumber(count) });
  const activityEventLabel = (event: ScanActivityEvent): string => {
    switch (event.code) {
      case "check_attempts_started":
      case "checks_completed":
      case "checks_failed":
      case "checks_partly_completed":
      case "checks_cancelled":
      case "checks_not_started":
        return event.count === 1
          ? text(copy.activityEventSingular[event.code])
          : text(copy.activityEvents[event.code], { count: formatNumber(event.count ?? 0) });
      case "progress_saved":
        return text(copy.activityEvents.progress_saved, { percent: formatNumber(event.progress ?? 0) });
      default:
        return text(copy.activityEvents[event.code]);
    }
  };
  const phaseLabel = (engine: EngineRun): string => {
    if (engine.phase === "interrupted_restart") return text(copy.interruptedPhase);
    if (engine.phase === "queued_for_resume") return text(copy.queuedResumePhase);
    if (engine.phase === "cancel_requested") return text(copy.cancelRequestedPhase);
    if (isExecutionStage(engine.phase)) return executionStageMeta[engine.phase].label;
    return text(copy.unknownPhase);
  };

  const aggregateTechnicalRecords = (engines: EngineRun[], summary: string) => (
    <details className="page-technical-details aggregate-engine-records">
      <summary>{summary}</summary>
      {engines.map((engine) => (
        <section key={engine.id} className="aggregate-engine-record">
          <strong>{engine.engineName}</strong>
          <dl>
            <div><dt>{text(copy.engineId)}</dt><dd><code>{engine.engineId}</code></dd></div>
            <div><dt>{text(copy.reportedPhase)}</dt><dd><code>{displayTechnicalDetail(engine.phase) ?? text(copy.noneReported)}</code></dd></div>
            <div><dt>{text(copy.errorCode)}</dt><dd><code>{displayTechnicalDetail(engine.errorCode) ?? text(copy.noneReported)}</code></dd></div>
            <div><dt>{text(copy.scannerMessage)}</dt><dd>{displayTechnicalDetail(engine.message) ?? text(copy.noneReported)}</dd></div>
            <div><dt>{text(copy.checkpointError)}</dt><dd>{displayTechnicalDetail(engine.checkpoint?.lastError) ?? text(copy.noneReported)}</dd></div>
          </dl>
        </section>
      ))}
      <p>{text(copy.diagnosticPrivacy)}</p>
    </details>
  );

  const downloadDiagnostic = (run: ScanRun) => {
    const blob = new Blob([buildScanDiagnostic(run, diagnosticContext)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `ai-security-scanner-diagnostic-${run.id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const downloadPreflightDiagnostic = () => {
    const blob = new Blob([
      buildReadinessDiagnostic({ readiness, checkFailed: Boolean(readinessCheckFailed) }, diagnosticContext),
    ], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `ai-security-scanner-preflight-${readiness?.caseId ?? "unavailable"}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  if (!selectedRun) {
    return (
      <div className="page">
        <PageHeader eyebrow={text(copy.eyebrow)} title={text(copy.title)} />
        <EmptyState
          icon="progress"
          title={text(starting ? copy.startingTitle : emptyTitle)}
          description={text(starting ? copy.startingDescription : emptyDescription)}
          action={starting ? (
            <button className="button button--primary" type="button" disabled aria-busy="true">
              <Icon name="progress" size={17} />{text(copy.startingAction)}
            </button>
          ) : canStart ? (
            <button className="button button--primary" type="button" disabled={busy} onClick={requestStart}>
              <Icon name="play" size={17} />{text(copy.start)}
            </button>
          ) : needsLatestInstaller ? (
            <a className="button button--primary" href={PRODUCT_RELEASES} target="_blank" rel="noreferrer">
              <Icon name="external" size={17} />{text(copy.getLatestInstaller)}
            </a>
          ) : readiness || readinessCheckFailed ? (
            <button
              className="button button--primary"
              type="button"
              disabled={busy || (readiness?.nextStep === "progress" && !startFreshScan)}
              onClick={runReadinessAction}
            >
              <Icon name="arrow" size={17} />{text(fixActionLabel)}
            </button>
          ) : (
            <button className="button button--secondary" type="button" disabled>
              <Icon name="refresh" size={17} />{text(copy.checkingReady)}
            </button>
          )}
        />
        <details className={`page-technical-details scan-activity${canStart || starting ? "" : " scan-activity--delayed"}`}>
          <summary>{text(copy.readinessDetails)}</summary>
          <div className="section-heading section-heading--row">
            <div>
              <p className="eyebrow">{text(copy.activityEyebrow)}</p>
              <h2 id="scan-preflight-activity-title">{text(starting ? copy.startingActivityTitle : copy.noRunActivityTitle)}</h2>
              <p>{text(starting ? copy.startingActivityDescription : copy.noRunActivityDescription)}</p>
              <small>{text(copy.lastReadinessCheck)} · {readiness?.checkedAt
                ? showDateTime(readiness.checkedAt)
                : text(copy.noReadinessTimestamp)}</small>
            </div>
            <button className="button button--secondary button--small" type="button" disabled={!readiness && !readinessCheckFailed} onClick={downloadPreflightDiagnostic}>
              <Icon name="download" size={15} />{text(copy.downloadTechnicalLog)}
            </button>
          </div>
          {starting && (
            <div className="scan-activity__current" role="status">
              <span className="scan-activity__icon"><Icon name="progress" size={20} /></span>
              <div>
                <small>{text(copy.currentActivity)}</small>
                <strong>{text(copy.startingTitle)}</strong>
                <p>{text(copy.startingActivityDescription)}</p>
              </div>
            </div>
          )}
          <div className="scan-activity__log">
            <div>
              <strong>{text(copy.activityLog)}</strong>
              <small>{text(copy.activityLogDescription)}</small>
            </div>
            {readiness?.checkedAt ? (
              <ol>
                <li>
                  <span aria-hidden="true" />
                  <div><strong>{text(copy.readinessChecked)}</strong><time dateTime={readiness.checkedAt}>{showDateTime(readiness.checkedAt)}</time></div>
                </li>
                {!readiness.ready && (
                  <li>
                    <span aria-hidden="true" />
                    <div><strong>{text(copy.scanNotStartedEvent)}</strong><time dateTime={readiness.checkedAt}>{showDateTime(readiness.checkedAt)}</time></div>
                  </li>
                )}
              </ol>
            ) : <p className="scan-activity__no-events">{text(copy.noReadinessTimestamp)}</p>}
          </div>
          <details className="page-technical-details scan-activity__technical">
            <summary>{text(copy.technicalPreflight)}</summary>
            <dl>
              <div><dt>{text(copy.blockerCode)}</dt><dd><code>{readiness?.blockerCode ?? text(copy.noneReported)}</code></dd></div>
              <div><dt>{text(copy.readinessState)}</dt><dd><code>{readiness?.state ?? text(copy.noneReported)}</code></dd></div>
              <div><dt>{text(copy.nextStepCode)}</dt><dd><code>{readiness?.nextStep ?? text(copy.noneReported)}</code></dd></div>
            </dl>
          </details>
          <small className="scan-activity__privacy"><Icon name="lock" size={13} />{text(copy.diagnosticPrivacy)}</small>
        </details>
      </div>
    );
  }

  const runMeta = runStatusMeta[selectedRun.status];
  const requestOutcomeSummary = scanRequestOutcomeBeginnerSummary(selectedRun.requestOutcome);
  const blocked = blockedRunSummary(selectedRun);
  const skipped = skippedEngineRunSummary(selectedRun);
  const sharedInfrastructureFailure = sharedInfrastructureFailureSummary(selectedRun);
  const visibleEngineRuns = sharedInfrastructureFailure
    ? []
    : selectedRun.engineRuns.filter((engine) => engine.status !== "not_executed");
  const localhostCancelRequested = isLocalhostQuickScanCancelRequested(selectedRun);
  const canPause = selectedRun.status === "running" && !exactLocalhostQuickScan;
  const recoverableEngines = selectedRun.engineRuns.filter((engine) => engine.resumable);
  const hasResumableEngine = recoverableEngines.length > 0;
  const recoveryActions = new Set(recoverableEngines.map((engine) =>
    engine.recoveryAction ?? "continue_saved_results"
  ));
  const recoveryActionLabel = recoveryActions.size === 1 && recoveryActions.has("restart_check")
    ? copy.retry
    : recoveryActions.has("restart_check")
      ? copy.recoverMixed
      : copy.resume;
  const canResume = !startFreshScan && !providerSetupRequired && (
    selectedRun.status === "paused"
    || ((selectedRun.status === "partial" || selectedRun.status === "failed" || selectedRun.status === "cancelled") && hasResumableEngine)
  ) && !exactLocalhostQuickScan;
  const canCancel = !localhostCancelRequested && (
    selectedRun.status === "running" || selectedRun.status === "paused" || selectedRun.status === "queued"
  );
  const savedPlanAfterRestart = neverStartedRun && !activeRunStatuses.has(selectedRun.status);
  const hasReleaseIncompatibleWork = selectedRun.engineRuns.some(
    (engine) => engine.errorCode === "resume_release_incompatible",
  );
  const interruptedEngines = selectedRun.engineRuns.filter(
    (engine) => engine.phase === "interrupted_restart"
      || engine.errorCode === "desktop_process_restarted"
      || engine.phase === "preflight_interrupted"
      || engine.errorCode === "preflight_interrupted",
  );
  const savedPlanActionCount = recoverableEngines.length;
  const neverStartedPlannedCount = selectedRun.engineRuns.filter(
    (engine) => engine.status !== "not_executed",
  ).length;
  const interruptedBody = canResume && canCancel
    ? copy.interruptedBody
    : canResume
      ? copy.interruptedBodyContinue
      : canCancel
        ? copy.interruptedBodyCancel
        : copy.interruptedBodyNoAction;
  const savedPlanBody = canResume && canStart
    ? copy.savedPlanBodyContinueStart
    : canResume
      ? copy.savedPlanBodyContinue
      : canStart
        ? copy.savedPlanBodyStart
        : copy.savedPlanBodyNoAction;
  const unevaluatedCompletedCheckCount = selectedRun.engineRuns.filter(
    (engine) => engine.status === "completed" && engineRecordedUnevaluatedTarget(engine),
  ).length;
  const settledSkippedCount = selectedRun.engineRuns.filter(isSettledSkippedCheck).length;
  const incompleteCount = stateCounts.partial + stateCounts.failed + (stateCounts.not_executed - settledSkippedCount) + stateCounts.cancelled + unevaluatedCompletedCheckCount;
  const incompleteNoticeVisible = !savedPlanAfterRestart && !blocked && !sharedInfrastructureFailure && incompleteCount > 0;
  // The failed and cancelled bodies repeat the incomplete notice. The
  // partly-completed body also says the finished checks are ready to review,
  // which that notice does not, so it stays visible.
  const suppressActivityBody = (activity?.state === "stopped" || activity?.state === "failed")
    && incompleteNoticeVisible;
  const terminalCount = terminalEngineStates.reduce((sum, state) => sum + stateCounts[state], 0);
  const completedAssetCount = Math.min(selectedRun.totalAssetCount, selectedRun.coveredAssetCount);
  const uncoveredAssetCount = Math.max(0, selectedRun.totalAssetCount - completedAssetCount);
  const knownAttentionAssetCount = Math.min(
    uncoveredAssetCount,
    new Set(selectedRun.engineRuns
      .filter((engine) => (["partial", "failed", "not_executed", "cancelled"].includes(engine.status)
        && !isSettledSkippedCheck(engine))
        || engineRecordedUnevaluatedTarget(engine))
      .flatMap((engine) => engine.assetIds)).size,
  );
  const attentionAssetCount = activeRunStatuses.has(selectedRun.status)
    ? knownAttentionAssetCount
    : uncoveredAssetCount;
  const remainingAssetCount = Math.max(0, uncoveredAssetCount - attentionAssetCount);
  const completedCheckCount = stateCounts.completed - unevaluatedCompletedCheckCount;
  const attentionCheckCount = incompleteCount;
  const remainingCheckCount = Math.max(
    0,
    selectedRun.engineRuns.length - completedCheckCount - attentionCheckCount - settledSkippedCount,
  );
  const knowledgeDates = [...new Set(selectedRun.engineRuns
    .map((engine) => engine.knowledgeInput?.knowledgeDate)
    .filter((value): value is string => Boolean(value)))]
    .sort();
  const knowledgeRange = knowledgeDates.length === 0
    ? text(copy.legacyKnowledge)
    : knowledgeDates.length === 1
      ? showPlainDate(knowledgeDates[0]!)
      : `${showPlainDate(knowledgeDates[0]!)} — ${showPlainDate(knowledgeDates.at(-1)!)}`;

  return (
    <div className="page">
      <PageHeader
        eyebrow={text(copy.eyebrow)}
        title={text(copy.title)}
        actions={(
          <div className="button-group">
            {canRetryLocalhostQuickScan && terminalLocalhostSummary && (
              <button
                className="button button--primary"
                type="button"
                disabled={busy || retryingLocalhostQuickScan}
                aria-busy={retryingLocalhostQuickScan}
                onClick={() => void onRetryLocalhostQuickScan(terminalLocalhostSummary.port)}
              >
                <Icon name={retryingLocalhostQuickScan ? "progress" : "refresh"} size={17} />
                {text(retryingLocalhostQuickScan ? copy.retryingLocalhostQuickScan : copy.retryLocalhostQuickScan)}
              </button>
            )}
            {showResultsAction && (
              <a
                className="button button--primary"
                href="#findings"
              >
                <Icon name="findings" size={17} />{text(copy.viewResults)}
              </a>
            )}
            {!terminalExactLocalhostQuickScan && reconnectBeforeNextScan && (
              <button className="button button--secondary" type="button" disabled={busy} onClick={onFixSetup}>
                <Icon name="refresh" size={17} />{text(copy.reconnectToScanAgain)}
              </button>
            )}
            {canStart && !hasReleaseIncompatibleWork && (
              <button className="button button--primary" type="button" disabled={busy || starting} aria-busy={starting} onClick={requestStart}>
                <Icon name={starting ? "progress" : "play"} size={17} />{text(starting ? copy.startingAction : copy.start)}
              </button>
            )}
            {canPause && (
              <button className="button button--secondary" type="button" disabled={busy} aria-label={text(copy.pauseAria, { id: selectedRun.id })} onClick={() => void onPause(selectedRun.id)}>
                <Icon name="pause" size={17} />{text(copy.pause)}
              </button>
            )}
            {canResume && (
              <button className="button button--primary" type="button" disabled={busy} aria-label={text(copy.resumeAria, { id: selectedRun.id })} onClick={() => void onResume(selectedRun.id)}>
                <Icon name="play" size={17} />{text(recoveryActionLabel)}
              </button>
            )}
            {canCancel && (
              <button className="button button--danger-ghost" type="button" disabled={busy} aria-label={text(copy.cancelAria, { id: selectedRun.id })} onClick={() => void onCancel(selectedRun.id)}>
                <Icon name="stop" size={17} />{text(copy.cancel)}
              </button>
            )}
            {localhostCancelRequested && (
              <span className="button button--danger-ghost" role="status" aria-live="polite" aria-label={text(copy.stoppingAria, { id: selectedRun.id })}>
                <Icon name="progress" size={17} />{text(copy.stopping)}
              </span>
            )}
          </div>
        )}
      />

      {waitingForTerminalPage && requestedTerminalPage && (
        <div ref={waitingNoticeRef} tabIndex={-1}>
          <InlineNotice
            key={terminalPageRequestCount}
            tone="info"
            title={text(requestedTerminalPage === "findings"
              ? copy.resultsWaitingTitle
              : copy.exportWaitingTitle)}
            announce
          >
            <p>{text(requestedTerminalPage === "findings"
              ? copy.resultsWaitingDescription
              : copy.exportWaitingDescription)}</p>
          </InlineNotice>
        </div>
      )}

      {canRetryLocalhostQuickScan && terminalLocalhostSummary && (
        <InlineNotice tone="warning" title={text(copy.retryLocalhostQuickScanTitle)}>
          <p>{text(copy.retryLocalhostQuickScanDescription, { port: String(terminalLocalhostSummary.port) })}</p>
        </InlineNotice>
      )}

      {starting && (
        <InlineNotice tone="info" title={text(copy.startingNewTitle)}>
          <p role="status">{text(copy.startingNewDescription)}</p>
        </InlineNotice>
      )}

      {undispatchedPlan && (
        <InlineNotice tone="warning" title={text(copy.undispatchedPlanTitle)} announce>
          <p>{text(copy.undispatchedPlanDescription)}</p>
          <button
            className="button button--danger-ghost button--small"
            type="button"
            disabled={busy}
            onClick={() => void onCancel(undispatchedPlan.id)}
          >
            <Icon name="stop" size={15} />{text(copy.undispatchedPlanCancel)}
          </button>
        </InlineNotice>
      )}

      {hasReleaseIncompatibleWork && (
        <InlineNotice tone="warning" title={text(copy.releaseIncompatibleTitle)}>
          <p>{text(scanWorkActive
            ? copy.releaseIncompatibleActiveBody
            : canStart
              ? copy.releaseIncompatibleBody
              : copy.releaseIncompatibleNotReadyBody)}</p>
          {canStart && (
            <button className="button button--primary button--small" type="button" disabled={busy || starting} onClick={requestStart}>
              <Icon name="play" size={15} />{text(copy.startFreshScan)}
            </button>
          )}
        </InlineNotice>
      )}

      {!terminalExactLocalhostQuickScan && readinessCheckFailed && (
        <InlineNotice tone="warning" title={text(copy.readinessUnavailableTitle)}>
          <p>{text(copy.readinessUnavailableDescription)}</p>
          <button className="button button--primary button--small" type="button" disabled={busy} onClick={onFixSetup}>
            <Icon name="refresh" size={15} />{text(copy.checkAgain)}
          </button>
        </InlineNotice>
      )}

      {/* While a scan is active the backend can only report that scan, so any other blocker is a pre-start reading. */}
      {!terminalExactLocalhostQuickScan && !scanWorkActive && !reconnectBeforeNextScan && readiness && !readiness.ready && readiness.blockerCode && (readiness.nextStep !== "progress" || startFreshScan) && (
        <InlineNotice tone="warning" title={text(blockerTitle)}>
          <p>{text(blockerDescription)}</p>
          {needsLatestInstaller ? (
            <a className="button button--primary button--small" href={PRODUCT_RELEASES} target="_blank" rel="noreferrer">
              <Icon name="external" size={15} />{text(copy.getLatestInstaller)}
            </a>
          ) : (
            <button className="button button--primary button--small" type="button" disabled={busy} onClick={runReadinessAction}>
              <Icon name="arrow" size={15} />{text(fixActionLabel)}
            </button>
          )}
        </InlineNotice>
      )}

      {runs.length > 1 && (
        <div className="run-picker" role="group" aria-label={text(copy.chooseRun)}>
          <span>{text(copy.viewRun)}</span>
          <div>
            {runs.map((run, index) => (
              <button
                key={run.id}
                type="button"
                className={run.id === selectedRun.id ? "run-picker__item run-picker__item--active" : "run-picker__item"}
                aria-pressed={run.id === selectedRun.id}
                onClick={() => selectRun(run.id)}
              >
                <strong>{scanRunIdentityPresentation(run, locale)}</strong>
                <span>{index === 0 ? text(copy.latest) : ""}{isNeverStartedScanRun(run) && !activeRunStatuses.has(run.status) ? text(copy.notStartedStatus) : runStatusMeta[run.status].label} · {showDateTime(run.startedAt)}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {savedPlanAfterRestart && (
        <InlineNotice tone="warning" title={text(copy.savedPlanTitle)}>
          <div className="interrupted-run-notice">
            <p>{text(savedPlanBody, { count: formatNumber(savedPlanActionCount) })}</p>
            <div className="button-group">
              {canResume && (
                <button className="button button--primary button--small" type="button" disabled={busy} onClick={() => void onResume(selectedRun.id)}>
                  <Icon name="play" size={15} />{text(copy.resumeOriginal)}
                </button>
              )}
              {canStart && (
                <button className="button button--secondary button--small" type="button" disabled={busy || starting} onClick={requestStart}>
                  <Icon name="play" size={15} />{text(copy.startNewScan)}
                </button>
              )}
            </div>
          </div>
        </InlineNotice>
      )}

      {interruptedEngines.length > 0 && !savedPlanAfterRestart && (
        <InlineNotice tone="warning" title={text(copy.interruptedTitle)}>
          <div className="interrupted-run-notice">
            <p>{text(interruptedBody, { count: formatNumber(interruptedEngines.length) })}</p>
            <div className="button-group">
              {canResume && (
                <button className="button button--primary button--small" type="button" disabled={busy} onClick={() => void onResume(selectedRun.id)}>
                  <Icon name="play" size={15} />{text(copy.resumeOriginal)}
                </button>
              )}
              {canCancel && (
                <button className="button button--danger-ghost button--small" type="button" disabled={busy} onClick={() => void onCancel(selectedRun.id)}>
                  <Icon name="stop" size={15} />{text(copy.cancelKeepRecord)}
                </button>
              )}
            </div>
          </div>
        </InlineNotice>
      )}

      <section className={`run-overview run-overview--single${blocked || sharedInfrastructureFailure || requestOutcomeSummary ? " run-overview--compact" : ""}`}>
        <div className="run-overview__copy">
          <div className="run-overview__meta">
            <StatusPill
              label={savedPlanAfterRestart ? text(copy.notStartedStatus) : runMeta.label}
              tone={savedPlanAfterRestart ? "warning" : runMeta.tone}
            />
            <span>{scanRunIdentityPresentation(selectedRun, locale)}</span>
          </div>
          {savedPlanAfterRestart && (
            <>
              <h2>{text(copy.noChecksStarted)}</h2>
              <p>{text(copy.savedPlanReady)}</p>
            </>
          )}
          {!savedPlanAfterRestart && !blocked && !sharedInfrastructureFailure && !requestOutcomeSummary && (
            <>
              <h2>{text(copy.processed, { percent: formatNumber(selectedRunOverallProgress) })}</h2>
              <p>
                {text(copy.runSummary, {
                  total: formatNumber(selectedRun.totalAssetCount),
                  started: showDateTime(selectedRun.startedAt),
                })}
                {selectedRun.finishedAt ? text(copy.finished, { finished: showDateTime(selectedRun.finishedAt) }) : ""}
              </p>
              {!exactLocalhostQuickScan && (
                <div className="run-overview__progress-counts" aria-label={text(copy.progressCountsAria)}>
                  <p>{text(copy.assetProgressCounts, {
                    completed: formatNumber(completedAssetCount),
                    remaining: formatNumber(remainingAssetCount),
                    attention: formatNumber(attentionAssetCount),
                  })}</p>
                  <p>{text(copy.checkProgressCounts, {
                    completed: formatNumber(completedCheckCount),
                    remaining: formatNumber(remainingCheckCount),
                    attention: formatNumber(attentionCheckCount),
                  })}</p>
                </div>
              )}
              <p className="run-overview__timing">
                {text(copy.elapsed, { time: elapsedLabel })}
                {activeTimingStatus ? ` · ${activeTimingStatus}` : ""}
                {` · ${text(copy.lastSaved, { time: showDateTime(activity?.lastProgressAt ?? selectedRun.finishedAt ?? selectedRun.startedAt) })}`}
              </p>
              <ProgressBar value={selectedRunOverallProgress} label={text(copy.overallProgress)} tone={selectedRun.status === "failed" ? "danger" : selectedRun.status === "partial" ? "warning" : "accent"} />
            </>
          )}
        </div>
      </section>

      {(blocked || requestOutcomeSummary) && (
        <InlineNotice tone="warning" title={requestOutcomeSummary ? text(requestOutcomeSummary.title) : text(copy.blockedTitle)}>
          <p>{requestOutcomeSummary
            ? [text(requestOutcomeSummary.description), text(requestOutcomeSummary.nextStep)].join(" ")
            : text(blocked?.kind === "no_targets" ? copy.blockedNoTargets : copy.blockedNoChecks)}</p>
          <div className="button-group">
            {needsLatestInstaller ? (
              <a className="button button--primary button--small" href={PRODUCT_RELEASES} target="_blank" rel="noreferrer">
                <Icon name="external" size={15} />{text(copy.getLatestInstaller)}
              </a>
            ) : (
              <button className="button button--primary button--small" type="button" onClick={runReadinessAction}>
                <Icon name="arrow" size={15} />{text(fixActionLabel)}
              </button>
            )}
            <button className="button button--secondary button--small" type="button" onClick={() => downloadDiagnostic(selectedRun)}>
              <Icon name="file" size={15} />{text(copy.downloadLog)}
            </button>
          </div>
        </InlineNotice>
      )}

      {sharedInfrastructureFailure && (
        <InlineNotice tone="warning" title={text(copy.sharedFailureTitle)}>
          <p>{text(copy.sharedFailureBody, { count: formatNumber(sharedInfrastructureFailure.checkCount) })}</p>
          <div className="button-group">
            <button
              className="button button--primary button--small"
              type="button"
              disabled={busy}
              onClick={() => void onResume(selectedRun.id)}
            >
              <Icon name="refresh" size={15} />{text(copy.retryStoppedChecks)}
            </button>
            <button className="button button--secondary button--small" type="button" onClick={() => downloadDiagnostic(selectedRun)}>
              <Icon name="file" size={15} />{text(copy.downloadLog)}
            </button>
          </div>
        </InlineNotice>
      )}

      {activity && (
        <section className={`scan-activity scan-activity--compact${activity.stale ? " scan-activity--delayed" : ""}`} aria-label={text(copy.activityTitle)}>
          <div className="scan-activity__current" aria-live="polite">
            <span className="scan-activity__icon"><Icon name={activity.stale
              ? "warning"
              : activity.state === "paused"
                ? "pause"
                : activity.active
                  ? "refresh"
                  : activity.state === "completed"
                    ? "check"
                    : "warning"} size={20} /></span>
            <div>
              <strong>{text(savedPlanAfterRestart ? copy.noChecksStarted : copy.activityStates[activity.state].title)}</strong>
              {savedPlanAfterRestart
                ? <p>{text(copy.savedPlanReady)}</p>
                : (!activity.active || activity.stale)
                  && !suppressActivityBody
                  && <p>{text(copy.activityStates[activity.state].body)}</p>}
              <span>{text(copy.lastProgress)} · {showDateTime(activity.lastProgressAt)}</span>
              {activity.activeCheckNames.length > 0 && (
                <span>{text(copy.activeScanTools)} · {activity.activeCheckNames.join(locale === "zh-TW" ? "、" : ", ")}</span>
              )}
              {activeAssetNames.length > 0 && (
                <span>
                  {text(activeAssetNames.length === 1 ? copy.activeScanAsset : copy.activeScanAssets)} · {activeAssetNames.join(locale === "zh-TW" ? "、" : ", ")}
                </span>
              )}
            </div>
          </div>
          {activity.stale && (
            <p className="scan-activity__delay">
              <Icon name="clock" size={15} />
              {text(copy.delayedProgress, { count: formatNumber(activity.staleMinutes) })}
            </p>
          )}
          <details className="page-technical-details scan-activity__technical">
            <summary>{text(copy.activityHistory, { count: formatNumber(activity.events.length) })}</summary>
            <button className="button button--secondary button--small" type="button" onClick={() => downloadDiagnostic(selectedRun)}>
              <Icon name="download" size={15} />{text(copy.downloadTechnicalLog)}
            </button>
            <div className="scan-activity__log">
              <ol>
                {activity.events.map((event) => (
                  <li key={event.id}>
                    <span aria-hidden="true" />
                    <div>
                      <strong>{activityEventLabel(event)}</strong>
                      <time dateTime={event.occurredAt}>{showDateTime(event.occurredAt)}</time>
                    </div>
                  </li>
                ))}
              </ol>
            </div>
            <small className="scan-activity__privacy"><Icon name="lock" size={13} />{text(copy.diagnosticPrivacy)}</small>
          </details>
        </section>
      )}

      <details className="page-technical-details page-technical-details--guide">
        <summary>{text(copy.scanTechnicalDetails)}</summary>
        <dl>
          <div><dt>{text(copy.runIdTitle)}</dt><dd><code>{selectedRun.id}</code></dd></div>
          <div><dt>{text(copy.knowledgeTitle)}</dt><dd>{knowledgeRange}</dd></div>
        </dl>
        <p>{text(copy.caseSnapshot, { date: showDateTime(selectedRun.knowledgeDate) })}</p>
        <div className="engine-state-ledger" aria-label={text(copy.ledgerAria)}>
          <span>{text(copy.scannerStates)}</span>
          {engineStates.map((state) => (
            <span key={state} className="engine-state-ledger__item">
              <StatusPill label={engineStatusMeta[state].label} tone={engineStatusMeta[state].tone} />
              <b>{formatNumber(stateCounts[state])}</b>
            </span>
          ))}
          <small>{text(copy.terminalCount, { done: formatNumber(terminalCount), total: formatNumber(selectedRun.engineRuns.length) })}</small>
        </div>
      </details>

      {!blocked && !sharedInfrastructureFailure && incompleteCount > 0 && (
        <div className="scan-attention-summary" role="status" aria-label={text(copy.metricsAria)}>
          {savedPlanAfterRestart && neverStartedPlannedCount > 0 && <span><StatusPill label={text(copy.notStartedStatus)} tone="warning" /><strong>{formatNumber(neverStartedPlannedCount)}</strong></span>}
          {!savedPlanAfterRestart && stateCounts.partial > 0 && <span><StatusPill label={text(copy.partial)} tone="warning" /><strong>{formatNumber(stateCounts.partial)}</strong></span>}
          {!savedPlanAfterRestart && stateCounts.failed + stateCounts.cancelled > 0 && <span><StatusPill label={text(copy.failedCancelled)} tone="danger" /><strong>{formatNumber(stateCounts.failed + stateCounts.cancelled)}</strong></span>}
          {stateCounts.not_executed > 0 && <span><StatusPill label={text(copy.notRun)} tone="warning" /><strong>{formatNumber(stateCounts.not_executed)}</strong></span>}
        </div>
      )}

      {incompleteNoticeVisible && (
        <InlineNotice tone="warning" title={text(copy.incompleteTitle)}>
          {/* Checks that finished without testing an asset did finish; only their next step differs. */}
          <p>{text(incompleteCount === unevaluatedCompletedCheckCount ? copy.untestedAssetsBody : copy.incompleteBody)}</p>
        </InlineNotice>
      )}

      <section className="section-block">
        <div className="section-heading section-heading--row">
          <div>
            <h2>{text(copy.workTitle)}</h2>
          </div>
          {!blocked && (
            <span className="count-label">{workCountLabel(selectedRun.engineRuns.length)}</span>
          )}
        </div>

        {blocked && blocked.skippedCheckCount > 0 ? (
          aggregateTechnicalRecords(
            selectedRun.engineRuns,
            text(copy.skippedTechnical, { count: formatNumber(blocked.skippedCheckCount) }),
          )
        ) : blocked ? (
          <EmptyState icon="progress" title={text(copy.noRecordedCheckTitle)} description={text(copy.noRecordedCheckDescription)} />
        ) : (
          <div className="engine-list">
            {sharedInfrastructureFailure && (
              aggregateTechnicalRecords(
                selectedRun.engineRuns.filter((engine) => engine.status !== "not_executed"),
                text(copy.aggregateTechnical, { count: formatNumber(sharedInfrastructureFailure.checkCount) }),
              )
            )}

            {skipped && !blocked && (
              <article className="engine-row engine-row--unknown engine-row--aggregate">
                <div className="engine-row__identity">
                  <span className="engine-icon engine-icon--unknown"><Icon name="info" size={19} /></span>
                  <span>
                    <strong>{text(copy.skippedGroupTitle, { count: formatNumber(skipped.checkCount) })}</strong>
                    <small>{text(skippedChecksNextStepFor(skipped.reasonCodes))}</small>
                  </span>
                </div>
                <div className="engine-row__progress">
                  {aggregateTechnicalRecords(
                    selectedRun.engineRuns.filter((engine) => engine.status === "not_executed"),
                    text(copy.skippedTechnical, { count: formatNumber(skipped.checkCount) }),
                  )}
                </div>
                <div className="engine-row__result">
                  <StatusPill label={engineStatusMeta.not_executed.label} tone={engineStatusMeta.not_executed.tone} />
                  <span>{workCountLabel(skipped.checkCount)}</span>
                </div>
              </article>
            )}

            {visibleEngineRuns.map((engine) => {
              const meta = engineStatusMeta[engine.status];
              const checkpoint = engine.checkpoint;
              const recoveryMode = canResume ? engineRecoveryModeFor(engine) : undefined;
              const localhostSummary = localhostTcpBeginnerSummary(engine);
              const localhostTone = !localhostSummary
                ? undefined
                : localhostSummary.outcome === "reachable"
                  ? "info"
                  : localhostSummary.outcome === "failed"
                    ? "danger"
                    : localhostSummary.outcome === "in_progress" || localhostSummary.outcome === "cancelling"
                      ? meta.tone
                      : "warning";
              const unevaluatedTarget = engineRecordedUnevaluatedTarget(engine);
              const showEngineAttention = engine.status !== "completed" || Boolean(localhostSummary) || unevaluatedTarget;
              return (
                <article key={engine.id} className={`engine-row engine-row--${localhostTone ?? (unevaluatedTarget ? "warning" : meta.tone)}${showEngineAttention ? "" : " engine-row--compact"}`}>
                  <div className="engine-row__identity">
                    <span className={`engine-icon engine-icon--${meta.tone}`}><Icon name={engineIcon(engine)} size={19} /></span>
                    <span>
                      <strong>{text(engineOutcomeFor(engine))}</strong>
                      {showEngineAttention && <small>{text(engineNextStepFor(engine))}</small>}
                    </span>
                  </div>
                  {showEngineAttention && <div className="engine-row__progress">
                    {savedPlanAfterRestart || engine.status === "not_executed" ? (
                      <div className="engine-not-executed">
                        <Icon name="info" size={16} />
                        <span><strong>{text(copy.notStarted)}</strong><small>{text(engineNextStepFor(engine))}</small></span>
                      </div>
                    ) : (
                      <ProgressBar value={engine.progress} label={text(copy.checkProgress)} tone={engine.status === "failed" ? "danger" : engine.status === "partial" ? "warning" : "accent"} />
                    )}
                    <details className="page-technical-details">
                      <summary>{text(copy.technicalDetails)}</summary>
                      <div className="engine-phase-line">
                        <span>{text(copy.currentStep)}<strong>{phaseLabel(engine)}</strong></span>
                      </div>
                      {engine.status === "not_executed" && <p>{text(copy.notRunTechnical)}</p>}
                      {localhostSummary ? (
                        <dl>
                          <div><dt>{text(copy.builtInCheck)}</dt><dd>{text(localhostSummary.outcomeLabel)}</dd></div>
                          <div><dt>{text(copy.endpoint)}</dt><dd><code>127.0.0.1:{String(localhostSummary.port)}</code></dd></div>
                          <div><dt>{text(copy.timeout)}</dt><dd>{formatNumber(localhostSummary.timeoutMs)} ms</dd></div>
                          <div><dt>{text(copy.payload)}</dt><dd>{text(copy.bytes, { count: formatNumber(localhostSummary.payloadBytes) })}</dd></div>
                        </dl>
                      ) : (
                        <dl>
                          <div><dt>{text(copy.scannerName)}</dt><dd>{engine.engineName}</dd></div>
                          <div><dt>{text(copy.targets)}</dt><dd>{formatNumber(engine.assetIds.length)}</dd></div>
                          <div><dt>{text(copy.rawEvidenceFiles)}</dt><dd>{formatNumber(engine.rawArtifactCount)}</dd></div>
                        </dl>
                      )}
                      {!localhostSummary && checkpoint && (
                        <div className="checkpoint-card">
                          <div>
                            <Icon name="database" size={15} />
                            <strong>{text(copy.checkpoint)}</strong>
                            <StatusPill label={executionStageMeta[checkpoint.stage].label} tone={engine.status === "failed" ? "danger" : engine.status === "partial" || engine.status === "paused" ? "warning" : "neutral"} />
                          </div>
                          <dl>
                            <div><dt>{text(copy.attempt)}</dt><dd>#{formatNumber(checkpoint.attempt)}</dd></div>
                            <div><dt>{text(copy.evidence)}</dt><dd>{text(copy.evidenceCount, { count: formatNumber(checkpoint.artifactCount) })}</dd></div>
                            <div>
                              <dt>{text(copy.authorizationPlan)}</dt>
                              <dd>{engine.scopeContractBound
                                ? text(copy.authorizationFrozen)
                                : text(copy.authorizationUnknown)}</dd>
                            </div>
                            <div>
                              <dt>{text(copy.runtimeScope)}</dt>
                              <dd>{checkpoint.scopeBound
                                ? text(copy.runtimeScopeCreated)
                                : text(copy.runtimeScopeNotReached)}</dd>
                            </div>
                            <div><dt>{text(copy.cleanup)}</dt><dd>{checkpoint.cleanupCompleted ? text(copy.cleanupDone) : text(copy.cleanupPending)}</dd></div>
                          </dl>
                          <p>{executionStageMeta[checkpoint.stage].description}</p>
                        </div>
                      )}
                      <dl>
                        <div><dt>{text(copy.reportedPhase)}</dt><dd><code>{displayTechnicalDetail(engine.phase) ?? text(copy.noneReported)}</code></dd></div>
                        <div><dt>{text(copy.errorCode)}</dt><dd><code>{displayTechnicalDetail(engine.errorCode) ?? text(copy.noneReported)}</code></dd></div>
                        <div><dt>{text(localhostSummary ? copy.taskMessage : copy.scannerMessage)}</dt><dd>{displayTechnicalDetail(engine.message) ?? text(copy.noneReported)}</dd></div>
                        {!localhostSummary && <div><dt>{text(copy.checkpointError)}</dt><dd>{displayTechnicalDetail(checkpoint?.lastError) ?? text(copy.noneReported)}</dd></div>}
                      </dl>
                    </details>
                  </div>}
                  <div className="engine-row__result">
                    <StatusPill
                      label={localhostSummary
                        ? text(localhostSummary.outcomeLabel)
                        : savedPlanAfterRestart
                          ? text(copy.notStartedStatus)
                          : meta.label}
                      tone={localhostTone ?? (savedPlanAfterRestart ? "warning" : meta.tone)}
                    />
                    <span>{localhostSummary
                      ? `127.0.0.1:${String(localhostSummary.port)}`
                      : engine.findingCountKnown === false
                        ? text(copy.legacyFindingUnknown)
                        : text(copy.findingCount, { count: formatNumber(engine.findingCount) })}</span>
                    {recoveryMode && (
                      <span className="engine-row__recovery">{text(recoveryMode)}</span>
                    )}
                  </div>
                  <details className="engine-provenance">
                    <summary>{text(localhostSummary ? copy.technicalDetails : copy.provenance)}</summary>
                    {localhostSummary ? (
                      <dl>
                        <div><dt>{text(copy.taskId)}</dt><dd><code>{engine.id}</code></dd></div>
                        <div><dt>{text(copy.endpoint)}</dt><dd><code>127.0.0.1:{String(localhostSummary.port)}</code></dd></div>
                        <div><dt>{text(copy.timeout)}</dt><dd>{formatNumber(localhostSummary.timeoutMs)} ms</dd></div>
                        <div><dt>{text(copy.payload)}</dt><dd>{text(copy.bytes, { count: formatNumber(localhostSummary.payloadBytes) })}</dd></div>
                        <div><dt>{text(copy.observedOutcome)}</dt><dd>{text(localhostSummary.outcomeLabel)}</dd></div>
                        <div><dt>{text(copy.savedObservation)}</dt><dd><code>{engine.localhostTcpObservation?.outcome ?? text(copy.noneReported)}</code></dd></div>
                        <div><dt>{text(copy.observedAt)}</dt><dd>{showDateTime(engine.localhostTcpObservation?.observedAt)}</dd></div>
                        <div><dt>{text(copy.notIncluded)}</dt><dd>{text(localhostSummary.exclusions)}</dd></div>
                        <div><dt>{text(copy.started)}</dt><dd>{showDateTime(engine.startedAt)}</dd></div>
                        <div><dt>{text(copy.ended)}</dt><dd>{showDateTime(engine.finishedAt)}</dd></div>
                      </dl>
                    ) : (
                      <dl>
                        <div><dt>{text(copy.jobId)}</dt><dd><code>{engine.id}</code></dd></div>
                        <div><dt>{text(copy.engineId)}</dt><dd><code>{engine.engineId}</code></dd></div>
                        <div><dt>{text(copy.categoryCode)}</dt><dd><code>{engine.category}</code></dd></div>
                        <div><dt>{text(copy.scannerVersion)}</dt><dd>{scannerVersionLabel(engine.version, engine.reportedVersion, "exact", locale)}</dd></div>
                        <div><dt>{text(copy.imageDigest)}</dt><dd><code>{engine.digest}</code></dd></div>
                        <div><dt>{text(copy.ruleVersion)}</dt><dd>{engine.ruleVersion ?? text(copy.noneReported)}</dd></div>
                        <div><dt>{text(copy.adapter)}</dt><dd>{engine.adapterVersion ?? text(copy.noneReported)}</dd></div>
                        <div><dt>{text(copy.manifestSchema)}</dt><dd>{engine.manifestSchemaVersion ?? text(copy.noneReported)}</dd></div>
                        <div><dt>{text(copy.sourceRevision)}</dt><dd><code>{engine.sourceRevision ?? text(copy.noneReported)}</code></dd></div>
                        <div><dt>{text(copy.sourceRepository)}</dt><dd>{engine.repositoryUrl ?? text(copy.noneReported)}</dd></div>
                        <div><dt>{text(copy.distributionMode)}</dt><dd>{engine.distributionMode ?? text(copy.noneReported)}</dd></div>
                        <div><dt>{text(copy.imageRepository)}</dt><dd>{engine.imageRepository ?? text(copy.noneReported)}</dd></div>
                        <div><dt>{text(copy.commandDigest)}</dt><dd><code>{engine.commandSha256 ?? text(copy.noneReported)}</code></dd></div>
                        <div><dt>{text(copy.knowledgeInput)}</dt><dd>{engine.knowledgeInput
                          ? `${engine.knowledgeInput.identifier} · ${engine.knowledgeInput.version ?? text(copy.noIndependentVersion)} · ${engine.knowledgeInput.pinState}`
                          : text(copy.noneReported)}</dd></div>
                        <div><dt>{text(copy.knowledgeDate)}</dt><dd>{engine.knowledgeInput?.knowledgeDate ? showPlainDate(engine.knowledgeInput.knowledgeDate) : text(copy.olderNotRecorded)}</dd></div>
                        <div><dt>{text(copy.runtime)}</dt><dd>{engine.runtimeProvider ? `${engine.runtimeProvider} ${engine.runtimeVersion ?? text(copy.unknownVersion)}` : text(copy.notRunYet)}</dd></div>
                        <div><dt>{text(copy.runtimeSecurity)}</dt><dd>{engine.runtimeSecurityOptions ?? text(copy.noneReported)}</dd></div>
                        <div><dt>{text(copy.exitCode)}</dt><dd>{engine.exitCode ?? text(copy.noneReported)}</dd></div>
                        <div><dt>{text(copy.cleanupResult)}</dt><dd>
                          {engine.cleanupRemoved === undefined ? text(copy.noneReported) : engine.cleanupRemoved ? text(copy.removed) : text(copy.absentOrUnneeded)}
                          {engine.cleanupDetail ? ` · ${displayTechnicalDetail(engine.cleanupDetail) ?? ""}` : ""}
                        </dd></div>
                        <div><dt>{text(copy.started)}</dt><dd>{showDateTime(engine.startedAt)}</dd></div>
                        <div><dt>{text(copy.ended)}</dt><dd>{showDateTime(engine.finishedAt)}</dd></div>
                      </dl>
                    )}
                    {engine.warnings.length > 0 && (
                      <div className="engine-not-executed">
                        <Icon name="info" size={16} />
                        <span><strong>{text(copy.warnings)}</strong><small>{displayTechnicalDetail(engine.warnings.map((warning) => localizedEngineWarning(warning, locale)).join(locale === "zh-TW" ? "；" : "; "))}</small></span>
                      </div>
                    )}
                  </details>
                </article>
              );
            })}
          </div>
        )}
      </section>

      <details className="section-block section-block--muted page-secondary-feature">
        <summary>{text(copy.runHistorySummary, { count: formatNumber(runs.length) })}</summary>
        <div className="history-list">
          {runs.map((run) => {
            const historyRequestOutcome = scanRequestOutcomeBeginnerSummary(run.requestOutcome);
            const historyBlocked = blockedRunSummary(run);
            const historySharedFailure = sharedInfrastructureFailureSummary(run);
            const historyNeverStarted = isNeverStartedScanRun(run) && !activeRunStatuses.has(run.status);
            return (
              <button key={run.id} type="button" className={run.id === selectedRun.id ? "history-row history-row--active" : "history-row"} onClick={() => selectRun(run.id)}>
                <span className="history-row__line" aria-hidden="true" />
                <span className="history-row__copy">
                  <strong>{scanRunIdentityPresentation(run, locale)}</strong>
                  <span>{showDateTime(run.startedAt)} · {text(copy.historySnapshot, { date: showDateTime(run.knowledgeDate) })}</span>
                </span>
                <StatusPill
                  label={historyBlocked
                    ? historyRequestOutcome
                      ? runStatusMeta[run.status].label
                      : text(copy.blockedTitle)
                    : historySharedFailure
                      ? text(copy.sharedFailureTitle)
                      : historyNeverStarted
                        ? text(copy.notStartedStatus)
                        : runStatusMeta[run.status].label}
                  tone={historyRequestOutcome || historyBlocked || historyNeverStarted ? "warning" : historySharedFailure ? "danger" : runStatusMeta[run.status].tone}
                />
                <b>{historyBlocked || historySharedFailure ? text(copy.historyNotStarted)
                  : historyNeverStarted
                    ? text(copy.historyNotStarted)
                    : `${formatNumber(scanRunOverallProgress(run))}%`}</b>
              </button>
            );
          })}
        </div>
      </details>
    </div>
  );
}
