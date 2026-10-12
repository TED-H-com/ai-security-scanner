import { localizeJapanese, type Locale } from "../i18n/core";
import { useMemo } from "react";

import type { ScannerSetupBlocker } from "../scanReadiness";
import {
  isDeveloperBuildPackagedRuntimeVerificationFailed,
  isDeveloperBuildWithoutPackagedRuntime,
  resolveRuntimeSetupPresentation,
} from "../runtimeSetupPresentation";
import type {
  AppMode,
  AppSnapshot,
  ManagedRuntimeSetupNextAction,
  ManagedRuntimeSetupPhase,
  ManagedRuntimeSetupStatus,
} from "../types";
import { Icon } from "./Icon";

import "../runtime-setup-assistant.css";

type RuntimeSetupLocale = Locale;

interface RuntimeSetupAssistantProps {
  locale: RuntimeSetupLocale;
  mode: AppMode;
  runtime?: AppSnapshot["runtime"];
  status?: ManagedRuntimeSetupStatus;
  busy?: boolean;
  scannerIssueBusy?: boolean;
  scannerSetupBlocker?: ScannerSetupBlocker;
  onSetup: () => void;
  onCheckScannerAvailability: () => void;
  onCancel: () => void;
}

interface RuntimeActionCopy {
  title: string;
  description: string;
  action?: string;
}

interface RuntimeAssistantCopy {
  eyebrow: string;
  title: string;
  description: string;
  readyTitle: string;
  readyDescription: string;
  idleTitle: string;
  idleDescription: string;
  demoTitle: string;
  demoDescription: string;
  progressTitle: string;
  progressDescription: string;
  staleTitle: string;
  staleDescription: string;
  recoveryTitle: string;
  recoveryDescription: string;
  cancelledTitle: string;
  cancelledDescription: string;
  start: string;
  continue: string;
  retry: string;
  starting: string;
  cancel: string;
  cancelling: string;
  technical: string;
  downloaded: string;
  resumed: string;
  failedTitle: string;
  failedDescription: string;
  nonRetryableTitle: string;
  nonRetryableDescription: string;
  developerBuildTitle: string;
  developerBuildDescription: string;
  developerBuildUnverifiedTitle: string;
  developerBuildUnverifiedDescription: string;
  scannerIssues: Partial<Record<ScannerSetupBlocker, {
    title: string;
    description: string;
    action: string;
  }>>;
  phases: Record<ManagedRuntimeSetupPhase, string>;
  actions: Record<ManagedRuntimeSetupNextAction, RuntimeActionCopy>;
}

const copyBase: Record<Exclude<Locale, "ja">, RuntimeAssistantCopy> = {
  en: {
    eyebrow: "ADVANCED LOCAL SCAN SETUP",
    title: "Preparing the local scan tools you requested",
    description: "Prepare the local tools required by the selected advanced scan.",
    readyTitle: "Advanced local scan tools were ready at the last check",
    readyDescription: "Choose an advanced local scan and get started. The app checks the tools again before it runs.",
    idleTitle: "This scan needs additional local tools",
    idleDescription: "Select Prepare scan tools to begin.",
    demoTitle: "Explore a scan with sample results",
    demoDescription: "Open the desktop app to scan a real website, cloud account, network, or codebase.",
    progressTitle: "Preparing the local scan tools you requested",
    progressDescription: "Downloading and preparing the tools needed for this scan.",
    staleTitle: "Stopping advanced local scan-tool setup",
    staleDescription: "Current setup step is stopping.",
    recoveryTitle: "Preparing a fresh advanced local scan workspace",
    recoveryDescription: "Preparing an isolated replacement workspace for this request.",
    cancelledTitle: "Advanced local scan-tool setup cancelled",
    cancelledDescription: "Scan-tool status: not ready.",
    start: "Prepare scan tools",
    continue: "Continue advanced scan setup",
    retry: "Try advanced scan setup again",
    starting: "Starting advanced scan setup…",
    cancel: "Stop advanced scan setup",
    cancelling: "Stopping…",
    technical: "Technical details",
    downloaded: "downloaded",
    resumed: "Existing download reused",
    failedTitle: "Advanced local scan-tool setup did not finish",
    failedDescription: "Try advanced scan setup again.",
    nonRetryableTitle: "An advanced local scan tool is unavailable in this app version",
    nonRetryableDescription: "Install a compatible app version to run this advanced check.",
    developerBuildTitle: "This developer build has no scan tools",
    developerBuildDescription: "Point it at a verified app bundle that includes them.",
    developerBuildUnverifiedTitle: "This developer build's scan tools failed verification",
    developerBuildUnverifiedDescription: "Fix the bundle or point it at a verified app bundle.",
    scannerIssues: {
      no_runnable_authorized_targets: {
        title: "This check is unavailable in the installed version",
        description: "Install the latest app version, then check availability again.",
        action: "Check availability again",
      },
      egress_gateway_unavailable: {
        title: "One installed scan component is unavailable",
        description: "Install the latest app version, then check availability again.",
        action: "Check availability again",
      },
      engine_execution_contract_invalid: {
        title: "One installed scan component is unavailable",
        description: "Install the latest app version, then check availability again.",
        action: "Check availability again",
      },
    },
    phases: {
      idle: "Ready to set up advanced local scans",
      install: "Preparing advanced local scan tools",
      prerequisite: "Checking advanced local scan requirements on this Windows computer",
      download: "Downloading advanced local scan tools",
      recovery: "Recovering the advanced local scan workspace",
      init: "Creating the advanced local scan workspace",
      start: "Starting advanced local scan tools",
      verify: "Running one final advanced-tool check",
      completed: "Advanced local scan tools ready",
      failed: "Advanced local scan-tool setup needs attention",
      cancelled: "Advanced local scan-tool setup cancelled",
    },
    actions: {
      install_wsl: {
        title: "Advanced local scan-tool setup did not finish",
        description: "Try advanced-tool setup again.",
      },
      enable_wsl_optional_features: {
        title: "Advanced local scan-tool setup did not finish",
        description: "Try advanced-tool setup again.",
      },
      update_wsl: {
        title: "Advanced local scan-tool setup did not finish",
        description: "Try advanced-tool setup again.",
      },
      restart_windows: {
        title: "Windows restart required for advanced local scan tools",
        description: "Restart Windows, reopen ai-security-scanner, then select Continue setup.",
        action: "Continue after restarting Windows",
      },
      retry_wsl_check: {
        title: "Advanced local scan-tool setup did not finish",
        description: "The advanced-tool check did not finish. Try setup again.",
      },
    },
  },
  "zh-TW": {
    eyebrow: "進階本機掃描設定",
    title: "正在準備你要求的本機掃描工具",
    description: "準備所選進階掃描需要的本機工具。",
    readyTitle: "進階本機掃描工具上次檢查時可用",
    readyDescription: "選擇進階本機掃描即可開始；程式會在執行前再次確認工具狀態。",
    idleTitle: "這項掃描需要額外的本機工具",
    idleDescription: "按下「準備掃描工具」即可開始。",
    demoTitle: "先用範例結果看看掃描怎麼運作",
    demoDescription: "準備掃描真實網站、雲端帳號、網路或程式碼時，再開啟桌面版即可。",
    progressTitle: "正在準備你要求的本機掃描工具",
    progressDescription: "正在下載並準備這項掃描所需的工具。",
    staleTitle: "正在停止進階本機掃描工具設定",
    staleDescription: "目前設定步驟正在停止。",
    recoveryTitle: "正在準備新的進階本機掃描隔離工作區",
    recoveryDescription: "正在為這次要求準備隔離的新工作空間。",
    cancelledTitle: "進階本機掃描工具設定已取消",
    cancelledDescription: "掃描工具狀態：尚未就緒。",
    start: "準備掃描工具",
    continue: "繼續進階掃描設定",
    retry: "再試一次進階掃描設定",
    starting: "正在開始進階掃描設定…",
    cancel: "停止進階掃描設定",
    cancelling: "正在停止…",
    technical: "技術細節",
    downloaded: "已下載",
    resumed: "已沿用先前下載進度",
    failedTitle: "進階本機掃描工具設定未能完成",
    failedDescription: "請再試一次進階掃描設定。",
    nonRetryableTitle: "這個程式版本無法使用一項進階本機掃描工具",
    nonRetryableDescription: "請安裝相容的程式版本，再執行這項進階檢查。",
    developerBuildTitle: "這個開發版未內建掃描工具",
    developerBuildDescription: "請指定一份已通過驗證、且含掃描工具的應用程式套件。",
    developerBuildUnverifiedTitle: "這個開發版的掃描工具驗證失敗",
    developerBuildUnverifiedDescription: "請修正套件，或改指定一份已通過驗證的應用程式套件。",
    scannerIssues: {
      no_runnable_authorized_targets: {
        title: "目前安裝版本無法執行這項檢查",
        description: "請安裝最新版本，再重新檢查可用性。",
        action: "重新檢查可用性",
      },
      egress_gateway_unavailable: {
        title: "一項隨附掃描元件目前無法使用",
        description: "請安裝最新版本，再重新檢查可用性。",
        action: "重新檢查可用性",
      },
      engine_execution_contract_invalid: {
        title: "一項隨附掃描元件目前無法使用",
        description: "請安裝最新版本，再重新檢查可用性。",
        action: "重新檢查可用性",
      },
    },
    phases: {
      idle: "可以開始設定進階本機掃描",
      install: "正在準備進階本機掃描工具",
      prerequisite: "正在檢查這台 Windows 電腦的進階本機掃描需求",
      download: "正在下載進階本機掃描工具",
      recovery: "正在復原進階本機掃描工作區",
      init: "正在建立進階本機掃描工作區",
      start: "正在啟動進階本機掃描工具",
      verify: "正在對進階工具做最後確認",
      completed: "進階本機掃描工具準備好了",
      failed: "進階本機掃描工具設定需要處理",
      cancelled: "進階本機掃描工具設定已取消",
    },
    actions: {
      install_wsl: {
        title: "進階本機掃描工具設定未能完成",
        description: "請再試一次進階工具設定。",
      },
      enable_wsl_optional_features: {
        title: "進階本機掃描工具設定未能完成",
        description: "請再試一次進階工具設定。",
      },
      update_wsl: {
        title: "進階本機掃描工具設定未能完成",
        description: "請再試一次進階工具設定。",
      },
      restart_windows: {
        title: "進階本機掃描工具需要重新啟動 Windows",
        description: "重新啟動 Windows，開啟 ai-security-scanner，再按下「繼續設定」。",
        action: "重新啟動 Windows 後繼續",
      },
      retry_wsl_check: {
        title: "進階本機掃描工具設定未能完成",
        description: "進階工具檢查未能完成；請再試一次設定。",
      },
    },
  },
};


const copy: Record<Locale, RuntimeAssistantCopy> = {
  ...copyBase,
  ja: localizeJapanese(copyBase.en),
};

const byteCount = (value: number, locale: RuntimeSetupLocale): string =>
  `${new Intl.NumberFormat(locale).format(value)} ${locale === "ja" ? "バイト" : locale !== "zh-TW" ? (value === 1 ? "byte" : "bytes") : "位元組"}`;

export function RuntimeSetupAssistant({
  locale,
  mode,
  runtime,
  status,
  busy,
  scannerIssueBusy,
  scannerSetupBlocker,
  onSetup,
  onCheckScannerAvailability,
  onCancel,
}: RuntimeSetupAssistantProps) {
  const text = copy[locale];
  const presentation = resolveRuntimeSetupPresentation({
    mode,
    runtimeAvailable: runtime?.available === true,
    status,
    requestPending: busy,
    blocker: scannerSetupBlocker,
  });
  const scannerIssue = presentation.showPackagedComponentIssue && scannerSetupBlocker
    ? text.scannerIssues[scannerSetupBlocker]
    : undefined;
  const {
    ready,
    setupStarting,
    setupActive,
    setupRecovering,
    setupStale,
    setupFailed,
    setupCancelled,
    setupIdleUnavailable,
    setupNonRetryable,
  } = presentation;
  const nextAction = status?.nextAction ? text.actions[status.nextAction] : undefined;
  const technicalDetail = setupFailed ? "local_scan_tool_unavailable" : undefined;
  const progress = useMemo(() => {
    if (!status?.totalBytes || status.totalBytes <= 0) return undefined;
    return Math.min(status.receivedBytes, status.totalBytes);
  }, [status?.receivedBytes, status?.totalBytes]);

  if (ready) {
    return (
      <section className="runtime-assistant runtime-assistant--ready" aria-label={text.title}>
        <span className="runtime-assistant__icon"><Icon name="check" size={23} /></span>
        <div>
          <strong>{text.readyTitle}</strong>
          <p>{text.readyDescription}</p>
        </div>
      </section>
    );
  }

  if (mode !== "native") {
    return (
      <section className="runtime-assistant runtime-assistant--demo" aria-label={text.title}>
        <span className="runtime-assistant__icon"><Icon name="info" size={23} /></span>
        <div>
          <strong>{text.demoTitle}</strong>
          <p>{text.demoDescription}</p>
        </div>
      </section>
    );
  }

  const developerBuild = isDeveloperBuildWithoutPackagedRuntime(status);
  const developerBuildUnverified = isDeveloperBuildPackagedRuntimeVerificationFailed(status);
  const title = scannerIssue?.title ?? (setupNonRetryable
    ? (developerBuild
      ? text.developerBuildTitle
      : developerBuildUnverified
        ? text.developerBuildUnverifiedTitle
        : text.nonRetryableTitle)
    : setupFailed
      ? nextAction?.title ?? text.failedTitle
      : setupCancelled
        ? text.cancelledTitle
        : setupStale
          ? text.staleTitle
          : setupRecovering
            ? text.recoveryTitle
            : setupActive
              ? text.progressTitle
              : setupIdleUnavailable
                ? text.idleTitle
                : text.title);
  const description = scannerIssue?.description ?? (setupNonRetryable
    ? (developerBuild
      ? text.developerBuildDescription
      : developerBuildUnverified
        ? text.developerBuildUnverifiedDescription
        : text.nonRetryableDescription)
    : setupFailed && nextAction
      ? nextAction.description
      : setupFailed
        ? text.failedDescription
        : setupCancelled
          ? text.cancelledDescription
          : setupStale
            ? text.staleDescription
            : setupRecovering
              ? text.recoveryDescription
              : setupActive
                ? text.progressDescription
                : setupIdleUnavailable
                  ? text.idleDescription
                  : text.description);

  return (
    <section
      className={`runtime-assistant${setupFailed || setupNonRetryable ? " runtime-assistant--failed" : ""}`}
      aria-labelledby="runtime-assistant-title"
      aria-live="polite"
    >
      <header className="runtime-assistant__header">
        <span className="runtime-assistant__icon">
          <Icon name={setupFailed || setupNonRetryable ? "warning" : "settings"} size={23} />
        </span>
        <div>
          <p className="eyebrow">{text.eyebrow}</p>
          <h2 id="runtime-assistant-title">{title}</h2>
          <p>{description}</p>
        </div>
      </header>

      {!scannerIssue && setupStarting && (
        <div className="runtime-assistant__status" role="status">
          <strong>{text.starting}</strong>
        </div>
      )}

      {!scannerIssue && !setupStarting && !setupNonRetryable && status && status.phase !== "idle" && (
        <div className="runtime-assistant__status" role="status">
          <strong>{text.phases[status.phase as ManagedRuntimeSetupPhase]}</strong>
          {progress !== undefined && status.totalBytes !== undefined && (
            <>
              <progress max={status.totalBytes} value={progress} />
              <span>
                {byteCount(status.receivedBytes, locale)} / {byteCount(status.totalBytes, locale)} · {text.downloaded}
              </span>
            </>
          )}
          {status.resumedFromBytes > 0 && <span>{text.resumed}</span>}
        </div>
      )}

      <div className="runtime-assistant__actions">
        {scannerIssue ? (
          <button
            className="button button--primary"
            type="button"
            disabled={scannerIssueBusy}
            onClick={onCheckScannerAvailability}
          >
            <Icon name="refresh" size={17} />
            {scannerIssue.action}
          </button>
        ) : setupStarting ? (
          <button className="button button--primary" type="button" disabled aria-busy="true">
            <Icon name="progress" size={17} />
            {text.starting}
          </button>
        ) : setupActive ? (
          <button
            className="button button--danger-ghost"
            type="button"
            disabled={!status?.canCancel || status.cancelRequested}
            onClick={onCancel}
          >
            <Icon name="close" size={16} />
            {status?.cancelRequested ? text.cancelling : text.cancel}
          </button>
        ) : setupNonRetryable || (!setupFailed && !setupCancelled && !setupIdleUnavailable) ? null : (
          <button className="button button--primary" type="button" disabled={busy} onClick={onSetup}>
            <Icon name="refresh" size={17} />
            {setupFailed ? nextAction?.action ?? text.retry : setupCancelled ? text.continue : text.start}
          </button>
        )}
      </div>

      {technicalDetail && setupFailed && (
        <details className="runtime-assistant__technical">
          <summary>{text.technical}</summary>
          <code>{technicalDetail}</code>
        </details>
      )}
    </section>
  );
}
