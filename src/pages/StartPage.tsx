import { localizeJapanese, type Locale } from "../i18n/core";
import { useEffect, useState, type ReactNode } from "react";

import { Icon } from "../components/Icon";
import {
  DEFAULT_LOCALHOST_QUICK_SCAN_PORT,
  parseLocalhostQuickScanPort,
} from "../localhostQuickScan";
import { primaryScanTiming } from "../primaryScanTiming";
import {
  useCaseDefinitions,
  type StartPageCopy,
  type UseCaseDefinition,
  type UseCaseId,
} from "../useCases";

import "../start-page.css";

interface StartPageProps {
  locale: Locale;
  copy: StartPageCopy;
  setup?: ReactNode;
  setupFocusKey?: number;
  nativeMode: boolean;
  localhostQuickScanBusy?: boolean;
  onStartLocalhostQuickScan: (port: number) => void;
  onChoose: (useCase: UseCaseDefinition) => void;
  onOpenExistingCase?: () => void;
}

interface MarketingCopy {
  title: string;
  description: string;
  previewDescription: string;
  localhostQuickScanAction: string;
  localhostQuickScanBusy: string;
  localhostQuickScanBoundary: string;
  localhostQuickScanOptions: string;
  localhostQuickScanPortLabel: string;
  localhostQuickScanPortHelp: string;
  localhostQuickScanPortError: string;
  connectionToolsTitle: string;
  connectionToolsDescription: string;
  choiceTitle: string;
  scopeAndLimits: string;
  moreWaysTitle: string;
  moreWaysDescription: string;
  controlSummary: string;
  cards: Record<UseCaseId, { title?: string; outcome: string; timing?: string; action: string }>;
}

const marketingCopyBase: Record<Exclude<Locale, "ja">, MarketingCopy> = {
  en: {
    title: "Security checks",
    description: "Scan repositories, websites or APIs, and specific internal systems together. Get one prioritized result organized by asset.",
    previewDescription: "Preview mode · choose a target to review its setup.",
    localhostQuickScanAction: "Test local service connection · 127.0.0.1:9001",
    localhostQuickScanBusy: "Testing the connection…",
    localhostQuickScanBoundary:
      "Connectivity only: one TCP connection to 127.0.0.1:9001, no payload, up to 3 seconds. This is not a vulnerability scan and does not check this computer for security problems.",
    localhostQuickScanOptions: "Use a different local port",
    localhostQuickScanPortLabel: "Local port",
    localhostQuickScanPortHelp: "Enter a port from 1 to 65535.",
    localhostQuickScanPortError: "Enter a whole-number port from 1 to 65535.",
    connectionToolsTitle: "Connection utility (not a security scan)",
    connectionToolsDescription: "Use this only to see whether one local service accepts a TCP connection.",
    choiceTitle: "Choose a target",
    scopeAndLimits: "Scope and limits",
    moreWaysTitle: "More ways to scan",
    moreWaysDescription: "Public or internal systems, cloud accounts, infrastructure code, containers, and Kubernetes",
    controlSummary: "How scanning stays under your control",
    cards: {
      deployed_website: {
        outcome: "Find website vulnerabilities and exposed services within the selected website origin.",
        timing: primaryScanTiming.en,
        action: "Check a website",
      },
      external_ip_or_domain: {
        outcome: "Inventory the ports and services your organization exposes to the public Internet.",
        action: "Check public exposure",
      },
      internal_it_environment: {
        title: "Company IT environment",
        outcome: "Check repositories, websites or APIs, and specific internal hosts together in one result organized by asset.",
        timing: primaryScanTiming.en,
        action: "Scan my environment",
      },
      ai_application: {
        outcome: "Catch risky AI-generated code, exposed secrets, and vulnerable dependencies before they ship.",
        action: "Check an AI project",
      },
      source_code: {
        title: "Code or AI project",
        outcome: "Find exposed secrets, vulnerable dependencies, risky code, and unsafe configuration in one local project.",
        timing: primaryScanTiming.en,
        action: "Check code or an AI project",
      },
      infrastructure_as_code: {
        outcome: "Find risky cloud and deployment settings before they go live.",
        action: "Check infrastructure code",
      },
      cloud_account: {
        outcome: "Turn a cloud account's identity and access settings into a prioritized fix list.",
        action: "Check a cloud account",
      },
      container_image: {
        outcome: "Know what is inside an image and which known vulnerabilities need attention.",
        action: "Check a container image",
      },
      kubernetes: {
        outcome: "Find workload and node settings that leave your Kubernetes environment exposed.",
        action: "Check Kubernetes",
      },
    },
  },
  "zh-TW": {
    title: "資安檢查",
    description: "把程式碼儲存庫、網站或 API 與指定的內部系統一起掃描，再依資產查看同一份優先結果。",
    previewDescription: "預覽模式 · 選擇目標以查看掃描設定。",
    localhostQuickScanAction: "測試本機服務連線 · 127.0.0.1:9001",
    localhostQuickScanBusy: "正在測試連線…",
    localhostQuickScanBoundary:
      "這只是連線測試：只嘗試一次到 127.0.0.1:9001 的 TCP 連線，不傳送內容，最長等待 3 秒。這不是漏洞掃描，也不會檢查這台電腦的資安問題。",
    localhostQuickScanOptions: "改用其他本機連接埠",
    localhostQuickScanPortLabel: "本機連接埠",
    localhostQuickScanPortHelp: "請輸入 1 到 65535 的連接埠。",
    localhostQuickScanPortError: "請輸入 1 到 65535 的整數連接埠。",
    connectionToolsTitle: "連線工具（不是資安掃描）",
    connectionToolsDescription: "只有在你想確認單一個本機服務是否接受 TCP 連線時才使用。",
    choiceTitle: "選擇目標",
    scopeAndLimits: "範圍與限制",
    moreWaysTitle: "更多檢查方式",
    moreWaysDescription: "公開或內部系統、雲端帳號、基礎設施程式碼、容器映像與 Kubernetes",
    controlSummary: "了解掃描如何由你控制",
    cards: {
      deployed_website: {
        outcome: "在所選網站來源範圍內找出弱點與暴露服務。",
        timing: primaryScanTiming.zhTW,
        action: "檢查網站",
      },
      external_ip_or_domain: {
        outcome: "盤點你的組織在公開網路上暴露的連接埠與服務。",
        action: "檢查對外暴露面",
      },
      internal_it_environment: {
        title: "公司 IT 環境",
        outcome: "把程式碼儲存庫、網站或 API 與指定的內部主機一起檢查，再依資產查看同一份結果。",
        timing: primaryScanTiming.zhTW,
        action: "掃描公司環境",
      },
      ai_application: {
        outcome: "在上線前抓出 AI 生成程式碼的危險寫法、暴露秘密與有弱點的相依套件。",
        action: "檢查 AI 專案",
      },
      source_code: {
        title: "程式碼或 AI 專案",
        outcome: "在一個本機專案找出暴露秘密、有弱點的相依套件、危險程式碼與不安全設定。",
        timing: primaryScanTiming.zhTW,
        action: "檢查程式碼或 AI 專案",
      },
      infrastructure_as_code: {
        outcome: "在部署前找出雲端與基礎設施設定裡的風險。",
        action: "檢查基礎設施程式碼",
      },
      cloud_account: {
        outcome: "把雲端帳號的身分與存取設定整理成有優先順序的改善清單。",
        action: "檢查雲端帳號",
      },
      container_image: {
        outcome: "看懂映像裡有哪些套件，以及哪些已知弱點需要先修。",
        action: "檢查容器映像",
      },
      kubernetes: {
        outcome: "找出讓 Kubernetes 工作負載與節點暴露風險的設定。",
        action: "檢查 Kubernetes",
      },
    },
  },
};


const marketingCopy: Record<Locale, MarketingCopy> = {
  ...marketingCopyBase,
  ja: localizeJapanese(marketingCopyBase.en),
};

export function StartPage({
  locale,
  copy,
  setup,
  setupFocusKey,
  nativeMode,
  localhostQuickScanBusy = false,
  onStartLocalhostQuickScan,
  onChoose,
  onOpenExistingCase,
}: StartPageProps) {
  const marketing = marketingCopy[locale];
  const primaryUseCaseIds: readonly UseCaseId[] = [
    "internal_it_environment",
    "deployed_website",
    "source_code",
  ];
  const primaryUseCases = primaryUseCaseIds.map(
    (id) => useCaseDefinitions.find((useCase) => useCase.id === id)!,
  );
  const additionalUseCases = useCaseDefinitions.filter(
    (useCase) => !primaryUseCaseIds.includes(useCase.id),
  );
  const [localhostPortInput, setLocalhostPortInput] = useState(String(DEFAULT_LOCALHOST_QUICK_SCAN_PORT));
  const localhostPort = parseLocalhostQuickScanPort(localhostPortInput);
  const localhostPortDisplay = localhostPortInput.trim() || "—";
  const localhostQuickScanAction = marketing.localhostQuickScanAction.replace(
    String(DEFAULT_LOCALHOST_QUICK_SCAN_PORT),
    localhostPortDisplay,
  );
  const localhostQuickScanBoundary = marketing.localhostQuickScanBoundary.replace(
    String(DEFAULT_LOCALHOST_QUICK_SCAN_PORT),
    localhostPortDisplay,
  );

  useEffect(() => {
    if (!setupFocusKey) return undefined;
    const frame = window.requestAnimationFrame(() => {
      const setupSection = document.getElementById("start-page-runtime-setup");
      setupSection?.focus({ preventScroll: true });
      setupSection?.scrollIntoView({ block: "start" });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [setupFocusKey]);

  const renderUseCaseCard = (useCase: UseCaseDefinition) => {
    const card = copy.cards[useCase.id];
    const marketingCard = marketing.cards[useCase.id];
    return (
      <article className="use-case-card" key={useCase.id}>
        <header className="use-case-card__header">
          <span className="use-case-card__icon">
            <Icon name={useCase.icon} size={22} />
          </span>
          <div>
            <h3>{marketingCard.title ?? card.title}</h3>
            <p>{marketingCard.outcome}</p>
          </div>
        </header>

        {marketingCard.timing && (
          <p className="use-case-card__timing">{marketingCard.timing}</p>
        )}

        <button
          className="button button--secondary use-case-card__action"
          type="button"
          onClick={() => onChoose(useCase)}
        >
          {marketingCard.action}
          <Icon name="arrow" size={17} />
        </button>

      </article>
    );
  };

  return (
    <div className="page start-page">
      <section className="start-page__hero" aria-labelledby="start-page-title">
        <div className="start-page__hero-copy">
          <h1 id="start-page-title" data-page-heading tabIndex={-1}>{marketing.title}</h1>
          {(nativeMode ? marketing.description : marketing.previewDescription) && (
            <p className="start-page__hero-description">{nativeMode ? marketing.description : marketing.previewDescription}</p>
          )}
          <div className="start-page__hero-actions">
            {onOpenExistingCase && (
              <div className="start-page__hero-secondary-actions">
                <button className="button button--secondary" type="button" onClick={onOpenExistingCase}>
                  <Icon name="cases" size={18} />
                  {copy.existingCaseAction}
                </button>
              </div>
            )}
          </div>
        </div>
      </section>

      <section id="start-a-check" className="start-page__choices" aria-labelledby="use-case-choice-title">
        <div className="start-page__section-heading">
          <h2 id="use-case-choice-title">{marketing.choiceTitle}</h2>
        </div>

        <div className="use-case-grid">
          {primaryUseCases.map(renderUseCaseCard)}
        </div>

        <details className="start-page__more-use-cases">
          <summary>
            <span>
              <strong>{marketing.moreWaysTitle}</strong>
              <small>{marketing.moreWaysDescription}</small>
            </span>
            <Icon name="chevron" size={20} />
          </summary>
          <div className="use-case-grid">
            {additionalUseCases.map(renderUseCaseCard)}
          </div>
        </details>

        {nativeMode && (
          <details className="start-page__connection-tools">
            <summary>
              <span>
                <strong>{marketing.connectionToolsTitle}</strong>
                <small>{marketing.connectionToolsDescription}</small>
              </span>
              <Icon name="chevron" size={20} />
            </summary>
            <div className="start-page__localhost-quick-scan">
              <button
                className="button button--secondary start-page__connection-action"
                type="button"
                disabled={localhostQuickScanBusy || localhostPort === undefined}
                aria-busy={localhostQuickScanBusy}
                onClick={() => {
                  if (localhostPort !== undefined) onStartLocalhostQuickScan(localhostPort);
                }}
              >
                {localhostQuickScanBusy ? marketing.localhostQuickScanBusy : localhostQuickScanAction}
                <Icon name="arrow" size={18} />
              </button>
              <p className="start-page__localhost-boundary">{localhostQuickScanBoundary}</p>
              <details className="start-page__localhost-options">
                <summary>{marketing.localhostQuickScanOptions}</summary>
                <label htmlFor="localhost-quick-scan-port">{marketing.localhostQuickScanPortLabel}</label>
                <input
                  id="localhost-quick-scan-port"
                  type="number"
                  inputMode="numeric"
                  min={1}
                  max={65535}
                  step={1}
                  required
                  value={localhostPortInput}
                  aria-invalid={localhostPort === undefined}
                  aria-describedby="localhost-quick-scan-port-help"
                  onChange={(event) => setLocalhostPortInput(event.currentTarget.value)}
                />
                <small
                  id="localhost-quick-scan-port-help"
                  className={localhostPort === undefined ? "start-page__localhost-port-error" : undefined}
                  aria-live="polite"
                  aria-atomic="true"
                >
                  {localhostPort === undefined
                    ? marketing.localhostQuickScanPortError
                    : marketing.localhostQuickScanPortHelp}
                </small>
              </details>
            </div>
          </details>
        )}

        <details className="start-page__scan-limits">
          <summary>{marketing.scopeAndLimits}</summary>
          <div className="start-page__scan-limit-list">
            {useCaseDefinitions.map((useCase) => {
              const card = copy.cards[useCase.id];
              return (
                <section key={useCase.id} className="start-page__scan-limit">
                  <h3>{card.title}</h3>
                  <dl>
                    <div className="use-case-card__does">
                      <dt><Icon name="check" size={15} /> {copy.productDoesLabel}</dt>
                      <dd>{card.productDoes}</dd>
                    </div>
                    <div className="use-case-card__does-not">
                      <dt><Icon name="close" size={15} /> {copy.productDoesNotLabel}</dt>
                      <dd>{card.productDoesNot}</dd>
                    </div>
                  </dl>
                </section>
              );
            })}
          </div>
        </details>
      </section>

      {setup && (
        <aside id="start-page-runtime-setup" className="start-page__setup" tabIndex={-1}>
          {setup}
        </aside>
      )}

      <details className="start-page__scope-note">
        <summary>
          <Icon name="info" size={19} />
          <span>{marketing.controlSummary}</span>
        </summary>
        <div>
          <strong>{copy.scopeNoticeTitle}</strong>
          <p>{copy.scopeNotice}</p>
        </div>
      </details>
    </div>
  );
}
