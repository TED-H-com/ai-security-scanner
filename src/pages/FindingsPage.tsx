import { type FormEvent, type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { ScannerMarkdown } from "../components/ScannerMarkdown";

import {
  confidenceMeta,
  engineStatusMeta,
  severityMeta,
  workflowMeta,
} from "../lib";
import { useI18n, type BilingualTextTranslator, type Locale } from "../i18n";
import {
  unavailableRunBoundReportCopy,
  unavailableSelectedRunCopy,
} from "../findingsReportAvailability";
import { localizedCoverageDimension } from "../coverageDimensionPresentation";
import { projectVisibleFindingGroups } from "../findingGroupPresentation";
import { problemGroupAction, problemGroupImpact, problemGroupTitle, projectProblemRows } from "../reportProblemPresentation";
import { isExposureObservation, isSecurityFinding } from "../findingClassification";
import {
  awsIamPolicySourceLabel,
  beginnerStepAction,
  engineNameFrom,
  findingActionSentence,
  findingUnconfirmedByCoverage,
  findingConfidencePresentation,
  benchmarkLine,
  findingPriorityReason,
  priorityGuidanceReason,
  findingUnattributedGap,
  coverageGapProse,
  coverageGapProseWithoutDiagnosticCode,
  findingRollbackSentence,
  findingVerificationSentence,
  findingHeadline,
  stepConfirmation,
  stepGroupLead,
  findingImpactSentence,
  findingLocationText,
  isEvidenceOnlyPriorityReason,
  findingSeverityIsUnrated,
  findingSummarySentence,
  localizedControlMappingRationale,
  localizedExpertType,
  localizedDataQualityWarning,
  localizedRequestedLimitKind,
  localizedRequestedLimitValue,
  localizedTestedValue,
  requestedLimitParts,
  testedObservationProse,
} from "../findingNarrative.ts";
import {
  localhostTcpBeginnerSummary,
  localhostTestedDimensionValue,
} from "../localhostTcpPresentation";
import { scannerVersionLabel } from "../scannerVersionPresentation";
import {
  isExactBuiltInLocalhostQuickScanEngine,
  isExactBuiltInLocalhostQuickScanRun,
} from "../localhostQuickScan";
import { scanRequestOutcomeBeginnerSummary } from "../scanRequestOutcomePresentation";
import { scanRunIdentityPresentation } from "../scanRunIdentityPresentation";
import { legacyCheckResultKind } from "../checkResultKind";
import { isSettledSkippedCheck } from "../settledSkippedChecks";
import type {
  BenchmarkReference,
  BeginnerCheckResultKind,
  BeginnerCoverageStatus,
  BeginnerTechnicalExecution,
  BeginnerInventoryItem,
  BeginnerMasterReport,
  BeginnerNextActionCode,
  BeginnerRequestedTarget,
  BeginnerReportStage,
  BeginnerReportSummary,
  CorrelationReport,
  CorroborationStatus,
  Finding,
  FindingGroup,
  FindingGroupEvent,
  FindingWorkflowEvent,
  FindingWorkflowState,
  FindingWorkflowUpdateInput,
  ScanRun,
  Severity,
} from "../types";
import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, MetricCard, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";

import "./page-technical-details.css";

interface FindingsPageProps {
  report?: BeginnerMasterReport;
  selectedRunId?: string;
  runningScanResultsPending?: boolean;
  reportUnavailable?: boolean;
  findings: Finding[];
  findingGroups: FindingGroup[];
  findingGroupEvents: FindingGroupEvent[];
  /**
   * Undefined when the suggestion read has not returned or failed. That is not
   * the same as an empty report, and must not be rendered as "nothing related".
   */
  correlationReport?: CorrelationReport;
  runs: ScanRun[];
  focusedFindingId?: string;
  workflowEvents: FindingWorkflowEvent[];
  busy: boolean;
  onUpdateWorkflow: (input: Omit<FindingWorkflowUpdateInput, "caseId">) => Promise<boolean>;
  onGroupFindings: (input: { title: string; findingIds: string[]; rationale: string }) => Promise<boolean>;
  onUngroupFindings: (groupId: string) => Promise<void>;
  onOpenCoverage: () => void;
  onOpenProgress: () => void;
  onOpenExport: (runId: string) => void;
  onSelectRun?: (runId: string) => void;
}

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "unknown", "info"];
const activeRunStatuses = new Set<ScanRun["status"]>(["queued", "running", "paused"]);
const workflowOrder = Object.keys(workflowMeta) as FindingWorkflowState[];
const narrowFindingLayout = "(max-width: 1050px)";

const scrollToSelectedFinding = (scrollOnWideLayout = true): void => {
  const narrow = window.matchMedia?.(narrowFindingLayout).matches ?? window.innerWidth <= 1050;
  if (!narrow && !scrollOnWideLayout) return;
  const target = narrow
    ? document.querySelector<HTMLElement>(".finding-detail:not(.finding-detail--empty)")
    : document.getElementById("finding-browser");
  target?.scrollIntoView?.({ behavior: "smooth", block: "start" });
};

const scrollToReportScope = (): void => {
  document.getElementById("beginner-master-report-title")?.scrollIntoView?.({ behavior: "smooth", block: "start" });
};

const decisionStates = [
  "unreviewed",
  "expert_review_requested",
  "confirmed",
  "false_positive",
  "remediation_reported",
  "verified_resolved",
] as const;
const controlKey = (framework: string, version: string, controlId: string): string =>
  JSON.stringify([framework, version, controlId]);

// Mirrors `UNTRUSTED_EVIDENCE_CAVEAT` in src-tauri/src/case_service.rs. The
// shared report strips this exact trailing sentence before deciding whether an
// evidence summary says anything past it; this page makes the same decision.
const UNTRUSTED_EVIDENCE_CAVEAT = " Raw target text is retained only as untrusted evidence.";

const copy = {
  eyebrow: { en: "PROBLEMS FOUND", zhTW: "發現的問題" },
  resultsEyebrow: { en: "SCAN RESULTS", zhTW: "掃描結果" },
  title: {
    en: "Know what to fix first",
    zhTW: "先知道該修什麼",
  },
  description: {
    en: "Review the highest-priority problems and next actions.",
    zhTW: "先看最高優先問題與下一步。",
  },
  scopeLimitations: { en: "Scope & limitations", zhTW: "掃描範圍與限制" },
  scopeSummary: {
    en: "{completed} completed · {gaps} gaps",
    zhTW: "完成 {completed} 項 · {gaps} 個缺口",
  },
  scopeAttentionSummary: {
    en: "{completed} completed · {gaps} gaps or checks without verdicts",
    zhTW: "完成 {completed} 項 · {gaps} 個缺口或未回傳判定的檢查",
  },
  reportBoundary: {
    en: "NIST and ISO references and AIDEFEND's independent, unofficial mapping are navigation only. This report is not an audit, certification, compliance decision, security guarantee, or automatic remediation.",
    zhTW: "NIST、ISO 參考與 AIDEFEND 的獨立非官方對照只供導航。本報告不是稽核、認證、合規判定、資安保證或自動修復。",
  },
  // Said once at the end, only when some retained summary needed it, rather
  // than the same sentence stapled to every evidence record on the page.
  untrustedEvidenceTerms: {
    en: "Target text quoted in an evidence summary is retained as untrusted input and is not interpreted by this report.",
    zhTW: "證據摘要引用的目標文字，是以不受信任的輸入形式保留，本報告不會加以解讀。",
  },
  relatedGroups: { en: "Related findings & groups", zhTW: "相關問題與群組" },
  reviewHistory: { en: "Resolution status & history", zhTW: "解決狀態與歷程" },
  emptyHeaderTitle: { en: "Problem list", zhTW: "問題清單" },
  emptyHeaderDescription: {
    en: "Review this run's outcome and next action.",
    zhTW: "查看這輪掃描的結果與下一步。",
  },
  connectionHeaderEyebrow: { en: "CONNECTION RESULT", zhTW: "連線結果" },
  connectionHeaderTitle: {
    en: "Connection test only — no vulnerability scan ran",
    zhTW: "這只是連線測試，沒有執行漏洞掃描",
  },
  connectionHeaderDescription: {
    en: "One local TCP port was checked. Choose an applicable security scan to look for weaknesses.",
    zhTW: "已檢查一個本機 TCP 連接埠；請選擇適用的資安掃描來尋找弱點。",
  },
  nonSecurityHeaderEyebrow: { en: "INVENTORY / CONNECTIVITY", zhTW: "盤點／連線" },
  nonSecurityHeaderTitle: {
    en: "Inventory or connectivity only — no security check ran",
    zhTW: "只完成盤點或連線工作，沒有執行資安檢查",
  },
  nonSecurityHeaderDescription: {
    en: "This run completed inventory or connectivity, not a security check. Choose an applicable security scan.",
    zhTW: "本輪完成盤點或連線工作，未執行資安檢查；請選擇適用的資安掃描。",
  },
  nonSecurityEmptyTitle: { en: "Inventory or connectivity results", zhTW: "盤點或連線結果" },
  nonSecurityEmptyDescription: {
    en: "The completed work records inventory or connectivity only. Choose an applicable security check to look for weaknesses.",
    zhTW: "已完成的工作只記錄盤點或連線資訊。若要尋找弱點，請選擇適用的資安檢查。",
  },
  observationsEyebrow: { en: "SERVICE INVENTORY", zhTW: "服務盤點" },
  observationsTitle: {
    en: "Reachable services observed — not vulnerabilities",
    zhTW: "觀察到可連線服務，但這些不是漏洞",
  },
  observationsDescription: {
    en: "These services responded. Reachability is inventory, not a security weakness.",
    zhTW: "這些服務有回應；連線結果屬於盤點，不代表資安弱點。",
  },
  observationSummary: {
    en: "{items} across {assets}",
    zhTW: "共觀察到 {items}，分布於 {assets}",
  },
  observationServicesCountOne: { en: "1 observed service", zhTW: "1 項服務" },
  observationServicesCountMany: { en: "{count} observed services", zhTW: "{count} 項服務" },
  observationAssetsCountOne: { en: "1 asset", zhTW: "1 項資產" },
  observationAssetsCountMany: { en: "{count} assets", zhTW: "{count} 項資產" },
  observationExamples: { en: "Representative services", zhTW: "代表項目" },
  observationCompleteListOne: { en: "View 1 observed service", zhTW: "查看全部 1 項觀察服務" },
  observationCompleteListMany: {
    en: "View all {count} observed services",
    zhTW: "查看全部 {count} 項觀察服務",
  },
  observationOpenPort: { en: "Open network service", zhTW: "可連線的網路服務" },
  observationHttp: { en: "Reachable HTTP service", zhTW: "可連線的 HTTP 服務" },
  observationPort: { en: "Port", zhTW: "連接埠" },
  observationProtocol: { en: "Protocol", zhTW: "協定" },
  observationStatus: { en: "HTTP status", zhTW: "HTTP 狀態" },
  observationNext: {
    en: "Confirm the service is expected. To look for weaknesses, choose an applicable security check.",
    zhTW: "先確認這項服務符合預期；若要找弱點，請選擇適用的資安檢查。",
  },
  chooseSecurityChecks: { en: "Choose security checks", zhTW: "選擇資安檢查" },
  typedInventoryEyebrow: { en: "INVENTORY", zhTW: "盤點" },
  typedInventoryTitle: { en: "What the scanners inventoried", zhTW: "掃描工具盤點到的項目" },
  typedInventoryDescription: {
    en: "These are services, software components, cloud resources, and workflow structure—not security problems or remediation advice.",
    zhTW: "這些是服務、軟體元件、雲端資源與工作流程結構，不是資安問題或修復建議。",
  },
  typedInventorySummary: {
    en: "{items} across {assets}",
    zhTW: "共 {items}，分布於 {assets}",
  },
  typedInventoryItemsCountOne: { en: "1 inventory item", zhTW: "1 個盤點項目" },
  typedInventoryItemsCountMany: { en: "{count} inventory items", zhTW: "{count} 個盤點項目" },
  typedInventoryAssetsCountOne: { en: "1 asset", zhTW: "1 個資產" },
  typedInventoryAssetsCountMany: { en: "{count} assets", zhTW: "{count} 個資產" },
  inventoryServices: { en: "Services", zhTW: "服務" },
  inventoryComponents: { en: "Software components", zhTW: "軟體元件" },
  inventoryCloudResources: { en: "Cloud resources", zhTW: "雲端資源" },
  inventoryWorkflowComponents: { en: "Workflow components", zhTW: "工作流程元件" },
  inventoryWorkflowRelationships: { en: "Workflow relationships", zhTW: "工作流程關係" },
  inventoryComponentType: { en: "Type", zhTW: "類型" },
  inventoryModel: { en: "Model", zhTW: "模型" },
  inventoryGuardrail: { en: "Guardrail", zhTW: "護欄" },
  inventoryYes: { en: "yes", zhTW: "是" },
  inventoryNo: { en: "no", zhTW: "否" },
  inventoryCondition: { en: "Condition", zhTW: "條件" },
  inventoryExamples: { en: "Representative examples", zhTW: "代表性範例" },
  inventoryAllItemsOne: { en: "Show 1 inventory item", zhTW: "顯示全部 1 個盤點項目" },
  inventoryAllItemsMany: { en: "Show all {count} inventory items", zhTW: "顯示全部 {count} 個盤點項目" },
  inventoryAssetSummaryOne: { en: "1 item for this asset", zhTW: "此資產共有 1 個項目" },
  inventoryAssetSummaryMany: { en: "{count} items for this asset", zhTW: "此資產共有 {count} 個項目" },
  inventorySources: { en: "Sources: {count}", zhTW: "來源：{count}" },
  inventoryHttpStatus: { en: "HTTP status", zhTW: "HTTP 狀態" },
  inventoryTlsObserved: { en: "TLS observed", zhTW: "觀察到 TLS" },
  inventoryNativeId: { en: "Native ID", zhTW: "原生識別碼" },
  emptyNoRunTitle: { en: "No scan results", zhTW: "沒有掃描結果" },
  emptyIncompleteTitle: {
    en: "Scan needs attention",
    zhTW: "掃描需要處理",
  },
  emptyCompletedTitle: {
    en: "No problems were observed in the work that completed",
    zhTW: "已完成的範圍內沒有觀察到問題",
  },
  emptyPartialTitle: {
    en: "Some checks need attention",
    zhTW: "仍有檢查需要處理",
  },
  emptyNoRunDescription: {
    en: "Add what you want to scan, then start the check from New scan.",
    zhTW: "先加入想掃描的目標，再到「開始新掃描」開始檢查。",
  },
  emptyIncompleteDescription: {
    en: "Open the scan to retry unfinished checks.",
    zhTW: "打開這次掃描以重試未完成的檢查。",
  },
  emptyCompletedDescription: {
    en: "The completed checks recorded no issues in their tested scope.",
    zhTW: "已完成的檢查在實際測試範圍內沒有記錄問題。",
  },
  emptyPartialDescription: {
    en: "Available security results recorded no problems, but some requested coverage is missing. Review what was not checked below.",
    zhTW: "已取得的資安結果未記錄問題，但仍有要求的範圍未完成。請查看下方未檢查的內容。",
  },
  openCoverage: { en: "Open scan setup", zhTW: "開啟掃描設定" },
  openProgress: { en: "Review scanner status", zhTW: "查看掃描工具狀態" },
  openReportScope: { en: "View checked scope", zhTW: "查看已檢查範圍" },
  openExport: { en: "Save or share report", zhTW: "保存或分享報告" },
  summaryAria: { en: "Problem summary", zhTW: "問題摘要" },
  critical: { en: "Critical", zhTW: "嚴重" },
  high: { en: "High priority", zhTW: "高風險" },
  needsReview: { en: "Open problems", zhTW: "待處理問題" },
  affectedAssets: { en: "Affected assets", zhTW: "受影響資產" },
  completeListCount: { en: "Problems in the complete list: {count}", zhTW: "完整清單共 {count} 項" },
  correlationEyebrow: { en: "SAME ISSUE, DIFFERENT TOOLS", zhTW: "同一問題，不同工具" },
  correlationTitle: {
    en: "These look like one issue reported more than once",
    zhTW: "這些看起來是同一個問題被重複回報",
  },
  correlationDescription: {
    en: "Two tools reported the same vulnerability ID for the same package and asset.",
    zhTW: "兩個工具在同一資產、同一套件上回報了相同的弱點編號。",
  },
  correlationMatch: {
    en: "{vulnerability} in {package}",
    zhTW: "{vulnerability}（套件：{package}）",
  },
  // No count placeholder: the list itself shows how many, and "1 tools" would
  // be ungrammatical if the backend's two-engine minimum ever changed.
  correlationBasis: {
    en: "Reported by these tools: {engines}",
    zhTW: "回報的工具：{engines}",
  },
  listSeparator: { en: ", ", zhTW: "、" },
  correlationMembers: { en: "Problems it would combine: {count}", zhTW: "會合併的問題：{count} 項" },
  // Spec 9.3: agreement between tools is not independent confirmation unless
  // the evidence sources are demonstrably independent, which is not recorded.
  correlationNotEstablished: {
    en: "Shared vulnerability data source; independent confirmation is not established.",
    zhTW: "共用弱點資料來源；未形成獨立確認。",
  },
  correlationAccept: { en: "Combine these for handoff", zhTW: "合併呈現以利交接" },
  correlationAcceptedRationale: {
    en: "Grouped by the same vulnerability ID, package, and asset.",
    zhTW: "依相同弱點編號、套件與資產分組。",
  },
  correlationUnverifiableTitle: {
    en: "Identifier match without comparison: {count}",
    zhTW: "編號相同但未完成比對：{count} 組",
  },
  correlationUnverifiableDescription: {
    en: "Listed separately: at least one record is missing the affected package or asset.",
    zhTW: "分開列出：至少一筆記錄缺少受影響套件或資產。",
  },
  correlationUnverifiableItem: {
    en: "{vulnerability} — problems sharing this identifier: {count}; the package or asset needed to compare them is missing",
    zhTW: "{vulnerability}——共用此編號的問題：{count} 項；缺少比對所需的套件或資產",
  },
  correlationTruncated: {
    en: "Additional grouping suggestions omitted: {count}. Every finding remains listed below.",
    zhTW: "另有 {count} 項分組建議未顯示；所有問題仍逐項列於下方。",
  },
  reversibleLinks: { en: "TEAM HANDOFF", zhTW: "團隊交接" },
  groupsTitle: { en: "Organize related issues for the right team", zhTW: "把相關問題整理給同一個團隊" },
  groupsDescription: {
    en: "Accepted groups reduce repetition during handoff.",
    zhTW: "已接受的群組可減少交接時的重複內容。",
  },
  manageGroups: { en: "Create, remove, or review groups", zhTW: "建立、移除或檢視群組" },
  manageGroupsDescription: {
    en: "Create or remove handoff groups.",
    zhTW: "建立或移除交接群組。",
  },
  caseHistoryMembers: {
    en: "Other members kept in case history: {count}",
    zhTW: "另有 {count} 項成員保留於案件歷史",
  },
  caseHistoryMember: {
    en: "Not observed in this selected report; kept as case history",
    zhTW: "本次選取的報告未觀察到；僅保留為案件歷史",
  },
  items: { en: "Items: {count}", zhTW: "{count} 項" },
  createdBy: { en: "Created by {actor}", zhTW: "建立者：{actor}" },
  technicalGroupDetails: { en: "Technical group details", zhTW: "群組技術細節" },
  groupId: { en: "Group ID", zhTW: "群組 ID" },
  removeGroup: { en: "Remove group", zhTW: "移除群組" },
  groupHistory: { en: "Permanent group history ({count})", zhTW: "不可變群組歷程（{count} 筆）" },
  groupHistoryDescription: {
    en: "Group changes are recorded here.",
    zhTW: "群組變更記錄於此。",
  },
  groupCreated: { en: "Group created", zhTW: "建立群組" },
  groupRemoved: { en: "Group removed", zhTW: "移除群組" },
  performedBy: { en: "Performed by {actor}", zhTW: "執行者：{actor}" },
  findingId: { en: "Problem ID", zhTW: "問題 ID" },
  groupTitle: { en: "Group title", zhTW: "群組標題" },
  groupTitlePlaceholder: {
    en: "For example: Privileged identities that should be reviewed together",
    zhTW: "例如：需要一起檢視的高權限身分保護問題",
  },
  groupReason: { en: "Why these belong together", zhTW: "關聯理由" },
  groupReasonPlaceholder: {
    en: "Describe why these problems should be handled together.",
    zhTW: "說明為什麼這些問題適合一起處理。",
  },
  chooseTwo: { en: "Choose at least two ungrouped problems", zhTW: "選擇至少兩項尚未分組的問題" },
  createGroup: { en: "Create reversible group", zhTW: "建立可逆群組" },
  doNow: { en: "START HERE", zhTW: "從這裡開始" },
  priorityTitle: { en: "Start with these issues", zhTW: "優先處理這些問題" },
  priorityDescription: {
    en: "Each item names the affected target, likely impact, next action, and how to check the fix.",
    zhTW: "每一項都直接列出受影響目標、可能影響、下一步與修復後的確認方式。",
  },
  affectedAssetEyebrow: { en: "AFFECTED ASSETS", zhTW: "受影響資產" },
  affectedAssetTitle: { en: "See where the problems are", zhTW: "直接看哪些資產有問題" },
  affectedAssetDescription: {
    en: "Every affected repository, device, website, cloud resource, or other selected system is listed here.",
    zhTW: "這裡列出每個受影響的 repo、設備、網站、雲端資源或其他已選系統。",
  },
  affectedAssetIssueCountOne: { en: "1 problem", zhTW: "1 個問題" },
  affectedAssetIssueCountMany: { en: "Problems: {count}", zhTW: "問題：{count}" },
  affectedAssetTopIssue: { en: "First issue", zhTW: "優先問題" },
  affectedAssetOpen: { en: "Show this asset's problems", zhTW: "查看這個資產的問題" },
  affectedAssetFilter: { en: "Showing problems for {asset}", zhTW: "目前顯示 {asset} 的問題" },
  assetResultEyebrow: { en: "BY ASSET", zhTW: "逐項資產" },
  assetResultTitle: { en: "Which assets need attention", zhTW: "哪些資產需要處理" },
  assetResultDescription: {
    en: "Every selected asset appears once.",
    zhTW: "每個已選資產都會列出一次。",
  },
  assetStatusProblems: { en: "Problems found", zhTW: "發現問題" },
  assetStatusNoProblems: {
    en: "No problems in completed checks",
    zhTW: "已完成檢查未發現問題",
  },
  assetStatusIncomplete: { en: "Incomplete or failed", zhTW: "未完成或失敗" },
  assetStatusNotTested: { en: "Not tested", zhTW: "未測試" },
  assetProblemCountOne: { en: "1 problem was found.", zhTW: "發現 1 個問題。" },
  assetProblemCountMany: { en: "Problems found: {count}.", zhTW: "發現 {count} 個問題。" },
  assetProblemAction: {
    en: "Review this asset's highest-priority problem first.",
    zhTW: "先檢視這個資產最高優先的問題。",
  },
  assetProblemIncomplete: {
    en: "Some checks are incomplete. Open Review scanner status to finish or retry them.",
    zhTW: "另有檢查尚未完成；請開啟「查看掃描工具狀態」完成或重試。",
  },
  assetNoProblemSummaryOne: {
    en: "1 completed security check reported no problems.",
    zhTW: "1 項已完成的資安檢查未回報問題。",
  },
  assetNoProblemSummaryMany: {
    en: "{count} completed security checks reported no problems.",
    zhTW: "{count} 項已完成的資安檢查未回報問題。",
  },
  assetNoProblemAction: {
    en: "Open the completed-check scope and any missing checks.",
    zhTW: "查看已完成檢查的範圍與缺少的檢查。",
  },
  assetIncompleteSummary: {
    en: "At least one requested check did not produce a complete result.",
    zhTW: "至少一項要求的檢查沒有產生完整結果。",
  },
  assetIncompleteAction: {
    en: "Open Review scanner status to finish or retry this asset's remaining checks.",
    zhTW: "請開啟「查看掃描工具狀態」完成或重試這個資產的其餘檢查。",
  },
  assetNotTestedSummary: {
    en: "No completed security check is recorded for this asset.",
    zhTW: "這個資產沒有已完成的資安檢查紀錄。",
  },
  assetNotTestedAction: {
    en: "Choose an applicable security check for this asset, then scan it.",
    zhTW: "為這個資產選擇適用的資安檢查，然後開始掃描。",
  },
  affectedTarget: { en: "Affected target", zhTW: "受影響目標" },
  reportedLocation: { en: "Location", zhTW: "位置" },
  locationUnavailable: { en: "Not retained by this result", zhTW: "這筆結果未保留位置" },
  nextActionNow: { en: "Next action", zhTW: "下一步" },
  verifyFix: { en: "Verify the fix", zhTW: "確認修復" },
  verifyFallback: {
    en: "No verification step was retained for this result.",
    zhTW: "這筆結果未保留驗證步驟。",
  },
  scannerRemediationMissing: {
    en: "The scanner did not provide a specific fix for this finding.",
    zhTW: "掃描工具未提供這項問題的具體修復方式。",
  },
  reviewEvidence: { en: "Open evidence and details", zhTW: "開啟證據與詳細資料" },
  allProblems: { en: "EXPLORE RESULTS", zhTW: "查看所有結果" },
  completeList: { en: "Browse every issue", zhTW: "瀏覽所有問題" },
  searchAria: { en: "Search problems, evidence, or source details", zhTW: "搜尋問題、證據或來源細節" },
  searchPlaceholder: { en: "Search problem, asset, evidence, fingerprint…", zhTW: "搜尋問題、資產、證據、內容指紋…" },
  severityFilter: { en: "Severity", zhTW: "嚴重度" },
  allSeverities: { en: "All severities", zhTW: "所有嚴重度" },
  workflowFilter: { en: "Review status", zhTW: "處理狀態" },
  allWorkflows: { en: "All review statuses", zhTW: "所有處理狀態" },
  advancedFilters: { en: "Advanced filters", zhTW: "進階篩選" },
  expertFilter: { en: "Specialist type", zhTW: "專家類型" },
  allExperts: { en: "All specialist types", zhTW: "所有專家類型" },
  controlFilter: { en: "Framework reference", zhTW: "框架參考" },
  allControls: { en: "All framework references", zhTW: "所有框架參考" },
  clearFilterCount: { en: "Clear filters ({count})", zhTW: "清除 {count} 個篩選條件" },
  noMatches: { en: "No problems match these filters", zhTW: "沒有符合的問題" },
  noMatchesDescription: {
    en: "Clear the search text, review status, specialist type, or framework filter.",
    zhTW: "清除搜尋字詞、處理狀態、專家類型或框架參考篩選。",
  },
  clearFilters: { en: "Clear filters", zhTW: "清除篩選" },
  rankAria: { en: "Handoff priority {rank}", zhTW: "交接優先順序第 {rank} 位" },
  rank: { en: "#{rank}", zhTW: "第 {rank}" },
  evidenceCount: { en: "Evidence records: {count}", zhTW: "{count} 份證據" },
  originalFindingCount: { en: "{count} original findings", zhTW: "{count} 筆原始發現" },
  relatedChecks: { en: "Related checks ({count})", zhTW: "相關檢查（{count} 筆）" },
  // Ordering by confidence cannot explain who made a rating. Keep the engine
  // and product-derived marker visible on the row where a beginner first sees
  // the finding.
  ratedByProduct: { en: "rated here", zhTW: "本產品評定" },
  ratedByProductAria: {
    en: "This severity was assigned by this product, not by the scanner.",
    zhTW: "這個嚴重程度由本產品評定，並非來自掃描工具。",
  },
  asset: { en: "Asset", zhTW: "資產" },
  reviewStatus: { en: "Review status", zhTW: "處理狀態" },
  recommendedExpert: { en: "Specialist to consult", zhTW: "建議專家類型" },
  lastObserved: { en: "Last observed", zhTW: "最後觀察" },
  evidenceConfidence: { en: "Evidence confidence", zhTW: "證據信心" },
  relatedAssets: { en: "Related assets", zhTW: "關聯資產" },
  assetCount: { en: "Assets: {count}", zhTW: "{count} 個" },
  decisionCount: { en: "Decisions: {count}", zhTW: "{count} 筆決定" },
  decisionBoundary: {
    en: "Save the review status here. Use ‘Verified resolved’ after comparable verification evidence is available.",
    zhTW: "在此保存處理狀態；取得可比較的複驗證據後，再使用「已驗證解決」。",
  },
  newStatus: { en: "New status", zhTW: "新狀態" },
  decidedBy: { en: "Updated by", zhTW: "更新者" },
  decidedByPlaceholder: { en: "Name, team, or traceable identifier", zhTW: "姓名、團隊或可追溯識別" },
  reason: { en: "Reason", zhTW: "理由" },
  reasonPlaceholder: {
    en: "Record the basis for the decision.",
    zhTW: "記錄判斷依據。",
  },
  falsePositiveExpiry: { en: "False-positive expiration (optional)", zhTW: "誤判到期日（選填）" },
  saveDecision: { en: "Save status", zhTW: "保存狀態" },
  noDecisions: { en: "No status change has been recorded.", zhTW: "尚未記錄狀態變更。" },
  decisionActor: { en: "Updated by {actor}", zhTW: "更新者：{actor}" },
  expires: { en: "expires {date}", zhTW: "到期：{date}" },
  neverExpires: { en: "no expiration", zhTW: "不到期" },
  possibleImpact: { en: "Possible impact", zhTW: "可能影響" },
  whyPriority: { en: "Why this order", zhTW: "排序原因" },
  recommendation: { en: "Recommended next step", zhTW: "建議下一步" },
  beforeChanging: { en: "Before making a change", zhTW: "變更前考量" },
  verification: { en: "How to verify the fix", zhTW: "修復確認方式" },
  scanEvidence: { en: "Scan evidence", zhTW: "掃描證據" },
  noEvidence: {
    en: "No scan evidence was retained for this problem.",
    zhTW: "這個問題未保留掃描證據。",
  },
  frozenEvidenceSummaryUnavailable: {
    en: "The selected run did not retain an evidence summary.",
    zhTW: "本輪未保留證據摘要。",
  },
  technicalEvidence: { en: "Technical evidence details", zhTW: "證據技術細節" },
  evidenceKind: { en: "Type", zhTW: "種類" },
  sourceRule: { en: "Source rule", zhTW: "來源規則" },
  evidenceLocation: { en: "Evidence location", zhTW: "證據位置" },
  scannerDescription: { en: "Scanner-provided description", zhTW: "掃描工具提供的說明" },
  iamPolicyContext: { en: "AWS IAM policy context", zhTW: "AWS IAM 政策脈絡" },
  iamPolicySource: { en: "Policy source", zhTW: "政策來源" },
  iamPolicyName: { en: "Policy", zhTW: "政策" },
  iamFindingIdentity: { en: "Upstream finding", zhTW: "上游問題" },
  iamActions: { en: "Reported actions", zhTW: "回報的動作" },
  iamRetainedActions: { en: "Retained actions", zhTW: "已保留的動作" },
  iamActionsIncomplete: {
    en: "The action list was shortened or sanitized for display. Open the raw evidence for the complete upstream list.",
    zhTW: "動作清單為了顯示而經過縮減或清理；完整上游清單請查看原始證據。",
  },
  iamAdditionalValues: { en: "+{count} more", zhTW: "另有 {count} 項" },
  iamAttachedRoles: { en: "Attached roles", zhTW: "附加的角色" },
  iamAttachedGroups: { en: "Attached groups", zhTW: "附加的群組" },
  iamAttachedUsers: { en: "Attached users", zhTW: "附加的使用者" },
  iamAttachmentsIncomplete: {
    en: "The retained attachment list is incomplete. Confirm the current IAM attachments before changing this policy.",
    zhTW: "保留的附加清單不完整；變更此政策前請先核對目前的 IAM 附加關係。",
  },
  installedVersion: { en: "Observed version", zhTW: "觀察到的版本" },
  fixedVersion: { en: "Scanner-reported fixed version", zhTW: "掃描工具回報的修正版" },
  scannerRemediation: {
    en: "Scanner-provided remediation",
    zhTW: "掃描工具提供的修復資訊",
  },
  benchmark: { en: "Benchmark", zhTW: "基準" },
  scanRun: { en: "Scan run", zhTW: "掃描輪次" },
  engineRun: { en: "Scanner job", zhTW: "掃描工具作業" },
  artifactId: { en: "Evidence file ID", zhTW: "證據檔案 ID" },
  contentHash: { en: "Content hash", zhTW: "內容雜湊" },
  evidencePointer: { en: "Internal evidence pointer", zhTW: "內部證據指標" },
  sensitiveValues: { en: "Sensitive values", zhTW: "敏感值" },
  notReported: { en: "Not reported", zhTW: "未回報" },
  legacyEngineRun: { en: "Not recorded by this older case", zhTW: "舊版案件未記錄" },
  noPointer: { en: "No internal pointer", zhTW: "無內部位置資訊" },
  redacted: { en: "Redacted", zhTW: "已遮罩" },
  notMarkedRedacted: { en: "Not marked as redacted", zhTW: "未標示遮罩" },
  controlsTitle: { en: "Related framework references", zhTW: "相關框架參考" },
  noControls: { en: "No framework reference is mapped to this problem.", zhTW: "這筆問題沒有對應的框架參考。" },
  relatedOnly: { en: "Relationship only", zhTW: "僅表示相關性" },
  viewSameControl: { en: "View problems with the same reference", zhTW: "查看同一框架參考的問題" },
  // ScubaGear tags a finding `tenant-disputed` when the tenant's own
  // configuration marks the result incorrect; the finding is still reported
  // on ScubaGear's own determination. This says that in words in the header,
  // instead of leaving the dispute to a raw tag chip in the technical detail.
  tenantDisputed: { en: "Disputed by the tenant", zhTW: "租用戶對此結果有異議" },
  provenance: { en: "Technical source details", zhTW: "技術來源細節" },
  firstRun: { en: "First-seen run", zhTW: "初見輪次" },
  lastRun: { en: "Last-seen run", zhTW: "末見輪次" },
  firstObserved: { en: "First observed", zhTW: "首次觀察" },
  officialReferences: { en: "Official references", zhTW: "官方參考" },
  // States what this record holds, not what the scanner published. A finding
  // whose canonical entry is gone still reaches this branch.
  noReferences: { en: "No official reference link is recorded for this finding.", zhTW: "這項問題沒有記錄官方參考連結。" },
  chooseProblem: { en: "Choose a problem", zhTW: "選擇一項問題" },
  chooseProblemDescription: {
    en: "Select a problem to review its evidence, source details, status history, and framework references.",
    zhTW: "選擇一項問題，查看證據、來源細節、處理歷程與框架參考。",
  },
  masterEyebrow: { en: "YOUR SCAN REPORT", zhTW: "你的掃描報告" },
  masterTitle: { en: "What was checked—and what was not", zhTW: "這次檢查了什麼，也漏了什麼" },
  reportComplete: { en: "Requested checks complete", zhTW: "要求的檢查已完成" },
  reportConnectionOnly: { en: "Connection result only", zhTW: "僅連線結果" },
  reportInventoryOnly: { en: "Service inventory only", zhTW: "僅完成服務盤點" },
  reportNonSecurityOnly: { en: "Inventory or connectivity only", zhTW: "僅完成盤點或連線工作" },
  reportPartial: { en: "Some checks are incomplete", zhTW: "部分檢查未完成" },
  reportNoChecks: { en: "No checks completed", zhTW: "沒有完成任何檢查" },
  reportRun: { en: "Report run", zhTW: "報告輪次" },
  finishedRunWhileScanning: {
    en: "Showing a finished scan; the latest results open automatically.",
    zhTW: "目前顯示已完成的掃描；最新結果將自動開啟。",
  },
  reportRunUnavailable: { en: "Previously selected scan unavailable", zhTW: "先前選擇的掃描已無法使用" },
  lastSaved: { en: "Last saved {time}", zhTW: "最後保存：{time}" },
  requestedTargets: { en: "Targets requested", zhTW: "要求檢查的目標" },
  testedComplete: { en: "Checks completed", zhTW: "完成的檢查" },
  testedPartialCount: { en: "Partly completed", zhTW: "部分完成" },
  failedCount: { en: "Failed", zhTW: "失敗" },
  timedOutCount: { en: "Timed out", zhTW: "逾時" },
  cancelledCount: { en: "Cancelled", zhTW: "已取消" },
  notTestedCount: { en: "Not tested", zhTW: "未測試" },
  excludedCount: { en: "Excluded", zhTW: "排除" },
  truncatedCount: { en: "Reduced by limits", zhTW: "受限制而縮減" },
  unavailableCount: { en: "Detail unavailable", zhTW: "資料不足" },
  unattributedCount: { en: "Not linked to your asset", zhTW: "未連結到你的資產" },
  manualReviewCount: { en: "No automated verdict", zhTW: "未回傳自動判定" },
  coverageGaps: { en: "Recorded coverage gaps", zhTW: "已記錄的涵蓋缺口" },
  coverageAttention: { en: "Unfinished checks and results to review", zhTW: "未完成的檢查與待判讀結果" },
  recordNotes: { en: "Record notes", zhTW: "記錄備註" },
  reportFindings: { en: "Problems found", zhTW: "發現的問題" },
  askedTitle: { en: "What you asked to scan", zhTW: "你要求掃描的內容" },
  testedTitle: { en: "What was actually tested", zhTW: "實際完成的測試" },
  gapsTitle: { en: "What was not tested", zhTW: "沒有測到的內容" },
  attentionTitle: { en: "What needs attention", zhTW: "需要留意的內容" },
  nextTitle: { en: "What to do next", zhTW: "接下來怎麼做" },
  moreItems: { en: "+{count} more", zhTW: "另 {count} 項" },
  stepConfirm: { en: "To confirm", zhTW: "確認方式" },
  noRequestedTarget: {
    en: "The older run did not retain an exact target description.",
    zhTW: "這筆舊掃描沒有保留精確的目標說明。",
  },
  noTestedDimension: {
    en: "No completed test dimension was saved for this run.",
    zhTW: "本輪沒有保存已完成的測試範圍。",
  },
  testedChecksBoth: { en: "Both checks completed", zhTW: "2 項檢查全部完成" },
  testedChecksAll: { en: "All {total} checks completed", zhTW: "{total} 項檢查全部完成" },
  testedChecksSome: {
    en: "{completed} of {total} checks completed",
    zhTW: "{total} 項檢查中完成 {completed} 項",
  },
  testedChecksNone: { en: "None of the {total} checks completed", zhTW: "{total} 項檢查都沒有完成" },
  checkDimensionsUnavailable: {
    en: "Exact tested dimensions not saved for this check",
    zhTW: "這項檢查未保存精確的測試範圍",
  },
  completedCheckForTargets: {
    en: "{check} completed for {targets}",
    zhTW: "已對 {targets} 完成 {check}",
  },
  completedCheckTargetUnavailable: {
    en: "{check} completed; target label not retained",
    zhTW: "已完成 {check}；未保存目標名稱",
  },
  firstLayerRequested: { en: "Requested", zhTW: "要求" },
  firstLayerActuallyTested: { en: "Actually tested", zhTW: "實際測試" },
  currentProjectFallback: {
    en: "from the current project; not retained by this run",
    zhTW: "來自目前專案；本輪未保存",
  },
  observedAt: { en: "Observed {time}", zhTW: "觀察時間：{time}" },
  observedFromOnly: { en: "Observed from {time}; end not retained", zhTW: "開始觀察：{time}；未保存結束時間" },
  observedUntilOnly: { en: "Observed through {time}; start not retained", zhTW: "觀察至：{time}；未保存開始時間" },
  observedTimeUnavailable: {
    en: "Observation time not retained",
    zhTW: "未保存觀察時間",
  },
  recordedExclusions: { en: "Recorded exclusions", zhTW: "已記錄的排除項目" },
  noRecordedExclusions: {
    en: "No exclusion was recorded within the requested checks.",
    zhTW: "要求的檢查內沒有記錄排除項目。",
  },
  recordedExclusionsUnavailable: {
    en: "Recorded exclusions: {count}; exact detail unavailable.",
    zhTW: "已記錄 {count} 項排除；無法取得精確細節。",
  },
  noGap: {
    en: "No gap was recorded within the requested checks.",
    zhTW: "要求的檢查內沒有記錄到缺口。",
  },
  noNextStep: {
    en: "No additional action is listed for this scan.",
    zhTW: "這次掃描沒有列出其他動作。",
  },
  stage: { en: "Scan depth", zhTW: "掃描深度" },
  stageConnection: { en: "Connection test (not a vulnerability scan)", zhTW: "連線測試（不是漏洞掃描）" },
  stageQuick: { en: "Quick discovery", zhTW: "快速探索" },
  stageInventory: { en: "Full inventory", zhTW: "完整盤點" },
  stageDeep: { en: "Deep scan", zhTW: "深度掃描" },
  stageUnknown: { en: "Not retained by this run", zhTW: "本輪未保存" },
  requestedLimits: { en: "Limits used", zhTW: "使用的限制" },
  automaticReductions: { en: "Automatic reductions", zhTW: "自動縮減的範圍" },
  reductionLine: { en: "Requested {requested}; tested {executed}", zhTW: "原要求：{requested}；實際測試：{executed}" },
  observedWindow: { en: "Observed {from} to {until}", zhTW: "觀察時間：{from} 至 {until}" },
  savedAt: { en: "Saved {time}", zhTW: "保存時間：{time}" },
  unavailableProvenance: { en: "Historical detail unavailable", zhTW: "無法取得歷史細節" },
  coverageDetail: { en: "Coverage detail", zhTW: "涵蓋範圍細節" },
  exactNetworkScope: { en: "Exact addresses and ports", zhTW: "實際位址與連接埠" },
  networkScopeCountOne: { en: "1 network scope group", zhTW: "1 組網路範圍" },
  networkScopeCountMany: { en: "{count} network scope groups", zhTW: "{count} 組網路範圍" },
  networkAddresses: { en: "Addresses", zhTW: "位址" },
  networkPorts: { en: "Ports", zhTW: "連接埠" },
  networkResult: { en: "Result", zhTW: "結果" },
  requestedScope: { en: "Requested scope", zhTW: "要求的範圍" },
  localConnectionCheck: { en: "Local connection check", zhTW: "本機連線檢查" },
  testedStatusComplete: { en: "Completed", zhTW: "完成" },
  testedStatusPartial: { en: "Partly completed", zhTW: "部分完成" },
  testedStatusFailed: { en: "Stopped with an error", zhTW: "因錯誤停止" },
  testedStatusTimeout: { en: "Timed out", zhTW: "逾時" },
  testedStatusCancelled: { en: "Cancelled", zhTW: "已取消" },
  testedStatusNotTested: { en: "Not tested", zhTW: "未測試" },
  reportEndMatter: { en: "Report terms and technical record", zhTW: "報告條款與技術紀錄" },
  reportTerms: { en: "Report terms", zhTW: "報告條款" },
  reportTechnicalDetails: { en: "Technical record", zhTW: "技術紀錄" },
  taskStatus: { en: "Status", zhTW: "狀態" },
  taskProgress: { en: "Progress", zhTW: "進度" },
  taskEvidence: { en: "Evidence hashes", zhTW: "證據雜湊" },
  taskErrorCode: { en: "Diagnostic code", zhTW: "診斷代碼" },
  taskNoError: { en: "No diagnostic code", zhTW: "沒有診斷代碼" },
  scannerVersionUpdated: { en: "Version {version} · last updated {date}", zhTW: "版本 {version} · 最後更新 {date}" },
  scannerVersionOnly: { en: "Version {version}", zhTW: "版本 {version}" },
  scannerUpdatedOnly: { en: "Last updated {date}", zhTW: "最後更新 {date}" },
  scannerVersion: { en: "Scanner version", zhTW: "掃描工具版本" },
  lastUpdated: { en: "Last updated", zhTW: "最後更新" },
  dataWarnings: { en: "Saved-data limitations: {count}", zhTW: "已保存資料的限制：{count} 項" },
  genericExpert: { en: "Security or IT specialist", zhTW: "資安或 IT 專業人員" },
} as const;

/**
 * What each corroboration status means to a beginner. Exhaustive by type: if
 * the backend gains a status this map does not cover, the build fails rather
 * than the page silently omitting the caveat.
 */
const corroborationCopy: Record<CorroborationStatus, typeof copy.correlationNotEstablished> = {
  "not-established": copy.correlationNotEstablished,
};

const reportSummaryPresentation = (summary: BeginnerReportSummary) => {
  switch (summary) {
    case "complete": return { label: copy.reportComplete, tone: "positive" };
    case "partial": return { label: copy.reportPartial, tone: "warning" };
    case "no_checks_completed": return { label: copy.reportNoChecks, tone: "danger" };
  }
};

const reportStageCopy = (stage?: BeginnerReportStage) => {
  switch (stage) {
    case "connection_diagnostic": return copy.stageConnection;
    case "quick_discovery": return copy.stageQuick;
    case "inventory": return copy.stageInventory;
    case "deep": return copy.stageDeep;
    default: return copy.stageUnknown;
  }
};

const catalogEngineProvenanceLine = (
  execution: BeginnerTechnicalExecution | undefined,
  text: BilingualTextTranslator,
  locale: Locale,
): string | undefined => {
  if (execution?.kind !== "catalog_engine") return undefined;
  const version = scannerVersionLabel(
    execution.engineVersion,
    execution.reportedVersion,
    "short",
    locale,
  );
  const date = execution.knowledgeDate?.trim();
  if (version && date) return text(copy.scannerVersionUpdated, { version, date });
  if (version) return text(copy.scannerVersionOnly, { version });
  if (date) return text(copy.scannerUpdatedOnly, { date });
  return undefined;
};

const testedStatusCopy = (status: BeginnerCoverageStatus) => {
  switch (status) {
    case "tested_complete": return copy.testedStatusComplete;
    case "tested_partial": return copy.testedStatusPartial;
    case "failed": return copy.testedStatusFailed;
    case "timed_out": return copy.testedStatusTimeout;
    case "cancelled": return copy.testedStatusCancelled;
    case "not_tested": return copy.testedStatusNotTested;
  }
};

const gapNextActionProse = (
  gap: BeginnerMasterReport["coverageGaps"][number],
  locale: "en" | "zh-TW",
): string => {
  if (gap.unattributed) {
    return findingUnattributedGap(
      locale,
      gap.dimension.split(":")[0] ?? gap.dimension,
      gap.unattributed,
      { dimension: gap.dimension, reason: gap.reason, nextAction: gap.nextAction },
    ).nextAction;
  }
  return coverageGapProse(locale, gap.nextAction);
};

const localizedCheckName = (
  checkId: string,
  locale: "en" | "zh-TW",
  engine?: ScanRun["engineRuns"][number],
): string => {
  if (engine && isExactBuiltInLocalhostQuickScanEngine(engine) && engine.taskKind.kind === "built_in_localhost_tcp") {
    return `${locale === "en" ? "Local connection check" : "本機連線檢查"} · 127.0.0.1:${engine.taskKind.port}`;
  }
  if (engine?.engineName.trim()) return engine.engineName.trim();
  return checkId;
};

/**
 * A gap's dimension, with its leading check id (the text before the first
 * ":") replaced by that check's display name -- the same `localizedCheckName`
 * every other row on this page uses, and the same substitution the saved HTML
 * report's `engine_named` makes. Without this the desktop prints the raw
 * check id while the report it exports names the check, so the two disagree
 * about what to call the same check.
 */
const coverageGapDimensionLabel = (
  gap: BeginnerMasterReport["coverageGaps"][number],
  locale: "en" | "zh-TW",
  run: ScanRun | undefined,
  unattributedDimension?: string,
): string => {
  const dimensionText = unattributedDimension ?? localizedCoverageDimension(gap.dimension, locale);
  const checkId = (gap.dimension.split(":")[0] ?? gap.dimension).trim();
  const taskEngine = gap.taskId
    ? run?.engineRuns.find((candidate) => candidate.id === gap.taskId)
    : undefined;
  const engine = taskEngine && taskEngine.engineId === checkId
    ? taskEngine
    : run?.engineRuns.find((candidate) => candidate.engineId === checkId);
  if (!engine || !dimensionText.startsWith(checkId)) return dimensionText;
  return `${localizedCheckName(engine.engineId, locale, engine)}${dimensionText.slice(checkId.length)}`;
};

/**
 * The coverage rows a gap-derived step closes, each named once with every
 * asset it closes a row on: the names the saved HTML report gives the same
 * step (`html_step_closes`). "Retry this check." names nothing, and a step
 * that stands apart from its coverage row needs them to say which check.
 * A report about one asset has no assets to tell apart and names none.
 */
const stepCoverageNames = (
  step: BeginnerMasterReport["nextSteps"][number],
  report: BeginnerMasterReport,
  locale: "en" | "zh-TW",
  run: ScanRun | undefined,
): string[] => {
  if (step.findingId || step.unattributed) return [];
  const assetCount = new Set([
    ...report.requested.targets.map((target) => target.assetId),
    ...report.actual.checks.flatMap((check) => check.targetAssetIds),
    ...report.findings.flatMap((finding) => finding.targetAssetIds),
    ...report.coverageGaps.flatMap((gap) => gap.targetAssetIds),
    ...(report.inventory?.assetIds ?? []),
  ]).size;
  const targetById = new Map(report.requested.targets.map((target) => [target.assetId, target]));
  const closes: Array<{ name: string; assetIds: string[] }> = [];
  for (const gap of report.coverageGaps) {
    if (gap.unattributed || gap.nextAction !== step.action) continue;
    const name = coverageGapDimensionLabel(gap, locale, run);
    let closed = closes.find((candidate) => candidate.name === name);
    if (!closed) {
      closed = { name, assetIds: [] };
      closes.push(closed);
    }
    for (const assetId of gap.targetAssetIds) {
      if (!closed.assetIds.includes(assetId)) closed.assetIds.push(assetId);
    }
  }
  return closes.map(({ name, assetIds }) => assetCount > 1 && assetIds.length > 0
    ? `${name} · ${requestedTargetListLabel(assetIds, targetById, locale)}`
    : name);
};

/**
 * An action with the coverage it is about in parentheses, inside the
 * sentence: "Retry this check (Nuclei)." The saved HTML report composes the
 * same sentence (`html_action_about`). Nothing to name, or no action, leaves
 * the action as it is.
 */
const actionAbout = (
  action: string,
  about: readonly string[],
  locale: "en" | "zh-TW",
): string => {
  if (about.length === 0 || !action.trim()) return action;
  const named = about.join(locale === "en" ? "; " : "；");
  if (locale === "en") {
    return action.endsWith(".") ? `${action.slice(0, -1)} (${named}).` : `${action} (${named})`;
  }
  return action.endsWith("。") ? `${action.slice(0, -1)}（${named}）。` : `${action}（${named}）`;
};

/**
 * What one coverage row measured, in the reader's language.
 *
 * The local connection check keeps its own richer sentence, which says how
 * many attempts and how much payload the boundary allowed. Every other row's
 * value is composed by the backend around counts and identifiers, and is
 * translated the same way the shared report translates it.
 */
const testedValueText = (
  engine: ScanRun["engineRuns"][number] | undefined,
  dimension: string,
  value: string,
  locale: "en" | "zh-TW",
): string => {
  const localhost = localhostTestedDimensionValue(engine, dimension, value, locale);
  return localhost === value ? localizedTestedValue(locale, dimension, value) : localhost;
};

const localizedAssetKind = (kind: string, locale: "en" | "zh-TW"): string => {
  if (locale === "en") return kind.replaceAll("_", " ");
  return ({
    web_service: "網站或本機服務",
    host: "伺服器或工作站",
    ip_address: "IP 位址",
    domain: "網域",
    repository: "程式碼儲存庫",
    iac_project: "基礎設施程式碼",
    container_image: "容器映像",
    kubernetes_cluster: "Kubernetes 叢集",
    cloud_account: "雲端帳號",
  } as Record<string, string>)[kind] ?? "掃描目標";
};

const requestedTargetQualifier = (
  target: BeginnerRequestedTarget | undefined,
  locale: "en" | "zh-TW",
): string | undefined => {
  const availability = target?.labelAvailability ?? "unavailable";
  const qualifier = availability === "current_case_fallback"
    ? copy.currentProjectFallback
    : availability === "unavailable"
      ? copy.unavailableProvenance
      : undefined;
  if (!qualifier) return undefined;
  return locale === "en" ? qualifier.en : qualifier.zhTW;
};

const requestedTargetLabel = (
  target: BeginnerRequestedTarget,
  locale: "en" | "zh-TW",
): string => {
  const label = target.label ?? target.assetId;
  const qualifier = requestedTargetQualifier(target, locale);
  return qualifier ? `${label} (${qualifier})` : label;
};

const requestedTargetLabelById = (
  assetId: string,
  targetById: ReadonlyMap<string, BeginnerRequestedTarget>,
  locale: "en" | "zh-TW",
): string => {
  const target = targetById.get(assetId);
  if (target) return requestedTargetLabel(target, locale);
  return `${assetId} (${requestedTargetQualifier(undefined, locale)})`;
};

const requestedTargetListLabel = (
  assetIds: readonly string[],
  targetById: ReadonlyMap<string, BeginnerRequestedTarget>,
  locale: "en" | "zh-TW",
): string => {
  const groups: Array<{ qualifier?: string; labels: string[] }> = [];
  const groupByQualifier = new Map<string | undefined, { qualifier?: string; labels: string[] }>();
  for (const assetId of assetIds) {
    const target = targetById.get(assetId);
    const qualifier = requestedTargetQualifier(target, locale);
    let group = groupByQualifier.get(qualifier);
    if (!group) {
      group = { qualifier, labels: [] };
      groupByQualifier.set(qualifier, group);
      groups.push(group);
    }
    group.labels.push(target?.label ?? assetId);
  }
  const itemSeparator = locale === "en" ? ", " : "、";
  const groupSeparator = locale === "en" ? "; " : "；";
  return groups.map(({ qualifier, labels }) => {
    const joined = labels.join(itemSeparator);
    return qualifier ? `${joined} (${qualifier})` : joined;
  }).join(groupSeparator);
};

/**
 * A network scope row carries the grant's own canonical target text, which is
 * part of this report. When the display label was not retained, show that text
 * rather than the internal ID: the detail is not unavailable, and a row that
 * says so while the address sits beside it is simply wrong.
 */
const networkScopeTargetLabel = (
  scope: BeginnerMasterReport["actual"]["networkScopes"][number],
  targetById: ReadonlyMap<string, BeginnerRequestedTarget>,
  locale: "en" | "zh-TW",
): string => {
  const target = targetById.get(scope.targetAssetId);
  if (target?.label) return requestedTargetLabel(target, locale);
  return scope.target || requestedTargetLabelById(scope.targetAssetId, targetById, locale);
};

type AssetResultStatus =
  | "problems_found"
  | "no_problems_completed"
  | "incomplete_failed"
  | "not_tested";

const incompleteCheckStatuses = new Set<BeginnerCoverageStatus>([
  "tested_partial",
  "failed",
  "timed_out",
  "cancelled",
]);

const incompleteGapKinds = new Set<BeginnerMasterReport["coverageGaps"][number]["kind"]>([
  "failed",
  "timed_out",
  "cancelled",
  "truncated",
  "unavailable",
  "unattributed",
]);

// Native profile gaps describe security dimensions outside the selected
// bounded check. They remain visible in coverage, but do not make a completed
// check on that asset unfinished when a sibling makes the shared task partial.
const boundedProfileLimitDimensions = new Set([
  "endpoint operating-system, package, application, and local-configuration coverage",
  "RDP implementation, authentication/NLA, and endpoint host coverage",
  "VNC implementation, authentication, and endpoint host coverage",
  "SMTP server behavior, implementation, and endpoint host coverage",
  "Telnet authentication, implementation, and endpoint host coverage",
  "device product and firmware vulnerability coverage",
]);

// A cloud check looks at identity and access alone. Its clean result names
// what the rest of the account did not get (`CLOUD_SCOPE_LIMIT_DIMENSIONS`).
const cloudScopeLimitDimensions = new Set([
  "AWS services other than IAM",
  "Azure services other than IAM",
  "Google Cloud settings other than four IAM checks",
  "Microsoft 365 products other than Entra ID",
]);

// Older reports and fixtures omit `class`. Absence keeps the conservative
// coverage-loss reading rather than becoming a quieter record note.
const isRecordNoteGap = (
  gap: BeginnerMasterReport["coverageGaps"][number],
): boolean => gap.class === "record_note";

const isCoverageLossGap = (
  gap: BeginnerMasterReport["coverageGaps"][number],
): boolean => !isRecordNoteGap(gap);

// Native completed tasks freeze one coordinate per asset that actually ran.
// The task can later become `tested_partial` when a sibling lacks evidence;
// only its exact recorded coordinate proves this asset completed a check.
const hasCompletedCoordinateForAsset = (
  check: BeginnerMasterReport["actual"]["checks"][number],
  assetId: string,
): boolean => check.testedDimensions.some((dimension) =>
  dimension.dimension === "completed check-to-target coordinate"
  && dimension.value.endsWith(` on asset ${assetId}`));

const dimensionRefersToAsset = (value: string, assetId: string): boolean =>
  [" on asset ", " for asset "].some((marker) => value.split(marker).slice(1)
    .some((rest) => rest === assetId || rest.startsWith(`${assetId} `)));

const checkStatusForAsset = (
  report: BeginnerMasterReport,
  check: BeginnerMasterReport["actual"]["checks"][number],
  assetId: string,
): BeginnerCoverageStatus => {
  if (check.status !== "tested_partial"
    || checkResultKind(check) !== "security_check"
    || !hasCompletedCoordinateForAsset(check, assetId)) return check.status;
  const missingCoverage = report.coverageGaps.some((gap) =>
    gap.taskId === check.taskId
    && gap.targetAssetIds.includes(assetId)
    && isCoverageLossGap(gap)
    && (incompleteGapKinds.has(gap.kind)
      || (gap.kind === "not_tested"
        && gap.nextActionCode !== "no_action_unless_scope_changes"
        && !(gap.nextActionCode === "preserve_visible_limitation"
          && boundedProfileLimitDimensions.has(gap.dimension)))));
  return missingCoverage ? "tested_partial" : "tested_complete";
};

// Keep the desktop count in the same check-to-asset unit as HTML Results.
// Older reports without exact target binding retain their stored task count.
const completedAssetCheckCount = (report: BeginnerMasterReport): number => Math.max(
  report.coverageCounts.testedComplete,
  report.requested.targets.reduce((count, target) => count + report.actual.checks.filter((check) =>
    check.targetAssetIds.includes(target.assetId)
    && checkStatusForAsset(report, check, target.assetId) === "tested_complete").length, 0),
);

const assetNextActionDestination = {
  // The retry lives in Progress.
  retry_check: "progress",
  // Progress renders Start when this check cannot be resumed.
  start_new_scan: "progress",
  // Ends in the same retry as retry_check.
  start_expected_service_and_retry: "progress",
  // Coverage is where applicable checks are chosen.
  choose_compatible_check: "coverage",
  review_coverage: "coverage",
  // Scope, target, connection, and the Start control live on Coverage.
  review_scope_and_retry: "coverage",
  // The control and its upstream detail are on the surface the user is already reading.
  review_manual_control: undefined,
  // Coverage is where the gap and its reason are stated before the user changes setup.
  add_asset_identifier: "coverage",
  // The finding is on the surface the user is already reading.
  review_finding: undefined,
  confirm_finding_after_incomplete_check: undefined,
  // Deliberately no action.
  preserve_visible_limitation: undefined,
  no_action_unless_scope_changes: undefined,
} as const satisfies Record<BeginnerNextActionCode, "progress" | "coverage" | undefined>;

const assetActionDestination = (
  nextActionCode: BeginnerNextActionCode | undefined,
  status: AssetResultStatus,
): "progress" | "coverage" | undefined => {
  if (nextActionCode) return assetNextActionDestination[nextActionCode];
  if (status === "incomplete_failed") return "progress";
  if (status === "not_tested") return "coverage";
  return undefined;
};

const partialReportActionDestination = (
  report: BeginnerMasterReport,
): "progress" | "coverage" | "scope" => {
  const actionableStep = [...report.nextSteps]
    .sort((left, right) => left.priority - right.priority)
    .find((step) => !step.findingId && assetActionDestination(step.code, "incomplete_failed"));
  return actionableStep
    ? assetActionDestination(actionableStep.code, "incomplete_failed") ?? "scope"
    : "scope";
};

const checkResultKind = (
  check: BeginnerMasterReport["actual"]["checks"][number],
): BeginnerCheckResultKind =>
  check.resultKind ?? legacyCheckResultKind(check.checkId);

const uniqueScannerRemediations = (
  evidence: Array<{ scannerDetails?: { remediation?: string } | null }>,
): string[] => {
  const seen = new Set<string>();
  const values: string[] = [];
  for (const item of evidence) {
    const text = item.scannerDetails?.remediation?.trim();
    if (!text || seen.has(text)) continue;
    seen.add(text);
    values.push(text);
  }
  return values;
};

const uniqueScannerFixedVersions = (
  evidence: Array<{ scannerDetails?: { fixedVersion?: string } | null }>,
): string[] => {
  const seen = new Set<string>();
  const values: string[] = [];
  for (const item of evidence) {
    const text = item.scannerDetails?.fixedVersion?.trim();
    if (!text || seen.has(text)) continue;
    seen.add(text);
    values.push(text);
  }
  return values;
};

/**
 * A reference link's display text: enough of the URL to tell it apart from
 * its neighbours without hovering every one, never the same generic label for
 * all of them. The full address stays in `href` and `title`. Anything that is
 * not a plain http(s) URL renders as the stored string, unchanged.
 */
const readableReference = (reference: string): string => {
  try {
    const url = new URL(reference);
    if (url.protocol !== "https:" && url.protocol !== "http:") return reference;
    const path = url.pathname.endsWith("/") ? url.pathname.slice(0, -1) : url.pathname;
    return `${url.host}${path}${url.search}${url.hash}`;
  } catch {
    return reference;
  }
};

/**
 * The advice section's run-in label, with exactly one colon set in the
 * reader's language instead of one baked into the label and another into the
 * surrounding punctuation. English keeps a space after the colon; Chinese's
 * full-width colon carries its own spacing and takes none.
 */
const adviceLabel = (locale: Locale, label: string): ReactNode =>
  locale === "en" ? (
    <>
      <strong>{label}:</strong>{" "}
    </>
  ) : (
    <strong>{label}：</strong>
  );

/**
 * One benchmark line per displayed engine name, in the order evidence is kept.
 * Identical references from sibling records of that engine are kept once.
 */
const benchmarkAdviceLines = (
  evidence: readonly Finding["evidence"][number][],
  engineNameFor: (item: Finding["evidence"][number]) => string,
  locale: Locale,
): Array<{ engineName: string; line: string }> => {
  const grouped: Array<{ engineName: string; benchmarks: BenchmarkReference[] }> = [];
  for (const item of evidence) {
    const reported = item.scannerDetails?.benchmarks;
    if (!reported?.length) continue;
    const engineName = engineNameFor(item);
    let entry = grouped.find((candidate) => candidate.engineName === engineName);
    if (!entry) {
      entry = { engineName, benchmarks: [] };
      grouped.push(entry);
    }
    for (const benchmark of reported) {
      if (entry.benchmarks.some((existing) =>
        existing.name === benchmark.name
        && existing.version === benchmark.version
        && existing.reference === benchmark.reference)) continue;
      entry.benchmarks.push(benchmark);
    }
  }
  return grouped.flatMap((entry) => {
    const line = benchmarkLine(locale, entry.engineName, entry.benchmarks);
    return line ? [{ engineName: entry.engineName, line }] : [];
  });
};

const checkRecordedTestedWork = (
  check: BeginnerMasterReport["actual"]["checks"][number],
): boolean =>
  check.status === "tested_complete"
  || check.status === "tested_partial"
  || check.testedDimensions.length > 0;

const hasOnlyTestedNonSecurityWork = (
  checks: BeginnerMasterReport["actual"]["checks"],
): boolean =>
  checks.length > 0
  && checks.every((check) => checkResultKind(check) !== "security_check")
  && checks.some(checkRecordedTestedWork);

const assetResultRank: Record<AssetResultStatus, number> = {
  problems_found: 0,
  incomplete_failed: 1,
  not_tested: 2,
  no_problems_completed: 3,
};

function AssetResultBoard({
  report,
  run,
  onOpenProgress,
  onOpenCoverage,
}: {
  report: BeginnerMasterReport;
  run?: ScanRun;
  onOpenProgress: () => void;
  onOpenCoverage: () => void;
}) {
  const { locale, text, formatNumber } = useI18n();
  if (report.requested.targets.length === 0) return null;

  const securityFindings = report.findings.filter(isSecurityFinding);
  const problemRows = projectProblemRows(securityFindings, report.problemGroups);
  const rows = report.requested.targets.map((target) => {
    const findingCount = new Set(
      problemRows
        .filter(({finding}) => finding.targetAssetIds.includes(target.assetId))
        .map(({finding}) => finding.findingId),
    ).size;
    const checks = report.actual.checks.filter((check) =>
      check.targetAssetIds.includes(target.assetId));
    const completedSecurityChecks = checks.filter((check) =>
      checkResultKind(check) === "security_check"
      && (check.status === "tested_complete"
        || (check.status === "tested_partial"
          && hasCompletedCoordinateForAsset(check, target.assetId))));
    const gaps = report.coverageGaps.filter((gap) =>
      gap.targetAssetIds.includes(target.assetId));
    const firstApplicableGap = gaps.find((gap) =>
      isCoverageLossGap(gap) && gap.kind !== "excluded");
    const firstIncompleteGap = gaps.find((gap) =>
      isCoverageLossGap(gap) && incompleteGapKinds.has(gap.kind));
    const hasIncompleteOutcome = checks.some((check) =>
      incompleteCheckStatuses.has(check.status)
      && !(check.status === "tested_partial"
        && checkResultKind(check) === "security_check"
        && hasCompletedCoordinateForAsset(check, target.assetId)));
    // A completed task's deliberate `not_tested` boundary does not erase its
    // bounded result. For a shared partial task, only the native profile-limit
    // dimensions have that meaning; a missing planned dimension (such as
    // SMTP TLS checks) must still mark this asset incomplete.
    const unfinishedRequestedGap = gaps.find((gap) => isCoverageLossGap(gap)
      && gap.kind === "not_tested"
      && gap.nextActionCode !== "no_action_unless_scope_changes"
      && Boolean(gap.taskId)
      && !checks.some((check) => check.taskId === gap.taskId && check.status === "tested_complete")
      && !(gap.nextActionCode === "preserve_visible_limitation"
        && boundedProfileLimitDimensions.has(gap.dimension)
        && completedSecurityChecks.some((check) => check.taskId === gap.taskId)));
    const hasIncompleteGap = Boolean(firstIncompleteGap);
    const hasIncompleteEvidence = hasIncompleteOutcome
      || hasIncompleteGap
      || (completedSecurityChecks.length > 0 && Boolean(unfinishedRequestedGap));

    let status: AssetResultStatus;
    if (findingCount > 0) status = "problems_found";
    else if (hasIncompleteEvidence) status = "incomplete_failed";
    else if (completedSecurityChecks.length > 0) status = "no_problems_completed";
    else status = "not_tested";

    const actionGap = status === "incomplete_failed"
      ? firstIncompleteGap ?? unfinishedRequestedGap
      : status === "no_problems_completed"
        ? gaps.find((gap) => gap.kind === "manual_review")
          ?? gaps.find((gap) => gap.kind === "not_tested" && cloudScopeLimitDimensions.has(gap.dimension))
        : firstApplicableGap;
    // The row is the asset, so its step names only the coverage it closes. An
    // unattributed step already names the identifier to add.
    const recordedNextAction = actionGap
      ? actionGap.unattributed
        ? gapNextActionProse(actionGap, locale)
        : actionAbout(
            gapNextActionProse(actionGap, locale),
            [coverageGapDimensionLabel(actionGap, locale, run)],
            locale,
          )
      : undefined;
    const presentation = (() => {
      switch (status) {
        case "problems_found":
          return {
            label: text(copy.assetStatusProblems),
            tone: "danger",
            summary: text(
              findingCount === 1 ? copy.assetProblemCountOne : copy.assetProblemCountMany,
              { count: formatNumber(findingCount) },
            ),
            prose: [
              text(copy.assetProblemAction),
              hasIncompleteEvidence ? text(copy.assetProblemIncomplete) : undefined,
            ].filter((value): value is string => Boolean(value)).join(" "),
            control: hasIncompleteEvidence
              ? { destination: "progress" as const }
              : undefined,
          };
        case "no_problems_completed":
          return {
            label: text(copy.assetStatusNoProblems),
            tone: "positive",
            summary: text(
              completedSecurityChecks.length === 1
                ? copy.assetNoProblemSummaryOne
                : copy.assetNoProblemSummaryMany,
              { count: formatNumber(completedSecurityChecks.length) },
            ),
            prose: recordedNextAction ?? text(copy.assetNoProblemAction),
            control: { destination: "scope" as const },
          };
        case "incomplete_failed": {
          const action = recordedNextAction ?? text(copy.assetIncompleteAction);
          const destination = assetActionDestination(actionGap?.nextActionCode, status);
          return {
            label: text(copy.assetStatusIncomplete),
            tone: "warning",
            summary: text(copy.assetIncompleteSummary),
            prose: action,
            control: destination ? { destination } : undefined,
          };
        }
        case "not_tested": {
          const action = recordedNextAction ?? text(copy.assetNotTestedAction);
          const destination = assetActionDestination(actionGap?.nextActionCode, status);
          return {
            label: text(copy.assetStatusNotTested),
            tone: "neutral",
            summary: text(copy.assetNotTestedSummary),
            prose: action,
            control: destination ? { destination } : undefined,
          };
        }
      }
    })();

    // Where this asset's most urgent problem sits in the report's own finding
    // order. `Infinity` for an asset with none, which sorts it behind every
    // asset that has one without needing a second rule.
    const firstProblem = securityFindings
      .findIndex((finding) => finding.targetAssetIds.includes(target.assetId));
    return {
      target,
      status,
      presentation,
      firstProblem: firstProblem === -1 ? Number.POSITIVE_INFINITY : firstProblem,
    };
  });
  // Ranked, not listed in the order the targets were declared. Under a heading
  // that promises the assets needing attention, the list is read as an order:
  // what was found, then what is unknown, then what is clean. The order within
  // the problem tier is the report's own finding order, so this board and the
  // problems list agree on what to read first. The HTML export ranks the same
  // way; the two surfaces show one report.
  rows.sort((left, right) => assetResultRank[left.status] - assetResultRank[right.status]
    || left.firstProblem - right.firstProblem);

  return (
    <section className="section-block asset-result-board" aria-labelledby="asset-result-board-title">
      <div className="section-heading">
        <p className="eyebrow">{text(copy.assetResultEyebrow)}</p>
        <h2 id="asset-result-board-title">{text(copy.assetResultTitle)}</h2>
        <p>{text(copy.assetResultDescription)}</p>
      </div>
      <ul className="asset-result-board__list">
        {rows.map(({ target, status, presentation }) => (
          <li key={target.assetId} className={`asset-result-row asset-result-row--${status}`} data-asset-result={status}>
            <div className="asset-result-row__identity">
              <strong>{requestedTargetLabel(target, locale)}</strong>
              {target.assetKind && <span>{localizedAssetKind(target.assetKind, locale)}</span>}
            </div>
            <StatusPill label={presentation.label} tone={presentation.tone} />
            <div className="asset-result-row__outcome">
              <strong>{presentation.summary}</strong>
              {presentation.prose ? <span>{presentation.prose}</span> : null}
              {presentation.control ? (
                <button
                  type="button"
                  className="button button--secondary button--small"
                  onClick={presentation.control.destination === "progress"
                    ? onOpenProgress
                    : presentation.control.destination === "scope"
                      ? scrollToReportScope
                      : onOpenCoverage}
                >
                  <Icon
                    name={presentation.control.destination === "progress" ? "progress" : "coverage"}
                    size={16}
                  />
                  {text(presentation.control.destination === "progress"
                    ? copy.openProgress
                    : presentation.control.destination === "scope"
                      ? copy.openReportScope
                      : copy.openCoverage)}
                </button>
              ) : null}
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}

// A first/last-seen timestamp exists to answer one question: how long has this
// been here? The shared `formatDateTime` default omits the year, which is right
// for a task that ran minutes ago and wrong here -- it renders a finding carried
// since 2024 identically to one first seen this March, which is the same erasure
// of history as stamping the current run onto `firstSeenRunId`. Scoped to the
// rows that make an age claim; run-local times elsewhere keep the terser form.
const historyDateTime: Intl.DateTimeFormatOptions = {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
};

const projectReportFindings = (
  report: BeginnerMasterReport,
  canonicalFindings: Finding[],
  locale: "en" | "zh-TW",
): Finding[] => {
  const canonicalById = new Map(canonicalFindings.map((finding) => [finding.id, finding]));
  const targetById = new Map(report.requested.targets.map((target) => [target.assetId, target]));
  const frozenEvidenceSummaryUnavailable = locale === "en"
    ? copy.frozenEvidenceSummaryUnavailable.en
    : copy.frozenEvidenceSummaryUnavailable.zhTW;
  return report.findings.map((frozen, index) => {
    const current = canonicalById.get(frozen.findingId);
    const currentEvidenceById = new Map(current?.evidence.map((evidence) => [evidence.id, evidence]));
    const evidence = frozen.evidenceReferences.map((reference) => {
      const retained = currentEvidenceById.get(reference.evidenceId);
      const legacyFallback = reference.detailsFrozen === true ? undefined : retained;
      return {
        id: reference.evidenceId,
        sourceEngine: reference.engineId,
        sourceRule: reference.detailsFrozen === true
          ? reference.sourceRule
          : legacyFallback?.sourceRule,
        scannerDetails: reference.detailsFrozen === true
          ? reference.scannerDetails
          : legacyFallback?.scannerDetails,
        observedAt: reference.observedAt,
        summary: reference.detailsFrozen === true
          ? reference.summary ?? frozenEvidenceSummaryUnavailable
          : legacyFallback?.summary ?? frozenEvidenceSummaryUnavailable,
        location: reference.detailsFrozen === true
          ? reference.location
          : reference.location ?? legacyFallback?.location,
        rawArtifactHash: reference.artifactSha256,
        kind: reference.detailsFrozen === true ? reference.kind : legacyFallback?.kind,
        runId: report.runId,
        engineRunId: reference.detailsFrozen === true
          ? reference.engineRunId
          : legacyFallback?.engineRunId,
        artifactId: reference.detailsFrozen === true
          ? reference.artifactId
          : legacyFallback?.artifactId,
        redacted: reference.detailsFrozen === true
          ? reference.redacted
          : legacyFallback?.redacted,
      };
    });
    const observedTimes = evidence.map((item) => item.observedAt).sort();
    // A run can retain an affected asset coordinate even when an older report
    // did not retain that asset's display label. Keep the exact ID visible;
    // omitting it turns attributable scanner output into an apparently
    // asset-less problem (or silently hides one member of a shared finding).
    const targetLabel = requestedTargetListLabel(
      [...new Set(frozen.targetAssetIds)],
      targetById,
      locale,
    );
    return {
      id: frozen.findingId,
      caseId: report.caseId,
      fingerprint: frozen.fingerprint,
      assetId: frozen.targetAssetIds[0] ?? current?.assetId ?? "unknown-target",
      assetIds: [...frozen.targetAssetIds],
      assetName: targetLabel || current?.assetName || (locale === "en" ? "Recorded target" : "已記錄目標"),
      title: frozen.title,
      summary: frozen.plainLanguageRisk,
      impact: frozen.possibleImpact,
      recommendation: frozen.nextStep,
      expertType: localizedExpertType(frozen.recommendedExpertType, locale),
      severity: frozen.severity,
      confidence: frozen.confidence,
      // Taken from the frozen snapshot rather than from `current`, because
      // these describe the three sentences this row shows and those are the
      // frozen run's. Without them the impact and action composers fall back
      // to English, and the summary composer takes its no-basis branch, which
      // tells the reader the engine assigned a rating this product derived.
      family: frozen.family,
      severityBasisCode: frozen.severityBasisCode,
      confidenceBasisCode: frozen.confidenceBasisCode,
      observationDetails: frozen.observationDetails,
      contextFactors: frozen.contextFactors,
      awsIamPolicy: evidence
        .map((item) => item.scannerDetails?.awsIamPolicy)
        .find((details) => details !== undefined),
      priority: frozen.priority ?? report.findings.length - index,
      priorityReasons: [...frozen.priorityReasons],
      // Workflow is intentionally current user state; scan facts above remain
      // the frozen selected-run projection.
      workflowState: current?.workflowState ?? "unreviewed",
      evidence,
      controls: frozen.frameworkReferences.map((reference) => ({
        framework: reference.framework,
        version: reference.frameworkVersion,
        controlId: reference.controlId,
        relationship: "related" as const,
        title: reference.title,
        rationale: reference.rationale,
        mappingVersion: reference.mappingVersion,
      })),
      // New reports freeze this collection, including a meaningful empty
      // collection. Only reports that predate the field fall back to the
      // current canonical finding; never replace a frozen empty collection.
      officialReferences: frozen.officialReferences !== undefined
        ? [...frozen.officialReferences]
        : current?.officialReferences ?? [],
      // Prefer the frozen snapshot: these describe the selected run, and a
      // finding the case no longer holds still has to explain itself.
      verificationGuidance: frozen.verificationGuidance ?? current?.verificationGuidance,
      rollbackConsiderations: frozen.rollbackConsiderations ?? current?.rollbackConsiderations,
      tags: current?.tags,
      // The frozen snapshot carries no first/last-seen fields at all, so these
      // were not the selected run's record of history -- they were invented from
      // the run being viewed. The backend keeps the real first-seen run
      // deliberately, carrying it across every merge and every replacement
      // (case_service.rs), and the labels rendered beside these values say
      // "First-seen run" and "First observed" with no qualifier. Stamping this
      // run's id answered "is this new, or has it been here for months?" with
      // "new" for every recurring finding. Falling back to the run's own
      // evidence is only for a finding the case no longer holds, where that is
      // the last thing still known about it; the run id is dropped there
      // because being seen in this run does not establish it was seen here
      // first.
      firstSeenRunId: current?.firstSeenRunId,
      lastSeenRunId: current?.lastSeenRunId,
      firstSeenAt: current?.firstSeenAt ?? observedTimes[0] ?? report.state.lastDurableUpdate,
      lastSeenAt: current?.lastSeenAt ?? observedTimes.at(-1) ?? report.state.lastDurableUpdate,
    };
  });
};

function BeginnerReportOverview({ report, run }: { report: BeginnerMasterReport; run?: ScanRun }) {
  const { locale, text, formatDateTime, formatNumber } = useI18n();
  const completedChecks = completedAssetCheckCount(report);
  // Scoped to the `report-first-layer-scope` paragraph only: a label there is
  // followed by ": " in English but by a full-width "：" with no following
  // space in Traditional Chinese (an ASCII colon plus space is not how a
  // Chinese-reading label ends). Every other label on this page keeps its
  // literal ": " regardless of locale.
  const firstLayerLabelColon = locale === "en" ? ":" : "：";
  const firstLayerLabelGap = locale === "en" ? " " : "";
  const firstLayerLabelSeparator = `${firstLayerLabelColon}${firstLayerLabelGap}`;
  const securityFindingIds = new Set(
    report.findings.filter(isSecurityFinding).map((finding) => finding.findingId),
  );
  const problemCount = projectProblemRows(report.findings.filter(isSecurityFinding), report.problemGroups).length;
  const localhostSummary = run && isExactBuiltInLocalhostQuickScanRun(run)
    ? localhostTcpBeginnerSummary(run.engineRuns[0]!)
    : undefined;
  const nonSecurityOnly = hasOnlyTestedNonSecurityWork(report.actual.checks);
  const summary = localhostSummary
    ? { label: copy.reportConnectionOnly, tone: "neutral" as const }
    : nonSecurityOnly
      ? { label: copy.reportNonSecurityOnly, tone: "neutral" as const }
    : reportSummaryPresentation(report.state.summary);
  const hasManualReview = report.coverageCounts.manualReview > 0;
  const coverageItemsLabel = hasManualReview ? copy.coverageAttention : copy.coverageGaps;
  const coverageItemsTitle = hasManualReview ? copy.attentionTitle : copy.gapsTitle;
  const noRecordedGapDetail = localhostSummary?.exclusions ?? copy.noGap;
  const testedChecks = report.actual.checks.filter(checkRecordedTestedWork);
  const testedNetworkScopes = report.actual.networkScopes.filter((scope) =>
    scope.outcome === "tested_complete" || scope.outcome === "tested_partial",
  );
  const untestedNetworkScopes = report.actual.networkScopes.filter((scope) =>
    scope.outcome !== "tested_complete" && scope.outcome !== "tested_partial",
  );
  const targetById = new Map(
    report.requested.targets.map((target) => [target.assetId, target]),
  );
  const engineByTaskId = new Map(run?.engineRuns.map((engine) => [engine.id, engine]) ?? []);
  const orderedNextSteps = report.nextSteps
    // A step is listed once and can be the fix several findings name, so it
    // stays as long as one of them is a security finding.
    .filter((step) => !step.findingId
      || securityFindingIds.has(step.findingId)
      || (step.alsoResolves ?? []).some((findingId) => securityFindingIds.has(findingId)))
    .sort((left, right) => left.priority - right.priority);
  const coverageLossGaps = report.coverageGaps.filter(isCoverageLossGap);
  const recordNotes = report.coverageGaps.filter(isRecordNoteGap);
  const firstRequestedTarget = report.requested.targets[0];
  const firstTestedCheck = testedChecks[0];
  const firstTestedEngine = firstTestedCheck ? engineByTaskId.get(firstTestedCheck.taskId) : undefined;
  const firstCoverageGap = coverageLossGaps[0];
  const firstRecordNote = recordNotes[0];
  const coverageGapDimensionText = (
    gap: BeginnerMasterReport["coverageGaps"][number],
    unattributedDimension?: string,
  ): string => coverageGapDimensionLabel(gap, locale, run, unattributedDimension);
  const coverageGapLine = (gap: BeginnerMasterReport["coverageGaps"][number]): string => {
    const targets = requestedTargetListLabel(gap.targetAssetIds, targetById, locale);
    const unattributedText = gap.unattributed
      ? findingUnattributedGap(
          locale,
          gap.dimension.split(":")[0] ?? gap.dimension,
          gap.unattributed,
          {
            dimension: gap.dimension,
            reason: gap.reason,
            nextAction: gap.nextAction,
          },
        )
      : undefined;
    return `${targets || text(copy.requestedScope)} · ${coverageGapDimensionText(gap, unattributedText?.dimension)} · ${unattributedText
      ? unattributedText.reason
      : coverageGapProseWithoutDiagnosticCode(locale, gap.reason)}`;
  };
  const appendRemainingCount = (value: string, count: number): string => count > 0
    ? `${value} · ${text(copy.moreItems, { count: formatNumber(count) })}`
    : value;
  /**
   * Sibling of `appendRemainingCount` for values that are already a complete
   * sentence (a coverage-gap line, a record note, or a next-step action).
   * That sentence carries its own trailing "." or "。"; once a "+N more" tail
   * follows it, the period reads as a dangling full stop before the count
   * rather than the end of anything, so it is dropped -- but only when a tail
   * is actually appended. A lone sentence (count 0) keeps its period.
   */
  const appendRemainingCountToSentence = (value: string, count: number): string =>
    appendRemainingCount(count > 0 ? value.replace(/[.。]$/u, "") : value, count);
  const requestedSummary = firstRequestedTarget
    ? appendRemainingCount(
        requestedTargetLabel(firstRequestedTarget, locale),
        report.requested.targets.length - 1,
      )
    : text(copy.noRequestedTarget);
  // A check that can never run -- not included in this app version,
  // deprecated, license review, research only, or missing MCP configuration
  // -- does not make the run partial, so it must not count against
  // completion below. A check with no engine run found (an older report)
  // stays counted rather than silently dropped.
  const countedChecks = report.actual.checks.filter((check) => {
    const engine = engineByTaskId.get(check.taskId);
    return !engine || !isSettledSkippedCheck(engine);
  });
  const countedCheckTotal = countedChecks.length;
  const countedCheckCompleted = countedChecks.filter((check) => check.status === "tested_complete").length;
  const testedSummary = countedCheckTotal <= 1
    ? (firstTestedCheck
        ? appendRemainingCount(
            `${localizedCheckName(firstTestedCheck.checkId, locale, firstTestedEngine)} · ${text(testedStatusCopy(firstTestedCheck.status))}`,
            testedChecks.length - 1,
          )
        : text(copy.noTestedDimension))
    : countedCheckCompleted === countedCheckTotal && countedCheckTotal === 2
      ? text(copy.testedChecksBoth)
      : countedCheckCompleted === countedCheckTotal
        ? text(copy.testedChecksAll, { total: formatNumber(countedCheckTotal) })
        : countedCheckCompleted === 0
          ? text(copy.testedChecksNone, { total: formatNumber(countedCheckTotal) })
          : text(copy.testedChecksSome, {
              completed: formatNumber(countedCheckCompleted),
              total: formatNumber(countedCheckTotal),
            });
  const gapSummary = firstCoverageGap
    ? appendRemainingCountToSentence(coverageGapLine(firstCoverageGap), coverageLossGaps.length - 1)
    : text(noRecordedGapDetail);
  const recordNoteSummary = firstRecordNote
    ? appendRemainingCountToSentence(coverageGapLine(firstRecordNote), recordNotes.length - 1)
    : undefined;
  const nextStepActionText = (step: (typeof orderedNextSteps)[number]): string =>
    beginnerStepAction(locale, step, report.findings, report.actual.checks);
  // The first step stands apart from the coverage rows it closes, so it names
  // them inside the sentence, as the saved report's summary does.
  const nextStepSummary = orderedNextSteps[0]
    ? appendRemainingCountToSentence(
        actionAbout(
          nextStepActionText(orderedNextSteps[0]),
          stepCoverageNames(orderedNextSteps[0], report, locale, run),
          locale,
        ),
        orderedNextSteps.length - 1,
      )
    : text(copy.noNextStep);
  const inlineSeparator = locale === "en" ? "; " : "；";
  const requestedTargetsSummary = report.requested.targets.length > 0
    ? requestedTargetListLabel(
        report.requested.targets.map((target) => target.assetId),
        targetById,
        locale,
      )
    : text(copy.noRequestedTarget);
  const requestedStageSummary = `${text(reportStageCopy(report.requested.stage.value))}${
    report.requested.stage.availability === "current_case_fallback"
      ? ` (${text(copy.currentProjectFallback)})`
      : report.requested.stage.availability === "unavailable" && report.requested.stage.value
        ? ` (${text(copy.unavailableProvenance)})`
        : ""
  }`;
  // Only a Naabu network-discovery plan or the native localhost diagnostic has
  // a scan-depth dimension at all. Every other run (local project, website, or
  // guided internal-system) must not print "Scan depth" as if a value could
  // have been retained but wasn't.
  const stageIsApplicable = report.requested.stage.availability !== "not_applicable";
  // The reader-facing name of whoever a limit applies to: the target list
  // above already carries provenance for a requested target, so its label is
  // shown bare; a scanner falls back to the same display name the tested-work
  // rows use; anything else keeps its raw identifier rather than inventing one.
  const requestedLimitHolderLabel = (holder: string): string => {
    const target = targetById.get(holder);
    if (target) return target.label || holder;
    const engine = run?.engineRuns.find((candidate) => candidate.engineId === holder);
    if (engine) return localizedCheckName(holder, locale, engine);
    return holder;
  };
  // One row per distinct policy rather than per holder: a case authorizing
  // several targets, or a run with several scanners, otherwise repeats the
  // same kind and value once per holder in the collapsed "Limits used" list.
  const groupedLimits: Array<{
    kind: string;
    name: string;
    value: string;
    source: string;
    holders: string[];
  }> = [];
  const groupedLimitIndexByKey = new Map<string, number>();
  for (const limit of report.requested.limits) {
    const { holder, kind } = requestedLimitParts(limit.name);
    const key = `${kind}\u0000${limit.value}\u0000${limit.source}`;
    let index = groupedLimitIndexByKey.get(key);
    if (index === undefined) {
      index = groupedLimits.length;
      groupedLimitIndexByKey.set(key, index);
      groupedLimits.push({ kind, name: limit.name, value: limit.value, source: limit.source, holders: [] });
    }
    if (holder) {
      const label = requestedLimitHolderLabel(holder);
      const group = groupedLimits[index]!;
      if (!group.holders.includes(label)) group.holders.push(label);
    }
  }
  // A completed check-to-target coordinate names one asset per check; a run
  // with several catalog checks bound to the same asset otherwise repeats
  // "completed for <asset>" once per check. A partial shared task joins a
  // group only for an asset whose own check coordinate completed. Each group is reserved a
  // slot (and rendered) at the position where its first member would have
  // been emitted, so the relative order with every other line is preserved.
  const completedCoordinateGroups = new Map<string, {
    labels: string[];
    resolvedTarget: string | undefined;
    index: number;
  }>();
  const unresolvedCoordinateGroupKey = "\u0000target-not-retained";
  const listSeparator = locale === "zh-TW" ? "、" : ", ";
  const testedCheckSummaries: string[] = [];
  for (const check of testedChecks) {
    const engine = engineByTaskId.get(check.taskId);
    const checkLabel = localizedCheckName(check.checkId, locale, engine);
    const targets = check.targetAssetIds
      .flatMap((assetId) => {
        const target = report.requested.targets.find((candidate) => candidate.assetId === assetId);
        return target?.label ? [target.label] : [];
      })
      .join(locale === "en" ? ", " : "、");
    const checkPrefix = `${targets ? `${targets} · ` : ""}${checkLabel} · ${text(testedStatusCopy(check.status))}`;
    if (check.testedDimensions.length === 0) {
      testedCheckSummaries.push(`${checkPrefix} · ${text(copy.checkDimensionsUnavailable)}`);
      continue;
    }
    for (const dimension of check.testedDimensions) {
      const dimensionAssetId = check.targetAssetIds.find((assetId) =>
        dimensionRefersToAsset(dimension.value, assetId));
      const dimensionTarget = dimensionAssetId ? targetById.get(dimensionAssetId)?.label : undefined;
      const dimensionStatus = dimensionAssetId
        ? checkStatusForAsset(report, check, dimensionAssetId)
        : check.status;
      if (dimension.dimension === "completed check-to-target coordinate") {
        if (dimensionStatus === "tested_complete") {
          const groupKey = dimensionTarget ? `asset:${dimensionAssetId}` : unresolvedCoordinateGroupKey;
          let group = completedCoordinateGroups.get(groupKey);
          if (!group) {
            group = { labels: [], resolvedTarget: dimensionTarget, index: testedCheckSummaries.length };
            completedCoordinateGroups.set(groupKey, group);
            testedCheckSummaries.push("");
          }
          if (!group.labels.includes(checkLabel)) group.labels.push(checkLabel);
          continue;
        }
        testedCheckSummaries.push(
          `${dimensionTarget ? `${dimensionTarget} · ` : ""}${checkLabel} · ${text(testedStatusCopy(dimensionStatus))}`,
        );
        continue;
      }
      const dimensionPrefix = dimensionAssetId
        ? `${dimensionTarget ? `${dimensionTarget} · ` : ""}${checkLabel} · ${text(testedStatusCopy(dimensionStatus))}`
        : checkPrefix;
      const displayedValue = testedValueText(engine, dimension.dimension, dimension.value, locale);
      testedCheckSummaries.push(
        `${dimensionPrefix} · ${localizedCoverageDimension(dimension.dimension, locale)}${firstLayerLabelSeparator}${dimensionAssetId && dimensionTarget
          ? displayedValue.replaceAll(dimensionAssetId, dimensionTarget)
          : displayedValue}`,
      );
    }
  }
  for (const group of completedCoordinateGroups.values()) {
    testedCheckSummaries[group.index] = text(
      group.resolvedTarget ? copy.completedCheckForTargets : copy.completedCheckTargetUnavailable,
      { check: group.labels.join(listSeparator), targets: group.resolvedTarget ?? "" },
    );
  }
  const testedNetworkScopeSummaries = testedNetworkScopes.map((scope) => {
    const target = networkScopeTargetLabel(scope, targetById, locale);
    const addresses = scope.addressRanges.join(locale === "en" ? ", " : "、");
    const ports = scope.portRanges.join(locale === "en" ? ", " : "、");
    return `${target}: ${addresses} · ${scope.transport.toUpperCase()} ${ports} · ${text(reportStageCopy(scope.stage))} · ${text(testedStatusCopy(scope.outcome))}`;
  });
  const coherentLocalhostObservation = localhostSummary
    && ["reachable", "closed", "timed_out"].includes(localhostSummary.outcome);
  const coherentLocalhostTestedSummary = coherentLocalhostObservation && localhostSummary
    ? text(localhostSummary.description)
    : undefined;
  const actualTestedSummary = testedCheckSummaries.length + testedNetworkScopeSummaries.length > 0
    ? [...testedCheckSummaries, ...testedNetworkScopeSummaries].join(inlineSeparator)
    : coherentLocalhostTestedSummary ?? text(copy.noTestedDimension);
  // `report.actual.observedFrom` / `observedUntil` span every saved task,
  // including failed, cancelled, and not-tested siblings. The "Actually
  // tested" line may only use timestamps attached to work with tested output.
  const recordedTestedTimes = [
    ...testedChecks.flatMap((check) => [
      check.startedAt,
      ...check.testedDimensions.map((dimension) => dimension.observedAt),
      check.finishedAt,
    ]),
    ...testedNetworkScopes.map((scope) => scope.observedAt),
    coherentLocalhostObservation ? run?.engineRuns[0]?.localhostTcpObservation?.observedAt : undefined,
  ].filter((value): value is string => typeof value === "string" && Number.isFinite(Date.parse(value)));
  recordedTestedTimes.sort((left, right) => Date.parse(left) - Date.parse(right));
  const observedFrom = recordedTestedTimes[0];
  const observedUntil = recordedTestedTimes.at(-1);
  const observedTimeSummary = observedFrom && observedUntil
    ? observedFrom === observedUntil
      ? text(copy.observedAt, { time: formatDateTime(observedFrom) })
      : text(copy.observedWindow, {
          from: formatDateTime(observedFrom),
          until: formatDateTime(observedUntil),
        })
    : observedFrom
      ? text(copy.observedFromOnly, { time: formatDateTime(observedFrom) })
      : observedUntil
        ? text(copy.observedUntilOnly, { time: formatDateTime(observedUntil) })
        : text(copy.observedTimeUnavailable);
  const excludedGaps = report.coverageGaps.filter((gap) => gap.kind === "excluded");
  const exclusionsSummary = localhostSummary
    ? text(localhostSummary.exclusions)
    : excludedGaps.length > 0
      ? `${text(copy.recordedExclusions)}${firstLayerLabelSeparator}${excludedGaps.map((gap) => {
          const targets = requestedTargetListLabel(gap.targetAssetIds, targetById, locale);
          return `${targets ? `${targets} · ` : ""}${coverageGapDimensionText(gap)} · ${coverageGapProse(locale, gap.reason)}`;
        }).join(inlineSeparator)}`
      : report.coverageCounts.excluded > 0
        ? text(copy.recordedExclusionsUnavailable, { count: formatNumber(report.coverageCounts.excluded) })
        : text(copy.noRecordedExclusions);
  const countBreakdown = [
    [copy.testedComplete, completedChecks],
    [copy.testedPartialCount, report.coverageCounts.testedPartial],
    [copy.failedCount, report.coverageCounts.failed],
    [copy.timedOutCount, report.coverageCounts.timedOut],
    [copy.cancelledCount, report.coverageCounts.cancelled],
    [copy.notTestedCount, report.coverageCounts.notTested],
    [copy.excludedCount, report.coverageCounts.excluded],
    [copy.truncatedCount, report.coverageCounts.truncated],
    [copy.unattributedCount, report.coverageCounts.unattributed],
    [copy.manualReviewCount, report.coverageCounts.manualReview],
    [copy.unavailableCount, report.coverageCounts.unavailable],
  ] as const;
  // Every place a step covers, the lead finding's first: a grouped step's
  // problems sit in different places. "[redacted location]" is the masked
  // placeholder, not a place a reader can open.
  const stepLocations = (
    findings: readonly BeginnerMasterReport["findings"][number][],
  ): string[] => [
    ...new Set(findings.flatMap((finding) => finding.evidenceReferences)
      .map((reference) => reference.location?.trim())
      .filter((location): location is string => Boolean(location) && location !== "[redacted location]")
      .map((location) => findingLocationText(locale, location))),
  ];
  const stepLocationLine = (locations: readonly string[]): string => {
    const first = locations[0];
    if (!first) return "";
    const more = locations.length - 1;
    if (more === 0) return first;
    return locale === "en"
      ? `${first} and ${formatNumber(more)} more`
      : `${first}，另有 ${formatNumber(more)} 處`;
  };

  return (
    <section className="section-block" aria-labelledby="beginner-master-report-title">
      <div className="section-heading section-heading--row">
        <div>
          <p className="eyebrow">{text(copy.masterEyebrow)}</p>
          <h2 id="beginner-master-report-title">{text(copy.masterTitle)}</h2>
          <p>{text(copy.lastSaved, { time: formatDateTime(report.state.lastDurableUpdate) })}</p>
        </div>
        <StatusPill label={text(summary.label)} tone={summary.tone} />
      </div>

      <dl className="report-outcome-strip" aria-label={text(copy.masterTitle)}>
        <div>
          <dt>{text(copy.askedTitle)} <span>{formatNumber(report.requested.targets.length)}</span></dt>
          <dd>{requestedSummary}</dd>
        </div>
        <div>
          <dt>{text(copy.testedTitle)} <span>{formatNumber(testedChecks.length)}</span></dt>
          <dd>{testedSummary}</dd>
        </div>
        <div className={coverageLossGaps.length > 0 ? "report-outcome-strip__warning" : undefined}>
          <dt>{text(coverageItemsTitle)} <span>{formatNumber(coverageLossGaps.length)}</span></dt>
          <dd>{gapSummary}</dd>
        </div>
        {recordNotes.length > 0 && (
          <div>
            <dt>{text(copy.recordNotes)} <span>{formatNumber(recordNotes.length)}</span></dt>
            <dd>{recordNoteSummary}</dd>
          </div>
        )}
        <div>
          <dt>{text(copy.nextTitle)} <span>{formatNumber(orderedNextSteps.length)}</span></dt>
          <dd>{nextStepSummary}</dd>
        </div>
      </dl>

      <p className="report-first-layer-scope">
        <strong>{text(copy.firstLayerRequested)}{firstLayerLabelColon}</strong>{firstLayerLabelGap}
        {requestedTargetsSummary}{stageIsApplicable ? ` · ${text(copy.stage)}${firstLayerLabelSeparator}${requestedStageSummary}` : ""}
        {" | "}
        <strong>{text(copy.firstLayerActuallyTested)}{firstLayerLabelColon}</strong>{firstLayerLabelGap}
        {actualTestedSummary} · {observedTimeSummary} · {exclusionsSummary}
      </p>

      <details className="page-secondary-feature report-scope-disclosure">
        <summary>
          {text(copy.scopeLimitations)} · {text(hasManualReview ? copy.scopeAttentionSummary : copy.scopeSummary, {
            completed: formatNumber(completedChecks),
            gaps: formatNumber(coverageLossGaps.length),
          })}
        </summary>
      <div className="metrics-grid metrics-grid--five" aria-label={text(copy.masterTitle)}>
        <MetricCard
          label={text(copy.requestedTargets)}
          value={formatNumber(report.requested.targets.length)}
          detail={stageIsApplicable ? text(reportStageCopy(report.requested.stage.value)) : undefined}
          icon="coverage"
        />
        <MetricCard
          label={text(copy.testedComplete)}
          value={formatNumber(completedChecks)}
          detail={report.coverageCounts.testedPartial > 0
            ? text(copy.testedStatusPartial)
            : text(copy.testedStatusComplete)}
          icon="check"
          tone={completedChecks > 0 ? "accent" : "default"}
        />
        <MetricCard
          label={text(coverageItemsLabel)}
          value={formatNumber(coverageLossGaps.length)}
          detail={coverageLossGaps.length > 0 ? text(coverageItemsTitle) : text(noRecordedGapDetail)}
          icon="warning"
          tone={coverageLossGaps.length > 0 ? "warning" : "default"}
        />
        <MetricCard
          label={text(copy.recordNotes)}
          value={formatNumber(recordNotes.length)}
          icon="info"
          tone="default"
        />
        <MetricCard
          label={text(copy.reportFindings)}
          value={formatNumber(problemCount)}
          detail={text(copy.priorityDescription)}
          icon="findings"
          tone={problemCount > 0 ? "warning" : "default"}
        />
      </div>

      <div className="report-count-breakdown" aria-label={text(coverageItemsLabel)}>
        {countBreakdown.map(([label, count]) => (
          <span key={label.en}><strong>{formatNumber(count)}</strong> {text(label)}</span>
        ))}
      </div>

      <div className="coverage-grid">
        <article className="coverage-card">
          <h3>{text(copy.askedTitle)}</h3>
          {report.requested.targets.length > 0 ? (
            <ul className="detail-list">
              {report.requested.targets.map((target) => (
                <li key={target.assetId}>
                  <strong>{requestedTargetLabel(target, locale)}</strong>
                  {target.assetKind && <span>{localizedAssetKind(target.assetKind, locale)}</span>}
                </li>
              ))}
            </ul>
          ) : <p>{text(copy.noRequestedTarget)}</p>}
          {stageIsApplicable && (
            <p><strong>{text(copy.stage)}:</strong> {text(reportStageCopy(report.requested.stage.value))}</p>
          )}
          {report.requested.limits.length > 0 && (
            <details>
              <summary>{text(copy.requestedLimits)}</summary>
              <ul className="detail-list">
                {groupedLimits.map((limit, index) => (
                  <li key={`${limit.kind}-${limit.value}-${limit.source}-${index}`}>
                    <strong>{localizedRequestedLimitKind(limit.kind, locale)}</strong>
                    <span>{localizedRequestedLimitValue(limit.name, limit.value, locale)}</span>
                    {limit.holders.length > 0 && (
                      <small>{limit.holders.join(locale === "en" ? ", " : "、")}</small>
                    )}
                  </li>
                ))}
              </ul>
            </details>
          )}
          {report.requested.automaticReductions.length > 0 && (
            <div>
              <h4>{text(copy.automaticReductions)}</h4>
              <ul className="detail-list">
                {report.requested.automaticReductions.map((reduction, index) => (
                  <li key={`${reduction.dimension}-${index}`}>
                    <strong>{localizedCoverageDimension(reduction.dimension, locale)}</strong>
                    <span>{text(copy.reductionLine, {
                      requested: reduction.requested,
                      executed: reduction.executed,
                    })}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </article>

        <article className="coverage-card">
          <h3>{text(copy.testedTitle)}</h3>
          {report.actual.observedFrom && report.actual.observedUntil && (
            <p>{text(copy.observedWindow, {
              from: formatDateTime(report.actual.observedFrom),
              until: formatDateTime(report.actual.observedUntil),
            })}</p>
          )}
          {testedChecks.length > 0 ? (
            <ul className="detail-list">
              {testedChecks.map((check) => {
                const engine = engineByTaskId.get(check.taskId);
                const provenance = catalogEngineProvenanceLine(
                  report.technicalDetails.tasks.find((task) => task.taskId === check.taskId)?.execution,
                  text,
                  locale,
                );
                return (
                <li key={check.taskId}>
                  <strong>{localizedCheckName(check.checkId, locale, engine)}</strong>
                  <span>{text(testedStatusCopy(check.status))}</span>
                  {provenance && <span>{provenance}</span>}
                  {check.testedDimensions.map((dimension, index) => (
                    <span key={`${dimension.dimension}-${dimension.value}-${index}`}>
                      <span>
                        {localizedCoverageDimension(dimension.dimension, locale)}: {testedValueText(
                          engine,
                          dimension.dimension,
                          dimension.value,
                          locale,
                        )}
                        {dimension.observedAt && ` · ${text(copy.savedAt, { time: formatDateTime(dimension.observedAt) })}`}
                      </span>
                      <small>{testedObservationProse(locale, dimension.observation)}</small>
                    </span>
                  ))}
                </li>
                );
              })}
            </ul>
          ) : <p>{text(copy.noTestedDimension)}</p>}
          {testedNetworkScopes.length > 0 && (
            <details>
              <summary>{text(testedNetworkScopes.length === 1 ? copy.networkScopeCountOne : copy.networkScopeCountMany, { count: formatNumber(testedNetworkScopes.length) })} · {text(copy.exactNetworkScope)}</summary>
              <ul className="detail-list">
                {testedNetworkScopes.map((scope) => (
                  <li key={`${scope.taskId}-${scope.workUnitId}`}>
                    <strong>{networkScopeTargetLabel(scope, targetById, locale)}</strong>
                    <span>{scope.target}</span>
                    <span>{text(copy.networkAddresses)}: {scope.addressRanges.join(locale === "en" ? ", " : "、")}</span>
                    <span>{text(copy.networkPorts)}: {scope.transport.toUpperCase()} {scope.portRanges.join(locale === "en" ? ", " : "、")}</span>
                    <span>{text(copy.stage)}: {text(reportStageCopy(scope.stage))}</span>
                    <span>{text(copy.networkResult)}: {text(testedStatusCopy(scope.outcome))}</span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </article>

        <article className="coverage-card">
          <h3>{text(coverageItemsTitle)}</h3>
          {coverageLossGaps.length > 0 ? (
            <ul className="detail-list">
              {coverageLossGaps.map((gap, index) => {
                const targets = requestedTargetListLabel(gap.targetAssetIds, targetById, locale);
                // The dimension is "{engine}: results for {provider} {id}", so
                // the engine name is what precedes the first colon.
                const unattributedText = gap.unattributed
                  ? findingUnattributedGap(
                      locale,
                      gap.dimension.split(":")[0] ?? gap.dimension,
                      gap.unattributed,
                      { dimension: gap.dimension, reason: gap.reason, nextAction: gap.nextAction },
                    )
                  : undefined;
                return (
                  <li key={`${gap.taskId ?? "request"}-${gap.dimension}-${index}`}>
                    <strong>{targets || text(copy.requestedScope)}</strong>
                    {/*
                      * The backend's own reason, not a sentence derived from
                      * the kind. It writes a distinct one for each situation --
                      * `not_tested` covers a check that saved partial work and
                      * one that never started -- so a single
                      * sentence per kind was false for all but one of them, and
                      * contradicted the dimension printed beside it.
                      */}
                    <span>{coverageGapDimensionText(gap, unattributedText?.dimension)} · {unattributedText
                      ? unattributedText.reason
                      : coverageGapProse(locale, gap.reason)}</span>
                    <span>{unattributedText
                      ? unattributedText.nextAction
                      : coverageGapProse(locale, gap.nextAction)}</span>
                  </li>
                );
              })}
            </ul>
          ) : <p>{text(noRecordedGapDetail)}</p>}
          {untestedNetworkScopes.length > 0 && (
            <details>
              <summary>{text(untestedNetworkScopes.length === 1 ? copy.networkScopeCountOne : copy.networkScopeCountMany, { count: formatNumber(untestedNetworkScopes.length) })} · {text(copy.exactNetworkScope)}</summary>
              <ul className="detail-list">
                {untestedNetworkScopes.map((scope) => (
                  <li key={`${scope.taskId}-${scope.workUnitId}`}>
                    <strong>{networkScopeTargetLabel(scope, targetById, locale)}</strong>
                    <span>{scope.target}</span>
                    <span>{text(copy.networkAddresses)}: {scope.addressRanges.join(locale === "en" ? ", " : "、")}</span>
                    <span>{text(copy.networkPorts)}: {scope.transport.toUpperCase()} {scope.portRanges.join(locale === "en" ? ", " : "、")}</span>
                    <span>{text(copy.stage)}: {text(reportStageCopy(scope.stage))}</span>
                    <span>{text(copy.networkResult)}: {text(testedStatusCopy(scope.outcome))}</span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </article>
        {recordNotes.length > 0 && (
          <article className="coverage-card">
            <h3>{text(copy.recordNotes)}</h3>
            <ul className="detail-list">
              {recordNotes.map((gap, index) => {
                const targets = requestedTargetListLabel(gap.targetAssetIds, targetById, locale);
                const unattributedText = gap.unattributed
                  ? findingUnattributedGap(
                      locale,
                      gap.dimension.split(":")[0] ?? gap.dimension,
                      gap.unattributed,
                      { dimension: gap.dimension, reason: gap.reason, nextAction: gap.nextAction },
                    )
                  : undefined;
                return (
                  <li key={`${gap.taskId ?? "request"}-${gap.dimension}-${index}`}>
                    <strong>{targets || text(copy.requestedScope)}</strong>
                    <span>{coverageGapDimensionText(gap, unattributedText?.dimension)} · {unattributedText
                      ? unattributedText.reason
                      : coverageGapProse(locale, gap.reason)}</span>
                    <span>{unattributedText
                      ? unattributedText.nextAction
                      : coverageGapProse(locale, gap.nextAction)}</span>
                  </li>
                );
              })}
            </ul>
          </article>
        )}
      </div>

      <div className="section-heading">
        <h3>{text(copy.nextTitle)}</h3>
      </div>
      {orderedNextSteps.length > 0 ? (
        <ol className="detail-list">
          {orderedNextSteps.map((step, index) => {
            const covers = new Set([step.findingId, ...(step.alsoResolves ?? [])].filter(Boolean).map(id =>
              report.problemGroups?.find(group => group.findingIds.includes(id!))?.groupId ?? id)).size;
            const closes = stepCoverageNames(step, report, locale, run);
            const lead = step.findingId
              ? report.findings.find((finding) => finding.findingId === step.findingId)
              : undefined;
            const headline = lead ? findingHeadline(locale, lead.title, lead.family) : undefined;
            const locations = lead
              ? stepLocations([lead, ...(step.alsoResolves ?? []).flatMap((id) =>
                report.findings.filter((finding) => finding.findingId === id))])
              : [];
            const locationLine = locations.length > 0 ? stepLocationLine(locations) : undefined;
            return (
              <li key={`${step.code}-${step.findingId ?? step.taskId ?? index}`}>
                <strong>{nextStepActionText(step)}</strong>
                {closes.length > 0 && <span>{closes.join(inlineSeparator)}</span>}
                {headline && (
                  <span>{covers > 1
                    ? stepGroupLead(locale, covers, step.sharedFix === true, headline)
                    : headline}</span>
                )}
                {locationLine && (
                  <span>
                    {adviceLabel(locale, text(copy.reportedLocation))}
                    {locationLine}
                  </span>
                )}
                {lead && step.code !== "confirm_finding_after_incomplete_check" && (
                  <span>
                    {adviceLabel(locale, text(copy.stepConfirm))}
                    {stepConfirmation(locale, lead.verificationGuidance, lead.title, covers)}
                  </span>
                )}
                {step.recommendedExpertType && <span>{localizedExpertType(step.recommendedExpertType, locale)}</span>}
              </li>
            );
          })}
        </ol>
      ) : <p>{text(copy.noNextStep)}</p>}

      </details>
    </section>
  );
}

function ReportEndMatter({ report, run }: { report: BeginnerMasterReport; run?: ScanRun }) {
  const { locale, text, formatDateTime, formatNumber } = useI18n();
  const engineByTaskId = new Map(run?.engineRuns.map((engine) => [engine.id, engine]) ?? []);
  const hasUntrustedEvidenceSummary = report.findings.some((finding) =>
    finding.evidenceReferences.some((reference) => reference.summary?.endsWith(UNTRUSTED_EVIDENCE_CAVEAT)));

  return (
    <footer className="report-end-matter">
      <details className="page-technical-details page-technical-details--guide">
        <summary>{text(copy.reportEndMatter)}</summary>
        <section>
          <h3>{text(copy.reportTerms)}</h3>
          <p>{text(copy.reportBoundary)}</p>
          {hasUntrustedEvidenceSummary && <p>{text(copy.untrustedEvidenceTerms)}</p>}
        </section>
        {report.dataQualityWarnings.length > 0 && (
          <section>
            <h3>{text(copy.dataWarnings, { count: formatNumber(report.dataQualityWarnings.length) })}</h3>
            <ul className="data-quality-warnings">
              {report.dataQualityWarnings.map((warning) => (
                <li key={warning}>{localizedDataQualityWarning(warning, locale)}</li>
              ))}
            </ul>
          </section>
        )}
        <section>
          <h3>{text(copy.reportTechnicalDetails)}</h3>
          <div className="evidence-list">
            {report.technicalDetails.tasks.map((task) => {
              const check = report.actual.checks.find((item) => item.taskId === task.taskId);
              const engine = engineByTaskId.get(task.taskId);
              return (
                <article key={task.taskId} className="evidence-item">
                  <div className="evidence-item__header">
                    <strong>{check ? localizedCheckName(check.checkId, locale, engine) : text(copy.coverageDetail)}</strong>
                    <span>{engineStatusMeta[task.status].label}</span>
                  </div>
                  <dl>
                    {task.execution.kind === "catalog_engine" && task.execution.engineVersion?.trim() && (
                      <div><dt>{text(copy.scannerVersion)}</dt><dd>{scannerVersionLabel(task.execution.engineVersion, task.execution.reportedVersion, "exact", locale)}</dd></div>
                    )}
                    {task.execution.kind === "catalog_engine" && task.execution.knowledgeDate?.trim() && (
                      <div><dt>{text(copy.lastUpdated)}</dt><dd>{task.execution.knowledgeDate.trim()}</dd></div>
                    )}
                    <div><dt>{text(copy.taskProgress)}</dt><dd>{formatNumber(task.progressPercent)}%</dd></div>
                    <div><dt>{text(copy.taskStatus)}</dt><dd>{engineStatusMeta[task.status].label}</dd></div>
                    <div><dt>{text(copy.taskErrorCode)}</dt><dd><code>{task.errorCode ?? text(copy.taskNoError)}</code></dd></div>
                    <div><dt>{text(copy.taskEvidence)}</dt><dd>{formatNumber(task.evidenceSha256.length)}</dd></div>
                    {task.startedAt && <div><dt>{text(copy.firstObserved)}</dt><dd>{formatDateTime(task.startedAt)}</dd></div>}
                    {task.finishedAt && <div><dt>{text(copy.lastObserved)}</dt><dd>{formatDateTime(task.finishedAt)}</dd></div>}
                  </dl>
                </article>
              );
            })}
          </div>
        </section>
      </details>
    </footer>
  );
}

const workflowTone = (state: FindingWorkflowState): string => {
  if (state === "verified_resolved" || state === "confirmed") return "positive";
  if (state === "false_positive") return "neutral";
  if (state === "remediated_pending_verification" || state === "remediation_reported") return "info";
  return "warning";
};

export function FindingsPage({
  report,
  selectedRunId,
  runningScanResultsPending,
  reportUnavailable,
  findings: canonicalFindings,
  findingGroups,
  findingGroupEvents,
  correlationReport,
  runs,
  focusedFindingId,
  workflowEvents,
  busy,
  onUpdateWorkflow,
  onGroupFindings,
  onUngroupFindings,
  onOpenCoverage,
  onOpenProgress,
  onOpenExport,
  onSelectRun,
}: FindingsPageProps) {
  const { locale, text, formatDateTime, formatNumber } = useI18n();
  const hasUnratedSeverity = (finding: Finding): boolean => findingSeverityIsUnrated({
    severity: finding.severity,
    severityBasisCode: finding.severityBasisCode,
    priorityReasons: finding.priorityReasons,
  });
  const severityLabelFor = (finding: Finding): string => severityMeta[finding.severity].label;
  const resultRecords = useMemo(
    () => report
      ? projectReportFindings(report, canonicalFindings, locale)
      : reportUnavailable
        ? []
        : canonicalFindings,
    [canonicalFindings, locale, report, reportUnavailable],
  );
  const findings = useMemo(
    () => resultRecords.filter(isSecurityFinding),
    [resultRecords],
  );
  const actionUnconfirmedByCoverage = (finding: Finding): boolean => {
    if (!report || isExposureObservation(finding)) return false;
    return findingUnconfirmedByCoverage(
      finding.evidence.map((item) => ({ engineRunId: item.engineRunId })),
      report.actual.checks,
    );
  };
  const hasTypedInventory = Boolean(report?.inventory?.total);
  const observations = useMemo(
    () => hasTypedInventory ? [] : resultRecords.filter(isExposureObservation),
    [hasTypedInventory, resultRecords],
  );
  const collationLocale = locale === "en" ? "en" : "zh-Hant";
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [workflow, setWorkflow] = useState<FindingWorkflowState | "all">("all");
  const [expertType, setExpertType] = useState("all");
  const [control, setControl] = useState("all");
  const [selectedAssetId, setSelectedAssetId] = useState<string | undefined>(undefined);
  const [selectedId, setSelectedId] = useState<string | undefined>(focusedFindingId);
  const [decisionStatus, setDecisionStatus] = useState<(typeof decisionStates)[number]>("expert_review_requested");
  const [decidedBy, setDecidedBy] = useState("");
  const [decisionReason, setDecisionReason] = useState("");
  const [decisionExpiry, setDecisionExpiry] = useState("");
  const [groupTitle, setGroupTitle] = useState("");
  const [groupRationale, setGroupRationale] = useState("");
  const [groupFindingIds, setGroupFindingIds] = useState<string[]>([]);
  const appliedFocusId = useRef<string | undefined>(undefined);
  const advancedFiltersRef = useRef<HTMLDetailsElement>(null);
  const clearFilters = () => {
    setQuery("");
    setSeverity("all");
    setWorkflow("all");
    setExpertType("all");
    setControl("all");
    setSelectedAssetId(undefined);
  };
  const revealFinding = (
    findingId: string,
    { preserveFilters = false, scrollOnWideLayout = true } = {},
  ): void => {
    if (!preserveFilters) clearFilters();
    setSelectedId(findingId);
    window.setTimeout(() => scrollToSelectedFinding(scrollOnWideLayout), 0);
  };

  useEffect(() => {
    if (focusedFindingId && appliedFocusId.current !== focusedFindingId && findings.some((finding) => finding.id === focusedFindingId)) {
      appliedFocusId.current = focusedFindingId;
      clearFilters();
      setSelectedId(focusedFindingId);
      window.setTimeout(scrollToSelectedFinding, 0);
    }
  }, [findings, focusedFindingId]);

  useEffect(() => {
    setSelectedAssetId(undefined);
  }, [report?.caseId, report?.runId]);

  useEffect(() => {
    setSelectedId((current) => findings.some((finding) => finding.id === current) ? current : undefined);
  }, [findings]);

  // Rows projected from the report keep its order, the order the exported report numbers; only rows without a report are sorted here.
  const ordered = useMemo(
    () => report
      ? [...findings]
      : [...findings].sort((a, b) => b.priority - a.priority || a.title.localeCompare(b.title, collationLocale)),
    [collationLocale, findings, report],
  );
  const orderedProblems = useMemo(
    () => projectProblemRows(ordered, report?.problemGroups),
    [ordered, report?.problemGroups],
  );
  const displayRankByFindingId = useMemo(
    () => new Map(orderedProblems.flatMap((row, index) => row.members.map(finding => [finding.id, index + 1] as const))),
    [orderedProblems],
  );
  const expertTypes = useMemo(
    () => [...new Set(findings.map((finding) => finding.expertType).filter(Boolean))].sort((a, b) => a.localeCompare(b, collationLocale)),
    [collationLocale, findings],
  );
  const controls = useMemo(() => {
    const values = new Map<string, { key: string; label: string }>();
    for (const finding of findings) {
      for (const item of finding.controls) {
        const key = controlKey(item.framework, item.version, item.controlId);
        values.set(key, { key, label: `${item.framework} ${item.controlId}` });
      }
    }
    return [...values.values()].sort((a, b) => a.label.localeCompare(b.label, collationLocale));
  }, [collationLocale, findings]);
  const filtered = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase(collationLocale);
    return ordered.filter((finding) => {
      const matchesSeverity = severity === "all" || finding.severity === severity;
      const matchesWorkflow = workflow === "all" || finding.workflowState === workflow;
      const matchesExpert = expertType === "all" || finding.expertType === expertType;
      const matchesControl = control === "all" || finding.controls.some(
        (item) => controlKey(item.framework, item.version, item.controlId) === control,
      );
      const findingAssetIds = finding.assetIds?.length ? finding.assetIds : [finding.assetId];
      const matchesAsset = selectedAssetId === undefined || findingAssetIds.includes(selectedAssetId);
      const matchesQuery = !normalizedQuery || [
        finding.title,
        ...report?.problemGroups?.filter(group => group.findingIds.includes(finding.id)).map(group => problemGroupTitle(group, locale)) ?? [],
        finding.assetName,
        finding.summary,
        finding.expertType,
        finding.fingerprint,
        ...(finding.tags ?? []),
        ...finding.evidence.map((item) => `${item.sourceEngine} ${item.summary}`),
        ...finding.controls.map((item) => `${item.framework} ${item.controlId} ${item.title ?? ""}`),
      ].join(" ").toLocaleLowerCase(collationLocale).includes(normalizedQuery);
      return matchesSeverity && matchesWorkflow && matchesExpert && matchesControl && matchesAsset && matchesQuery;
    });
  }, [collationLocale, control, expertType, locale, ordered, query, report?.problemGroups, selectedAssetId, severity, workflow]);

  const filteredProblems = useMemo(
    () => projectProblemRows(filtered, report?.problemGroups),
    [filtered, report?.problemGroups],
  );
  const selected = filtered.find((finding) => finding.id === selectedId);
  const selectedProblem = orderedProblems.find(row => row.members.some(member => member.id === selectedId));
  const selectedProblemGroup = selectedProblem?.group;
  const selectedProblemMembers = selectedProblemGroup
    ? selectedProblem!.members
    : [];
  const selectedScannerRemediations = selected
    ? uniqueScannerRemediations(selected.evidence)
    : [];
  const selectedScannerFixedVersions = selected
    ? uniqueScannerFixedVersions(selected.evidence)
    : [];
  const iamValuePreview = (values: string[]): string => {
    if (values.length === 0) return text(copy.notReported);
    const visible = values.slice(0, 6).join(" · ");
    const omitted = values.length - 6;
    return omitted > 0
      ? `${visible} · ${text(copy.iamAdditionalValues, { count: formatNumber(omitted) })}`
      : visible;
  };
  const selectedEvents = workflowEvents
    .filter((event) => event.findingId === selectedId)
    .sort((left, right) => right.decidedAt.localeCompare(left.decidedAt));
  const activeProblems = useMemo(() => projectProblemRows(
    ordered.filter((finding) => finding.workflowState !== "verified_resolved" && finding.workflowState !== "false_positive"),
    report?.problemGroups,
  ), [ordered, report?.problemGroups]);
  const topFindings = activeProblems.slice(0, 3);
  const affectedAssetSummaries = useMemo(() => {
    const targetById = new Map(
      (report?.requested.targets ?? []).map((target) => [target.assetId, target]),
    );
    const summaries = new Map<string, {
      assetId: string;
      label: string;
      findingCount: number;
      highestSeverity: Severity;
      topFindingId: string;
      topFindingTitle: string;
    }>();
    for (const {finding, group} of activeProblems) {
      const assetIds = finding.assetIds?.length ? finding.assetIds : [finding.assetId];
      for (const assetId of new Set(assetIds)) {
        const existing = summaries.get(assetId);
        if (existing) {
          existing.findingCount += 1;
          if (severityOrder.indexOf(finding.severity) < severityOrder.indexOf(existing.highestSeverity)) {
            existing.highestSeverity = finding.severity;
          }
          continue;
        }
        // A finding carries its own resolved asset name. That was never the
        // internal-ID defect, so it stays ahead of the qualified ID fallback.
        const requestedTarget = targetById.get(assetId);
        summaries.set(assetId, {
          assetId,
          label: requestedTarget?.label
            ? requestedTargetLabel(requestedTarget, locale)
            : assetIds.length === 1 && finding.assetName
              ? finding.assetName
              : requestedTargetLabelById(assetId, targetById, locale),
          findingCount: 1,
          highestSeverity: finding.severity,
          topFindingId: finding.id,
          topFindingTitle: group ? problemGroupTitle(group, locale) : findingHeadline(locale, finding.title, finding.family),
        });
      }
    }
    return [...summaries.values()].sort((left, right) =>
      severityOrder.indexOf(left.highestSeverity) - severityOrder.indexOf(right.highestSeverity)
      || right.findingCount - left.findingCount
      || left.label.localeCompare(right.label, collationLocale));
  }, [activeProblems, collationLocale, locale, report?.requested.targets]);
  // Evidence carried over from an earlier run names an engine run of that
  // run, so every run the page holds is searched, not only the one on screen.
  const engineNameByEngineRunId = new Map(runs.flatMap((run) =>
    run.engineRuns.map((engine) => [engine.id, engine.engineName.trim()] as const)));
  const engineNameForEvidence = (evidence: Finding["evidence"][number]): string =>
    engineNameByEngineRunId.get(evidence.engineRunId ?? "") ?? evidence.sourceEngine;
  const selectedBenchmarkLines = selected
    ? benchmarkAdviceLines(selected.evidence, engineNameForEvidence, locale)
    : [];
  // One location already joins its parts with " · ", so two locations are
  // separated by a semicolon rather than another dot.
  const locationsFor = (finding: Finding): string[] => [
    ...new Set(finding.evidence
      .map((evidence) => evidence.location?.trim())
      .filter((location): location is string => Boolean(location))
      .map((location) => findingLocationText(locale, location))),
  ];
  const criticalCount = orderedProblems.filter(({finding}) => finding.severity === "critical").length;
  const highCount = orderedProblems.filter(({finding}) => finding.severity === "high").length;
  const needsReview = orderedProblems.filter(({members}) => members.some(finding => ["unreviewed", "unconfirmed", "expert_review_requested"].includes(finding.workflowState))).length;
  const affectedAssets = new Set(findings.flatMap((finding) => finding.assetIds ?? [finding.assetId])).size;
  const selectedAssetLabel = affectedAssetSummaries.find((asset) => asset.assetId === selectedAssetId)?.label
    ?? selectedAssetId;
  const groupedFindingIds = useMemo(
    () => new Set(findingGroups.flatMap((group) => group.findingIds)),
    [findingGroups],
  );
  const findingById = useMemo(
    () => new Map(findings.map((finding) => [finding.id, finding])),
    [findings],
  );
  const visibleFindingGroups = useMemo(
    () => projectVisibleFindingGroups(findingGroups, new Set(findingById.keys())),
    [findingById, findingGroups],
  );
  const orderedGroupEvents = useMemo(
    () => [...findingGroupEvents].sort((left, right) => right.occurredAt.localeCompare(left.occurredAt) || right.id.localeCompare(left.id)),
    [findingGroupEvents],
  );
  // A suggestion stays when every finding it names is on this page and is not
  // already in a case finding group. It also drops when those findings all
  // belong to one rendered problem card. Membership comes from the rows
  // `projectProblemRows` produced for the findings this page lists, so a group
  // the report stored but did not render leaves the suggestion in place.
  // Accepting a suggestion that names a missing finding would be rejected, and
  // findings already shown together are read on that card.
  const correlationSuggestions = useMemo(() => {
    const alreadyGrouped = new Set(findingGroups.flatMap((group) => group.findingIds));
    const renderedGroupByFinding = new Map<string, string>();
    for (const row of orderedProblems) {
      if (row.group && row.members.length >= 2) {
        for (const member of row.members) renderedGroupByFinding.set(member.id, row.group.groupId);
      }
    }
    return (correlationReport?.suggestions ?? []).filter((suggestion) => {
      if (!suggestion.findingIds.every((findingId) => findingById.has(findingId) && !alreadyGrouped.has(findingId))) {
        return false;
      }
      const rendered = suggestion.findingIds.map((findingId) => renderedGroupByFinding.get(findingId));
      const shared = rendered[0];
      return !(shared !== undefined && rendered.every((groupId) => groupId === shared));
    });
  }, [correlationReport, findingById, findingGroups, orderedProblems]);
  const correlationUnverifiable = useMemo(
    () => (correlationReport?.unverifiable ?? []).filter((entry) =>
      entry.findingIds.every((findingId) => findingById.has(findingId))),
    [correlationReport, findingById],
  );
  // Reported separately from the lists above: the backend capped its own output,
  // and that must never read as "this is everything".
  const correlationTruncated = correlationReport?.truncatedSuggestions ?? 0;
  const hasCorrelationContent = correlationSuggestions.length > 0
    || correlationUnverifiable.length > 0
    || correlationTruncated > 0;

  useEffect(() => {
    setGroupFindingIds((current) => current.filter((findingId) => !groupedFindingIds.has(findingId)));
  }, [groupedFindingIds]);

  const explicitlySelectedRun = selectedRunId === undefined
    ? undefined
    : runs.find((run) => run.id === selectedRunId);
  const latestRun = selectedRunId === undefined
    ? (report ? runs.find((run) => run.id === report.runId) : undefined) ?? runs[0]
    : explicitlySelectedRun;
  const activeRun = latestRun && activeRunStatuses.has(latestRun.status) ? latestRun : undefined;
  const latestRequestOutcomeSummary = scanRequestOutcomeBeginnerSummary(latestRun?.requestOutcome);
  const reportRunPicker = runs.length > 1 || (runs.length > 0 && !latestRun) ? (
    <label className="select-filter">
      <span>{text(copy.reportRun)}</span>
      <select value={latestRun?.id ?? ""} onChange={(event) => onSelectRun?.(event.target.value)}>
        {!latestRun && <option value="" disabled>{text(copy.reportRunUnavailable)}</option>}
        {runs.map((run) => (
          <option key={run.id} value={run.id}>{scanRunIdentityPresentation(run, locale)}</option>
        ))}
      </select>
    </label>
  ) : undefined;
  const reportActions = (
    <div className="button-group">
      {reportRunPicker}
      {latestRun && (
        <button
          className={`button ${report && report.state.summary !== "complete" ? "button--secondary" : "button--primary"} button--small`}
          type="button"
          onClick={() => onOpenExport(latestRun.id)}
        >
          <Icon name="export" size={16} />{text(copy.openExport)}
        </button>
      )}
    </div>
  );
  const unavailableReportNotice = latestRun
    ? unavailableRunBoundReportCopy
    : unavailableSelectedRunCopy;
  if (activeRun) {
    return null;
  }
  const nonSecurityOnly = Boolean(report
    && hasOnlyTestedNonSecurityWork(report.actual.checks));
  const observationDetails = (finding: Finding): string[] => {
    const retained = finding.observationDetails
      ?? finding.tags?.filter((tag) =>
        tag.startsWith("port:")
        || tag.startsWith("protocol:")
        || tag.startsWith("http-status:"))
      ?? [];
    return retained.map((detail) => {
      const [key, ...valueParts] = detail.split(":");
      const value = valueParts.join(":");
      if (!value) return detail;
      if (key === "port") return `${text(copy.observationPort)} ${value}`;
      if (key === "protocol") return `${text(copy.observationProtocol)} ${value}`;
      if (key === "http-status") return `${text(copy.observationStatus)} ${value}`;
      return detail;
    });
  };
  const observationAssetCount = new Set(observations.flatMap((finding) =>
    finding.assetIds?.length ? finding.assetIds : [finding.assetId])).size;
  const representativeObservations = observations.slice(0, 3);
  const typedInventory = report?.inventory;
  const inventoryTargetById = new Map(
    report?.requested.targets.map((target) => [target.assetId, target]) ?? [],
  );
  const inventoryItemPresentation = (item: BeginnerInventoryItem) => {
    if (item.kind === "service") {
      return {
        title: `${item.endpoint}${item.port === undefined ? "" : `:${item.port}`}`,
        detail: [
          item.transport,
          ...item.schemes,
          item.httpStatuses.length > 0
            ? `${text(copy.inventoryHttpStatus)} ${item.httpStatuses.join(", ")}`
            : undefined,
          item.tlsObservations.includes(true) ? text(copy.inventoryTlsObserved) : undefined,
        ].filter(Boolean).join(" · "),
      };
    }
    if (item.kind === "software_component") {
      return {
        title: [item.name, item.version].filter(Boolean).join(" "),
        detail: [item.packageType, item.purl].filter(Boolean).join(" · "),
      };
    }
    if (item.kind === "cloud_resource") return {
      title: item.displayName ?? item.nativeId ?? item.resourceType,
      detail: [
        item.resourceType,
        item.nativeId ? `${text(copy.inventoryNativeId)} ${item.nativeId}` : undefined,
      ].filter(Boolean).join(" · "),
    };
    if (item.kind === "workflow_component") return {
      title: item.name,
      detail: [
        `${text(copy.inventoryComponentType)} ${item.componentType}`,
        item.model ? `${text(copy.inventoryModel)} ${item.model}` : undefined,
        item.isGuardrail === undefined
          ? undefined
          : `${text(copy.inventoryGuardrail)} ${text(item.isGuardrail ? copy.inventoryYes : copy.inventoryNo)}`,
      ].filter(Boolean).join(" · "),
    };
    return {
      title: `${item.source} → ${item.target}`,
      detail: item.condition ? `${text(copy.inventoryCondition)} ${item.condition}` : "",
    };
  };
  const renderInventoryItem = (item: BeginnerInventoryItem, key: string) => {
    const presentation = inventoryItemPresentation(item);
    const sourceEngines = [...new Set(item.sources.map((source) => source.engineId))]
      .sort((left, right) => left.localeCompare(right, collationLocale));
    return (
      <article className="evidence-item" key={key}>
        <div className="evidence-item__header">
          <strong>{presentation.title}</strong>
          <span>{[
            requestedTargetLabelById(item.assetId, inventoryTargetById, locale),
            presentation.detail,
          ].filter(Boolean).join(" · ")}</span>
        </div>
        <small>{text(copy.inventorySources, { count: formatNumber(item.sources.length) })} · {
          sourceEngines.join(locale === "en" ? ", " : "、")
        }</small>
      </article>
    );
  };
  const typedInventorySection = typedInventory && typedInventory.total > 0 ? (
    <section className="section-block" aria-labelledby="typed-inventory-title">
      <div className="section-heading">
        <p className="eyebrow">{text(copy.typedInventoryEyebrow)}</p>
        <h2 id="typed-inventory-title">{text(copy.typedInventoryTitle)}</h2>
        <p>{text(copy.typedInventoryDescription)}</p>
      </div>
      <p className="service-observations__summary">
        <strong>{text(copy.typedInventorySummary, {
          items: text(
            typedInventory.total === 1 ? copy.typedInventoryItemsCountOne : copy.typedInventoryItemsCountMany,
            { count: formatNumber(typedInventory.total) },
          ),
          assets: text(
            typedInventory.assetIds.length === 1 ? copy.typedInventoryAssetsCountOne : copy.typedInventoryAssetsCountMany,
            { count: formatNumber(typedInventory.assetIds.length) },
          ),
        })}</strong>
      </p>
      <div className="metrics-grid metrics-grid--three">
        <MetricCard label={text(copy.inventoryServices)} value={typedInventory.counts.services} icon="database" />
        <MetricCard label={text(copy.inventoryComponents)} value={typedInventory.counts.softwareComponents} icon="file" />
        <MetricCard label={text(copy.inventoryCloudResources)} value={typedInventory.counts.cloudResources} icon="database" />
        {typedInventory.counts.workflowComponents > 0 ? (
          <MetricCard label={text(copy.inventoryWorkflowComponents)} value={typedInventory.counts.workflowComponents} icon="file" />
        ) : null}
        {typedInventory.counts.workflowRelationships > 0 ? (
          <MetricCard label={text(copy.inventoryWorkflowRelationships)} value={typedInventory.counts.workflowRelationships} icon="database" />
        ) : null}
      </div>
      <div className="section-heading"><h3>{text(copy.inventoryExamples)}</h3></div>
      <div className="evidence-list">
        {typedInventory.representativeSample.slice(0, 3).map((item, index) =>
          renderInventoryItem(item, `inventory-sample-${index}`))}
      </div>
      <details className="page-secondary-feature service-observations__complete">
        <summary>{text(typedInventory.total === 1 ? copy.inventoryAllItemsOne : copy.inventoryAllItemsMany, { count: formatNumber(typedInventory.total) })}</summary>
        {typedInventory.byAsset.map((asset) => (
          <section className="section-block" key={asset.assetId}>
            <div className="section-heading">
              <h3>{requestedTargetLabelById(asset.assetId, inventoryTargetById, locale)}</h3>
              <p>{text(asset.total === 1 ? copy.inventoryAssetSummaryOne : copy.inventoryAssetSummaryMany, { count: formatNumber(asset.total) })}</p>
            </div>
            <div className="evidence-list">
              {typedInventory.items
                .filter((item) => item.assetId === asset.assetId)
                .map((item, index) => renderInventoryItem(item, `${asset.assetId}-${index}`))}
            </div>
          </section>
        ))}
      </details>
    </section>
  ) : null;
  const renderObservation = (finding: Finding, complete: boolean) => {
    const details = observationDetails(finding);
    return (
      <article className="evidence-item" key={finding.id}>
        <div className="evidence-item__header">
          <strong>{text(finding.severityBasisCode === "open_port" ? copy.observationOpenPort : copy.observationHttp)}</strong>
          <span>{[finding.assetName, ...details].join(" · ")}</span>
        </div>
        {complete && (
          <>
            <p>{text(copy.observationNext)}</p>
            <small>{[
              finding.evidence[0]?.sourceEngine,
              text(copy.evidenceCount, { count: formatNumber(finding.evidence.length) }),
            ].filter(Boolean).join(" · ")}</small>
          </>
        )}
      </article>
    );
  };
  const observationSection = !hasTypedInventory && observations.length > 0 ? (
    <section className="section-block" aria-labelledby="service-observations-title">
      <div className="section-heading">
        <p className="eyebrow">{text(copy.observationsEyebrow)}</p>
        <h2 id="service-observations-title">{text(copy.observationsTitle)}</h2>
        <p>{text(copy.observationsDescription)}</p>
      </div>
      <p className="service-observations__summary">
        <strong>{text(copy.observationSummary, {
          items: text(
            observations.length === 1 ? copy.observationServicesCountOne : copy.observationServicesCountMany,
            { count: formatNumber(observations.length) },
          ),
          assets: text(
            observationAssetCount === 1 ? copy.observationAssetsCountOne : copy.observationAssetsCountMany,
            { count: formatNumber(observationAssetCount) },
          ),
        })}</strong>
      </p>
      <div className="section-heading">
        <h3>{text(copy.observationExamples)}</h3>
      </div>
      <div className="evidence-list service-observations__representatives">
        {representativeObservations.map((finding) => renderObservation(finding, false))}
      </div>
      <details className="page-secondary-feature service-observations__complete">
        <summary>{text(observations.length === 1 ? copy.observationCompleteListOne : copy.observationCompleteListMany, { count: formatNumber(observations.length) })}</summary>
        <div className="evidence-list">
          {observations.map((finding) => renderObservation(finding, true))}
        </div>
      </details>
      <button className="button button--primary button--small" type="button" onClick={onOpenCoverage}>
        <Icon name="coverage" size={16} />{text(copy.chooseSecurityChecks)}
      </button>
    </section>
  ) : null;

  if (findings.length === 0) {
    const incompleteRun = latestRun && latestRun.status !== "completed";
    const localhostSummary = latestRun && isExactBuiltInLocalhostQuickScanRun(latestRun)
      ? localhostTcpBeginnerSummary(latestRun.engineRuns[0]!)
      : undefined;
    const requestOutcomeSummary = latestRequestOutcomeSummary;
    const hasCompletedSecurityCheck = Boolean(report?.actual.checks.some((check) =>
      check.status === "tested_complete" && checkResultKind(check) === "security_check"));
    const hasSecurityResult = Boolean(report?.actual.checks.some((check) =>
      (check.status === "tested_complete" || check.status === "tested_partial")
      && checkResultKind(check) === "security_check"));
    const hasTestedNonSecurityWork = Boolean(report?.actual.checks.some((check) =>
      checkRecordedTestedWork(check) && checkResultKind(check) !== "security_check"));
    const title = !latestRun
      ? text(copy.emptyNoRunTitle)
      : requestOutcomeSummary
        ? text(requestOutcomeSummary.title)
        : localhostSummary
          ? text(localhostSummary.title)
          : nonSecurityOnly
            ? text(copy.nonSecurityEmptyTitle)
          : incompleteRun
            ? text(copy.emptyIncompleteTitle)
          : hasCompletedSecurityCheck
            ? text(copy.emptyCompletedTitle)
          : hasTestedNonSecurityWork
            ? text(copy.nonSecurityEmptyTitle)
            : text(copy.emptyIncompleteTitle);
    const description = !latestRun
      ? text(copy.emptyNoRunDescription)
      : requestOutcomeSummary
        ? [text(requestOutcomeSummary.description), text(requestOutcomeSummary.nextStep)].join(" ")
        : localhostSummary
          ? [
              text(localhostSummary.description),
              text(localhostSummary.exclusions),
              text(localhostSummary.nextStep),
            ].join(" ")
          : nonSecurityOnly
            ? text(copy.nonSecurityEmptyDescription)
          : incompleteRun
            ? text(copy.emptyIncompleteDescription)
          : hasCompletedSecurityCheck
            ? text(copy.emptyCompletedDescription)
          : hasTestedNonSecurityWork
            ? text(copy.nonSecurityEmptyDescription)
            : text(copy.emptyIncompleteDescription);
    const cleanCompletedOutcome = Boolean(latestRun)
      && !incompleteRun
      && !requestOutcomeSummary
      && !localhostSummary
      && !nonSecurityOnly
      && hasCompletedSecurityCheck
      && report?.state.summary === "complete";
    const partialSecurityOutcome = Boolean(latestRun)
      && !requestOutcomeSummary
      && !localhostSummary
      && !nonSecurityOnly
      && hasSecurityResult
      && report?.state.summary === "partial";
    const partialActionDestination = partialSecurityOutcome && report
      ? partialReportActionDestination(report)
      : undefined;
    const terminalActions = (
      <div className="button-group">
        {partialActionDestination ? (
          <button
            className="button button--primary"
            type="button"
            onClick={partialActionDestination === "progress"
              ? onOpenProgress
              : partialActionDestination === "coverage"
                ? onOpenCoverage
                : scrollToReportScope}
          >
            <Icon name={partialActionDestination === "progress" ? "progress" : "coverage"} size={16} />
            {text(partialActionDestination === "progress"
              ? copy.openProgress
              : partialActionDestination === "coverage"
                ? copy.openCoverage
                : copy.openReportScope)}
          </button>
        ) : cleanCompletedOutcome ? (
          <button className="button button--secondary" type="button" onClick={scrollToReportScope}>
            <Icon name="coverage" size={16} />{text(copy.openReportScope)}
          </button>
        ) : (
          <>
            <button className="button button--secondary" type="button" onClick={onOpenCoverage}><Icon name="coverage" size={16} />{text(copy.openCoverage)}</button>
            {latestRun && <button className="button button--primary" type="button" onClick={onOpenProgress}><Icon name="progress" size={16} />{text(copy.openProgress)}</button>}
          </>
        )}
      </div>
    );
    return (
      <div className="page">
        <PageHeader
          showEyebrow
          eyebrow={text(localhostSummary
            ? copy.connectionHeaderEyebrow
            : nonSecurityOnly
              ? copy.nonSecurityHeaderEyebrow
              : copy.resultsEyebrow)}
          title={cleanCompletedOutcome || partialSecurityOutcome
            ? text(partialSecurityOutcome ? copy.emptyPartialTitle : copy.emptyCompletedTitle)
            : text(localhostSummary
              ? copy.connectionHeaderTitle
              : nonSecurityOnly
                ? copy.nonSecurityHeaderTitle
                : copy.emptyHeaderTitle)}
          description={cleanCompletedOutcome || partialSecurityOutcome
            ? text(partialSecurityOutcome ? copy.emptyPartialDescription : copy.emptyCompletedDescription)
            : text(localhostSummary
              ? copy.connectionHeaderDescription
              : nonSecurityOnly
                ? copy.nonSecurityHeaderDescription
                : copy.emptyHeaderDescription)}
          actions={reportActions}
        />
        {runningScanResultsPending && (
          <InlineNotice tone="info" title={text(copy.finishedRunWhileScanning)} />
        )}
        {(cleanCompletedOutcome || partialSecurityOutcome) && (
          <div className="report-terminal-outcome" data-report-outcome={partialSecurityOutcome ? "incomplete" : "no_problems_completed"}>
            {terminalActions}
          </div>
        )}
        {report && (
          <AssetResultBoard
            report={report}
            run={latestRun}
            onOpenProgress={onOpenProgress}
            onOpenCoverage={onOpenCoverage}
          />
        )}
        {!cleanCompletedOutcome && !partialSecurityOutcome && (
          <EmptyState
            icon={incompleteRun
              || Boolean(requestOutcomeSummary)
              || ["closed", "timed_out", "failed", "cancelled", "missing", "inconsistent"]
                .includes(localhostSummary?.outcome ?? "")
              ? "warning"
              : "findings"}
            title={title}
            description={description}
            action={terminalActions}
          />
        )}
        {report && <BeginnerReportOverview report={report} run={latestRun} />}
        {reportUnavailable && <InlineNotice tone="warning" title={text(unavailableReportNotice.title)}><p>{text(unavailableReportNotice.body)}</p></InlineNotice>}
        {typedInventorySection}
        {observationSection}
        {report && <ReportEndMatter report={report} run={latestRun} />}
      </div>
    );
  }

  const applyControlFilter = (key: string) => {
    clearFilters();
    setControl(key);
    if (advancedFiltersRef.current) advancedFiltersRef.current.open = true;
    document.getElementById("finding-browser")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };
  const activeFilterCount = [severity !== "all", workflow !== "all", expertType !== "all", control !== "all", Boolean(query.trim()), selectedAssetId !== undefined].filter(Boolean).length;
  const submitDecision = async (event: FormEvent) => {
    event.preventDefault();
    if (!selected || !decidedBy.trim() || !decisionReason.trim()) return;
    const updated = await onUpdateWorkflow({
      findingId: selected.id,
      status: decisionStatus,
      decidedBy: decidedBy.trim(),
      reason: decisionReason.trim(),
      expiresAt: decisionStatus === "false_positive" && decisionExpiry
        ? new Date(`${decisionExpiry}T23:59:59`).toISOString()
        : undefined,
    });
    if (!updated) return;
    setDecisionReason("");
    setDecisionExpiry("");
  };
  const toggleGroupedFinding = (findingId: string) => {
    setGroupFindingIds((current) =>
      current.includes(findingId)
        ? current.filter((item) => item !== findingId)
        : [...current, findingId],
    );
  };
  const submitGroup = async (event: FormEvent) => {
    event.preventDefault();
    if (!groupTitle.trim() || !groupRationale.trim() || groupFindingIds.length < 2) return;
    const grouped = await onGroupFindings({
      title: groupTitle.trim(),
      findingIds: groupFindingIds,
      rationale: groupRationale.trim(),
    });
    if (!grouped) return;
    setGroupTitle("");
    setGroupRationale("");
    setGroupFindingIds([]);
  };

  return (
    <div className="page">
      <PageHeader
        showEyebrow
        eyebrow={text(copy.eyebrow)}
        title={text(copy.title)}
        actions={reportActions}
      />

      {runningScanResultsPending && (
        <InlineNotice tone="info" title={text(copy.finishedRunWhileScanning)} />
      )}

      {reportUnavailable && <InlineNotice tone="warning" title={text(unavailableReportNotice.title)}><p>{text(unavailableReportNotice.body)}</p></InlineNotice>}

      {latestRequestOutcomeSummary && (
        <InlineNotice tone="warning" title={text(latestRequestOutcomeSummary.title)}>
          <p>{[text(latestRequestOutcomeSummary.description), text(latestRequestOutcomeSummary.nextStep)].join(" ")}</p>
          <button className="button button--secondary button--small" type="button" onClick={onOpenProgress}>
            <Icon name="progress" size={15} /> {text(copy.openProgress)}
          </button>
        </InlineNotice>
      )}

      {report && (
        <AssetResultBoard
          report={report}
          run={latestRun}
          onOpenProgress={onOpenProgress}
          onOpenCoverage={onOpenCoverage}
        />
      )}

      {topFindings.length > 0 && (
        <section className="section-block priority-section">
          <div className="section-heading">
            <p className="eyebrow">{text(copy.doNow)}</p>
            <h2>{text(copy.priorityTitle)}</h2>
          </div>
          <div className="priority-grid">
            {topFindings.map(({finding, group, members}, index) => {
              const scannerRemediations = group ? [] : uniqueScannerRemediations(finding.evidence);
              const scannerFixedVersions = group ? [] : uniqueScannerFixedVersions(finding.evidence);
              const locations = group ? [] : locationsFor(finding);
              // A partly lowered password-policy group already says what comes first.
              const orderReason = (
                group?.lowerPriorityMembers === "partial"
                || (group !== undefined && members.some((member) => !priorityGuidanceReason(member.priorityReasons ?? [])))
              )
                ? undefined
                : priorityGuidanceReason(finding.priorityReasons ?? []);
              return (
              <button
                key={finding.id}
                type="button"
                className="priority-card"
                onClick={() => revealFinding(finding.id)}
              >
                <span className="priority-card__number">{String(index + 1).padStart(2, "0")}</span>
                <span className="priority-card__status">
                  <StatusPill label={severityLabelFor(finding)} tone={severityMeta[finding.severity].tone} />
                  {!group && <StatusPill label={confidenceMeta[finding.confidence]} tone="neutral" />}
                  {group && <span>{text(copy.originalFindingCount, {count: formatNumber(members.length)})}</span>}
                </span>
                <h3>{group ? problemGroupTitle(group, locale) : findingHeadline(locale, finding.title, finding.family)}</h3>
                <p className="priority-card__impact">{problemGroupImpact(group, locale) ?? findingImpactSentence(locale, {
                  englishFallback: finding.impact,
                  severity: finding.severity,
                  severityLabel: severityMeta[finding.severity].label,
                  severityBasisCode: finding.severityBasisCode,
                  priorityReasons: finding.priorityReasons,
                  family: finding.family,
                  contextFactors: finding.contextFactors,
                })}</p>
                <span className="priority-card__target">
                  <span><strong>{text(copy.affectedTarget)}</strong>{finding.assetName}</span>
                  {locations.length > 0 && (
                    <span><strong>{text(copy.reportedLocation)}</strong>{locations.join(locale === "en" ? "; " : "；")}</span>
                  )}
                </span>
                <span className="priority-card__guidance">
                  <span>
                    <strong>{text(copy.nextActionNow)}</strong>
                    <ScannerMarkdown compact text={problemGroupAction(group, locale) ?? findingActionSentence(locale, {
                      englishFallback: finding.recommendation,
                      family: finding.family,
                      awsIamPolicy: finding.awsIamPolicy,
                      unconfirmedByCoverage: actionUnconfirmedByCoverage(finding),
                    })} />
                  </span>
                  {orderReason && (
                    <span>
                      <strong>{text(copy.whyPriority)}</strong>
                      {findingPriorityReason(locale, orderReason)}
                    </span>
                  )}
                  {scannerRemediations.map((remediation) => (
                    <span key={remediation}>
                      <strong>{text(copy.scannerRemediation)}</strong>
                      <ScannerMarkdown text={remediation} compact />
                    </span>
                  ))}
                  {scannerFixedVersions.length > 0 && (
                    <span><strong>{text(copy.fixedVersion)}</strong>{scannerFixedVersions.join(" · ")}</span>
                  )}
                  {!group && finding.verificationGuidance && (
                    <span>
                      <strong>{text(copy.verifyFix)}</strong>
                      {findingVerificationSentence(locale, finding.verificationGuidance, finding.title)}
                    </span>
                  )}
                </span>
                <span className="priority-card__action">{text(copy.reviewEvidence)} <Icon name="arrow" size={15} /></span>
              </button>
              );
            })}
          </div>
        </section>
      )}

      {affectedAssetSummaries.length > 0 && (
        <section className="section-block affected-asset-section" aria-labelledby="affected-assets-title">
          <div className="section-heading">
            <p className="eyebrow">{text(copy.affectedAssetEyebrow)}</p>
            <h2 id="affected-assets-title">{text(copy.affectedAssetTitle)}</h2>
            <p>{text(copy.affectedAssetDescription)}</p>
          </div>
          <ul className="affected-asset-list">
            {affectedAssetSummaries.map((asset) => (
              <li key={asset.assetId}>
                <button
                  type="button"
                  className="affected-asset-row"
                  onClick={() => {
                    setSeverity("all");
                    setWorkflow("all");
                    setExpertType("all");
                    setControl("all");
                    setQuery("");
                    setSelectedAssetId(asset.assetId);
                    revealFinding(asset.topFindingId, { preserveFilters: true });
                  }}
                  aria-label={`${text(copy.affectedAssetOpen)}: ${asset.label}`}
                >
                  <span className="affected-asset-row__identity">
                    <strong>{asset.label}</strong>
                    <small>
                      {text(copy.affectedAssetTopIssue)} · {asset.topFindingTitle}
                    </small>
                  </span>
                  <span className="affected-asset-row__summary">
                    <StatusPill label={severityMeta[asset.highestSeverity].label} tone={severityMeta[asset.highestSeverity].tone} />
                    <strong>{asset.findingCount === 1
                      ? text(copy.affectedAssetIssueCountOne)
                      : text(copy.affectedAssetIssueCountMany, { count: formatNumber(asset.findingCount) })}</strong>
                    <Icon name="arrow" size={15} />
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="metrics-grid metrics-grid--four" aria-label={text(copy.summaryAria)}>
        <MetricCard label={text(copy.critical)} value={criticalCount} icon="warning" tone={criticalCount ? "danger" : "default"} />
        <MetricCard label={text(copy.high)} value={highCount} icon="findings" tone={highCount ? "warning" : "default"} />
        <MetricCard label={text(copy.needsReview)} value={needsReview} icon="search" />
        <MetricCard label={text(copy.affectedAssets)} value={affectedAssets} icon="database" />
      </section>

      {report && <BeginnerReportOverview report={report} run={latestRun} />}

      <details className="section-block page-secondary-feature findings-related-work">
        <summary>{text(copy.relatedGroups)}</summary>
      {hasCorrelationContent && (
        <section className="section-block" aria-labelledby="finding-correlations-title">
          <div className="section-heading">
            <p className="eyebrow">{text(copy.correlationEyebrow)}</p>
            <h2 id="finding-correlations-title">{text(copy.correlationTitle)}</h2>
            <p>{text(copy.correlationDescription)}</p>
          </div>
          <div className="evidence-list">
            {correlationSuggestions.map((suggestion) => (
              <article key={suggestion.id} className="evidence-item">
                <div className="evidence-item__header">
                  <strong>
                    {text(copy.correlationMatch, {
                      vulnerability: suggestion.vulnerabilityId,
                      package: suggestion.package,
                    })}
                  </strong>
                  <span>
                    {/* Engine ids are proper names; they are not translated. */}
                    {text(copy.correlationBasis, {
                      engines: suggestion.engineIds.join(text(copy.listSeparator)),
                    })}
                  </span>
                </div>
                <ul className="detail-list">
                  {suggestion.findingIds.map((findingId) => {
                    const finding = findingById.get(findingId);
                    return (
                      <li key={findingId}>
                        {finding
                          ? (
                            <button
                              className="clear-filters"
                              type="button"
                              onClick={() => revealFinding(finding.id)}
                            >
                              {findingHeadline(locale, finding.title, finding.family)}
                            </button>
                          )
                          : findingId}
                      </li>
                    );
                  })}
                </ul>
                <small>{text(copy.correlationMembers, { count: formatNumber(suggestion.findingIds.length) })}</small>
                <small>{text(corroborationCopy[suggestion.corroboration])}</small>
                <button
                  className="button button--secondary button--small"
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    void onGroupFindings({
                      title: text(copy.correlationMatch, {
                        vulnerability: suggestion.vulnerabilityId,
                        package: suggestion.package,
                      }),
                      findingIds: suggestion.findingIds,
                      rationale: text(copy.correlationAcceptedRationale),
                    });
                  }}
                >
                  {text(copy.correlationAccept)}
                </button>
              </article>
            ))}
          </div>
          {correlationUnverifiable.length > 0 && (
            <InlineNotice
              tone="warning"
              title={text(copy.correlationUnverifiableTitle, { count: formatNumber(correlationUnverifiable.length) })}
            >
              <p>{text(copy.correlationUnverifiableDescription)}</p>
              <ul className="detail-list">
                {correlationUnverifiable.map((entry) => (
                  <li key={`${entry.vulnerabilityId}-${entry.findingIds.join("-")}`}>
                    {text(copy.correlationUnverifiableItem, {
                      vulnerability: entry.vulnerabilityId,
                      count: formatNumber(entry.findingIds.length),
                    })}
                  </li>
                ))}
              </ul>
            </InlineNotice>
          )}
          {correlationTruncated > 0 && (
            <InlineNotice tone="warning" title={text(copy.correlationTruncated, { count: formatNumber(correlationTruncated) })}>
              <p>{text(copy.correlationDescription)}</p>
            </InlineNotice>
          )}
        </section>
      )}

      {visibleFindingGroups.length > 0 && (
        <section className="section-block" aria-labelledby="finding-groups-title">
          <div className="section-heading">
            <p className="eyebrow">{text(copy.reversibleLinks)}</p>
            <h2 id="finding-groups-title">{text(copy.groupsTitle)}</h2>
            <p>{text(copy.groupsDescription)}</p>
          </div>
          <div className="evidence-list">
            {visibleFindingGroups.map(({ group, visibleFindingIds, caseHistoryFindingCount }) => {
              const members = visibleFindingIds
                .map((findingId) => findingById.get(findingId))
                .filter((finding): finding is Finding => Boolean(finding));
              return (
                <article key={group.id} className="evidence-item">
                  <div className="evidence-item__header">
                    <strong>{group.title}</strong>
                    <span>{text(copy.items, { count: formatNumber(members.length) })} · {formatDateTime(group.createdAt)}</span>
                  </div>
                  <p>{group.rationale}</p>
                  <ul className="detail-list">
                    {members.map((finding) => (
                      <li key={finding.id}>
                        <button
                          className="clear-filters"
                          type="button"
                          onClick={() => revealFinding(finding.id)}
                        >
                          {findingHeadline(locale, finding.title, finding.family)}
                        </button>
                      </li>
                    ))}
                  </ul>
                  {caseHistoryFindingCount > 0 && (
                    <small>{text(copy.caseHistoryMembers, { count: formatNumber(caseHistoryFindingCount) })}</small>
                  )}
                  <small>{text(copy.createdBy, { actor: group.groupedBy })}</small>
                </article>
              );
            })}
          </div>
        </section>
      )}

      <details className="section-block page-secondary-feature">
        <summary id="finding-group-management-title">{text(copy.manageGroups)}</summary>
        <p className="page-secondary-feature__intro">{text(copy.manageGroupsDescription)}</p>

        {findingGroups.length > 0 && (
          <div className="evidence-list">
            {findingGroups.map((group) => {
              const members = group.findingIds
                .map((findingId) => ({ findingId, finding: findingById.get(findingId) }));
              return (
                <article key={group.id} className="evidence-item">
                  <div className="evidence-item__header">
                    <strong>{group.title}</strong>
                    <span>{text(copy.items, { count: formatNumber(members.length) })} · {formatDateTime(group.createdAt)}</span>
                  </div>
                  <p>{group.rationale}</p>
                  <ul className="detail-list">
                    {members.map(({ findingId, finding }) => (
                      <li key={findingId}>
                        {finding ? (
                          <button className="clear-filters" type="button" onClick={() => revealFinding(finding.id)}>
                            {findingHeadline(locale, finding.title, finding.family)}
                          </button>
                        ) : (
                          <span>{text(copy.caseHistoryMember)} · <code>{findingId}</code></span>
                        )}
                      </li>
                    ))}
                  </ul>
                  <small>{text(copy.createdBy, { actor: group.groupedBy })}</small>
                  <details className="page-technical-details">
                    <summary>{text(copy.technicalGroupDetails)}</summary>
                    <dl><div><dt>{text(copy.groupId)}</dt><dd><code>{group.id}</code></dd></div></dl>
                  </details>
                  <button
                    className="button button--ghost button--small"
                    type="button"
                    disabled={busy}
                    onClick={() => void onUngroupFindings(group.id)}
                  >
                    {text(copy.removeGroup)}
                  </button>
                </article>
              );
            })}
          </div>
        )}

        {orderedGroupEvents.length > 0 && (
          <details className="source-connect-panel">
            <summary>{text(copy.groupHistory, { count: formatNumber(orderedGroupEvents.length) })}</summary>
            <p>{text(copy.groupHistoryDescription)}</p>
            <div className="evidence-list">
              {orderedGroupEvents.map((event) => (
                <article key={event.id} className="evidence-item">
                  <div className="evidence-item__header">
                    <strong>{event.action === "created" ? text(copy.groupCreated) : text(copy.groupRemoved)}: {event.title}</strong>
                    <span>{formatDateTime(event.occurredAt)}</span>
                  </div>
                  <p>{event.rationale}</p>
                  <ul className="detail-list">
                    {event.findingIds.map((findingId) => {
                      const named = findingById.get(findingId);
                      return (
                        <li key={findingId}>{named
                          ? findingHeadline(locale, named.title, named.family)
                          : `${text(copy.findingId)}: ${findingId}`}</li>
                      );
                    })}
                  </ul>
                  <small>{text(copy.performedBy, { actor: event.actor })}</small>
                  <details className="page-technical-details">
                    <summary>{text(copy.technicalGroupDetails)}</summary>
                    <dl><div><dt>{text(copy.groupId)}</dt><dd><code>{event.groupId}</code></dd></div></dl>
                  </details>
                </article>
              ))}
            </div>
          </details>
        )}

        <form className="source-connect-panel source-connect-panel--stacked" onSubmit={(event) => void submitGroup(event)}>
          <label className="field">
            <span>{text(copy.groupTitle)}</span>
            <input maxLength={200} required value={groupTitle} onChange={(event) => setGroupTitle(event.target.value)} placeholder={text(copy.groupTitlePlaceholder)} />
          </label>
          <label className="field">
            <span>{text(copy.groupReason)}</span>
            <textarea maxLength={2000} required value={groupRationale} onChange={(event) => setGroupRationale(event.target.value)} placeholder={text(copy.groupReasonPlaceholder)} />
          </label>
          <fieldset className="choice-fieldset">
            <legend>{text(copy.chooseTwo)}</legend>
            <div className="choice-grid choice-grid--compact">
              {ordered.filter((finding) => !groupedFindingIds.has(finding.id)).map((finding) => (
                <label key={finding.id} className="check-card check-card--compact">
                  <input
                    type="checkbox"
                    checked={groupFindingIds.includes(finding.id)}
                    onChange={() => toggleGroupedFinding(finding.id)}
                  />
                  <span>{findingHeadline(locale, finding.title, finding.family)}<small>{finding.assetName} · {severityLabelFor(finding)}</small></span>
                </label>
              ))}
            </div>
          </fieldset>
          <button className="button button--secondary" type="submit" disabled={busy || !groupTitle.trim() || !groupRationale.trim() || groupFindingIds.length < 2}>
            {text(copy.createGroup)}
          </button>
        </form>
      </details>
      </details>

      <section id="finding-browser" className={`finding-browser${selected ? "" : " finding-browser--list-only"}`}>
        <div className="finding-browser__list">
          <div className="section-heading section-heading--row finding-toolbar-heading">
            <div><p className="eyebrow">{text(copy.allProblems)}</p><h2>{text(copy.completeList)}</h2></div>
            <span className="count-label">{formatNumber(filteredProblems.length)} / {formatNumber(orderedProblems.length)}{report?.problemGroups?.length ? ` · ${text(copy.originalFindingCount, {count: formatNumber(findings.length)})}` : ""}</span>
          </div>

          <div className="finding-filter-stack">
            {selectedAssetId && selectedAssetLabel && (
              <div className="finding-asset-filter" role="status">
                <Icon name="database" size={15} />
                <span>{text(copy.affectedAssetFilter, { asset: selectedAssetLabel })}</span>
              </div>
            )}
            <label className="search-field">
              <span className="sr-only">{text(copy.searchAria)}</span>
              <Icon name="search" size={18} />
              <input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={text(copy.searchPlaceholder)} />
            </label>
            <div className="finding-filter-grid">
              <label className="select-filter">
                <Icon name="filter" size={17} /><span className="sr-only">{text(copy.severityFilter)}</span>
                <select value={severity} onChange={(event) => setSeverity(event.target.value as Severity | "all")}>
                  <option value="all">{text(copy.allSeverities)}</option>
                  {severityOrder.map((item) => <option key={item} value={item}>{severityMeta[item].label}</option>)}
                </select>
              </label>
              <label className="select-filter">
                <Icon name="filter" size={17} /><span className="sr-only">{text(copy.workflowFilter)}</span>
                <select value={workflow} onChange={(event) => setWorkflow(event.target.value as FindingWorkflowState | "all")}>
                  <option value="all">{text(copy.allWorkflows)}</option>
                  {workflowOrder.map((item) => <option key={item} value={item}>{workflowMeta[item]}</option>)}
                </select>
              </label>
            </div>
            <details ref={advancedFiltersRef} className="page-secondary-feature finding-advanced-filters">
              <summary>{text(copy.advancedFilters)}</summary>
              <div className="finding-filter-grid">
                <label className="select-filter">
                  <Icon name="filter" size={17} /><span className="sr-only">{text(copy.expertFilter)}</span>
                  <select value={expertType} onChange={(event) => setExpertType(event.target.value)}>
                    <option value="all">{text(copy.allExperts)}</option>
                    {expertTypes.map((item) => <option key={item} value={item}>{localizedExpertType(item, locale)}</option>)}
                  </select>
                </label>
                <label className="select-filter">
                  <Icon name="filter" size={17} /><span className="sr-only">{text(copy.controlFilter)}</span>
                  <select value={control} onChange={(event) => setControl(event.target.value)}>
                    <option value="all">{text(copy.allControls)}</option>
                    {controls.map((item) => <option key={item.key} value={item.key}>{item.label}</option>)}
                  </select>
                </label>
              </div>
            </details>
            {activeFilterCount > 0 && <button className="clear-filters" type="button" onClick={clearFilters}><Icon name="close" size={14} />{text(copy.clearFilterCount, { count: formatNumber(activeFilterCount) })}</button>}
          </div>

          <ul className="finding-list">
            {filtered.length === 0 ? (
              <li className="finding-list__empty">
                <EmptyState icon="search" title={text(copy.noMatches)} description={text(copy.noMatchesDescription)} action={<button className="button button--ghost button--small" type="button" onClick={clearFilters}>{text(copy.clearFilters)}</button>} />
              </li>
            ) : filteredProblems.map(({finding, group, members}) => (
              <li key={finding.id}>
                <button
                  type="button"
                  className={members.some(member => member.id === selectedId) ? "finding-row finding-row--active" : "finding-row"}
                  onClick={() => revealFinding(finding.id, { preserveFilters: true, scrollOnWideLayout: false })}
                >
                  <span className="finding-row__priority" aria-label={text(copy.rankAria, { rank: displayRankByFindingId.get(finding.id) ?? "—" })}>
                    {text(copy.rank, { rank: displayRankByFindingId.get(finding.id) ?? "—" })}
                  </span>
                  <span className="finding-row__main">
                    <span className="finding-row__top">
                      <StatusPill label={severityLabelFor(finding)} tone={severityMeta[finding.severity].tone} />
                      {finding.severityBasisCode && !hasUnratedSeverity(finding) && (
                        <span className="finding-row__basis" title={text(copy.ratedByProductAria)}>
                          {text(copy.ratedByProduct)}
                        </span>
                      )}
                      {!group && <StatusPill label={workflowMeta[finding.workflowState]} tone={workflowTone(finding.workflowState)} />}
                      {group && <span>{text(copy.originalFindingCount, {count: formatNumber(members.length)})}</span>}
                    </span>
                    <strong>{group ? problemGroupTitle(group, locale) : findingHeadline(locale, finding.title, finding.family)}</strong>
                    <span>
                      {[
                        finding.assetName,
                        // The engine's own display name, read off the sentence it
                        // wrote. Without it every finding on one repository reads
                        // as the repository name: engine runs are single-asset,
                        // so `assetName` is the same target label on every row.
                        group ? [...new Set(members.flatMap(member => member.evidence.map(evidence =>
                          engineNameByEngineRunId.get(evidence.engineRunId ?? "") ?? evidence.sourceEngine)))].join(" · ") : engineNameFrom(finding.summary),
                        text(copy.evidenceCount, { count: formatNumber(members.reduce((count, member) => count + member.evidence.length, 0)) }),
                        !group ? findingConfidencePresentation(
                          locale,
                          confidenceMeta[finding.confidence],
                          finding.confidenceBasisCode,
                          finding.priorityReasons ?? [],
                        ) : undefined,
                      ].filter(Boolean).join(" · ")}
                    </span>
                  </span>
                  <Icon name="chevron" size={18} />
                </button>
              </li>
            ))}
          </ul>
        </div>

        <section className={`finding-detail${selected ? "" : " finding-detail--empty"}`} aria-live="polite">
          {selected ? (
            <>
              {selectedProblemGroup && selectedProblemMembers.length > 1 && (
                <details key={selectedProblemGroup.groupId} className="detail-section page-secondary-feature" open>
                  <summary>{problemGroupTitle(selectedProblemGroup, locale)} · {text(copy.relatedChecks, {count: formatNumber(selectedProblemMembers.length)})}</summary>
                  {problemGroupAction(selectedProblemGroup, locale) && <p>{problemGroupAction(selectedProblemGroup, locale)}</p>}
                  <ul className="detail-list problem-group-members">
                    {selectedProblemMembers.map(member => (
                      <li key={member.id}>
                        <button className="button button--ghost button--small" type="button" aria-current={member.id === selected.id ? "true" : undefined} onClick={() => revealFinding(member.id)}>
                          {findingHeadline(locale, member.title, member.family)}
                        </button>
                        <span className="tag-row">
                          <StatusPill label={severityLabelFor(member)} tone={severityMeta[member.severity].tone} />
                          <span>{[...new Set(member.evidence.map(evidence => evidence.sourceEngine))].join(" · ")}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                </details>
              )}
              <div className="finding-detail__header">
                <div className="tag-row">
                  <StatusPill label={severityLabelFor(selected)} tone={severityMeta[selected.severity].tone} />
                  <StatusPill label={findingConfidencePresentation(
                    locale,
                    confidenceMeta[selected.confidence],
                    selected.confidenceBasisCode,
                    selected.priorityReasons ?? [],
                  )} tone="neutral" />
                  <StatusPill label={workflowMeta[selected.workflowState]} tone={workflowTone(selected.workflowState)} />
                  {selected.tags?.includes("tenant-disputed") && (
                    <StatusPill label={text(copy.tenantDisputed)} tone="neutral" />
                  )}
                </div>
                <h2>{findingHeadline(locale, selected.title, selected.family)}</h2>
                <p>{findingSummarySentence(locale, {
                  englishFallback: selected.summary,
                  severity: selected.severity,
                  severityLabel: severityMeta[selected.severity].label,
                  severityBasisCode: selected.severityBasisCode,
                  confidenceLabel: confidenceMeta[selected.confidence],
                  confidenceBasisCode: selected.confidenceBasisCode,
                  priorityReasons: selected.priorityReasons ?? [],
                  family: selected.family,
                })}</p>
              </div>

              <dl className="detail-facts">
                <div><dt>{text(copy.asset)}</dt><dd>{selected.assetName}</dd></div>
                <div><dt>{text(copy.recommendedExpert)}</dt><dd>{localizedExpertType(selected.expertType, locale)}</dd></div>
                <div><dt>{text(copy.lastObserved)}</dt><dd>{formatDateTime(selected.lastSeenAt, historyDateTime)}</dd></div>
                <div><dt>{text(copy.relatedAssets)}</dt><dd>{text(copy.assetCount, { count: formatNumber(selected.assetIds?.length ?? 1) })}</dd></div>
              </dl>

              <details className="detail-section page-secondary-feature">
                <summary>{text(copy.reviewHistory)} · {text(copy.decisionCount, { count: formatNumber(selectedEvents.length) })}</summary>
                <form className="source-connect-panel source-connect-panel--stacked" onSubmit={(event) => void submitDecision(event)}>
                  <p>{text(copy.decisionBoundary)}</p>
                  <label className="field">
                    <span>{text(copy.newStatus)}</span>
                    <select value={decisionStatus} onChange={(event) => setDecisionStatus(event.target.value as (typeof decisionStates)[number])}>
                      {decisionStates.map((state) => <option key={state} value={state}>{workflowMeta[state]}</option>)}
                    </select>
                  </label>
                  <label className="field">
                    <span>{text(copy.decidedBy)}</span>
                    <input required maxLength={120} value={decidedBy} onChange={(event) => setDecidedBy(event.target.value)} placeholder={text(copy.decidedByPlaceholder)} />
                  </label>
                  <label className="field">
                    <span>{text(copy.reason)}</span>
                    <textarea required maxLength={2000} value={decisionReason} onChange={(event) => setDecisionReason(event.target.value)} placeholder={text(copy.reasonPlaceholder)} />
                  </label>
                  {decisionStatus === "false_positive" && (
                    <label className="field">
                      <span>{text(copy.falsePositiveExpiry)}</span>
                      <input type="date" value={decisionExpiry} onChange={(event) => setDecisionExpiry(event.target.value)} />
                    </label>
                  )}
                  <button className="button button--secondary" type="submit" disabled={busy || !decidedBy.trim() || !decisionReason.trim() || decisionStatus === selected.workflowState}>
                    <Icon name="database" size={16} />{text(copy.saveDecision)}
                  </button>
                </form>
                {selectedEvents.length === 0 ? <p>{text(copy.noDecisions)}</p> : (
                  <div className="evidence-list">
                    {selectedEvents.map((event) => (
                      <article key={event.id} className="evidence-item">
                        <div className="evidence-item__header"><strong>{workflowMeta[event.fromStatus]} → {workflowMeta[event.toStatus]}</strong><span>{formatDateTime(event.decidedAt)}</span></div>
                        <p>{event.reason}</p>
                        <small>
                          {text(copy.decisionActor, { actor: event.decidedBy })} · {event.expiresAt
                            ? text(copy.expires, { date: formatDateTime(event.expiresAt) })
                            : text(copy.neverExpires)}
                        </small>
                      </article>
                    ))}
                  </div>
                )}
              </details>

              <section className="detail-section">
                <h3>{text(copy.possibleImpact)}</h3>
                <p>{findingImpactSentence(locale, {
                  englishFallback: selected.impact,
                  severity: selected.severity,
                  severityLabel: severityMeta[selected.severity].label,
                  severityBasisCode: selected.severityBasisCode,
                  priorityReasons: selected.priorityReasons,
                  family: selected.family,
                  contextFactors: selected.contextFactors,
                })}</p>
              </section>

              {(selected.priorityReasons?.some((reason) => !isEvidenceOnlyPriorityReason(reason)) ?? false) && (
                <section className="detail-section">
                  <h3>{text(copy.whyPriority)}</h3>
                  <ul className="detail-list">{selected.priorityReasons
                    ?.filter((reason) => !isEvidenceOnlyPriorityReason(reason))
                    .map((reason) => <li key={reason}>{findingPriorityReason(locale, reason)}</li>)}</ul>
                </section>
              )}

              <section className="detail-section detail-section--advice">
                <h3>{text(copy.recommendation)}</h3>
                <ScannerMarkdown text={findingActionSentence(locale, {
                  englishFallback: selected.recommendation,
                  family: selected.family,
                  awsIamPolicy: selected.awsIamPolicy,
                  unconfirmedByCoverage: actionUnconfirmedByCoverage(selected),
                })} />
                {selectedScannerRemediations.map((remediation) => (
                  <div key={remediation} className="scanner-remediation-advice">
                    {adviceLabel(locale, text(copy.scannerRemediation))}
                    <ScannerMarkdown text={remediation} />
                  </div>
                ))}
                {selectedScannerFixedVersions.length > 0 && (
                  <p>
                    {adviceLabel(locale, text(copy.fixedVersion))}
                    {selectedScannerFixedVersions.join(" · ")}
                  </p>
                )}
                {selectedBenchmarkLines.map((entry) => (
                  <p key={entry.engineName}>
                    {adviceLabel(locale, text(copy.benchmark))}
                    {entry.line}
                  </p>
                ))}
                {selectedScannerRemediations.length === 0 && selectedScannerFixedVersions.length === 0 && (
                  <p>
                    {adviceLabel(locale, text(copy.scannerRemediation))}
                    {text(copy.scannerRemediationMissing)}
                  </p>
                )}
                {selected.rollbackConsiderations && (
                  <p>
                    {adviceLabel(locale, text(copy.beforeChanging))}
                    {findingRollbackSentence(locale, selected.rollbackConsiderations)}
                  </p>
                )}
              </section>

              <section className="detail-section">
                <h3>{text(copy.verification)}</h3>
                <p>{selected.verificationGuidance
                  ? findingVerificationSentence(locale, selected.verificationGuidance, selected.title)
                  : text(copy.verifyFallback)}</p>
              </section>

              <section className="detail-section">
                <div className="detail-section__heading"><h3>{text(copy.scanEvidence)}</h3><span>{text(copy.evidenceCount, { count: formatNumber(selected.evidence.length) })}</span></div>
                {selected.evidence.length === 0 ? (
                  <p>{text(copy.noEvidence)}</p>
                ) : (
                  <div className="evidence-list">
                    {selected.evidence.map((evidence) => {
                      // The engine that produced this record, named the same way
                      // the coverage rows name a check -- falling back to the raw
                      // engine id only when no run on the page can place it.
                      const evidenceHeaderName = (evidence.engineRunId
                        ? engineNameByEngineRunId.get(evidence.engineRunId)
                        : undefined) || evidence.sourceEngine;
                      const evidenceSummary = evidence.summary.endsWith(UNTRUSTED_EVIDENCE_CAVEAT)
                        ? evidence.summary.slice(0, -UNTRUSTED_EVIDENCE_CAVEAT.length)
                        : evidence.summary;
                      // A summary that only glues together the engine, source rule
                      // and location already shown beside it says nothing past
                      // those three fields, so it is dropped rather than rendered.
                      const evidenceSummaryRestatesNeighbours = Boolean(evidence.sourceRule) && Boolean(evidence.location)
                        && evidenceSummary === `${evidence.sourceEngine} reported rule ${evidence.sourceRule} at ${evidence.location}.`;
                      return (
                      <article key={evidence.id} className="evidence-item">
                        <div className="evidence-item__header"><strong>{evidenceHeaderName}</strong><span>{formatDateTime(evidence.observedAt)}</span></div>
                        {!evidenceSummaryRestatesNeighbours && <p>{evidenceSummary}</p>}
                        {evidence.location && (
                          <div className="scanner-evidence-location">
                            <strong>{text(copy.reportedLocation)}</strong>
                            <p>{findingLocationText(locale, evidence.location)}</p>
                          </div>
                        )}
                        {evidence.scannerDetails?.description && (
                          <div className="scanner-evidence-description">
                            <strong>{text(copy.scannerDescription)}</strong>
                            <ScannerMarkdown text={evidence.scannerDetails.description} />
                          </div>
                        )}
                        {evidence.scannerDetails?.awsIamPolicy && (
                          <div className="scanner-evidence-description">
                            <strong>{text(copy.iamPolicyContext)}</strong>
                            <dl className="evidence-provenance">
                              <div><dt>{text(copy.iamPolicySource)}</dt><dd>{awsIamPolicySourceLabel(evidence.scannerDetails.awsIamPolicy.policySource, locale)}</dd></div>
                              <div><dt>{text(copy.iamPolicyName)}</dt><dd><code>{evidence.scannerDetails.awsIamPolicy.policyName}</code></dd></div>
                              <div><dt>{text(copy.iamFindingIdentity)}</dt><dd><code>{evidence.scannerDetails.awsIamPolicy.findingIdentity}</code></dd></div>
                              <div><dt>{text(evidence.scannerDetails.awsIamPolicy.actionsComplete ? copy.iamActions : copy.iamRetainedActions)}</dt><dd>{iamValuePreview(evidence.scannerDetails.awsIamPolicy.actions)}</dd></div>
                              <div><dt>{text(copy.iamAttachedRoles)}</dt><dd>{iamValuePreview(evidence.scannerDetails.awsIamPolicy.attachedTo.roles)}</dd></div>
                              <div><dt>{text(copy.iamAttachedGroups)}</dt><dd>{iamValuePreview(evidence.scannerDetails.awsIamPolicy.attachedTo.groups)}</dd></div>
                              <div><dt>{text(copy.iamAttachedUsers)}</dt><dd>{iamValuePreview(evidence.scannerDetails.awsIamPolicy.attachedTo.users)}</dd></div>
                            </dl>
                            {!evidence.scannerDetails.awsIamPolicy.actionsComplete && (
                              <small>{text(copy.iamActionsIncomplete)}</small>
                            )}
                            {!evidence.scannerDetails.awsIamPolicy.attachedTo.complete && (
                              <small>{text(copy.iamAttachmentsIncomplete)}</small>
                            )}
                          </div>
                        )}
                        {(evidence.scannerDetails?.installedVersion || evidence.scannerDetails?.fixedVersion) && (
                          <dl className="evidence-provenance scanner-evidence-versions">
                            {evidence.scannerDetails.installedVersion && (
                              <div><dt>{text(copy.installedVersion)}</dt><dd><code>{evidence.scannerDetails.installedVersion}</code></dd></div>
                            )}
                            {evidence.scannerDetails.fixedVersion && (
                              <div><dt>{text(copy.fixedVersion)}</dt><dd><code>{evidence.scannerDetails.fixedVersion}</code></dd></div>
                            )}
                          </dl>
                        )}
                        {evidence.scannerDetails?.remediation && (
                          <div className="scanner-evidence-remediation">
                            <strong>{text(copy.scannerRemediation)}</strong>
                            <ScannerMarkdown text={evidence.scannerDetails.remediation} />
                          </div>
                        )}
                        <details className="page-technical-details">
                          <summary>{text(copy.technicalEvidence)}</summary>
                          <dl className="evidence-provenance">
                            <div><dt>{text(copy.evidenceKind)}</dt><dd>{evidence.kind?.replaceAll("_", " ") ?? text(copy.notReported)}</dd></div>
                            <div><dt>{text(copy.sourceRule)}</dt><dd><code>{evidence.sourceRule ?? text(copy.notReported)}</code></dd></div>
                            {evidence.location && (
                              <div><dt>{text(copy.evidenceLocation)}</dt><dd><code>{evidence.location}</code></dd></div>
                            )}
                            <div><dt>{text(copy.scanRun)}</dt><dd><code>{evidence.runId ?? selected.lastSeenRunId ?? text(copy.notReported)}</code></dd></div>
                            <div><dt>{text(copy.engineRun)}</dt><dd><code>{evidence.engineRunId ?? text(copy.legacyEngineRun)}</code></dd></div>
                            <div><dt>{text(copy.artifactId)}</dt><dd><code>{evidence.artifactId ?? text(copy.notReported)}</code></dd></div>
                            <div><dt>{text(copy.contentHash)}</dt><dd><code>{evidence.rawArtifactHash}</code></dd></div>
                            <div><dt>{text(copy.evidencePointer)}</dt><dd><code>{evidence.rawArtifactPath ?? text(copy.noPointer)}</code></dd></div>
                            <div><dt>{text(copy.sensitiveValues)}</dt><dd>{evidence.redacted === true ? text(copy.redacted) : evidence.redacted === false ? text(copy.notMarkedRedacted) : text(copy.notReported)}</dd></div>
                          </dl>
                        </details>
                      </article>
                      );
                    })}
                  </div>
                )}
              </section>

              <section className="detail-section">
                <h3>{text(copy.controlsTitle)}</h3>
                {selected.controls.length === 0 ? <p>{text(copy.noControls)}</p> : (
                  <div className="control-list">
                    {selected.controls.map((item) => {
                      const key = controlKey(item.framework, item.version, item.controlId);
                      return (
                        <button key={key} type="button" className={control === key ? "control-item control-item--active" : "control-item"} onClick={() => applyControlFilter(key)}>
                          <span><b>{item.framework}</b><small>{item.version}</small></span>
                          {/* Framework control titles are official names and stay verbatim in every locale. */}
                          <span><strong>{item.controlId}{item.title ? ` · ${item.title}` : ""}</strong><small>{item.rationale ? localizedControlMappingRationale(item.rationale, locale) : item.note ?? text(copy.relatedOnly)}</small></span>
                          <span className="control-item__action">{text(copy.viewSameControl)} <Icon name="arrow" size={13} /></span>
                          {item.mappingVersion && <code>mapping {item.mappingVersion}</code>}
                        </button>
                      );
                    })}
                  </div>
                )}
              </section>

              <section className="detail-section provenance-section">
                <details className="page-technical-details">
                  <summary>{text(copy.provenance)}</summary>
                  <dl>
                    <div><dt>Fingerprint</dt><dd><code>{selected.fingerprint}</code></dd></div>
                    <div><dt>{text(copy.findingId)}</dt><dd><code>{selected.id}</code></dd></div>
                    <div><dt>{text(copy.firstRun)}</dt><dd><code>{selected.firstSeenRunId ?? text(copy.notReported)}</code></dd></div>
                    <div><dt>{text(copy.lastRun)}</dt><dd><code>{selected.lastSeenRunId ?? text(copy.notReported)}</code></dd></div>
                    <div><dt>{text(copy.firstObserved)}</dt><dd>{formatDateTime(selected.firstSeenAt, historyDateTime)}</dd></div>
                    <div><dt>{text(copy.lastObserved)}</dt><dd>{formatDateTime(selected.lastSeenAt, historyDateTime)}</dd></div>
                  </dl>
                  {(selected.tags?.length ?? 0) > 0 && <div className="tag-row">{selected.tags?.map((tag) => <span className="tag tag--light" key={tag}>{tag}</span>)}</div>}
                </details>
              </section>

              <section className="detail-section">
                <h3>{text(copy.officialReferences)}</h3>
                {selected.officialReferences.length === 0 ? <p>{text(copy.noReferences)}</p> : (
                  <ul className="reference-list">
                    {selected.officialReferences.map((reference) => (
                      <li key={reference}>
                        <a href={reference} target="_blank" rel="noreferrer noopener" title={reference}>
                          {readableReference(reference)} <Icon name="external" size={14} />
                        </a>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            </>
          ) : (
            <EmptyState icon="findings" title={text(copy.chooseProblem)} description={text(copy.chooseProblemDescription)} />
          )}
        </section>
      </section>
      {typedInventorySection}
      {observationSection}
      {report && <ReportEndMatter report={report} run={latestRun} />}
    </div>
  );
}
