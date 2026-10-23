import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";

import { coverageMeta, platformMeta } from "../lib";
import type {
  AssessmentActivity,
  Asset,
  AgenticRadarFramework,
  AttachWorkspaceSnapshotInput,
  ConnectSourceSnapshotInput,
  ConnectedSource,
  CoverageRecord,
  CoverageState,
  EngineManifest,
  ExternalActivity,
  ExternalScopeRequest,
  ScopeGrant,
  ScopeMode,
  SnapshotParserProfile,
  SourceKind,
  TransportProtocol,
} from "../types";
import { Icon } from "../components/Icon";
import { EmptyState, InlineNotice, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";
import {
  ProviderAuthorizationPanel,
  type ProviderConnectionBoundary,
} from "../components/ProviderAuthorizationPanel";
import { useI18n, type BilingualText } from "../i18n";
import { primaryScanTiming } from "../primaryScanTiming";
import type { CoverageSetupFocus } from "../scanReadiness";
import { isScopeEligible, permittedModes, suggestedModesForAsset } from "../scopePolicy";
import type { UseCaseId } from "../useCases";
import {
  hasExactGuidedCloudConsent,
  recommendedGuidedLowImpactRatePolicy,
  recommendedGuidedNetworkPreset,
  shouldPromptForFirstAsset,
  singleGuidedSelectableAsset,
  type GuidedCoverageRoute,
} from "../coverageGuidance";
import { durationParts, estimateNetworkScanMinimum } from "../networkScanEstimate";
import { localizedCoverageRecordDetail } from "../findingNarrative.ts";
import { websitePassiveProfile, websiteQuickOrigin, websiteQuickProfile } from "../websiteQuickProfile";
import {
  internalDeviceProfileFromScanProfile,
  internalDeviceTlsVulnerabilityOids,
} from "../internalDeviceProfile";
import {
  internalEndpointCoordinate,
  internalEndpointProfiles,
  internalEndpointServiceFromScanProfile,
} from "../internalEndpointProfile";
import { internalHostGreenboneProfile } from "../internalHostProfile";
import { validateExternalTarget } from "../caseForm";
import type { EngineAssetRoute, ScopeApprovalInput } from "../services/scanner";
import {
  localInputDefinitions,
  localInputDefinitionForAssessmentIntent,
  localInputEngineIds,
  localInputEngines,
  localPathDisplayName,
  localProfileByAssessmentIntent,
  type LocalInputProfile,
} from "../localInputProfiles";
import { INCIDENT_FOCUS_ID, selectIncidentFocusEngines } from "../incidentFocusProfile";
import { ExternalScannerImport } from "../components/ExternalScannerImport";
import { engineOutcomeForId } from "../scanPresentation";
import { agenticRadarFramework, agenticRadarFrameworks } from "../agenticRadarProfile";
import { ModelEndpointPanel } from "../components/ModelEndpointPanel";
import type { StartModelCheckInput } from "../types";

import "../coverage-page.css";

export interface CoveragePageProps {
  caseId: string;
  assessmentIntent?: UseCaseId;
  focusSetup?: CoverageSetupFocus;
  requestedActivities: AssessmentActivity[];
  coverage: CoverageRecord[];
  sources: ConnectedSource[];
  engineManifests: EngineManifest[];
  assets: Asset[];
  scopeGrants: ScopeGrant[];
  nativeMode: boolean;
  busy?: boolean;
  discoveryBusy?: boolean;
  runtimeSetupNotice?: ReactNode;
  onChooseSnapshot: () => Promise<string | null>;
  onConnectSourceSnapshot: (input: ConnectSourceSnapshotInput) => Promise<void>;
  onChooseWorkspace: () => Promise<string | null>;
  onAttachWorkspaceSnapshot: (input: AttachWorkspaceSnapshotInput) => Promise<boolean>;
  onSelectMcpConfiguration: (assetId: string, relativePath: string) => Promise<boolean>;
  onSelectAgenticFramework?: (assetId: string, framework: AgenticRadarFramework | null) => Promise<boolean>;
  onStartModelCheck?: (input: StartModelCheckInput) => Promise<boolean>;
  onStartDiscovery: () => Promise<void>;
  onAuthorizationChanged: () => Promise<void>;
  onStartScan: (
    assetIds: string[],
    modes: ScopeMode[],
    confirmation: string,
    externalScope?: ExternalScopeRequest,
    engineIds?: string[],
    campaignId?: string,
  ) => Promise<boolean>;
  onStartEnvironmentScan: (
    authorizations: Array<Omit<ScopeApprovalInput, "caseId">>,
    engineAssetRoutes: EngineAssetRoute[],
    campaignId?: string,
  ) => Promise<boolean>;
}

interface SourceDefinition {
  label: BilingualText;
  platform: keyof typeof platformMeta;
  profiles: readonly SnapshotParserProfile[];
  description: BilingualText;
}

const bilingual = <const En extends string, const ZhTW extends string>(en: En, zhTW: ZhTW) => ({ en, zhTW });

const sourceDefinitions = {
  aws_organization: {
    label: bilingual("AWS organization", "AWS 組織"),
    platform: "aws",
    profiles: ["cloudquery", "steampipe", "prowler"],
    description: bilingual("A saved export of AWS accounts, Regions, and resources.", "AWS 帳號、區域與資源的既有匯出結果。"),
  },
  azure_tenant: {
    label: bilingual("Azure tenant", "Azure 租用戶"),
    platform: "azure",
    profiles: ["cloudquery", "steampipe", "prowler"],
    description: bilingual("A saved export of an Azure tenant, subscriptions, and resources.", "Azure 租用戶、訂閱與資源的既有匯出結果。"),
  },
  gcp_organization: {
    label: bilingual("Google Cloud organization", "Google Cloud 組織"),
    platform: "gcp",
    profiles: ["cloudquery", "steampipe", "prowler"],
    description: bilingual("A saved export of a Google Cloud organization, folders, projects, and resources.", "Google Cloud 組織、資料夾、專案與資源的既有匯出結果。"),
  },
  microsoft365_tenant: {
    label: bilingual("Microsoft 365 tenant", "Microsoft 365 租用戶"),
    platform: "m365",
    profiles: ["scubagear", "maester"],
    description: bilingual("Saved tenant results from ScubaGear or Maester.", "ScubaGear 或 Maester 已保存的租用戶結果。"),
  },
  dns: {
    label: bilingual("DNS records", "DNS 紀錄"),
    platform: "external",
    profiles: ["dns-response"],
    description: bilingual("Saved DNS answers for a website or domain.", "網站或網域的既有 DNS 查詢結果。"),
  },
  certificate_transparency: {
    label: bilingual("Certificate Transparency", "憑證透明度紀錄"),
    platform: "external",
    profiles: ["certificate-transparency-response"],
    description: bilingual("Saved responses from public Certificate Transparency searches.", "已保存的公開憑證透明度查詢回應。"),
  },
  billing: {
    label: bilingual("Billing export", "帳務匯出"),
    platform: "external",
    profiles: ["billing-export"],
    description: bilingual("A saved billing export that can help find cloud resources.", "可協助找出雲端資源的既有帳務匯出檔。"),
  },
  git_repository: {
    label: bilingual("Git repositories", "Git 程式碼儲存庫"),
    platform: "code",
    profiles: ["git-manifest"],
    description: bilingual("A saved list of the code repositories you selected.", "你所選程式碼儲存庫的既有清單。"),
  },
  terraform_state: {
    label: bilingual("Terraform state", "Terraform 狀態檔"),
    platform: "code",
    profiles: ["terraform-state"],
    description: bilingual("A JSON snapshot of Terraform state without secret values.", "不含秘密值的 Terraform 狀態 JSON 快照。"),
  },
  kubernetes_cluster: {
    label: bilingual("Kubernetes clusters", "Kubernetes 叢集"),
    platform: "kubernetes",
    profiles: ["kubernetes-manifest"],
    description: bilingual("A saved JSON manifest of clusters and workloads.", "已保存的叢集與工作負載 JSON 清單。"),
  },
  container_registry: {
    label: bilingual("Container registries", "容器映像倉庫"),
    platform: "container",
    profiles: ["container-registry-manifest"],
    description: bilingual("A saved list of container registries and images.", "容器映像倉庫與映像的既有清單。"),
  },
  file_system: {
    label: bilingual("Local files", "本機檔案"),
    platform: "code",
    profiles: ["filesystem-manifest"],
    description: bilingual("A saved list of the local files you selected.", "你所選本機檔案的既有清單。"),
  },
  user_declared: {
    label: bilingual("Websites and systems already added", "已加入的網站與系統"),
    platform: "external",
    profiles: ["user-declared-manifest"],
    description: bilingual("Websites, IP addresses, and systems already added to this scan.", "已加入這次掃描的網站、IP 位址與系統。"),
  },
} as const satisfies Record<SourceKind, SourceDefinition>;

const parserProfileLabels: Record<SnapshotParserProfile, string> = {
  cloudquery: "CloudQuery JSON",
  steampipe: "Steampipe JSON",
  prowler: "Prowler JSON",
  scubagear: "ScubaGear JSON",
  maester: "Maester JSON",
  "dns-response": "DNS response JSON",
  "certificate-transparency-response": "Certificate Transparency response JSON",
  "billing-export": "Billing export JSON",
  "git-manifest": "Git manifest JSON",
  "terraform-state": "Terraform state JSON",
  "kubernetes-manifest": "Kubernetes manifest JSON",
  "container-registry-manifest": "Container registry manifest JSON",
  "filesystem-manifest": "Filesystem manifest JSON",
  "user-declared-manifest": "User-declared manifest JSON",
};

const allSourceKinds = Object.keys(sourceDefinitions) as SourceKind[];
const coverageStates = Object.keys(coverageMeta) as CoverageState[];

const networkAssessmentIntents: readonly UseCaseId[] = [
  "deployed_website",
  "external_ip_or_domain",
  "internal_it_environment",
];

const scopeModeLabels: Record<ScopeMode, { label: BilingualText; detail: BilingualText }> = {
  inventory: { label: bilingual("Read-only inventory", "唯讀盤點"), detail: bilingual("Read the names of the selected items only", "只讀取已選項目的名稱") },
  configuration: { label: bilingual("Review settings", "檢查設定"), detail: bilingual("Read configuration or an attached snapshot without making changes", "唯讀檢查設定或已附加快照") },
  local_artifact: { label: bilingual("Review the saved local copy", "檢查本機副本"), detail: bilingual("Check the prepared copy without changing your project", "檢查準備好的副本，不會修改你的專案") },
  public_data: { label: bilingual("Public records", "公開資料"), detail: bilingual("Saved DNS, certificate, and similar public records only", "既有 DNS、憑證等公開資料") },
  low_impact_external: { label: bilingual("Low-impact connection checks", "低影響連線檢查"), detail: bilingual("Send limited requests only to the confirmed target", "只對已確認目標發出受限連線") },
  active_external: { label: bilingual("Approved active website tests", "已核准的主動網站測試"), detail: bilingual("Use only with written approval and a specific test list", "只在取得書面核准與指定測試清單時使用") },
  passive: { label: bilingual("Public records", "公開資料"), detail: bilingual("Saved DNS, certificate, and similar public records only", "既有 DNS、憑證等公開資料") },
  active: { label: bilingual("Approved active website tests", "已核准的主動網站測試"), detail: bilingual("Use only with written approval and a specific test list", "只在取得書面核准與指定測試清單時使用") },
};

const externalActivities: Partial<Record<ScopeMode, ExternalActivity>> = {
  low_impact_external: "low_impact_external",
  active_external: "active_external",
  active: "active_external",
};

const rateLimits: Record<ExternalActivity, { rate: number; concurrency: number; timeout: number }> = {
  passive_public_discovery: { rate: 100, concurrency: 20, timeout: 3_600 },
  low_impact_external: { rate: 25, concurrency: 10, timeout: 1_800 },
  active_external: { rate: 10, concurrency: 5, timeout: 3_600 },
};

const activityLabels: Record<ExternalActivity, BilingualText> = {
  passive_public_discovery: bilingual("Public-record review", "公開資料盤點"),
  low_impact_external: bilingual("Low-impact external checks", "低影響外部連線"),
  active_external: bilingual("Approved active external tests", "已核准的主動外部測試"),
};

const coverageStatePlainCopy: Record<CoverageState, { short: BilingualText; description: BilingualText }> = {
  discovered_authorized_scanned: {
    short: bilingual("Finished", "已完成"),
    description: bilingual("The selected checks for these items finished.", "這些項目的已選檢查都已完成。"),
  },
  discovered_not_authorized: {
    short: bilingual("Choose checks", "選擇檢查方式"),
    description: bilingual("These items are ready for you to choose checks in step 3.", "這些項目已整理好，請在步驟 3 選擇檢查方式。"),
  },
  authorized_incomplete: {
    short: bilingual("Needs attention", "需要處理"),
    description: bilingual("Some checks did not finish and can be continued.", "部分檢查尚未完成，可以繼續執行。"),
  },
  source_connected_none: {
    short: bilingual("Nothing found", "沒有找到"),
    description: bilingual("This source had nothing to add to the list this time.", "這個來源本次沒有內容可加入清單。"),
  },
  source_unavailable_unknown: {
    short: bilingual("Connect source", "連接來源"),
    description: bilingual("Connect this source to see what it contains.", "連接這個來源後，就能查看其中內容。"),
  },
  not_applicable: {
    short: bilingual("Not included", "未納入"),
    description: bilingual("This source is not included in the current scan.", "這個來源未納入目前的掃描。"),
  },
};

const isAwaitingFirstScan = (state: CoverageState, scanAttempted: boolean | undefined): boolean =>
  state === "authorized_incomplete" && scanAttempted === false;

const pageCopy = {
  incidentFocusTitle: bilingual("October 21–22 incident triage", "10/21–10/22 事件專項檢查"),
  incidentFocusDetail: bilingual("Check packages in selected local copies with Trivy. Websites and internal hosts are excluded; results show incident matches and coverage.", "使用 Trivy 檢查所選本機副本的套件弱點。網站與內部主機不納入；結果列出事件命中與涵蓋範圍。"),
  incidentFocusPackages: bilingual("Check known package vulnerabilities in the selected copies.", "檢查所選副本中的已知套件弱點。"),
  incidentFocusExcludedCount: bilingual("{count} assets excluded from package incident checks", "套件事件檢查不納入 {count} 項資產"),
  incidentFocusExcluded: bilingual("Not included in incident triage", "未納入這次事件專項檢查"),
  headerEyebrow: bilingual("Set up your scan", "設定這次掃描"),
  headerTitle: bilingual("Scan setup", "掃描設定"),
  refresh: bilingual("Refresh items", "重新整理項目"),
  refreshing: bilingual("Refreshing…", "正在重新確認…"),
  addEyebrow: bilingual("Step 1", "步驟 1"),
  addTitle: bilingual("1. Add inputs", "1. 加入內容"),
  addDescription: bilingual("Choose one source. Add others only when needed.", "先選一個來源，需要時再加入其他來源。"),
  sourceSetupSummary: bilingual("Add or change source", "新增或變更資料來源"),
  sourceSetupCleanupSummary: bilingual("Temporary cloud cleanup required", "需要清理暫時雲端存取"),
  cleanupAttentionTitle: bilingual("Temporary cloud cleanup required", "需要清理暫時雲端存取"),
  cleanupAttentionBody: bilingual(
    "Open the recorded cleanup.",
    "請開啟已記錄的清理項目。",
  ),
  reviewCleanup: bilingual("Review cleanup", "檢視清理狀態"),
  providerTitle: bilingual("Cloud account", "雲端帳號"),
  providerBody: bilingual("Sign in through AWS, Azure, Google Cloud, or Microsoft and turn identity and access settings into a fix list.", "透過 AWS、Azure、Google Cloud 或 Microsoft 登入，把身分與存取設定整理成改善清單。"),
  providerOpen: bilingual("Connect a cloud account", "連接雲端帳號"),
  providerClose: bilingual("Close cloud setup", "關閉雲端設定"),
  snapshotTitle: bilingual("An inventory file", "盤點檔"),
  snapshotBody: bilingual("Already have a JSON export? Add it here and review the assets locally.", "已經有 JSON 匯出檔？直接加入並在本機整理資產。"),
  snapshotOpen: bilingual("Add an inventory file", "加入盤點檔"),
  snapshotClose: bilingual("Close inventory form", "關閉盤點檔表單"),
  workspaceTitle: bilingual("Code, infrastructure, containers, or Kubernetes", "程式碼、基礎設施、容器或 Kubernetes"),
  workspaceBody: bilingual("Choose a local folder and find issues without uploading the project.", "選擇本機資料夾，不必上傳專案就能找問題。"),
  workspaceOpen: bilingual("Choose a project", "選擇專案"),
  workspaceClose: bilingual("Close local-files form", "關閉本機檔案表單"),
  guidedWorkspaceOpen: bilingual("Show setup", "顯示設定"),
  guidedWorkspaceClose: bilingual("Hide setup", "隱藏設定"),
  knownTargetsTitle: bilingual("Website, IP, or internal system already added", "已加入的網站、IP 或內部系統"),
  knownTargetsBody: bilingual("Turn the targets from your scan project into a review list.", "把掃描專案中的目標整理成可確認的清單。"),
  networkReadyTitle: bilingual("Review your network target", "確認你的網路目標"),
  networkReadyBody: bilingual("Check the exact website, IP address, or internal network below. Recommended low-impact settings are selected.", "在下方確認精確的網站、IP 位址或內部網路；建議的低影響設定已選取。"),
  websiteQuickReadyBody: bilingual("Review the exact website address below. The fixed Nuclei quick scan is already selected.", "在下方確認精確的網站來源範圍；固定的 Nuclei 快速掃描已自動選取。"),
  networkReadyAction: bilingual("Review this target", "確認這個目標"),
  otherInputsSummary: bilingual("Other ways to add scan inputs", "其他加入掃描內容的方式"),
  otherInputsBody: bilingual("Use these options for another input type.", "其他輸入類型使用這些選項。"),
  selectDoesNotAuthorizeTitle: bilingual("How scan approval works", "掃描確認方式"),
  selectDoesNotAuthorizeBody: bilingual("Adding an item prepares it. Step 3 confirms the exact network target, check, and limits.", "加入項目會完成準備；步驟 3 會確認精確網路目標、檢查與限制。"),

  sourceEyebrow: bilingual("Saved inventory", "已保存的盤點檔"),
  sourceTitle: bilingual("Attach one saved JSON inventory", "附加一份已保存的 JSON 盤點檔"),
  sourceIntro: bilingual("Choose a saved inventory export. The app copies and organizes it locally.", "選擇已保存的盤點匯出檔；程式會在本機複製並整理。"),
  noSecretsSnapshotTitle: bilingual("Inventory requirement: no passwords, tokens, private keys, or other secret values", "盤點檔規格：不得包含密碼、token、私鑰或其他秘密值"),
  noSecretsSnapshotBody: bilingual("This step adds selected items. Step 3 confirms network checks.", "這一步會加入選定項目；步驟 3 確認網路檢查。"),
  demoFileTitle: bilingual("Desktop app required for local files", "本機檔案需要桌面程式"),
  demoFileBody: bilingual("Open the signed desktop app to attach a real snapshot. This preview only shows the steps.", "請使用已簽章的桌面程式附加真實快照；目前預覽只會顯示步驟。"),
  sourceKind: bilingual("What produced this inventory?", "這份盤點檔來自哪裡？"),
  snapshotFormat: bilingual("Saved-file format", "盤點檔格式"),
  snapshotFormatHelp: bilingual("The choice is limited by the source. The product never guesses with a general-purpose parser.", "格式會依來源限制；產品不會用通用解析器猜測。"),
  inputTechnicalSummary: bilingual("Technical input details", "輸入技術細節"),
  localEngineDetail: bilingual("Bound scanner engines: {engines}.", "綁定的掃描引擎：{engines}。"),
  mcpConfigurationLabel: bilingual("MCP configuration to check", "要檢查的 MCP 設定"),
  agenticInventoryTitle: bilingual("AI workflow inventory (optional)", "AI 工作流程盤點（選用）"),
  agenticFrameworkLabel: bilingual("Workflow framework", "工作流程框架"),
  agenticInventoryOff: bilingual("Skip workflow inventory", "不加入工作流程盤點"),
  agenticInventoryHelp: bilingual("Agentic Radar reads the saved copy to list agents, tools, and their connections. Inventory supplements the security checks.", "Agentic Radar 會讀取保存副本，列出 Agent、工具與連接關係；盤點可補充安全檢查結果。"),
  mcpConfigurationHelp: bilingual(
    "MCP Armor reads only this file from the private snapshot. It does not start or contact any MCP server.",
    "MCP Armor 只會讀取私密快照中的這一份檔案，不會啟動或連線任何 MCP 伺服器。",
  ),
  mcpConfigurationChoose: bilingual("Choose one configuration", "選擇一份設定"),
  sourceLabel: bilingual("Name shown in this scan", "這次掃描中顯示的名稱"),
  sourceLabelPlaceholder: bilingual("Example: Production AWS inventory", "例如：正式環境 AWS 盤點"),
  sourceLabelHelp: bilingual("Label requirement: recognizable, without credentials or secret values.", "標籤規格：容易辨識，且不含憑證或秘密值。"),
  jsonSnapshot: bilingual("JSON file", "JSON 檔案"),
  choosingPicker: bilingual("Opening the file picker…", "正在開啟檔案選擇器…"),
  chooseJson: bilingual("Choose one .json file", "選擇一份 .json 檔"),
  snapshotPathHelp: bilingual("Only this file is copied. Its original folder location stays on this computer.", "只會複製這個檔案；原本的資料夾位置會留在這台電腦上。"),
  sourceAfterHelp: bilingual("After attaching it, refresh what the product can see.", "附加後仍要重新確認產品看得到什麼。"),
  connectSnapshot: bilingual("Copy and attach this inventory", "複製並附加這份盤點檔"),
  connectingSnapshot: bilingual("Attaching…", "正在附加…"),
  fileFallback: bilingual("Selected JSON file", "已選取 JSON 檔"),
  sourceErrorJson: bilingual("Choose one .json file.", "請選擇一份 .json 檔。"),
  sourceErrorPicker: bilingual("Open the local file picker again.", "請重新開啟本機檔案選擇器。"),
  sourceErrorLabel: bilingual("Enter a name that identifies this inventory.", "請輸入能辨識這份來源的標籤。"),
  sourceErrorPath: bilingual("Choose one JSON inventory first.", "請先明確選擇一份 JSON 快照。"),

  workspaceEyebrow: bilingual("Saved local copy", "保存本機副本"),
  workspaceFormTitle: bilingual("Choose the local project you want checked", "選擇想檢查的本機專案"),
  workspaceIntro: bilingual("Pick one folder. The app scans a private local copy.", "選擇一個資料夾；程式會掃描私密的本機副本。"),
  gitWarningTitle: bilingual("Scan a private local copy", "掃描私密的本機副本"),
  gitWarningBody: bilingual("Only the selected folder is copied into the private local scan. Detected secret values are masked in results.", "只會把選定資料夾複製到私密的本機掃描；找到的秘密值會在結果中遮罩。"),
  gitTechnicalBody: bilingual("Every .git directory is excluded, so Git history, refs, hooks, and credentials stored inside .git are not opened or copied.", "所有 .git 目錄都會排除，因此不會開啟或複製其中的 Git history、refs、hooks 與 credentials。"),
  localSelectionPermissionTitle: bilingual("Choose once, then scan the private copy", "選擇一次，再掃描私密副本"),
  localSelectionPermissionBody: bilingual("Choosing a folder creates a private read-only snapshot. The case saves its snapshot ID, input type, content hash, and relative paths—not the original host path. Starting the scan runs the recommended checks.", "選擇資料夾會建立私密唯讀快照。案件保存快照 ID、輸入類型、內容雜湊與相對路徑，不保存原始主機路徑；開始掃描時會執行建議的檢查。"),
  demoFolderTitle: bilingual("Desktop app required for local folders", "本機資料夾需要桌面程式"),
  demoFolderBody: bilingual("Open the desktop app to create a real local snapshot. This preview only shows the steps.", "請使用桌面程式建立真實本機快照；目前預覽只會顯示步驟。"),
  inputType: bilingual("What are you attaching?", "你要附加什麼？"),
  localLabel: bilingual("Name shown in this scan", "這次掃描中顯示的名稱"),
  localLabelPlaceholder: bilingual("Example: Production container image", "例如：Production container image"),
  localLabelHelp: bilingual("Label requirement: recognizable, without passwords, keys, or tokens.", "標籤規格：容易辨識，且不含密碼、金鑰或 token。"),
  localDirectory: bilingual("Folder to copy", "要複製的資料夾"),
  localPathHelp: bilingual("Only the folder name is shown here. Its full location stays on this computer.", "這裡只會顯示資料夾名稱；完整位置會留在這台電腦上。"),
  workspaceAfterHelp: bilingual("Prepare the private copy, then review the checks.", "準備私密副本後，接著檢查掃描項目。"),
  attachWorkspace: bilingual("Prepare this project for scanning", "準備這份專案進行掃描"),
  attachingWorkspace: bilingual("Copying and verifying locally…", "正在本機複製並驗證…"),
  folderFallback: bilingual("Selected folder", "已選取資料夾"),
  workspaceErrorPicker: bilingual("Open the local folder picker again.", "請重新開啟本機目錄選擇器。"),
  workspaceErrorLabel: bilingual("Enter a name for this project.", "請輸入這份專案的名稱。"),
  workspaceErrorPath: bilingual("Choose one project folder first.", "請先選擇一個專案資料夾。"),
  workspaceErrorCopy: bilingual(
    "Folder copy failed. Choose a source-only project folder without generated dependencies or build output, then try again.",
    "資料夾複製失敗。請選擇不含產生式相依套件或建置輸出的純原始碼專案資料夾，再試一次。",
  ),

  seeEyebrow: bilingual("Step 2", "步驟 2"),
  seeTitle: bilingual("2. Review items", "2. 確認項目"),
  candidateAssets: bilingual("Items found", "找到的項目"),
  scannedAssets: bilingual("Items fully checked", "已完整檢查的項目"),
  readyToScan: bilingual("Ready to scan", "準備掃描"),
  readyToScanDetail: bilingual("Permission saved. Start this item.", "掃描許可已儲存；開始這個項目。"),
  readyToScanNext: bilingual("Permission saved. Start the scan.", "掃描許可已儲存；開始掃描。"),
  incompleteAssets: bilingual("Needs attention", "需要處理"),
  pendingAssets: bilingual("Setup required", "需要設定"),
  metricsLabel: bilingual("What the product can currently see", "產品目前看得到的摘要"),
  unknownTitle: bilingual("Sources without data: {count}", "沒有資料的來源：{count} 個"),
  unknownBody: bilingual("Connect or import these sources to see what they contain.", "連接或匯入這些來源，就能查看其中內容。"),
  noneTitle: bilingual("Connected sources finding no items: {count}", "{count} 個已連接來源沒有找到項目"),
  noneBody: bilingual("Source connected. Items added: 0.", "來源已連接；加入項目：0。"),
  sourcesEyebrow: bilingual("Your sources", "你的資料來源"),
  sourcesTitle: bilingual("Sources ({count})", "來源（{count}）"),
  noSourcesTitle: bilingual("No input attached", "沒有附加輸入"),
  noSourcesBody: bilingual("Add an inventory file or local project in step 1, then refresh this list.", "請先在步驟 1 加入盤點檔或本機專案，再重新整理這份清單。"),
  assetsCount: bilingual("Items: {count}", "{count} 個項目"),
  lastChecked: bilingual("Checked {date}", "確認時間 {date}"),
  notScannedYet: bilingual("Not scanned", "未掃描"),
  notConnected: bilingual("Not connected", "尚未連接"),
  sourceTechnical: bilingual("Technical source details", "來源技術細節"),
  rawSourceDetail: bilingual("Raw saved-source detail", "原始來源細節"),
  acceptedProfiles: bilingual("Accepted profiles", "接受的檔案格式"),
  sourceKindTechnical: bilingual("Source kind", "來源種類"),
  sourceStatusTechnical: bilingual("Connection state", "連接狀態"),
  coverageStateTechnical: bilingual("Coverage state", "涵蓋狀態"),
  coverageDetailsSummary: bilingual("Coverage states and filters", "涵蓋狀態與篩選條件"),
  coverageDetailsIntro: bilingual("Use these technical states when diagnosing why an item has or does not have results.", "排查為什麼某一項有結果或沒有結果時，可使用這些技術狀態。"),
  showAll: bilingual("Show all items", "顯示所有項目"),

  allowEyebrow: bilingual("Step 3", "步驟 3"),
  allowTitle: bilingual("3. Review and start", "3. 確認後開始"),
  allowDescription: bilingual("Confirm the target and limits.", "確認目標與限制。"),
  focusedReviewTitle: bilingual("Review and start", "確認後開始"),
  environmentPlanTitle: bilingual("One scan for this IT environment", "一次掃描這個 IT 環境"),
  environmentPlanBody: bilingual(
    "Choose the scan-ready items below. Each scanner receives only the assets it can check, and all completed results go into one report.",
    "選擇下方已可掃描的項目。每個掃描工具只會收到它能檢查的資產，所有完成結果會整合成一份報告。",
  ),
  environmentTiming: primaryScanTiming,
  websiteTiming: primaryScanTiming,
  localTiming: primaryScanTiming,
  environmentRepositoriesTitle: bilingual("Project folders", "專案資料夾"),
  environmentRepositoriesBody: bilingual(
    "Read-only checks for risky code, exposed secrets, vulnerable dependencies, and unsafe configuration when applicable.",
    "依專案內容執行危險程式碼、暴露秘密、有弱點相依套件與不安全設定的唯讀檢查。",
  ),
  environmentWebsitesTitle: bilingual("Websites and APIs", "網站與 API"),
  environmentWebsitesBody: bilingual(
    "Nuclei identifies the website technology and applies its matching vulnerability and exposure checks to each origin below. It does not sign in, exploit findings, crawl other hosts, or add targets.",
    "Nuclei 會辨識網站使用的技術，並對下方每個網站來源範圍執行適用的弱點與暴露檢查；不會登入、利用弱點、爬取其他主機或加入目標。",
  ),
  environmentWebsiteCheck: bilingual(
    "Nuclei automatic web scan",
    "Nuclei 自動網站掃描",
  ),
  environmentHostsTitle: bilingual("Internal systems", "內部系統"),
  environmentHostsBody: bilingual(
    "Greenbone discovers supported services on the selected ports and applies its pinned remote-safe profile to each host below. It does not sign in, use credentials, expand a range, or add another host.",
    "Greenbone 會在所選連接埠探索支援的服務，並對下方每台主機套用固定的遠端安全掃描設定；不會登入、使用帳密、擴大網段或加入其他主機。",
  ),
  environmentHostCheck: bilingual(
    "Greenbone remote-safe profile · TCP {ports}",
    "Greenbone 遠端安全掃描設定 · TCP {ports}",
  ),
  environmentEndpointsTitle: bilingual("Servers and workstations — SSH, RDP, VNC, SMTP, or Telnet", "伺服器與工作站（SSH、RDP、VNC、SMTP 或 Telnet）"),
  environmentEndpointsBody: bilingual(
    "Greenbone runs only the displayed SSH, RDP, VNC, SMTP, or Telnet security profile against each exact host and port below. It does not sign in, send mail, start a remote desktop, scan the whole server or workstation, expand a range, or add other hosts.",
    "Greenbone 只會對下方每個精確主機與連接埠執行畫面所列的 SSH、RDP、VNC、SMTP 或 Telnet 資安檢查；不會登入、寄信、啟動遠端桌面、掃描整台伺服器或工作站、擴大網段或加入其他主機。",
  ),
  environmentEndpointCheck: bilingual(
    "{service} · Greenbone · {checks} security checks",
    "{service} · Greenbone · {checks} 項資安檢查",
  ),
  environmentEndpointCheckOne: bilingual(
    "{service} · Greenbone · 1 security check",
    "{service} · Greenbone · 1 項資安檢查",
  ),
  environmentDevicesTitle: bilingual("Network devices with HTTPS management", "使用 HTTPS 管理的網路設備"),
  environmentDevicesBody: bilingual(
    "Greenbone checks only each exact HTTPS management service below for TLS protocol, cipher, and certificate weaknesses. It does not sign in, inspect the whole device, expand the network range, or add other hosts.",
    "Greenbone 只會檢查下方每個精確 HTTPS 管理服務的 TLS 協定、cipher 與憑證弱點；不會登入、檢查整台設備、擴大網段或加入其他主機。",
  ),
  environmentDeviceCheck: bilingual(
    "Greenbone · {checks} TLS vulnerability checks",
    "Greenbone · {checks} 項 TLS 弱點檢查",
  ),
  environmentNotReadyTitle: bilingual(
    "Recorded for inventory, not scanned",
    "僅記錄於盤點，不會掃描",
  ),
  environmentNotReadyBody: bilingual(
    "The report lists these as not tested. To check one of these hosts, start a new scan and add it under Internal systems.",
    "報告會將它們列為未測試。若要檢查其中的主機，請開始新的掃描，並在「內部系統」加入該主機。",
  ),
  environmentNoReadyTitle: bilingual("Add one scan-ready item", "請加入至少一個可掃描項目"),
  environmentNoReadyBody: bilingual(
    "Add a project folder, a complete HTTP(S) website or API URL, or one internal-system hostname or IP. Inventory-only ranges remain visible as not tested and are not contacted or scanned.",
    "請加入專案資料夾、完整 HTTP(S) 網站或 API 網址，或一個內部系統的主機名稱或 IP。僅供盤點的網段仍會顯示為未測試，而且不會被連線或掃描。",
  ),
  environmentNetworkConfirmationTitle: bilingual(
    "I confirm I am allowed to scan every selected website, API, and internal system",
    "我確認自己有權掃描每個已選的網站、API 與內部系統",
  ),
  environmentNetworkConfirmationBody: bilingual(
    "Start will contact only these network targets: {origins}",
    "開始後只會連線到這些網路目標：{origins}",
  ),
  environmentEndpointConfirmation: bilingual(
    "The user explicitly confirmed authorization to run the displayed fixed Greenbone {service} profile against the exact {origin} service.",
    "使用者已明確確認獲准對精確的 {origin} 服務執行畫面所列的固定 Greenbone {service} 檢查。",
  ),
  environmentHostConfirmation: bilingual(
    "The user explicitly confirmed authorization to run the pinned Greenbone remote-safe profile against the exact {origin} boundary.",
    "使用者已明確確認獲准對精確的 {origin} 範圍執行固定的 Greenbone remote-safe 設定。",
  ),
  environmentDeviceConfirmation: bilingual(
    "The user explicitly confirmed authorization to run the displayed fixed Greenbone HTTPS management-service profile against the exact {origin} origin.",
    "使用者已明確確認獲准對精確的 {origin} 來源範圍執行畫面所列的固定 Greenbone HTTPS 管理服務檢查。",
  ),
  environmentStart: bilingual("Start one combined scan", "開始一次整合掃描"),
  editInputs: bilingual("Edit inputs", "編輯輸入"),
  backToReview: bilingual("Back to review", "返回確認"),
  pendingNoticeTitle: bilingual("Choose an item to see its checks", "選擇項目以查看檢查方式"),
  selectedCount: bilingual("{count} selected", "已選 {count} 項"),
  chooseAsset: bilingual("Choose {name}", "選取 {name}"),
  incompatibleSelection: bilingual("Set up each website or internal system separately. Finish or clear the current selection first.", "網站或內部系統需要逐一設定；請先完成或清除目前的選取。"),
  addPermission: bilingual("Select this item again to finish its scan setup.", "再次選取這個項目，即可完成掃描設定。"),
  assetNext: bilingual("Next step", "下一步"),
  noOwner: bilingual("Owner not recorded", "未記錄負責人"),
  owner: bilingual("Owner", "負責人"),
  region: bilingual("Region", "區域"),
  identifiers: bilingual("Source identifiers", "來源識別碼"),
  allowedModes: bilingual("Allowed checks", "已允許的檢查"),
  noAllowedModes: bilingual("No checks allowed", "未允許任何檢查"),
  findingsCount: bilingual("Saved result records", "已保存的結果紀錄"),
  assetTechnical: bilingual("Technical asset details", "資產技術細節"),
  locator: bilingual("Exact coordinate", "精確位置"),
  assetType: bilingual("Asset type", "資產類型"),
  authorizationState: bilingual("Permission state", "授權狀態"),
  internetExposure: bilingual("Internet exposure", "對外狀態"),
  exposed: bilingual("Source says public", "來源顯示為公開"),
  internal: bilingual("Source says internal", "來源顯示為內部"),
  exposureUnknown: bilingual("Unknown", "未知"),
  clearSelection: bilingual("Clear selected items", "清除已選項目"),
  grantEyebrow: bilingual("Scan choices", "掃描選項"),
  grantTitle: bilingual("Set up checks for selected items: {count}", "設定 {count} 個已選項目的檢查"),
  grantDescription: bilingual("Review the suggested checks, confirm authorization, then start.", "確認建議的檢查與執行授權，然後直接開始。"),
  guidedNetworkGrantDescription: bilingual("The exact target and recommended low-impact check are shown below.", "下方會顯示精確目標與建議的低影響檢查。"),
  guidedLocalBoundary: bilingual(
    "Saved copy: {copy} · Read-only checks: {checks}.",
    "已保存副本：{copy} · 唯讀檢查：{checks}。",
  ),
  guidedCloudBoundary: bilingual(
    "Signed-in account: {account} · Read-only checks: {checks}.",
    "已登入帳號：{account} · 唯讀檢查：{checks}。",
  ),
  presetTitle: bilingual("Recommended settings are ready", "建議設定已準備好"),
  presetBody: bilingual("Review the recommended checks and limits, then start.", "請檢查建議的掃描項目與限制後開始。"),
  guidedNetworkBoundary: bilingual(
    "{target} · {protocol} {ports} · max {rate}/s · {concurrency} concurrent · {timeout}s timeout. No exploitation, credentials, destructive actions, or added targets. Start confirms authorization.",
    "{target} · {protocol} {ports} · 每秒最多 {rate} 次 · 同時 {concurrency} 個 · {timeout} 秒逾時。不會利用弱點、使用憑證、執行破壞性操作或加入其他目標；開始即確認已獲授權。",
  ),
  websiteProfileLabel: bilingual("Website checks", "網站檢查方式"),
  websiteProfileQuick: bilingual("Quick security checks (recommended)", "快速安全檢查（建議）"),
  websiteProfilePassive: bilingual("Page response checks (ZAP)", "頁面回應檢查（ZAP）"),
  websitePassiveBounds: bilingual("Crawl: up to 2 minutes, depth 5, 100 children per page; response processing: up to 2 minutes.", "爬取最多 2 分鐘、深度 5 層、每頁最多 100 個子連結；回應處理最多 2 分鐘。"),
  websitePassiveReadyBody: bilingual("Review the exact website address below. ZAP will crawl pages and check their responses.", "在下方確認精確的網站來源範圍；ZAP 會爬取頁面並檢查回應。"),
  websitePassiveDescription: bilingual("ZAP follows links on this website and checks the responses for security issues. Confirm the origin and limits, then start.", "ZAP 會跟隨網站內的連結，檢查回應中的安全問題。確認來源範圍與限制後開始。"),
  websitePassiveBoundary: bilingual(
    "Scope: {origin}, including linked pages beyond {path}. ZAP checks responses at max {rate}/s, {concurrency} concurrent, and {timeout}s timeout. No sign-in, form submission, attack payloads, or other origins. Start only with permission for the full origin.",
    "範圍：{origin}，包含 {path} 以外的網站內連結。ZAP 檢查回應；每秒最多 {rate} 次、同時 {concurrency} 個、逾時 {timeout} 秒。不登入、不送出表單、不發送攻擊內容，也不接觸其他來源。獲准檢查完整來源範圍後再開始。",
  ),
  environmentWebsitePassiveBody: bilingual("ZAP crawls links within each selected origin and checks responses at 5 requests/s, five concurrent and a 10s timeout. It does not sign in, submit forms, send attack payloads, or contact other origins.", "ZAP 會爬取每個已選來源內的連結並檢查回應；每秒最多 5 次、同時 5 個、逾時 10 秒。不登入、不送出表單、不發送攻擊內容，也不接觸其他來源。"),
  websiteQuickBoundary: bilingual(
    "Scope: {origin}, not only {path}. Nuclei applies matching pinned read-only checks at max {rate}/s, {concurrency} concurrent, and {timeout}s timeout. No sign-in, forms, redirects, or exploitation. Start only with permission for the full origin.",
    "範圍：{origin}，不只 {path}。Nuclei 會執行適用的固定唯讀檢查；每秒最多 {rate} 次、同時 {concurrency} 個、逾時 {timeout} 秒。不登入、不送出表單、不跟隨重新導向，也不利用弱點。獲准檢查完整來源範圍後再開始。",
  ),
  guidedNetworkTechnicalPreset: bilingual(
    "Current preset: {protocol}; exact service ports: {count}; up to {concurrency} simultaneous connections.",
    "目前設定：{protocol}、{count} 個精確服務連接埠、最多 {concurrency} 個並行連線。",
  ),
  noCommonTitle: bilingual("These items need different scan setups", "這些項目需要不同的掃描設定"),
  noCommonBody: bilingual("Set up websites and internal systems separately from cloud accounts and local projects.", "請把網站與內部系統，和雲端帳號與本機專案分開設定。"),
  allowedQuestion: bilingual("What should this scan check?", "這次掃描要檢查哪些內容？"),
  changeScanType: bilingual("Use a different scan type (advanced)", "改用其他掃描方式（進階）"),

  externalEyebrow: bilingual("Target confirmation", "確認掃描目標"),
  externalTitle: bilingual("Confirm {name}", "確認 {name}"),
  externalDescription: bilingual("Conservative settings are selected. Confirm authorization, then start.", "保守設定已選取；確認授權後即可開始。"),
  websiteQuickDescription: bilingual("This scan is limited to the website origin and fixed checks shown below. Confirm it, then start.", "這次掃描只會使用下方顯示的網站來源範圍與固定檢查。確認後即可開始。"),
  guidedExternalDescription: bilingual("This is the exact target saved in your scan project.", "這是掃描專案中保存的精確目標。"),
  advancedScanSettings: bilingual("Advanced scan settings", "進階掃描設定"),
  advancedScanSettingsHelp: bilingual("Connection details, speed limits, and the active-test list", "連線細節、速度限制與主動測試清單"),
  activeSetupTitle: bilingual("Active testing needs one more step", "主動測試還需要一個步驟"),
  activeSetupBody: bilingual("Open Advanced scan settings and add the approved test list before starting.", "請打開「進階掃描設定」，加入已核准的測試清單後再開始。"),
  sourcePublic: bilingual("Public website", "公開網站"),
  sourceInternal: bilingual("Internal system", "內部系統"),
  sourceExposureUnknown: bilingual("Needs source details", "需要補充來源資料"),
  noDirectTitle: bilingual("Public-record review only", "僅查看公開紀錄"),
  noDirectBody: bilingual("Add source connection details to enable direct testing.", "加入來源連線資料即可啟用直接測試。"),
  internalGrantTitle: bilingual("This is an internal system", "這是內部系統"),
  internalGrantBody: bilingual("To connect from this computer, turn on the internal-network confirmation below.", "若要從這台電腦連線，請開啟下方的內部網路確認。"),
  noTargetTitle: bilingual("Add one specific website or IP address first", "請先加入一個明確的網站或 IP 位址"),
  noTargetBody: bilingual("Go back to the scan project, enter one complete address, then refresh this list.", "請回到掃描專案，輸入一個完整位址，再重新整理這份清單。"),
  declaredServiceTitle: bilingual("Website service details", "網站服務資訊"),
  declaredServiceBody: bilingual("The saved URL sets {protocol}, port {port}, and path {path}. The scan uses the protocol and port below; the path remains context.", "保存的網址設定為 {protocol}、連接埠 {port} 與路徑 {path}。掃描使用下方協定與連接埠；路徑保留為背景資訊。"),
  canonicalTarget: bilingual("Website or system to check", "要檢查的網站或系統"),
  canonicalTargetHelp: bilingual("This value comes from the item you added. Return to the scan project if it needs to change.", "這個值來自你加入的項目；若要修改，請回到掃描專案。"),
  protocol: bilingual("Protocol", "傳輸協定"),
  protocolHelp: bilingual("The protocol list is fixed when the scan starts.", "掃描開始時即固定協定清單。"),
  ports: bilingual("Allowed ports", "允許的連接埠"),
  portsInvalid: bilingual("Use numbers from 1 to 65535, separated by commas or spaces.", "格式錯誤：只接受 1–65535 的數字，以逗號或空白分隔。"),
  portsValid: bilingual("Exact ports accepted: {count}; ranges and port 0 are not accepted.", "{count} 個固定連接埠；不支援範圍或連接埠 0。"),
  policyRevision: bilingual("Locked test-list revision", "鎖定的測試清單版本"),
  revisionValid: bilingual("Locked to the exact template commit bundled with this product.", "已鎖定到產品內嵌測試範本的精確版本。"),
  revisionInvalid: bilingual("The bundled template revision does not match the product's pinned value.", "內嵌測試範本版本不符合產品鎖定值。"),
  rateTitle: bilingual("Request and timeout limits", "請求速率與逾時限制"),
  rps: bilingual("Requests per second", "每秒請求"),
  concurrency: bilingual("Concurrent requests", "並行請求數"),
  timeout: bilingual("Timeout in seconds", "逾時秒數"),
  durationWarningTitleHours: bilingual(
    "Minimum scan time: {hours} hr {minutes} min",
    "這次掃描至少需要 {hours} 小時 {minutes} 分鐘",
  ),
  durationWarningTitleMinutes: bilingual(
    "Minimum scan time: {minutes} min",
    "這次掃描至少需要 {minutes} 分鐘",
  ),
  durationWarningBody: bilingual(
    "Exact CIDR scope — usable addresses: {addresses}; ports: {ports}; connection checks: {probes}. Pacing floor: {effectiveRate}/s; requested rate: {requestedRate}/s; concurrency: {concurrency}. Hosts that do not answer can take longer because each connection has its own timeout.",
    "這個 CIDR 包含 {addresses} 個可用位址與 {ports} 個連接埠（共 {probes} 次連線檢查）。速率下限採用每秒 {effectiveRate} 次檢查，也就是每秒請求 {requestedRate} 次與 {concurrency} 個並行檢查中較低的數值。無回應的主機可能因每次連線各有逾時而花更久。",
  ),
  durationCeilingRiskBody: bilingual(
    "Estimated upper bound: {upperHours} hr {upperMinutes} min; scanner limit: {ceilingHours} hr. Narrow the CIDR, ports, or {timeout}-second timeout before starting.",
    "預估上限：{upperHours} 小時 {upperMinutes} 分鐘；掃描限制：{ceilingHours} 小時。開始前請縮小 CIDR、連接埠或 {timeout} 秒逾時。",
  ),
  durationCeilingWithinBody: bilingual(
    "Estimated upper bound: {upperHours} hr {upperMinutes} min; scanner limit: {ceilingHours} hr.",
    "預估上限：{upperHours} 小時 {upperMinutes} 分鐘；掃描限制：{ceilingHours} 小時。",
  ),
  maximum: bilingual("Maximum {value}", "最多 {value}"),
  templateIds: bilingual("Exact active-test IDs (required)", "精確主動測試 ID（必填）"),
  templatePlaceholder: bilingual("One exact template ID per line; * is not accepted", "每行一個精確 template ID；不接受 *"),
  templateValid: bilingual("Exact IDs accepted: {count}.", "{count} 個精確 ID。"),
  templateInvalid: bilingual("Wildcard * is not accepted.", "不可使用萬用字元 *。"),
  prohibitedIntro: bilingual("The following capabilities always remain off:", "以下能力固定保持關閉："),
  sensitiveTitle: bilingual("I confirm this scan may connect to the selected internal network", "我確認這次掃描可以連線到所選內部網路"),
  sensitiveBody: bilingual("System-owner approval for access from this computer is required. Public websites leave this off.", "從這台電腦存取必須取得系統負責人核准；公開網站不需開啟。"),
  sensitiveTechnicalTitle: bilingual("Exact internal-network behavior", "內部網路的精確行為"),
  sensitiveTechnicalBody: bilingual("This permits only the selected target to resolve to approved private, loopback, or link-local networks. Metadata endpoints remain blocked, and no additional target is added.", "只允許所選目標解析到已核准的 private、loopback 或 link-local 網段；metadata endpoints 仍保持阻擋，也不會加入其他目標。"),
  publicBoundaryTitle: bilingual("Exact public-target boundary", "公開目標的精確界線"),
  publicBoundaryBody: bilingual("Only the selected target, protocol, and ports are allowed. Private, loopback, link-local, and metadata addresses remain blocked, and no additional target is added.", "只允許所選目標、協定與連接埠；private、loopback、link-local 與 metadata 位址仍保持阻擋，也不會加入其他目標。"),
  internalAssetPlatform: bilingual("Internal system / LAN", "內部系統／區域網路"),
  ownershipTitle: bilingual("I confirm that I am allowed to scan every selected item", "我確認自己有權掃描每一個已選項目"),
  externalOwnershipTitle: bilingual("I confirm this is my website or a system I am allowed to scan", "我確認這是我的網站，或是我有權掃描的系統"),
  internalOwnershipTitle: bilingual("I confirm this is an internal system I am allowed to scan", "我確認這是我有權掃描的內部系統"),
  ownershipBody: bilingual("Scan authorization must cover every selected item before Start.", "開始前，掃描授權必須涵蓋每一個已選項目。"),
  authorityRequired: bilingual("Approval reference (required)", "核准紀錄（必填）"),
  scopeNote: bilingual("Note (optional)", "備註（選填）"),
  authorityPlaceholder: bilingual("Example: ticket or contract number and approver", "例如：工單／合約編號與核准人"),
  notePlaceholder: bilingual("Example: internal approval for this read-only review", "例如：本次唯讀檢查的內部核准紀錄"),
  authorityHelp: bilingual("Required record: ticket, contract, or approver confirming this scan. Passwords, keys, and tokens are not accepted.", "必要紀錄：確認本次掃描的工單、合約或核准人。不接受密碼、金鑰或 token。"),
  noteHelp: bilingual("Field requirement: no secret values or credentials.", "欄位規格：不得包含秘密值或憑證。"),
  activeAuthorityLength: bilingual("An active-test permission reference needs at least 8 characters.", "主動測試的授權參考至少需要 8 個字元。"),
  grantBoundaryHelp: bilingual("This saves the exact target and limits, then starts the scan. Unavailable checks will be listed without stopping the others.", "這會保存精確目標與限制並開始掃描；無法執行的檢查會列出，不會阻止其他檢查。"),
  startScan: bilingual("Start scan", "開始掃描"),
  confirmAndStart: bilingual("Confirm and start scan", "確認並開始掃描"),
  scanSignedInCloud: bilingual("Scan this signed-in account", "掃描這個已登入帳號"),
  startingScan: bilingual("Starting…", "正在開始…"),
  preparingScanTools: bilingual("Preparing scan tools…", "正在準備掃描工具…"),
  defaultScopeNote: bilingual("The user confirmed ownership and the read-only boundary item by item in the local interface.", "使用者已在本機介面逐項確認資產所有權與唯讀範圍。"),
  guidedNetworkConfirmation: bilingual("The user explicitly confirmed this exact low-impact network target in the guided local interface.", "使用者已在本機引導介面明確確認這個精確的低影響網路目標。"),
  websiteQuickConfirmation: bilingual("The user explicitly confirmed authorization to scan the exact {origin} origin with the displayed fixed quick profile.", "使用者已明確確認獲准以畫面所列固定快速設定掃描精確的 {origin} 網站來源範圍。"),
  guidedLocalConfirmation: bilingual("The user explicitly selected this saved local copy and confirmed the recommended read-only checks.", "使用者已明確選擇這份已保存的本機副本，並確認建議的唯讀檢查。"),
  guidedCloudConfirmation: bilingual("The user signed in through the provider and explicitly added this exact account with the displayed read-only checks.", "使用者已透過雲端服務商登入，並明確以畫面所列唯讀檢查加入這個精確帳號。"),
  advancedLocalInputSummary: bilingual("Use a different kind of local input", "改用其他本機輸入類型"),
  advancedLocalInputHelp: bilingual("Use this control to attach a different project or export type.", "使用這個選項附加其他專案或匯出類型。"),

  emptyUnknownTitle: bilingual("No items: source missing", "沒有項目：缺少資料來源"),
  emptyUnknownBody: bilingual("Required input missing. Connect it to list its assets.", "缺少必要輸入；連接後即可列出資產。"),
  emptyNoneTitle: bilingual("Connected sources found 0 items", "已連接來源找到 0 個項目"),
  emptyNoneBody: bilingual("Source result: 0 items.", "來源結果：0 個項目。"),
  emptyNeverTitle: bilingual("List not refreshed", "清單未重新整理"),
  emptyNeverBody: bilingual("Attach an input in step 1, then refresh what the product can see.", "請先在步驟 1 附加輸入，再重新確認產品看得到什麼。"),
  emptyFilterTitle: bilingual("No items match this filter", "沒有項目符合這個篩選條件"),
  emptyFilterBody: bilingual("Clear the filter to review the other items.", "請清除篩選以查看其他項目。"),

  grantsEyebrow: bilingual("Saved scan access", "已儲存的掃描許可"),
  grantsTitle: bilingual("Network checks already approved", "已確認的網路檢查"),
  grantsDescription: bilingual("These saved choices keep future runs consistent. Open a record when you need the exact technical limits.", "這些選擇會讓後續掃描維持一致；需要時可打開紀錄查看精確技術限制。"),
  grantsCount: bilingual("Saved setups: {count}", "{count} 份已儲存設定"),
  savedApprovals: bilingual("Saved network approvals ({count})", "已儲存的網路許可（{count}）"),
  grantTechnical: bilingual("View saved scan settings", "查看已儲存的掃描設定"),
  expires: bilingual("Expires {date}", "到期 {date}"),
  lowImpactInternalActivity: bilingual("Low-impact internal checks", "低影響內部連線"),
  sensitiveAllowed: bilingual("Internal network access allowed", "已允許內部網路存取"),
  sensitiveBlocked: bilingual("Internal network access off", "未開啟內部網路存取"),
  targetTerm: bilingual("Target", "目標"),
  protocolPortsTerm: bilingual("Protocol and ports", "協定與連接埠"),
  noDirectPort: bilingual("No direct-connection port", "沒有直接連線連接埠"),
  rateTerm: bilingual("Request limits", "請求限制"),
  templatesTerm: bilingual("Test-list policy", "測試清單政策"),
  allowedIdsCount: bilingual("Allowed IDs: {count}", "允許的 ID：{count}"),
  authorityTerm: bilingual("Permission reference", "授權參考"),
  approvalTerm: bilingual("Recorded by", "記錄者"),
  prohibitedAll: bilingual("Headless browser, out-of-band callback, fuzzing, file upload, denial of service, and credential attacks are all blocked.", "無頭瀏覽器、站外回呼、模糊測試、檔案上傳、阻斷服務與密碼攻擊全部禁止。"),
} as const;

const assetTypeLabels: Record<Asset["type"], BilingualText> = {
  cloud_account: bilingual("Cloud account", "雲端帳號"),
  subscription: bilingual("Cloud subscription", "雲端訂閱"),
  project: bilingual("Cloud project", "雲端專案"),
  tenant: bilingual("Tenant", "租用戶"),
  domain: bilingual("Domain", "網域"),
  ip: bilingual("IP address", "IP 位址"),
  repository: bilingual("Source or infrastructure-code project", "程式碼或基礎設施程式碼專案"),
  image: bilingual("Container image", "容器映像"),
  cluster: bilingual("Kubernetes cluster", "Kubernetes 叢集"),
  service: bilingual("Network service", "網路服務"),
  cloud_resource: bilingual("Cloud resource", "雲端資源"),
  identity: bilingual("Identity", "身分"),
  storage: bilingual("Cloud storage", "雲端儲存空間"),
};

const authorizationStateLabels: Record<Asset["authorizationState"], BilingualText> = {
  authorized: bilingual("Target confirmed", "目標已確認"),
  pending: bilingual("Choose checks first", "請先選擇檢查方式"),
  excluded: bilingual("Not included in this scan", "未納入這次掃描"),
  unknown: bilingual("Confirm who owns it", "請確認負責人"),
};

const prohibitedCapabilities = [
  bilingual("Headless browser", "無頭瀏覽器"),
  bilingual("Out-of-band callback", "站外回呼"),
  bilingual("Fuzzing", "模糊測試"),
  bilingual("File upload", "檔案上傳"),
  bilingual("Denial of service", "阻斷服務"),
  bilingual("Credential attacks", "密碼攻擊"),
];

const nextStepForAsset = (asset: Asset): BilingualText => {
  if (isAwaitingFirstScan(asset.coverageState, asset.scanAttempted)) {
    return pageCopy.readyToScanNext;
  }
  if (asset.localInputProfile) {
    if (asset.localInputProfile === "repository_working_tree") {
      return bilingual(
        "Allow read-only review of this saved source-code copy.",
        "允許唯讀檢查這份已保存的程式碼副本。",
      );
    }
    if (asset.localInputProfile === "iac_working_tree") {
      return bilingual(
        "Allow read-only review of this saved infrastructure-code copy.",
        "允許唯讀檢查這份已保存的基礎設施程式碼副本。",
      );
    }
    if (asset.localInputProfile === "kubernetes_manifests"
      || asset.localInputProfile === "kubernetes_node_snapshot") {
      return bilingual(
        "Allow offline review of this saved Kubernetes input only.",
        "只允許離線檢查這份已保存的 Kubernetes 輸入。",
      );
    }
    if (asset.localInputProfile === "container_image_oci_layout") {
      return bilingual(
        "Allow offline review of this saved container image only.",
        "只允許離線檢查這份已保存的容器映像。",
      );
    }
    return bilingual(
      "Allow read-only review of this saved local input.",
      "允許唯讀檢查這份已保存的本機輸入。",
    );
  }
  if (asset.platform === "external" && asset.internetExposed === false) {
    return bilingual(
      "Confirm authorization for this exact internal system, then use the recommended low-impact settings.",
      "確認這個精確內部系統的授權，再使用建議的低影響設定。",
    );
  }
  if (asset.platform === "external" && asset.type === "ip") {
    return bilingual(
      "Use the recommended low-impact connection check for this IP address.",
      "對這個 IP 使用建議的低影響連線檢查。",
    );
  }
  if (asset.platform === "external") {
    return bilingual(
      "Confirm authorization for this exact website, then use the recommended scan settings.",
      "確認這個精確網站的授權，再使用建議的掃描設定。",
    );
  }
  if (asset.platform === "code") {
    return bilingual(
      "Confirm this is the code project you want checked.",
      "確認這是你想檢查的程式碼專案。",
    );
  }
  if (asset.platform === "container") {
    return bilingual("Confirm this is the container image you want checked.", "確認這是你想檢查的容器映像。");
  }
  if (asset.platform === "kubernetes") {
    return bilingual(
      "Confirm that this is the Kubernetes cluster you want checked.",
      "確認這是你想檢查的 Kubernetes 叢集。",
    );
  }
  return bilingual(
    "Confirm this is the cloud account you want checked, then choose the recommended read-only checks.",
    "確認這是你想檢查的雲端帳號，再選擇建議的唯讀檢查。",
  );
};

const scrollToCoverageStep = (id: string): boolean => {
  const target = document.getElementById(id);
  if (!target) return false;
  const reduceMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
  target.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
  return true;
};

const parsePorts = (value: string): number[] | undefined => {
  if (!value.trim()) return [];
  const parts = value.split(/[\s,]+/).filter(Boolean).map(Number);
  if (parts.some((port) => !Number.isInteger(port) || port < 1 || port > 65_535)) return undefined;
  return [...new Set(parts)].sort((a, b) => a - b);
};

const parseTemplateIds = (value: string): string[] =>
  [...new Set(value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean))];

const directExternalTargetsForAsset = (asset: Asset): string[] => {
  const acceptedNamespaces = asset.declaredWebService || asset.declaredNetworkService || asset.declaredHostScan
    ? new Set(["dns_name", "ip_address"])
    : new Set(["dns_name", "ip_address", "ip_network"]);
  return [...new Set((asset.identifiers ?? [])
    .filter((identifier) => acceptedNamespaces.has(identifier.namespace))
    .map((identifier) => identifier.value.trim())
    .filter((value) => validateExternalTarget(value).ok))];
};

export function CoveragePage({
  caseId,
  assessmentIntent,
  focusSetup,
  requestedActivities,
  coverage,
  sources,
  engineManifests,
  assets,
  scopeGrants,
  nativeMode,
  busy,
  discoveryBusy,
  runtimeSetupNotice,
  onChooseSnapshot,
  onConnectSourceSnapshot,
  onChooseWorkspace,
  onAttachWorkspaceSnapshot,
  onSelectMcpConfiguration,
  onSelectAgenticFramework,
  onStartModelCheck,
  onStartDiscovery,
  onAuthorizationChanged,
  onStartScan,
  onStartEnvironmentScan,
}: CoveragePageProps) {
  const { locale, text, formatDateTime, formatNumber } = useI18n();
  const guidedLocalProfile = assessmentIntent ? localProfileByAssessmentIntent[assessmentIntent] : undefined;
  const guidedLocalInput = guidedLocalProfile
    ? localInputDefinitionForAssessmentIntent(guidedLocalProfile, assessmentIntent)
    : undefined;
  const environmentRoute = assessmentIntent === "internal_it_environment";
  const guidedNetworkRoute = !environmentRoute
    && Boolean(assessmentIntent && networkAssessmentIntents.includes(assessmentIntent));
  const guidedCloudRoute = assessmentIntent === "cloud_account";
  const guidedCoverageRoute = useMemo<GuidedCoverageRoute>(() => {
    if (guidedNetworkRoute) return { kind: "network" };
    if (guidedCloudRoute) return { kind: "cloud" };
    if (guidedLocalProfile) return { kind: "local", profile: guidedLocalProfile };
    return { kind: "none" };
  }, [guidedCloudRoute, guidedLocalProfile, guidedNetworkRoute]);
  const [incidentFocus, setIncidentFocus] = useState(false);
  useEffect(() => setIncidentFocus(false), [caseId]);
  const [filter, setFilter] = useState<CoverageState | "all">("all");
  const [selectedAssets, setSelectedAssets] = useState<string[]>([]);
  const [showSourceForm, setShowSourceForm] = useState(false);
  const [showWorkspaceForm, setShowWorkspaceForm] = useState(Boolean(guidedLocalProfile));
  const [showProviderSetup, setShowProviderSetup] = useState(guidedCloudRoute);
  // A cloud project's next step is the sign-in panel inside source setup, and
  // native projects always list their planned sources, so open it explicitly.
  const sourceSetupStartsOpen = guidedCloudRoute || (assets.length === 0 && sources.length === 0);
  const [sourceSetupOpen, setSourceSetupOpen] = useState(sourceSetupStartsOpen);
  const [sourceKind, setSourceKind] = useState<SourceKind>("aws_organization");
  const [profile, setProfile] = useState<SnapshotParserProfile>("cloudquery");
  const [sourceLabel, setSourceLabel] = useState<string>(() => text(sourceDefinitions.aws_organization.label));
  const [selectedPath, setSelectedPath] = useState("");
  const [choosingSnapshot, setChoosingSnapshot] = useState(false);
  const [sourceFormError, setSourceFormError] = useState<BilingualText>();
  const [workspaceLabel, setWorkspaceLabel] = useState(() => text(
    guidedLocalInput
      ? guidedLocalInput.label
      : bilingual("Local source-code project", "本機程式碼專案"),
  ));
  const [workspaceInputProfile, setWorkspaceInputProfile] = useState<LocalInputProfile>(guidedLocalProfile ?? "repository_working_tree");
  const [selectedWorkspacePath, setSelectedWorkspacePath] = useState("");
  const [choosingWorkspace, setChoosingWorkspace] = useState(false);
  const [workspaceFormError, setWorkspaceFormError] = useState<BilingualText>();
  const [scopeModes, setScopeModes] = useState<ScopeMode[]>([]);
  const [scopeConfirmation, setScopeConfirmation] = useState("");
  const [ownershipConfirmed, setOwnershipConfirmed] = useState(false);
  const [externalTarget, setExternalTarget] = useState("");
  const [externalPorts, setExternalPorts] = useState("443");
  const [externalProtocol, setExternalProtocol] = useState<TransportProtocol>("https");
  const [requestsPerSecond, setRequestsPerSecond] = useState(1);
  const [externalConcurrency, setExternalConcurrency] = useState(1);
  const [externalTimeout, setExternalTimeout] = useState(60);
  const [templateRevision, setTemplateRevision] = useState<string>(websiteQuickProfile.templateRevision);
  const [websiteScanProfile, setWebsiteScanProfile] = useState<"quick" | "passive">("quick");
  const zapRunnable = engineManifests.some((manifest) => manifest.id === "zap" && manifest.runnable === true);
  const passiveWebsiteSelected = !incidentFocus && zapRunnable && websiteScanProfile === "passive";
  const selectedWebsiteProfile = passiveWebsiteSelected ? websitePassiveProfile : websiteQuickProfile;
  const [allowedTemplateIds, setAllowedTemplateIds] = useState("");
  const [allowSensitiveNetworks, setAllowSensitiveNetworks] = useState(false);
  const [showAdvancedExternalSettings, setShowAdvancedExternalSettings] = useState(false);
  const [showCompletedSetup, setShowCompletedSetup] = useState(false);
  const [providerConnection, setProviderConnection] = useState<ProviderConnectionBoundary>();
  const [providerCleanupNeedsAttention, setProviderCleanupNeedsAttention] = useState(false);
  const [environmentNetworkConfirmed, setEnvironmentNetworkConfirmed] = useState(false);

  const counts = useMemo(
    () => Object.fromEntries(coverageStates.map((state) => [state, coverage.filter((item) => item.state === state).length])) as Record<CoverageState, number>,
    [coverage],
  );

  const filteredAssets = useMemo(
    () => (filter === "all" ? assets : assets.filter((asset) => asset.coverageState === filter)),
    [assets, filter],
  );

  const pendingAssets = assets.filter((asset) => asset.authorizationState === "pending");
  const scopeEligibleAssets = useMemo(() => assets.filter(isScopeEligible), [assets]);
  const mcpArmorRunnable = engineManifests.some((manifest) => (
    manifest.id === "mcp-armor" && manifest.runnable === true && manifest.compatibilityValid
  ));
  const agenticRadarRunnable = engineManifests.some((manifest) => (
    manifest.id === "agentic-radar" && manifest.runnable === true && manifest.compatibilityValid
  ));
  const localEngineIdsForAsset = (asset: Asset): string[] => {
    const engineIds = [
    ...(asset.localInputProfile ? localInputEngineIds[asset.localInputProfile] : []),
    ...(mcpArmorRunnable && asset.localInputProfile === "repository_working_tree" && asset.selectedMcpConfiguration
      ? ["mcp-armor"]
      : []),
    ...(agenticRadarRunnable && asset.localInputProfile === "repository_working_tree" && asset.agenticRadarFramework
      ? ["agentic-radar"]
      : []),
    ];
    return incidentFocus ? selectIncidentFocusEngines(engineIds) : engineIds;
  };
  const agenticInventorySelection = (selected: readonly Asset[]) => {
    const repositories = selected.filter((asset) => asset.localInputProfile === "repository_working_tree");
    if (!agenticRadarRunnable || repositories.length === 0) return null;
    return (
      <details className="coverage-form-technical coverage-scan-advanced" data-agentic-inventory>
        <summary>{text(pageCopy.agenticInventoryTitle)}</summary>
        <p>{text(pageCopy.agenticInventoryHelp)}</p>
        {repositories.map((asset) => (
          <label className="field" key={`${asset.id}-agentic-framework`}>
            <span>{text(pageCopy.agenticFrameworkLabel)}{repositories.length > 1 ? ` · ${asset.name}` : ""}</span>
            <select
              disabled={busy || !onSelectAgenticFramework}
              value={asset.agenticRadarFramework ?? ""}
              onChange={(event) => {
                const framework = agenticRadarFramework(event.target.value);
                if (framework || event.target.value === "") {
                  setEnvironmentNetworkConfirmed(false);
                  setOwnershipConfirmed(false);
                  void onSelectAgenticFramework?.(asset.id, framework ?? null);
                }
              }}
            >
              <option value="">{text(pageCopy.agenticInventoryOff)}</option>
              {agenticRadarFrameworks.map((framework) => <option value={framework.id} key={framework.id}>{framework.label}</option>)}
            </select>
          </label>
        ))}
      </details>
    );
  };
  const environmentLocalAssets = useMemo(
    () => scopeEligibleAssets.filter((asset) => Boolean(asset.localInputProfile)),
    [scopeEligibleAssets],
  );
  const environmentHostAssets = useMemo(() => scopeEligibleAssets.flatMap((asset) => {
    const hostScan = asset.declaredHostScan;
    const target = directExternalTargetsForAsset(asset)[0];
    if (
      asset.platform !== "external"
      || !hostScan
      || hostScan.protocol !== "tcp"
      || hostScan.scanProfile !== internalHostGreenboneProfile.scanProfile
      || !target
      || typeof asset.internetExposed !== "boolean"
    ) return [];
    return [{
      asset,
      target,
      origin: `${target} · TCP ${hostScan.ports.join(", ")}`,
      ports: hostScan.ports,
      profile: internalHostGreenboneProfile,
    }];
  }), [scopeEligibleAssets]);
  const environmentDeviceAssets = useMemo(() => scopeEligibleAssets.flatMap((asset) => {
    const service = asset.declaredWebService;
    const profile = internalDeviceProfileFromScanProfile(service?.scanProfile);
    const target = directExternalTargetsForAsset(asset)[0];
    if (
      asset.platform !== "external"
      || !service
      || service.protocol !== "https"
      || !profile
      || !target
      || typeof asset.internetExposed !== "boolean"
    ) return [];
    return [{
      asset,
      target,
      origin: websiteQuickOrigin(target, service.protocol, service.port),
      profile,
    }];
  }), [scopeEligibleAssets]);
  const environmentEndpointAssets = useMemo(() => scopeEligibleAssets.flatMap((asset) => {
    const service = asset.declaredNetworkService;
    const serviceType = internalEndpointServiceFromScanProfile(service?.scanProfile);
    const target = directExternalTargetsForAsset(asset)[0];
    if (
      asset.platform !== "external"
      || !service
      || service.protocol !== "tcp"
      || !serviceType
      || !target
      || typeof asset.internetExposed !== "boolean"
    ) return [];
    return [{
      asset,
      target,
      origin: internalEndpointCoordinate(target, service.port),
      serviceType,
      profile: internalEndpointProfiles[serviceType],
    }];
  }), [scopeEligibleAssets]);
  const environmentWebsiteAssets = useMemo(() => scopeEligibleAssets.flatMap((asset) => {
    const service = asset.declaredWebService;
    const target = directExternalTargetsForAsset(asset)[0];
    if (
      asset.platform !== "external"
      || !service
      || internalDeviceProfileFromScanProfile(service.scanProfile)
      || !target
      || typeof asset.internetExposed !== "boolean"
    ) return [];
    return [{
      asset,
      target,
      origin: websiteQuickOrigin(target, service.protocol, service.port),
    }];
  }), [scopeEligibleAssets]);
  const environmentReadyAssetIds = useMemo(
    () => new Set([
      ...environmentLocalAssets.map((asset) => asset.id),
      ...environmentHostAssets.map(({ asset }) => asset.id),
      ...environmentWebsiteAssets.map(({ asset }) => asset.id),
      ...environmentEndpointAssets.map(({ asset }) => asset.id),
      ...environmentDeviceAssets.map(({ asset }) => asset.id),
    ]),
    [environmentDeviceAssets, environmentEndpointAssets, environmentHostAssets, environmentLocalAssets, environmentWebsiteAssets],
  );
  const environmentNetworkAssetIds = useMemo(
    () => new Set([
      ...environmentWebsiteAssets.map(({ asset }) => asset.id),
      ...environmentHostAssets.map(({ asset }) => asset.id),
      ...environmentEndpointAssets.map(({ asset }) => asset.id),
      ...environmentDeviceAssets.map(({ asset }) => asset.id),
    ]),
    [environmentDeviceAssets, environmentEndpointAssets, environmentHostAssets, environmentWebsiteAssets],
  );
  const environmentUnreadyExternalAssets = useMemo(
    () => scopeEligibleAssets.filter((asset) => (
      asset.platform === "external" && !environmentReadyAssetIds.has(asset.id)
    )),
    [environmentReadyAssetIds, scopeEligibleAssets],
  );
  const guidedSelectableAsset = useMemo(
    () => singleGuidedSelectableAsset(scopeEligibleAssets, guidedCoverageRoute),
    [guidedCoverageRoute, scopeEligibleAssets],
  );
  const scannedAssets = assets.filter((asset) => asset.coverageState === "discovered_authorized_scanned").length;
  const incompleteAssets = assets.filter((asset) =>
    asset.coverageState === "authorized_incomplete" && asset.scanAttempted !== false
  ).length;
  const unknownSourceCount = coverage.filter((item) => item.state === "source_unavailable_unknown").length;
  const connectedNoAssetCount = coverage.filter((item) => item.state === "source_connected_none").length;
  const hasExistingInputs = assets.length > 0 || sources.length > 0;
  const useCompactAssetList = filteredAssets.length > 4;
  const frozenExternalGrants = scopeGrants.filter((grant) => grant.externalScope);
  const selectedSource = sourceDefinitions[sourceKind];
  const selectedLocalInput = guidedLocalProfile === workspaceInputProfile && guidedLocalInput
    ? guidedLocalInput
    : localInputDefinitions[workspaceInputProfile];
  const selectedScopeAssets = assets.filter((asset) => selectedAssets.includes(asset.id));
  const selectedEnvironmentLocalAssets = environmentLocalAssets.filter((asset) => selectedAssets.includes(asset.id)
    && localEngineIdsForAsset(asset).length > 0);
  const selectedEnvironmentHostAssets = environmentHostAssets.filter(({ asset }) => !incidentFocus && selectedAssets.includes(asset.id));
  const selectedEnvironmentWebsiteAssets = environmentWebsiteAssets.filter(({ asset }) => !incidentFocus && selectedAssets.includes(asset.id));
  const selectedEnvironmentEndpointAssets = environmentEndpointAssets.filter(({ asset }) => !incidentFocus && selectedAssets.includes(asset.id));
  const selectedEnvironmentDeviceAssets = environmentDeviceAssets.filter(({ asset }) => !incidentFocus && selectedAssets.includes(asset.id));
  const incidentFocusAvailable = scopeEligibleAssets.some((asset) => asset.localInputProfile
    && selectIncidentFocusEngines(localInputEngineIds[asset.localInputProfile]).length > 0);
  const incidentExcludedAssets = incidentFocus ? scopeEligibleAssets.filter((asset) =>
    !asset.localInputProfile || localEngineIdsForAsset(asset).length === 0) : [];
  const selectedEnvironmentNetworkAssets = [
    ...selectedEnvironmentHostAssets,
    ...selectedEnvironmentWebsiteAssets,
    ...selectedEnvironmentEndpointAssets,
    ...selectedEnvironmentDeviceAssets,
  ];
  const selectedEnvironmentAssetCount = selectedEnvironmentLocalAssets.length
    + selectedEnvironmentHostAssets.length
    + selectedEnvironmentWebsiteAssets.length
    + selectedEnvironmentEndpointAssets.length
    + selectedEnvironmentDeviceAssets.length;
  const firstSelectedScopeAsset = selectedScopeAssets[0];
  const availableScopeModes = !firstSelectedScopeAsset
    ? []
    : permittedModes(firstSelectedScopeAsset).filter((mode) => selectedScopeAssets.every((asset) => permittedModes(asset).includes(mode)));
  const selectedExternalAsset = selectedScopeAssets.length === 1 && selectedScopeAssets[0]?.platform === "external"
    ? selectedScopeAssets[0]
    : undefined;
  const selectedWebsiteService = selectedExternalAsset?.declaredWebService;
  const externalMode = scopeModes.find((mode) => externalActivities[mode]);
  const externalActivity = externalMode ? externalActivities[externalMode] : undefined;
  const guidedLowImpactNetwork = guidedNetworkRoute && externalActivity === "low_impact_external";
  const guidedWebsiteQuickProfile = Boolean(
    assessmentIntent === "deployed_website"
    && selectedWebsiteService
    && externalActivity === "active_external",
  );
  const guidedLocalConsent = Boolean(
    guidedLocalProfile
    && selectedScopeAssets.length > 0
    && selectedScopeAssets.every((asset) => Boolean(asset.localInputProfile))
    && scopeModes.length === 1
    && scopeModes[0] === "local_artifact",
  );
  const guidedLocalEngineIds = guidedLocalConsent
    ? [...new Set(selectedScopeAssets.flatMap((asset) => localEngineIdsForAsset(asset)))]
    : undefined;
  const mcpSelectionRequired = Boolean(
    !incidentFocus
    && mcpArmorRunnable
    && guidedLocalConsent
    && selectedScopeAssets.some((asset) => (
      asset.localInputProfile === "repository_working_tree"
      && (asset.mcpConfigurationCandidates?.length ?? 0) > 1
      && !asset.selectedMcpConfiguration
    )),
  );
  const guidedCloudConsent = guidedCloudRoute
    && hasExactGuidedCloudConsent(selectedScopeAssets, providerConnection);
  const conciseGuidedConsent = guidedLowImpactNetwork || guidedWebsiteQuickProfile || guidedLocalConsent || guidedCloudConsent;
  // The cloud consent boundary is owned by the mounted provider panel. Keep
  // that panel visible instead of creating an unmount/reconnect loop.
  // The IT-environment form already collected every target, so its review is
  // the plan and Start alone; source setup and the ledger stay one click away.
  const focusedGuidedReview = (
    (guidedLowImpactNetwork || guidedWebsiteQuickProfile || guidedLocalConsent)
    && assets.length === 1
    && selectedScopeAssets.length === 1
  ) || (environmentRoute && environmentReadyAssetIds.size > 0);
  const compactGuidedReview = focusedGuidedReview && !showCompletedSetup;
  const requiresAuthorizationReference = externalActivity === "active_external" && !guidedWebsiteQuickProfile;
  const quickProfileOrigin = guidedWebsiteQuickProfile && selectedWebsiteService && externalTarget
    ? websiteQuickOrigin(externalTarget, selectedWebsiteService.protocol, selectedWebsiteService.port)
    : undefined;
  const effectiveScopeConfirmation = scopeConfirmation.trim()
    || (guidedWebsiteQuickProfile
      ? text(pageCopy.websiteQuickConfirmation, { origin: quickProfileOrigin ?? "" })
      : guidedLowImpactNetwork
        ? text(pageCopy.guidedNetworkConfirmation)
        : guidedLocalConsent
          ? text(pageCopy.guidedLocalConfirmation)
          : guidedCloudConsent
            ? text(pageCopy.guidedCloudConfirmation)
            : text(pageCopy.defaultScopeNote));
  const effectiveAllowSensitiveNetworks = allowSensitiveNetworks
    || Boolean(guidedLowImpactNetwork && selectedExternalAsset?.internetExposed === false);
  const limits = externalActivity ? rateLimits[externalActivity] : undefined;
  const externalTargetOptions = useMemo(() => {
    if (!selectedExternalAsset) return [];
    return directExternalTargetsForAsset(selectedExternalAsset);
  }, [selectedExternalAsset]);
  const parsedPorts = parsePorts(externalPorts);
  const networkScanEstimate = externalActivity === "low_impact_external" && parsedPorts
    ? estimateNetworkScanMinimum(
      externalTarget,
      parsedPorts.length,
      requestsPerSecond,
      externalConcurrency,
      externalTimeout,
    )
    : undefined;
  const networkScanDuration = networkScanEstimate
    ? durationParts(networkScanEstimate.minimumSeconds)
    : undefined;
  const networkScanConservativeDuration = networkScanEstimate
    ? durationParts(networkScanEstimate.conservativeUpperSeconds)
    : undefined;
  const networkScanCeilingDuration = networkScanEstimate
    ? durationParts(networkScanEstimate.engineCeilingSeconds)
    : undefined;
  const parsedTemplateIds = parseTemplateIds(allowedTemplateIds);
  const templateIdsValid = parsedTemplateIds.every((id) => id !== "*" && !/[\n\r\0]/.test(id));
  const templateRevisionPinned = /(?:^|@)(?:sha256:)?(?:[0-9a-f]{40}|[0-9a-f]{64})$/i.test(templateRevision.trim());
  const activeTemplateSelectionReady = guidedWebsiteQuickProfile
    ? selectedWebsiteProfile.profileId.length > 0
    : parsedTemplateIds.length > 0;
  const isDirectExternal = externalActivity === "low_impact_external" || externalActivity === "active_external";
  const directNetworkBoundaryConfirmed = selectedExternalAsset?.internetExposed === true
    || (selectedExternalAsset?.internetExposed === false && effectiveAllowSensitiveNetworks);
  const externalScopeReady = !externalActivity || Boolean(
    selectedExternalAsset
    && externalTarget
    && externalTargetOptions.includes(externalTarget)
    && effectiveScopeConfirmation
    && (externalActivity !== "active_external" || guidedWebsiteQuickProfile || scopeConfirmation.trim().length >= 8)
    && (externalActivity !== "active_external" || templateRevisionPinned)
    && parsedPorts
    && (!isDirectExternal || (parsedPorts.length > 0 && directNetworkBoundaryConfirmed))
    && templateIdsValid
    && (externalActivity !== "active_external" || activeTemplateSelectionReady)
    && requestsPerSecond >= 1
    && limits
    && requestsPerSecond <= limits.rate
    && externalConcurrency >= 1
    && externalConcurrency <= limits.concurrency
    && externalTimeout >= 1
    && externalTimeout <= limits.timeout
  );

  useEffect(() => {
    if (!externalTargetOptions.includes(externalTarget)) setExternalTarget(externalTargetOptions[0] ?? "");
  }, [externalTarget, externalTargetOptions]);

  useEffect(() => {
    const service = selectedExternalAsset?.declaredWebService;
    if (service) {
      setExternalProtocol(service.protocol);
      setExternalPorts(String(service.port));
      return;
    }
    if (assessmentIntent === "external_ip_or_domain" || assessmentIntent === "internal_it_environment") {
      const preset = recommendedGuidedNetworkPreset(
        assessmentIntent,
        selectedExternalAsset?.type,
        externalTarget,
      );
      setExternalProtocol(preset.protocol);
      setExternalPorts(preset.ports.join(", "));
      return;
    }
    setExternalProtocol("https");
    setExternalPorts("443");
  }, [
    assessmentIntent,
    externalTarget,
    selectedExternalAsset?.id,
    selectedExternalAsset?.type,
    selectedExternalAsset?.declaredWebService?.port,
    selectedExternalAsset?.declaredWebService?.protocol,
  ]);

  useEffect(() => {
    setShowAdvancedExternalSettings(false);
  }, [externalActivity, selectedExternalAsset?.id]);

  useEffect(() => {
    setWebsiteScanProfile("quick");
  }, [caseId]);

  useEffect(() => {
    setEnvironmentNetworkConfirmed(false);
  }, [websiteScanProfile]);

  useEffect(() => {
    if (!externalActivity || !limits) return;
    if (guidedWebsiteQuickProfile) {
      setRequestsPerSecond(selectedWebsiteProfile.ratePolicy.requestsPerSecond);
      setExternalConcurrency(selectedWebsiteProfile.ratePolicy.concurrency);
      setExternalTimeout(selectedWebsiteProfile.ratePolicy.timeoutSeconds);
      setTemplateRevision(selectedWebsiteProfile.templateRevision);
      setAllowedTemplateIds(selectedWebsiteProfile.allowedTemplateIds.join("\n"));
      return;
    }
    if (guidedLowImpactNetwork) {
      const policy = recommendedGuidedLowImpactRatePolicy();
      setRequestsPerSecond(policy.requestsPerSecond);
      setExternalConcurrency(policy.concurrency);
      setExternalTimeout(policy.timeoutSeconds);
      return;
    }
    // Switching from the quick low-impact preset to a stricter activity must
    // never leave invalid values hidden inside the collapsed advanced panel.
    setRequestsPerSecond((current) => Math.max(1, Math.min(current, limits.rate)));
    setExternalConcurrency((current) => Math.max(1, Math.min(current, limits.concurrency)));
    setExternalTimeout((current) => Math.max(1, Math.min(current, limits.timeout)));
  }, [caseId, externalActivity, guidedLowImpactNetwork, guidedWebsiteQuickProfile, limits, selectedExternalAsset?.id, selectedWebsiteProfile]);

  const resetScopeForm = () => {
    setSelectedAssets([]);
    setScopeModes([]);
    setScopeConfirmation("");
    setOwnershipConfirmed(false);
    setExternalTarget("");
    setExternalPorts("443");
    setExternalProtocol("https");
    setRequestsPerSecond(1);
    setExternalConcurrency(1);
    setExternalTimeout(60);
    setTemplateRevision(websiteQuickProfile.templateRevision);
    setAllowedTemplateIds("");
    setAllowSensitiveNetworks(false);
    setEnvironmentNetworkConfirmed(false);
    setShowAdvancedExternalSettings(false);
  };

  useEffect(() => {
    resetScopeForm();
    setShowCompletedSetup(false);
    setShowSourceForm(false);
    setShowProviderSetup(guidedCloudRoute);
    setShowWorkspaceForm(Boolean(guidedLocalProfile));
    setSourceSetupOpen(sourceSetupStartsOpen);
    setProviderConnection(undefined);
    setProviderCleanupNeedsAttention(false);
    if (guidedLocalProfile) {
      setWorkspaceInputProfile(guidedLocalProfile);
      setWorkspaceLabel(text(guidedLocalInput?.label ?? localInputDefinitions[guidedLocalProfile].label));
      setSelectedWorkspacePath("");
      setWorkspaceFormError(undefined);
    }
  }, [caseId, assessmentIntent]);

  useEffect(() => {
    if (!focusSetup) return undefined;
    setSourceSetupOpen(true);
    setShowProviderSetup(focusSetup === "provider");
    setShowSourceForm(focusSetup === "source");
    setShowWorkspaceForm(focusSetup === "workspace");
    const targetId = focusSetup === "provider"
      ? "coverage-cloud-connection"
      : focusSetup === "source"
        ? "source-snapshot-form"
        : "workspace-snapshot-form";
    const frame = window.requestAnimationFrame(() => {
      document.getElementById(targetId)?.scrollIntoView({ block: "start" });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [caseId, focusSetup]);

  useEffect(() => {
    if (providerCleanupNeedsAttention) setShowProviderSetup(true);
  }, [providerCleanupNeedsAttention]);

  const reviewProviderCleanup = () => {
    setShowCompletedSetup(true);
    setSourceSetupOpen(true);
    setShowProviderSetup(true);
    window.requestAnimationFrame(() => {
      const cleanupTarget = document.getElementById("provider-cleanup-attention");
      cleanupTarget?.focus();
      (cleanupTarget ?? document.getElementById("coverage-cloud-connection"))?.scrollIntoView({ block: "start" });
    });
  };

  useEffect(() => {
    const asset = guidedSelectableAsset;
    if (!asset) return;
    setSelectedAssets((current) => {
      if (current.length > 0) return current;
      setScopeModes(
        assessmentIntent === "deployed_website" && Boolean(asset.declaredWebService)
          ? ["active_external"]
          : suggestedModesForAsset(requestedActivities, asset),
      );
      if (guidedLocalProfile || guidedCloudRoute) {
        window.requestAnimationFrame(() => scrollToCoverageStep("coverage-step-3"));
      }
      return [asset.id];
    });
  }, [caseId, assessmentIntent, guidedCloudRoute, guidedLocalProfile, guidedSelectableAsset, requestedActivities]);

  const environmentReadyAssetKey = [...environmentReadyAssetIds].join("\0");
  useEffect(() => {
    if (!environmentRoute) return;
    setSelectedAssets([...environmentReadyAssetIds]);
    setScopeModes([]);
    setScopeConfirmation("");
    setOwnershipConfirmed(false);
    setEnvironmentNetworkConfirmed(false);
  }, [caseId, environmentReadyAssetKey, environmentRoute]);

  const toggleEnvironmentAsset = (assetId: string) => {
    if (!environmentReadyAssetIds.has(assetId)) return;
    if (environmentNetworkAssetIds.has(assetId)) setEnvironmentNetworkConfirmed(false);
    setSelectedAssets((current) => current.includes(assetId)
      ? current.filter((id) => id !== assetId)
      : [...current, assetId]);
  };

  const toggleAsset = (assetId: string) => {
    setSelectedAssets((current) => {
      const removing = current.includes(assetId);
      const next = removing ? current.filter((id) => id !== assetId) : [...current, assetId];
      const selected = assets.filter((asset) => next.includes(asset.id));
      const firstSelected = selected[0];
      const common = !firstSelected
        ? []
        : permittedModes(firstSelected).filter((mode) => selected.every((asset) => permittedModes(asset).includes(mode)));
      setScopeModes((modes) => (
        !removing && current.length === 0 && firstSelected
          ? suggestedModesForAsset(requestedActivities, firstSelected).filter((mode) => common.includes(mode))
          : modes.filter((mode) => common.includes(mode))
      ));
      if (next.length === 0) {
        setScopeConfirmation("");
        setOwnershipConfirmed(false);
      } else if (!removing && current.length === 0) {
        window.requestAnimationFrame(() => scrollToCoverageStep("coverage-step-3"));
      }
      return next;
    });
  };

  const toggleScopeMode = (mode: ScopeMode) => {
    setScopeModes((current) => {
      if (externalActivities[mode]) return current.includes(mode) ? [] : [mode];
      return current.includes(mode) ? current.filter((item) => item !== mode) : [...current, mode];
    });
  };

  const startScan = async () => {
    if (selectedAssets.length === 0 || scopeModes.length === 0 || (!conciseGuidedConsent && !ownershipConfirmed)) return;
    if (requiresAuthorizationReference && !scopeConfirmation.trim()) return;
    if (!externalScopeReady || mcpSelectionRequired) return;
    // Never let an empty focused selection become the generic default engine plan.
    if (incidentFocus && (!guidedLocalConsent || !guidedLocalEngineIds?.length
      || selectedScopeAssets.some((asset) => localEngineIdsForAsset(asset).length === 0))) return;
    const externalScope: ExternalScopeRequest | undefined = externalActivity && parsedPorts ? {
      target: externalTarget,
      ports: parsedPorts,
      protocol: externalProtocol,
      activity: externalActivity,
      ratePolicy: {
        requestsPerSecond: guidedWebsiteQuickProfile ? selectedWebsiteProfile.ratePolicy.requestsPerSecond : requestsPerSecond,
        concurrency: guidedWebsiteQuickProfile ? selectedWebsiteProfile.ratePolicy.concurrency : externalConcurrency,
        timeoutSeconds: guidedWebsiteQuickProfile ? selectedWebsiteProfile.ratePolicy.timeoutSeconds : externalTimeout,
      },
      templatePolicy: {
        revision: externalActivity === "active_external" ? guidedWebsiteQuickProfile ? selectedWebsiteProfile.templateRevision : templateRevision.trim() : "not_applicable",
        ...(externalActivity === "active_external" && guidedWebsiteQuickProfile
          ? { profileId: selectedWebsiteProfile.profileId }
          : {}),
        allowedTemplateIds: externalActivity === "active_external" && !guidedWebsiteQuickProfile
          ? parsedTemplateIds
          : [],
        allowHeadless: false,
        allowOutOfBand: false,
        allowFuzzing: false,
        allowFileUpload: false,
        allowDenialOfService: false,
        allowCredentialAttacks: false,
      },
      assertedAuthority: effectiveScopeConfirmation,
      allowSensitiveNetworks: effectiveAllowSensitiveNetworks,
    } : undefined;
    const started = await onStartScan(
      selectedAssets,
      scopeModes,
      effectiveScopeConfirmation,
      externalScope,
      guidedWebsiteQuickProfile
        ? [...selectedWebsiteProfile.engineIds]
        : guidedLocalEngineIds,
      ...(incidentFocus ? [INCIDENT_FOCUS_ID] as [string] : [] as []),
    );
    if (started) resetScopeForm();
  };

  const startEnvironmentScan = async () => {
    if (!environmentRoute || selectedEnvironmentAssetCount === 0) return;
    if (selectedEnvironmentNetworkAssets.length > 0 && !environmentNetworkConfirmed) return;

    const authorizations: Array<Omit<ScopeApprovalInput, "caseId">> = [];
    const routes = new Map<string, string[]>();
    const addEngineRoute = (engineId: string, assetId: string) => {
      if (incidentFocus && selectIncidentFocusEngines([engineId]).length === 0) return;
      const routedAssetIds = routes.get(engineId) ?? [];
      if (!routedAssetIds.includes(assetId)) routedAssetIds.push(assetId);
      routes.set(engineId, routedAssetIds);
    };

    for (const asset of selectedEnvironmentLocalAssets) {
      const profile = asset.localInputProfile;
      if (!profile) continue;
      authorizations.push({
        assetIds: [asset.id],
        modes: ["local_artifact"],
        confirmation: text(pageCopy.guidedLocalConfirmation),
      });
      for (const engineId of localEngineIdsForAsset(asset)) addEngineRoute(engineId, asset.id);
    }

    for (const { asset, target, origin, ports, profile } of selectedEnvironmentHostAssets) {
      const confirmation = text(pageCopy.environmentHostConfirmation, { origin });
      authorizations.push({
        assetIds: [asset.id],
        modes: ["active_external"],
        confirmation,
        externalScope: {
          target,
          ports: [...ports],
          protocol: "tcp",
          activity: "active_external",
          ratePolicy: { ...profile.ratePolicy },
          templatePolicy: {
            revision: profile.templateRevision,
            profileId: profile.profileId,
            allowedTemplateIds: [],
            allowHeadless: false,
            allowOutOfBand: false,
            allowFuzzing: false,
            allowFileUpload: false,
            allowDenialOfService: false,
            allowCredentialAttacks: false,
          },
          assertedAuthority: confirmation,
          allowSensitiveNetworks: asset.internetExposed === false,
        },
      });
      for (const engineId of profile.engineIds) addEngineRoute(engineId, asset.id);
    }

    for (const { asset, target, origin } of selectedEnvironmentWebsiteAssets) {
      const service = asset.declaredWebService;
      if (!service) continue;
      const confirmation = text(pageCopy.websiteQuickConfirmation, { origin });
      authorizations.push({
        assetIds: [asset.id],
        modes: ["active_external"],
        confirmation,
        externalScope: {
          target,
          ports: [service.port],
          protocol: service.protocol,
          activity: "active_external",
          ratePolicy: { ...selectedWebsiteProfile.ratePolicy },
          templatePolicy: {
            revision: selectedWebsiteProfile.templateRevision,
            profileId: selectedWebsiteProfile.profileId,
            allowedTemplateIds: [...selectedWebsiteProfile.allowedTemplateIds],
            allowHeadless: false,
            allowOutOfBand: false,
            allowFuzzing: false,
            allowFileUpload: false,
            allowDenialOfService: false,
            allowCredentialAttacks: false,
          },
          assertedAuthority: confirmation,
          allowSensitiveNetworks: asset.internetExposed === false,
        },
      });
      for (const engineId of selectedWebsiteProfile.engineIds) addEngineRoute(engineId, asset.id);
    }

    for (const { asset, target, origin, profile } of selectedEnvironmentEndpointAssets) {
      const service = asset.declaredNetworkService;
      if (!service || service.protocol !== "tcp") continue;
      const confirmation = text(pageCopy.environmentEndpointConfirmation, {
        origin,
        service: text(profile.label),
      });
      authorizations.push({
        assetIds: [asset.id],
        modes: ["active_external"],
        confirmation,
        externalScope: {
          target,
          ports: [service.port],
          protocol: "tcp",
          activity: "active_external",
          ratePolicy: { ...profile.ratePolicy },
          templatePolicy: {
            revision: profile.templateRevision,
            allowedTemplateIds: [...profile.allowedTemplateIds],
            allowHeadless: false,
            allowOutOfBand: false,
            allowFuzzing: false,
            allowFileUpload: false,
            allowDenialOfService: false,
            allowCredentialAttacks: false,
          },
          assertedAuthority: confirmation,
          allowSensitiveNetworks: asset.internetExposed === false,
        },
      });
      for (const engineId of profile.engineIds) addEngineRoute(engineId, asset.id);
    }

    for (const { asset, target, origin, profile } of selectedEnvironmentDeviceAssets) {
      const service = asset.declaredWebService;
      if (!service || service.protocol !== "https") continue;
      const confirmation = text(pageCopy.environmentDeviceConfirmation, { origin });
      authorizations.push({
        assetIds: [asset.id],
        modes: ["active_external"],
        confirmation,
        externalScope: {
          target,
          ports: [service.port],
          protocol: "https",
          activity: "active_external",
          ratePolicy: { ...profile.ratePolicy },
          templatePolicy: {
            revision: profile.templateRevision,
            allowedTemplateIds: [...profile.allowedTemplateIds],
            allowHeadless: false,
            allowOutOfBand: false,
            allowFuzzing: false,
            allowFileUpload: false,
            allowDenialOfService: false,
            allowCredentialAttacks: false,
          },
          assertedAuthority: confirmation,
          allowSensitiveNetworks: asset.internetExposed === false,
        },
      });
      for (const engineId of profile.engineIds) addEngineRoute(engineId, asset.id);
    }

    if (routes.size === 0 || authorizations.length === 0) return;
    const started = await onStartEnvironmentScan(
      authorizations,
      [...routes].map(([engineId, assetIds]) => ({ engineId, assetIds })),
      ...(incidentFocus ? [INCIDENT_FOCUS_ID] as [string] : [] as []),
    );
    if (started) resetScopeForm();
  };

  const changeSourceKind = (nextKind: SourceKind) => {
    const nextSource = sourceDefinitions[nextKind];
    setSourceKind(nextKind);
    setProfile(nextSource.profiles[0]);
    setSourceLabel(text(nextSource.label));
    setSelectedPath("");
    setSourceFormError(undefined);
  };

  const chooseSnapshot = async () => {
    setChoosingSnapshot(true);
    setSourceFormError(undefined);
    try {
      const path = await onChooseSnapshot();
      if (!path) return;
      if (!path.toLocaleLowerCase("en-US").endsWith(".json")) {
        setSourceFormError(pageCopy.sourceErrorJson);
        return;
      }
      setSelectedPath(path);
    } catch {
      setSourceFormError(pageCopy.sourceErrorPicker);
    } finally {
      setChoosingSnapshot(false);
    }
  };

  const connectSnapshot = async (event: FormEvent) => {
    event.preventDefault();
    if (!sourceLabel.trim()) {
      setSourceFormError(pageCopy.sourceErrorLabel);
      return;
    }
    if (!selectedPath) {
      setSourceFormError(pageCopy.sourceErrorPath);
      return;
    }
    setSourceFormError(undefined);
    await onConnectSourceSnapshot({
      caseId,
      sourceKind,
      label: sourceLabel.trim(),
      profile,
      selectedPath,
    });
  };

  const chooseWorkspace = async () => {
    setChoosingWorkspace(true);
    setWorkspaceFormError(undefined);
    try {
      const path = await onChooseWorkspace();
      if (path) setSelectedWorkspacePath(path);
    } catch {
      setWorkspaceFormError(pageCopy.workspaceErrorPicker);
    } finally {
      setChoosingWorkspace(false);
    }
  };

  const attachWorkspace = async (event: FormEvent) => {
    event.preventDefault();
    if (!workspaceLabel.trim()) {
      setWorkspaceFormError(pageCopy.workspaceErrorLabel);
      return;
    }
    if (!selectedWorkspacePath) {
      setWorkspaceFormError(pageCopy.workspaceErrorPath);
      return;
    }
    setWorkspaceFormError(undefined);
    const attached = await onAttachWorkspaceSnapshot({
      caseId,
      label: workspaceLabel.trim(),
      selectedPath: selectedWorkspacePath,
      inputProfile: workspaceInputProfile,
    });
    if (!attached) setWorkspaceFormError(pageCopy.workspaceErrorCopy);
  };

  const providerInputCard = (
    <article key="provider" className={showProviderSetup ? "coverage-input-card coverage-input-card--active" : "coverage-input-card"}>
      <span><Icon name="database" size={20} /></span>
      <div><strong>{text(pageCopy.providerTitle)}</strong><p>{text(pageCopy.providerBody)}</p></div>
      <button className="button button--secondary button--small" type="button" disabled={busy} aria-expanded={showProviderSetup} aria-controls="coverage-cloud-connection" onClick={() => { setShowProviderSetup((value) => !value); setShowSourceForm(false); setShowWorkspaceForm(false); }}>
        {text(showProviderSetup ? pageCopy.providerClose : pageCopy.providerOpen)}
      </button>
    </article>
  );
  const sourceInputCard = (
    <article key="snapshot" className={showSourceForm ? "coverage-input-card coverage-input-card--active" : "coverage-input-card"}>
      <span><Icon name="file" size={20} /></span>
      <div><strong>{text(pageCopy.snapshotTitle)}</strong><p>{text(pageCopy.snapshotBody)}</p></div>
      <button className="button button--secondary button--small" type="button" disabled={busy} aria-expanded={showSourceForm} aria-controls="source-snapshot-form" onClick={() => { setShowSourceForm((value) => !value); setShowWorkspaceForm(false); setShowProviderSetup(false); }}>
        {text(showSourceForm ? pageCopy.snapshotClose : pageCopy.snapshotOpen)}
      </button>
    </article>
  );
  const workspaceInputCard = (
    <article key="workspace" className={showWorkspaceForm ? "coverage-input-card coverage-input-card--active" : "coverage-input-card"}>
      <span><Icon name="database" size={20} /></span>
      <div>
        <strong>{text(guidedLocalInput ? guidedLocalInput.label : pageCopy.workspaceTitle)}</strong>
        <p>{text(guidedLocalInput ? guidedLocalInput.detail : pageCopy.workspaceBody)}</p>
      </div>
      <button className="button button--secondary button--small" type="button" disabled={busy} aria-expanded={showWorkspaceForm} aria-controls="workspace-snapshot-form" onClick={() => { setShowWorkspaceForm((value) => !value); setShowSourceForm(false); setShowProviderSetup(false); }}>
        {text(guidedLocalProfile
          ? showWorkspaceForm ? pageCopy.guidedWorkspaceClose : pageCopy.guidedWorkspaceOpen
          : showWorkspaceForm ? pageCopy.workspaceClose : pageCopy.workspaceOpen)}
      </button>
    </article>
  );
  const knownTargetsInputCard = (
    <article key="known-targets" className="coverage-input-card">
      <span><Icon name="coverage" size={20} /></span>
      <div><strong>{text(pageCopy.knownTargetsTitle)}</strong><p>{text(pageCopy.knownTargetsBody)}</p></div>
      {nativeMode && (
        <button className="button button--secondary button--small" type="button" disabled={busy} onClick={() => void onStartDiscovery()}>
          {busy ? text(pageCopy.refreshing) : text(pageCopy.refresh)}
        </button>
      )}
    </article>
  );
  const websiteProfileSelect = zapRunnable ? (
    <label className="field">
      <span>{text(pageCopy.websiteProfileLabel)}</span>
      <select data-website-profile disabled={busy} value={websiteScanProfile}
        onChange={(event) => setWebsiteScanProfile(event.target.value === "passive" ? "passive" : "quick")}>
        <option value="quick">{text(pageCopy.websiteProfileQuick)}</option>
        <option value="passive">{text(pageCopy.websiteProfilePassive)}</option>
      </select>
      {passiveWebsiteSelected && <small>{text(pageCopy.websitePassiveBounds)}</small>}
    </label>
  ) : null;
  const websiteProfileChooser = zapRunnable ? (
    <details className="coverage-form-technical coverage-scan-advanced">
      <summary>{text(pageCopy.advancedScanSettings)}</summary>
      {websiteProfileSelect}
    </details>
  ) : null;
  const guidedNetworkInputCard = (
    <article className="coverage-input-card coverage-input-card--active">
      <span><Icon name="coverage" size={20} /></span>
      <div><strong>{text(pageCopy.networkReadyTitle)}</strong><p>{text(
        assessmentIntent === "deployed_website"
          ? passiveWebsiteSelected ? pageCopy.websitePassiveReadyBody : pageCopy.websiteQuickReadyBody
          : pageCopy.networkReadyBody,
      )}</p></div>
      <button className="button button--primary button--small" type="button" disabled={busy} onClick={() => scrollToCoverageStep("coverage-step-3")}>
        {text(pageCopy.networkReadyAction)}
      </button>
    </article>
  );
  const scopeModeChooser = (
    <fieldset className="scope-mode-fieldset">
      <legend>{text(pageCopy.allowedQuestion)}</legend>
      <div className="scope-mode-grid">
        {availableScopeModes.map((mode) => {
          const unavailableExternalMode = Boolean(
            externalActivities[mode]
            && selectedExternalAsset?.internetExposed === undefined,
          );
          return (
            <label key={mode} className={`${scopeModes.includes(mode) ? "scope-mode-card scope-mode-card--active" : "scope-mode-card"}${unavailableExternalMode ? " scope-mode-card--disabled" : ""}`}>
              <input
                type={externalActivities[mode] ? "radio" : "checkbox"}
                name={externalActivities[mode] ? "external-activity" : undefined}
                checked={scopeModes.includes(mode)}
                disabled={busy || unavailableExternalMode}
                onChange={() => toggleScopeMode(mode)}
              />
              <span><strong>{text(scopeModeLabels[mode].label)}</strong><small>{text(scopeModeLabels[mode].detail)}</small></span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );

  return (
    <div className="page page--coverage">
      <PageHeader
        eyebrow={text(pageCopy.headerEyebrow)}
        title={text(compactGuidedReview ? pageCopy.focusedReviewTitle : pageCopy.headerTitle)}
        description={compactGuidedReview ? text(pageCopy.allowDescription) : undefined}
        actions={focusedGuidedReview ? (
          <button className="button button--secondary" type="button" disabled={busy} onClick={() => setShowCompletedSetup((current) => !current)}>
            <Icon name={showCompletedSetup ? "check" : "settings"} size={18} />
            {text(showCompletedSetup ? pageCopy.backToReview : pageCopy.editInputs)}
          </button>
        ) : nativeMode && guidedCoverageRoute.kind === "none" ? (
          <button className="button button--primary" type="button" disabled={busy} onClick={() => void onStartDiscovery()}>
            <Icon name="refresh" size={18} />
            {busy ? text(pageCopy.refreshing) : text(pageCopy.refresh)}
          </button>
        ) : undefined}
      />

      {runtimeSetupNotice}

      {providerCleanupNeedsAttention && (
        <InlineNotice tone="warning" title={text(pageCopy.cleanupAttentionTitle)} announce>
          <p>{text(pageCopy.cleanupAttentionBody)}</p>
          <button className="button button--secondary button--small" type="button" onClick={reviewProviderCleanup}>
            {text(pageCopy.reviewCleanup)}
          </button>
        </InlineNotice>
      )}

      <section id="coverage-step-1" className="section-block coverage-step-section" hidden={compactGuidedReview}>
        <div className="section-heading">
          <h2>{text(pageCopy.addTitle)}</h2>
          {!hasExistingInputs && <p>{text(pageCopy.addDescription)}</p>}
        </div>

        <details
          className="coverage-source-setup"
          open={sourceSetupOpen}
          onToggle={(event) => setSourceSetupOpen(event.currentTarget.open)}
        >
          <summary>{text(providerCleanupNeedsAttention ? pageCopy.sourceSetupCleanupSummary : pageCopy.sourceSetupSummary)}</summary>
          <div className="coverage-source-setup__body">
        {assessmentIntent ? (
          <>
            <div className="coverage-input-grid coverage-input-grid--guided">
              {guidedNetworkRoute
                ? guidedNetworkInputCard
                : guidedCloudRoute
                  ? providerInputCard
                  : workspaceInputCard}
            </div>
            <details className="coverage-situation-details coverage-advanced-inputs">
              <summary>{text(pageCopy.otherInputsSummary)}</summary>
              <p>{text(pageCopy.otherInputsBody)}</p>
              <div className="coverage-input-grid">
                {!guidedCloudRoute && providerInputCard}
                {sourceInputCard}
                {!guidedLocalProfile && workspaceInputCard}
                {!guidedNetworkRoute && !guidedCloudRoute && knownTargetsInputCard}
              </div>
            </details>
          </>
        ) : (
          <div className="coverage-input-grid">
            {providerInputCard}
            {sourceInputCard}
            {workspaceInputCard}
            {knownTargetsInputCard}
          </div>
        )}

        <details className="coverage-situation-details">
          <summary>{text(pageCopy.selectDoesNotAuthorizeTitle)}</summary>
          <p>{text(pageCopy.selectDoesNotAuthorizeBody)}</p>
        </details>

        <div id="coverage-cloud-connection" className="coverage-provider-slot" hidden={!showProviderSetup}>
            <ProviderAuthorizationPanel
              key={caseId}
              caseId={caseId}
              sources={sources}
              engineManifests={engineManifests}
              nativeMode={nativeMode}
              disabled={busy}
              findingAssets={discoveryBusy}
              onAuthorizationChanged={onAuthorizationChanged}
              onFindAssets={onStartDiscovery}
              onConnectionStateChanged={setProviderConnection}
              onCleanupAttentionChanged={setProviderCleanupNeedsAttention}
            />
        </div>

      {showSourceForm && (
        <form id="source-snapshot-form" className="source-connect-panel" aria-labelledby="source-connect-title" onSubmit={connectSnapshot}>
          <div className="section-heading">
            <p className="eyebrow">{text(pageCopy.sourceEyebrow)}</p>
            <h2 id="source-connect-title">{text(pageCopy.sourceTitle)}</h2>
            <p>{text(pageCopy.sourceIntro)}</p>
          </div>

          <InlineNotice tone="warning" title={text(pageCopy.noSecretsSnapshotTitle)}>
            <p>{text(pageCopy.noSecretsSnapshotBody)}</p>
          </InlineNotice>

          {!nativeMode && (
            <InlineNotice tone="info" title={text(pageCopy.demoFileTitle)}>
              <p>{text(pageCopy.demoFileBody)}</p>
            </InlineNotice>
          )}

          <div className="form-grid form-grid--two">
            <label className="field">
              <span>{text(pageCopy.sourceKind)}</span>
              <select value={sourceKind} onChange={(event) => changeSourceKind(event.target.value as SourceKind)}>
                {allSourceKinds.map((kind) => (
                  <option key={kind} value={kind}>{text(sourceDefinitions[kind].label)}</option>
                ))}
              </select>
              <small>{text(selectedSource.description)}</small>
            </label>
            <label className="field">
              <span>{text(pageCopy.sourceLabel)}</span>
              <input required maxLength={120} value={sourceLabel} onChange={(event) => setSourceLabel(event.target.value)} placeholder={text(pageCopy.sourceLabelPlaceholder)} />
              <small>{text(pageCopy.sourceLabelHelp)}</small>
            </label>
            <div className="field">
              <span id="snapshot-file-label">{text(pageCopy.jsonSnapshot)}</span>
              <button className="snapshot-picker" type="button" disabled={!nativeMode || busy || choosingSnapshot} aria-describedby="snapshot-file-help" onClick={() => void chooseSnapshot()}>
                <Icon name="file" size={18} />
                <span>{selectedPath
                  ? localPathDisplayName(selectedPath, text(pageCopy.fileFallback))
                  : choosingSnapshot
                    ? text(pageCopy.choosingPicker)
                    : text(pageCopy.chooseJson)}</span>
                <Icon name="chevron" size={16} />
              </button>
              <small id="snapshot-file-help">{text(pageCopy.snapshotPathHelp)}</small>
            </div>
          </div>

          <details className="coverage-form-technical">
            <summary>{text(pageCopy.inputTechnicalSummary)}</summary>
            <label className="field">
              <span>{text(pageCopy.snapshotFormat)}</span>
              <select value={profile} onChange={(event) => setProfile(event.target.value as SnapshotParserProfile)}>
                {selectedSource.profiles.map((parserProfile) => (
                  <option key={parserProfile} value={parserProfile}>{parserProfileLabels[parserProfile]}</option>
                ))}
              </select>
              <small>{text(pageCopy.snapshotFormatHelp)}</small>
            </label>
          </details>

          {sourceFormError && <p className="form-error" role="alert"><Icon name="warning" size={16} />{text(sourceFormError)}</p>}

          <div className="form-actions">
            <p><Icon name="lock" size={16} /> {text(pageCopy.sourceAfterHelp)}</p>
            <button className="button button--primary" type="submit" disabled={!nativeMode || busy || choosingSnapshot || !sourceLabel.trim() || !selectedPath}>
              {busy ? text(pageCopy.connectingSnapshot) : text(pageCopy.connectSnapshot)}
              <Icon name="arrow" size={17} />
            </button>
          </div>
        </form>
      )}

      {showWorkspaceForm && (
        <form id="workspace-snapshot-form" className="source-connect-panel" aria-labelledby="workspace-snapshot-title" onSubmit={attachWorkspace}>
          <div className="section-heading">
            <p className="eyebrow">{text(pageCopy.workspaceEyebrow)}</p>
            <h2 id="workspace-snapshot-title">{text(guidedLocalProfile ? selectedLocalInput.formTitle : pageCopy.workspaceFormTitle)}</h2>
            <p>{text(guidedLocalProfile ? selectedLocalInput.formIntro : pageCopy.workspaceIntro)}</p>
          </div>

          <InlineNotice tone="warning" title={text(guidedLocalProfile ? selectedLocalInput.cautionTitle : pageCopy.gitWarningTitle)}>
            <p>{text(guidedLocalProfile ? selectedLocalInput.cautionBody : pageCopy.gitWarningBody)}</p>
          </InlineNotice>

          {!nativeMode && (
            <InlineNotice tone="info" title={text(pageCopy.demoFolderTitle)}>
              <p>{text(pageCopy.demoFolderBody)}</p>
            </InlineNotice>
          )}

          <div className="form-grid form-grid--two">
            {!guidedLocalProfile && <label className="field">
              <span>{text(pageCopy.inputType)}</span>
              <select
                value={workspaceInputProfile}
                onChange={(event) => {
                  const next = event.target.value as LocalInputProfile;
                  setWorkspaceInputProfile(next);
                  setSelectedWorkspacePath("");
                  setWorkspaceFormError(undefined);
                }}
              >
                {(Object.keys(localInputDefinitions) as LocalInputProfile[]).map((inputProfile) => (
                  <option key={inputProfile} value={inputProfile}>{text(localInputDefinitions[inputProfile].label)}</option>
                ))}
              </select>
              <small>{text(localInputDefinitions[workspaceInputProfile].detail)}</small>
            </label>}
            <label className="field">
              <span>{text(pageCopy.localLabel)}</span>
              <input required maxLength={120} value={workspaceLabel} onChange={(event) => setWorkspaceLabel(event.target.value)} placeholder={text(pageCopy.localLabelPlaceholder)} />
              <small>{text(pageCopy.localLabelHelp)}</small>
            </label>
            <div className="field">
              <span id="workspace-directory-label">{text(guidedLocalProfile ? selectedLocalInput.directoryLabel : pageCopy.localDirectory)}</span>
              <button className="snapshot-picker" type="button" disabled={!nativeMode || busy || choosingWorkspace} aria-describedby="workspace-directory-help" onClick={() => void chooseWorkspace()}>
                <Icon name="database" size={18} />
                <span>{selectedWorkspacePath
                  ? localPathDisplayName(selectedWorkspacePath, text(pageCopy.folderFallback))
                  : choosingWorkspace
                    ? text(pageCopy.choosingPicker)
                    : text(selectedLocalInput.selection)}</span>
                <Icon name="chevron" size={16} />
              </button>
              <small id="workspace-directory-help">{text(pageCopy.localPathHelp)}</small>
            </div>
          </div>

          <details className="coverage-form-technical">
            <summary>{text(pageCopy.inputTechnicalSummary)}</summary>
            {guidedLocalProfile && (
              <label className="field">
                <span>{text(pageCopy.advancedLocalInputSummary)}</span>
                <select
                  value={workspaceInputProfile}
                  onChange={(event) => {
                    const next = event.target.value as LocalInputProfile;
                    setWorkspaceInputProfile(next);
                    setWorkspaceLabel(text(
                      next === guidedLocalProfile && guidedLocalInput
                        ? guidedLocalInput.label
                        : localInputDefinitions[next].label,
                    ));
                    setSelectedWorkspacePath("");
                    setWorkspaceFormError(undefined);
                  }}
                >
                  {(Object.keys(localInputDefinitions) as LocalInputProfile[]).map((inputProfile) => (
                    <option key={inputProfile} value={inputProfile}>{text(localInputDefinitions[inputProfile].label)}</option>
                  ))}
                </select>
                <small>{text(pageCopy.advancedLocalInputHelp)}</small>
              </label>
            )}
            {workspaceInputProfile === "repository_working_tree" && <p>{text(pageCopy.gitTechnicalBody)}</p>}
            <p>{text(localInputDefinitions[workspaceInputProfile].technical)}</p>
            <p><strong>{text(pageCopy.localSelectionPermissionTitle)}</strong></p>
            <p>{text(pageCopy.localSelectionPermissionBody)}</p>
            <p>{text(pageCopy.localEngineDetail, { engines: localInputEngines[workspaceInputProfile] })}</p>
            <code>{workspaceInputProfile}</code>
          </details>

          {workspaceFormError && <p className="form-error" role="alert"><Icon name="warning" size={16} />{text(workspaceFormError)}</p>}

          <div className="form-actions">
            {!guidedLocalProfile && <p><Icon name="lock" size={16} /> {text(pageCopy.workspaceAfterHelp)}</p>}
            <button className="button button--primary" type="submit" disabled={!nativeMode || busy || choosingWorkspace || !workspaceLabel.trim() || !selectedWorkspacePath}>
              {busy ? text(pageCopy.attachingWorkspace) : text(guidedLocalProfile ? selectedLocalInput.attachAction : pageCopy.attachWorkspace)}
              <Icon name="arrow" size={17} />
            </button>
          </div>
        </form>
      )}

          </div>
        </details>
      </section>

      {onStartModelCheck && (assessmentIntent === "ai_application" || environmentRoute)
        && engineManifests.some((engine) => engine.id === "garak" && engine.runnable === true && engine.compatibilityValid)
        && <ModelEndpointPanel key={caseId} nativeMode={nativeMode} busy={busy}
          initialInput={assets.find((asset) => asset.modelEndpoint)?.modelEndpoint} onStart={onStartModelCheck} />}

      {!compactGuidedReview && <section id="coverage-step-2" className="section-block coverage-step-section">
        <div className="section-heading coverage-step-heading">
          <h2>{text(pageCopy.seeTitle)}</h2>
        </div>

        <dl className="coverage-summary-row" aria-label={text(pageCopy.metricsLabel)}>
          <div className="coverage-summary-chip">
            <dt>{text(pageCopy.candidateAssets)}</dt>
            <dd>{formatNumber(assets.length)}</dd>
          </div>
          {scannedAssets > 0 && <div className="coverage-summary-chip coverage-summary-chip--positive">
            <dt>{text(pageCopy.scannedAssets)}</dt>
            <dd>{formatNumber(scannedAssets)}</dd>
          </div>}
          {incompleteAssets > 0 && <div className="coverage-summary-chip coverage-summary-chip--warning">
            <dt>{text(pageCopy.incompleteAssets)}</dt>
            <dd>{formatNumber(incompleteAssets)}</dd>
          </div>}
          {pendingAssets.length > 0 && <div className="coverage-summary-chip coverage-summary-chip--warning">
            <dt>{text(pageCopy.pendingAssets)}</dt>
            <dd>{formatNumber(pendingAssets.length)}</dd>
          </div>}
        </dl>

      {(unknownSourceCount > 0 || connectedNoAssetCount > 0) && (
        <div className="coverage-truth-grid">
          {unknownSourceCount > 0 && (
            <div className="coverage-truth-card coverage-truth-card--unknown">
              <Icon name="warning" size={20} />
              <div><strong>{text(pageCopy.unknownTitle, { count: formatNumber(unknownSourceCount) })}</strong><p>{text(pageCopy.unknownBody)}</p></div>
            </div>
          )}
          {connectedNoAssetCount > 0 && (
            <div className="coverage-truth-card coverage-truth-card--none">
              <Icon name="database" size={20} />
              <div><strong>{text(pageCopy.noneTitle, { count: formatNumber(connectedNoAssetCount) })}</strong><p>{text(pageCopy.noneBody)}</p></div>
            </div>
          )}
        </div>
      )}

      {coverage.length === 0 ? (
        <EmptyState icon="coverage" title={text(pageCopy.noSourcesTitle)} description={text(pageCopy.noSourcesBody)} />
      ) : (
        <details className="coverage-source-ledger page-secondary-feature">
          <summary>{text(pageCopy.sourcesTitle, { count: formatNumber(coverage.length) })}</summary>
          <div className="source-grid">
            {coverage.map((record) => {
              const meta = coverageMeta[record.state];
              const readyForFirstScan = isAwaitingFirstScan(record.state, record.scanAttempted);
              const presentationTone = readyForFirstScan ? "positive" : meta.tone;
              const connectedSource = sources.find((source) => source.kind === record.sourceKind && source.label === record.label)
                ?? sources.find((source) => source.kind === record.sourceKind);
              return (
                <article key={record.id} className={`source-card source-card--${presentationTone}`}>
                  <div className="source-card__top">
                    <span className="platform-avatar">{platformMeta[record.platform].abbreviation}</span>
                    <StatusPill label={readyForFirstScan ? text(pageCopy.readyToScan) : meta.shortLabel} tone={presentationTone} />
                  </div>
                  <h3>{record.label}</h3>
                  <p>{readyForFirstScan ? text(pageCopy.readyToScanDetail) : meta.description}</p>
                  <div className="source-card__footer">
                    <span>{text(pageCopy.assetsCount, { count: formatNumber(record.assetCount) })}</span>
                    <span>{readyForFirstScan
                      ? text(pageCopy.notScannedYet)
                      : record.lastCheckedAt
                        ? text(pageCopy.lastChecked, { date: formatDateTime(record.lastCheckedAt) })
                        : text(pageCopy.notConnected)}</span>
                  </div>
                  <details className="source-card__technical">
                    <summary>{text(pageCopy.sourceTechnical)}</summary>
                    <dl>
                      <div><dt>{text(pageCopy.sourceKindTechnical)}</dt><dd><code>{record.sourceKind}</code></dd></div>
                      <div><dt>{text(pageCopy.coverageStateTechnical)}</dt><dd><code>{record.state}</code></dd></div>
                      <div><dt>{text(pageCopy.acceptedProfiles)}</dt><dd>{sourceDefinitions[record.sourceKind].profiles.map((item) => parserProfileLabels[item]).join(", ")}</dd></div>
                      {connectedSource && <div><dt>{text(pageCopy.sourceStatusTechnical)}</dt><dd><code>{connectedSource.status}</code></dd></div>}
                      <div><dt>{text(pageCopy.rawSourceDetail)}</dt><dd>{localizedCoverageRecordDetail(record.detail, locale)}</dd></div>
                    </dl>
                  </details>
                </article>
              );
            })}
          </div>
        </details>
      )}

      <details className="coverage-technical-details">
        <summary>{text(pageCopy.coverageDetailsSummary)}</summary>
        <p>{text(pageCopy.coverageDetailsIntro)}</p>
        <button className="button button--ghost button--small" type="button" onClick={() => setFilter("all")}>
          {text(pageCopy.showAll)}
        </button>
        <div className="coverage-legend">
          {coverageStates.map((state) => {
            const meta = coverageMeta[state];
            return (
              <button
                key={state}
                type="button"
                className={filter === state ? "coverage-legend__item coverage-legend__item--active" : "coverage-legend__item"}
                onClick={() => setFilter((current) => (current === state ? "all" : state))}
                aria-pressed={filter === state}
              >
                <span className={`coverage-state-mark coverage-state-mark--${meta.tone}`} aria-hidden="true" />
                <span><strong>{meta.label}</strong><small>{meta.description}</small></span>
                <b>{formatNumber(counts[state])}</b>
              </button>
            );
          })}
        </div>
      </details>
      </section>}

      <ExternalScannerImport key={caseId} caseId={caseId} assets={assets} nativeMode={nativeMode} busy={busy}
        onImported={onAuthorizationChanged} />

      {!environmentRoute && shouldPromptForFirstAsset(pendingAssets.length, selectedAssets.length) && (
        <InlineNotice tone="warning" title={text(pageCopy.pendingNoticeTitle)} />
      )}

      <section id="coverage-step-3" className="section-block coverage-step-section">
        {!compactGuidedReview && <div className="section-heading section-heading--row">
          <div>
            <h2>{text(pageCopy.allowTitle)}</h2>
          </div>
          {selectedAssets.length > 0 && !conciseGuidedConsent && <span className="count-label">{text(pageCopy.selectedCount, { count: formatNumber(selectedAssets.length) })}</span>}
        </div>}

        {incidentFocusAvailable && (environmentRoute || Boolean(guidedLocalProfile)) && (
          <label className="toggle-row">
            <input type="checkbox" checked={incidentFocus} disabled={busy}
              onChange={(event) => { setIncidentFocus(event.target.checked); setEnvironmentNetworkConfirmed(false); setOwnershipConfirmed(false); }} />
            <span><strong>{text(pageCopy.incidentFocusTitle)}</strong>
              <small>{text(pageCopy.incidentFocusDetail)}</small></span>
          </label>
        )}

        {environmentRoute && (
          <form className="scope-confirmation-panel" onSubmit={(event) => { event.preventDefault(); void startEnvironmentScan(); }}>
            <div className="scope-confirmation-panel__heading">
              <div>
                <h3>{text(pageCopy.environmentPlanTitle)}</h3>
                <p>{text(pageCopy.environmentPlanBody)}</p>
              </div>
            </div>
            <p className="coverage-review-timing">{text(pageCopy.environmentTiming)}</p>

            {incidentFocus && incidentExcludedAssets.length > 0 && (
              <InlineNotice tone="warning" title={text(pageCopy.incidentFocusExcludedCount, { count: formatNumber(incidentExcludedAssets.length) })}>
                <ul>{incidentExcludedAssets.map((asset) => <li key={asset.id}>{asset.name}</li>)}</ul>
              </InlineNotice>
            )}

            {environmentLocalAssets.length > 0 && (
              <fieldset className="scope-mode-fieldset">
                <legend>{text(pageCopy.environmentRepositoriesTitle)}</legend>
                <p>{text(incidentFocus ? pageCopy.incidentFocusPackages : pageCopy.environmentRepositoriesBody)}</p>
                <div className="scope-mode-grid">
                  {environmentLocalAssets.map((asset) => (
                    <label key={asset.id} className={selectedAssets.includes(asset.id) && localEngineIdsForAsset(asset).length > 0 ? "scope-mode-card scope-mode-card--active" : "scope-mode-card"}>
                      <input
                        type="checkbox"
                        disabled={busy || localEngineIdsForAsset(asset).length === 0}
                        checked={selectedAssets.includes(asset.id) && localEngineIdsForAsset(asset).length > 0}
                        aria-label={text(pageCopy.chooseAsset, { name: asset.name })}
                        onChange={() => toggleEnvironmentAsset(asset.id)}
                      />
                      <span>
                        <strong>{asset.name}</strong>
                        <small>{incidentFocus ? localEngineIdsForAsset(asset).join(", ") || text(pageCopy.incidentFocusExcluded) : asset.localInputProfile ? localInputEngines[asset.localInputProfile] : ""}</small>
                      </span>
                    </label>
                  ))}
                </div>
                {!incidentFocus && agenticInventorySelection(selectedEnvironmentLocalAssets)}
              </fieldset>
            )}

            {!incidentFocus && environmentHostAssets.length > 0 && (
              <fieldset className="scope-mode-fieldset">
                <legend>{text(pageCopy.environmentHostsTitle)}</legend>
                <p>{text(pageCopy.environmentHostsBody)}</p>
                <div className="scope-mode-grid">
                  {environmentHostAssets.map(({ asset, origin, ports, profile }) => (
                    <label key={asset.id} className={selectedAssets.includes(asset.id) ? "scope-mode-card scope-mode-card--active" : "scope-mode-card"}>
                      <input
                        type="checkbox"
                        disabled={busy}
                        checked={selectedAssets.includes(asset.id)}
                        aria-label={text(pageCopy.chooseAsset, { name: asset.name })}
                        onChange={() => toggleEnvironmentAsset(asset.id)}
                      />
                      <span>
                        <strong>{asset.name}</strong>
                        <small>{text(pageCopy.environmentHostCheck, { ports: ports.join(", ") })}</small>
                      </span>
                    </label>
                  ))}
                </div>
              </fieldset>
            )}

            {!incidentFocus && environmentWebsiteAssets.length > 0 && (
              <fieldset className="scope-mode-fieldset">
                <legend>{text(pageCopy.environmentWebsitesTitle)}</legend>
                <p>{text(passiveWebsiteSelected ? pageCopy.environmentWebsitePassiveBody : pageCopy.environmentWebsitesBody)}</p>
                {websiteProfileChooser}
                <div className="scope-mode-grid">
                  {environmentWebsiteAssets.map(({ asset, origin }) => (
                    <label key={asset.id} className={selectedAssets.includes(asset.id) ? "scope-mode-card scope-mode-card--active" : "scope-mode-card"}>
                      <input
                        type="checkbox"
                        disabled={busy}
                        checked={selectedAssets.includes(asset.id)}
                        aria-label={text(pageCopy.chooseAsset, { name: origin })}
                        onChange={() => toggleEnvironmentAsset(asset.id)}
                      />
                      <span>
                        <strong>{origin}</strong>
                        <small>{text(passiveWebsiteSelected ? pageCopy.websiteProfilePassive : pageCopy.environmentWebsiteCheck)}</small>
                      </span>
                    </label>
                  ))}
                </div>
              </fieldset>
            )}

            {!incidentFocus && environmentEndpointAssets.length > 0 && (
              <fieldset className="scope-mode-fieldset">
                <legend>{text(pageCopy.environmentEndpointsTitle)}</legend>
                <p>{text(pageCopy.environmentEndpointsBody)}</p>
                <div className="scope-mode-grid">
                  {environmentEndpointAssets.map(({ asset, origin, profile }) => (
                    <label key={asset.id} className={selectedAssets.includes(asset.id) ? "scope-mode-card scope-mode-card--active" : "scope-mode-card"}>
                      <input
                        type="checkbox"
                        disabled={busy}
                        checked={selectedAssets.includes(asset.id)}
                        aria-label={text(pageCopy.chooseAsset, { name: origin })}
                        onChange={() => toggleEnvironmentAsset(asset.id)}
                      />
                      <span>
                        <strong>{origin}</strong>
                        <small>{text(profile.allowedTemplateIds.length === 1
                          ? pageCopy.environmentEndpointCheckOne
                          : pageCopy.environmentEndpointCheck, {
                          service: text(profile.label),
                          checks: formatNumber(profile.allowedTemplateIds.length),
                        })}</small>
                        <small>{text(profile.coverageNote)}</small>
                      </span>
                    </label>
                  ))}
                </div>
              </fieldset>
            )}

            {!incidentFocus && environmentDeviceAssets.length > 0 && (
              <fieldset className="scope-mode-fieldset">
                <legend>{text(pageCopy.environmentDevicesTitle)}</legend>
                <p>{text(pageCopy.environmentDevicesBody)}</p>
                <div className="scope-mode-grid">
                  {environmentDeviceAssets.map(({ asset, origin, profile }) => (
                    <label key={asset.id} className={selectedAssets.includes(asset.id) ? "scope-mode-card scope-mode-card--active" : "scope-mode-card"}>
                      <input
                        type="checkbox"
                        disabled={busy}
                        checked={selectedAssets.includes(asset.id)}
                        aria-label={text(pageCopy.chooseAsset, { name: origin })}
                        onChange={() => toggleEnvironmentAsset(asset.id)}
                      />
                      <span>
                        <strong>{origin}</strong>
                        <small>{text(profile.label)} · {text(pageCopy.environmentDeviceCheck, {
                          checks: formatNumber(internalDeviceTlsVulnerabilityOids.length),
                        })}</small>
                        <small>{text(profile.coverageNote)}</small>
                      </span>
                    </label>
                  ))}
                </div>
              </fieldset>
            )}

            {!incidentFocus && environmentUnreadyExternalAssets.length > 0 && (
              <InlineNotice
                tone="warning"
                title={text(pageCopy.environmentNotReadyTitle)}
              >
                <p>{text(pageCopy.environmentNotReadyBody)}</p>
                <ul>
                  {environmentUnreadyExternalAssets.map((asset) => <li key={asset.id}>{asset.name}</li>)}
                </ul>
              </InlineNotice>
            )}

            {environmentLocalAssets.length === 0
              && environmentHostAssets.length === 0
              && environmentWebsiteAssets.length === 0
              && environmentEndpointAssets.length === 0
              && environmentDeviceAssets.length === 0 && (
              <InlineNotice tone="warning" title={text(pageCopy.environmentNoReadyTitle)}>
                <p>{text(pageCopy.environmentNoReadyBody)}</p>
              </InlineNotice>
            )}

            {selectedEnvironmentNetworkAssets.length > 0 && (
              <label className="toggle-row">
                <input
                  type="checkbox"
                  disabled={busy}
                  checked={environmentNetworkConfirmed}
                  onChange={(event) => setEnvironmentNetworkConfirmed(event.target.checked)}
                />
                <span>
                  <strong>{text(pageCopy.environmentNetworkConfirmationTitle)}</strong>
                  <small>{text(pageCopy.environmentNetworkConfirmationBody, {
                    origins: selectedEnvironmentNetworkAssets.map(({ origin }) => origin).join(", "),
                  })}</small>
                </span>
              </label>
            )}

            <div className="form-actions">
              <button
                className="button button--primary"
                type="submit"
                disabled={busy
                  || selectedEnvironmentAssetCount === 0
                  || (selectedEnvironmentNetworkAssets.length > 0 && !environmentNetworkConfirmed)}
              >
                <Icon name="lock" size={16} />{runtimeSetupNotice
                  ? text(pageCopy.preparingScanTools)
                  : busy
                    ? text(pageCopy.startingScan)
                    : text(pageCopy.environmentStart)}
              </button>
            </div>
          </form>
        )}

        {!environmentRoute && selectedAssets.length > 0 && (
          <form className="scope-confirmation-panel" onSubmit={(event) => { event.preventDefault(); void startScan(); }}>
            {!conciseGuidedConsent && (
              <div className="scope-confirmation-panel__heading">
                <div>
                  <h3>{text(pageCopy.selectedCount, { count: formatNumber(selectedAssets.length) })} · {text(pageCopy.presetTitle)}</h3>
                </div>
                <button className="icon-button" type="button" disabled={busy} aria-label={text(pageCopy.clearSelection)} onClick={resetScopeForm}><Icon name="close" size={17} /></button>
              </div>
            )}

            {guidedWebsiteQuickProfile && (
              <p className="coverage-review-timing">{text(pageCopy.websiteTiming)}</p>
            )}
            {guidedLocalConsent && (
              <p className="coverage-review-timing">{text(pageCopy.localTiming)}</p>
            )}

            {availableScopeModes.length === 0 ? (
              <InlineNotice tone="warning" title={text(pageCopy.noCommonTitle)}>
                <p>{text(pageCopy.noCommonBody)}</p>
              </InlineNotice>
            ) : guidedCloudConsent ? (
              <details className="coverage-situation-details coverage-scan-type-advanced">
                <summary>{text(pageCopy.changeScanType)}</summary>
                {scopeModeChooser}
              </details>
            ) : !conciseGuidedConsent ? scopeModeChooser : null}

            {isDirectExternal && selectedExternalAsset && limits && (
              <section className="external-scope-builder" aria-labelledby="external-scope-title">
                <div className="external-scope-builder__heading">
                  <div>
                    {!guidedLowImpactNetwork && <p className="eyebrow">{text(pageCopy.externalEyebrow)}</p>}
                    <h4 id="external-scope-title">{text(pageCopy.externalTitle, { name: selectedExternalAsset.name })}</h4>
                    {!guidedLowImpactNetwork && <p>{text(
                      guidedWebsiteQuickProfile
                        ? passiveWebsiteSelected ? pageCopy.websitePassiveDescription : pageCopy.websiteQuickDescription
                        : pageCopy.externalDescription,
                    )}</p>}
                  </div>
                  <StatusPill
                    label={text(selectedExternalAsset.internetExposed === true
                      ? pageCopy.sourcePublic
                      : selectedExternalAsset.internetExposed === false
                        ? pageCopy.sourceInternal
                        : pageCopy.sourceExposureUnknown)}
                    tone={selectedExternalAsset.internetExposed === true ? "positive" : "unknown"}
                  />
                </div>

                {isDirectExternal && selectedExternalAsset.internetExposed === undefined && (
                  <InlineNotice tone="warning" title={text(pageCopy.noDirectTitle)}>
                    <p>{text(pageCopy.noDirectBody)}</p>
                  </InlineNotice>
                )}

                {isDirectExternal && selectedExternalAsset.internetExposed === false && !effectiveAllowSensitiveNetworks && (
                  <InlineNotice tone="warning" title={text(pageCopy.internalGrantTitle)}>
                    <p>{text(pageCopy.internalGrantBody)}</p>
                  </InlineNotice>
                )}

                {externalTargetOptions.length === 0 && (
                  <InlineNotice tone="warning" title={text(pageCopy.noTargetTitle)}>
                    <p>{text(pageCopy.noTargetBody)}</p>
                  </InlineNotice>
                )}

                {externalActivity === "active_external" && !guidedWebsiteQuickProfile && (
                  <InlineNotice tone="info" title={text(pageCopy.activeSetupTitle)}>
                    <p>{text(pageCopy.activeSetupBody)}</p>
                  </InlineNotice>
                )}

                {guidedLowImpactNetwork && parsedPorts && (
                  <p className="coverage-guided-boundary">
                    {text(pageCopy.guidedNetworkBoundary, {
                      target: externalTarget,
                      protocol: externalProtocol.toUpperCase(),
                      ports: parsedPorts.join(", "),
                      rate: formatNumber(requestsPerSecond),
                      concurrency: formatNumber(externalConcurrency),
                      timeout: formatNumber(externalTimeout),
                    })}
                  </p>
                )}

                {guidedWebsiteQuickProfile && quickProfileOrigin && selectedExternalAsset.declaredWebService && (
                  <p className="coverage-guided-boundary">
                    {text(passiveWebsiteSelected ? pageCopy.websitePassiveBoundary : pageCopy.websiteQuickBoundary, {
                      origin: quickProfileOrigin,
                      path: selectedExternalAsset.declaredWebService.path,
                      rate: formatNumber(selectedWebsiteProfile.ratePolicy.requestsPerSecond),
                      concurrency: formatNumber(selectedWebsiteProfile.ratePolicy.concurrency),
                      timeout: formatNumber(selectedWebsiteProfile.ratePolicy.timeoutSeconds),
                    })}
                  </p>
                )}

                <details
                  className="coverage-form-technical coverage-scan-advanced"
                  open={showAdvancedExternalSettings}
                  onToggle={(event) => setShowAdvancedExternalSettings(event.currentTarget.open)}
                >
                  <summary>
                    <span>{text(pageCopy.advancedScanSettings)}</span>
                    <small>{text(pageCopy.advancedScanSettingsHelp)}</small>
                  </summary>
                  {guidedWebsiteQuickProfile && websiteProfileSelect}
                  {guidedLowImpactNetwork && parsedPorts && (
                    <p className="coverage-technical-preset-summary">{text(pageCopy.guidedNetworkTechnicalPreset, {
                      protocol: externalProtocol.toUpperCase(),
                      count: formatNumber(parsedPorts.length),
                      concurrency: formatNumber(externalConcurrency),
                    })}</p>
                  )}
                  {guidedLowImpactNetwork && scopeModeChooser}
                  {selectedExternalAsset.declaredWebService && (
                    <InlineNotice tone="info" title={text(pageCopy.declaredServiceTitle)}>
                      <p>{text(pageCopy.declaredServiceBody, {
                        protocol: selectedExternalAsset.declaredWebService.protocol.toUpperCase(),
                        port: formatNumber(selectedExternalAsset.declaredWebService.port),
                        path: selectedExternalAsset.declaredWebService.path,
                      })}</p>
                    </InlineNotice>
                  )}
                  <label className="field">
                    <span>{text(pageCopy.canonicalTarget)}</span>
                    <select disabled={busy || guidedWebsiteQuickProfile} value={externalTarget} onChange={(event) => setExternalTarget(event.target.value)}>
                      {externalTargetOptions.map((target) => <option key={target} value={target}>{target}</option>)}
                    </select>
                    <small>{text(pageCopy.canonicalTargetHelp)}</small>
                  </label>
                  <div className="form-grid form-grid--two">
                    <label className="field">
                      <span>{text(pageCopy.protocol)}</span>
                      <select disabled={busy || guidedWebsiteQuickProfile} value={externalProtocol} onChange={(event) => setExternalProtocol(event.target.value as TransportProtocol)}>
                        <option value="https">HTTPS</option>
                        <option value="http">HTTP</option>
                        <option value="tls">TLS</option>
                        <option value="tcp">TCP</option>
                        <option value="udp">UDP</option>
                      </select>
                      <small>{text(pageCopy.protocolHelp)}</small>
                    </label>
                    <label className="field">
                      <span>{text(pageCopy.ports)}</span>
                      <input disabled={busy || guidedWebsiteQuickProfile} value={externalPorts} onChange={(event) => setExternalPorts(event.target.value)} placeholder="443, 8443" inputMode="numeric" />
                      <small>{parsedPorts === undefined
                        ? text(pageCopy.portsInvalid)
                        : text(pageCopy.portsValid, { count: formatNumber(parsedPorts.length) })}</small>
                    </label>
                    {externalActivity === "active_external" && <label className="field">
                      <span>{text(pageCopy.policyRevision)}</span>
                      <input value={templateRevision} readOnly disabled={busy} aria-readonly="true" />
                      <small>{text(templateRevisionPinned ? pageCopy.revisionValid : pageCopy.revisionInvalid)}</small>
                    </label>}
                  </div>

                  <fieldset className="rate-policy-fieldset">
                    <legend>{text(pageCopy.rateTitle)}</legend>
                    <div className="rate-policy-grid">
                      <label className="field"><span>{text(pageCopy.rps)}</span><input disabled={busy || guidedWebsiteQuickProfile} type="number" min={1} max={limits.rate} value={requestsPerSecond} onChange={(event) => setRequestsPerSecond(event.target.valueAsNumber)} /><small>{text(pageCopy.maximum, { value: formatNumber(limits.rate) })}</small></label>
                      <label className="field"><span>{text(pageCopy.concurrency)}</span><input disabled={busy || guidedWebsiteQuickProfile} type="number" min={1} max={limits.concurrency} value={externalConcurrency} onChange={(event) => setExternalConcurrency(event.target.valueAsNumber)} /><small>{text(pageCopy.maximum, { value: formatNumber(limits.concurrency) })}</small></label>
                      <label className="field"><span>{text(pageCopy.timeout)}</span><input disabled={busy || guidedWebsiteQuickProfile} type="number" min={1} max={limits.timeout} value={externalTimeout} onChange={(event) => setExternalTimeout(event.target.valueAsNumber)} /><small>{text(pageCopy.maximum, { value: formatNumber(limits.timeout) })}</small></label>
                    </div>
                  </fieldset>

                  {externalActivity === "active_external" && !guidedWebsiteQuickProfile && <label className="field">
                    <span>{text(pageCopy.templateIds)}</span>
                    <textarea disabled={busy} rows={3} value={allowedTemplateIds} onChange={(event) => setAllowedTemplateIds(event.target.value)} placeholder={text(pageCopy.templatePlaceholder)} />
                    <small>{templateIdsValid
                      ? text(pageCopy.templateValid, { count: formatNumber(parsedTemplateIds.length) })
                      : text(pageCopy.templateInvalid)} {text(pageCopy.prohibitedIntro)}</small>
                  </label>}

                  <div className="prohibited-template-list" aria-label={text(pageCopy.prohibitedIntro)}>
                    {prohibitedCapabilities.map((item) => <span key={item.en}><Icon name="lock" size={13} />{text(item)}</span>)}
                  </div>
                  <InlineNotice
                    tone="info"
                    title={text(effectiveAllowSensitiveNetworks
                      ? pageCopy.sensitiveTechnicalTitle
                      : pageCopy.publicBoundaryTitle)}
                  >
                    <p>{text(effectiveAllowSensitiveNetworks
                      ? pageCopy.sensitiveTechnicalBody
                      : pageCopy.publicBoundaryBody)}</p>
                  </InlineNotice>
                </details>

                {networkScanEstimate
                  && networkScanDuration
                  && networkScanConservativeDuration
                  && networkScanCeilingDuration && (
                  <InlineNotice
                    tone="warning"
                    title={text(
                      networkScanDuration.hours > 0
                        ? pageCopy.durationWarningTitleHours
                        : pageCopy.durationWarningTitleMinutes,
                      {
                        hours: formatNumber(networkScanDuration.hours),
                        minutes: formatNumber(networkScanDuration.minutes),
                      },
                    )}
                  >
                    <p>{text(pageCopy.durationWarningBody, {
                      addresses: formatNumber(networkScanEstimate.addressCount),
                      ports: formatNumber(parsedPorts?.length ?? 0),
                      probes: formatNumber(networkScanEstimate.probeCount),
                      effectiveRate: formatNumber(networkScanEstimate.effectiveRequestsPerSecond),
                      requestedRate: formatNumber(requestsPerSecond),
                      concurrency: formatNumber(externalConcurrency),
                    })}</p>
                    <p>{text(
                      networkScanEstimate.mayExceedEngineCeiling
                        ? pageCopy.durationCeilingRiskBody
                        : pageCopy.durationCeilingWithinBody,
                      {
                        ceilingHours: formatNumber(networkScanCeilingDuration.hours),
                        timeout: formatNumber(externalTimeout),
                        upperHours: formatNumber(networkScanConservativeDuration.hours),
                        upperMinutes: formatNumber(networkScanConservativeDuration.minutes),
                      },
                    )}</p>
                  </InlineNotice>
                )}

                {isDirectExternal && selectedExternalAsset.internetExposed === false && !guidedLowImpactNetwork && (
                  <label className="toggle-row toggle-row--danger">
                    <input type="checkbox" disabled={busy} checked={allowSensitiveNetworks} onChange={(event) => setAllowSensitiveNetworks(event.target.checked)} />
                    <span><strong>{text(pageCopy.sensitiveTitle)}</strong><small>{text(pageCopy.sensitiveBody)}</small></span>
                  </label>
                )}
              </section>
            )}

            {guidedCloudConsent && (
              <p className="coverage-guided-boundary">
                {text(pageCopy.guidedCloudBoundary, {
                  account: selectedScopeAssets.map((asset) => asset.name).join(", "),
                  checks: scopeModes.map((mode) => text(scopeModeLabels[mode].label)).join(", "),
                })}
              </p>
            )}

            {guidedLocalConsent && (
              <>
                {agenticInventorySelection(selectedScopeAssets)}
                {mcpArmorRunnable && selectedScopeAssets.map((asset) => asset.mcpConfigurationCandidates && asset.mcpConfigurationCandidates.length > 1 ? (
                  <label className="field" key={`${asset.id}-mcp-configuration`}>
                    <span>{text(pageCopy.mcpConfigurationLabel)}</span>
                    <select
                      disabled={busy}
                      value={asset.selectedMcpConfiguration ?? ""}
                      onChange={(event) => {
                        if (event.target.value) void onSelectMcpConfiguration(asset.id, event.target.value);
                      }}
                    >
                      <option value="">{text(pageCopy.mcpConfigurationChoose)}</option>
                      {asset.mcpConfigurationCandidates.map((candidate) => (
                        <option key={candidate.relativePath} value={candidate.relativePath}>{candidate.relativePath}</option>
                      ))}
                    </select>
                    <small>{text(pageCopy.mcpConfigurationHelp)}</small>
                  </label>
                ) : null)}
                <p className="coverage-guided-boundary">
                  {text(pageCopy.guidedLocalBoundary, {
                    copy: selectedScopeAssets.map((asset) => asset.name).join(", "),
                    checks: (guidedLocalEngineIds ?? []).map((engineId) => text(engineOutcomeForId(engineId))).join(locale === "zh-TW" ? "、" : ", "),
                  })}
                </p>
              </>
            )}

            {!conciseGuidedConsent && (
              <div className="scope-confirmation-panel__assets">
                {selectedScopeAssets.map((asset) => <span key={asset.id}><b>{asset.name}</b><small>{asset.platform === "external" && asset.internetExposed === false
                  ? text(pageCopy.internalAssetPlatform)
                  : platformMeta[asset.platform].label} · {text(assetTypeLabels[asset.type])}</small></span>)}
              </div>
            )}

            {!conciseGuidedConsent && (
              <>
                <label className="toggle-row">
                  <input type="checkbox" disabled={busy} checked={ownershipConfirmed} onChange={(event) => setOwnershipConfirmed(event.target.checked)} />
                  <span><strong>{text(selectedExternalAsset
                    ? selectedExternalAsset.internetExposed === false
                      ? pageCopy.internalOwnershipTitle
                      : pageCopy.externalOwnershipTitle
                    : pageCopy.ownershipTitle)}</strong><small>{text(pageCopy.ownershipBody)}</small></span>
                </label>

                <label className="field">
                  <span>{text(requiresAuthorizationReference ? pageCopy.authorityRequired : pageCopy.scopeNote)}</span>
                  <input disabled={busy} value={scopeConfirmation} onChange={(event) => setScopeConfirmation(event.target.value)} placeholder={text(requiresAuthorizationReference ? pageCopy.authorityPlaceholder : pageCopy.notePlaceholder)} />
                  <small>{text(requiresAuthorizationReference ? pageCopy.authorityHelp : pageCopy.noteHelp)}</small>
                  {externalActivity === "active_external" && scopeConfirmation.trim().length > 0 && scopeConfirmation.trim().length < 8 && <small className="field-error">{text(pageCopy.activeAuthorityLength)}</small>}
                </label>
              </>
            )}

            <div className="form-actions">
              {!conciseGuidedConsent && <p><Icon name="lock" size={16} /> {text(pageCopy.grantBoundaryHelp)}</p>}
              <button className="button button--primary" type="submit" disabled={busy || availableScopeModes.length === 0 || scopeModes.length === 0 || (!conciseGuidedConsent && !ownershipConfirmed) || (requiresAuthorizationReference && !scopeConfirmation.trim()) || !externalScopeReady || mcpSelectionRequired}>
                <Icon name="lock" size={16} />{runtimeSetupNotice
                  ? text(pageCopy.preparingScanTools)
                  : busy
                  ? text(pageCopy.startingScan)
                  : text(guidedCloudConsent
                    ? pageCopy.scanSignedInCloud
                    : conciseGuidedConsent
                      ? pageCopy.confirmAndStart
                      : pageCopy.startScan)}
              </button>
            </div>
          </form>
        )}

        {!environmentRoute && (filteredAssets.length === 0 ? (
          <EmptyState
            icon={assets.length === 0 && unknownSourceCount > 0 ? "warning" : "database"}
            title={assets.length === 0
              ? unknownSourceCount > 0
                ? text(pageCopy.emptyUnknownTitle)
                : connectedNoAssetCount > 0
                  ? text(pageCopy.emptyNoneTitle)
                  : text(pageCopy.emptyNeverTitle)
              : text(pageCopy.emptyFilterTitle)}
            description={assets.length === 0
              ? unknownSourceCount > 0
                ? text(pageCopy.emptyUnknownBody)
                : connectedNoAssetCount > 0
                  ? text(pageCopy.emptyNoneBody)
                  : text(pageCopy.emptyNeverBody)
              : text(pageCopy.emptyFilterBody)}
          />
        ) : conciseGuidedConsent && filteredAssets.length === 1 ? null : (
          <div
            className={useCompactAssetList ? "asset-review-list asset-review-list--compact" : "asset-review-list"}
            role="list"
          >
            {filteredAssets.map((asset) => {
              const scopeEligible = scopeEligibleAssets.some((item) => item.id === asset.id);
              const meta = coverageMeta[asset.coverageState];
              const readyForFirstScan = isAwaitingFirstScan(asset.coverageState, asset.scanAttempted);
              const anotherAssetSelected = selectedAssets.length > 0 && !selectedAssets.includes(asset.id);
              const selectedIncludesExternal = selectedScopeAssets.some((item) => item.platform === "external");
              const incompatibleWithSelection = anotherAssetSelected
                && (asset.platform === "external" || selectedIncludesExternal || guidedCloudRoute);
              const showAssetNext = asset.authorizationState !== "authorized"
                || readyForFirstScan
                || selectedAssets.includes(asset.id);
              const cardClassName = [
                "asset-review-card",
                selectedAssets.includes(asset.id) ? "asset-review-card--selected" : "",
                showAssetNext ? "" : "asset-review-card--compact",
                useCompactAssetList ? "asset-review-card--list-row" : "",
              ].filter(Boolean).join(" ");
              return (
                <article key={asset.id} className={cardClassName} role="listitem">
                  <label className="asset-review-card__choice">
                    <input
                      type="checkbox"
                      aria-label={text(pageCopy.chooseAsset, { name: asset.name })}
                      checked={selectedAssets.includes(asset.id)}
                      disabled={busy || !scopeEligible || incompatibleWithSelection}
                      title={incompatibleWithSelection
                        ? text(pageCopy.incompatibleSelection)
                        : asset.authorizationState === "authorized"
                          ? text(pageCopy.addPermission)
                          : undefined}
                      onChange={() => toggleAsset(asset.id)}
                    />
                    <span className="platform-avatar platform-avatar--small">{platformMeta[asset.platform].abbreviation}</span>
                    <span>
                      <strong>{asset.name}</strong>
                      <small>{asset.platform === "external" && asset.internetExposed === false
                        ? text(pageCopy.internalAssetPlatform)
                        : platformMeta[asset.platform].label} · {text(assetTypeLabels[asset.type])}</small>
                      {useCompactAssetList && showAssetNext && (
                        <small className="asset-review-card__next-inline">{text(nextStepForAsset(asset))}</small>
                      )}
                    </span>
                  </label>
                  <div className="asset-review-card__status">
                    <StatusPill
                      label={readyForFirstScan ? text(pageCopy.readyToScan) : meta.shortLabel}
                      tone={readyForFirstScan ? "positive" : meta.tone}
                    />
                    <small>{text(authorizationStateLabels[asset.authorizationState])}</small>
                  </div>
                  {showAssetNext && !useCompactAssetList && (
                    <div className="asset-review-card__next">
                      <strong>{text(pageCopy.assetNext)}</strong>
                      <p>{text(nextStepForAsset(asset))}</p>
                    </div>
                  )}
                  <details className="asset-review-card__technical">
                    <summary>{text(pageCopy.assetTechnical)}</summary>
                    <dl>
                      <div><dt>{text(pageCopy.locator)}</dt><dd><code>{asset.locator}</code></dd></div>
                      <div><dt>{text(pageCopy.assetType)}</dt><dd><code>{asset.type}</code></dd></div>
                      <div><dt>{text(pageCopy.coverageStateTechnical)}</dt><dd><code>{asset.coverageState}</code></dd></div>
                      <div><dt>{text(pageCopy.authorizationState)}</dt><dd><code>{asset.authorizationState}</code></dd></div>
                      <div><dt>{text(pageCopy.internetExposure)}</dt><dd>{text(asset.internetExposed === true ? pageCopy.exposed : asset.internetExposed === false ? pageCopy.internal : pageCopy.exposureUnknown)}</dd></div>
                      <div><dt>{text(pageCopy.allowedModes)}</dt><dd>{asset.allowedModes.length
                        ? asset.allowedModes.map((mode) => text(scopeModeLabels[mode].label)).join(", ")
                        : text(pageCopy.noAllowedModes)}</dd></div>
                      <div><dt>{text(pageCopy.findingsCount)}</dt><dd>{formatNumber(asset.findingCount)}</dd></div>
                      <div><dt>{text(pageCopy.owner)}</dt><dd>{asset.owner ?? text(pageCopy.noOwner)}</dd></div>
                      {asset.region && <div><dt>{text(pageCopy.region)}</dt><dd>{asset.region}</dd></div>}
                      {asset.identifiers && asset.identifiers.length > 0 && <div><dt>{text(pageCopy.identifiers)}</dt><dd>{asset.identifiers.map((identifier) => `${identifier.namespace}:${identifier.value}`).join(", ")}</dd></div>}
                      {asset.selectedMcpConfiguration && <div><dt>{text(pageCopy.mcpConfigurationLabel)}</dt><dd><code>{asset.selectedMcpConfiguration}</code></dd></div>}
                    </dl>
                  </details>
                </article>
              );
            })}
          </div>
        ))}
      </section>

      {frozenExternalGrants.length > 0 && (
        <details className="section-block page-secondary-feature">
          <summary>{text(pageCopy.savedApprovals, { count: formatNumber(frozenExternalGrants.length) })}</summary>
          <div className="external-grant-list">
            {frozenExternalGrants.map((grant) => {
              const scope = grant.externalScope!;
              const asset = assets.find((item) => item.id === grant.assetId);
              return (
                <article key={grant.id} className="external-grant-card">
                  <div className="external-grant-card__header">
                    <span><Icon name="lock" size={17} /></span>
                    <div><strong>{asset?.name ?? grant.assetId}</strong><small>{text(scope.activity === "low_impact_external" && scope.allowSensitiveNetworks
                      ? pageCopy.lowImpactInternalActivity
                      : activityLabels[scope.activity])} · {text(pageCopy.expires, { date: formatDateTime(scope.expiresAt) })}</small></div>
                    <StatusPill label={text(scope.allowSensitiveNetworks ? pageCopy.sensitiveAllowed : pageCopy.sensitiveBlocked)} tone={scope.allowSensitiveNetworks ? "warning" : "positive"} />
                  </div>
                  <details className="external-grant-card__technical">
                    <summary>{text(pageCopy.grantTechnical)}</summary>
                    <dl>
                      <div><dt>{text(pageCopy.targetTerm)}</dt><dd><code>{scope.targetKind}:{scope.target}</code></dd></div>
                      <div><dt>{text(pageCopy.protocolPortsTerm)}</dt><dd>{scope.protocol.toUpperCase()} · {scope.ports.length ? scope.ports.join(", ") : text(pageCopy.noDirectPort)}</dd></div>
                      <div><dt>{text(pageCopy.rateTerm)}</dt><dd>{formatNumber(scope.ratePolicy.requestsPerSecond)} req/s · {formatNumber(scope.ratePolicy.concurrency)} concurrent · {formatNumber(scope.ratePolicy.timeoutSeconds)}s</dd></div>
                      <div><dt>{text(pageCopy.templatesTerm)}</dt><dd><code>{scope.templatePolicy.revision}</code> · {scope.templatePolicy.profileId
                        ? <code>{scope.templatePolicy.profileId}</code>
                        : text(pageCopy.allowedIdsCount, { count: formatNumber(scope.templatePolicy.allowedTemplateIds.length) })}</dd></div>
                      <div><dt>{text(pageCopy.authorityTerm)}</dt><dd>{scope.assertedAuthority}</dd></div>
                      <div><dt>{text(pageCopy.approvalTerm)}</dt><dd>{scope.approvedBy} · {formatDateTime(scope.approvedAt)}</dd></div>
                    </dl>
                    <p><Icon name="lock" size={13} /> {text(pageCopy.prohibitedAll)}</p>
                  </details>
                </article>
              );
            })}
          </div>
        </details>
      )}

    </div>
  );
}
