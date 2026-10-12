import type {
  AiGeneratedArtifactAnswer,
  AppSnapshot,
  Asset,
  AssessmentCase,
  CaseWorkspace,
  CloudPlatform,
  ConnectedSource,
  CoverageRecord,
  CreateCaseInput,
  EngineCategory,
  EngineManifest,
  KnownAssetInput,
} from "../types";
import { getActiveLocale } from "../i18n/core";
import {
  explicitTargetRequiresSensitiveNetworkAllowance,
  validateExternalTarget,
} from "../caseForm";

const DEMO_NOTICE =
  "合成範例資料，只供預覽。";

export { DEMO_NOTICE };

export const getDemoNotice = (): string => getActiveLocale() !== "zh-TW"
  ? "Synthetic sample data for preview."
  : DEMO_NOTICE;

const demoEnglishTranslations: Record<string, string> = {
  "2 個候選網域尚未取得主動掃描授權。": "Two candidate domains do not yet have permission for active testing.",
  "AWS 雲端安全／資料治理": "AWS cloud security / data governance",
  "BlockPublicAccess 設定未套用至所有層級。": "BlockPublicAccess is not enabled at every level.",
  "Conditional Access policy coverage 未涵蓋所有使用者。": "Conditional Access policy coverage does not include every user.",
  "Git 歷史中疑似包含仍有效的雲端金鑰": "Git history may contain an active cloud access key",
  "Gitleaks 在歷史 commit 中識別出符合雲端 access key 格式的字串。": "Gitleaks found a string in an earlier commit that matches a cloud access-key format.",
  "IAM credential report 顯示 MFA active=false。": "The IAM credential report shows MFA active=false.",
  "IAM／身分安全": "IAM / identity security",
  "Kubernetes API 驗證範圍未完成": "Kubernetes API verification did not finish",
  "Kubernetes short-lived token 已過期。": "The short-lived Kubernetes token expired.",
  "Kubernetes 平台安全": "Kubernetes platform security",
  "M365 設定未能證明所有使用者均由 Conditional Access 阻擋 legacy authentication。": "The M365 configuration does not prove that Conditional Access blocks legacy authentication for every user.",
  "Microsoft Graph API 限流；可從此引擎續跑。": "Microsoft Graph rate-limited the request; this scanner can resume from its saved point.",
  "Northstar Labs（展示）": "Northstar Labs (demo)",
  "Northstar 初步安全健檢": "Northstar initial security review",
  "Root access key 已停用": "Root access key disabled",
  "ScubaGear 完成；Maester 因 API 限流僅完成 72%。": "ScubaGear completed; Maester reached 72% before an API rate limit.",
  "Trivy 在基底映像中識別出有修補版本可用的高風險套件。": "Trivy found a high-risk package in the base image with a fixed version available.",
  "Web／平台安全": "Web / platform security",
  "主動弱點測試": "Active vulnerability testing",
  "候選資產": "Candidate assets",
  "高權限帳號濫用的相關觀察；原始問題各自保留證據與改善措施。": "Related privileged-account abuse observations. Each original finding retains its evidence and remediation.",
  "公開 DNS 與憑證紀錄": "Public DNS and certificate records",
  "公開服務仍接受過時 TLS 設定": "A public service still accepts outdated TLS settings",
  "初步健檢 #2": "Initial review #2",
  "原規則 0.0.0.0/0 已移除；本次證據顯示只允許應用子網。": "The original 0.0.0.0/0 rule was removed; current evidence allows only the application subnet.",
  "可能降低傳輸保護強度，並增加舊式攻擊或相容性降級風險。": "This may weaken transport protection and increase exposure to older attacks or downgrade behavior.",
  "同一身分在本次 credential report 仍顯示 MFA inactive。": "The current credential report still shows MFA inactive for the same identity.",
  "Azure 適用性：案件問卷記錄為不使用。": "Azure applicability: recorded as not used in the case questionnaire.",
  "外部攻擊面": "Public websites and IP addresses",
  "外部檢查觀察到較弱的加密套件仍可協商。": "The external check observed that a weaker cipher suite can still be negotiated.",
  "客戶匯出儲存桶可能允許公開讀取": "A customer-export bucket may allow public reads",
  "容器弱點": "Container vulnerabilities",
  "容器映像包含高風險系統套件弱點": "A container image contains a high-risk system-package vulnerability",
  "容器與 SBOM": "Containers and software inventory",
  "容器／DevSecOps": "Containers / DevSecOps",
  "尚未連接資料來源": "No data source connected",
  "尚未連接資料來源的展示案件。": "A demo case with no connected data source.",
  "展示 CVE：系統套件已有 fixed version。": "Demo CVE: a fixed version is available for this system package.",
  "合成預覽用公開資料政策。": "Synthetic public-data policy for preview.",
  "展示案件資料來源：未連接。掃描狀態：未開始。": "Demo source: not connected. Scan status: not started.",
  "展示案件建立器": "Demo case builder",
  "合成預覽目標。": "Synthetic preview target.",
  "展示資料": "Demo data",
  "展示資料：外部端點回傳可列舉內容的 HTTP 回應。": "Demo data: an external endpoint returned an HTTP response with listable content.",
  "展示資料：弱式 cipher suite 可協商。": "Demo data: a weak cipher suite can be negotiated.",
  "工作於 31% 時因 token expired 中止。": "Work stopped at 31% because the token expired.",
  "已掃描 6 個使用者選取的 repositories。": "Scanned six repositories selected by the user.",
  "已檢查提供的帳務匯出，未發現其他供應商線索。": "The provided billing export was checked and did not identify another provider.",
  "已盤點 3 個帳號與 18 項核心資產。": "Inventoried three accounts and 18 core assets.",
  "已遮罩：AKIA••••••••7Q2P，位於過往 commit。": "Redacted: AKIA••••••••7Q2P in an earlier commit.",
  "帳務來源": "Billing source",
  "平台團隊": "Platform team",
  "憑證遭竊時，攻擊者可能直接取得生產環境的廣泛權限。": "If the credential is stolen, an attacker may gain broad access to the production environment.",
  "應用團隊": "Application team",
  "應用安全／雲端 IAM": "Application security / cloud IAM",
  "找到 4 個候選網域，其中 2 個尚未確認主動測試範圍。": "Found four candidate domains; active-testing scope is not confirmed for two of them.",
  "掃描權杖於驗證期間過期；匿名存取設定狀態：未知。": "Scan token expired during verification. Anonymous-access setting status: unknown.",
  "新映像與更新後的弱點資料庫首次觀察到此項問題。": "This problem was first observed with the new image and updated vulnerability database.",
  "GCP 資料來源：未連接。": "GCP source: not connected.",
  "本機使用者": "Local user",
  "基準比較：無法完成，token 已過期。": "Baseline comparison: unavailable because the token expired.",
  "機密": "Secrets",
  "產品團隊": "Product team",
  "用來展示資產盤點、涵蓋清冊、finding 與複驗差異的本機案件。": "A local demo case showing asset inventory, coverage, findings, and before-and-after verification.",
  "相同檢查已不再觀察到有效 root access key。": "The same check no longer observes an active root access key.",
  "程式碼": "Source code",
  "第二辦公室盤點": "Second-office inventory",
  "至少一個具有高權限的 IAM 身分未觀察到可用的 MFA 裝置。": "At least one privileged IAM identity has no observed active MFA device.",
  "舊式驗證可能繞過現代 MFA 與條件式存取保護。": "Legacy authentication may bypass modern MFA and Conditional Access protections.",
  "若服務可達且弱點路徑成立，可能造成未授權程式執行或資料暴露。": "If the service is reachable and the vulnerable path is present, unauthorized code execution or data exposure may be possible.",
  "若權限確實有效，未授權人員可能取得含個人資料的匯出檔案。": "If the permission is effective, an unauthorized person may access exports containing personal data.",
  "若金鑰仍有效，取得 repository 的人可能存取雲端資源。": "If the key is still active, anyone with repository access may be able to reach cloud resources.",
  "設定與外部觀測證據仍存在，尚未看到有效修正。": "Configuration and external-observation evidence remain; no effective fix has been observed.",
  "確認實際 bucket policy、使用情境與相依服務，再收斂公開權限。": "Confirm the effective bucket policy, use case, and dependent services, then reduce public access.",
  "確認身分用途與登入方式，優先處理可互動登入的高權限帳號。": "Confirm the identity's purpose and sign-in method, prioritizing privileged accounts that allow interactive sign-in.",
  "更新短效唯讀權杖，再續跑 Kubescape 工作。": "Renew the short-lived read-only token, then resume the Kubescape work.",
  "核對登入記錄與現行例外，再逐步阻擋舊式驗證。": "Review sign-in logs and current exceptions, then stage the legacy-authentication block.",
  "確認客戶端相容性，停用弱式套件，再重新驗證。": "Confirm client compatibility, disable weak cipher suites, then verify again.",
  "更新基底映像並重新建置，再由本案件複驗新的 fixed image digest。": "Update the base image and rebuild, then use this case to verify the new fixed image digest.",
  "驗證並撤銷該金鑰，再清理 Git 歷史並更新秘密管理流程。": "Validate and revoke the key, then clean Git history and update secret-management practices.",
  "資料來源可用，但此案件未發現 Terraform state。": "The data source was available, but no Terraform state was found for this case.",
  "資料團隊": "Data team",
  "資料庫安全群組不再對外開放": "Database security group is no longer public",
  "檢查狀態：未完成。恢復唯讀權限後完成檢查。": "Check status: incomplete. Restore read-only access to finish the check.",
  "部分帳號仍可能使用舊式驗證": "Some accounts may still use legacy authentication",
  "雲端盤點": "Cloud inventory",
  "雲端設定": "Cloud configuration",
  "雲端設定顯示公開存取保護未完整啟用，外部檢查亦觀察到可存取回應。": "Cloud configuration shows incomplete public-access protection, and an external check also observed a reachable response.",
  "高權限身分保護需要一起檢視": "Review privileged-identity protections together",
  "高權限身分缺少完整 MFA 保護": "A privileged identity does not have complete MFA protection",
};

const localizeBuiltInDemo = <T,>(value: T): T => {
  if (getActiveLocale() === "zh-TW") return clone(value);
  const visit = (candidate: unknown): unknown => {
    if (typeof candidate === "string") return demoEnglishTranslations[candidate] ?? candidate;
    if (Array.isArray(candidate)) return candidate.map(visit);
    if (candidate && typeof candidate === "object") {
      return Object.fromEntries(
        Object.entries(candidate).map(([key, nested]) => [key, visit(nested)]),
      );
    }
    return candidate;
  };
  return visit(value) as T;
};

const sampleCase: AssessmentCase = {
  id: "case-demo-northstar",
  name: "Northstar 初步安全健檢",
  aiGeneratedArtifact: "unknown",
  organizationName: "Northstar Labs（展示）",
  companySize: "small",
  dataClasses: ["pii", "credentials"],
  requestedActivities: [
    "configuration_assessment",
    "local_artifact_analysis",
    "low_impact_external_checks",
  ],
  platforms: ["aws", "m365", "external", "code", "container", "kubernetes"],
  createdAt: "2026-08-18T09:30:00-04:00",
  updatedAt: "2026-08-24T02:42:00-04:00",
  phase: "verification_due",
  isDemo: true,
  description: "用來展示資產盤點、涵蓋清冊、finding 與複驗差異的本機案件。",
  latestRunId: "run-demo-002",
};

const draftCase: AssessmentCase = {
  id: "case-demo-blank",
  name: "第二辦公室盤點",
  aiGeneratedArtifact: "unknown",
  organizationName: "Northstar Labs（展示）",
  companySize: "small",
  dataClasses: ["none"],
  requestedActivities: ["configuration_assessment"],
  platforms: ["azure", "external"],
  createdAt: "2026-08-23T14:10:00-04:00",
  updatedAt: "2026-08-23T14:10:00-04:00",
  phase: "draft",
  isDemo: true,
  description: "尚未連接資料來源的展示案件。",
};

const manifest = (
  id: string,
  name: string,
  category: EngineCategory,
  version: string,
  license: string,
  platforms: CloudPlatform[],
  redistribution: EngineManifest["redistribution"] = "on_demand",
  runnable = true,
): EngineManifest => ({
  id,
  name,
  category,
  version,
  imageDigest: `sha256:demo-${id}-not-a-real-digest`,
  license,
  redistribution,
  platforms,
  supportedProviders: platforms.filter((platform) => ["aws", "azure", "gcp", "m365"].includes(platform)),
  status: runnable ? "ready" : "not_downloaded",
  runnable,
  blockedBy: runnable ? [] : ["The pinned managed engine image is not released in this product version."],
  compatibilityValid: true,
  providerExecutionProfiles: id === "prowler" ? [
    { provider: "aws", assetKind: "cloud_account", profile: "aws_iam_service_exact_account" },
    { provider: "azure", assetKind: "subscription", profile: "azure_iam_service_static_token_exact_subscription" },
    { provider: "gcp", assetKind: "project", profile: "gcp_iam_four_checks_exact_project" },
  ] : [],
  knowledgeDate: "2026-08-24",
});

export const demoEngineManifests: EngineManifest[] = [
  manifest("cloudquery", "CloudQuery", "cloud_inventory", "2.0.31-aws9.2.0-file1.0.4", "MPL-2.0", ["aws"]),
  manifest("steampipe", "Steampipe", "cloud_inventory", "2.4.5", "AGPL-3.0", ["aws"]),
  manifest("prowler", "Prowler", "cloud_configuration", "5.39.1", "Apache-2.0", ["aws", "azure", "gcp"]),
  manifest("scoutsuite", "ScoutSuite", "cloud_configuration", "5.14.0", "GPL-2.0", ["aws"]),
  manifest("cloudsplaining", "Cloudsplaining", "identity_and_access", "0.9.1", "BSD-3-Clause", ["aws"]),
  manifest("scubagear", "ScubaGear", "microsoft365", "1.8.0", "CC0-1.0", ["m365"], "on_demand", false),
  manifest("maester", "Maester", "microsoft365", "2.0.0", "MIT", ["m365"], "on_demand", false),
  manifest("naabu", "Naabu", "external_attack_surface", "2.6.1", "MIT", ["external"]),
  manifest("httpx", "httpx", "external_attack_surface", "1.10.0", "MIT", ["external"]),
  manifest("nuclei", "Nuclei", "external_attack_surface", "3.11.1", "MIT", ["external"]),
  manifest("greenbone", "Greenbone", "external_attack_surface", "23.50.24", "GPL-2.0", ["external"]),
  manifest("semgrep", "Semgrep", "code_and_secrets", "source@a0c13f304151e531c7e7c00838076211a07a790c", "LGPL-2.1", ["code"]),
  manifest("gitleaks", "Gitleaks", "code_and_secrets", "8.30.1", "MIT", ["code"]),
  manifest("trufflehog", "TruffleHog", "code_and_secrets", "source@3ab759fef4bb5935d4fe9ac68b503d05346b8364", "AGPL-3.0", ["code"]),
  manifest("checkov", "Checkov", "infrastructure_as_code", "3.3.13", "Apache-2.0", ["code"]),
  manifest("kics", "KICS", "infrastructure_as_code", "2.1.20", "Apache-2.0", ["code"]),
  manifest("trivy", "Trivy", "container_and_sbom", "0.74.0", "Apache-2.0", ["container"]),
  manifest("grype", "Grype", "container_and_sbom", "0.117.0", "Apache-2.0", ["container"]),
  manifest("syft", "Syft", "container_and_sbom", "1.51.0", "Apache-2.0", ["container"]),
  manifest("kubescape", "Kubescape", "kubernetes", "4.0.12", "Apache-2.0", ["kubernetes"]),
  manifest("kube-bench", "kube-bench", "kubernetes", "source@9f133cb7509ce1dbedfc860e94474588000e25ac", "Apache-2.0", ["kubernetes"]),
];

const demoWorkspace: CaseWorkspace = {
  case: sampleCase,
  sources: [
    { id: "source-aws-demo", kind: "aws_organization", label: "AWS Organization", status: "connected", readOnly: true, connectedAt: "2026-08-24T02:20:00-04:00", lastDiscoveredAt: "2026-08-24T02:40:00-04:00" },
    { id: "source-m365-demo", kind: "microsoft365_tenant", label: "Microsoft 365 Tenant", status: "connected", readOnly: true, connectedAt: "2026-08-24T02:20:00-04:00", lastDiscoveredAt: "2026-08-24T02:38:00-04:00" },
    { id: "source-azure-demo", kind: "azure_tenant", label: "Azure Tenant", status: "not_applicable", readOnly: true },
    { id: "source-gcp-demo", kind: "gcp_organization", label: "GCP Organization", status: "not_connected", readOnly: true },
  ],
  coverage: [
    {
      id: "coverage-aws-org",
      label: "AWS Organization",
      platform: "aws",
      sourceKind: "aws_organization",
      state: "discovered_authorized_scanned",
      assetCount: 18,
      detail: "已盤點 3 個帳號與 18 項核心資產。",
      lastCheckedAt: "2026-08-24T02:40:00-04:00",
    },
    {
      id: "coverage-m365",
      label: "Microsoft 365 Tenant",
      platform: "m365",
      sourceKind: "microsoft365_tenant",
      state: "authorized_incomplete",
      assetCount: 1,
      detail: "ScubaGear 完成；Maester 因 API 限流僅完成 72%。",
      lastCheckedAt: "2026-08-24T02:38:00-04:00",
    },
    {
      id: "coverage-dns",
      label: "公開 DNS 與憑證紀錄",
      platform: "external",
      sourceKind: "dns",
      state: "discovered_not_authorized",
      assetCount: 4,
      detail: "找到 4 個候選網域，其中 2 個尚未確認主動測試範圍。",
      lastCheckedAt: "2026-08-24T02:31:00-04:00",
    },
    {
      id: "coverage-git",
      label: "Git repositories",
      platform: "code",
      sourceKind: "git_repository",
      state: "discovered_authorized_scanned",
      assetCount: 6,
      detail: "已掃描 6 個使用者選取的 repositories。",
      lastCheckedAt: "2026-08-24T02:27:00-04:00",
    },
    {
      id: "coverage-terraform",
      label: "Terraform state",
      platform: "code",
      sourceKind: "terraform_state",
      state: "source_connected_none",
      assetCount: 0,
      detail: "資料來源可用，但此案件未發現 Terraform state。",
      lastCheckedAt: "2026-08-24T02:18:00-04:00",
    },
    {
      id: "coverage-azure",
      label: "Azure Tenant",
      platform: "azure",
      sourceKind: "azure_tenant",
      state: "not_applicable",
      assetCount: 0,
      detail: "Azure 適用性：案件問卷記錄為不使用。",
    },
    {
      id: "coverage-gcp",
      label: "GCP Organization",
      platform: "gcp",
      sourceKind: "gcp_organization",
      state: "source_unavailable_unknown",
      assetCount: 0,
      detail: "GCP 資料來源：未連接。",
    },
    {
      id: "coverage-billing",
      label: "帳務來源",
      platform: "aws",
      sourceKind: "billing",
      state: "source_connected_none",
      assetCount: 0,
      detail: "已檢查提供的帳務匯出，未發現其他供應商線索。",
      lastCheckedAt: "2026-08-24T02:14:00-04:00",
    },
  ],
  assets: [
    {
      id: "asset-aws-prod",
      name: "production-account",
      type: "cloud_account",
      platform: "aws",
      locator: "AWS 4821••••9031",
      region: "us-east-1",
      owner: "平台團隊",
      coverageState: "discovered_authorized_scanned",
      authorizationState: "authorized",
      allowedModes: ["inventory", "configuration"],
      findingCount: 4,
      lastObservedAt: "2026-08-24T02:40:00-04:00",
      tags: ["production", "PII"],
    },
    {
      id: "asset-s3-export",
      name: "customer-export",
      type: "storage",
      platform: "aws",
      locator: "s3://customer-export-demo",
      region: "us-east-1",
      owner: "資料團隊",
      coverageState: "discovered_authorized_scanned",
      authorizationState: "authorized",
      allowedModes: ["inventory", "configuration"],
      findingCount: 1,
      lastObservedAt: "2026-08-24T02:39:00-04:00",
      tags: ["PII"],
    },
    {
      id: "asset-m365",
      name: "northstar-demo.onmicrosoft.com",
      type: "tenant",
      platform: "m365",
      locator: "Tenant 15b9••••4d7c",
      owner: "IT",
      coverageState: "authorized_incomplete",
      authorizationState: "authorized",
      allowedModes: ["inventory", "configuration"],
      findingCount: 2,
      lastObservedAt: "2026-08-24T02:38:00-04:00",
    },
    {
      id: "asset-web",
      name: "app.demo.invalid",
      type: "domain",
      platform: "external",
      locator: "app.demo.invalid",
      identifiers: [{ namespace: "dns_name", value: "app.demo.invalid" }],
      owner: "產品團隊",
      internetExposed: true,
      coverageState: "discovered_authorized_scanned",
      authorizationState: "authorized",
      allowedModes: ["passive", "active"],
      findingCount: 2,
      lastObservedAt: "2026-08-24T02:22:00-04:00",
    },
    {
      id: "asset-old-domain",
      name: "legacy.demo.invalid",
      type: "domain",
      platform: "external",
      locator: "legacy.demo.invalid",
      identifiers: [{ namespace: "dns_name", value: "legacy.demo.invalid" }],
      internetExposed: true,
      coverageState: "discovered_not_authorized",
      authorizationState: "pending",
      allowedModes: ["passive"],
      findingCount: 0,
      lastObservedAt: "2026-08-24T02:12:00-04:00",
      tags: ["候選資產"],
    },
    {
      id: "asset-repo",
      name: "northstar/api",
      type: "repository",
      platform: "code",
      locator: "git:demo/northstar-api",
      owner: "應用團隊",
      coverageState: "discovered_authorized_scanned",
      authorizationState: "authorized",
      allowedModes: ["local_artifact"],
      findingCount: 1,
      lastObservedAt: "2026-08-24T02:27:00-04:00",
    },
    {
      id: "asset-image",
      name: "api:v2026.08",
      type: "image",
      platform: "container",
      locator: "local-registry/api@sha256:demo",
      owner: "應用團隊",
      coverageState: "discovered_authorized_scanned",
      authorizationState: "authorized",
      allowedModes: ["local_artifact"],
      findingCount: 1,
      lastObservedAt: "2026-08-24T02:25:00-04:00",
    },
    {
      id: "asset-cluster",
      name: "prod-eks",
      type: "cluster",
      platform: "kubernetes",
      locator: "arn:aws:eks:us-east-1:••••:cluster/prod",
      owner: "平台團隊",
      coverageState: "authorized_incomplete",
      authorizationState: "authorized",
      allowedModes: ["local_artifact"],
      findingCount: 1,
      lastObservedAt: "2026-08-24T02:20:00-04:00",
    },
  ],
  scopeGrants: [
    {
      id: "scope-aws",
      assetId: "asset-aws-prod",
      modes: ["inventory", "configuration"],
      state: "authorized",
      confirmedAt: "2026-08-23T20:02:00-04:00",
      confirmedBy: "本機使用者",
    },
    {
      id: "scope-web",
      assetId: "asset-web",
      modes: ["active_external"],
      state: "authorized",
      confirmedAt: "2026-08-23T20:10:00-04:00",
      confirmedBy: "本機使用者",
      note: "合成預覽目標。",
      externalScope: {
        id: "external-scope-demo-web",
        caseId: sampleCase.id,
        assetId: "asset-web",
        target: "app.demo.invalid",
        targetKind: "hostname",
        ports: [443],
        protocol: "https",
        activity: "active_external",
        ratePolicy: { requestsPerSecond: 1, concurrency: 1, timeoutSeconds: 60 },
        templatePolicy: {
          revision: "demo-policy-not-executable",
          allowedTemplateIds: ["demo/tls-policy"],
          allowHeadless: false,
          allowOutOfBand: false,
          allowFuzzing: false,
          allowFileUpload: false,
          allowDenialOfService: false,
          allowCredentialAttacks: false,
        },
        assertedAuthority: "DEMO ONLY — no real target authorization",
        approvedBy: "展示資料",
        approvedAt: "2026-08-23T20:10:00-04:00",
        expiresAt: "2026-09-22T20:10:00-04:00",
        allowSensitiveNetworks: false,
      },
    },
    {
      id: "scope-web-public",
      assetId: "asset-web",
      modes: ["public_data"],
      state: "authorized",
      confirmedAt: "2026-08-23T20:09:00-04:00",
      confirmedBy: "本機使用者",
      note: "合成預覽用公開資料政策。",
      externalScope: {
        id: "external-scope-demo-web-public",
        caseId: sampleCase.id,
        assetId: "asset-web",
        target: "app.demo.invalid",
        targetKind: "hostname",
        ports: [],
        protocol: "https",
        activity: "passive_public_discovery",
        ratePolicy: { requestsPerSecond: 1, concurrency: 1, timeoutSeconds: 60 },
        templatePolicy: {
          revision: "demo-public-policy-not-executable",
          allowedTemplateIds: [],
          allowHeadless: false,
          allowOutOfBand: false,
          allowFuzzing: false,
          allowFileUpload: false,
          allowDenialOfService: false,
          allowCredentialAttacks: false,
        },
        assertedAuthority: "DEMO ONLY — public-data scope",
        approvedBy: "展示資料",
        approvedAt: "2026-08-23T20:09:00-04:00",
        expiresAt: "2026-09-22T20:09:00-04:00",
        allowSensitiveNetworks: false,
      },
    },
    {
      id: "scope-old-domain",
      assetId: "asset-old-domain",
      modes: ["passive"],
      state: "pending",
    },
  ],
  runs: [
    {
      id: "run-demo-002",
      caseId: sampleCase.id,
      label: "初步健檢 #2",
      status: "partial",
      progress: 88,
      startedAt: "2026-08-24T01:52:00-04:00",
      finishedAt: "2026-08-24T02:42:00-04:00",
      knowledgeDate: "2026-08-21",
      coveredAssetCount: 25,
      totalAssetCount: 29,
      engineRuns: [
        {
          id: "er-prowler",
          engineId: "prowler",
          engineName: "Prowler",
          taskKind: { kind: "catalog_engine" },
          category: "cloud_configuration",
          version: "5.39.1",
          digest: "sha256:demo-prowler",
          ruleVersion: "2026-08-21",
          status: "completed",
          progress: 100,
          phase: "completed",
          assetIds: ["asset-aws-prod", "asset-s3-export"],
          rawArtifactCount: 2,
          savedResultArtifactCount: 2,
          startedAt: "2026-08-24T01:53:00-04:00",
          finishedAt: "2026-08-24T02:08:00-04:00",
          findingCount: 4,
          warnings: ["Synthetic demo record; no scanner was executed."],
          resumable: false,
        },
        {
          id: "er-httpx",
          engineId: "httpx",
          engineName: "httpx",
          taskKind: { kind: "catalog_engine" },
          category: "external_attack_surface",
          version: "1.10.0",
          digest: "sha256:demo-httpx",
          status: "completed",
          progress: 100,
          phase: "completed",
          assetIds: ["asset-s3-export"],
          rawArtifactCount: 1,
          savedResultArtifactCount: 1,
          startedAt: "2026-08-24T02:09:00-04:00",
          finishedAt: "2026-08-24T02:14:00-04:00",
          findingCount: 1,
          findingCountKnown: true,
          warnings: ["Synthetic demo record; no scanner was executed."],
          resumable: false,
        },
        {
          id: "er-scubagear",
          engineId: "scubagear",
          engineName: "ScubaGear",
          taskKind: { kind: "catalog_engine" },
          category: "microsoft365",
          version: "1.8.0",
          digest: "sha256:demo-scubagear",
          status: "completed",
          progress: 100,
          phase: "completed",
          assetIds: ["asset-m365"],
          rawArtifactCount: 1,
          savedResultArtifactCount: 1,
          startedAt: "2026-08-24T01:55:00-04:00",
          finishedAt: "2026-08-24T02:18:00-04:00",
          findingCount: 2,
          warnings: ["Synthetic demo record; no scanner was executed."],
          resumable: false,
        },
        {
          id: "er-maester",
          engineId: "maester",
          engineName: "Maester",
          taskKind: { kind: "catalog_engine" },
          category: "microsoft365",
          version: "2.0.0",
          digest: "sha256:demo-maester",
          status: "partial",
          progress: 72,
          phase: "captured_awaiting_adapter",
          assetIds: ["asset-m365"],
          rawArtifactCount: 1,
          savedResultArtifactCount: 1,
          startedAt: "2026-08-24T01:55:00-04:00",
          finishedAt: "2026-08-24T02:41:00-04:00",
          findingCount: 1,
          message: "Microsoft Graph API 限流；可從此引擎續跑。",
          errorCode: "provider_rate_limited",
          warnings: ["Synthetic demo record; no scanner was executed."],
          checkpoint: {
            attempt: 1,
            stage: "captured_awaiting_adapter",
            artifactCount: 1,
            cleanupCompleted: true,
            scopeBound: true,
            lastError: "Microsoft Graph API rate limit",
          },
          resumable: true,
        },
        {
          id: "er-nuclei",
          engineId: "nuclei",
          engineName: "Nuclei",
          taskKind: { kind: "catalog_engine" },
          category: "external_attack_surface",
          version: "3.11.1",
          digest: "sha256:demo-nuclei",
          ruleVersion: "templates 10.2.6",
          status: "completed",
          progress: 100,
          phase: "completed",
          assetIds: ["asset-web"],
          rawArtifactCount: 1,
          savedResultArtifactCount: 1,
          startedAt: "2026-08-24T02:05:00-04:00",
          finishedAt: "2026-08-24T02:16:00-04:00",
          findingCount: 2,
          warnings: ["Synthetic demo record; no scanner was executed."],
          resumable: false,
        },
        {
          id: "er-gitleaks",
          engineId: "gitleaks",
          engineName: "Gitleaks",
          taskKind: { kind: "catalog_engine" },
          category: "code_and_secrets",
          version: "8.30.1",
          digest: "sha256:demo-gitleaks",
          status: "completed",
          progress: 100,
          phase: "completed",
          assetIds: ["asset-repo"],
          rawArtifactCount: 1,
          savedResultArtifactCount: 1,
          startedAt: "2026-08-24T02:00:00-04:00",
          finishedAt: "2026-08-24T02:09:00-04:00",
          findingCount: 1,
          warnings: ["Synthetic demo record; no scanner was executed."],
          resumable: false,
        },
        {
          id: "er-trivy",
          engineId: "trivy",
          engineName: "Trivy",
          taskKind: { kind: "catalog_engine" },
          category: "container_and_sbom",
          version: "0.74.0",
          digest: "sha256:demo-trivy",
          ruleVersion: "DB 2026-08-21",
          status: "completed",
          progress: 100,
          phase: "completed",
          assetIds: ["asset-image"],
          rawArtifactCount: 1,
          savedResultArtifactCount: 1,
          startedAt: "2026-08-24T02:08:00-04:00",
          finishedAt: "2026-08-24T02:19:00-04:00",
          findingCount: 1,
          warnings: ["Synthetic demo record; no scanner was executed."],
          resumable: false,
        },
        {
          id: "er-kubescape",
          engineId: "kubescape",
          engineName: "Kubescape",
          taskKind: { kind: "catalog_engine" },
          category: "kubernetes",
          version: "4.0.12",
          digest: "sha256:demo-kubescape",
          status: "failed",
          progress: 31,
          phase: "failed",
          assetIds: ["asset-cluster"],
          rawArtifactCount: 1,
          savedResultArtifactCount: 1,
          startedAt: "2026-08-24T02:13:00-04:00",
          finishedAt: "2026-08-24T02:20:00-04:00",
          findingCount: 0,
          message: "Kubernetes short-lived token 已過期。",
          errorCode: "credential_expired",
          warnings: ["Synthetic demo record; no scanner was executed."],
          checkpoint: {
            attempt: 1,
            stage: "failed",
            artifactCount: 1,
            cleanupCompleted: true,
            scopeBound: true,
            lastError: "Kubernetes short-lived token expired",
          },
          resumable: true,
        },
        {
          id: "er-greenbone",
          engineId: "greenbone",
          engineName: "Greenbone",
          taskKind: { kind: "catalog_engine" },
          category: "external_attack_surface",
          version: "23.50.24",
          digest: "sha256:demo-greenbone",
          status: "not_executed",
          progress: 0,
          phase: "not_executed",
          assetIds: ["asset-old-domain"],
          rawArtifactCount: 0,
          savedResultArtifactCount: 0,
          findingCount: 0,
          message: "2 個候選網域尚未取得主動掃描授權。",
          errorCode: "missing_active_authorization",
          warnings: ["Synthetic demo record; no scanner was executed."],
          resumable: false,
        },
      ],
    },
  ],
  findings: [
    {
      id: "finding-s3-public",
      fingerprint: "demo:aws:s3:customer-export:public",
      assetId: "asset-s3-export",
      assetName: "customer-export",
      title: "客戶匯出儲存桶可能允許公開讀取",
      summary: "雲端設定顯示公開存取保護未完整啟用，外部檢查亦觀察到可存取回應。",
      impact: "若權限確實有效，未授權人員可能取得含個人資料的匯出檔案。",
      recommendation: "確認實際 bucket policy、使用情境與相依服務，再收斂公開權限。",
      expertType: "AWS 雲端安全／資料治理",
      severity: "critical",
      confidence: "high",
      priority: 96,
      workflowState: "assigned",
      evidence: [
        {
          id: "evidence-s3-prowler",
          sourceEngine: "Prowler",
          observedAt: "2026-08-24T02:04:00-04:00",
          summary: "BlockPublicAccess 設定未套用至所有層級。",
          rawArtifactHash: "sha256:demo-evidence-s3-prowler",
          rawArtifactPath: "/checks/s3_public_access/0",
          kind: "configuration",
          runId: "run-demo-002",
          engineRunId: "er-prowler",
          artifactId: "artifact-demo-prowler-s3",
          redacted: true,
        },
        {
          id: "evidence-s3-httpx",
          sourceEngine: "httpx",
          observedAt: "2026-08-24T02:14:00-04:00",
          summary: "展示資料：外部端點回傳可列舉內容的 HTTP 回應。",
          rawArtifactHash: "sha256:demo-evidence-s3-httpx",
          rawArtifactPath: "/responses/0",
          kind: "external_validation",
          runId: "run-demo-002",
          engineRunId: "er-httpx",
          artifactId: "artifact-demo-httpx-s3",
          redacted: false,
        },
      ],
      controls: [
        { framework: "NIST CSF", version: "2.0", controlId: "PR.DS", relationship: "related" },
        { framework: "ISO 27001", version: "2022", controlId: "A.8.3", relationship: "related" },
      ],
      officialReferences: ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
      firstSeenAt: "2026-08-18T10:08:00-04:00",
      lastSeenAt: "2026-08-24T02:14:00-04:00",
    },
    {
      id: "finding-mfa-admin",
      fingerprint: "demo:aws:iam:privileged:mfa",
      assetId: "asset-aws-prod",
      assetName: "production-account",
      title: "高權限身分缺少完整 MFA 保護",
      summary: "至少一個具有高權限的 IAM 身分未觀察到可用的 MFA 裝置。",
      impact: "憑證遭竊時，攻擊者可能直接取得生產環境的廣泛權限。",
      recommendation: "確認身分用途與登入方式，優先處理可互動登入的高權限帳號。",
      expertType: "IAM／身分安全",
      severity: "critical",
      confidence: "high",
      priority: 92,
      workflowState: "unconfirmed",
      evidence: [
        {
          id: "evidence-mfa-prowler",
          sourceEngine: "Prowler",
          observedAt: "2026-08-24T02:06:00-04:00",
          summary: "IAM credential report 顯示 MFA active=false。",
          rawArtifactHash: "sha256:demo-evidence-mfa",
          rawArtifactPath: "/checks/iam_mfa/0",
          kind: "configuration",
          runId: "run-demo-002",
          engineRunId: "er-prowler",
          artifactId: "artifact-demo-prowler-mfa",
          redacted: true,
        },
      ],
      controls: [
        { framework: "NIST CSF", version: "2.0", controlId: "PR.AA", relationship: "related" },
        { framework: "ISO 27001", version: "2022", controlId: "A.5.17", relationship: "related" },
      ],
      officialReferences: ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"],
      firstSeenAt: "2026-08-18T10:11:00-04:00",
      lastSeenAt: "2026-08-24T02:06:00-04:00",
    },
    {
      id: "finding-secret-git",
      fingerprint: "demo:git:api:secret",
      assetId: "asset-repo",
      assetName: "northstar/api",
      title: "Git 歷史中疑似包含仍有效的雲端金鑰",
      summary: "Gitleaks 在歷史 commit 中識別出符合雲端 access key 格式的字串。",
      impact: "若金鑰仍有效，取得 repository 的人可能存取雲端資源。",
      recommendation: "驗證並撤銷該金鑰，再清理 Git 歷史並更新秘密管理流程。",
      expertType: "應用安全／雲端 IAM",
      severity: "high",
      confidence: "medium",
      priority: 88,
      workflowState: "assigned",
      evidence: [
        {
          id: "evidence-gitleaks",
          sourceEngine: "Gitleaks",
          observedAt: "2026-08-24T02:07:00-04:00",
          summary: "已遮罩：AKIA••••••••7Q2P，位於過往 commit。",
          rawArtifactHash: "sha256:demo-evidence-gitleaks",
          rawArtifactPath: "/findings/0",
          kind: "source_code",
          runId: "run-demo-002",
          engineRunId: "er-gitleaks",
          artifactId: "artifact-demo-gitleaks",
          redacted: true,
        },
      ],
      controls: [
        { framework: "NIST CSF", version: "2.0", controlId: "PR.AA", relationship: "related" },
        { framework: "ISO 27001", version: "2022", controlId: "A.8.24", relationship: "related" },
      ],
      officialReferences: ["https://docs.github.com/code-security/secret-scanning/introduction/about-secret-scanning"],
      firstSeenAt: "2026-08-18T10:20:00-04:00",
      lastSeenAt: "2026-08-24T02:07:00-04:00",
    },
    {
      id: "finding-m365-legacy",
      fingerprint: "demo:m365:legacy-auth",
      assetId: "asset-m365",
      assetName: "northstar-demo.onmicrosoft.com",
      title: "部分帳號仍可能使用舊式驗證",
      summary: "M365 設定未能證明所有使用者均由 Conditional Access 阻擋 legacy authentication。",
      impact: "舊式驗證可能繞過現代 MFA 與條件式存取保護。",
      recommendation: "核對登入記錄與現行例外，再逐步阻擋舊式驗證。",
      expertType: "Microsoft 365／Entra ID",
      severity: "high",
      confidence: "medium",
      priority: 78,
      workflowState: "unconfirmed",
      evidence: [
        {
          id: "evidence-scuba",
          sourceEngine: "ScubaGear",
          observedAt: "2026-08-24T02:16:00-04:00",
          summary: "Conditional Access policy coverage 未涵蓋所有使用者。",
          rawArtifactHash: "sha256:demo-evidence-scuba",
          rawArtifactPath: "/results/conditional_access/0",
          kind: "configuration",
          runId: "run-demo-002",
          engineRunId: "er-scubagear",
          artifactId: "artifact-demo-scubagear",
          redacted: true,
        },
      ],
      controls: [
        { framework: "NIST CSF", version: "2.0", controlId: "PR.AA", relationship: "related" },
        { framework: "ISO 27001", version: "2022", controlId: "A.8.5", relationship: "related" },
      ],
      officialReferences: ["https://learn.microsoft.com/entra/identity/conditional-access/block-legacy-authentication"],
      firstSeenAt: "2026-08-18T10:22:00-04:00",
      lastSeenAt: "2026-08-24T02:16:00-04:00",
    },
    {
      id: "finding-tls",
      fingerprint: "demo:web:tls:protocol",
      assetId: "asset-web",
      assetName: "app.demo.invalid",
      title: "公開服務仍接受過時 TLS 設定",
      summary: "外部檢查觀察到較弱的加密套件仍可協商。",
      impact: "可能降低傳輸保護強度，並增加舊式攻擊或相容性降級風險。",
      recommendation: "確認客戶端相容性，停用弱式套件，再重新驗證。",
      expertType: "Web／平台安全",
      severity: "medium",
      confidence: "high",
      priority: 60,
      workflowState: "remediated_pending_verification",
      evidence: [
        {
          id: "evidence-tls",
          sourceEngine: "Nuclei",
          observedAt: "2026-08-24T02:13:00-04:00",
          summary: "展示資料：弱式 cipher suite 可協商。",
          rawArtifactHash: "sha256:demo-evidence-tls",
          rawArtifactPath: "/results/0",
          kind: "external_validation",
          runId: "run-demo-002",
          engineRunId: "er-nuclei",
          artifactId: "artifact-demo-nuclei-tls",
          redacted: false,
        },
      ],
      controls: [
        { framework: "NIST CSF", version: "2.0", controlId: "PR.DS", relationship: "related" },
        { framework: "ISO 27001", version: "2022", controlId: "A.8.24", relationship: "related" },
      ],
      officialReferences: ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
      firstSeenAt: "2026-08-18T10:24:00-04:00",
      lastSeenAt: "2026-08-24T02:13:00-04:00",
    },
    {
      id: "finding-container-cve",
      fingerprint: "demo:image:openssl:cve",
      assetId: "asset-image",
      assetName: "api:v2026.08",
      title: "容器映像包含高風險系統套件弱點",
      summary: "Trivy 在基底映像中識別出有修補版本可用的高風險套件。",
      impact: "若服務可達且弱點路徑成立，可能造成未授權程式執行或資料暴露。",
      recommendation: "更新基底映像並重新建置，再由本案件複驗新的 fixed image digest。",
      expertType: "容器／DevSecOps",
      severity: "high",
      confidence: "high",
      priority: 82,
      workflowState: "assigned",
      evidence: [
        {
          id: "evidence-trivy",
          sourceEngine: "Trivy",
          observedAt: "2026-08-24T02:18:00-04:00",
          summary: "展示 CVE：系統套件已有 fixed version。",
          rawArtifactHash: "sha256:demo-evidence-trivy",
          rawArtifactPath: "/results/0/vulnerabilities/0",
          kind: "package_inventory",
          runId: "run-demo-002",
          engineRunId: "er-trivy",
          artifactId: "artifact-demo-trivy",
          redacted: false,
        },
      ],
      controls: [
        { framework: "NIST CSF", version: "2.0", controlId: "PR.PS", relationship: "related" },
        { framework: "ISO 27001", version: "2022", controlId: "A.8.8", relationship: "related" },
      ],
      officialReferences: ["https://aquasecurity.github.io/trivy/"],
      firstSeenAt: "2026-08-24T02:18:00-04:00",
      lastSeenAt: "2026-08-24T02:18:00-04:00",
    },
    {
      id: "finding-k8s",
      fingerprint: "demo:k8s:anonymous-auth",
      assetId: "asset-cluster",
      assetName: "prod-eks",
      title: "Kubernetes API 驗證範圍未完成",
      summary: "掃描權杖於驗證期間過期；匿名存取設定狀態：未知。",
      impact: "檢查狀態：未完成。恢復唯讀權限後完成檢查。",
      recommendation: "更新短效唯讀權杖，再續跑 Kubescape 工作。",
      expertType: "Kubernetes 平台安全",
      severity: "info",
      confidence: "low",
      priority: 18,
      workflowState: "unconfirmed",
      evidence: [
        {
          id: "evidence-k8s-incomplete",
          sourceEngine: "Kubescape",
          observedAt: "2026-08-24T02:20:00-04:00",
          summary: "工作於 31% 時因 token expired 中止。",
          rawArtifactHash: "sha256:demo-evidence-k8s-incomplete",
          rawArtifactPath: "/errors/0",
          kind: "raw_tool_output",
          runId: "run-demo-002",
          engineRunId: "er-kubescape",
          artifactId: "artifact-demo-kubescape-incomplete",
          redacted: true,
        },
      ],
      controls: [
        { framework: "NIST CSF", version: "2.0", controlId: "PR.AA", relationship: "related" },
      ],
      officialReferences: ["https://kubernetes.io/docs/reference/access-authn-authz/authentication/"],
      firstSeenAt: "2026-08-24T02:20:00-04:00",
      lastSeenAt: "2026-08-24T02:20:00-04:00",
    },
  ],
  findingGroups: [
    {
      id: "group-demo-identity-access",
      caseId: sampleCase.id,
      title: "高權限身分保護需要一起檢視",
      findingIds: ["finding-mfa-admin", "finding-m365-legacy"],
      rationale: "高權限帳號濫用的相關觀察；原始問題各自保留證據與改善措施。",
      groupedBy: "展示案件建立器",
      createdAt: "2026-08-24T02:45:00-04:00",
    },
  ],
  findingGroupEvents: [
    {
      id: "group-event-demo-identity-access-created",
      caseId: sampleCase.id,
      groupId: "group-demo-identity-access",
      action: "created",
      title: "高權限身分保護需要一起檢視",
      findingIds: ["finding-mfa-admin", "finding-m365-legacy"],
      rationale: "高權限帳號濫用的相關觀察；原始問題各自保留證據與改善措施。",
      actor: "展示案件建立器",
      occurredAt: "2026-08-24T02:45:00-04:00",
    },
  ],
  workflowEvents: [],
  exports: [
    {
      id: "export-demo-001",
      caseId: sampleCase.id,
      runId: "run-demo-001",
      format: "case_bundle",
      createdAt: "2026-08-18T11:14:00-04:00",
      fileName: "northstar-case-demo-001.case.tar.gz",
      sha256: "demo-sha256-not-cryptographic",
      signatureState: "local_integrity",
      includesRawEvidence: true,
      isDemo: true,
    },
  ],
  verification: {
    baselineRunId: "run-demo-001",
    comparisonRunId: "run-demo-002",
    baselineAt: "2026-08-18T10:45:00-04:00",
    comparisonAt: "2026-08-24T02:42:00-04:00",
    diffs: [
      {
        id: "diff-resolved-1",
        findingId: "finding-root-key",
        title: "Root access key 已停用",
        assetName: "production-account",
        state: "resolved",
        beforeSeverity: "critical",
        explanation: "相同檢查已不再觀察到有效 root access key。",
        evidenceChanged: true,
      },
      {
        id: "diff-resolved-2",
        findingId: "finding-sg-public",
        title: "資料庫安全群組不再對外開放",
        assetName: "production-account",
        state: "resolved",
        beforeSeverity: "high",
        explanation: "原規則 0.0.0.0/0 已移除；本次證據顯示只允許應用子網。",
        evidenceChanged: true,
      },
      {
        id: "diff-persistent-1",
        findingId: "finding-s3-public",
        title: "客戶匯出儲存桶可能允許公開讀取",
        assetName: "customer-export",
        state: "persistent",
        beforeSeverity: "critical",
        afterSeverity: "critical",
        explanation: "設定與外部觀測證據仍存在，尚未看到有效修正。",
        evidenceChanged: false,
      },
      {
        id: "diff-persistent-2",
        findingId: "finding-mfa-admin",
        title: "高權限身分缺少完整 MFA 保護",
        assetName: "production-account",
        state: "persistent",
        beforeSeverity: "critical",
        afterSeverity: "critical",
        explanation: "同一身分在本次 credential report 仍顯示 MFA inactive。",
        evidenceChanged: true,
      },
      {
        id: "diff-new-1",
        findingId: "finding-container-cve",
        title: "容器映像包含高風險系統套件弱點",
        assetName: "api:v2026.08",
        state: "new",
        afterSeverity: "high",
        explanation: "新映像與更新後的弱點資料庫首次觀察到此項問題。",
        evidenceChanged: true,
      },
      {
        id: "diff-unverifiable-1",
        findingId: "finding-k8s",
        title: "Kubernetes API 驗證範圍未完成",
        assetName: "prod-eks",
        state: "unverifiable",
        beforeSeverity: "medium",
        explanation: "基準比較：無法完成，token 已過期。",
        evidenceChanged: false,
      },
    ],
  },
};

const blankWorkspace = (assessmentCase: AssessmentCase): CaseWorkspace => ({
  case: assessmentCase,
  sources: [],
  coverage: [
    {
      id: `${assessmentCase.id}-coverage-unknown`,
      label: "尚未連接資料來源",
      platform: assessmentCase.platforms[0] ?? "external",
      sourceKind: "aws_organization",
      state: "source_unavailable_unknown",
      assetCount: 0,
      detail: "展示案件資料來源：未連接。掃描狀態：未開始。",
    },
  ],
  assets: [],
  scopeGrants: [],
  runs: [],
  findings: [],
  findingGroups: [],
  findingGroupEvents: [],
  workflowEvents: [],
  exports: [],
});

type StoredDemoCase = AssessmentCase & {
  /** Browser-preview persistence only. Native cases keep this data in the backend. */
  knownAssets?: KnownAssetInput[];
  demoStorageSchemaVersion?: 2;
};

const knownAssetKinds = new Set<KnownAssetInput["kind"]>([
  "external_target",
  "repository",
  "iac_project",
  "container_image",
  "kubernetes_cluster",
]);

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const safeDeclaredWebService = (value: unknown): KnownAssetInput["webService"] | undefined => {
  if (!isPlainRecord(value)) return undefined;
  const { protocol, port, path, scanProfile } = value;
  const acceptedScanProfile = scanProfile === "internal_device_https"
    ? scanProfile
    : undefined;
  return (protocol === "http" || protocol === "https")
    && Number.isInteger(port)
    && Number(port) >= 1
    && Number(port) <= 65_535
    && typeof path === "string"
    && path.length > 0
    && path.length <= 2_048
    && path.startsWith("/")
    && !path.includes("?")
    && !path.includes("#")
    && !/[\u0000-\u001f\u007f]/u.test(path)
    && (scanProfile === undefined || acceptedScanProfile !== undefined)
    ? {
      protocol,
      port: Number(port),
      path,
      ...(acceptedScanProfile === undefined ? {} : { scanProfile: acceptedScanProfile }),
    }
    : undefined;
};

const safeDeclaredNetworkService = (value: unknown): KnownAssetInput["networkService"] | undefined => {
  if (!isPlainRecord(value)) return undefined;
  const { protocol, port, scanProfile } = value;
  const acceptedScanProfile = scanProfile === "internal_endpoint_ssh"
    || scanProfile === "internal_endpoint_rdp_tls"
    || scanProfile === "internal_endpoint_vnc"
    || scanProfile === "internal_endpoint_smtp"
    || scanProfile === "internal_endpoint_telnet"
    ? scanProfile
    : undefined;
  return protocol === "tcp"
    && Number.isInteger(port)
    && Number(port) >= 1
    && Number(port) <= 65_535
    && acceptedScanProfile !== undefined
    ? { protocol, port: Number(port), scanProfile: acceptedScanProfile }
    : undefined;
};

const safeDeclaredHostScan = (value: unknown): KnownAssetInput["hostScan"] | undefined => {
  if (!isPlainRecord(value)) return undefined;
  const { protocol, ports, scanProfile } = value;
  if (
    protocol !== "tcp"
    || scanProfile !== "internal_host_greenbone_remote_safe"
    || !Array.isArray(ports)
    || ports.length === 0
    || ports.length > 64
    || ports.some((port) => !Number.isInteger(port) || Number(port) < 1 || Number(port) > 65_535)
  ) return undefined;
  const normalizedPorts = [...new Set(ports.map(Number))].sort((left, right) => left - right);
  return normalizedPorts.length === ports.length
    ? { protocol, ports: normalizedPorts, scanProfile }
    : undefined;
};

const safeKnownAsset = (value: unknown): KnownAssetInput | undefined => {
  if (!isPlainRecord(value) || !knownAssetKinds.has(value.kind as KnownAssetInput["kind"])) return undefined;
  if (typeof value.value !== "string") return undefined;
  const coordinate = value.value.trim();
  const maximumLength = value.kind === "kubernetes_cluster" ? 512 : 2_048;
  if (
    !coordinate
    || coordinate.length > maximumLength
    || /[\u0000-\u001f\u007f]/u.test(coordinate)
  ) return undefined;

  const kind = value.kind as KnownAssetInput["kind"];
  if (kind === "external_target" && !validateExternalTarget(coordinate).ok) return undefined;
  if (
    value.internetExposure !== undefined
    && value.internetExposure !== "public"
    && value.internetExposure !== "internal"
  ) return undefined;
  if (kind !== "external_target" && value.internetExposure !== undefined) return undefined;

  const webService = value.webService === undefined
    ? undefined
    : safeDeclaredWebService(value.webService);
  if (value.webService !== undefined && !webService) return undefined;
  if (kind !== "external_target" && webService) return undefined;
  if (webService && coordinate.includes("/")) return undefined;
  const networkService = value.networkService === undefined
    ? undefined
    : safeDeclaredNetworkService(value.networkService);
  if (value.networkService !== undefined && !networkService) return undefined;
  if (kind !== "external_target" && networkService) return undefined;
  if (networkService && coordinate.includes("/")) return undefined;
  const hostScan = value.hostScan === undefined
    ? undefined
    : safeDeclaredHostScan(value.hostScan);
  if (value.hostScan !== undefined && !hostScan) return undefined;
  if (kind !== "external_target" && hostScan) return undefined;
  if (hostScan && coordinate.includes("/")) return undefined;
  if ([webService, networkService, hostScan].filter(Boolean).length > 1) return undefined;

  return {
    kind,
    value: coordinate,
    ...(value.internetExposure === "public" || value.internetExposure === "internal"
      ? { internetExposure: value.internetExposure }
      : {}),
    ...(webService ? { webService } : {}),
    ...(networkService ? { networkService } : {}),
    ...(hostScan ? { hostScan } : {}),
  };
};

const safeKnownAssets = (value: unknown): KnownAssetInput[] => {
  if (!Array.isArray(value) || value.length > 200) return [];
  const assets: KnownAssetInput[] = [];
  const identities = new Map<string, string>();
  for (const candidate of value) {
    const asset = safeKnownAsset(candidate);
    if (!asset) return [];
    const serviceIdentity = asset.webService
      ? `${asset.webService.protocol}:${asset.webService.port}`
      : asset.networkService
        ? `${asset.networkService.protocol}:${asset.networkService.port}`
        : asset.hostScan
          ? `${asset.hostScan.protocol}:${asset.hostScan.scanProfile}`
        : "";
    const identity = `${asset.kind}\u0000${asset.value}\u0000${serviceIdentity}`;
    const serialized = JSON.stringify(asset);
    const existing = identities.get(identity);
    if (existing && existing !== serialized) return [];
    if (!existing) {
      identities.set(identity, serialized);
      assets.push(asset);
    }
  }
  return assets;
};

const externalIdentity = (value: string): { type: Asset["type"]; namespace: string } => {
  if (value.includes("/")) return { type: "ip", namespace: "ip_network" };
  if (value.includes(":")) return { type: "ip", namespace: "ip_address" };
  if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/u.test(value)) {
    return { type: "ip", namespace: "ip_address" };
  }
  return { type: "domain", namespace: "dns_name" };
};

const declaredAssetShape = (
  input: KnownAssetInput,
): Pick<Asset, "type" | "platform" | "identifiers" | "questionnairePlaceholder"> => {
  if (input.kind === "external_target") {
    const identity = externalIdentity(input.value);
    return {
      type: input.networkService ? "service" : identity.type,
      platform: "external",
      identifiers: [{ namespace: identity.namespace, value: input.value }],
    };
  }
  if (input.kind === "container_image") {
    return {
      type: "image",
      platform: "container",
      identifiers: [{ namespace: "oci_image_digest", value: input.value }],
      questionnairePlaceholder: true,
    };
  }
  if (input.kind === "kubernetes_cluster") {
    return {
      type: "cluster",
      platform: "kubernetes",
      identifiers: [{ namespace: "kubernetes_context", value: input.value }],
      questionnairePlaceholder: true,
    };
  }
  return {
    type: "repository",
    platform: "code",
    identifiers: [{
      namespace: input.kind === "iac_project" ? "iac_locator" : "repository_locator",
      value: input.value,
    }],
    questionnairePlaceholder: true,
  };
};

const storedWorkspace = (storedCase: StoredDemoCase): CaseWorkspace => {
  const locale = getActiveLocale();
  const knownAssets = safeKnownAssets(storedCase.knownAssets);
  const sourceId = `${storedCase.id}-source-user-declared`;
  const sourceLabel = locale !== "zh-TW"
    ? "Known assets entered in the scan project"
    : "掃描專案中輸入的已知項目";
  const coverageDetail = locale !== "zh-TW"
    ? "Saved from project setup. Permission status: unconfirmed. Scan status: not started."
    : "由專案設定保存。掃描權限：未確認。掃描狀態：未開始。";
  const sources: ConnectedSource[] = knownAssets.length > 0
    ? [{
        id: sourceId,
        kind: "user_declared",
        label: sourceLabel,
        status: "connected",
        readOnly: true,
        connectedAt: storedCase.createdAt,
      }]
    : [];
  const assets: Asset[] = knownAssets.map((input, index) => {
    const shape = declaredAssetShape(input);
    const sensitiveExternalTarget = input.kind === "external_target"
      && explicitTargetRequiresSensitiveNetworkAllowance(input.value);
    const internetExposed = input.kind !== "external_target"
      ? undefined
      : sensitiveExternalTarget
        ? false
        : input.internetExposure === "public"
          ? true
          : input.internetExposure === "internal"
            ? false
            : undefined;
    return {
      id: `${storedCase.id}-asset-${index + 1}`,
      name: input.value,
      locator: input.value,
      ...shape,
      discoveredFromSourceIds: [sourceId],
      ...(internetExposed === undefined ? {} : { internetExposed }),
      coverageState: "discovered_not_authorized",
      authorizationState: "pending",
      allowedModes: [],
      findingCount: 0,
      scanAttempted: false,
      ...(input.webService ? { declaredWebService: input.webService } : {}),
      ...(input.networkService ? { declaredNetworkService: input.networkService } : {}),
      ...(input.hostScan ? { declaredHostScan: input.hostScan } : {}),
    };
  });
  const coverage: CoverageRecord[] = assets.map((asset) => ({
    id: `${storedCase.id}-coverage-${asset.id}`,
    label: asset.name,
    platform: asset.platform,
    sourceKind: "user_declared",
    state: "discovered_not_authorized",
    assetId: asset.id,
    assetCount: 1,
    detail: coverageDetail,
    scanAttempted: false,
  }));

  if (knownAssets.length === 0) {
    return {
      ...localizeBuiltInDemo(blankWorkspace(stripStoredFields(storedCase))),
      case: stripStoredFields(storedCase),
    };
  }
  return {
    case: stripStoredFields(storedCase),
    sources,
    coverage,
    assets,
    scopeGrants: [],
    runs: [],
    findings: [],
    findingGroups: [],
    findingGroupEvents: [],
    workflowEvents: [],
    exports: [],
  };
};

const stripStoredFields = (storedCase: StoredDemoCase): AssessmentCase => {
  const {
    knownAssets: _knownAssets,
    demoStorageSchemaVersion: _demoStorageSchemaVersion,
    ...assessmentCase
  } = storedCase;
  return assessmentCase;
};

const clone = <T,>(value: T): T => structuredClone(value);

export const getDemoSnapshot = (selectedCaseId = sampleCase.id): AppSnapshot => {
  const storedRecords = loadStoredDemoCaseRecords();
  const storedCases = storedRecords.map(stripStoredFields);
  const cases = [...localizeBuiltInDemo([sampleCase, draftCase]), ...storedCases];
  const selected = cases.find((item) => item.id === selectedCaseId) ?? localizeBuiltInDemo(sampleCase);
  const storedRecord = storedRecords.find((item) => item.id === selected.id);
  const workspace = selected.id === sampleCase.id
    ? localizeBuiltInDemo(demoWorkspace)
    : storedRecord
      ? storedWorkspace(clone(storedRecord))
      : localizeBuiltInDemo(blankWorkspace(clone(selected)));

  return {
    cases: clone(cases),
    selectedCaseId: selected.id,
    workspace,
    engineManifests: localizeBuiltInDemo(demoEngineManifests),
    generatedAt: new Date().toISOString(),
    provenance: "demo",
  };
};

const STORAGE_KEY = "ai-security-scanner.demo-cases.v1";

const safeAiGeneratedArtifactAnswer = (value: unknown): AiGeneratedArtifactAnswer =>
  value === "yes" || value === "no" || value === "unknown" ? value : "unknown";

const loadStoredDemoCaseRecords = (): StoredDemoCase[] => {
  try {
    const value = window.localStorage.getItem(STORAGE_KEY);
    if (!value) return [];
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed)
      ? (parsed as StoredDemoCase[]).map((assessmentCase) => {
          const knownAssets = safeKnownAssets(assessmentCase.knownAssets);
          return {
            ...assessmentCase,
            aiGeneratedArtifact: safeAiGeneratedArtifactAnswer(assessmentCase.aiGeneratedArtifact),
            requestedActivities: assessmentCase.requestedActivities ?? [],
            phase: assessmentCase.phase === "draft" && knownAssets.length > 0
              ? "scope_review"
              : assessmentCase.phase,
            knownAssets,
          };
        })
      : [];
  } catch {
    return [];
  }
};

export const loadStoredDemoCases = (): AssessmentCase[] =>
  loadStoredDemoCaseRecords().map(stripStoredFields);

export const createStoredDemoCase = (input: CreateCaseInput): AssessmentCase => {
  const now = new Date().toISOString();
  const knownAssets = safeKnownAssets(input.knownAssets);
  const assessmentCase: StoredDemoCase = {
    ...input,
    knownAssets,
    demoStorageSchemaVersion: 2,
    id: `case-local-${crypto.randomUUID()}`,
    createdAt: now,
    updatedAt: now,
    phase: knownAssets.length > 0 ? "scope_review" : "draft",
    isDemo: true,
  };
  const cases = [assessmentCase, ...loadStoredDemoCaseRecords()];
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(cases));
  return stripStoredFields(assessmentCase);
};

/**
 * Delete only a project that the browser preview itself persisted. Built-in
 * sample projects never enter this storage collection, and the exact-name
 * check is repeated here so callers cannot bypass the visible confirmation.
 */
export const deleteStoredDemoCase = (caseId: string, confirmation: string): boolean => {
  try {
    const cases = loadStoredDemoCaseRecords();
    const selected = cases.find((assessmentCase) => assessmentCase.id === caseId);
    if (!selected || confirmation !== selected.name) return false;
    window.localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify(cases.filter((assessmentCase) => assessmentCase.id !== caseId)),
    );
    return true;
  } catch {
    return false;
  }
};

export const getDemoWorkspace = (caseId: string): CaseWorkspace => {
  return getDemoSnapshot(caseId).workspace ?? localizeBuiltInDemo(blankWorkspace(draftCase));
};
