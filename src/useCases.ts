import { localizeJapanese, type Locale } from "./i18n/core.ts";
import type { IconName } from "./components/Icon";
import type { Provider } from "./providerAuthorizationPolicy";
import type { AssessmentActivity, AssessmentIntent, CloudPlatform, KnownAssetKind } from "./types";

/** Product-facing name for the native assessment-intent wire coordinate. */
export type UseCaseId = AssessmentIntent;

export type UseCaseInputKind =
  | "url"
  | "ip_or_domain"
  | "internal_ip_or_snapshot"
  | "repository_or_folder"
  | "iac_project"
  | "provider_account"
  | "container_image"
  | "manifest_or_node_snapshot";

export interface UseCaseDefinition {
  id: UseCaseId;
  icon: IconName;
  inputKind: UseCaseInputKind;
  suggestedActivities: readonly AssessmentActivity[];
  suggestedPlatforms: readonly CloudPlatform[];
  knownAssetKind?: KnownAssetKind;
  internetExposure: "public" | "internal" | "not_applicable";
  supportedProviders?: readonly Provider[];
}

export interface UseCaseCardCopy {
  title: string;
  summary: string;
  want: string;
  prepare: string;
  productDoes: string;
  productDoesNot: string;
}

export interface StartPageCopy {
  eyebrow: string;
  title: string;
  description: string;
  choiceTitle: string;
  choiceDescription: string;
  wantLabel: string;
  prepareLabel: string;
  productDoesLabel: string;
  productDoesNotLabel: string;
  chooseAction: string;
  existingCaseAction: string;
  scopeNoticeTitle: string;
  scopeNotice: string;
  cards: Record<UseCaseId, UseCaseCardCopy>;
}

export const useCaseDefinitions = [
  {
    id: "deployed_website",
    icon: "external",
    inputKind: "url",
    suggestedActivities: ["active_external_vulnerability_tests"],
    suggestedPlatforms: ["external"],
    knownAssetKind: "external_target",
    internetExposure: "public",
  },
  {
    id: "external_ip_or_domain",
    icon: "coverage",
    inputKind: "ip_or_domain",
    suggestedActivities: ["low_impact_external_checks"],
    suggestedPlatforms: ["external"],
    knownAssetKind: "external_target",
    internetExposure: "public",
  },
  {
    id: "internal_it_environment",
    icon: "database",
    inputKind: "internal_ip_or_snapshot",
    suggestedActivities: ["local_artifact_analysis", "active_external_vulnerability_tests"],
    suggestedPlatforms: ["code", "external"],
    knownAssetKind: "external_target",
    internetExposure: "internal",
  },
  {
    id: "ai_application",
    icon: "spark",
    inputKind: "repository_or_folder",
    suggestedActivities: ["local_artifact_analysis"],
    suggestedPlatforms: ["code"],
    knownAssetKind: "repository",
    internetExposure: "not_applicable",
  },
  {
    id: "source_code",
    icon: "file",
    inputKind: "repository_or_folder",
    suggestedActivities: ["local_artifact_analysis"],
    suggestedPlatforms: ["code"],
    knownAssetKind: "repository",
    internetExposure: "not_applicable",
  },
  {
    id: "infrastructure_as_code",
    icon: "settings",
    inputKind: "iac_project",
    suggestedActivities: ["local_artifact_analysis"],
    suggestedPlatforms: ["code"],
    knownAssetKind: "iac_project",
    internetExposure: "not_applicable",
  },
  {
    id: "cloud_account",
    icon: "spark",
    inputKind: "provider_account",
    suggestedActivities: ["configuration_assessment"],
    suggestedPlatforms: ["aws", "azure", "gcp", "m365"],
    internetExposure: "not_applicable",
    supportedProviders: ["aws", "azure", "gcp", "microsoft365"],
  },
  {
    id: "container_image",
    icon: "archive",
    inputKind: "container_image",
    suggestedActivities: ["local_artifact_analysis"],
    suggestedPlatforms: ["container"],
    knownAssetKind: "container_image",
    internetExposure: "not_applicable",
  },
  {
    id: "kubernetes",
    icon: "shield",
    inputKind: "manifest_or_node_snapshot",
    suggestedActivities: ["local_artifact_analysis"],
    suggestedPlatforms: ["kubernetes"],
    knownAssetKind: "kubernetes_cluster",
    internetExposure: "not_applicable",
  },
] as const satisfies readonly UseCaseDefinition[];

const startPageCopyBase: Record<Exclude<Locale, "ja">, StartPageCopy> = {
  en: {
    eyebrow: "Start with what matters",
    title: "What do you want to protect first?",
    description:
      "Pick the closest match. The app brings the right tools together and guides you from setup to a prioritized fix list.",
    choiceTitle: "Choose one place to start",
    choiceDescription: "Start with one. Add other checks from Scan setup.",
    wantLabel: "What you want to check",
    prepareLabel: "What to prepare",
    productDoesLabel: "What the product does",
    productDoesNotLabel: "What it does not do",
    chooseAction: "Set up this check",
    existingCaseAction: "Open my scans",
    scopeNoticeTitle: "Network scan boundary",
    scopeNotice:
      "A network check starts only after review of its exact target, scan type, and limits. Advanced limits are in Scan setup.",
    cards: {
      deployed_website: {
        title: "A website or API that is already online",
        summary: "Find website vulnerabilities and exposed services within one selected website origin.",
        want:
          "An exact website or API URL, including the hostname and the service you want reviewed.",
        prepare:
          "The URL and permission to test its entire scheme://host:port origin. Do not use this quick profile for path-only permission.",
        productDoes:
          "Runs Nuclei's pinned upstream automatic web profile against the exact approved origin, limited to 10 requests per second and 5 concurrent requests.",
        productDoesNot:
          "It does not sign in, submit forms, follow redirects, exploit findings, or replace a human penetration test.",
      },
      external_ip_or_domain: {
        title: "External IP addresses or domains",
        summary: "See the services your organization exposes to the public Internet.",
        want:
          "Specific public IP addresses, domains, or hostnames that belong to your organization.",
        prepare:
          "An exact target list, ownership or authorization evidence, exclusions, and the allowed scan intensity.",
        productDoes:
          "Checks approved targets for reachable ports and services, then runs only the external checks allowed by the case.",
        productDoesNot:
          "It does not expand the target list on its own, contact neighboring addresses, or treat an unreachable target as secure.",
      },
      internal_it_environment: {
        title: "Your repositories, internal systems, and websites",
        summary: "Check selected code, websites, and specific internal hosts together in one result organized by asset.",
        want:
          "The exact repository folders, website or API URLs, and hostname or IP for each internal system you want checked.",
        prepare:
          "Local project folders, complete website or API URLs, internal hostnames or IPs, and permission to assess every network target. Common ports are selected automatically and can be changed under Advanced.",
        productDoes:
          "Runs applicable upstream code and vulnerability checks against each scan-ready selected asset, keeps target-specific limits, and combines completed results with explicit not-tested inventory in one prioritized report.",
        productDoesNot:
          "It does not scan unlisted addresses, install agents, change code or devices, bypass access controls, or call an inventory-only observation a vulnerability scan.",
      },
      ai_application: {
        title: "An AI app or agent you are building",
        summary: "Find security problems in vibe-coded and AI-assisted project files before deployment.",
        want:
          "The local project for an AI app, agent, or codebase generated or materially changed with AI.",
        prepare:
          "The exact local project folder or read-only repository snapshot you want checked.",
        productDoes:
          "Checks the selected copy locally for risky code, exposed secrets, dependencies, and related deployment files, then adds applicable AIDEFEND references to the results.",
        productDoesNot:
          "It does not upload or change project files, verify discovered secrets against live services, or claim that the app passes AIDEFEND or any compliance framework.",
      },
      source_code: {
        title: "Source code you have written",
        summary: "Find exposed secrets, vulnerable dependencies, risky code, and unsafe configuration locally.",
        want:
          "A local project folder or read-only copy of a repository that you are allowed to assess.",
        prepare:
          "The exact local folder or read-only repository snapshot you want checked.",
        productDoes:
          "Runs the applicable upstream code, secret, dependency, and configuration checks on this device against only the selected read-only copy, masks detected secret values, and never changes project files.",
        productDoesNot:
          "It does not push changes, verify discovered secrets against live services, inspect unselected folders, or prove that the code is bug-free.",
      },
      infrastructure_as_code: {
        title: "Infrastructure as code",
        summary: "Catch risky cloud and deployment settings before they go live.",
        want:
          "The files that describe how cloud or infrastructure resources should be created.",
        prepare:
          "A local read-only project snapshot, including the modules and variable files needed to understand it.",
        productDoes:
          "Checks the selected files locally for risky defaults and configuration mistakes and preserves the exact input snapshot used.",
        productDoesNot:
          "It does not deploy a plan, contact your cloud account, rewrite files, or assume that a clean template matches the live environment.",
      },
      cloud_account: {
        title: "An AWS, Azure, GCP, or Microsoft 365 account",
        summary: "Review the identity and access settings of one selected cloud account or Microsoft 365 tenant.",
        want:
          "One exact AWS account, Azure subscription, GCP project, or Microsoft 365 tenant at a time.",
        prepare:
          "Owner or administrator access to set up read-only access once (the app lists each step), or read-only access someone else set up. Passwords are entered only on the provider's page.",
        productDoes:
          "Lists the console steps for read-only access, opens the provider's official sign-in, checks that the access is read-only and bound to the chosen account, and runs the applicable checks.",
        productDoesNot:
          "It does not accept a client secret in the case UI, keep an administrator credential, change cloud settings, or silently include another account.",
      },
      container_image: {
        title: "A container image",
        summary: "See what is inside an image and which known vulnerabilities need attention.",
        want:
          "The exact image artifact or OCI layout that you build or are authorized to inspect.",
        prepare:
          "A local exported copy of the image with its unique digest. If the image is private, export it before attaching it to the case.",
        productDoes:
          "Analyzes the attached image read-only with pinned offline vulnerability data, records recognized packages, and produces a software inventory (SBOM).",
        productDoesNot:
          "Image execution, registry sign-in, mutable tags such as latest, and unrecognized content are outside this scan.",
      },
      kubernetes: {
        title: "Kubernetes configuration",
        summary: "Find risky workload and node settings before they expose the cluster.",
        want:
          "Kubernetes YAML or an approved, immutable snapshot of the node configuration you want checked.",
        prepare:
          "The selected manifests or snapshot, cluster-owner permission, and confirmation that unrelated secrets have been removed.",
        productDoes:
          "Checks the selected YAML settings against pinned security rules and checks an attached node snapshot against a bounded CIS baseline.",
        productDoesNot:
          "It does not request administrator access to the cluster, mount a live server, change workloads, or continuously monitor the running cluster.",
      },
    },
  },
  "zh-TW": {
    eyebrow: "從最在意的地方開始",
    title: "你想先保護哪裡？",
    description:
      "選一個最接近的情況，產品會整合適合的工具，從設定一路帶你走到有優先順序的改善清單。",
    choiceTitle: "先選一個地方開始",
    choiceDescription: "先從一項開始；其他檢查可從「掃描設定」加入。",
    wantLabel: "你想檢查什麼",
    prepareLabel: "需要準備什麼",
    productDoesLabel: "產品會做什麼",
    productDoesNotLabel: "不會做什麼",
    chooseAction: "設定這項檢查",
    existingCaseAction: "開啟我的掃描",
    scopeNoticeTitle: "網路掃描邊界",
    scopeNotice:
      "網路檢查只會在確認精確目標、檢查類型與限制後開始；進階限制位於「掃描設定」。",
    cards: {
      deployed_website: {
        title: "已經架好的網站或 API",
        summary: "在一個所選網站來源範圍內找出弱點與暴露服務。",
        want: "一個精確的網站或 API 網址，包含要檢查的主機名稱與服務。",
        prepare: "網址，以及可測試整個 scheme://host:port 網站來源範圍的許可；如果只獲准特定路徑，請勿使用此快速設定。",
        productDoes: "對精確獲准的網站來源範圍執行固定版本的 Nuclei 上游自動網站設定，每秒最多 10 次且同時最多 5 次。",
        productDoesNot: "不登入、不送出表單、不跟隨重新導向、不利用發現的弱點，也不能取代人工滲透測試。",
      },
      external_ip_or_domain: {
        title: "外部 IP 或網域",
        summary: "看清楚你的組織在公開網路上暴露了哪些服務。",
        want: "明確屬於你組織的公開 IP、網域或主機名稱。",
        prepare: "精確目標清單、所有權或授權證明、排除項目，以及允許的掃描強度。",
        productDoes: "只檢查核准目標可連線的連接埠與服務，再依案件授權執行外部檢查。",
        productDoesNot: "不自行擴大目標、不掃相鄰 IP，也不會把無法連線說成安全。",
      },
      internal_it_environment: {
        title: "公司的程式碼儲存庫、內部系統與網站",
        summary: "把指定的程式碼、網站與內部主機一起檢查，再依資產查看同一份結果。",
        want: "要檢查的程式碼儲存庫資料夾、網站或 API 網址，以及每個內部系統的主機名稱或 IP。",
        prepare: "本機專案資料夾、完整網站或 API 網址、內部主機名稱或 IP，以及每個網路目標的檢查許可。系統會自動選用常用連接埠，也可在「進階」中修改。",
        productDoes: "對每項已可掃描的資產執行適用的程式碼與弱點檢查，保留各目標限制，再把完成結果與明確的未測試盤點整合成一份有優先順序的報告。",
        productDoesNot: "不掃未列出的位址、不安裝代理程式、不修改程式碼或設備、不繞過存取控制，也不把只有盤點的觀察稱為漏洞掃描。",
      },
      ai_application: {
        title: "正在開發的 AI 應用或 Agent",
        summary: "在部署前找出 vibe coding 與 AI 協作專案檔案裡的資安問題。",
        want: "AI 應用、Agent，或由 AI 生成／大幅修改的本機程式碼專案。",
        prepare: "你想檢查的精確本機專案資料夾或唯讀程式碼儲存庫快照。",
        productDoes: "在本機檢查選定副本的危險程式碼、暴露秘密、相依套件與相關部署檔案，並在適用結果上附上 AIDEFEND 參考座標。",
        productDoesNot: "不會上傳或修改專案檔案、不拿找到的秘密登入線上服務，也不會宣稱應用已通過 AIDEFEND 或任何合規框架。",
      },
      source_code: {
        title: "自己寫的程式碼",
        summary: "在本機找出暴露秘密、有弱點的相依套件、危險程式碼與不安全設定。",
        want: "你有權檢查的本機專案資料夾或唯讀程式碼儲存庫副本。",
        prepare: "你想檢查的精確本機資料夾或唯讀程式碼儲存庫快照。",
        productDoes: "在這台裝置上，以適用的上游工具檢查選定唯讀副本的程式碼、秘密、相依套件與設定，在結果中遮罩找到的秘密值，而且不會修改專案檔案。",
        productDoesNot: "不推送修改、不拿找到的秘密去登入線上服務、不讀未選取資料夾，也不保證程式完全沒有錯誤。",
      },
      infrastructure_as_code: {
        title: "基礎設施程式碼（IaC）",
        summary: "在部署前抓出雲端與基礎設施設定風險。",
        want: "描述雲端或基礎設施應如何建立的檔案。",
        prepare: "本機唯讀專案快照，包含理解設定所需的模組與變數檔。",
        productDoes: "在本機檢查選定檔案裡的危險預設值與設定錯誤，並保留這次使用的精確輸入快照。",
        productDoesNot: "不執行部署、不連你的雲端帳號、不改寫檔案，也不假設乾淨的範本等於線上環境沒問題。",
      },
      cloud_account: {
        title: "AWS、Azure、GCP 或 Microsoft 365 帳號",
        summary: "檢查單一所選雲端帳號或 Microsoft 365 租用戶的身分與存取設定。",
        want: "一次只檢查一個精確的 AWS 帳號、Azure 訂閱、GCP 專案或 Microsoft 365 租用戶。",
        prepare: "能設定一次唯讀存取的擁有者或管理員權限（程式會列出每一步），或別人已為你設定好的唯讀存取。密碼只在雲端服務商的頁面輸入。",
        productDoes: "列出在主控台設定唯讀存取的步驟，開啟雲端服務商的官方登入，確認取得的是綁定所選帳號的唯讀存取，再執行適用檢查。",
        productDoesNot: "案件畫面不收用戶端密鑰、不保存管理員權限、不修改雲端設定，也不會偷偷加入其他帳號。",
      },
      container_image: {
        title: "容器映像",
        summary: "看懂映像包含哪些套件，以及哪些已知弱點要先修。",
        want: "你建立或有權檢查的一份精確本機映像匯出檔。",
        prepare: "帶有唯一內容摘要的本機映像副本；若映像位於私人倉庫，請先匯出再附加到案件。",
        productDoes: "用固定的離線弱點資料唯讀分析映像，記錄辨識到的套件，並產生軟體內容清單（SBOM）。",
        productDoesNot: "不執行映像、不登入映像倉庫、不掃名為 latest 的不確定標籤，也不替無法辨識的內容宣稱已有涵蓋。",
      },
      kubernetes: {
        title: "Kubernetes 設定",
        summary: "找出讓 Kubernetes 工作負載與節點暴露風險的設定。",
        want: "要檢查的 Kubernetes YAML 設定檔，或經核准且不可變更的節點設定快照。",
        prepare: "選定的設定檔或快照、叢集負責人的許可，並確認已移除無關秘密。",
        productDoes: "以固定的安全規則檢查 YAML 設定，並用有限範圍的 CIS 安全基準檢查附加的節點快照。",
        productDoesNot: "不要求叢集管理員權限、不掛載線上主機、不修改工作負載，也不持續監控執行中的叢集。",
      },
    },
  },
};


export const startPageCopy: Record<Locale, StartPageCopy> = {
  ...startPageCopyBase,
  ja: localizeJapanese(startPageCopyBase.en),
};

export const useCaseById = (id: UseCaseId): UseCaseDefinition => {
  const definition = useCaseDefinitions.find((candidate) => candidate.id === id);
  if (!definition) throw new Error(`Unknown use case: ${id}`);
  return definition;
};
