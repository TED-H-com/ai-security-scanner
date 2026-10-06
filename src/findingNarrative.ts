import type {
  AwsIamPolicyFindingDetails,
  BeginnerCoverageStatus,
  BeginnerNextActionCode,
  BenchmarkReference,
  ConfidenceBasisCode,
  ContextFactor,
  FindingFamily,
  Severity,
  SeverityBasisCode,
  UnattributedResults,
} from "./types";

/**
 * Writes the sentences this product says about a finding, in the reader's
 * language.
 *
 * The backend composes the same three sentences in English and stores them on
 * the finding. That happens before any locale is known and the result is frozen
 * into the case, so a zh-TW reader was shown 可能影響 above "If the scanner
 * result is confirmed, ..." — a translated heading over an English paragraph,
 * on the three fields that carry the entire meaning of a finding.
 *
 * Every input the backend composed from is a closed set, so this side can write
 * the same sentence rather than translate the finished one. Two consequences
 * are deliberate:
 *
 *  - English and Chinese are composed from the same structured fields. Legacy
 *    stored prose is normalized so an older case follows the current report
 *    contract too.
 *  - A finding with no code — stored before the codes were carried, or produced
 *    by a build that knows a family this one does not — falls back to that same
 *    English prose. Untranslated is worse than translated and better than blank.
 *
 * The engine's own `title` is not covered. That is the engine's wording; saying
 * it back in another language would be this product speaking for it.
 */

/** The direct possible impact for each finding family. */
const CONSEQUENCE: Record<FindingFamily, string> = {
  cloud_posture: "雲端資源或資料可能遭到未預期的存取、變更或使用",
  cloud_identity: "某個身分可能擁有超出其角色所需的操作權限",
  microsoft365: "Microsoft 365 的身分、郵件、檔案或管理設定的保護可能不足",
  network_exposure: "可從網際網路連線的服務可能暴露非預期的功能或已知弱點",
  source_code: "原始碼或憑證可能導致未授權存取或不安全的程式行為",
  secret: "原始碼或憑證可能導致未授權存取或不安全的程式行為",
  infrastructure_as_code: "之後部署出來的基礎架構會沿用這個不安全的設定",
  vulnerable_component: "容器或軟體元件可能讓工作負載暴露於已知弱點",
  kubernetes: "Kubernetes 叢集或工作負載的隔離或管理保護可能不足",
  model_behavior: "這個模型端點可能會產生它原本應該拒絕的輸出",
  mcp_secret: "MCP 設定中的憑證可能被取得設定檔的人用來未授權存取服務",
  mcp_configuration: "MCP 伺服器程序或工具可能取得超出其用途所需的本機能力",
};

const CONSEQUENCE_ENGLISH: Record<FindingFamily, string> = {
  cloud_posture: "Cloud resources or data may be exposed, changed, or used beyond the organization's intent",
  cloud_identity: "An identity may be able to perform broader actions than its role requires",
  microsoft365: "Microsoft 365 identities, messages, files, or administrative settings may have weaker protection",
  network_exposure: "An internet-reachable service may expose unexpected functionality or a known weakness",
  source_code: "Source code or credentials may permit unauthorized access or unsafe application behavior",
  secret: "Source code or credentials may permit unauthorized access or unsafe application behavior",
  infrastructure_as_code: "Deployed infrastructure may inherit the reported insecure configuration",
  vulnerable_component: "A container or software component may expose the workload to a known weakness",
  kubernetes: "The Kubernetes cluster or workload may have reduced isolation or administrative protection",
  model_behavior: "The model endpoint may produce output it is supposed to refuse",
  mcp_secret: "A credential embedded in MCP configuration may let anyone who obtains that file access the service without authorization",
  mcp_configuration: "An MCP server process or tool may receive broader local capabilities than its purpose requires",
};

/** The secret family's full next step, including the period the report prints. */
export const EXPOSED_CREDENTIAL_NEXT_STEP_ENGLISH =
  "Revoke and rotate the exposed credential, then remove it from the source and every retained history entry.";

/** The Traditional Chinese form of {@link EXPOSED_CREDENTIAL_NEXT_STEP_ENGLISH}. */
export const EXPOSED_CREDENTIAL_NEXT_STEP_ZH_HANT =
  "先撤銷並輪替這組已外洩的憑證，再從原始碼以及仍保留它的歷史紀錄中移除。";

/**
 * The direct recommended action for each finding family.
 *
 * `secret` departs from `source_code` even though they share a consequence. A
 * leaked credential stays valid until it is revoked, so sending the reader to a
 * permissions screen first leaves it valid for exactly that long.
 */
const REMEDY: Record<FindingFamily, string> = {
  cloud_posture: "調整這項檢查所指出的雲端設定或政策",
  cloud_identity: "改用只授予該身分角色所需操作的較小範圍政策",
  microsoft365: "調整這項控制項所檢查的 Microsoft 365 租用戶設定",
  // Used by Nuclei and Greenbone vulnerability findings. Reachability
  // inventory from Naabu/httpx takes the exposure-observation path and
  // never reads this clause. A rated finding whose only backing check
  // did not complete takes the confirm-first action and also never
  // reads this clause.
  network_exposure: "調整這項檢查所指出的服務或設定",
  source_code: "修改程式碼以移除回報的不安全寫法",
  secret: EXPOSED_CREDENTIAL_NEXT_STEP_ZH_HANT.slice(0, -1),
  infrastructure_as_code:
    "修改基礎架構即程式碼的範本，讓重新部署不會再還原這個設定",
  vulnerable_component:
    "將受影響的元件升級到已修正的版本，或記錄目前無法升級的原因",
  kubernetes: "調整這項檢查所指出的工作負載或叢集設定",
  model_behavior:
    "重現這個探測項目，判斷這些回覆是否確實違反該端點的使用政策；若是，請在模型之前或之後加上防護措施",
  mcp_secret:
    "先撤銷並輪替這組憑證，再從 MCP 設定以及仍保留它的歷史紀錄中移除",
  mcp_configuration:
    "移除 MCP 設定中不必要的權限與危險命令旗標，只保留伺服器用途確實需要的能力",
};

const REMEDY_ENGLISH: Record<FindingFamily, string> = {
  cloud_posture: "Correct the cloud setting or policy named by this check",
  cloud_identity: "Replace the affected policy with a narrower policy that grants only the actions the identity's role requires",
  microsoft365: "Correct the Microsoft 365 tenant setting named by this control",
  network_exposure: "Correct the service or configuration named by this check",
  source_code: "Change the code to remove the reported unsafe pattern",
  secret: EXPOSED_CREDENTIAL_NEXT_STEP_ENGLISH.slice(0, -1),
  infrastructure_as_code: "Correct the infrastructure-as-code template so redeployment does not restore the insecure setting",
  vulnerable_component: "Upgrade the affected component to a fixed version; if none is available, record the blocker and track the fix",
  kubernetes: "Correct the workload or cluster setting named by this check",
  model_behavior:
    "Reproduce the probe, decide whether those replies actually breach this endpoint's usage policy, and if so add a guardrail in front of or behind the model",
  mcp_secret:
    "Revoke and rotate the credential, then remove it from the MCP configuration and every retained history entry",
  mcp_configuration:
    "Remove unnecessary permissions and dangerous command flags from the MCP configuration, leaving only the capabilities the server's purpose requires",
};

/** The secret family's remedy, with the period the report prints. */
export const exposedCredentialNextStep = (locale: "en" | "zh-TW"): string =>
  locale === "en" ? EXPOSED_CREDENTIAL_NEXT_STEP_ENGLISH : EXPOSED_CREDENTIAL_NEXT_STEP_ZH_HANT;

const IAM_PRINCIPAL_PREVIEW_LIMIT = 6;

const iamPrincipalLabels = (
  details: AwsIamPolicyFindingDetails,
  locale: "en" | "zh-TW",
): string[] => {
  const [role, group, user] = locale === "en"
    ? ["role", "group", "user"]
    : ["角色", "群組", "使用者"];
  return [
    ...details.attachedTo.roles.map((name) => `${role} ${name}`),
    ...details.attachedTo.groups.map((name) => `${group} ${name}`),
    ...details.attachedTo.users.map((name) => `${user} ${name}`),
  ];
};

/**
 * The attached principals a reader sees, and how many there are. English prose
 * downstream has to agree in number with a one-principal attachment, which is
 * the common case for an inline or customer-managed policy.
 */
const iamPrincipalSummary = (
  details: AwsIamPolicyFindingDetails,
  locale: "en" | "zh-TW",
): { text: string; count: number } | undefined => {
  const labels = iamPrincipalLabels(details, locale);
  if (labels.length === 0) return undefined;
  const count = labels.length;
  const retained = labels
    .slice(0, IAM_PRINCIPAL_PREVIEW_LIMIT)
    .join(locale === "en" ? ", " : "、");
  const omitted = Math.max(0, count - IAM_PRINCIPAL_PREVIEW_LIMIT);
  if (omitted === 0) return { text: retained, count };
  if (locale !== "en") return { text: `${retained}，以及另外 ${omitted} 個主體`, count };
  return {
    text: omitted === 1
      ? `${retained}, and 1 more principal`
      : `${retained}, and ${omitted} more principals`,
    count,
  };
};

export const awsIamPolicySourceLabel = (
  source: AwsIamPolicyFindingDetails["policySource"],
  locale: "en" | "zh-TW",
): string => {
  if (source === "aws_managed") return locale === "en" ? "AWS-managed" : "AWS 受管";
  if (source === "customer_managed") return locale === "en" ? "Customer-managed" : "客戶受管";
  return locale === "en" ? "Inline" : "內嵌";
};

const awsIamPolicyActionZhTW = (details: AwsIamPolicyFindingDetails): string => {
  const principals = iamPrincipalSummary(details, "zh-TW")?.text;
  const attachmentsComplete = details.attachedTo.complete;
  let action: string;
  if (details.policySource === "aws_managed") {
    action = principals
      ? `在${principals}上將 AWS 受管政策 ${details.policyName} 改為權限較小的政策；若不需要則解除附加。AWS 受管政策無法由此帳戶直接編輯`
      : attachmentsComplete
        ? `確認 AWS 受管政策 ${details.policyName} 維持未附加狀態；之後如有需要，應選用權限較小的政策。AWS 受管政策無法由此帳戶直接編輯`
        : `先確認目前有哪些角色、群組與使用者附加了 AWS 受管政策 ${details.policyName}，再改用權限較小的政策；若不需要則解除附加。AWS 受管政策無法由此帳戶直接編輯`;
  } else if (details.policySource === "customer_managed") {
    action = principals
      ? `縮小客戶受管政策 ${details.policyName} 的權限，並確認${principals}只保留工作所需權限`
      : attachmentsComplete
        ? `在客戶受管政策 ${details.policyName} 再次附加或使用前縮小其權限`
        : `先確認客戶受管政策 ${details.policyName} 目前附加到哪些 IAM 主體，再縮小政策權限，並確認每個主體只保留工作所需權限`;
  } else {
    action = principals
      ? `直接在${principals}上縮小內嵌政策 ${details.policyName} 的權限`
      : `確認內嵌政策 ${details.policyName} 所屬的 IAM 主體，並在再次使用前於該處縮小權限`;
  }
  const incomplete = details.attachedTo.complete
    ? ""
    : "請先核對目前的 IAM 附加關係。";
  return `${action}。${incomplete}`;
};

const awsIamPolicyActionEnglish = (details: AwsIamPolicyFindingDetails): string => {
  const summary = iamPrincipalSummary(details, "en");
  const principals = summary?.text;
  const onePrincipal = summary?.count === 1;
  let action: string;
  if (details.policySource === "aws_managed") {
    action = principals
      ? `Replace AWS-managed policy ${details.policyName} with a narrower policy on ${principals}, or detach it where it is not needed; AWS-managed policies cannot be edited by this account`
      : details.attachedTo.complete
        ? `Keep AWS-managed policy ${details.policyName} detached and choose a narrower policy before attaching it; AWS-managed policies cannot be edited by this account`
        : `Identify the current roles, groups, and users attached to AWS-managed policy ${details.policyName}, then replace it with a narrower policy or detach it where it is not needed; AWS-managed policies cannot be edited by this account`;
  } else if (details.policySource === "customer_managed") {
    action = principals
      ? `Narrow customer-managed policy ${details.policyName} and verify that ${principals} ${onePrincipal ? "retains" : "retain"} only the permissions they need`
      : details.attachedTo.complete
        ? `Narrow customer-managed policy ${details.policyName} before it is attached or reused`
        : `Identify the current attachments to customer-managed policy ${details.policyName}, then narrow it and verify that each principal retains only the permissions it needs`;
  } else {
    action = principals
      ? `Narrow inline policy ${details.policyName} directly on ${principals}`
      : `Identify where inline policy ${details.policyName} is owned and narrow it there before reuse`;
  }
  const incomplete = details.attachedTo.complete
    ? ""
    : " Confirm the current IAM attachments first.";
  return `${action}.${incomplete}`;
};

/** The clause completing "This product rated it {severity} from ...". */
const BASIS: Record<SeverityBasisCode, string> = {
  open_port: "開放連接埠的觀察結果，而非缺陷",
  reachable_http_service: "可連線 HTTP 服務的觀察結果，而非缺陷",
  secret_pattern_match: "掃描到的原始碼中符合機密資料的樣式",
  unverified_credential_detector: "憑證偵測器的比對結果",
  iac_policy_check:
    "一項未通過的基礎架構即程式碼政策檢查；因為 Checkov 離線執行時不提供各別檢查的嚴重程度，所以一律採用相同等級",
  cis_kubernetes_benchmark: "一項未通過的 CIS Kubernetes Benchmark 檢查",
  cloud_control_query: "本產品自有固定查詢中一項未通過的 IAM 控制項",
  cloudsplaining_iam_policy_finding:
    "Cloudsplaining 未評定嚴重程度的 IAM 政策問題",
  unrated_vulnerability_test_alarm:
    "Greenbone 弱點測試發出的警示，但固定版本 feed 條目沒有可解析的嚴重程度向量",
  adversarial_probe_failure_rate:
    "garak 偵測器判定為失敗的對抗式探測次數；garak 只提供次數，不提供嚴重程度",
};

const CONFIDENCE_BASIS: Record<ConfidenceBasisCode, string> = {
  deterministic_policy_evaluation: "確定性的政策或設定評估結果",
  advisory_version_match: "已安裝版本符合已發布公告的受影響範圍",
  unverified_pattern_or_detector_match: "樣式或偵測器比對結果",
  observed_response: "本產品直接觀察到的回應",
  template_matcher: "範本比對器在受評估目標上觸發",
  missing_detection_quality_score: "引擎結果中未提供偵測品質分數",
};

export const ALL_CONFIDENCE_BASIS_CODES: readonly ConfidenceBasisCode[] = [
  "deterministic_policy_evaluation",
  "advisory_version_match",
  "unverified_pattern_or_detector_match",
  "observed_response",
  "template_matcher",
  "missing_detection_quality_score",
];

const sourceConfidence = (
  priorityReasons: readonly string[],
): string | undefined =>
  priorityReasons
    .map((reason) => reason.trim())
    .find((reason) => reason.startsWith("Source confidence: "))
    ?.slice("Source confidence: ".length) || undefined;

const sourceSeverity = (
  priorityReasons: readonly string[],
): string | undefined =>
  priorityReasons
    .map((reason) => reason.trim())
    .find((reason) => reason.startsWith("Source severity: "))
    ?.slice("Source severity: ".length) || undefined;

/**
 * True only when an `unknown` finding has no scanner severity to present.
 *
 * Current findings retain a non-empty scanner severity in the exact
 * `Source severity: ...` priority reason. A basis code is stronger evidence
 * that the scanner supplied no severity, including if stale mixed metadata is
 * ever encountered. Keeping this separate from `severityBasisCode` preserves
 * the existing presentation of historical derived High/Medium findings.
 */
export const findingSeverityIsUnrated = (options: {
  severity: Severity;
  severityBasisCode?: SeverityBasisCode;
  priorityReasons?: readonly string[];
}): boolean => options.severity === "unknown" && (
  options.severityBasisCode !== undefined
  || sourceSeverity(options.priorityReasons ?? []) === undefined
);

export const findingConfidencePresentation = (
  locale: "en" | "zh-TW",
  confidenceLabel: string,
  confidenceBasisCode: ConfidenceBasisCode | undefined,
  priorityReasons: readonly string[],
): string => {
  if (confidenceBasisCode) {
    if (confidenceBasisCode === "missing_detection_quality_score") {
      return locale === "en"
        ? `${confidenceLabel} — scanner did not report detection quality`
        : `${confidenceLabel} — 掃描工具未提供偵測品質`;
    }
    const basis = CONFIDENCE_BASIS[confidenceBasisCode];
    if (!basis) return confidenceLabel;
    return locale === "en"
      ? `${confidenceLabel} — this product's rating from ${CONFIDENCE_BASIS_ENGLISH[confidenceBasisCode]}`
      : `${confidenceLabel} — 本產品依據${basis}評定`;
  }
  const source = sourceConfidence(priorityReasons);
  if (!source) return confidenceLabel;
  return locale === "en"
    ? `${confidenceLabel} — engine rating: ${source}`
    : `${confidenceLabel} — 來源工具評定：${source}`;
};

/**
 * The nine specialists the backend recommends, mapped exactly.
 *
 * Matched on the whole string rather than on substrings. The previous helper
 * asked whether the name contained "it", which "security" and "vulnerability"
 * both do, so a Kubernetes finding and a Microsoft 365 finding each told the
 * reader to go find an IT administrator. Sniffing survives only as the fallback
 * for a name this build has never seen.
 */
const EXPERT: Record<string, string> = {
  "Cloud security engineer": "雲端安全工程師",
  "Cloud identity specialist": "雲端身分權限專家",
  "Microsoft 365 security administrator": "Microsoft 365 安全管理員",
  "Network security engineer": "網路安全工程師",
  "Application security engineer": "應用程式安全工程師",
  "Vulnerability manager": "弱點管理負責人",
  "Secrets-response specialist": "機密外洩應變專家",
  "Infrastructure-as-code engineer": "基礎架構即程式碼工程師",
  "Container security engineer": "容器安全工程師",
  "Software supply-chain engineer": "軟體供應鏈工程師",
  "Kubernetes security engineer": "Kubernetes 安全工程師",
  "AI security engineer": "AI 安全工程師",
  // Not from an adapter. A check that timed out is a network or system problem,
  // and the report says so on purpose; letting it fall through would send the
  // reader to a security specialist for a connectivity fault, which is the same
  // misdirection the substring rule used to cause. The generic name is what a
  // finding with no details gets.
  "Network or system administrator": "網路或系統管理員",
  "Security professional": "資安專業人員",
};

export const localizedExpertType = (
  expert: string,
  locale: "en" | "zh-TW",
): string => {
  if (locale === "en") return expert;
  // A name from a build this one has never seen still has to say something, and
  // a general answer beats a confidently wrong one. Kept identical to the Rust
  // fallback rather than sniffed here: two surfaces guessing differently about
  // the same unknown title is the drift this pair exists to avoid.
  return EXPERT[expert.trim()] ?? "資安或 IT 專業人員";
};

/**
 * The engine's display name, read back off the sentence the backend wrote.
 *
 * Taken from the prose rather than looked up so the name in the translated
 * sentence is byte-for-byte the one in the English it replaces — "httpx" and
 * "kube-bench" are lowercase, "Greenbone Community Edition" is three words, and
 * a second source for that would be a second thing to keep in step. Returns
 * undefined on any sentence that is not the shape this product writes, which
 * sends the caller back to the English.
 */
export const engineNameFrom = (englishSummary: string): string | undefined => {
  // The summary is normalized twice: once into the report's English, then
  // again by the exporter for the reader's locale. `" checked this "` is how
  // the control verdict below opens, so recognizing it here keeps the second
  // pass able to re-render in Chinese what the first pass already rewrote.
  const opener = englishSummary.includes(" reported ")
    ? " reported "
    : " checked this ";
  const [name, ...rest] = englishSummary.split(opener);
  if (rest.length === 0 || !name || name.includes(".")) return undefined;
  return name;
};

/** "{engine} reported a {severity}-severity condition on the assessed asset." */
/**
 * The verdict sentence for a control the tenant did not meet.
 *
 * ScubaGear and Maester title a finding with the requirement they checked --
 * "Legacy authentication is blocked", "Privileged accounts use phishing-
 * resistant MFA" -- and only a control that failed becomes a finding at all.
 * Printed as a heading under "Problems found" over a sentence that said no
 * more than "reported a high-severity condition", the requirement read as a
 * statement that the tenant was already in that state, which is the opposite
 * of what the scanner found. The upstream title stays exactly as the scanner
 * wrote it; the verdict goes in the prose this product owns.
 */
const controlVerdict = (
  family: FindingFamily | undefined,
  english: string,
  localeZh: boolean,
): string | undefined => {
  if (family !== "microsoft365") return undefined;
  const engine = engineNameFrom(english);
  if (!engine) return undefined;
  return localeZh
    ? `${engine} 檢查了這項 Microsoft 365 要求，這個租戶未通過。`
    : `${engine} checked this Microsoft 365 requirement and the tenant did not meet it.`;
};

/**
 * Drops the trailing confidence-methodology sentence.
 *
 * The adapter composes the risk summary as "{what the scanner reported} {how
 * this product rated its confidence}". The second half is already on the same
 * card twice: as the labelled `Confidence` field with its basis, and again in
 * the priority reasons. Keeping a third copy spent the one sentence a beginner
 * reads on the product's own rating method instead of on what the scanner
 * found, on 43 of the 45 findings in a 21-engine run.
 */
const withoutConfidenceMethodology = (english: string): string => {
  const openers = [" reported no confidence rating for it.", " reported confidence "];
  const cuts = openers
    .map((opener) => english.indexOf(opener))
    .filter((at) => at >= 0)
    // The sentence opens with the engine's display name, so the cut is the
    // sentence boundary before it. Without a preceding boundary the summary is
    // only the confidence sentence and there is nothing to keep.
    .map((at) => english.slice(0, at).lastIndexOf(". "))
    .filter((end) => end >= 0)
    .map((end) => end + 2);
  if (cuts.length === 0) return english;
  return english.slice(0, Math.min(...cuts)).trimEnd();
};

export const findingSummarySentence = (
  locale: "en" | "zh-TW",
  options: {
    englishFallback: string;
    severity?: Severity;
    severityLabel: string;
    severityBasisCode?: SeverityBasisCode;
    confidenceLabel?: string;
    confidenceBasisCode?: ConfidenceBasisCode;
    priorityReasons?: readonly string[];
    family?: FindingFamily;
  },
): string => {
  const verdict = controlVerdict(options.family, options.englishFallback, locale === "zh-TW");
  if (verdict) return verdict;
  const englishFallback = withoutConfidenceMethodology(options.englishFallback)
    .replace(" The attached raw record is evidence, not an instruction.", "")
    .replace("Severity remains Unknown and requires human review.", "Severity is Unknown.")
    .replace("a credential detector match that this product does not verify", "a credential detector match")
    .replace("an unverified credential detector match", "a credential detector match")
    .replace("an unverified pattern or detector match", "a pattern or detector match");
  if (locale === "en") return englishFallback;
  const { severityLabel, severityBasisCode } = options;
  const unratedSeverity = options.severity !== undefined && findingSeverityIsUnrated({
    severity: options.severity,
    severityBasisCode,
    priorityReasons: options.priorityReasons,
  });
  const engineName = engineNameFrom(englishFallback);
  if (!engineName) return englishFallback;
  let summary: string;
  if (unratedSeverity) {
    summary = `${engineName} 回報了這項狀況，但未評定嚴重程度。嚴重程度為未知。`;
  } else if (!severityBasisCode) {
    summary = `${engineName} 在受評估的資產上回報了一項${severityLabel}等級的狀況。`;
  } else {
    const basis = BASIS[severityBasisCode];
    if (!basis) return englishFallback;
    summary = `${engineName} 在受評估的資產上回報了這項狀況，但未評定嚴重程度。本產品依據${basis}，將它評為${severityLabel}。`;
  }
  // The English twin drops the same sentence. The confidence rating, its
  // basis, and the engine's own lack of one are already the labelled
  // confidence field and a priority reason on this same card.
  return summary;
};

/**
 * The case-specific clauses the backend appends to `possible_impact`.
 *
 * They are appended to the English rather than composed into it, so a surface
 * that rewrites the impact sentence replaces the string they live in and drops
 * them unless it puts them back. That is not a missing translation but a
 * missing fact: the same case raised this finding's priority by up to ten
 * points, and these are the only text saying why.
 */
const CONTEXT: Record<ContextFactor, string> = {
  internet_exposed_asset:
    "受影響的資產可從網際網路存取，因此可被觸及的攻擊面較大。",
  sensitive_data_asset:
    "受影響的資產含有敏感資料，因此問題造成的影響可能更高。",
};

const CONTEXT_ENGLISH: Record<ContextFactor, string> = {
  internet_exposed_asset:
    " The affected asset is internet-accessible, increasing the reachable attack surface.",
  sensitive_data_asset:
    " The affected asset contains sensitive data, increasing the potential impact.",
};

const directLegacyImpact = (english: string): string => {
  let normalized = english.trim()
    .replace(/^If the scanner result is confirmed, /u, "")
    .replace(/ The (?:critical|high|medium|low|informational|unknown) source severity is not a product-wide compliance score\.$/u, "")
    .replace(/ The scanner did not assign a severity; it remains Unknown for human review\.$/u, "")
    .replace(
      " The affected asset is marked internet-exposed and has only retained non-questionnaire source attribution, which may increase the reachable attack surface; field-level provenance for that attribute is not retained, so it still requires human confirmation.",
      " The affected asset is internet-accessible, increasing the reachable attack surface.",
    )
    .replace(
      " The affected asset is marked as containing sensitive data and has only retained non-questionnaire source attribution, while the case questionnaire separately records sensitive-data context. This may increase the impact of a confirmed exposure, but field-level data-class provenance is not retained and neither entry is itself proof of data exposure.",
      " The affected asset contains sensitive data, increasing the potential impact.",
    );
  if (normalized) normalized = normalized[0]!.toLocaleUpperCase("en") + normalized.slice(1);
  return normalized;
};

/** The direct possible impact and case context. */
export const findingImpactSentence = (
  locale: "en" | "zh-TW",
  options: {
    englishFallback: string;
    severity?: Severity;
    severityLabel: string;
    severityBasisCode?: SeverityBasisCode;
    priorityReasons?: readonly string[];
    family?: FindingFamily;
    contextFactors?: readonly ContextFactor[];
  },
): string => {
  const consequence = options.family
    ? (locale === "en" ? CONSEQUENCE_ENGLISH[options.family] : CONSEQUENCE[options.family])
    : undefined;
  if (!consequence) return directLegacyImpact(options.englishFallback);
  const context = locale === "en" ? CONTEXT_ENGLISH : CONTEXT;
  const ending = locale === "en" ? "." : "。";
  return `${consequence}${ending}${(options.contextFactors ?? [])
    .map((factor) => context[factor] ?? "")
    .join("")}`;
};

/**
 * The one sentence every adapter finding carries before any change is made.
 *
 * Matched exactly rather than inferred from a code. If the adapter's wording
 * ever changes, an exact match falls back to the English -- visible and honest
 * -- where a code would keep confidently printing the old sentence in Chinese.
 * A Rust test pins this string to the one the adapters actually write.
 */
export const ENGLISH_ROLLBACK =
  "Capture the current configuration and test its restoration path before making the change.";

/** "Before any manual change, preserve ... and document a tested restoration path." */
export const findingRollbackSentence = (
  locale: "en" | "zh-TW",
  english: string,
): string => {
  const normalized = english.trim() === "Before any manual change, preserve the current approved configuration and document a tested restoration path."
    ? ENGLISH_ROLLBACK
    : english;
  if (locale === "en" || normalized.trim() !== ENGLISH_ROLLBACK) return normalized;
  return "變更前先保存目前設定，並測試還原路徑。";
};

const OPAQUE_RULE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * "Rerun {engine} with the same scope after the change and confirm source rule {rule} is no
 * longer reported."
 *
 * Read back off the sentence for the same reason `engineNameFrom` is: the
 * engine's display name and the source rule id are the engine's own strings and
 * have to appear in the Chinese exactly as they do in the English. Returns the
 * English unchanged for any sentence not in this shape.
 *
 * When the rule is opaque -- a UUID, as KICS names every query -- and a title
 * is given, the sentence names the title instead: the rule stays in the
 * evidence, and the reader recognises the title.
 */
export const findingVerificationSentence = (
  locale: "en" | "zh-TW",
  english: string,
  title?: string,
): string => {
  const LEGACY_RERUN = "After an approved manual change, rerun ";
  const LEGACY_SCOPE = " with the same authorized scope and confirm that source rule ";
  const RERUN = "Rerun ";
  const SCOPE = " with the same scope after the change and confirm that source rule ";
  const TAIL = " is no longer reported.";
  const trimmed = english.trim();
  const legacy = trimmed.startsWith(LEGACY_RERUN);
  const prefix = legacy ? LEGACY_RERUN : RERUN;
  const scope = legacy ? LEGACY_SCOPE : SCOPE;
  if (!trimmed.startsWith(prefix) || !trimmed.endsWith(TAIL)) return english;
  const middle = trimmed.slice(prefix.length, trimmed.length - TAIL.length);
  const at = middle.indexOf(scope);
  if (at < 0) return english;
  const engine = middle.slice(0, at);
  const rule = middle.slice(at + scope.length);
  if (!engine || !rule) return english;
  const trimmedTitle = title?.trim();
  const namedTitle = trimmedTitle && OPAQUE_RULE_ID.test(rule) ? trimmedTitle : undefined;
  if (locale === "en") {
    return namedTitle
      ? `Rerun ${engine} with the same scope after the change and confirm that “${namedTitle}” is no longer reported.`
      : `Rerun ${engine} with the same scope after the change and confirm that source rule ${rule} is no longer reported.`;
  }
  return namedTitle
    ? `變更後以相同範圍重新執行 ${engine}，並確認「${namedTitle}」不再被回報。`
    : `變更後以相同範圍重新執行 ${engine}，並確認來源規則 ${rule} 不再被回報。`;
};

/**
 * The name a reader sees for one problem.
 *
 * ScubaGear and Maester title every control for the state that passes, and
 * only a failed control becomes a finding. Printed alone, that title reads as
 * a pass. Other families keep the engine's own title.
 */
export const findingHeadline = (
  locale: "en" | "zh-TW",
  title: string,
  family?: FindingFamily,
): string => {
  if (family !== "microsoft365") return title;
  return locale === "en" ? `Requirement not met: ${title}` : `未符合要求：${title}`;
};

/**
 * The line under a next step that covers more than one problem.
 *
 * Shared means every merged finding is fixed by the one specific change the
 * action names. Otherwise the action is one kind of change that each problem
 * still has to receive in its own place.
 */
export const stepGroupLead = (
  locale: "en" | "zh-TW",
  count: number,
  sharedFix: boolean,
  reason: string,
): string => {
  if (sharedFix) {
    return locale === "en"
      ? `${count} problems name this same fix. The first is ${reason}`
      : `有 ${count} 項問題指向同一個修復方式，第一項是 ${reason}`;
  }
  return locale === "en"
    ? `${count} related problems call for this kind of change; each needs its own fix. The first is ${reason}`
    : `有 ${count} 項相關問題需要這類處理，每一項都要分別修正；第一項是 ${reason}`;
};

/**
 * How the reader confirms the step.
 *
 * One problem uses that finding's own verification sentence when one was
 * retained. Several problems only share a kind of change, so confirmation is
 * a rerun of the same scan.
 */
export const stepConfirmation = (
  locale: "en" | "zh-TW",
  verification: string | undefined,
  title: string,
  problems: number,
): string => {
  if (problems > 1) {
    return locale === "en"
      ? "Rerun the same scan after the changes and confirm these problems are no longer reported."
      : "修正後以相同範圍重新掃描，確認這些問題不再被回報。";
  }
  const guidance = verification?.trim();
  if (guidance) return findingVerificationSentence(locale, guidance, title);
  return locale === "en"
    ? "Rerun the same scan after the change and confirm this problem is no longer reported."
    : "修正後以相同範圍重新掃描，確認這項問題不再被回報。";
};

/**
 * The canonical English basis clauses, as the backend writes them.
 *
 * Held here so a stored priority reason can be recognised by shape. Keyed by
 * the same code the summary sentence uses, and pinned to the Rust definition by
 * a fixture test, because a drifted string would show up as a silently
 * untranslated reason rather than as a failure.
 */
const BASIS_ENGLISH: Record<SeverityBasisCode, string> = {
  open_port: "an open port observation rather than a defect",
  reachable_http_service:
    "a reachable HTTP service observation rather than a defect",
  secret_pattern_match: "a secret pattern match in scanned source",
  unverified_credential_detector:
    "a credential detector match",
  iac_policy_check:
    "a failed infrastructure-as-code policy check, rated flat because Checkov publishes no per-check severity offline",
  cis_kubernetes_benchmark: "a failed CIS Kubernetes Benchmark check",
  cloud_control_query:
    "a failed IAM control from this product's own fixed query",
  cloudsplaining_iam_policy_finding:
    "an IAM policy finding Cloudsplaining did not rate",
  unrated_vulnerability_test_alarm:
    "a Greenbone vulnerability-test alarm whose pinned feed entry carries no parseable severity vector",
  adversarial_probe_failure_rate:
    "a count of adversarial probe attempts a garak detector judged as failures, which garak publishes without a severity",
};

const CONFIDENCE_BASIS_ENGLISH: Record<ConfidenceBasisCode, string> = {
  deterministic_policy_evaluation:
    "a deterministic policy or configuration evaluation",
  advisory_version_match:
    "an installed-version match against a published advisory range",
  unverified_pattern_or_detector_match:
    "a pattern or detector match",
  observed_response: "a response this product observed directly",
  template_matcher: "a template matcher firing on the assessed target",
  missing_detection_quality_score:
    "the absence of a detection-quality score in the engine result",
};

/** The one priority reason every adapter finding carries. */
export const ENGLISH_EVIDENCE_REASON =
  "Direct scanner evidence is attached.";
export const isEvidenceOnlyPriorityReason = (reason: string): boolean =>
  reason.trim() === ENGLISH_EVIDENCE_REASON
  || reason.trim() === "Direct scanner evidence is attached and still requires human review.";
export const ENGLISH_EXPOSURE_OBSERVATION_REASON =
  "Classified as a reachable-service inventory observation, not a vulnerability.";

/** The two reasons `apply_case_context` pushes when the case raises a finding. */
const ENGLISH_INTERNET_REASON =
  "The affected asset is internet-accessible.";
const ENGLISH_SENSITIVE_REASON =
  "The affected asset contains sensitive data, increasing the potential impact.";
const LEGACY_ENGLISH_INTERNET_REASON =
  "An affected asset is marked internet-exposed, and all retained source attribution for that asset is non-questionnaire.";
const LEGACY_ENGLISH_SENSITIVE_REASON =
  "An affected asset is marked sensitive, all retained source attribution for that asset is non-questionnaire, and the case questionnaire separately records sensitive-data context.";

/**
 * Stored when this product orders a character-mix password check below the
 * scanner's severity. Recognised by exact trimmed equality; never reclassified here.
 */
export const PASSWORD_COMPOSITION_ORDER_REASON =
  "Placed lower than its severity suggests. CIS AWS Foundations Benchmark v1.2.0 asks for this character rule, but later CIS versions dropped it and NIST SP 800-63B-4 says not to require character mixes. Check password length and MFA first; change this only if an audit you must pass still requires it.";
/**
 * Stored when this product orders a scheduled password-expiry check below the
 * scanner's severity. Recognised by exact trimmed equality; never reclassified here.
 */
export const PASSWORD_EXPIRY_ORDER_REASON =
  "Placed lower than its severity suggests. CIS AWS Foundations Benchmark v1.2.0 asks for scheduled password expiry, but later CIS versions dropped it and NIST SP 800-63B-4 says to force a change only when there is evidence a password was compromised. Change this only if an audit you must pass still requires it.";

/**
 * "Why this order", in the reader's language.
 *
 * priorityReasons is a bare string list with no per-entry code, so each entry
 * is recognised by its shape. Anything this build cannot identify is returned
 * unchanged: a reason is the product's account of why it placed a finding
 * where it did, including a place lower than the severity suggests, and
 * printing a confident Chinese sentence for text it cannot read would
 * be inventing that account.
 */
export const findingPriorityReason = (
  locale: "en" | "zh-TW",
  english: string,
): string => {
  const UNRATED_PREFIX = "Severity remains Unknown because ";
  const UNRATED_TAIL = " did not assign one; human review is required.";
  const CURRENT_UNRATED_PREFIX = "Severity is Unknown because ";
  const CURRENT_UNRATED_TAIL = " did not provide a rating.";
  const original = english.trim();
  const legacyEngine = original.startsWith(UNRATED_PREFIX) && original.endsWith(UNRATED_TAIL)
    ? original.slice(UNRATED_PREFIX.length, original.length - UNRATED_TAIL.length)
    : undefined;
  const normalized = legacyEngine
    ? `${CURRENT_UNRATED_PREFIX}${legacyEngine}${CURRENT_UNRATED_TAIL}`
    : original === LEGACY_ENGLISH_INTERNET_REASON
      ? ENGLISH_INTERNET_REASON
      : original === LEGACY_ENGLISH_SENSITIVE_REASON
        ? ENGLISH_SENSITIVE_REASON
        : english
          .replace("a credential detector match that this product does not verify", "a credential detector match")
          .replace("an unverified credential detector match", "a credential detector match")
          .replace("an unverified pattern or detector match", "a pattern or detector match");
  const trimmed = normalized.trim();
  if (locale === "en") return normalized;
  if (trimmed === PASSWORD_COMPOSITION_ORDER_REASON)
    return "處理順序比嚴重程度所示更後面。CIS AWS Foundations Benchmark v1.2.0 要求這項字元規則，但之後的 CIS 版本已移除，NIST SP 800-63B-4 也要求不要強制混合字元類型。請先確認密碼長度與 MFA；只有在必須通過的稽核仍要求這項規則時，才需要變更。";
  if (trimmed === PASSWORD_EXPIRY_ORDER_REASON)
    return "處理順序比嚴重程度所示更後面。CIS AWS Foundations Benchmark v1.2.0 要求密碼定期到期，但之後的 CIS 版本已移除，NIST SP 800-63B-4 也規定只有在有證據顯示密碼已外洩時，才強制更換。只有在必須通過的稽核仍要求這項規則時，才需要變更。";
  if (trimmed === ENGLISH_EVIDENCE_REASON)
    return "已附上掃描工具的直接證據。";
  if (trimmed === ENGLISH_EXPOSURE_OBSERVATION_REASON)
    return "這是可連線服務的盤點觀察，不是漏洞。";
  if (trimmed === ENGLISH_INTERNET_REASON || trimmed === LEGACY_ENGLISH_INTERNET_REASON)
    return "受影響的資產可從網際網路存取。";
  if (trimmed === ENGLISH_SENSITIVE_REASON || trimmed === LEGACY_ENGLISH_SENSITIVE_REASON)
    return "受影響的資產含有敏感資料，因此問題造成的影響可能更高。";
  // The engine's own raw severity word, kept verbatim. Restating "high" as 高
  // would stop it matching what the reader sees in the engine's own output.
  const SOURCE = "Source severity: ";
  if (trimmed.startsWith(SOURCE)) {
    const value = trimmed.slice(SOURCE.length);
    if (value) return `來源工具評定的嚴重程度：${value}`;
  }
  if (
    legacyEngine
    || (trimmed.startsWith(CURRENT_UNRATED_PREFIX) && trimmed.endsWith(CURRENT_UNRATED_TAIL))
  ) {
    const engine = legacyEngine ?? trimmed.slice(
      CURRENT_UNRATED_PREFIX.length,
      trimmed.length - CURRENT_UNRATED_TAIL.length,
    );
    if (engine) return `嚴重程度為未知，因為 ${engine} 未提供評級。`;
  }
  const SOURCE_CONFIDENCE = "Source confidence: ";
  if (trimmed.startsWith(SOURCE_CONFIDENCE)) {
    const value = trimmed.slice(SOURCE_CONFIDENCE.length);
    if (value) return `來源工具評定的信心：${value}`;
  }
  const CONFIDENCE_DERIVED = "Confidence derived from ";
  const CONFIDENCE_TAIL = " reports no confidence of its own.";
  if (
    trimmed.startsWith(CONFIDENCE_DERIVED) &&
    trimmed.endsWith(CONFIDENCE_TAIL)
  ) {
    const middle = trimmed.slice(
      CONFIDENCE_DERIVED.length,
      trimmed.length - CONFIDENCE_TAIL.length,
    );
    const at = middle.lastIndexOf("; ");
    if (at < 0) return english;
    const basisText = middle.slice(0, at);
    const engine = middle.slice(at + 2);
    const code = (
      Object.keys(CONFIDENCE_BASIS_ENGLISH) as ConfidenceBasisCode[]
    ).find((key) => CONFIDENCE_BASIS_ENGLISH[key] === basisText);
    if (!code || !engine) return english;
    return `信心是由${CONFIDENCE_BASIS[code]}推導而來；${engine} 本身不提供信心評定。`;
  }
  const DERIVED = "Severity derived from ";
  const TAIL = " reports no severity of its own.";
  if (!trimmed.startsWith(DERIVED) || !trimmed.endsWith(TAIL)) return english;
  const middle = trimmed.slice(DERIVED.length, trimmed.length - TAIL.length);
  // No basis text contains "; ", so the last one separates basis from engine.
  const at = middle.lastIndexOf("; ");
  if (at < 0) return english;
  const basisText = middle.slice(0, at);
  const engine = middle.slice(at + 2);
  const code = (Object.keys(BASIS_ENGLISH) as SeverityBasisCode[]).find(
    (key) => BASIS_ENGLISH[key] === basisText,
  );
  if (!code || !engine) return english;
  return `嚴重程度是由${BASIS[code]}推導而來；${engine} 本身不提供嚴重程度。`;
};

/** The first stored reason that places a password-policy check below its severity. */
export const priorityGuidanceReason = (reasons: readonly string[]): string | undefined => {
  for (const reason of reasons) {
    const trimmed = reason.trim();
    if (trimmed === PASSWORD_COMPOSITION_ORDER_REASON || trimmed === PASSWORD_EXPIRY_ORDER_REASON) {
      return trimmed;
    }
  }
  return undefined;
};

/**
 * One benchmark line for the references a scanner reported.
 * At most three groups; an empty list produces no line.
 */
export const benchmarkLine = (
  locale: "en" | "zh-TW",
  engine: string,
  benchmarks: readonly BenchmarkReference[],
): string | undefined => {
  if (benchmarks.length === 0) return undefined;
  const groups: Array<{ name: string; reference: string; versions: string[] }> = [];
  for (const benchmark of benchmarks) {
    const group = groups.find((candidate) =>
      candidate.name === benchmark.name && candidate.reference === benchmark.reference);
    if (!group) {
      groups.push({ name: benchmark.name, reference: benchmark.reference, versions: [benchmark.version] });
      continue;
    }
    if (!group.versions.includes(benchmark.version)) group.versions.push(benchmark.version);
  }
  const shown = groups.slice(0, 3);
  const hidden = groups.length - shown.length;
  const body = shown.map((group) => {
    const versions = group.versions.join("/");
    return locale === "en"
      ? `${group.name} ${versions} item ${group.reference}`
      : `${group.name} ${versions} 第 ${group.reference} 項`;
  }).join(locale === "en" ? "; " : "；");
  const more = hidden > 0
    ? (locale === "en" ? ` and ${hidden} more` : `，另有 ${hidden} 項`)
    : "";
  const reportedBy = locale === "en"
    ? ` (reported by ${engine})`
    : `（${engine} 回報）`;
  return `${body}${more}${reportedBy}`;
};

/**
 * The three strings of an unattributed-results coverage gap.
 *
 * Composed from the structured payload rather than translated from the
 * English, for the same reason every other pair in this file is: the provider
 * and the identifier are the engine's own strings, have to read identically in
 * both languages, and the identifier is the thing the reader copies onto their
 * asset. Legacy English wording is normalized before it is displayed.
 */
export const findingUnattributedGap = (
  locale: "en" | "zh-TW",
  engineId: string,
  unattributed: UnattributedResults,
  english: { dimension: string; reason: string; nextAction: string },
): { dimension: string; reason: string; nextAction: string } => {
  if (locale === "en") return english;
  const { provider, identifier, discardedResults } = unattributed;
  return {
    dimension: `${engineId}：針對 ${provider} ${identifier} 的結果`,
    reason: `${engineId} 回報了 ${discardedResults} 筆針對 ${provider} 識別碼 ${identifier} 的結果。你已授權的資產都沒有登記這個識別碼，因此這些結果都沒有被歸屬，也不會出現在這份報告中。`,
    nextAction: `請在你已授權的資產上，新增 ${provider} 識別碼 ${identifier}，然後重新掃描。`,
  };
};

/**
 * The check a task-level coverage row is about, and whether the row stands for
 * all of it. The backend names these rows `"{check}: {state}"`, and the state --
 * failed, timed out, cancelled, not tested -- is what the row's own sentence
 * already says, so the check alone names the row. A partly completed check's
 * row is only the part it did not finish (`false`). `task_state_check` is the
 * Rust twin.
 */
const taskStateCheck = (dimension: string): [string, boolean] | undefined => {
  const separator = dimension.indexOf(": ");
  if (separator < 0) return undefined;
  const check = dimension.slice(0, separator).trim();
  if (!check) return undefined;
  switch (dimension.slice(separator + 2)) {
    case "failed check dimension":
    case "timed-out check dimension":
    case "cancelled check dimension":
    case "not-tested check dimension":
      return [check, true];
    case "remaining requested dimensions":
      return [check, false];
    default:
      return undefined;
  }
};

/**
 * The name a coverage row is speaking about, in the reader's language.
 *
 * This lives here rather than beside the page that shows it because the shared
 * HTML report names the same rows, and Rust has to compose the identical
 * sentence there. `coverage_dimension_zh_hant` and
 * `coverage_dimension_english` are its twins.
 *
 * English keeps the backend's wording except for a row about a whole check,
 * which is named by the check: "Nuclei", not "Nuclei: failed check dimension".
 *
 * Most of these names are composed at runtime around an identifier -- a check
 * id, an engine id, or the label a person wrote on an exclusion -- and the
 * identifier is the only thing telling one row from the next. So the kind is
 * translated and the identifier carried through untouched, rather than the
 * whole phrase being replaced by a fixed label.
 *
 * An unrecognized name keeps its original text behind a marker. Untranslated
 * detail is worth more than fluent erasure: a person can search their scanner's
 * own output for "cloudquery", and cannot search it for a label this product
 * invented.
 */
export const localizedCoverageDimension = (
  dimension: string,
  locale: "en" | "zh-TW",
): string => {
  const taskState = taskStateCheck(dimension);
  if (taskState) {
    const [check, whole] = taskState;
    if (locale === "en") return whole ? check : `${check}: unfinished part`;
    return whole ? `${check} 檢查` : `${check} 未完成的部分`;
  }
  if (locale === "en") return dimension;
  const lower = dimension.toLocaleLowerCase("en");

  const noVerdictSeparators = [": no verdict for ", ": manual review for "];
  const noVerdictSeparator = noVerdictSeparators.find((separator) => dimension.includes(separator));
  const noVerdictAt = noVerdictSeparator ? dimension.indexOf(noVerdictSeparator) : -1;
  if (noVerdictSeparator && noVerdictAt > 0) {
    const check = dimension.slice(0, noVerdictAt);
    const control = dimension.slice(noVerdictAt + noVerdictSeparator.length);
    if (control) return `${check}：未回傳判定的控制項 ${control}`;
  }

  // Fixed names, in the order the more specific one has to be tried first:
  // "completed planned scan batches" is a substring of the partly-completed one.
  for (const [needle, label] of [
    ["tcp reachability", "TCP 連線狀態"],
    ["bounded connection contract", "受限的連線檢查"],
    ["nuclei upstream website scan", "Nuclei 上游網站掃描"],
    ["greenbone remote vulnerability scan", "Greenbone 遠端弱點掃描"],
    ["internal-device tls vulnerability checks", "內部設備 TLS 弱點檢查"],
    ["internal-device scan-profile coverage", "內部設備掃描設定檔涵蓋記錄"],
    ["ssh service vulnerability checks", "SSH 服務弱點檢查"],
    ["ssh endpoint scan-profile coverage", "SSH 端點掃描設定檔涵蓋記錄"],
    ["rdp transport security checks", "RDP 傳輸安全性檢查"],
    [
      "rdp transport endpoint scan-profile coverage",
      "RDP 傳輸端點掃描設定檔涵蓋記錄",
    ],
    [
      "rdp implementation, authentication/nla, and endpoint host coverage",
      "RDP 實作、驗證／NLA 與端點主機涵蓋範圍",
    ],
    ["vnc transport security check", "VNC 傳輸安全性檢查"],
    [
      "vnc transport endpoint scan-profile coverage",
      "VNC 傳輸端點掃描設定檔涵蓋記錄",
    ],
    [
      "vnc implementation, authentication, and endpoint host coverage",
      "VNC 實作、驗證與端點主機涵蓋範圍",
    ],
    [
      "smtp cleartext-login and tls security checks",
      "SMTP 明文登入與 TLS 安全性檢查",
    ],
    [
      "smtp fixed security profile attempt",
      "SMTP 固定安全設定檔嘗試",
    ],
    [
      "smtp tls checks with selected-run evidence",
      "具有所選本輪證據的 SMTP TLS 檢查",
    ],
    [
      "smtp tls negotiation-dependent coverage",
      "需成功協商 TLS 的 SMTP 涵蓋範圍",
    ],
    [
      "smtp endpoint scan-profile coverage",
      "SMTP 端點掃描設定檔涵蓋記錄",
    ],
    [
      "smtp server behavior, implementation, and endpoint host coverage",
      "SMTP 伺服器行為、實作與端點主機涵蓋範圍",
    ],
    ["telnet cleartext-login security check", "Telnet 明文登入安全性檢查"],
    [
      "telnet endpoint scan-profile coverage",
      "Telnet 端點掃描設定檔涵蓋記錄",
    ],
    [
      "telnet authentication, implementation, and endpoint host coverage",
      "Telnet 驗證、實作與端點主機涵蓋範圍",
    ],
    [
      "endpoint operating-system, package, application, and local-configuration coverage",
      "端點作業系統、套件、應用程式與本機設定涵蓋範圍",
    ],
    ["supported vulnerability profile", "可用的弱點掃描設定"],
    [
      "device product and firmware vulnerability coverage",
      "設備產品與韌體弱點涵蓋範圍",
    ],
    ["completed check-to-target coordinate", "完成的目標檢查"],
    ["aws services other than iam", "IAM 以外的 AWS 服務"],
    ["azure services other than iam", "IAM 以外的 Azure 服務"],
    [
      "google cloud settings other than four iam checks",
      "四項 IAM 檢查以外的 Google Cloud 設定",
    ],
    [
      "microsoft 365 products other than entra id",
      "Entra ID 以外的 Microsoft 365 產品",
    ],
    ["requested scan stage", "要求的掃描深度"],
    ["requested limits", "要求的掃描限制"],
    ["scope reduction", "自動縮減的範圍"],
    ["truncation", "自動縮減的範圍"],
    ["target label", "目標的歷史顯示資料"],
    ["target type", "目標的歷史顯示資料"],
    ["finding presentation", "本輪問題顯示資料"],
    ["request outcome", "掃描結果資料一致性"],
    ["recorded finding wording", "記錄的問題說明文字"],
    ["saved run summary", "保存的掃描摘要"],
    ["partly completed planned scan batches", "部分完成的計畫掃描批次"],
    ["completed planned scan batches", "已完成的計畫掃描批次"],
    ["additional packaged checks", "額外的內建檢查項目"],
    ["requested checks", "要求的檢查項目"],
  ] as const) {
    if (lower.includes(needle)) return label;
  }

  // "{check id} {kind} scan batches ({count})". The count is what makes the row
  // worth reading, so it survives beside the id.
  const counted = /^(.*) \((\d+)\)$/u.exec(dimension);
  if (counted) {
    for (const [suffix, label] of [
      [" partly completed scan batches", "部分完成的掃描批次"],
      [" failed scan batches", "失敗的掃描批次"],
      [" timed-out scan batches", "逾時的掃描批次"],
      [" cancelled scan batches", "已取消的掃描批次"],
      [" not-tested scan batches", "未檢測的掃描批次"],
    ] as const) {
      const head = counted[1] ?? "";
      if (head.endsWith(suffix)) {
        return withCheck(
          head.slice(0, head.length - suffix.length),
          `${label}（${counted[2]}）`,
        );
      }
    }
  }

  // "{check id} {kind}".
  for (const [suffix, label] of [
    [" completed-check time", "檢查完成時間"],
    [" saved scan-batch coverage", "已儲存的掃描批次涵蓋記錄"],
    [" saved result processing", "已儲存結果的處理"],
    [" final-state reconciliation", "最終狀態核對"],
    [" ended after its time limit", "因逾時而結束"],
    [" stopped before finishing", "未完成就停止"],
    [" was cancelled before finishing", "未完成就被取消"],
  ] as const) {
    if (dimension.endsWith(suffix)) {
      return withCheck(
        dimension.slice(0, dimension.length - suffix.length),
        label,
      );
    }
  }

  // "{check id}: {kind}".
  const separator = dimension.indexOf(": ");
  if (separator >= 0) {
    const rest = dimension.slice(separator + 2);
    for (const [fragment, label] of [
      ["expired detection knowledge", "已過期的偵測知識"],
      ["controls not evaluated", "未評估控制項"],
      ["unfinished check dimension", "未完成的檢查項目"],
      ["vulnerability profile evidence", "弱點掃描設定檔證據"],
      ["website execution evidence", "網站執行證據"],
      ["target response", "目標回應"],
      ["service identification", "服務辨識"],
      ["scanner errors", "掃描工具錯誤"],
      ["unsupported target input", "不支援的目標輸入"],
      [
        "connections refused by the rate limit",
        "遭速率限制拒絕的連線",
      ],
      ["destination outside the approved scope", "核准範圍外的目的地"],
      ["unrecorded connection refusals", "未記錄的連線拒絕"],
    ] as const) {
      if (rest === fragment)
        return withCheck(dimension.slice(0, separator), label);
    }
  }

  // "requested check {engine id}", singular: the plural rule above is a
  // different row, about the whole requested list rather than one scanner.
  if (dimension.startsWith("requested check ")) {
    const engine = dimension.slice("requested check ".length);
    if (engine) return `要求的檢查項目：${engine}`;
  }

  return `涵蓋範圍細節：${dimension}`;
};

/**
 * Names the check a composed dimension belongs to, or just the kind when the
 * producer had no id to interpolate.
 */
const withCheck = (check: string, label: string): string => {
  const trimmed = check.trim();
  if (!trimmed) return label;
  return `${trimmed} 的${label}`;
};

/**
 * The sentences a coverage row says, paired with their Traditional Chinese.
 *
 * The backend writes these in English before any locale is known and freezes
 * them into the case, so the English is canonical and this is a lookup rather
 * than a second source of truth. `undefined` means the sentence is not one this
 * product authored -- a case exclusion carries the words a person typed -- and
 * the caller shows the stored text rather than inventing a label for it.
 *
 * `coverage_gap_prose_zh_hant` is the twin. Completeness against the producer
 * is enforced on the Rust side, where a debug assertion in `beginner_report.rs`
 * checks every gap the whole suite builds; the parity test holds this table to
 * that one, English key and Chinese sentence together.
 */
const COVERAGE_GAP_PROSE: ReadonlyArray<readonly [string, string]> = [
  [
    "This check's packaged scanner cannot read this kind of target, so nothing was tested by it.",
    "這項檢查的內建掃描工具無法讀取這類目標，因此沒有測試任何內容。",
  ],
  [
    "Maester evaluated this control but did not return a pass or fail verdict.",
    "Maester 已評估這項控制措施，但未回傳通過或失敗的判定。",
  ],
  [
    "Website security-template evidence unavailable. This website cannot be shown as tested.",
    "網站安全模板證據無法取得；無法確認此網站已測試。",
  ],
  [
    "Host response unavailable. Vulnerability checks did not complete.",
    "主機回應無法取得；弱點檢查未完成。",
  ],
  [
    "Confirm the host is powered on and reachable from this computer on the approved ports, then run this check again.",
    "請確認這台主機已開機，且本機能連到已核准的連接埠，然後再執行一次這項檢查。",
  ],
  [
    "If this host serves a web page, add its full address as a website, then start a new scan.",
    "如果這台主機提供網頁，請把它的完整網址加入為網站，然後開始新的掃描。",
  ],
  [
    "Greenbone reported errors for this host, so its checks cannot be shown as complete.",
    "Greenbone 回報了這台主機的錯誤，因此其檢查不能顯示為已完成。",
  ],
  [
    "No service identified on the approved ports. Vulnerability checks did not run for this host.",
    "已核准的連接埠上沒有辨識出任何服務，因此這台主機沒有執行弱點檢查。",
  ],
  [
    "The saved summary did not match this run's checks, so the report follows the checks.",
    "保存的摘要與這次掃描的檢查不符，因此報告以檢查為準。",
  ],
  [
    "Some findings are shown without the wording this scan recorded.",
    "部分問題顯示的說明不是這次掃描當時記錄的內容。",
  ],
  [
    "This check's own record of what it scanned is unusable, so it cannot be shown as complete.",
    "這項檢查自己對已掃描內容的記錄無法使用，因此不能顯示為已完成。",
  ],
  [
    "This check ran on detection knowledge whose declared support had already ended, so issues published after that date were not tested.",
    "這項檢查執行時所用的偵測知識，其宣告的支援期限已經結束，因此該日期之後才公布的問題並未受測。",
  ],
  [
    "Treat these results as evidence from expired knowledge, not as current coverage.",
    "請將這些結果視為過期知識留下的證據，而不是目前的涵蓋範圍。",
  ],
  [
    "Usable results were saved for these batches, but the rest of their planned addresses and ports were not tested.",
    "這些掃描批次已儲存可用的結果，但其餘計畫中的位址與連接埠並未受測。",
  ],
  [
    "These planned scan batches stopped before establishing completed coverage.",
    "這些計畫中的掃描批次在建立完整涵蓋之前就停止了。",
  ],
  [
    "These planned scan batches reached their bounded time limit before completed coverage was recorded.",
    "這些計畫中的掃描批次在記錄完整涵蓋之前就達到時間上限。",
  ],
  [
    "These planned scan batches were cancelled before completed coverage was recorded.",
    "這些計畫中的掃描批次在記錄完整涵蓋之前就被取消。",
  ],
  [
    "These frozen scan batches have no validated tested outcome in any saved attempt.",
    "這些已凍結的掃描批次，在任何一次已儲存的嘗試中都沒有通過驗證的檢測結果。",
  ],
  [
    "Some of this check's results could not be read, so findings from it may be missing.",
    "這項檢查的部分結果無法讀取，因此這項檢查的問題可能有所遺漏。",
  ],
  [
    "All of this check's planned work produced evidence, but the check timed out before it finished.",
    "這項檢查所有計畫中的工作都已產生證據，但這項檢查在完成之前就逾時。",
  ],
  [
    "All of this check's planned work produced evidence, but the check ended in failure.",
    "這項檢查所有計畫中的工作都已產生證據，但這項檢查以失敗結束。",
  ],
  [
    "All of this check's planned work produced evidence, but the check was cancelled before it finished.",
    "這項檢查所有計畫中的工作都已產生證據，但這項檢查在完成之前就被取消。",
  ],
  [
    "All of this check's planned work produced evidence, but the check never recorded that it finished.",
    "這項檢查所有計畫中的工作都已產生證據，但這項檢查從未記錄自己已完成。",
  ],
  [
    "The check reached its time limit after saving some usable results.",
    "這項檢查在儲存了一部分可用結果之後達到時間上限。",
  ],
  [
    "The check reached its time limit before saving a tested outcome.",
    "這項檢查在儲存任何檢測結果之前就達到時間上限。",
  ],
  [
    "The check stopped after saving some usable results.",
    "這項檢查在儲存了一部分可用結果之後停止。",
  ],
  [
    "The check stopped before saving a tested outcome.",
    "這項檢查在儲存任何檢測結果之前就停止。",
  ],
  [
    "The check was cancelled after saving some usable results.",
    "這項檢查在儲存了一部分可用結果之後被取消。",
  ],
  [
    "The check was cancelled before saving a tested outcome.",
    "這項檢查在儲存任何檢測結果之前就被取消。",
  ],
  [
    "This check did not reach a confirmed complete result.",
    "這項檢查沒有取得可確認的完整結果。",
  ],
  [
    "The bounded check reached its time limit, so it cannot be treated as tested complete.",
    "這項受限的檢查達到時間上限，因此不能視為已完整檢測。",
  ],
  [
    "This check failed, so it cannot be shown as tested.",
    "這項檢查失敗了，因此不能顯示為已測試。",
  ],
  [
    "This check was cancelled before completed coverage was recorded.",
    "這項檢查在記錄完整涵蓋之前就被取消。",
  ],
  [
    "This check did not start, so it is not a pass.",
    "這項檢查沒有啟動，因此不代表通過。",
  ],
  [
    "The app closed while preparing this check. Retry from the saved plan.",
    "應用程式在準備這項檢查時關閉。請從已儲存的計畫重新執行。",
  ],
  [
    "Packaged check list unavailable. Additional checks: not tested.",
    "內建檢查清單無法取得；額外檢查：未測試。",
  ],
  [
    "Some packaged checks could not be loaded. Additional checks: not tested.",
    "部分內建檢查無法載入；額外檢查：未測試。",
  ],
  [
    "At least one target identifier is frozen with the run, but its displayed label or type comes from current project data or is unavailable. The report labels that provenance and does not call it historical fact.",
    "至少有一個目標的識別資料是與本輪一起凍結的，但畫面上顯示的名稱或類型來自目前的專案資料，或是無法取得。報告會標示這項來源，不會把它當成歷史事實。",
  ],
  [
    "This run did not retain an exact reduction record. An empty list therefore cannot be interpreted as proof that no requested dimension was reduced.",
    "本輪沒有保留精確的縮減記錄。因此清單為空，並不能證明沒有任何要求的項目被縮減。",
  ],
  [
    "No exact per-run limits were retained. Current project settings are not substituted for historical requested limits.",
    "沒有保留本輪的精確限制。目前的專案設定不會拿來代替當時要求的限制。",
  ],
  [
    "Recorded stage selection: unavailable. Current project settings: excluded from this historical record.",
    "已記錄的階段選擇：無法取得。目前專案設定：不納入此歷史記錄。",
  ],
  [
    "At least one readable frozen network plan includes full inventory, but another network check has no valid saved plan. Inventory is the highest known stage, not a complete run-wide record.",
    "至少有一份可讀取的凍結網路計畫包含完整清點，但另一項網路檢查沒有有效的已儲存計畫。清點是目前已知的最高階段，不代表整輪的完整記錄。",
  ],
  [
    "Readable frozen network plans contain quick discovery only, but another network check has no valid saved plan. Quick discovery is the highest known stage, not a complete run-wide record.",
    "可讀取的凍結網路計畫只包含快速探索，但另一項網路檢查沒有有效的已儲存計畫。快速探索是目前已知的最高階段，不代表整輪的完整記錄。",
  ],
  [
    "This HTTPS management-service profile contains no device product or firmware vulnerability checks. TLS protocol, cipher, and certificate checks are reported separately.",
    "此 HTTPS 管理服務設定檔不包含設備產品或韌體弱點檢查；TLS 協定、加密套件與憑證檢查會另行回報。",
  ],
  [
    "This HTTPS management-service profile contains no device product or firmware vulnerability checks.",
    "此 HTTPS 管理服務設定檔不包含設備產品或韌體弱點檢查。",
  ],
  [
    "This run does not retain one exact frozen HTTPS management-service profile for this asset. Current project metadata is not used to claim historical TLS coverage.",
    "本輪沒有為此資產保留一份精確凍結的 HTTPS 管理服務設定檔。目前的專案資料不會用來宣稱當時已涵蓋 TLS。",
  ],
  [
    "This run does not retain the exact fixed SSH profile for this asset. Current project metadata is not used to claim historical SSH vulnerability coverage.",
    "本輪沒有為此資產保留精確固定的 SSH 設定檔。目前的專案資料不會用來宣稱當時已完成 SSH 弱點涵蓋。",
  ],
  [
    "The unauthenticated SSH service profile does not inspect operating-system patch level, installed packages or applications, or local host configuration.",
    "這項不需登入的 SSH 服務設定檔，不會檢查作業系統修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定。",
  ],
  [
    "This run does not retain the exact fixed RDP transport profile for this asset. Current project metadata is not used to claim historical RDP transport security coverage.",
    "本輪沒有為此資產保留精確固定的 RDP 傳輸設定檔。目前的專案資料不會用來宣稱當時已完成 RDP 傳輸安全性涵蓋。",
  ],
  [
    "The unauthenticated RDP transport profile checks one legacy RDP 5.2-or-earlier fixed-private-key issue, but does not inspect broader or current RDP implementation CVEs, authentication or Network Level Authentication (NLA), Windows patch level, installed packages or applications, or local host configuration.",
    "這項不需登入的 RDP 傳輸設定檔會檢查一項 RDP 5.2 或更早版本的舊式固定私密金鑰問題，但不會檢查更廣泛或現行的 RDP 實作 CVE、驗證或網路層級驗證（NLA）、Windows 修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定。",
  ],
  [
    "This run does not retain the exact fixed VNC transport profile for this asset. Current project metadata is not used to claim historical VNC transport security coverage.",
    "本輪沒有為此資產保留精確固定的 VNC 傳輸設定檔。目前的專案資料不會用來宣稱當時已完成 VNC 傳輸安全性涵蓋。",
  ],
  [
    "The unauthenticated VNC transport profile checks whether the VNC connection is encrypted. It does not inspect VNC implementation CVEs, authentication strength, operating-system patch level, installed packages or applications, or local host configuration. No login or desktop session was attempted.",
    "這項不需登入的 VNC 傳輸設定檔會檢查 VNC 連線是否加密，但不會檢查 VNC 實作 CVE、驗證強度、作業系統修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定；本輪未嘗試登入或建立桌面工作階段。",
  ],
  [
    "This run does not retain the exact fixed SMTP profile for this asset. Current project metadata is not used to claim historical SMTP security coverage.",
    "本輪沒有為此資產保留精確固定的 SMTP 設定檔。目前的專案資料不會用來宣稱當時已完成 SMTP 安全性涵蓋。",
  ],
  [
    "The unauthenticated SMTP profile reads the banner, issues EHLO, negotiates STARTTLS when offered, and checks advertised AUTH for an unencrypted cleartext-login risk. Its TLS checks apply only when TLS can be negotiated. It does not send credentials or mail, test relay or delivery, authentication enforcement or bypass, anti-spam behavior, general mail-server implementation CVEs, operating-system patches, installed software, or local configuration.",
    "這項不需登入的 SMTP 設定檔會讀取 banner、送出 EHLO、在服務提供時協商 STARTTLS，並檢查服務宣告的 AUTH 是否存在未加密的明文登入風險。只有在能協商 TLS 時才會執行 TLS 檢查。它不會送出帳號或密碼、寄信，也不會測試 relay 或投遞、驗證強制或繞過、anti-spam 行為、一般郵件伺服器實作 CVE、作業系統修補、已安裝軟體或本機設定。",
  ],
  [
    "The SMTP profile ran, but this scan did not record every one of its TLS checks. Which TLS checks ran is shown only by each finding's source OID.",
    "SMTP 設定檔已執行，但這次掃描沒有記錄它的每一項 TLS 檢查。哪些 TLS 檢查已執行，只由各問題的來源 OID 顯示。",
  ],
  [
    "This check did not complete, so its SMTP TLS checks cannot be shown as run. Which TLS checks ran is shown only by each finding's source OID.",
    "這項檢查沒有完成，因此其 SMTP TLS 檢查不能顯示為已執行。哪些 TLS 檢查已執行，只由各問題的來源 OID 顯示。",
  ],
  [
    "This run does not retain the exact fixed Telnet profile for this asset. Current project metadata is not used to claim historical Telnet security coverage.",
    "本輪沒有為此資產保留精確固定的 Telnet 設定檔。目前的專案資料不會用來宣稱當時已完成 Telnet 安全性涵蓋。",
  ],
  [
    "The unauthenticated Telnet profile observes whether a login or password prompt is offered without TLS. It sends no username or password and does not log in; it does not test default credentials, authentication bypass, Telnet implementation CVEs, operating-system patches, installed software, or local configuration.",
    "這項不需登入的 Telnet 設定檔會觀察服務是否在沒有 TLS 的情況下提供登入或密碼提示。它不會送出帳號或密碼，也不會登入；不會測試預設帳密、驗證繞過、Telnet 實作 CVE、作業系統修補、已安裝軟體或本機設定。",
  ],
  [
    "The Greenbone process completed, but this run does not retain one exact reviewed vulnerability profile for every bound asset. Process completion is not counted as a vulnerability result.",
    "Greenbone 程序雖已完成，但本輪沒有為每個綁定資產保留一份精確且經審查的弱點掃描設定檔。因此程序完成不會被算成弱點掃描結果。",
  ],
  [
    "Supported service-specific vulnerability profile unavailable. Outcome: not tested.",
    "支援的服務專屬弱點掃描設定無法取得；結果：未測試。",
  ],
  [
    "Completed-check time: unavailable. Finish and bounded observation times are absent.",
    "已完成檢查時間：無法取得。缺少結束時間與受限觀察時間。",
  ],
  [
    "Start the expected service, then run this check again.",
    "啟動預定的服務，再重新執行這項檢查。",
  ],
  [
    "The port refused the bounded TCP connection at the recorded time; this is not a security pass or failure.",
    "在記錄的時間點，這個連接埠拒絕了受限的 TCP 連線；這不代表安全性通過或失敗。",
  ],
  [
    "Review what was tested before deciding whether you need a broader scan.",
    "請先檢視已檢測的內容，再決定是否需要更大範圍的掃描。",
  ],
  [
    "Actionable findings in completed checks: 0.",
    "已完成檢查中的可處理問題：0。",
  ],
  [
    "No checks ran because this scan has no active permission for a selected target.",
    "沒有執行任何檢查，因為這次掃描對所選目標沒有有效的授權。",
  ],
  [
    "No checks ran because none of the selected targets is confirmed as yours to scan.",
    "沒有執行任何檢查，因為所選目標都尚未確認是你有權掃描的對象。",
  ],
  [
    "No installed check applies to the selected target and permission.",
    "沒有已安裝的檢查同時符合所選目標與授權範圍。",
  ],
  [
    "Review the exact target and permission, then start the scan again.",
    "請確認目標與授權範圍，然後重新開始掃描。",
  ],
  [
    "Choose a target you control, then start the scan again.",
    "請選擇一個你有掌控權的目標，然後重新開始掃描。",
  ],
  [
    "Finish target setup or add a supported input, then start a new scan.",
    "請完成目標設定或加入受支援的輸入，然後重新開始掃描。",
  ],
  [
    "Run this SSH profile again to create a complete coverage record.",
    "重新執行此 SSH 設定檔以建立完整涵蓋記錄。",
  ],
  [
    "Run this RDP profile again to create a complete coverage record.",
    "重新執行此 RDP 設定檔以建立完整涵蓋記錄。",
  ],
  [
    "Run this VNC profile again to create a complete coverage record.",
    "重新執行此 VNC 設定檔以建立完整涵蓋記錄。",
  ],
  [
    "Run this SMTP profile again to create a complete coverage record.",
    "重新執行此 SMTP 設定檔以建立完整涵蓋記錄。",
  ],
  [
    "Run this Telnet profile again to create a complete coverage record.",
    "重新執行此 Telnet 設定檔以建立完整涵蓋記錄。",
  ],
  [
    "Run the HTTPS management-service profile again to create a complete coverage record.",
    "重新執行 HTTPS 管理服務設定檔以建立完整涵蓋記錄。",
  ],
  [
    "Run a separately approved device firmware assessment or use endpoint inventory.",
    "另行執行經核准的裝置韌體評估，或使用端點盤點資料。",
  ],
  [
    "Use an approved endpoint inventory or local snapshot for host-level checks.",
    "使用已核准的端點盤點資料或本機快照進行主機層級檢查。",
  ],
  [
    "Run a separately approved host or RDP-authentication assessment for those checks.",
    "另行執行經核准的主機或 RDP 驗證評估。",
  ],
  [
    "Use an approved endpoint inventory or run a separate authorized VNC assessment.",
    "使用已核准的端點盤點資料，或另行執行已授權的 VNC 評估。",
  ],
  [
    "Run a separately approved mail-server assessment or use endpoint inventory.",
    "另行執行經核准的郵件伺服器評估，或使用端點盤點資料。",
  ],
  [
    "Run a separately approved TLS assessment for complete SMTP TLS coverage.",
    "另行執行經核准的 TLS 評估以取得完整 SMTP TLS 涵蓋。",
  ],
  [
    "Run a separately approved authentication assessment or use endpoint inventory.",
    "另行執行經核准的驗證評估，或使用端點盤點資料。",
  ],
  [
    "Start a new scan and add each exact host under Internal systems.",
    "請開始新的掃描，並在「內部系統」逐一加入要檢查的主機。",
  ],
  [
    "Retry this scan to create a consistent coverage record.",
    "重新執行掃描以建立一致的涵蓋記錄。",
  ],
  [
    "Rerun the scan to create a fully frozen result.",
    "重新執行掃描以建立完全凍結的結果。",
  ],
  [
    "Run this check again to get a usable record.",
    "重新執行這項檢查以取得可用的記錄。",
  ],
  [
    "Retry only the unfinished work.",
    "只重新執行尚未完成的工作。",
  ],
  [
    "Retry only the failed work.",
    "只重新執行失敗的工作。",
  ],
  [
    "Retry only the timed-out work.",
    "只重新執行逾時的工作。",
  ],
  [
    "Restart the cancelled work.",
    "重新啟動已取消的工作。",
  ],
  [
    "Retry the work without a tested outcome.",
    "重試未產生檢測結果的工作。",
  ],
  [
    "Start a new scan for a fresh result.",
    "開始新的掃描以取得新結果。",
  ],
  [
    "Run this check again to confirm the result.",
    "重新執行這項檢查以確認結果。",
  ],
  [
    "Retry only the unfinished work.",
    "只重新執行尚未完成的工作。",
  ],
  [
    "Retry this check for a confirmed result.",
    "重新執行這項檢查以取得可確認的結果。",
  ],
  [
    "Retry the timed-out work.",
    "重新執行逾時的工作。",
  ],
  [
    "Retry this check.",
    "重新執行這項檢查。",
  ],
  [
    "Retry this check to complete the missing coverage.",
    "重新執行這項檢查以完成缺少的涵蓋範圍。",
  ],
  [
    "Review the target and try this check again.",
    "請檢視目標設定，然後重新執行這項檢查。",
  ],
  [
    "This project has no MCP configuration to check. Continue with the other checks.",
    "這個專案沒有可檢查的 MCP 設定；請繼續查看其他檢查。",
  ],
  [
    "Return to scan setup and choose which MCP configuration to check.",
    "回到掃描設定，選擇要檢查的 MCP 設定。",
  ],
  [
    "Return to scan setup and choose the AI workflow framework for inventory.",
    "回到掃描設定，選擇要盤點的 AI 工作流程框架。",
  ],
  [
    "MCP configuration discovery did not finish. Continue with the other checks.",
    "MCP 設定探索未完成；請繼續查看其他檢查。",
  ],
  [
    "Update the app, then retry these checks.",
    "請更新應用程式，再重試這些檢查。",
  ],
  [
    "This version of the app does not include this check.",
    "這個版本的應用程式沒有提供這項檢查。",
  ],
  [
    "Retry this check; scan-tool setup is automatic.",
    "重試這項檢查；掃描工具會自動準備。",
  ],
  [
    "Return to scan setup, choose the intended target, and confirm it once.",
    "回到掃描設定，選擇正確目標並確認一次。",
  ],
  [
    "Return to scan setup and reconnect or review the cloud account.",
    "請回到掃描設定，重新連接或檢查雲端帳號。",
  ],
  [
    "Open the skipped check's technical records and match this check to the approved protocol or target form.",
    "請展開未執行檢查的技術紀錄，讓這項檢查符合已核准的通訊協定或目標形式。",
  ],
  [
    "Update the app, then run these checks again.",
    "請更新應用程式，再重新執行這些檢查。",
  ],
  [
    "Review the upstream detail and record a human decision for this control.",
    "請檢視上游詳細資料，並為這項控制措施記錄人工判定。",
  ],
  [
    "No action for the current scope.",
    "目前範圍不需處理。",
  ],
  // What a cloud or Microsoft 365 check's fixed profile leaves out.
  [
    "This scan checked identity and access (IAM) settings only. Other AWS services, such as S3, EC2, RDS, CloudTrail and GuardDuty, were not checked.",
    "這次掃描只檢查了身分與存取（IAM）設定。其他 AWS 服務（例如 S3、EC2、RDS、CloudTrail、GuardDuty）沒有檢查。",
  ],
  [
    "This scan checked identity and access (IAM) role settings only. Other Azure services, such as Microsoft Entra ID, Storage, Virtual Machines, networking, Key Vault and Microsoft Defender for Cloud, were not checked.",
    "這次掃描只檢查了身分與存取（IAM）角色設定。其他 Azure 服務（例如 Microsoft Entra ID、儲存體、虛擬機器、網路、Key Vault、適用於雲端的 Microsoft Defender）沒有檢查。",
  ],
  [
    "This scan ran four identity and access (IAM) checks only: audit logging, service-account roles granted at the project level, and separation of duties for KMS and service-account roles. Other IAM settings and other Google Cloud services were not checked.",
    "這次掃描只執行了四項身分與存取（IAM）檢查：稽核記錄、在專案層級授予的服務帳戶角色，以及 KMS 與服務帳戶角色的職責分離。其他 IAM 設定與其他 Google Cloud 服務沒有檢查。",
  ],
  [
    "This scan checked Microsoft Entra ID only. Other Microsoft 365 products, such as Exchange Online, Defender for Office 365, SharePoint and OneDrive, and Teams, were not checked.",
    "這次掃描只檢查了 Microsoft Entra ID。其他 Microsoft 365 產品（例如 Exchange Online、Defender for Office 365、SharePoint 與 OneDrive、Teams）沒有檢查。",
  ],
  [
    "Run a full Prowler scan of this account.",
    "請對這個帳號執行完整的 Prowler 掃描。",
  ],
  [
    "Run a full Prowler scan of this subscription.",
    "請對這個訂用帳戶執行完整的 Prowler 掃描。",
  ],
  [
    "Run a full Prowler scan of this Google Cloud project.",
    "請對這個 Google Cloud 專案執行完整的 Prowler 掃描。",
  ],
  [
    "Run ScubaGear with all products for this tenant.",
    "請對這個租用戶執行包含所有產品的 ScubaGear 掃描。",
  ],
  [
    "Some controls in scope were not evaluated, so their state is unknown.",
    "範圍內有部分控制項未經評估，因此狀態未知。",
  ],
  [
    "Check these controls by hand.",
    "請以人工方式檢查這些控制項。",
  ],
  [
    "The approved rate limit refused some of this check's connections, so part of the check never reached the target.",
    "核准的速率限制拒絕了這項檢查的部分連線，因此部分檢查未能送達目標。",
  ],
  [
    "Connections this check attempted outside the approved scope were refused.",
    "這項檢查嘗試在核准範圍以外建立的連線已被拒絕。",
  ],
  [
    "Whether any of this check's connections were refused was not recorded.",
    "這項檢查是否有連線遭到拒絕，並未留下記錄。",
  ],
];

/**
 * One sentence of a coverage row, in the reader's language.
 *
 * English is the stored sentence. Traditional Chinese is that sentence when
 * this product authored it, with a recorded upstream detail, diagnostic code,
 * support-end date, or refused-connection count kept verbatim.
 */
export const coverageGapProse = (
  locale: "en" | "zh-TW",
  english: string,
): string => {
  if (locale === "en") return english;
  const trimmed = english.trim();
  const reviewBase = "Maester evaluated this control but did not return a pass or fail verdict.";
  const reviewDetailPrefix = `${reviewBase} Upstream detail: `;
  if (trimmed.startsWith(reviewDetailPrefix) && trimmed.length > reviewDetailPrefix.length) {
    const base = lookupProse(reviewBase);
    if (base) return `${base}上游詳細資料：${trimmed.slice(reviewDetailPrefix.length)}`;
  }
  // Six reasons gain a diagnostic code when the task recorded one. It is the
  // scanner's own code and stays verbatim; only the sentence around it moves.
  const withCode = /^(.*\.) Diagnostic code: (.+)\.$/u.exec(trimmed);
  if (withCode) {
    const base = lookupProse(withCode[1] ?? "");
    if (base) return `${base}診斷代碼：${withCode[2]}。`;
    return english;
  }
  // The stale-knowledge reason carries the support date the run recorded.
  // Same split as the diagnostic code above: the date is data and stays
  // verbatim, only the sentence around it moves.
  const withSupportEnd = /^(.*\.) Support ended: (.+)\.$/u.exec(trimmed);
  if (withSupportEnd) {
    const base = lookupProse(withSupportEnd[1] ?? "");
    if (base) return `${base}支援結束日期：${withSupportEnd[2]}。`;
    return english;
  }
  // A gateway refusal count is data the cleanup record measured. Same split
  // as the support date: the number stays verbatim, only the sentence moves.
  const withRefusals = /^(.*\.) Refused connections: (\d+)\.$/u.exec(trimmed);
  if (withRefusals) {
    const base = lookupProse(withRefusals[1] ?? "");
    if (base) return `${base}拒絕的連線：${withRefusals[2]}。`;
    return english;
  }
  // Unevaluated controls are counted by kind. Each count is the engine's and
  // stays verbatim; each kind is this product's wording.
  const withUnevaluated = /^(.*\.) Not evaluated: (.+)\.$/u.exec(trimmed);
  if (withUnevaluated) {
    const base = lookupProse(withUnevaluated[1] ?? "");
    if (base) return `${base}未評估：${unevaluatedControlItemsZhTW(withUnevaluated[2] ?? "")}。`;
    return english;
  }
  return lookupProse(trimmed) ?? english;
};

/**
 * The kinds of unevaluated control the Microsoft 365 adapters count, in
 * Traditional Chinese. They are sentence fragments this product wrote, not
 * values an engine reported; only the count in front of each one is the
 * engine's. `UNEVALUATED_CONTROL_KINDS` in `finding_narrative.rs` is the twin.
 */
export const UNEVALUATED_CONTROL_KINDS: ReadonlyArray<readonly [string, string]> = [
  ["left without an automated verdict", "未回傳自動判定"],
  ["omitted by configuration", "依設定略過"],
  ["could not be evaluated", "無法評估"],
  ["skipped", "已略過"],
  ["not run", "未執行"],
  [
    "reported by the engine but not carried into results",
    "掃描工具已回報，但未帶入結果",
  ],
  [
    "not accounted for by any reported category",
    "未計入任何已回報類別",
  ],
];

/**
 * "20 left without an automated verdict, 5 could not be evaluated", item by
 * item. An item another build wrote keeps its own text.
 */
export const unevaluatedControlItemsZhTW = (items: string): string => items
  .split(", ")
  .map((item) => {
    for (const [english, chinese] of UNEVALUATED_CONTROL_KINDS) {
      const count = item.endsWith(` ${english}`)
        ? item.slice(0, item.length - english.length - 1)
        : undefined;
      if (count && /^\d+$/u.test(count)) return `${count} ${chinese}`;
    }
    return item;
  })
  .join("、");

/**
 * `coverageGapProse`, with a trailing diagnostic code removed first.
 *
 * The first-layer summary is not the place for a scanner's internal code --
 * the collapsed coverage-gap list already prints this same reason with its
 * code and the next action, so the code stays available there. A sentence
 * with no code to remove passes through `coverageGapProse` unchanged.
 */
export const coverageGapProseWithoutDiagnosticCode = (
  locale: "en" | "zh-TW",
  english: string,
): string => {
  const withCode = /^(.*\.) Diagnostic code: (.+)\.$/u.exec(english.trim());
  return coverageGapProse(locale, withCode ? withCode[1] ?? english : english);
};

const lookupProse = (english: string): string | undefined =>
  COVERAGE_GAP_PROSE.find(([candidate]) => candidate === english)?.[1];

/**
 * The fixed observations attached to tested dimensions, paired with their
 * Traditional Chinese. The whole stored observation is the lookup key because
 * the backend writes it before any locale is known and freezes it in the case.
 */
const TESTED_OBSERVATION_PROSE: ReadonlyArray<readonly [string, string]> = [
  [
    "Nuclei completed the pinned upstream automatic web profile on the displayed origin. Applied checks: templates selected by upstream technology detection. Eligible-template execution completeness: unavailable.",
    "Nuclei 已對畫面所列網站來源範圍完成固定版本的上游自動網站設定。套用的檢查：由上游技術偵測選取的模板。合格模板執行完整度：無法取得。",
  ],
  [
    "Greenbone completed the frozen remote-safe profile on the displayed host and ports. Applied checks: feed checks selected by upstream service and product prerequisites. Scheduled-VT execution completeness: unavailable.",
    "Greenbone 已對畫面所列主機與連接埠完成凍結的遠端安全掃描設定。套用的檢查：由上游服務與產品先決條件選取的 feed 檢查。排程 VT 執行完整度：無法取得。",
  ],
  [
    "The port accepted the bounded TCP connection.",
    "這個連接埠接受了受限的 TCP 連線。",
  ],
  [
    "The port refused the bounded TCP connection.",
    "這個連接埠拒絕了受限的 TCP 連線。",
  ],
  [
    "The bounded TCP connection attempt timed out; reachability was not established.",
    "受限的 TCP 連線嘗試逾時；無法確認連線可達。",
  ],
  [
    "The native task only observed whether the endpoint accepted, refused, or timed out during the bounded connection attempt. It did not perform a vulnerability test.",
    "這項內建工作只觀察端點在受限的連線嘗試期間，是接受連線、拒絕連線，還是逾時。它沒有執行弱點檢測。",
  ],
  [
    "The durable task reached completed state for this target binding. More granular executed dimensions were not frozen in this case record.",
    "這項已保存的工作已針對這個目標完成。這份案件記錄沒有凍結更細部的執行範圍。",
  ],
  [
    "The completed Greenbone task retained a frozen allowlist containing the profile's TLS protocol, cipher, and certificate vulnerability checks.",
    "已完成的 Greenbone 工作保留了凍結的允許清單，其中包含此設定檔的 TLS 協定、加密套件與憑證弱點檢查。",
  ],
  [
    "The completed Greenbone task retained the exact reviewed SSH profile for deprecated protocol, known or static host key, and weak MAC, encryption, host-key, key-size, or key-exchange choices.",
    "已完成的 Greenbone 工作保留了精確且經過檢視的 SSH 設定檔，用來檢查淘汰的協定、已知或固定的 host key，以及較弱的 MAC、加密、host-key、key size 或 key-exchange 選項。",
  ],
  [
    "The completed Greenbone task retained the exact reviewed RDP transport profile: ten TLS protocol, cipher, and certificate checks plus one check for the legacy fixed private key used by RDP 5.2 or earlier.",
    "已完成的 Greenbone 工作保留了精確且經過檢視的 RDP 傳輸設定檔：十項 TLS 協定、加密套件與憑證檢查，加上一項針對 RDP 5.2 或更早版本所使用之舊式固定私密金鑰的檢查。",
  ],
  [
    "The completed Greenbone task retained the exact reviewed VNC transport profile containing one check for an unencrypted VNC connection.",
    "已完成的 Greenbone 工作保留了精確且經過檢視的 VNC 傳輸設定檔，其中包含一項未加密 VNC 連線檢查。",
  ],
  [
    "The completed Greenbone task retained and attempted the exact SMTP profile: one check reads the banner, sends EHLO, tries STARTTLS when offered, and reviews advertised AUTH for cleartext-login risk; ten more checks depend on TLS. TLS-check execution: evidenced by selected-run source OIDs. Credentials and mail: not sent.",
    "已完成的 Greenbone 工作保留並嘗試執行精確的 SMTP 設定檔：其中一項檢查會讀取 banner、送出 EHLO、在服務提供時嘗試 STARTTLS，並檢視服務宣告的 AUTH 是否有明文登入風險；另有十項檢查依賴 TLS。TLS 檢查執行情況：由所選輪次的來源 OID 提供證據。帳密與郵件：未送出。",
  ],
  [
    "Counted coverage: exact TLS source OIDs in selected-run finding evidence. Each OID evidences only its own check.",
    "計入的涵蓋範圍：所選輪次問題證據中的精確 TLS 來源 OID。每個 OID 只證明自己的檢查。",
  ],
  [
    "The completed Greenbone task retained the exact reviewed Telnet profile, which observes whether a login or password prompt is offered without TLS. No username or password was sent and no login was attempted.",
    "已完成的 Greenbone 工作保留了精確且經過檢視的 Telnet 設定檔，用來觀察服務是否在沒有 TLS 的情況下提供登入或密碼提示。本輪未送出帳號或密碼，也沒有嘗試登入。",
  ],
  [
    "These exact frozen scan batches have validated completed outcomes across all saved attempts. A completed network check reports reachability; it is not a security pass.",
    "這些已凍結的特定掃描批次，在所有已儲存的嘗試中都有通過驗證的完成結果。完成的網路檢查只回報連線是否可達；不代表安全性檢查通過。",
  ],
  [
    "Scan-batch status: Partial. Planned operations remain unfinished.",
    "掃描批次狀態：部分完成；仍有計畫中的操作未完成。",
  ],
];

/** A tested-dimension observation in the reader's language. */
export const testedObservationProse = (
  locale: "en" | "zh-TW",
  english: string,
): string => {
  const trimmed = english.trim();
  if (locale === "en") return trimmed;
  return (
    TESTED_OBSERVATION_PROSE.find(
      ([candidate]) => candidate === trimmed,
    )?.[1] ?? english
  );
};

/**
 * A slot this build fills with a number. Requiring the digits keeps a value
 * composed by some other build from being read as one of these shapes and
 * rearranged into a sentence that says something it does not.
 */
const counted = (value: string): string | undefined =>
  /^\d+$/u.test(value) ? value : undefined;

/**
 * What a coverage row measured, in Traditional Chinese.
 *
 * The third field of a tested row is composed the same way its name is: a
 * fixed phrase the backend authors, wrapped around a count, a port, or the
 * identifier of the asset the row is about. So the phrase is translated and
 * every number and identifier is carried through untouched. Dispatch is on the
 * row's name because that vocabulary is already closed; matching the composed
 * value itself would mean guessing at its shape.
 *
 * `undefined` for a row name this build does not author.
 */
export const testedValueZhHant = (
  dimension: string,
  value: string,
): string | undefined => {
  // Every Greenbone profile row counts its own frozen checks and names the
  // asset. Only the noun differs, so they share one shape.
  const countedProfile = (noun: string, translated: string): string | undefined => {
    const frozenAt = value.indexOf(" frozen ");
    if (frozenAt <= 0) return undefined;
    const count = counted(value.slice(0, frozenAt));
    const rest = value.slice(frozenAt + " frozen ".length);
    const onAsset = `${noun} on asset `;
    if (count === undefined || !rest.startsWith(onAsset)) return undefined;
    const asset = rest.slice(onAsset.length);
    return asset ? `對資產 ${asset} 的 ${count} 項已凍結 ${translated}` : undefined;
  };
  const suffixed = (text: string, suffix: string): string | undefined =>
    text.endsWith(suffix) ? text.slice(0, -suffix.length) : undefined;
  const split = (text: string, separator: string): [string, string] | undefined => {
    const at = text.indexOf(separator);
    return at < 0 ? undefined : [text.slice(0, at), text.slice(at + separator.length)];
  };

  switch (dimension) {
    // An endpoint and a port carry no words to translate.
    case "TCP reachability":
      return value;
    case "bounded connection contract": {
      // The attempt count is the spelled-out word this build writes, not a
      // number, so it is translated rather than carried through.
      const prefix = "one connection attempt; ";
      if (!value.startsWith(prefix)) return undefined;
      const parts = split(value.slice(prefix.length), "; ");
      if (!parts) return undefined;
      const timeoutText = suffixed(parts[0], " ms timeout");
      const payloadText = suffixed(parts[1], " application-payload bytes");
      if (timeoutText === undefined || payloadText === undefined) return undefined;
      const timeout = counted(timeoutText);
      const payload = counted(payloadText);
      if (timeout === undefined || payload === undefined) return undefined;
      return `一次連線嘗試；逾時 ${timeout} 毫秒；應用層酬載 ${payload} 位元組`;
    }
    case "completed check-to-target coordinate": {
      const parts = split(value, " on asset ");
      return parts && parts[0] && parts[1] ? `${parts[0]} 對資產 ${parts[1]}` : undefined;
    }
    case "completed planned scan batches":
    case "partly completed planned scan batches": {
      const parts = split(value, " of ");
      if (!parts) return undefined;
      const done = counted(parts[0]);
      const total = counted(parts[1]);
      return done !== undefined && total !== undefined
        ? `${total} 個中的 ${done} 個`
        : undefined;
    }
    case "internal-device TLS vulnerability checks":
      return countedProfile("Greenbone TLS tests", "Greenbone TLS 檢查");
    case "SSH service vulnerability checks":
      return countedProfile("upstream Greenbone SSH tests", "上游 Greenbone SSH 檢查");
    case "RDP transport security checks":
      return countedProfile(
        "upstream Greenbone RDP transport tests",
        "上游 Greenbone RDP 傳輸檢查",
      );
    case "VNC transport security check":
      return countedProfile(
        "upstream Greenbone VNC transport test",
        "上游 Greenbone VNC 傳輸檢查",
      );
    case "Telnet cleartext-login security check":
      return countedProfile("upstream Greenbone Telnet check", "上游 Greenbone Telnet 檢查");
    case "Nuclei upstream website scan": {
      const prefix = "technology-aware upstream profile on exact website origin for asset ";
      if (!value.startsWith(prefix)) return undefined;
      const asset = value.slice(prefix.length);
      return asset
        ? `依技術偵測選擇的上游設定檔，套用於資產 ${asset} 的確切網站來源`
        : undefined;
    }
    case "Greenbone remote vulnerability scan": {
      const prefix = "applicability-driven upstream profile on asset ";
      if (!value.startsWith(prefix)) return undefined;
      const parts = split(value.slice(prefix.length), " across ");
      if (!parts || !parts[0]) return undefined;
      const portsText = suffixed(parts[1], " approved TCP ports");
      const ports = portsText === undefined ? undefined : counted(portsText);
      return ports === undefined
        ? undefined
        : `依適用性選擇的上游設定檔，套用於資產 ${parts[0]} 的 ${ports} 個已核准 TCP 連接埠`;
    }
    case "SMTP fixed security profile attempt": {
      const prefix = "exact ";
      if (!value.startsWith(prefix)) return undefined;
      const parts = split(
        value.slice(prefix.length),
        "-check upstream Greenbone SMTP profile on asset ",
      );
      if (!parts || !parts[1]) return undefined;
      const count = counted(parts[0]);
      return count === undefined
        ? undefined
        : `對資產 ${parts[1]} 的確切上游 Greenbone SMTP 設定檔，共 ${count} 項檢查`;
    }
    case "SMTP TLS checks with selected-run evidence": {
      const first = split(value, " of ");
      if (!first) return undefined;
      const evidenced = counted(first[0]);
      const second = split(first[1], " selected TLS checks on asset ");
      if (!second || !second[1]) return undefined;
      const total = counted(second[0]);
      return evidenced === undefined || total === undefined
        ? undefined
        : `對資產 ${second[1]} 已選取的 ${total} 項 TLS 檢查中的 ${evidenced} 項`;
    }
    default:
      return undefined;
  }
};

/** A tested-dimension value in the reader's language. */
export const localizedTestedValue = (
  locale: "en" | "zh-TW",
  dimension: string,
  value: string,
): string => (locale === "en" ? value : testedValueZhHant(dimension, value) ?? value);

/** Fixed coverage-ledger explanations shared by the screen and case export. */
const COVERAGE_RECORD_DETAIL_PROSE: ReadonlyArray<readonly [string, string]> = [
  [
    "Choose the AI workflow framework for this repository before running its workflow inventory.",
    "請先選擇這個專案的 AI 工作流程框架，再執行工作流程盤點。",
  ],
  [
    "The source is connected, but no attributable discovery has completed and no assets are known. Coverage is not established.",
    "來源已連線，但尚未完成可歸屬的探索，也沒有已知資產。尚未建立涵蓋。",
  ],
  [
    "The discovered candidate has not had ownership and scope explicitly confirmed. Discovery never authorizes a target automatically.",
    "探索到的候選資產尚未明確確認所有權與範圍。探索本身絕不會自動授權目標。",
  ],
  [
    "The asset has no unexpired, valid scope grant. Discovery never authorizes a target automatically.",
    "此資產沒有尚未到期的有效範圍授權。探索本身絕不會自動授權目標。",
  ],
  [
    "The asset is authorized, but no scan plan is tied to its current effective grants.",
    "此資產已獲授權，但沒有任何掃描計畫連結到目前有效的授權。",
  ],
  [
    "The scan predates frozen scope-grant snapshots, so its historical authorization and permission coverage are unknown. Live grants are never substituted for missing run evidence.",
    "這次掃描早於凍結範圍授權快照的機制，因此無法得知當時的授權與權限涵蓋。絕不會用現行授權補上缺少的執行記錄。",
  ],
  [
    "The asset is authorized, but the latest applicable scan plan contains no engine run for it.",
    "此資產已獲授權，但最近適用的掃描計畫沒有包含它的掃描工具工作。",
  ],
];

const COVERAGE_STATE_APPEND = [
  " This state is independent of how many findings were reported.",
  " 此狀態與回報了多少個問題無關。",
] as const;
const PROVIDER_DISCOVERY_APPEND = [
  " Latest provider discovery: ",
  " 最近一次供應商探索：",
] as const;
const STALE_KNOWLEDGE_APPEND = [
  " Explicit stale-knowledge warning: ",
  " 明確的過時知識警告：",
] as const;
const STALE_KNOWLEDGE_SUFFIX = [
  ". Completion proves execution, not current knowledge.",
  "。完成只證明已執行，不代表知識仍為最新。",
] as const;
const LOCALHOST_ATTEMPT_APPEND = [
  " Exact built-in localhost TCP attempt(s): ",
  " 精確的內建 localhost TCP 嘗試：",
] as const;
const LOCALHOST_ATTEMPT_SUFFIX = [
  ". This records only those connection attempts; it does not establish that the service or computer is secure, and it does not cover other ports or hosts.",
  "。這只記錄這些連線嘗試；無法證明服務或電腦安全，也不涵蓋其他連接埠或主機。",
] as const;

const stripFrame = (
  value: string,
  prefix: string,
  suffix: string,
): string | undefined => {
  if (!value.startsWith(prefix) || !value.endsWith(suffix)) return undefined;
  const end = suffix ? value.length - suffix.length : value.length;
  return value.slice(prefix.length, end);
};

const translateTrailingCoverageFrame = (
  english: string,
  middle: readonly [string, string],
  suffix: readonly [string, string],
): string | undefined => {
  const index = english.lastIndexOf(middle[0]);
  if (index < 0 || !english.endsWith(suffix[0])) return undefined;
  const base = english.slice(0, index);
  const end = suffix[0] ? english.length - suffix[0].length : english.length;
  const retained = english.slice(index + middle[0].length, end);
  if (!retained) return undefined;
  const translatedBase = base ? translateCoverageRecordDetail(base) : "";
  if (base && translatedBase === undefined) return undefined;
  return `${translatedBase ?? ""}${middle[1]}${retained}${suffix[1]}`;
};

const translateCoverageRecordDetail = (english: string): string | undefined => {
  const fixed = COVERAGE_RECORD_DETAIL_PROSE.find(
    ([candidate]) => candidate === english,
  )?.[1];
  if (fixed) return fixed;

  const stale = translateTrailingCoverageFrame(
    english,
    STALE_KNOWLEDGE_APPEND,
    STALE_KNOWLEDGE_SUFFIX,
  );
  if (stale) return stale;
  const localhost = translateTrailingCoverageFrame(
    english,
    LOCALHOST_ATTEMPT_APPEND,
    LOCALHOST_ATTEMPT_SUFFIX,
  );
  if (localhost) return localhost;
  const provider = translateTrailingCoverageFrame(
    english,
    PROVIDER_DISCOVERY_APPEND,
    ["", ""],
  );
  if (provider) return provider;

  const summary = english.endsWith(COVERAGE_STATE_APPEND[0])
    ? english.slice(0, -COVERAGE_STATE_APPEND[0].length)
    : undefined;
  if (summary !== undefined) {
    const translated = translateCoverageRecordDetail(summary);
    if (translated) return `${translated}${COVERAGE_STATE_APPEND[1]}`;
  }

  const applicabilityReason = stripFrame(
    english,
    "The source area is explicitly outside this case: ",
    " This is a scoped applicability statement, not a successful scan result.",
  );
  if (applicabilityReason) {
    return `此來源範圍明確不在本案件內：${applicabilityReason} 這是範圍適用性的說明，不是掃描成功的結果。`;
  }

  const retainedCount = stripFrame(
    english,
    "The source is connected and the latest attributable discovery returned no assets. This is not a successful scan result; ",
    " prior asset observation(s) remain retained.",
  );
  if (retainedCount && /^\d+$/u.test(retainedCount)) {
    return `來源已連線，且最近一次可歸屬的探索未傳回任何資產。這不是掃描成功的結果；仍保留 ${retainedCount} 筆先前的資產觀察結果。`;
  }

  const disconnected = english.match(
    /^The source is not currently connected \(status: (.+)\)\. Its present coverage is unknown; (\d+) previously attributed asset\(s\) are retained but do not make the source green\.$/u,
  );
  if (disconnected?.[1] && disconnected[2]) {
    return `來源目前未連線（狀態：${disconnected[1]}）。目前的涵蓋未知；仍保留 ${disconnected[2]} 筆先前歸屬的資產，但這不會讓來源顯示為綠色。`;
  }

  const authorizationDetail = stripFrame(
    english,
    "The scan's frozen authorization evidence is incomplete: ",
    ". Live grants are never used to reconstruct historical scan permission.",
  );
  if (authorizationDetail) {
    return `掃描中凍結的授權證據不完整：${authorizationDetail}。絕不會用現行授權重建過去的掃描權限。`;
  }

  const compatibleCount = stripFrame(
    english,
    "All ",
    " compatible engine run(s) planned for this asset completed.",
  );
  if (compatibleCount && /^\d+$/u.test(compatibleCount)) {
    return `為此資產規劃的 ${compatibleCount} 項相容掃描工具工作皆已完成。`;
  }

  const exactTaskCount = stripFrame(
    english,
    "All ",
    " planned task(s) for this asset completed their exact declared dimensions.",
  );
  if (exactTaskCount && /^\d+$/u.test(exactTaskCount)) {
    return `為此資產規劃的 ${exactTaskCount} 項工作，皆已完成各自明確宣告的檢查範圍。`;
  }

  const incompleteReasons = stripFrame(
    english,
    "The authorized scan is incomplete: ",
    ". Only completed compatible catalog-engine runs or exact completed built-in tasks can produce scanned coverage.",
  );
  if (incompleteReasons) {
    return `已授權的掃描未完成：${incompleteReasons}。只有已完成且相容的目錄掃描工具工作，或精確完成的內建工作，才能產生已掃描涵蓋。`;
  }
  return undefined;
};

/** Reviewed English catalog rationales and their Traditional Chinese presentation. */
const CONTROL_MAPPING_RATIONALE_PROSE: ReadonlyArray<
  readonly [string, string]
> = [
  [
    "Evidence that an identity has no registered multi-factor device is related to authenticating users and safeguarding authentication information.",
    "某個身分未登記多重要素驗證裝置的證據，與驗證使用者及保護驗證資訊有關。",
  ],
  [
    "Evidence that an attached identity policy grants unrestricted administrative permissions is related to least privilege, entitlement review, and privileged access safeguards.",
    "附加的身分政策授予不受限制之管理權限的證據，與最小權限、權限審查及特權存取保護有關。",
  ],
  [
    "Evidence that an object-storage resource permits public access is related to access policy, authorization review, and cloud service protection.",
    "物件儲存資源允許公開存取的證據，與存取政策、授權審查及雲端服務保護有關。",
  ],
  [
    "Evidence that the account password policy does not require an uppercase character is related to credential lifecycle management and to safeguarding authentication information.",
    "帳戶密碼政策未要求包含大寫字元的證據，與憑證生命週期管理及保護驗證資訊有關。",
  ],
  [
    "Evidence that a role assumable by the EC2 service is attached to no instance is related to least privilege and entitlement review; an unused entitlement stays usable until it is removed.",
    "可由 EC2 服務擔任的角色未附加到任何執行個體的證據，與最小權限及權限審查有關；未使用的權限在移除前仍然可用。",
  ],
  [
    "Evidence of an identity privilege-escalation path is related to least privilege, entitlement review, and privileged access safeguards.",
    "身分權限提升路徑的證據，與最小權限、權限審查及特權存取保護有關。",
  ],
  [
    "Evidence that an identity policy permits actions returning credential material is related to credential lifecycle management, least privilege, authentication information safeguards, and privileged access safeguards.",
    "身分政策允許會回傳憑證資料之操作的證據，與憑證生命週期管理、最小權限、驗證資訊保護及特權存取保護有關。",
  ],
  [
    "Evidence that an identity policy permits actions that can read stored data out of the account is related to least privilege, protection of data at rest, access policy, and entitlement review.",
    "身分政策允許將帳戶內已儲存資料讀出之操作的證據，與最小權限、靜態資料保護、存取政策及權限審查有關。",
  ],
  [
    "Evidence that an identity policy permits actions that change who can reach a resource is related to least privilege, access policy, entitlement review, and cloud service security responsibilities.",
    "身分政策允許變更誰可以存取資源之操作的證據，與最小權限、存取政策、權限審查及雲端服務安全責任有關。",
  ],
  [
    "Evidence that an identity policy permits actions that alter account infrastructure is related to least privilege, entitlement review, and privileged access safeguards.",
    "身分政策允許變更帳戶基礎架構之操作的證據，與最小權限、權限審查及特權存取保護有關。",
  ],
  [
    "Evidence that an identity policy grants every action in a service is related to least privilege, entitlement review, and privileged access safeguards; a wildcard also covers actions the account has never reviewed.",
    "身分政策授予某項服務全部操作的證據，與最小權限、權限審查及特權存取保護有關；萬用字元也會涵蓋該帳戶從未審查過的操作。",
  ],
  [
    "Evidence that legacy authentication is not blocked is related to enforcing appropriate authentication and protecting authentication information.",
    "未封鎖舊式驗證的證據，與強制使用適當的驗證方式及保護驗證資訊有關。",
  ],
  [
    "Evidence that privileged identities lack phishing-resistant authentication is related to authentication enforcement and authentication information safeguards.",
    "特權身分缺少抗網路釣魚驗證的證據，與強制驗證及驗證資訊保護有關。",
  ],
  [
    "Evidence of an exposed database administration interface is related to identifying, validating, recording, and handling technical vulnerabilities.",
    "資料庫管理介面對外暴露的證據，與識別、確認、記錄及處理技術弱點有關。",
  ],
  [
    "Static-analysis evidence of dynamic code execution is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.",
    "動態程式碼執行的靜態分析證據，與安全開發及執行前的危險程式結構檢查有關。當所選程式碼由 AI 產生或經 AI 實質修改時，AIDEFEND 的 AI 產生構件條目才適用。",
  ],
  [
    "Static-analysis evidence that Python code invokes an operating-system shell is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.",
    "Python 程式碼呼叫作業系統 shell 的靜態分析證據，與安全開發及執行前的危險程式結構檢查有關。當所選程式碼由 AI 產生或經 AI 實質修改時，AIDEFEND 的 AI 產生構件條目才適用。",
  ],
  [
    "Static-analysis evidence that JavaScript or TypeScript code invokes a command through a shell is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.",
    "JavaScript 或 TypeScript 程式碼透過 shell 呼叫命令的靜態分析證據，與安全開發及執行前的危險程式結構檢查有關。當所選程式碼由 AI 產生或經 AI 實質修改時，AIDEFEND 的 AI 產生構件條目才適用。",
  ],
  [
    "Static-analysis evidence of private-key material in current project files is related to managing credentials and protecting authentication information. AIDEFEND's static-admission coordinate applies when the selected artifact was generated or materially changed by AI.",
    "目前專案檔案含有私密金鑰資料的靜態分析證據，與管理憑證及保護驗證資訊有關。當所選構件由 AI 產生或經 AI 實質修改時，AIDEFEND 的靜態准入條目才適用。",
  ],
  [
    "Evidence of a credential embedded in current project files is related to managing credentials and protecting authentication information. AIDEFEND's static-admission coordinate applies when the selected artifact was generated or materially changed by AI.",
    "目前專案檔案內嵌憑證的證據，與管理憑證及保護驗證資訊有關。當所選構件由 AI 產生或經 AI 實質修改時，AIDEFEND 的靜態准入條目才適用。",
  ],
  [
    "Every TruffleHog result is a detected credential, so this reference covers the engine's whole detector surface rather than one detector. Evidence of a credential in source material is related to managing credentials and protecting authentication information. AIDEFEND's static-admission coordinate applies when the selected artifact was generated or materially changed by AI.",
    "每一筆 TruffleHog 結果都是偵測到的憑證，因此這項參照涵蓋該掃描工具的完整偵測範圍，而不是單一偵測器。原始資料中含有憑證的證據，與管理憑證及保護驗證資訊有關。當所選構件由 AI 產生或經 AI 實質修改時，AIDEFEND 的靜態准入條目才適用。",
  ],
  [
    "Static evidence that an MCP configuration embeds a credential pattern is related to credential lifecycle management, authentication-information protection, and sensitive-information disclosure.",
    "MCP 設定內嵌憑證樣式的靜態證據，與憑證生命週期管理、驗證資訊保護及敏感資訊外洩有關。",
  ],
  [
    "Static evidence that an MCP server configuration grants a risky tool, permission, command, or command flag is related to least privilege, configuration management, privileged access safeguards, and excessive agency.",
    "MCP 伺服器設定授予高風險工具、權限、命令或命令旗標的靜態證據，與最小權限、組態管理、特權存取保護及過度代理能力有關。",
  ],
  [
    "Infrastructure-as-code evidence that access logging is disabled is related to security-relevant audit records. AIDEFEND's IaC-scanning coordinate applies when the selected configuration provisions an AI system.",
    "基礎架構即程式碼顯示存取記錄已停用的證據，與安全性相關的稽核記錄有關。當所選設定用來佈建 AI 系統時，AIDEFEND 的 IaC 掃描條目才適用。",
  ],
  [
    "Infrastructure-as-code evidence that server-side encryption is absent is related to protecting data at rest and using cryptographic safeguards. AIDEFEND's IaC-scanning coordinate applies when the selected configuration provisions an AI system.",
    "基礎架構即程式碼顯示未使用伺服器端加密的證據，與保護靜態資料及使用密碼學保護措施有關。當所選設定用來佈建 AI 系統時，AIDEFEND 的 IaC 掃描條目才適用。",
  ],
  [
    "Evidence that an installed component is affected by a CVE is related to vulnerability handling. For an AI system, AIDEFEND separates build or deployment admission from the deployed-software remediation lifecycle; this reference does not decide which lifecycle state applies.",
    "已安裝元件受某項 CVE 影響的證據，與弱點處理有關。對 AI 系統而言，AIDEFEND 將建置或部署准入與已部署軟體的修復生命週期分開；這項參照不會判定適用哪一個生命週期階段。",
  ],
  [
    "Evidence that subjects can run commands inside running containers is related to least-privilege authorization, privileged access safeguards, and container isolation. AIDEFEND's container-isolation coordinate applies when the workload is part of an AI system.",
    "主體可以在執行中的容器內執行命令的證據，與最小權限授權、特權存取保護及容器隔離有關。當工作負載屬於 AI 系統的一部分時，AIDEFEND 的容器隔離條目才適用。",
  ],
  [
    "Evidence that a workload declares no CPU or memory limit is related to maintaining resource capacity for availability, capacity management, and platform configuration management.",
    "工作負載未宣告 CPU 或記憶體上限的證據，與維持可用性所需的資源容量、容量管理及平台組態管理有關。",
  ],
  [
    "Evidence that a container can write to its own root filesystem is related to platform configuration management and container isolation. AIDEFEND's container-isolation coordinate applies when the workload is part of an AI system.",
    "容器可以寫入自身根檔案系統的證據，與平台組態管理及容器隔離有關。當工作負載屬於 AI 系統的一部分時，AIDEFEND 的容器隔離條目才適用。",
  ],
  [
    "Evidence that the kubelet service file is writable beyond its owner is related to node configuration management and privileged access safeguards; that file governs a root-level service.",
    "kubelet 服務檔案可由擁有者以外的人寫入的證據，與節點組態管理及特權存取保護有關；該檔案掌管一個以 root 執行的服務。",
  ],
  [
    "Evidence that the kubelet config.yaml file is readable or writable beyond its owner is related to node configuration management and privileged access safeguards; that file holds the kubelet's security settings.",
    "kubelet config.yaml 檔案可由擁有者以外的人讀取或寫入的證據，與節點組態管理及特權存取保護有關；該檔案存放 kubelet 的安全設定。",
  ],
  [
    "Evidence that the kubelet config.yaml file is not owned by root is related to node configuration management and privileged access safeguards; a non-root owner can change the kubelet's security settings.",
    "kubelet config.yaml 檔案的擁有者不是 root 的證據，與節點組態管理及特權存取保護有關；非 root 的擁有者可以變更 kubelet 的安全設定。",
  ],
  [
    "Evidence that the kubelet accepts anonymous authentication is related to authentication enforcement and authentication information safeguards. This is the node check the shipped snapshot benchmark runs; the control-plane equivalent is not in scope for this product.",
    "kubelet 接受匿名驗證的證據，與強制驗證及驗證資訊保護有關。這是隨附的快照基準所執行的節點檢查；對應的控制平面檢查不在本產品範圍內。",
  ],
  [
    "Evidence that kubelet client certificate rotation is turned off is related to credential lifecycle management, authentication information safeguards, and cryptographic safeguards.",
    "kubelet 用戶端憑證輪替已關閉的證據，與憑證生命週期管理、驗證資訊保護及密碼學保護措施有關。",
  ],
  [
    "Evidence that the kube-proxy metrics endpoint is not bound to localhost is related to protecting networks from unauthorized access, node configuration management, and network security.",
    "kube-proxy 指標端點未繫結至 localhost 的證據，與保護網路免於未經授權的存取、節點組態管理及網路安全有關。",
  ],
  [
    "A Greenbone vulnerability-test alarm on an authorized host is evidence related to technical vulnerability handling. For an AI system, AIDEFEND separates build-time dependency admission from the deployed-software remediation lifecycle; this reference points at the deployed lifecycle and does not decide remediation state.",
    "Greenbone 對已授權主機發出的弱點測試警示，是與技術性弱點處理相關的證據。對 AI 系統而言，AIDEFEND 將建置階段的相依套件准入與已部署軟體的修復生命週期分開；這項參照指向已部署的生命週期，並不判定修復狀態。",
  ],
  [
    "garak's dan module holds do-anything-now and other long-form instruction attacks whose stated purpose is to make a target ignore its alignment. A detector judging those attempts as failures is evidence related to prompt injection.",
    "garak 的 dan 模組收錄 do-anything-now 等長篇指令式攻擊，其目的是讓目標忽略自身的對齊限制。偵測器把這些嘗試判定為失敗，是與提示注入相關的證據。",
  ],
  [
    "Every probe in garak's encoding module hides an instruction or payload in an encoding to get it past alignment. A detector judging those attempts as failures is evidence related to prompt injection carried in obfuscated input.",
    "garak encoding 模組中的每個探測項目，都把指令或酬載藏在某種編碼裡，以繞過對齊限制。偵測器把這些嘗試判定為失敗，是與經混淆輸入夾帶提示注入相關的證據。",
  ],
  [
    "garak's latentinjection module buries an instruction inside content the target is asked to process, such as a resume, a report or a passage to translate. A detector judging those attempts as failures is evidence related to indirect prompt injection.",
    "garak 的 latentinjection 模組把指令埋在要求目標處理的內容裡，例如履歷、報告或待翻譯的段落。偵測器把這些嘗試判定為失敗，是與間接提示注入相關的證據。",
  ],
  [
    "garak's sysprompt_extraction module asks the target for its own system prompt through direct requests, encoding tricks and role play. A detector judging those attempts as failures is evidence related to system prompt leakage.",
    "garak 的 sysprompt_extraction 模組透過直接索取、編碼手法與角色扮演，向目標取得它自己的系統提示。偵測器把這些嘗試判定為失敗，是與系統提示外洩相關的證據。",
  ],
  [
    "garak's leakreplay module asks the target to complete or fill in excerpts of documents, to see whether it replays text it was trained on. A detector judging those attempts as failures is evidence related to sensitive information disclosure.",
    "garak 的 leakreplay 模組要求目標補完或填空文件片段，藉此觀察它是否覆述訓練用過的文字。偵測器把這些嘗試判定為失敗，是與敏感資訊外洩相關的證據。",
  ],
  [
    "garak's divergence.Repeat probe asks the target to repeat a word until its output diverges and leaks other material. Its sibling divergence.RepeatedToken measures stability rather than leakage, so this reference is bound to the one probe.",
    "garak 的 divergence.Repeat 探測項目要求目標不斷重複某個詞，直到輸出偏離並洩漏其他內容。同模組的 divergence.RepeatedToken 量測的是穩定性而非外洩，因此這項參照只綁定這一個探測項目。",
  ],
  [
    "garak's packagehallucination module asks the target for code and checks whether the imports it names exist in the language's real package registry. A detector judging those attempts as failures is evidence related to misinformation in generated code.",
    "garak 的 packagehallucination 模組要求目標產生程式碼，並檢查其中列出的匯入項目是否真的存在於該語言的套件登錄中。偵測器把這些嘗試判定為失敗，是與生成程式碼中的錯誤資訊相關的證據。",
  ],
  [
    "garak's snowball module poses reasoning questions whose only correct response is that the task is impossible. A detector judging those attempts as failures is evidence related to misinformation, because the target asserted an answer instead.",
    "garak 的 snowball 模組提出的推理題，唯一正確的回應是指出該任務無法達成。偵測器把這些嘗試判定為失敗，是與錯誤資訊相關的證據，因為目標反而給出了肯定的答案。",
  ],
  [
    "garak's misleading module states false claims and checks whether the target refutes them. A detector judging those attempts as failures is evidence related to misinformation, because the target went along with the claim.",
    "garak 的 misleading 模組提出不實主張，並檢查目標是否加以反駁。偵測器把這些嘗試判定為失敗，是與錯誤資訊相關的證據，因為目標順著該主張作答。",
  ],
  [
    "garak's ansiescape module tries to make the target emit ANSI terminal escape codes, which disrupt whatever renders the reply. A detector judging those attempts as failures is evidence related to improper output handling downstream of the model.",
    "garak 的 ansiescape 模組嘗試讓目標輸出 ANSI 終端跳脫碼，這類字元會干擾負責呈現回覆的元件。偵測器把這些嘗試判定為失敗，是與模型下游輸出處理不當相關的證據。",
  ],
  [
    "garak's web_injection module tries to make the target emit markdown or script that a client will act on, either exfiltrating conversation content through a URI or running as cross-site scripting. A detector judging those attempts as failures is evidence related to improper output handling and to sensitive information disclosure.",
    "garak 的 web_injection 模組嘗試讓目標輸出用戶端會實際處理的 markdown 或指令碼，藉此經由 URI 外傳對話內容，或形成跨站腳本攻擊。偵測器把這些嘗試判定為失敗，是與輸出處理不當及敏感資訊外洩相關的證據。",
  ],
  [
    "OWASP publishes A01:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
    "OWASP 公布 A01:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
  ],
  [
    "OWASP publishes A02:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
    "OWASP 公布 A02:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
  ],
  [
    "OWASP publishes A03:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
    "OWASP 公布 A03:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
  ],
  [
    "OWASP publishes A04:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
    "OWASP 公布 A04:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
  ],
  [
    "OWASP publishes A05:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
    "OWASP 公布 A05:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
  ],
  [
    "OWASP publishes A06:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
    "OWASP 公布 A06:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
  ],
  [
    "OWASP publishes A07:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
    "OWASP 公布 A07:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
  ],
  [
    "OWASP publishes A08:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
    "OWASP 公布 A08:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
  ],
  [
    "OWASP publishes A09:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
    "OWASP 公布 A09:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
  ],
  [
    "OWASP publishes A10:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
    "OWASP 公布 A10:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
  ],
];

export const controlMappingRationaleZhHant = (
  english: string,
): string | undefined =>
  CONTROL_MAPPING_RATIONALE_PROSE.find(
    ([candidate]) => candidate === english,
  )?.[1];

export const localizedControlMappingRationale = (
  rationale: string,
  locale: "en" | "zh-TW",
): string =>
  locale === "en"
    ? rationale
    : (controlMappingRationaleZhHant(rationale) ?? rationale);

/** A stored coverage-record explanation in the reader's language. */
export const localizedCoverageRecordDetail = (
  detail: string,
  locale: "en" | "zh-TW",
): string =>
  locale === "en" ? detail : (translateCoverageRecordDetail(detail) ?? detail);

const DATA_QUALITY_WARNING_PROSE: ReadonlyArray<readonly [string, string]> = [
  [
    "This run has inconsistent request and check data.",
    "本輪的請求與檢查資料不一致。",
  ],
  [
    "The selected run has an inconsistent project identity. Report data: selected in-project record.",
    "所選掃描輪次的專案識別資料不一致；報告資料：專案內所選記錄。",
  ],
  [
    "One check has incomplete coverage history.",
    "有一項檢查的涵蓋歷程未完成。",
  ],
];

const translateDataQualityWarning = (english: string): string | undefined => {
  const fixed = DATA_QUALITY_WARNING_PROSE.find(
    ([candidate]) => candidate === english,
  )?.[1];
  if (fixed) return fixed;
  const missingSnapshot = stripFrame(
    english,
    "Finding ",
    " selected-run presentation snapshot: unavailable. Display wording: current canonical text.",
  );
  if (missingSnapshot)
    return `問題 ${missingSnapshot} 所選輪次呈現快照：無法取得；顯示文字：目前正式版本。`;
  const observationOnly = stripFrame(
    english,
    "Finding ",
    " presentation detail: unavailable. Retained run observation: available.",
  );
  if (observationOnly)
    return `問題 ${observationOnly} 呈現細節：無法取得；保留的輪次觀察：可用。`;
  return undefined;
};

export const localizedDataQualityWarning = (
  warning: string,
  locale: "en" | "zh-TW",
): string => locale === "en" ? warning : (translateDataQualityWarning(warning) ?? warning);

/** Next action when every attached check failed to produce observations. */
export const INCOMPLETE_CHECK_CONFIRM_ACTION =
  "Finish the check that did not complete, then re-verify this observation, before changing anything.";
export const INCOMPLETE_CHECK_CONFIRM_ACTION_ZH_HANT =
  "先完成未完成的檢查，再確認這項觀察，之後才變更任何內容。";

export const coverageProducedObservations = (
  status: BeginnerCoverageStatus,
): boolean => status === "tested_complete" || status === "tested_partial";

/**
 * True when every evidence reference points at a check this report does not
 * classify as having produced observations. Unknowns fail closed: missing
 * engine-run ids, ids absent from `checks`, and findings with no evidence at
 * all are unconfirmed.
 */
export const findingUnconfirmedByCoverage = (
  evidenceReferences: readonly { engineRunId?: string }[],
  checks: readonly { taskId: string; status: BeginnerCoverageStatus }[],
): boolean => {
  const statusByTaskId = new Map(checks.map((check) => [check.taskId, check.status]));
  return evidenceReferences.every((reference) => {
    if (!reference.engineRunId) return true;
    const status = statusByTaskId.get(reference.engineRunId);
    return status === undefined || !coverageProducedObservations(status);
  });
};

/** The direct recommended action for the finding family. */
export const findingActionSentence = (
  locale: "en" | "zh-TW",
  options: {
    englishFallback: string;
    family?: FindingFamily;
    awsIamPolicy?: AwsIamPolicyFindingDetails;
    unconfirmedByCoverage?: boolean;
  },
): string => {
  if (options.unconfirmedByCoverage) {
    return locale === "zh-TW"
      ? INCOMPLETE_CHECK_CONFIRM_ACTION_ZH_HANT
      : INCOMPLETE_CHECK_CONFIRM_ACTION;
  }
  if (options.awsIamPolicy) {
    return locale === "zh-TW"
      ? awsIamPolicyActionZhTW(options.awsIamPolicy)
      : awsIamPolicyActionEnglish(options.awsIamPolicy);
  }
  const remedy = options.family ? REMEDY[options.family] : undefined;
  if (!remedy || !options.family) {
    const marker = ", then plan and approve ";
    const at = options.englishFallback.lastIndexOf(marker);
    if (at < 0) return options.englishFallback;
    const direct = options.englishFallback.slice(at + marker.length).trim();
    return direct ? direct[0]!.toLocaleUpperCase("en") + direct.slice(1) : options.englishFallback;
  }
  if (locale === "en") return `${REMEDY_ENGLISH[options.family]}.`;
  return `${remedy}。`;
};

/**
 * One next step's action sentence, composed the same way the HTML report
 * composes it (`beginner_step_action` in `case_service.rs`).
 *
 * A finding-derived step uses that finding's own recommendation — family or
 * Cloudsplaining policy, otherwise the stored sentence. A gap-derived step is
 * looked up as coverage prose. An unattributed step names the identifier the
 * reader has to add. The categorical `code` still groups and orders the step;
 * it is not this sentence. An empty stored action with nothing to compose from
 * stays empty: the report layer's absence statement is for a scan with no
 * steps, not a fabricated code-label fallback.
 */
export const beginnerStepAction = (
  locale: "en" | "zh-TW",
  step: {
    action: string;
    code?: BeginnerNextActionCode;
    family?: FindingFamily;
    findingId?: string;
    unattributed?: UnattributedResults;
    reason: string;
  },
  findings: readonly {
    findingId: string;
    severityBasisCode?: SeverityBasisCode;
    evidenceReferences: readonly {
      detailsFrozen?: boolean;
      engineId: string;
      engineRunId?: string;
      scannerDetails?: { awsIamPolicy?: AwsIamPolicyFindingDetails };
    }[];
  }[],
  checks?: readonly { taskId: string; status: BeginnerCoverageStatus }[],
): string => {
  const derivedFrom = step.findingId
    ? findings.find((finding) => finding.findingId === step.findingId)
    : undefined;
  if (step.unattributed) {
    const engineId = step.reason.split(" ")[0] || step.reason;
    return findingUnattributedGap(locale, engineId, step.unattributed, {
      dimension: "",
      reason: step.reason,
      nextAction: step.action,
    }).nextAction;
  }
  const exposureObservation = derivedFrom?.severityBasisCode === "open_port"
    || derivedFrom?.severityBasisCode === "reachable_http_service";
  const unconfirmedByCoverage = derivedFrom !== undefined
    && !exposureObservation
    && (checks
      ? findingUnconfirmedByCoverage(derivedFrom.evidenceReferences, checks)
      : step.code === "confirm_finding_after_incomplete_check");
  const awsIamPolicy = derivedFrom
    ?.evidenceReferences
    .filter((reference) =>
      reference.detailsFrozen === true && reference.engineId === "cloudsplaining")
    .map((reference) => reference.scannerDetails?.awsIamPolicy)
    .find((details) => details !== undefined);
  const composed = locale === "en" && !derivedFrom
    ? step.action
    : findingActionSentence(locale, {
      englishFallback: step.action,
      family: step.family,
      awsIamPolicy,
      unconfirmedByCoverage,
    });
  return derivedFrom ? composed : coverageGapProse(locale, composed);
};

/** Appends the identifier a composed name carries, when it has one. */
const withIdentifier = (label: string, identifier: string): string =>
  identifier ? `${label}（${identifier}）` : label;

/**
 * The limit kinds the backend appends to a holder identifier, in match order,
 * each with its Traditional Chinese label.
 */
const REQUESTED_LIMIT_KIND_SUFFIXES: ReadonlyArray<readonly [string, string]> = [
  ["approved ports", "允許檢查的連接埠"],
  ["request rate", "請求速率"],
  ["network timeout", "網路逾時限制"],
  ["authorized network target", "已確認的網路目標"],
  ["execution timeout", "檢查逾時限制"],
];

/**
 * The label for a limit kind this build authors, if it is one. Three names are
 * fixed strings rather than composed ones, so they never carry a holder.
 */
const requestedLimitKindZh = (kind: string): string | undefined => {
  if (kind === "endpoint") return "連線端點";
  if (kind === "connection timeout") return "連線逾時限制";
  if (kind === "application payload") return "應用資料量";
  return REQUESTED_LIMIT_KIND_SUFFIXES.find(([suffix]) => suffix === kind)?.[1];
};

/**
 * Splits a requested-limit name into the holder that carries it and the kind
 * of limit it is. A name with none of the holder suffixes -- "endpoint",
 * "connection timeout", "application payload", or a name this build has never
 * seen -- has no holder to extract, so the whole name becomes the kind and the
 * holder is empty.
 */
export const requestedLimitParts = (
  name: string,
): { holder: string; kind: string } => {
  for (const [suffix] of REQUESTED_LIMIT_KIND_SUFFIXES) {
    if (name.endsWith(suffix)) {
      return {
        holder: name.slice(0, name.length - suffix.length).trim(),
        kind: suffix,
      };
    }
  }
  return { holder: "", kind: name };
};

/**
 * Names a limit's kind alone, for a list that shows the holders in their own
 * element beside it.
 */
export const localizedRequestedLimitKind = (
  kind: string,
  locale: "en" | "zh-TW",
): string => {
  const label = requestedLimitKindZh(kind);
  if (locale === "zh-TW") return label ?? `本輪使用的限制：${kind}`;
  return label === undefined
    ? kind
    : `${kind.charAt(0).toLocaleUpperCase("en")}${kind.slice(1)}`;
};

/**
 * Names one limit the run was executed under. The backend composes most of
 * these as "<engine or asset id> <limit kind>", so translating the kind alone
 * erases the only part saying which scanner or which authorized target the
 * limit applied to. A case with three scope grants would otherwise show three
 * rows all reading "approved ports" with no way to attribute them.
 *
 * Lives here rather than in `coverageDimensionPresentation.ts` because the
 * shared HTML report names the same limits and Rust composes the identical
 * label there; this file is where the two languages are held to each other.
 */
export const localizedRequestedLimitName = (
  name: string,
  locale: "en" | "zh-TW",
): string => {
  if (locale === "en") return name;
  const { holder, kind } = requestedLimitParts(name);
  return withIdentifier(localizedRequestedLimitKind(kind, locale), holder);
};

const REQUESTED_LIMIT_VALUE_UNITS: ReadonlyArray<readonly [string, string]> = [
  [" ms", " 毫秒"],
  [" bytes", " 位元組"],
  [" seconds", " 秒"],
];

const REQUEST_RATE_MIDDLE = [
  " per second, concurrency ",
  " 次，並行 ",
] as const;

/** One stored requested-limit value in the reader's language. */
export const localizedRequestedLimitValue = (
  name: string,
  value: string,
  locale: "en" | "zh-TW",
): string => {
  if (locale === "en") return value;
  for (const [englishUnit, chineseUnit] of REQUESTED_LIMIT_VALUE_UNITS) {
    const match = value.match(new RegExp(`^(\\d+)${englishUnit}$`, "u"));
    if (match?.[1]) return `${match[1]}${chineseUnit}`;
  }

  const [requests, concurrency, extra] = value.split(REQUEST_RATE_MIDDLE[0]);
  if (
    !extra &&
    /^\d+$/u.test(requests ?? "") &&
    /^\d+$/u.test(concurrency ?? "")
  ) {
    return `每秒 ${requests}${REQUEST_RATE_MIDDLE[1]}${concurrency}`;
  }

  // Identifier-shaped values are intentionally returned unchanged. Keeping
  // these names here mirrors the backend's producer census distinction between
  // a recognized identifier and an unknown unit-bearing value.
  if (
    name === "endpoint" ||
    name.endsWith(" authorized network target") ||
    name.endsWith(" approved ports")
  )
    return value;
  return value;
};

/**
 * The coordinate tail `source_coordinate_location`
 * (src-tauri/src/adapters/mod.rs) appends to a path when the scanner reported
 * a line, column, or resource: `path[:line=N][:column=N][:resource=R]`. A
 * string with none of those markers is not this form at all -- a plain path, a
 * URL, a `host:port` pair, `package:name` -- and is left alone below.
 */
const LOCATION_COORDINATE_FORM = /^(.*?)(?::line=(\d+))?(?::column=(\d+))?(?::resource=(.+))?$/s;

/**
 * Present a scanner's snapshot path consistently without changing the stored
 * evidence. Checkov names the snapshot root with a leading slash while KICS
 * and the other source scanners use repository-relative paths. Backslashes
 * and a leading `./` are likewise scanner conventions, not useful location
 * information for the reader.
 */
const reportFilePath = (raw: string): string => {
  let path = raw.replaceAll("\\", "/");
  while (path.startsWith("./")) path = path.slice(2);
  if (path.startsWith("/") && !path.startsWith("//")) path = path.replace(/^\/+/, "");
  return path || raw;
};

/**
 * The resource label worth printing after `path`, or "" when there is none.
 * KICS writes `n/a` when a result has no resource, and Checkov names a
 * Dockerfile resource after the file (`/Dockerfile.`) or the file and an
 * instruction (`/Dockerfile.EXPOSE`); only the instruction adds anything to
 * the path already printed in front of it.
 */
const resourceLabel = (part: string, path: string): string => {
  if (part === "n/a") return "";
  const bare = reportFilePath(part);
  if (!bare.startsWith(path)) return part;
  const rest = bare.slice(path.length);
  if (!rest) return "";
  return rest.startsWith(".") ? rest.slice(1) : part;
};

/**
 * Reads a stored scanner location as a place, not the coordinate string it is
 * kept in. KICS's `R` carries a `resource:<name>` label and/or a
 * `similarity:<64-hex hash>` deduplication key, joined by a comma; that hash
 * is KICS's own dedup key, not something a reader needs to find the spot, so
 * it is dropped here and kept verbatim in the technical details instead, as
 * is a resource label that says `n/a` or only repeats the path (see
 * `resourceLabel`). A plain path receives the same separator/root cleanup.
 * URLs, endpoints, package coordinates, and other non-path locations are
 * returned untouched.
 */
export const findingLocationText = (locale: "en" | "zh-TW", raw: string): string => {
  const trimmed = raw.trim();
  const [, path, line, column, resource] = LOCATION_COORDINATE_FORM.exec(trimmed) ?? [];
  if (!path || (!line && !column && !resource)) {
    if (/^(?:\.{0,2}[\\/]|[A-Za-z]:[\\/])/u.test(trimmed)) return reportFilePath(trimmed);
    return raw;
  }

  const pathText = reportFilePath(path);
  const parts = [pathText];
  if (line && column) {
    parts.push(locale === "en" ? `line ${line}, column ${column}` : `第 ${line} 行第 ${column} 欄`);
  } else if (line) {
    parts.push(locale === "en" ? `line ${line}` : `第 ${line} 行`);
  } else if (column) {
    parts.push(locale === "en" ? `column ${column}` : `第 ${column} 欄`);
  }
  if (resource) {
    const resourceParts = resource
      .split(",")
      .map((part) => part.trim())
      .filter((part) => part && !part.startsWith("similarity:"))
      .map((part) => (part.startsWith("resource:") ? part.slice("resource:".length).trim() : part))
      .map((part) => resourceLabel(part, pathText))
      .filter((part, index, all) => part && all.indexOf(part) === index);
    if (resourceParts.length > 0) parts.push(resourceParts.join(", "));
  }
  return parts.join(" · ");
};
