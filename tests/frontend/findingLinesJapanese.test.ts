import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { parseSync } from "vite";
import {
  ENGLISH_EVIDENCE_REASON,
  ENGLISH_EXPOSURE_OBSERVATION_REASON,
  ENGLISH_ROLLBACK,
  EXPOSED_CREDENTIAL_NEXT_STEP_ENGLISH,
  EXPOSED_CREDENTIAL_NEXT_STEP_ZH_HANT,
  INCOMPLETE_CHECK_CONFIRM_ACTION,
  INCOMPLETE_CHECK_CONFIRM_ACTION_ZH_HANT,
  PASSWORD_COMPOSITION_ORDER_REASON,
  PASSWORD_EXPIRY_ORDER_REASON,
  awsIamPolicyAction,
  awsIamPolicySourceLabel,
  beginnerStepAction,
  benchmarkLine,
  exposedCredentialNextStep,
  findingActionSentence,
  findingConfidencePresentation,
  findingHeadline,
  findingImpactSentence,
  findingLineText,
  findingLocationText,
  findingPriorityReason,
  findingRollbackSentence,
  findingSummarySentence,
  findingUnattributedGap,
  findingVerificationSentence,
  iamPrincipalLabels,
  iamPrincipalSummary,
  localizedExpertType,
  stepConfirmation,
  stepGroupLead,
} from "../../src/findingNarrative.ts";
import { jaInline } from "../../src/i18n/locales/ja-inline.ts";
import type {
  AwsIamPolicyFindingDetails,
  BenchmarkReference,
  ConfidenceBasisCode,
  ContextFactor,
  FindingFamily,
  SeverityBasisCode,
  UnattributedResults,
} from "../../src/types.ts";

const resolveStringValue = (node: any): string => {
  if (node?.type === "Literal" && typeof node.value === "string") return node.value;
  if (
    node?.type === "CallExpression"
    && node.callee?.type === "MemberExpression"
    && node.callee.object?.type === "Identifier"
    && node.callee.object.name === "EXPOSED_CREDENTIAL_NEXT_STEP_ENGLISH"
    && node.callee.property?.name === "slice"
    && node.arguments?.length === 2
  ) {
    return EXPOSED_CREDENTIAL_NEXT_STEP_ENGLISH.slice(0, -1);
  }
  assert.fail(`Unexpected object entry value node: ${String(node?.type)}`);
};

const objectEntries = (name: string): Array<[string, string]> => {
  const path = "../../src/findingNarrative.ts";
  const parsed = parseSync(path, readFileSync(new URL(path, import.meta.url), "utf8"));
  assert.deepEqual(parsed.errors, []);
  let properties: unknown[] | undefined;
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) return value.forEach(visit);
    if (!value || typeof value !== "object") return;
    const node = value as Record<string, any>;
    if (node.type === "VariableDeclarator" && node.id?.name === name) {
      assert.equal(node.init?.type, "ObjectExpression");
      properties = node.init.properties;
    }
    Object.values(value).forEach(visit);
  };
  visit(parsed.program);
  assert.ok(properties?.length, `${name} must contain entries`);
  return properties.map((prop: any) => {
    assert.equal(prop.type, "Property");
    const key = prop.key?.type === "Literal" ? String(prop.key.value) : String(prop.key?.name);
    return [key, resolveStringValue(prop.value)];
  });
};

const JAPANESE_SCRIPT = /[\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Han}]/u;

const templatesAndFixed = [
  EXPOSED_CREDENTIAL_NEXT_STEP_ENGLISH,
  "role",
  "group",
  "user",
  "{retained}, and 1 more principal",
  "{retained}, and {omitted} more principals",
  "AWS-managed",
  "Customer-managed",
  "Inline",
  "Replace AWS-managed policy {policyName} with a narrower policy on {principals}, or detach it where it is not needed; AWS-managed policies cannot be edited by this account.",
  "Keep AWS-managed policy {policyName} detached and choose a narrower policy before attaching it; AWS-managed policies cannot be edited by this account.",
  "Identify the current roles, groups, and users attached to AWS-managed policy {policyName}, then replace it with a narrower policy or detach it where it is not needed; AWS-managed policies cannot be edited by this account.",
  "Narrow customer-managed policy {policyName} and verify that {principals} retain only the permissions they need.",
  "Narrow customer-managed policy {policyName} before it is attached or reused.",
  "Identify the current attachments to customer-managed policy {policyName}, then narrow it and verify that each principal retains only the permissions it needs.",
  "Narrow inline policy {policyName} directly on {principals}.",
  "Identify where inline policy {policyName} is owned and narrow it there before reuse.",
  "Confirm the current IAM attachments first.",
  "{confidenceLabel} — scanner did not report detection quality",
  "{confidenceLabel} — this product's rating from {basis}",
  "{confidenceLabel} — engine rating: {source}",
  "Security or IT professional",
  "Cloudflare source audit",
  "{engine} checked this Microsoft 365 requirement and the tenant did not meet it.",
  "{engine} reported this condition without rating it. Severity is Unknown.",
  "{engine} reported a {severity}-severity condition on the assessed asset.",
  "{engine} reported this condition on the assessed asset without rating it. This product rated it {severity} from {basis}.",
  ENGLISH_ROLLBACK,
  "Rerun {engine} with the same scope after the change and confirm that “{title}” is no longer reported.",
  "Rerun {engine} with the same scope after the change and confirm that source rule {rule} is no longer reported.",
  "Requirement not met: {title}",
  "{count} problems name this same fix. The first is {reason}",
  "{count} related problems call for this kind of change; each needs its own fix. The first is {reason}",
  "Rerun the same scan after the changes and confirm these problems are no longer reported.",
  "Rerun the same scan after the change and confirm this problem is no longer reported.",
  PASSWORD_COMPOSITION_ORDER_REASON,
  PASSWORD_EXPIRY_ORDER_REASON,
  ENGLISH_EVIDENCE_REASON,
  ENGLISH_EXPOSURE_OBSERVATION_REASON,
  "The affected asset is internet-accessible.",
  "The affected asset contains sensitive data, increasing the potential impact.",
  "Source severity: {value}",
  "Severity is Unknown because {engine} did not provide a rating.",
  "Source confidence: {value}",
  "Confidence derived from {basis}; {engine} reports no confidence of its own.",
  "Severity derived from {basis}; {engine} reports no severity of its own.",
  "{name} {versions} item {reference}",
  " and {hidden} more",
  " (reported by {engine})",
  "{engineId}: results for {provider} {identifier}",
  "{engineId} reported {discardedResults} results for {provider} identifier {identifier}. None of your authorized assets carry this identifier, so those results were not attributed and are absent from this report.",
  "Add {provider} identifier {identifier} to your authorized asset and scan again.",
  INCOMPLETE_CHECK_CONFIRM_ACTION,
  "line {line}, column {column}",
  "line {line}",
  "column {column}",
] as const;

test("finding line tables and templates have complete Japanese entries with matching placeholders", () => {
  const confidenceBasisValues = objectEntries("CONFIDENCE_BASIS_ENGLISH").map(([, value]) => value);
  const basisValues = objectEntries("BASIS_ENGLISH").map(([, value]) => value);
  const consequenceValues = objectEntries("CONSEQUENCE_ENGLISH").map(([, value]) => value);
  const contextValues = objectEntries("CONTEXT_ENGLISH").map(([, value]) => value);
  const expertKeys = objectEntries("EXPERT").map(([key]) => key);
  const remedyValues = objectEntries("REMEDY_ENGLISH").map(([, value]) => value);

  const english = new Set([
    ...confidenceBasisValues,
    ...basisValues,
    ...consequenceValues,
    ...contextValues,
    ...expertKeys,
    ...remedyValues,
    ...templatesAndFixed,
  ]);

  const missing = [...english].filter((entry) => !Object.hasOwn(jaInline, entry)).sort();
  assert.deepEqual(missing, [], `Missing Japanese inline entries:\n${missing.join("\n")}`);

  const invalid = [...english]
    .filter((entry) => !jaInline[entry]?.trim() || jaInline[entry] === entry || !JAPANESE_SCRIPT.test(jaInline[entry]!))
    .sort();
  assert.deepEqual(invalid, [], `Empty or untranslated Japanese inline entries:\n${invalid.join("\n")}`);

  const placeholders = (value: string) => [...value.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/gu)]
    .map((match) => match[1])
    .sort();
  for (const entry of english) {
    assert.deepEqual(placeholders(jaInline[entry]!), placeholders(entry), entry);
  }
});

test("exposedCredentialNextStep and awsIamPolicySourceLabel translate Japanese and keep en/zh-TW", () => {
  assert.equal(exposedCredentialNextStep("en"), EXPOSED_CREDENTIAL_NEXT_STEP_ENGLISH);
  assert.equal(exposedCredentialNextStep("zh-TW"), EXPOSED_CREDENTIAL_NEXT_STEP_ZH_HANT);
  assert.equal(exposedCredentialNextStep("ja"), jaInline[EXPOSED_CREDENTIAL_NEXT_STEP_ENGLISH]);

  assert.equal(awsIamPolicySourceLabel("aws_managed", "en"), "AWS-managed");
  assert.equal(awsIamPolicySourceLabel("aws_managed", "zh-TW"), "AWS 受管");
  assert.equal(awsIamPolicySourceLabel("aws_managed", "ja"), jaInline["AWS-managed"]);

  assert.equal(awsIamPolicySourceLabel("customer_managed", "en"), "Customer-managed");
  assert.equal(awsIamPolicySourceLabel("customer_managed", "zh-TW"), "客戶受管");
  assert.equal(awsIamPolicySourceLabel("customer_managed", "ja"), jaInline["Customer-managed"]);

  assert.equal(awsIamPolicySourceLabel("inline", "en"), "Inline");
  assert.equal(awsIamPolicySourceLabel("inline", "zh-TW"), "內嵌");
  assert.equal(awsIamPolicySourceLabel("inline", "ja"), jaInline["Inline"]);
});

test("iamPrincipalLabels, iamPrincipalSummary, and awsIamPolicyAction cover all shapes in en, zh-TW, and ja", () => {
  const iamDetails = (
    policySource: AwsIamPolicyFindingDetails["policySource"],
    attachedTo: AwsIamPolicyFindingDetails["attachedTo"],
  ): AwsIamPolicyFindingDetails => ({
    policySource,
    policyName: "PowerUserPolicy",
    findingIdentity: "iam-finding-1",
    actions: ["iam:*"],
    actionsComplete: true,
    attachedTo,
  });

  const threePrincipals = iamDetails("aws_managed", {
    roles: ["app-role"],
    groups: ["devs"],
    users: ["deploy"],
    complete: true,
  });
  assert.deepEqual(iamPrincipalLabels(threePrincipals, "en"), ["role app-role", "group devs", "user deploy"]);
  assert.deepEqual(iamPrincipalLabels(threePrincipals, "zh-TW"), ["角色 app-role", "群組 devs", "使用者 deploy"]);
  assert.deepEqual(iamPrincipalLabels(threePrincipals, "ja"), [
    `${jaInline.role} app-role`,
    `${jaInline.group} devs`,
    `${jaInline.user} deploy`,
  ]);

  const unattached = iamDetails("aws_managed", { roles: [], groups: [], users: [], complete: true });
  assert.equal(iamPrincipalSummary(unattached, "en"), undefined);
  assert.equal(iamPrincipalSummary(unattached, "zh-TW"), undefined);
  assert.equal(iamPrincipalSummary(unattached, "ja"), undefined);

  assert.deepEqual(iamPrincipalSummary(threePrincipals, "en"), {
    text: "role app-role, group devs, user deploy",
    count: 3,
  });
  assert.deepEqual(iamPrincipalSummary(threePrincipals, "zh-TW"), {
    text: "角色 app-role、群組 devs、使用者 deploy",
    count: 3,
  });
  assert.deepEqual(iamPrincipalSummary(threePrincipals, "ja"), {
    text: `${jaInline.role} app-role、${jaInline.group} devs、${jaInline.user} deploy`,
    count: 3,
  });

  const sevenPrincipals = iamDetails("aws_managed", {
    roles: ["r1", "r2", "r3", "r4", "r5", "r6", "r7"],
    groups: [],
    users: [],
    complete: true,
  });
  assert.deepEqual(iamPrincipalSummary(sevenPrincipals, "en"), {
    text: "role r1, role r2, role r3, role r4, role r5, role r6, and 1 more principal",
    count: 7,
  });
  assert.deepEqual(iamPrincipalSummary(sevenPrincipals, "zh-TW"), {
    text: "角色 r1、角色 r2、角色 r3、角色 r4、角色 r5、角色 r6，以及另外 1 個主體",
    count: 7,
  });
  const sevenJa = iamPrincipalSummary(sevenPrincipals, "ja");
  assert.equal(sevenJa?.count, 7);
  assert.ok(sevenJa && sevenJa.text.includes("r6") && JAPANESE_SCRIPT.test(sevenJa.text), sevenJa?.text);
  assert.ok(sevenJa && !sevenJa.text.includes("more principal"), sevenJa?.text);

  const eightPrincipals = iamDetails("aws_managed", {
    roles: ["r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8"],
    groups: [],
    users: [],
    complete: true,
  });
  assert.equal(
    iamPrincipalSummary(eightPrincipals, "en")?.text,
    "role r1, role r2, role r3, role r4, role r5, role r6, and 2 more principals",
  );
  assert.equal(
    iamPrincipalSummary(eightPrincipals, "zh-TW")?.text,
    "角色 r1、角色 r2、角色 r3、角色 r4、角色 r5、角色 r6，以及另外 2 個主體",
  );
  const eightJa = iamPrincipalSummary(eightPrincipals, "ja");
  assert.equal(eightJa?.count, 8);
  assert.ok(eightJa && eightJa.text.includes("2") && JAPANESE_SCRIPT.test(eightJa.text), eightJa?.text);
  assert.ok(eightJa && !eightJa.text.includes("more principals"), eightJa?.text);

  const oneAttached = { roles: ["app-role"], groups: [], users: [], complete: true };
  const detached = { roles: [], groups: [], users: [], complete: true };
  const incomplete = { roles: [], groups: [], users: [], complete: false };

  assert.equal(
    awsIamPolicyAction(iamDetails("aws_managed", oneAttached), "en"),
    "Replace AWS-managed policy PowerUserPolicy with a narrower policy on role app-role, or detach it where it is not needed; AWS-managed policies cannot be edited by this account.",
  );
  assert.equal(
    awsIamPolicyAction(iamDetails("aws_managed", oneAttached), "zh-TW"),
    "在角色 app-role上將 AWS 受管政策 PowerUserPolicy 改為權限較小的政策；若不需要則解除附加。AWS 受管政策無法由此帳戶直接編輯。",
  );
  assert.equal(
    awsIamPolicyAction(iamDetails("aws_managed", detached), "en"),
    "Keep AWS-managed policy PowerUserPolicy detached and choose a narrower policy before attaching it; AWS-managed policies cannot be edited by this account.",
  );
  assert.equal(
    awsIamPolicyAction(iamDetails("aws_managed", incomplete), "en"),
    "Identify the current roles, groups, and users attached to AWS-managed policy PowerUserPolicy, then replace it with a narrower policy or detach it where it is not needed; AWS-managed policies cannot be edited by this account. Confirm the current IAM attachments first.",
  );
  assert.equal(
    awsIamPolicyAction(iamDetails("customer_managed", oneAttached), "en"),
    "Narrow customer-managed policy PowerUserPolicy and verify that role app-role retains only the permissions they need.",
  );
  assert.equal(
    awsIamPolicyAction(iamDetails("customer_managed", detached), "en"),
    "Narrow customer-managed policy PowerUserPolicy before it is attached or reused.",
  );
  assert.equal(
    awsIamPolicyAction(iamDetails("customer_managed", incomplete), "en"),
    "Identify the current attachments to customer-managed policy PowerUserPolicy, then narrow it and verify that each principal retains only the permissions it needs. Confirm the current IAM attachments first.",
  );
  assert.equal(
    awsIamPolicyAction(iamDetails("inline", oneAttached), "en"),
    "Narrow inline policy PowerUserPolicy directly on role app-role.",
  );
  assert.equal(
    awsIamPolicyAction(iamDetails("inline", incomplete), "en"),
    "Identify where inline policy PowerUserPolicy is owned and narrow it there before reuse. Confirm the current IAM attachments first.",
  );

  for (const source of ["aws_managed", "customer_managed", "inline"] as const) {
    for (const attached of [oneAttached, detached, incomplete]) {
      const zh = awsIamPolicyAction(iamDetails(source, attached), "zh-TW");
      assert.ok(zh.includes("PowerUserPolicy") && JAPANESE_SCRIPT.test(zh), zh);
      const ja = awsIamPolicyAction(iamDetails(source, attached), "ja");
      assert.ok(ja.includes("PowerUserPolicy") && JAPANESE_SCRIPT.test(ja), ja);
      assert.ok(!ja.includes("policy PowerUserPolicy"), ja);
      if (attached === oneAttached) assert.ok(ja.includes(`${jaInline.role} app-role`), ja);
      if (attached === incomplete) {
        assert.ok(ja.endsWith(jaInline["Confirm the current IAM attachments first."]!), ja);
      }
    }
  }
});

test("findingConfidencePresentation handles missing score, every basis code, source rating, and fallbacks", () => {
  assert.equal(
    findingConfidencePresentation("en", "Unknown confidence", "missing_detection_quality_score", []),
    "Unknown confidence — scanner did not report detection quality",
  );
  assert.equal(
    findingConfidencePresentation("zh-TW", "信心未知", "missing_detection_quality_score", []),
    "信心未知 — 掃描工具未提供偵測品質",
  );
  const missingJa = findingConfidencePresentation("ja", "確度：不明", "missing_detection_quality_score", []);
  assert.ok(JAPANESE_SCRIPT.test(missingJa) && missingJa.startsWith("確度：不明 — "), missingJa);
  assert.ok(!missingJa.includes("scanner did not report"), missingJa);

  for (const [code, basisEn] of objectEntries("CONFIDENCE_BASIS_ENGLISH") as Array<[ConfidenceBasisCode, string]>) {
    if (code === "missing_detection_quality_score") continue;
    const enOut = findingConfidencePresentation("en", "High confidence", code, []);
    const zhOut = findingConfidencePresentation("zh-TW", "高信心", code, []);
    const jaOut = findingConfidencePresentation("ja", "確度：高", code, []);
    assert.equal(enOut, `High confidence — this product's rating from ${basisEn}`);
    assert.ok(zhOut.startsWith("高信心 — 本產品依據"), zhOut);
    assert.ok(jaOut.startsWith("確度：高 — ") && jaOut.includes(jaInline[basisEn]!), jaOut);
    assert.ok(!jaOut.includes(basisEn), jaOut);
  }

  for (const locale of ["en", "zh-TW", "ja"] as const) {
    assert.equal(
      findingConfidencePresentation(locale, "Label", "future_basis" as ConfidenceBasisCode, []),
      "Label",
    );
    assert.equal(findingConfidencePresentation(locale, "Label", undefined, []), "Label");
  }

  assert.equal(
    findingConfidencePresentation("en", "High confidence", undefined, ["Source confidence: HIGH"]),
    "High confidence — engine rating: HIGH",
  );
  assert.equal(
    findingConfidencePresentation("zh-TW", "高信心", undefined, ["Source confidence: HIGH"]),
    "高信心 — 來源工具評定：HIGH",
  );
  const sourceJa = findingConfidencePresentation("ja", "確度：高", undefined, ["Source confidence: HIGH"]);
  assert.ok(sourceJa.startsWith("確度：高 — ") && sourceJa.endsWith("HIGH"), sourceJa);
  assert.ok(!sourceJa.includes("engine rating"), sourceJa);
});

test("localizedExpertType maps every known specialist and uses the generic Japanese fallback", () => {
  for (const [expert, zh] of objectEntries("EXPERT")) {
    assert.equal(localizedExpertType(expert, "en"), expert);
    assert.equal(localizedExpertType(expert, "zh-TW"), zh);
    assert.equal(localizedExpertType(`  ${expert}  `, "ja"), jaInline[expert]);
  }
  assert.equal(localizedExpertType("Quantum risk officer", "en"), "Quantum risk officer");
  assert.equal(localizedExpertType("Quantum risk officer", "zh-TW"), "資安或 IT 專業人員");
  assert.equal(localizedExpertType("Quantum risk officer", "ja"), jaInline["Security or IT professional"]);
});

test("findingSummarySentence covers m365 verdict, unrated, engine-rated, basis-rated, sourceAudit, and unknown fallback", () => {
  const m365 = "ScubaGear reported this control as failing.";
  assert.equal(
    findingSummarySentence("en", { englishFallback: m365, severityLabel: "High", family: "microsoft365" }),
    "ScubaGear checked this Microsoft 365 requirement and the tenant did not meet it.",
  );
  assert.equal(
    findingSummarySentence("zh-TW", { englishFallback: m365, severityLabel: "高", family: "microsoft365" }),
    "ScubaGear 檢查了這項 Microsoft 365 要求，這個租戶未通過。",
  );
  const m365Ja = findingSummarySentence("ja", { englishFallback: m365, severityLabel: "高", family: "microsoft365" });
  assert.ok(m365Ja.startsWith("ScubaGear ") && JAPANESE_SCRIPT.test(m365Ja), m365Ja);
  assert.ok(!m365Ja.includes("checked this Microsoft 365 requirement"), m365Ja);
  assert.equal(
    findingSummarySentence("ja", {
      englishFallback: "ScubaGear checked this Microsoft 365 requirement and the tenant did not meet it.",
      severityLabel: "高",
      family: "microsoft365",
    }),
    m365Ja,
  );

  const cloudflare = "Cloudflare source audit reported a high-severity condition on the assessed asset.";
  assert.equal(
    findingSummarySentence("en", { englishFallback: cloudflare, severityLabel: "High" }),
    cloudflare,
  );
  assert.equal(
    findingSummarySentence("zh-TW", { englishFallback: cloudflare, severityLabel: "高" }),
    "Cloudflare 原始碼稽核 在受評估的資產上回報了一項高等級的狀況。",
  );
  const cfJa = findingSummarySentence("ja", { englishFallback: cloudflare, severityLabel: "高" });
  assert.ok(cfJa.startsWith("Cloudflare ソースコード監査") && cfJa.includes("高"), cfJa);

  const unratedRaw = "httpx reported this condition without rating it. Severity remains Unknown and requires human review.";
  assert.equal(
    findingSummarySentence("en", { englishFallback: unratedRaw, severity: "unknown", severityLabel: "Unknown" }),
    "httpx reported this condition without rating it. Severity is Unknown.",
  );
  assert.equal(
    findingSummarySentence("zh-TW", { englishFallback: unratedRaw, severity: "unknown", severityLabel: "未知" }),
    "httpx 回報了這項狀況，但未評定嚴重程度。嚴重程度為未知。",
  );
  const unratedJa = findingSummarySentence("ja", { englishFallback: unratedRaw, severity: "unknown", severityLabel: "不明" });
  assert.ok(unratedJa.startsWith("httpx ") && JAPANESE_SCRIPT.test(unratedJa), unratedJa);
  assert.ok(!unratedJa.includes("reported this condition"), unratedJa);

  const engineRated = "Greenbone Community Edition reported a medium-severity condition on the assessed asset. The attached raw record is evidence, not an instruction.";
  assert.equal(
    findingSummarySentence("en", { englishFallback: engineRated, severityLabel: "Medium" }),
    "Greenbone Community Edition reported a medium-severity condition on the assessed asset.",
  );
  assert.equal(
    findingSummarySentence("zh-TW", { englishFallback: engineRated, severityLabel: "中" }),
    "Greenbone Community Edition 在受評估的資產上回報了一項中等級的狀況。",
  );
  const ratedJa = findingSummarySentence("ja", { englishFallback: engineRated, severityLabel: "中" });
  assert.ok(ratedJa.startsWith("Greenbone Community Edition ") && ratedJa.includes("中"), ratedJa);
  assert.ok(!ratedJa.includes("assessed asset"), ratedJa);

  for (const [code, basisEn] of objectEntries("BASIS_ENGLISH") as Array<[SeverityBasisCode, string]>) {
    const fallback = `Trivy reported this condition on the assessed asset without rating it. This product rated it high from ${basisEn}.`;
    const ja = findingSummarySentence("ja", {
      englishFallback: fallback,
      severity: "high",
      severityLabel: "高",
      severityBasisCode: code,
    });
    assert.ok(ja.startsWith("Trivy ") && ja.includes(jaInline[basisEn]!) && ja.includes("高"), ja);
    assert.ok(!ja.includes("assessed asset"), ja);
  }

  for (const locale of ["en", "zh-TW", "ja"] as const) {
    assert.equal(
      findingSummarySentence(locale, { sourceAudit: true, englishFallback: "Native summary.", severityLabel: "高" }),
      "Native summary.",
    );
    assert.equal(
      findingSummarySentence(locale, { englishFallback: "Some other text entirely.", severityLabel: "高" }),
      "Some other text entirely.",
    );
    const unknownBasis = "Trivy reported this condition on the assessed asset without rating it.";
    assert.equal(
      findingSummarySentence(locale, {
        englishFallback: unknownBasis,
        severity: "high",
        severityLabel: "高",
        severityBasisCode: "future_basis" as SeverityBasisCode,
      }),
      unknownBasis,
    );
  }
});

test("findingImpactSentence covers every family, context factor, sourceAudit, and legacy fallback", () => {
  const families = objectEntries("CONSEQUENCE_ENGLISH") as Array<[FindingFamily, string]>;
  const jaImpacts = new Set<string>();
  for (const [family, consequenceEn] of families) {
    const enOut = findingImpactSentence("en", { englishFallback: "fallback", severityLabel: "High", family });
    const zhOut = findingImpactSentence("zh-TW", { englishFallback: "fallback", severityLabel: "高", family });
    const jaOut = findingImpactSentence("ja", { englishFallback: "fallback", severityLabel: "高", family });
    assert.equal(enOut, `${consequenceEn}.`);
    assert.ok(JAPANESE_SCRIPT.test(zhOut) && zhOut.endsWith("。"), zhOut);
    assert.equal(jaOut, `${jaInline[consequenceEn]}。`);
    jaImpacts.add(jaOut);
  }
  assert.equal(jaImpacts.size, families.length - 1);

  const contextEn = findingImpactSentence("en", {
    englishFallback: "fallback",
    severityLabel: "High",
    family: "cloud_posture",
    contextFactors: ["internet_exposed_asset", "sensitive_data_asset", "future_factor" as ContextFactor],
  });
  const contextZh = findingImpactSentence("zh-TW", {
    englishFallback: "fallback",
    severityLabel: "高",
    family: "cloud_posture",
    contextFactors: ["internet_exposed_asset", "sensitive_data_asset", "future_factor" as ContextFactor],
  });
  const contextJa = findingImpactSentence("ja", {
    englishFallback: "fallback",
    severityLabel: "高",
    family: "cloud_posture",
    contextFactors: ["internet_exposed_asset", "sensitive_data_asset", "future_factor" as ContextFactor],
  });
  assert.equal(
    contextEn,
    "Cloud resources or data may be exposed, changed, or used beyond the organization's intent. The affected asset is internet-accessible, increasing the reachable attack surface. The affected asset contains sensitive data, increasing the potential impact.",
  );
  assert.equal(
    contextZh,
    "雲端資源或資料可能遭到未預期的存取、變更或使用。受影響的資產可從網際網路存取，因此可被觸及的攻擊面較大。受影響的資產含有敏感資料，因此問題造成的影響可能更高。",
  );
  assert.equal(
    contextJa,
    `${jaInline["Cloud resources or data may be exposed, changed, or used beyond the organization's intent"]}。${jaInline[" The affected asset is internet-accessible, increasing the reachable attack surface."]}${jaInline[" The affected asset contains sensitive data, increasing the potential impact."]}`,
  );

  const legacy = "If the scanner result is confirmed, a container may be exposed. The medium source severity is not a product-wide compliance score.";
  for (const locale of ["en", "zh-TW", "ja"] as const) {
    assert.equal(
      findingImpactSentence(locale, { sourceAudit: true, englishFallback: legacy, severityLabel: "Medium", family: "vulnerable_component" }),
      legacy,
    );
    assert.equal(
      findingImpactSentence(locale, { englishFallback: legacy, severityLabel: "Medium", family: "quantum_posture" as FindingFamily }),
      "A container may be exposed.",
    );
  }
});

test("findingRollbackSentence, findingVerificationSentence, findingHeadline, stepGroupLead, and stepConfirmation", () => {
  const legacyRollback = "Before any manual change, preserve the current approved configuration and document a tested restoration path.";
  const foreignRollback = "Custom rollback instructions.";
  assert.equal(findingRollbackSentence("en", ENGLISH_ROLLBACK), ENGLISH_ROLLBACK);
  assert.equal(findingRollbackSentence("en", legacyRollback), ENGLISH_ROLLBACK);
  assert.equal(findingRollbackSentence("zh-TW", ENGLISH_ROLLBACK), "變更前先保存目前設定，並測試還原路徑。");
  assert.equal(findingRollbackSentence("ja", ENGLISH_ROLLBACK), jaInline[ENGLISH_ROLLBACK]);
  assert.equal(findingRollbackSentence("ja", legacyRollback), jaInline[ENGLISH_ROLLBACK]);
  for (const locale of ["en", "zh-TW", "ja"] as const) {
    assert.equal(findingRollbackSentence(locale, foreignRollback), foreignRollback);
  }

  const ruleVerify = "After an approved manual change, rerun kube-bench with the same authorized scope and confirm that source rule 4.2.1 is no longer reported.";
  assert.equal(
    findingVerificationSentence("en", ruleVerify),
    "Rerun kube-bench with the same scope after the change and confirm that source rule 4.2.1 is no longer reported.",
  );
  assert.equal(
    findingVerificationSentence("zh-TW", ruleVerify),
    "變更後以相同範圍重新執行 kube-bench，並確認來源規則 4.2.1 不再被回報。",
  );
  const ruleVerifyJa = findingVerificationSentence("ja", ruleVerify);
  assert.ok(ruleVerifyJa.includes("kube-bench") && ruleVerifyJa.includes("4.2.1") && JAPANESE_SCRIPT.test(ruleVerifyJa), ruleVerifyJa);
  assert.ok(!ruleVerifyJa.includes("with the same scope"), ruleVerifyJa);

  const uuid = "38c5ee0d-7f22-4260-ab72-5073048df100";
  const title = "S3 Bucket ACL Allows Read Or Write to All Users";
  const uuidVerify = `Rerun KICS with the same scope after the change and confirm that source rule ${uuid} is no longer reported.`;
  assert.equal(
    findingVerificationSentence("en", uuidVerify, title),
    `Rerun KICS with the same scope after the change and confirm that “${title}” is no longer reported.`,
  );
  assert.equal(
    findingVerificationSentence("zh-TW", uuidVerify, title),
    `變更後以相同範圍重新執行 KICS，並確認「${title}」不再被回報。`,
  );
  const uuidVerifyJa = findingVerificationSentence("ja", uuidVerify, title);
  assert.ok(uuidVerifyJa.includes("KICS") && uuidVerifyJa.includes(`「${title}」`), uuidVerifyJa);
  assert.ok(!uuidVerifyJa.includes(uuid), uuidVerifyJa);

  for (const locale of ["en", "zh-TW", "ja"] as const) {
    assert.equal(findingVerificationSentence(locale, "Re-run the responsible engine."), "Re-run the responsible engine.");
  }

  const m365Title = "Legacy authentication is blocked";
  assert.equal(findingHeadline("en", m365Title, "microsoft365"), `Requirement not met: ${m365Title}`);
  assert.equal(findingHeadline("zh-TW", m365Title, "microsoft365"), `未符合要求：${m365Title}`);
  const headlineJa = findingHeadline("ja", m365Title, "microsoft365");
  assert.ok(headlineJa.endsWith(m365Title) && JAPANESE_SCRIPT.test(headlineJa), headlineJa);
  assert.ok(!headlineJa.includes("Requirement not met"), headlineJa);
  for (const locale of ["en", "zh-TW", "ja"] as const) {
    assert.equal(findingHeadline(locale, m365Title, "cloud_posture"), m365Title);
    assert.equal(findingHeadline(locale, m365Title, undefined), m365Title);
  }

  const reason = "Privileged containers are allowed";
  assert.equal(stepGroupLead("en", 3, true, reason), `3 problems name this same fix. The first is ${reason}`);
  assert.equal(stepGroupLead("zh-TW", 3, true, reason), `有 3 項問題指向同一個修復方式，第一項是 ${reason}`);
  const sharedJa = stepGroupLead("ja", 3, true, reason);
  assert.ok(sharedJa.includes("3") && sharedJa.includes(reason) && JAPANESE_SCRIPT.test(sharedJa), sharedJa);
  assert.ok(!sharedJa.includes("problems name this same fix"), sharedJa);

  assert.equal(
    stepGroupLead("en", 4, false, reason),
    `4 related problems call for this kind of change; each needs its own fix. The first is ${reason}`,
  );
  assert.equal(
    stepGroupLead("zh-TW", 4, false, reason),
    `有 4 項相關問題需要這類處理，每一項都要分別修正；第一項是 ${reason}`,
  );
  const separateJa = stepGroupLead("ja", 4, false, reason);
  assert.ok(separateJa.includes("4") && separateJa.includes(reason) && JAPANESE_SCRIPT.test(separateJa), separateJa);
  assert.ok(!separateJa.includes("related problems"), separateJa);

  assert.equal(
    stepConfirmation("en", ruleVerify, title, 2),
    "Rerun the same scan after the changes and confirm these problems are no longer reported.",
  );
  assert.equal(
    stepConfirmation("zh-TW", ruleVerify, title, 2),
    "修正後以相同範圍重新掃描，確認這些問題不再被回報。",
  );
  assert.equal(
    stepConfirmation("ja", ruleVerify, title, 2),
    jaInline["Rerun the same scan after the changes and confirm these problems are no longer reported."],
  );
  assert.equal(stepConfirmation("ja", ruleVerify, title, 1), ruleVerifyJa);
  assert.equal(
    stepConfirmation("en", undefined, title, 1),
    "Rerun the same scan after the change and confirm this problem is no longer reported.",
  );
  assert.equal(
    stepConfirmation("zh-TW", " ", title, 1),
    "修正後以相同範圍重新掃描，確認這項問題不再被回報。",
  );
  assert.equal(
    stepConfirmation("ja", undefined, title, 1),
    jaInline["Rerun the same scan after the change and confirm this problem is no longer reported."],
  );
  for (const locale of ["en", "zh-TW", "ja"] as const) {
    assert.equal(stepConfirmation(locale, "Custom verification guidance.", title, 1), "Custom verification guidance.");
  }
});

test("findingPriorityReason covers every sentence shape and fallback in en, zh-TW, and ja", () => {
  assert.equal(findingPriorityReason("en", PASSWORD_COMPOSITION_ORDER_REASON), PASSWORD_COMPOSITION_ORDER_REASON);
  assert.equal(
    findingPriorityReason("zh-TW", PASSWORD_COMPOSITION_ORDER_REASON),
    "處理順序比嚴重程度所示更後面。CIS AWS Foundations Benchmark v1.2.0 要求這項字元規則，但之後的 CIS 版本已移除，NIST SP 800-63B-4 也要求不要強制混合字元類型。請先確認密碼長度與 MFA；只有在必須通過的稽核仍要求這項規則時，才需要變更。",
  );
  assert.equal(findingPriorityReason("ja", PASSWORD_COMPOSITION_ORDER_REASON), jaInline[PASSWORD_COMPOSITION_ORDER_REASON]);

  assert.equal(findingPriorityReason("en", PASSWORD_EXPIRY_ORDER_REASON), PASSWORD_EXPIRY_ORDER_REASON);
  assert.equal(
    findingPriorityReason("zh-TW", PASSWORD_EXPIRY_ORDER_REASON),
    "處理順序比嚴重程度所示更後面。CIS AWS Foundations Benchmark v1.2.0 要求密碼定期到期，但之後的 CIS 版本已移除，NIST SP 800-63B-4 也規定只有在有證據顯示密碼已外洩時，才強制更換。只有在必須通過的稽核仍要求這項規則時，才需要變更。",
  );
  assert.equal(findingPriorityReason("ja", PASSWORD_EXPIRY_ORDER_REASON), jaInline[PASSWORD_EXPIRY_ORDER_REASON]);

  assert.equal(findingPriorityReason("en", ENGLISH_EVIDENCE_REASON), ENGLISH_EVIDENCE_REASON);
  assert.equal(findingPriorityReason("zh-TW", ENGLISH_EVIDENCE_REASON), "已附上掃描工具的直接證據。");
  assert.equal(findingPriorityReason("ja", ENGLISH_EVIDENCE_REASON), jaInline[ENGLISH_EVIDENCE_REASON]);

  assert.equal(findingPriorityReason("en", ENGLISH_EXPOSURE_OBSERVATION_REASON), ENGLISH_EXPOSURE_OBSERVATION_REASON);
  assert.equal(
    findingPriorityReason("zh-TW", ENGLISH_EXPOSURE_OBSERVATION_REASON),
    "這是可連線服務的盤點觀察，不是漏洞。",
  );
  assert.equal(
    findingPriorityReason("ja", ENGLISH_EXPOSURE_OBSERVATION_REASON),
    jaInline[ENGLISH_EXPOSURE_OBSERVATION_REASON],
  );

  const legacyInternet =
    "An affected asset is marked internet-exposed, and all retained source attribution for that asset is non-questionnaire.";
  assert.equal(findingPriorityReason("en", legacyInternet), "The affected asset is internet-accessible.");
  assert.equal(findingPriorityReason("zh-TW", legacyInternet), "受影響的資產可從網際網路存取。");
  assert.equal(findingPriorityReason("ja", legacyInternet), jaInline["The affected asset is internet-accessible."]);

  const legacySensitive =
    "An affected asset is marked sensitive, all retained source attribution for that asset is non-questionnaire, and the case questionnaire separately records sensitive-data context.";
  assert.equal(
    findingPriorityReason("en", legacySensitive),
    "The affected asset contains sensitive data, increasing the potential impact.",
  );
  assert.equal(findingPriorityReason("zh-TW", legacySensitive), "受影響的資產含有敏感資料，因此問題造成的影響可能更高。");
  assert.equal(
    findingPriorityReason("ja", legacySensitive),
    jaInline["The affected asset contains sensitive data, increasing the potential impact."],
  );

  assert.equal(findingPriorityReason("en", "Source severity: HIGH"), "Source severity: HIGH");
  assert.equal(findingPriorityReason("zh-TW", "Source severity: HIGH"), "來源工具評定的嚴重程度：HIGH");
  const jaSourceSeverity = findingPriorityReason("ja", "Source severity: HIGH");
  assert.equal(jaSourceSeverity, jaInline["Source severity: {value}"]!.replace("{value}", "HIGH"));
  assert.ok(jaSourceSeverity.includes("HIGH"));

  const legacyUnrated = "Severity remains Unknown because Checkov did not assign one; human review is required.";
  assert.equal(
    findingPriorityReason("en", legacyUnrated),
    "Severity is Unknown because Checkov did not provide a rating.",
  );
  assert.equal(findingPriorityReason("zh-TW", legacyUnrated), "嚴重程度為未知，因為 Checkov 未提供評級。");
  assert.equal(
    findingPriorityReason("ja", legacyUnrated),
    jaInline["Severity is Unknown because {engine} did not provide a rating."]!.replace("{engine}", "Checkov"),
  );

  assert.equal(findingPriorityReason("en", "Source confidence: medium"), "Source confidence: medium");
  assert.equal(findingPriorityReason("zh-TW", "Source confidence: medium"), "來源工具評定的信心：medium");
  const jaSourceConfidence = findingPriorityReason("ja", "Source confidence: medium");
  assert.equal(jaSourceConfidence, jaInline["Source confidence: {value}"]!.replace("{value}", "medium"));
  assert.ok(jaSourceConfidence.includes("medium"));

  const confidenceDerived =
    "Confidence derived from a deterministic policy or configuration evaluation; Checkov reports no confidence of its own.";
  assert.equal(findingPriorityReason("en", confidenceDerived), confidenceDerived);
  assert.equal(
    findingPriorityReason("zh-TW", confidenceDerived),
    "信心是由確定性的政策或設定評估結果推導而來；Checkov 本身不提供信心評定。",
  );
  assert.equal(
    findingPriorityReason("ja", confidenceDerived),
    jaInline["Confidence derived from {basis}; {engine} reports no confidence of its own."]!
      .replace("{basis}", jaInline["a deterministic policy or configuration evaluation"]!)
      .replace("{engine}", "Checkov"),
  );

  const severityDerived =
    "Severity derived from an unverified credential detector match; Gitleaks reports no severity of its own.";
  assert.equal(
    findingPriorityReason("en", severityDerived),
    "Severity derived from a credential detector match; Gitleaks reports no severity of its own.",
  );
  assert.equal(
    findingPriorityReason("zh-TW", severityDerived),
    "嚴重程度是由憑證偵測器的比對結果推導而來；Gitleaks 本身不提供嚴重程度。",
  );
  assert.equal(
    findingPriorityReason("ja", severityDerived),
    jaInline["Severity derived from {basis}; {engine} reports no severity of its own."]!
      .replace("{basis}", jaInline["a credential detector match"]!)
      .replace("{engine}", "Gitleaks"),
  );

  for (const fallback of [
    "Custom untranslated priority reason.",
    "Confidence derived from unknown basis; Checkov reports no confidence of its own.",
    "Severity derived from unknown basis; Checkov reports no severity of its own.",
  ]) {
    assert.equal(findingPriorityReason("en", fallback), fallback);
    assert.equal(findingPriorityReason("zh-TW", fallback), fallback);
    assert.equal(findingPriorityReason("ja", fallback), fallback);
  }
});

test("benchmarkLine formats items, separators, overflow, and engine verbatim in en, zh-TW, and ja", () => {
  assert.equal(benchmarkLine("en", "Checkov", []), undefined);
  assert.equal(benchmarkLine("zh-TW", "Checkov", []), undefined);
  assert.equal(benchmarkLine("ja", "Checkov", []), undefined);

  const benchmarks: BenchmarkReference[] = [
    { name: "CIS AWS", version: "1.2.0", reference: "1.1" },
    { name: "CIS AWS", version: "1.4.0", reference: "1.1" },
    { name: "NIST 800-53", version: "rev5", reference: "AC-2" },
    { name: "ISO 27001", version: "2022", reference: "A.8.2" },
    { name: "PCI DSS", version: "4.0", reference: "3.5" },
  ];

  assert.equal(
    benchmarkLine("en", "Checkov", benchmarks),
    "CIS AWS 1.2.0/1.4.0 item 1.1; NIST 800-53 rev5 item AC-2; ISO 27001 2022 item A.8.2 and 1 more (reported by Checkov)",
  );
  assert.equal(
    benchmarkLine("zh-TW", "Checkov", benchmarks),
    "CIS AWS 1.2.0/1.4.0 第 1.1 項；NIST 800-53 rev5 第 AC-2 項；ISO 27001 2022 第 A.8.2 項，另有 1 項（Checkov 回報）",
  );
  const item = (name: string, versions: string, reference: string) =>
    jaInline["{name} {versions} item {reference}"]!
      .replace("{name}", name)
      .replace("{versions}", versions)
      .replace("{reference}", reference);
  assert.equal(
    benchmarkLine("ja", "Checkov", benchmarks),
    `${[
      item("CIS AWS", "1.2.0/1.4.0", "1.1"),
      item("NIST 800-53", "rev5", "AC-2"),
      item("ISO 27001", "2022", "A.8.2"),
    ].join("；")}${jaInline[" and {hidden} more"]!.replace("{hidden}", "1")}${jaInline[" (reported by {engine})"]!.replace("{engine}", "Checkov")}`,
  );
});

test("findingUnattributedGap formats dimension, reason, and nextAction in en, zh-TW, and ja", () => {
  const unattributed: UnattributedResults = {
    provider: "aws_account",
    identifier: "123456789012",
    discardedResults: 4,
  };
  const english = {
    dimension: "prowler: results for aws_account 123456789012",
    reason:
      "prowler reported 4 results for aws_account identifier 123456789012. None of your authorized assets carry this identifier, so those results were not attributed and are absent from this report.",
    nextAction: "Add aws_account identifier 123456789012 to your authorized asset and scan again.",
  };
  assert.deepEqual(findingUnattributedGap("en", "prowler", unattributed, english), english);
  assert.deepEqual(findingUnattributedGap("zh-TW", "prowler", unattributed, english), {
    dimension: "prowler：針對 aws_account 123456789012 的結果",
    reason:
      "prowler 回報了 4 筆針對 aws_account 識別碼 123456789012 的結果。你已授權的資產都沒有登記這個識別碼，因此這些結果都沒有被歸屬，也不會出現在這份報告中。",
    nextAction: "請在你已授權的資產上，新增 aws_account 識別碼 123456789012，然後重新掃描。",
  });
  assert.deepEqual(findingUnattributedGap("ja", "prowler", unattributed, english), {
    dimension: jaInline["{engineId}: results for {provider} {identifier}"]!
      .replace("{engineId}", "prowler")
      .replace("{provider}", "aws_account")
      .replace("{identifier}", "123456789012"),
    reason: jaInline[
      "{engineId} reported {discardedResults} results for {provider} identifier {identifier}. None of your authorized assets carry this identifier, so those results were not attributed and are absent from this report."
    ]!
      .replace("{engineId}", "prowler")
      .replace("{discardedResults}", "4")
      .replace("{provider}", "aws_account")
      .replace("{identifier}", "123456789012"),
    nextAction: jaInline["Add {provider} identifier {identifier} to your authorized asset and scan again."]!
      .replace("{provider}", "aws_account")
      .replace("{identifier}", "123456789012"),
  });
});

test("findingActionSentence covers sourceAudit, unconfirmed, IAM, families, and fallback in en, zh-TW, and ja", () => {
  assert.equal(
    findingActionSentence("ja", { sourceAudit: true, englishFallback: "Native remediation.", family: "source_code" }),
    "Native remediation.",
  );

  assert.equal(
    findingActionSentence("en", { englishFallback: "Fallback.", unconfirmedByCoverage: true }),
    INCOMPLETE_CHECK_CONFIRM_ACTION,
  );
  assert.equal(
    findingActionSentence("zh-TW", { englishFallback: "Fallback.", unconfirmedByCoverage: true }),
    INCOMPLETE_CHECK_CONFIRM_ACTION_ZH_HANT,
  );
  assert.equal(
    findingActionSentence("ja", { englishFallback: "Fallback.", unconfirmedByCoverage: true }),
    jaInline[INCOMPLETE_CHECK_CONFIRM_ACTION],
  );

  const iam: AwsIamPolicyFindingDetails = {
    policySource: "inline",
    policyName: "InlineAdmin",
    findingIdentity: "iam-1",
    actions: ["*"],
    actionsComplete: true,
    attachedTo: { roles: ["app-role"], groups: [], users: [], complete: true },
  };
  for (const locale of ["en", "zh-TW", "ja"] as const) {
    assert.equal(
      findingActionSentence(locale, { englishFallback: "Fallback.", family: "cloud_identity", awsIamPolicy: iam }),
      awsIamPolicyAction(iam, locale),
    );
  }

  const remedyByFamily = Object.fromEntries(objectEntries("REMEDY_ENGLISH")) as Record<FindingFamily, string>;
  for (const [family, remedyEnglish] of Object.entries(remedyByFamily) as Array<[FindingFamily, string]>) {
    assert.equal(findingActionSentence("en", { englishFallback: "Fallback.", family }), `${remedyEnglish}.`);
    assert.equal(findingActionSentence("ja", { englishFallback: "Fallback.", family }), `${jaInline[remedyEnglish]}。`);
    assert.ok(!findingActionSentence("ja", { englishFallback: "Fallback.", family }).endsWith("。。"));
  }
  assert.equal(
    findingActionSentence("zh-TW", { englishFallback: "Fallback.", family: "infrastructure_as_code" }),
    "修改基礎架構即程式碼的範本，讓重新部署不會再還原這個設定。",
  );
  assert.equal(
    findingActionSentence("zh-TW", { englishFallback: "Fallback.", family: "secret" }),
    EXPOSED_CREDENTIAL_NEXT_STEP_ZH_HANT,
  );

  for (const locale of ["en", "zh-TW", "ja"] as const) {
    assert.equal(
      findingActionSentence(locale, { englishFallback: "Review details, then plan and approve rotating the token." }),
      "Rotating the token.",
    );
    assert.equal(
      findingActionSentence(locale, { englishFallback: "Custom untranslated action." }),
      "Custom untranslated action.",
    );
  }
});

test("beginnerStepAction covers finding-derived, unattributed, gap-derived, and fallback in en, zh-TW, and ja", () => {
  const findings = [
    {
      findingId: "f-iac",
      evidenceReferences: [{ engineId: "checkov", engineRunId: "task-1" }],
    },
    {
      findingId: "f-audit",
      sourceAudit: true,
      evidenceReferences: [{ engineId: "cloudflare", engineRunId: "task-audit" }],
    },
  ];
  const incompleteChecks = [{ taskId: "task-1", status: "failed" as const }];
  const completeChecks = [{ taskId: "task-1", status: "tested_complete" as const }];

  assert.equal(
    beginnerStepAction("ja", { action: "Native step action.", findingId: "f-audit", family: "source_code", reason: "audit" }, findings),
    "Native step action.",
  );

  const unattributedStep = {
    action: "Add aws_account identifier 123456789012 to your authorized asset and scan again.",
    unattributed: { provider: "aws_account", identifier: "123456789012", discardedResults: 2 },
    reason: "prowler reported unattributed results",
  };
  assert.equal(beginnerStepAction("en", unattributedStep, findings), unattributedStep.action);
  assert.equal(
    beginnerStepAction("zh-TW", unattributedStep, findings),
    "請在你已授權的資產上，新增 aws_account 識別碼 123456789012，然後重新掃描。",
  );
  assert.equal(
    beginnerStepAction("ja", unattributedStep, findings),
    jaInline["Add {provider} identifier {identifier} to your authorized asset and scan again."]!
      .replace("{provider}", "aws_account")
      .replace("{identifier}", "123456789012"),
  );

  const iacStep = {
    action: "Correct the infrastructure-as-code template so redeployment does not restore the insecure setting.",
    family: "infrastructure_as_code" as const,
    findingId: "f-iac",
    reason: "S3 ACL",
  };
  assert.equal(beginnerStepAction("en", iacStep, findings, completeChecks), iacStep.action);
  assert.equal(
    beginnerStepAction("zh-TW", iacStep, findings, completeChecks),
    "修改基礎架構即程式碼的範本，讓重新部署不會再還原這個設定。",
  );
  assert.equal(
    beginnerStepAction("ja", iacStep, findings, completeChecks),
    `${jaInline["Correct the infrastructure-as-code template so redeployment does not restore the insecure setting"]}。`,
  );

  assert.equal(beginnerStepAction("en", iacStep, findings, incompleteChecks), INCOMPLETE_CHECK_CONFIRM_ACTION);
  assert.equal(beginnerStepAction("zh-TW", iacStep, findings, incompleteChecks), INCOMPLETE_CHECK_CONFIRM_ACTION_ZH_HANT);
  assert.equal(beginnerStepAction("ja", iacStep, findings, incompleteChecks), jaInline[INCOMPLETE_CHECK_CONFIRM_ACTION]);

  const gapKnown = {
    action: "Retry this check; scan-tool setup is automatic.",
    reason: "Check did not run.",
  };
  assert.equal(beginnerStepAction("en", gapKnown, findings), gapKnown.action);
  assert.equal(beginnerStepAction("zh-TW", gapKnown, findings), "重試這項檢查；掃描工具會自動準備。");
  assert.equal(beginnerStepAction("ja", gapKnown, findings), jaInline[gapKnown.action]);

  const gapPlanAndApprove = {
    action: "Wait for setup, then plan and approve retry this check; scan-tool setup is automatic.",
    reason: "Check did not run.",
  };
  assert.equal(beginnerStepAction("en", gapPlanAndApprove, findings), gapPlanAndApprove.action);
  assert.equal(beginnerStepAction("zh-TW", gapPlanAndApprove, findings), "重試這項檢查；掃描工具會自動準備。");
  assert.equal(beginnerStepAction("ja", gapPlanAndApprove, findings), jaInline[gapKnown.action]);

  const gapUnknown = { action: "Custom untranslated gap step.", reason: "Unknown." };
  for (const locale of ["en", "zh-TW", "ja"] as const) {
    assert.equal(beginnerStepAction(locale, gapUnknown, findings), gapUnknown.action);
  }
});

test("findingLocationText and findingLineText format coordinates and preserve raw non-path locations", () => {
  const full = "infra/main.tf:line=12:column=4:resource=aws_s3_bucket.example,similarity:deadbeef";
  assert.equal(findingLocationText("en", full), "infra/main.tf · line 12, column 4 · aws_s3_bucket.example");
  assert.equal(findingLocationText("zh-TW", full), "infra/main.tf · 第 12 行第 4 欄 · aws_s3_bucket.example");
  assert.equal(
    findingLocationText("ja", full),
    `infra/main.tf · ${jaInline["line {line}, column {column}"]!.replace("{line}", "12").replace("{column}", "4")} · aws_s3_bucket.example`,
  );

  assert.equal(findingLocationText("en", "./src\\app.ts:line=8:resource=n/a"), "src/app.ts · line 8");
  assert.equal(findingLocationText("zh-TW", "./src\\app.ts:line=8:resource=n/a"), "src/app.ts · 第 8 行");
  assert.equal(
    findingLocationText("ja", "./src\\app.ts:line=8:resource=n/a"),
    `src/app.ts · ${jaInline["line {line}"]!.replace("{line}", "8")}`,
  );

  assert.equal(findingLocationText("en", "/Dockerfile:column=3:resource=/Dockerfile.EXPOSE"), "Dockerfile · column 3 · EXPOSE");
  assert.equal(findingLocationText("zh-TW", "/Dockerfile:column=3:resource=/Dockerfile.EXPOSE"), "Dockerfile · 第 3 欄 · EXPOSE");
  assert.equal(
    findingLocationText("ja", "/Dockerfile:column=3:resource=/Dockerfile.EXPOSE"),
    `Dockerfile · ${jaInline["column {column}"]!.replace("{column}", "3")} · EXPOSE`,
  );

  assert.equal(findingLineText("en", full), "infra/main.tf · line 12");
  assert.equal(findingLineText("zh-TW", full), "infra/main.tf · 第 12 行");
  assert.equal(
    findingLineText("ja", full),
    `infra/main.tf · ${jaInline["line {line}"]!.replace("{line}", "12")}`,
  );

  for (const locale of ["en", "zh-TW", "ja"] as const) {
    assert.equal(findingLocationText(locale, "./src\\index.ts"), "src/index.ts");
    assert.equal(findingLocationText(locale, "https://example.com:8443/login"), "https://example.com:8443/login");
    assert.equal(findingLocationText(locale, "pkg:npm/lodash@4.17.20"), "pkg:npm/lodash@4.17.20");
  }
});
