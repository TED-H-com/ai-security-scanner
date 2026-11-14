import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { parseSync } from "vite";
import {
  ENGLISH_ROLLBACK,
  EXPOSED_CREDENTIAL_NEXT_STEP_ENGLISH,
  EXPOSED_CREDENTIAL_NEXT_STEP_ZH_HANT,
  awsIamPolicyAction,
  awsIamPolicySourceLabel,
  exposedCredentialNextStep,
  findingConfidencePresentation,
  findingHeadline,
  findingImpactSentence,
  findingRollbackSentence,
  findingSummarySentence,
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
  ConfidenceBasisCode,
  ContextFactor,
  FindingFamily,
  SeverityBasisCode,
} from "../../src/types.ts";

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
    assert.equal(prop.value?.type, "Literal");
    assert.equal(typeof prop.value?.value, "string");
    return [key, prop.value.value as string];
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
] as const;

test("finding line tables and templates have complete Japanese entries with matching placeholders", () => {
  const confidenceBasisValues = objectEntries("CONFIDENCE_BASIS_ENGLISH").map(([, value]) => value);
  const basisValues = objectEntries("BASIS_ENGLISH").map(([, value]) => value);
  const consequenceValues = objectEntries("CONSEQUENCE_ENGLISH").map(([, value]) => value);
  const contextValues = objectEntries("CONTEXT_ENGLISH").map(([, value]) => value);
  const expertKeys = objectEntries("EXPERT").map(([key]) => key);

  const english = new Set([
    ...confidenceBasisValues,
    ...basisValues,
    ...consequenceValues,
    ...contextValues,
    ...expertKeys,
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
