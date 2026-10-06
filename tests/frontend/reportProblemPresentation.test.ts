import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { projectProblemRows, problemGroupAction, problemGroupImpact, problemGroupTitle } from "../../src/reportProblemPresentation.ts";
import type { BeginnerReportProblemGroup, Finding } from "../../src/types.ts";

const finding = (id: string, severity: Finding["severity"] = "low", assetId = "aws"): Finding => ({
  id, fingerprint: id, assetId, assetIds: [assetId], assetName: "AWS account", title: id,
  summary: id, impact: id, recommendation: id, expertType: "cloud", severity, confidence: "high",
  priority: 50, workflowState: "unreviewed", evidence: [], controls: [], officialReferences: [],
  firstSeenAt: "2026-10-02T12:00:00Z", lastSeenAt: "2026-10-02T12:00:00Z",
});
const group: BeginnerReportProblemGroup = {
  groupId: "group", ruleVersion: "aws-related-checks-1", kind: "iam_password_policy",
  title: "IAM password policy needs attention", targetAssetId: "aws",
  representativeFindingId: "high", findingIds: ["low","high"],
};

test("report rows preserve originals and use the highest visible severity", () => {
  const findings = [finding("low"),finding("other","medium"),finding("high","high")];
  const before = structuredClone(findings);
  const rows = projectProblemRows(findings,[group]);
  assert.equal(rows.length,2);
  assert.equal(rows[0].finding.id,"high");
  assert.deepEqual(rows[0].members.map(member => member.id),["low","high"]);
  assert.deepEqual(findings,before);
  assert.deepEqual(projectProblemRows([findings[0]], [group]),[{finding:findings[0],members:[findings[0]]}]);
});
test("asset boundaries, missing members and overlapping groups cannot hide originals", () => {
  const findings = [finding("low"),finding("high","high","other-account")];
  assert.equal(projectProblemRows(findings,[group]).length,2);
  assert.equal(projectProblemRows([findings[0]], [group]).length,1);
  assert.equal(projectProblemRows(findings).length,2);
  const sameAsset = [finding("low"),finding("high","high"),finding("third")];
  const rows = projectProblemRows(sameAsset,[group,{...group,groupId:"overlap",findingIds:["high","third"]}]);
  assert.equal(rows.length,2);
  assert.equal(rows[1].finding.id,"third");
});
test("group titles translate product wording and keep the recorded policy label", () => {
  assert.equal(problemGroupTitle(group,"zh-TW"),"IAM 密碼政策需要調整");
  assert.equal(problemGroupTitle({...group,kind:"root_account_usage"},"zh-TW"),"最近使用過 root 帳號");
  assert.equal(problemGroupTitle({...group,kind:"iam_policy_permissions",policyName:"Policy 1"},"zh-TW"),"檢查 IAM policy 的權限：Policy 1");
});

const PARTIAL_ACTION = {
  en: "Review the account's IAM password policy. Fix the failed length or reuse settings first; change the character-mix or expiry settings only if an audit you must pass still requires them.",
  "zh-TW": "檢查帳號的 IAM 密碼政策：先調整未通過的長度或重複使用設定；字元組成或到期設定，只有在必須通過的稽核仍要求時才需要變更。",
} as const;
const ALL_ACTION = {
  en: "Change these IAM password policy settings only if an audit you must pass still requires them; NIST SP 800-63B-4 says not to require character mixes or scheduled expiry.",
  "zh-TW": "只有在必須通過的稽核仍要求時，才需要變更這些 IAM 密碼政策設定；NIST SP 800-63B-4 要求不要強制混合字元類型或定期到期。",
} as const;
const ALL_IMPACT = {
  en: "CIS AWS Foundations Benchmark v1.2.0 lists these settings; current guidance does not treat their absence as a weakness.",
  "zh-TW": "CIS AWS Foundations Benchmark v1.2.0 列出這些設定；現行指引不把缺少這些設定視為弱點。",
} as const;

test("a lowered password-policy group says what still comes first", () => {
  const partial = {...group, lowerPriorityMembers: "partial" as const};
  const all = {...group, lowerPriorityMembers: "all" as const};
  for (const locale of ["en", "zh-TW"] as const) {
    assert.equal(problemGroupAction(partial, locale), PARTIAL_ACTION[locale]);
    assert.equal(problemGroupImpact(partial, locale), problemGroupImpact(group, locale));
    assert.equal(problemGroupAction(all, locale), ALL_ACTION[locale]);
    assert.equal(problemGroupImpact(all, locale), ALL_IMPACT[locale]);
    assert.equal(problemGroupTitle(partial, locale), problemGroupTitle(group, locale));
    assert.equal(problemGroupTitle(all, locale), problemGroupTitle(group, locale));
  }
  const root = {...group, kind: "root_account_usage" as const, lowerPriorityMembers: "all" as const};
  assert.equal(problemGroupAction(root, "en"), problemGroupAction({...group, kind: "root_account_usage"}, "en"));
  assert.equal(problemGroupImpact(root, "zh-TW"), problemGroupImpact({...group, kind: "root_account_usage"}, "zh-TW"));
});

test("Results group guidance matches the shared HTML report in both languages", () => {
  const shared = readFileSync(new URL("../../src-tauri/src/report_problem_groups.rs", import.meta.url), "utf8");
  const passwordGroups = [
    group,
    {...group, lowerPriorityMembers: "partial" as const},
    {...group, lowerPriorityMembers: "all" as const},
  ];
  const missing: string[] = [];
  for (const kind of ["iam_password_policy", "root_account_usage"] as const) {
    for (const locale of ["en", "zh-TW"] as const) {
      const candidates = kind === "iam_password_policy" ? passwordGroups : [group];
      for (const base of candidates) {
        const candidate = {...base, kind};
        for (const sentence of [problemGroupTitle(candidate, locale), problemGroupAction(candidate, locale), problemGroupImpact(candidate, locale)]) {
          assert.ok(sentence);
          if (!shared.includes(JSON.stringify(sentence))) missing.push(`${locale} ${kind}: ${sentence}`);
        }
      }
    }
  }
  assert.deepEqual(missing, [], `Shared report must retain this guidance:\n${missing.join("\n")}`);
  assert.equal(problemGroupAction({...group,kind:"iam_policy_permissions"},"en"),undefined);
});

test("package and secret cards use the recorded fields and the secret remedy", () => {
  const dependency = {
    ...group,
    kind: "vulnerable_dependency" as const,
    title: "Vulnerable package pyyaml 5.3.1 (CVE-2020-14343 / GHSA-8q59-q68h-6hv4)",
    packageName: "pyyaml",
    installedVersion: "5.3.1",
    advisoryIds: ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"],
  };
  const secret = {
    ...group,
    kind: "exposed_secret" as const,
    title: "Secret found in a file",
  };
  assert.equal(problemGroupTitle(dependency, "en"), dependency.title);
  assert.equal(problemGroupTitle(dependency, "zh-TW"), "有已知弱點的套件 pyyaml 5.3.1（CVE-2020-14343 / GHSA-8q59-q68h-6hv4）");
  assert.equal(problemGroupTitle(secret, "en"), "Secret found in a file");
  assert.equal(problemGroupTitle(secret, "zh-TW"), "檔案中發現機密");
  assert.equal(problemGroupAction(dependency, "en"), undefined);
  assert.equal(problemGroupAction(dependency, "zh-TW"), undefined);
  assert.equal(problemGroupImpact(dependency, "en"), undefined);
  assert.equal(problemGroupImpact(secret, "zh-TW"), undefined);
  assert.equal(problemGroupAction(secret, "en"), "Revoke and rotate the exposed credential, then remove it from the source and every retained history entry.");
  assert.equal(problemGroupAction(secret, "zh-TW"), "先撤銷並輪替這組已外洩的憑證，再從原始碼以及仍保留它的歷史紀錄中移除。");
});
