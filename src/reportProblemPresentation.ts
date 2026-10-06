import { exposedCredentialNextStep } from "./findingNarrative.ts";
import type { Locale } from "./i18n";
import type { BeginnerReportFinding, BeginnerReportProblemGroup, Finding, Severity } from "./types";

type ProblemFinding = Finding | BeginnerReportFinding;
export interface ProblemRow<T extends ProblemFinding> {
  finding: T;
  members: T[];
  group?: BeginnerReportProblemGroup;
}

const idOf = (finding: ProblemFinding): string =>
  "findingId" in finding ? finding.findingId : finding.id;
const assetsOf = (finding: ProblemFinding): string[] =>
  "targetAssetIds" in finding ? finding.targetAssetIds : finding.assetIds ?? [finding.assetId];
const severityOrder: Severity[] = ["critical", "high", "medium", "low", "unknown", "info"];

/** Render the groups selected by the shared report; never classify scanner rules here. */
export function projectProblemRows<T extends ProblemFinding>(
  findings: readonly T[],
  groups: readonly BeginnerReportProblemGroup[] = [],
): ProblemRow<T>[] {
  const byId = new Map(findings.map(finding => [idOf(finding), finding]));
  const membership = new Map<string, ProblemRow<T>>();
  for (const group of groups) {
    const ids = [...new Set(group.findingIds)];
    const members = ids.flatMap(id => byId.has(id) ? [byId.get(id)!] : []);
    if (!ids.includes(group.representativeFindingId) || members.length < 2 || members.some(member =>
      assetsOf(member).length !== 1 || assetsOf(member)[0] !== group.targetAssetId
      || membership.has(idOf(member)))) continue;
    const finding = [...members].sort((left, right) =>
      severityOrder.indexOf(left.severity) - severityOrder.indexOf(right.severity)
      || (right.priority ?? 0) - (left.priority ?? 0)
      || idOf(left).localeCompare(idOf(right)))[0]!;
    const row = { finding, members, group };
    for (const member of members) membership.set(idOf(member), row);
  }
  const emitted = new Set<string>();
  return findings.flatMap(finding => {
    const row = membership.get(idOf(finding));
    if (!row) return [{ finding, members: [finding] }];
    if (emitted.has(row.group!.groupId)) return [];
    emitted.add(row.group!.groupId);
    return [row];
  });
}

export function problemGroupTitle(group: BeginnerReportProblemGroup, locale: Locale): string {
  if (locale === "en") return group.title;
  switch (group.kind) {
    case "iam_password_policy": return "IAM 密碼政策需要調整";
    case "root_account_usage": return "最近使用過 root 帳號";
    case "iam_policy_permissions": return `檢查 IAM policy 的權限：${group.policyName ?? "IAM policy"}`;
    case "vulnerable_dependency":
      return `有已知弱點的套件 ${group.packageName ?? ""} ${group.installedVersion ?? ""}（${(group.advisoryIds ?? []).join(" / ")}）`;
    case "exposed_secret": return "檔案中發現機密";
  }
}

export function problemGroupAction(group: BeginnerReportProblemGroup | undefined, locale: Locale): string | undefined {
  switch (group?.kind) {
    case "iam_password_policy":
      if (group.lowerPriorityMembers === "partial") return locale === "en"
        ? "Review the account's IAM password policy. Fix the failed length or reuse settings first; change the character-mix or expiry settings only if an audit you must pass still requires them."
        : "檢查帳號的 IAM 密碼政策：先調整未通過的長度或重複使用設定；字元組成或到期設定，只有在必須通過的稽核仍要求時才需要變更。";
      if (group.lowerPriorityMembers === "all") return locale === "en"
        ? "Change these IAM password policy settings only if an audit you must pass still requires them; NIST SP 800-63B-4 says not to require character mixes or scheduled expiry."
        : "只有在必須通過的稽核仍要求時，才需要變更這些 IAM 密碼政策設定；NIST SP 800-63B-4 要求不要強制混合字元類型或定期到期。";
      return locale === "en"
        ? "Review the account's IAM password policy and address each failed setting."
        : "檢查帳號的 IAM 密碼政策，並調整每項未通過的設定。";
    case "root_account_usage": return locale === "en"
      ? "Review each scanner's root-usage window and use an IAM role for routine work."
      : "檢查各掃描工具記錄的 root 使用時間範圍，日常工作改用 IAM role。";
    case "exposed_secret": return exposedCredentialNextStep(locale);
    case "vulnerable_dependency": return undefined;
    default: return undefined;
  }
}

export function problemGroupImpact(group: BeginnerReportProblemGroup | undefined, locale: Locale): string | undefined {
  switch (group?.kind) {
    case "iam_password_policy":
      if (group.lowerPriorityMembers === "all") return locale === "en"
        ? "CIS AWS Foundations Benchmark v1.2.0 lists these settings; current guidance does not treat their absence as a weakness."
        : "CIS AWS Foundations Benchmark v1.2.0 列出這些設定；現行指引不把缺少這些設定視為弱點。";
      return locale === "en"
        ? "Weak password settings increase the risk of unauthorized access to IAM users."
        : "較弱的密碼設定會增加 IAM 使用者遭未授權存取的風險。";
    case "root_account_usage": return locale === "en"
      ? "Root-account activity uses permissions with broad control of this AWS account."
      : "root 帳號的活動會使用可廣泛控制此 AWS 帳號的權限。";
    case "vulnerable_dependency":
    case "exposed_secret": return undefined;
    default: return undefined;
  }
}
