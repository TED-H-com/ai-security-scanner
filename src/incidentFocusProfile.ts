import campaign from "../engines/campaigns/october-2026.json" with { type: "json" };

export const INCIDENT_FOCUS_ID = "october-2026";
export const incidentFocusProfile = campaign;

/** Apply only after existing per-asset eligibility and authorization routing. */
export const selectIncidentFocusEngines = (engineIds: readonly string[]): string[] =>
  [...new Set(engineIds.filter((id) => campaign.engine_ids.includes(id)))];

export type IncidentCoverageStatus = "upstream_match" | "not_tested" | "investigation_required" | "advisory_pending";
export interface IncidentIssueCoverage {
  issue_id: string;
  title: string;
  asset_id: string | null;
  status: IncidentCoverageStatus;
  finding_ids: string[];
  reason_code: string;
  reason: string;
  next_action: string;
  sources: string[];
}
export interface IncidentCampaignReport {
  campaign_id: string;
  title: string;
  reviewed_at: string;
  issues: IncidentIssueCoverage[];
}

/** Translate product guidance from shared campaign data; preserve saved evidence. */
export const incidentIssueGuidance = (issue: IncidentIssueCoverage, locale: string): {
  reason: string; nextAction: string;
} => {
  if (locale !== "zh-TW") return { reason: issue.reason, nextAction: issue.next_action };
  const entry = campaign.issues.find((candidate) => candidate.id === issue.issue_id);
  if (!entry) return { reason: issue.reason, nextAction: issue.next_action };
  const reasons: Readonly<Record<string, string>> = campaign.reason_zh_tw;
  const reason = issue.reason_code === "investigation" || issue.reason_code === "advisory_pending"
    ? entry.summary_zh_tw
    : reasons[issue.reason_code] ?? issue.reason;
  return { reason, nextAction: entry.next_action_zh_tw };
};

export const incidentFocusCopy = {
  en: {
    title: "October incident triage",
    description: "Check packages in selected local copies with Trivy, then review coverage of the October 21–22 incidents. Websites and internal hosts are excluded.",
    limit: "Specific advisory coverage depends on upstream detectors. Account breaches and advisories awaiting public CVE mappings need separate investigation.",
    upstream_match: "Upstream finding",
    not_tested: "Not tested",
    investigation_required: "Investigation needed",
    advisory_pending: "Advisory pending",
  },
  "zh-TW": {
    title: "10 月事件初步檢查",
    description: "使用 Trivy 檢查所選本機副本中的套件，並查看 10 月 21–22 日事件的涵蓋範圍。網站與內部主機不納入。",
    limit: "特定漏洞涵蓋範圍取決於上游偵測器。帳戶入侵及尚待 CVE 對應的漏洞須另外調查。",
    upstream_match: "上游發現",
    not_tested: "未測試",
    investigation_required: "需要調查",
    advisory_pending: "公告對應待確認",
  },
  ja: {
    title: "10 月のインシデント初期確認",
    description: "選択したローカルコピーのパッケージを Trivy で検査し、10 月 21～22 日の事案の確認範囲を表示します。Web サイトと内部ホストは対象外です。",
    limit: "個別の脆弱性の確認範囲は上流の検出機能によります。アカウント侵害と CVE の対応が未確認の脆弱性には別途調査が必要です。",
    upstream_match: "上流の検出結果",
    not_tested: "未検査",
    investigation_required: "調査が必要",
    advisory_pending: "公開情報の対応確認待ち",
  },
} as const;
