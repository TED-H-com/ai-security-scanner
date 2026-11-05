import { useI18n } from "../i18n";
import { incidentFocusCopy, incidentIssueGuidance, type IncidentCampaignReport } from "../incidentFocusProfile";
import { maskSecrets } from "../technicalDetails";

export function IncidentFocusReport({ report, targets }: {
  report: IncidentCampaignReport;
  targets: ReadonlyArray<{ assetId: string; label?: string }>;
}) {
  const { locale, text } = useI18n();
  const copy = incidentFocusCopy[locale];
  const matches = report.issues.filter((issue) => issue.status === "upstream_match").length;
  return (
    <section className="section-block" aria-label={copy.title}>
      <h3>{copy.title}</h3>
      <p>{text({ en: "{count} asset/advisory matches. Review the remaining incident coverage below.",
        zhTW: "找到 {count} 筆資產與漏洞公告命中；其餘事件的涵蓋範圍如下。" }, { count: matches })}</p>
      <details className="page-technical-details">
        <summary>{text({ en: "Incident coverage and next actions", zhTW: "事件涵蓋範圍與下一步" })}</summary>
        <p>{copy.limit}</p>
        <div className="table-wrap"><table className="data-table"><thead><tr>
          <th>{text({ en: "Issue", zhTW: "項目" })}</th>
          <th>{text({ en: "Asset", zhTW: "資產" })}</th>
          <th>{text({ en: "Outcome", zhTW: "結果" })}</th>
          <th>{text({ en: "Evidence and guidance", zhTW: "證據與建議" })}</th>
        </tr></thead><tbody>
          {report.issues.map((issue) => {
            const guidance = incidentIssueGuidance(issue, locale);
            return <tr key={`${issue.issue_id}-${issue.asset_id ?? "all"}`}>
            <td>{maskSecrets(issue.title)}</td>
            <td>{targets.find((target) => target.assetId === issue.asset_id)?.label
              ?? text({ en: "Incident context", zhTW: "事件資訊" })}</td>
            <td>{copy[issue.status]}</td>
            <td><details><summary>{text({ en: "View details", zhTW: "查看詳情" })}</summary>
              <p>{guidance.reason}</p><p>{guidance.nextAction}</p>
              {issue.finding_ids.length > 0 && <p>{text({ en: "Original findings", zhTW: "原始發現" })}: {issue.finding_ids.join(", ")}</p>}
              <ul>{issue.sources.filter((source) => source.startsWith("https://")).map((source) =>
                <li key={source}><a href={source} target="_blank" rel="noreferrer">{new URL(source).hostname}</a></li>)}</ul>
            </details></td>
          </tr>;
          })}
        </tbody></table></div>
      </details>
    </section>
  );
}
