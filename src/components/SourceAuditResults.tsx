import { useI18n } from "../i18n";
import type { SourceAuditReportWire } from "../sourceAuditTypes";

/** Provider data never enters a markup parser, URL attribute, or translation lookup. */
export function ProviderValue({ value }: { value: unknown }) {
  const { text } = useI18n();
  if (value === null || value === undefined) return <span>{text({ en: "not recorded", zhTW: "未記錄" })}</span>;
  if (Array.isArray(value)) return <ul>{value.map((item, i) => <li key={i}><ProviderValue value={item} /></li>)}</ul>;
  if (typeof value === "object") return <dl>{Object.entries(value).map(([key, item]) => (
    <div key={key}><dt className="provider-text">{key}</dt><dd><ProviderValue value={item} /></dd></div>
  ))}</dl>;
  return <span className="provider-text">{String(value)}</span>;
}

const object = (value: unknown): Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const string = (value: unknown): string => typeof value === "string" ? value : "";

export function SourceAuditResults({ audits }: { audits: readonly SourceAuditReportWire[] }) {
  const { text } = useI18n();
  const t = (en: string, zhTW: string) => text({ en, zhTW });
  return <>{audits.map((audit) => {
    const n = audit.coverage_gaps.filter((gap) => gap.status !== "out_of_scope").length;
    const m = audit.unresolved_candidates.length;
    const unresolved = text({
      en: m === 1 ? "{count} candidate finding remains unresolved." : "{count} candidate findings remain unresolved.",
      zhTW: "尚有 {count} 個候選問題未解決。",
    }, { count: m });
    const incomplete = n > 0
      ? text({
        en: n === 1 ? "Source audit incomplete: {count} unit remains. Continue with the listed paths."
          : "Source audit incomplete: {count} units remain. Continue with the listed paths.",
        zhTW: "原始碼稽核未完成：尚有 {count} 個單元未完成。請從列出的路徑繼續。",
      }, { count: n })
      : m > 0 ? text({
        en: m === 1 ? "Source audit incomplete: {count} candidate finding remains unresolved."
          : "Source audit incomplete: {count} candidate findings remain unresolved.",
        zhTW: "原始碼稽核未完成：尚有 {count} 個候選問題未解決。",
      }, { count: m })
        : t("Source audit incomplete.", "原始碼稽核未完成。");
    const technical: Array<[string, string, unknown]> = [
      ["Method", "方法", audit.method], ["Outcome", "結果", audit.outcome],
      ["To validate records", "待驗證紀錄", audit.to_validate],
      ["Unresolved candidate fingerprints", "未解決候選問題的指紋", audit.unresolved_candidates],
      ["Counts", "計數", { records: audit.counts, coverage: audit.coverage_by_status }],
      ["Confirmed records", "已確認紀錄", audit.technical_detail.confirmed],
      ["Rejected records", "已排除紀錄", audit.technical_detail.rejected],
      ["Coverage and attempts", "涵蓋範圍與嘗試紀錄", audit.technical_detail.coverage_ledger],
      ["View and canonical lineage", "檢視與標準來源沿革", audit.technical_detail.lineage],
      ["Custody digests", "保管摘要", audit.technical_detail.custody_digests],
      ["Admission digest", "納入摘要", audit.technical_detail.admission_sha256],
      ["Copied originals and digests", "複製的原始檔與摘要", audit.technical_detail.originals],
    ];
    return <section key={audit.task_id} className="section-block source-audit" aria-label={t("Source audit", "原始碼稽核")}>
      <h2>{t("Source audit", "原始碼稽核")}</h2>
      <p>{t("Cloudflare source audit", "Cloudflare 原始碼稽核")}</p>
      {audit.outcome.state === "incomplete" && <>
        <p>{incomplete}</p>
        {audit.outcome.incomplete_reason !== null && <ProviderValue value={audit.outcome.incomplete_reason} />}
      </>}
      {m > 0 && <p>{unresolved}</p>}
      {audit.counts.confirmed === 0 && <p>{t("No confirmed findings in the recorded checks.", "已記錄的檢查中未發現已確認問題。")}</p>}
      {audit.to_validate.length > 0 && <h3>{t("To validate", "待驗證")}</h3>}
      {audit.to_validate.map((record) => {
        const native = object(record.native_record);
        const evidence = Array.isArray(native.evidence) ? native.evidence : [];
        const plan = object(native.validation_plan);
        return <article key={record.native_record_index} className="detail-section source-audit-candidate">
          <h4 className="provider-text">{string(native.title)}</h4>
          <h5>{t("Evidence locations", "證據位置")}</h5>
          {evidence.map((item, i) => {
            const location = object(item);
            return <div key={i}><ProviderValue value={`${string(location.file)}:${JSON.stringify(location.line ?? null)} — ${string(location.description)}`} /></div>;
          })}
          {([['description', 'Description', '說明'], ['claimed_root_cause', 'Claim', '待驗證主張'], ['blockers', 'Blockers', '阻礙']] as const).map(([key, en, zh]) =>
            <div key={key}><h5>{t(en, zh)}</h5><ProviderValue value={native[key]} /></div>)}
          <h5>{t("Validation plan", "驗證計畫")}</h5>
          <h6>{t("Local check", "本機檢查")}</h6><ProviderValue value={plan.local} />
          <h6>{t("Deployment check", "部署環境檢查")}</h6><ProviderValue value={plan.deployment} />
        </article>;
      })}
      {audit.coverage_gaps.length > 0 && <>
        <h3>{t("What was not tested", "未測試項目")}</h3>
        <ul>{audit.coverage_gaps.map((gap) => {
          const labels: Record<string, [string, string]> = {
            planned: ["Not started", "尚未開始"], in_progress: ["In progress", "進行中"],
            blocked: ["Blocked", "受阻"], deferred: ["Deferred", "已延後"],
            candidate: ["Unresolved candidate", "候選問題未解決"], out_of_scope: ["Outside the audit scope", "不在稽核範圍內"],
          };
          const label = labels[gap.status] ?? ["Not tested", "未測試"];
          return <li key={gap.coverage_id}>
            <div className="provider-text">{gap.label}{"\n"}{t(label[0]!, label[1]!)}</div>
            {gap.status !== "out_of_scope" && <>
              <p>{t("Continue with these paths", "請從這些路徑繼續")}</p>
              <ProviderValue value={gap.continuation_paths.join("\n")} />
            </>}
          </li>;
        })}</ul>
      </>}
      <details className="page-technical-details">
        <summary>{t("Source audit technical details", "原始碼稽核技術詳細資料")}</summary>
        <p>{t("Issued invocations", "已發出的呼叫次數")}: {audit.method.issued_invocations}</p>
        {technical.map(([en, zh, value]) => <section key={en}><h3>{t(en, zh)}</h3><ProviderValue value={value} /></section>)}
      </details>
    </section>;
  })}</>;
}
