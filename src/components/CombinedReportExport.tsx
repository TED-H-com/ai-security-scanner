import { runSupportsReportAttachments } from "../exportFormatEligibility";
import { useState } from "react";
import { useI18n } from "../i18n";
import { runStatusMeta } from "../lib";
import { reportLocaleForUiLocale } from "../reportLocale";
import { hasSourceAudit, isTerminalResultRun } from "../runLifecycle";
import { scanRunIdentityPresentation } from "../scanRunIdentityPresentation";
import { scannerService } from "../services/scanner";
import type { ScanRun } from "../types";

const copy = {
  title: { en: "Combine saved scan results", zhTW: "整合已保存的掃描結果" },
  detail: { en: "Choose 2–16 finished scans, including imported results. One report groups their problems by asset and retains each source's date and coverage.",
    zhTW: "選擇 2–16 筆已結束的掃描，也可包含匯入結果。報告會依資產整理問題，並保留各來源的時間與涵蓋範圍。" },
  sources: { en: "Scans to include", zhTW: "要整合的掃描" },
  imported: { en: "Imported evidence", zhTW: "匯入證據" },
  blocked: { en: "Cloudflare source audit — did not start", zhTW: "Cloudflare 原始碼稽核 — 未開始" },
  terminated: { en: "Cloudflare source audit — ended before completion", zhTW: "Cloudflare 原始碼稽核 — 未完成即結束" },
  audit: { en: "Source audit", zhTW: "原始碼稽核" },
  saved: { en: "Saved scan", zhTW: "已保存的掃描" },
  format: { en: "File format", zhTW: "檔案格式" },
  redact: { en: "Hide sensitive identifiers", zhTW: "遮罩敏感識別資訊" },
  originals: { en: "Include original files and allow a private case archive if they exceed the report limit", zhTW: "附上原始檔案；超出報告容量時，另存私密案件封存" },
  originalsDetail: { en: "Original files can contain sensitive data. The fallback archive includes the full case and evidence from all its scans. Keep it private when sharing the report.", zhTW: "原始檔案可能含敏感資料。超限時的封存包含完整案件與所有掃描證據；分享報告時請將封存另行保密。" },
  auditOriginals: { en: "Include original files", zhTW: "附上原始檔案" },
  auditOriginalsDetail: { en: "Standard excludes source audit originals. With masking disabled, originals may contain sensitive data. If attachments exceed the limit, select fewer runs or export a case bundle.", zhTW: "標準遮罩會排除原始碼稽核原件。停用遮罩時，原件可能包含敏感資料。若附件超出容量，請減少選取的輪次或匯出案件包。" },
  savedArchive: { en: "Original files: {path}", zhTW: "原始檔案封存：{path}" },
  export: { en: "Save combined report", zhTW: "儲存整合報告" },
  preparing: { en: "Preparing…", zhTW: "準備中…" },
  savedFile: { en: "Saved to {path}", zhTW: "已儲存至 {path}" },
};

export function CombinedReportExport({ caseId, runs, nativeMode, busy }: {
  caseId: string;
  runs: ScanRun[];
  nativeMode: boolean;
  busy?: boolean;
}) {
  const { locale, text, formatDateTime } = useI18n();
  const [selected, setSelected] = useState<string[]>([]);
  const [format, setFormat] = useState<"html" | "json">("html");
  const [originals, setOriginals] = useState(false);
  const [redact, setRedact] = useState(true);
  const [working, setWorking] = useState(false);
  const [message, setMessage] = useState("");
  const terminalRuns = runs.filter(isTerminalResultRun);
  const caseHasAudit = runs.some(hasSourceAudit);
  const selectedIds = selected.filter((id) => terminalRuns.some((run) => run.id === id));
  const attachmentsAvailable = terminalRuns.filter((run) => selectedIds.includes(run.id)).every(runSupportsReportAttachments);
  if (terminalRuns.length < 2) return null;
  const exportReport = async () => {
    if (selectedIds.length < 2 || selectedIds.length > 16) return;
    setWorking(true);
    setMessage("");
    try {
      const result = await scannerService.exportSelectedRunReport({ caseId, runIds: selectedIds,
        locale: reportLocaleForUiLocale(locale), format, redactSensitiveValues: redact,
        ...(attachmentsAvailable && originals && format === "html" ? { includeRawArtifacts: true, acknowledgeSensitiveRawArtifacts: true, acknowledgeSensitiveData: true } : {}) });
      if (result.data) setMessage(text(copy.savedFile).replace("{path}", result.data.path)
        + (result.data.attachment_archive ? ` · ${text(copy.savedArchive).replace("{path}", result.data.attachment_archive.path)}` : ""));
    } catch (error) {
      setMessage(String(error));
    } finally {
      setWorking(false);
    }
  };
  return (
    <details className="section-block page-secondary-feature">
      <summary>{text(copy.title)}</summary>
      <p>{text(copy.detail)}</p>
      <fieldset className="scope-mode-fieldset">
        <legend>{text(copy.sources)}</legend>
        <div className="scope-mode-grid">
          {terminalRuns.map((run) => {
            const checked = selectedIds.includes(run.id);
            const audit = run.engineRuns.length > 0 && run.engineRuns.every((task) => task.taskKind.kind === "agent_audit");
            const failure = run.engineRuns.find((task) => task.taskKind.kind === "agent_audit_failure")?.taskKind;
            const imported = run.engineRuns.some((task) => task.taskKind.kind === "external_report_import");
            return <label key={run.id} className={checked ? "scope-mode-card scope-mode-card--active" : "scope-mode-card"}>
              <input type="checkbox" checked={checked}
                disabled={!nativeMode || busy || working || (!checked && selectedIds.length >= 16)}
                onChange={() => { setMessage(""); setSelected((current) => checked
                  ? current.filter((id) => id !== run.id) : [...current, run.id]); }} />
              <span><strong>{scanRunIdentityPresentation(run, locale)}</strong>
                <small>{formatDateTime(run.finishedAt ?? run.startedAt)} · {text(failure?.kind === "agent_audit_failure" ? copy[failure.outcome.ending] : audit ? copy.audit : imported ? copy.imported : copy.saved)} · {runStatusMeta[run.status].label}</small></span>
            </label>;
          })}
        </div>
      </fieldset>
      <div className="form-grid form-grid--two">
        <label className="field"><span>{text(copy.format)}</span>
          <select value={format} disabled={working || busy} onChange={(event) => { setFormat(event.target.value as "html" | "json"); setOriginals(false); setMessage(""); }}>
            <option value="html">HTML</option><option value="json">JSON</option>
          </select>
        </label>
        <label className="toggle-row"><input type="checkbox" checked={redact} disabled={working || busy}
          onChange={(event) => setRedact(event.target.checked)} /><span>{text(copy.redact)}</span></label>
      </div>
      {format === "html" && attachmentsAvailable && <div>
        <label className="toggle-row"><input type="checkbox" checked={originals} disabled={!nativeMode || working || busy}
          onChange={(event) => { setOriginals(event.target.checked); setMessage(""); }} />
          <span>{text(caseHasAudit ? copy.auditOriginals : copy.originals)}</span></label>
        {originals && <p>{text(caseHasAudit ? copy.auditOriginalsDetail : copy.originalsDetail)}</p>}
      </div>}
      <div className="form-actions"><button type="button" className="button button--secondary"
        disabled={!nativeMode || busy || working || selectedIds.length < 2 || selectedIds.length > 16}
        onClick={() => void exportReport()}>{text(working ? copy.preparing : copy.export)}</button></div>
      {message && <p role="status" style={{ overflowWrap: "anywhere" }}>{message}</p>}
    </details>
  );
}
