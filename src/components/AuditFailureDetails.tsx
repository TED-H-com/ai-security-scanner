import { useI18n } from "../i18n";
import type { BeginnerTechnicalExecution } from "../types";

export function AuditFailureDetails({ execution }: {
  execution: Extract<BeginnerTechnicalExecution, { kind: "agent_audit_failure" }>;
}) {
  const { text, formatDateTime } = useI18n();
  const ending = execution.ending;
  const rows: Array<[string, string, string | number]> = [
    ["Source audit", "原始碼稽核", text(ending.ending === "blocked"
      ? { en: "Source audit did not start", zhTW: "原始碼稽核未開始" }
      : { en: "Source audit ended before completion", zhTW: "原始碼稽核未完成即結束" })],
    ["reason codes", "原因代碼", ending.ending === "blocked" ? ending.reasons.join(", ") : ending.reason],
    ["recorded time", "記錄時間", formatDateTime(execution.occurredAt)],
    ["preparation receipt SHA-256", "準備收據 SHA-256", execution.receiptSha256],
  ];
  if (ending.ending === "terminated") rows.push(
    ["terminal record entry SHA-256", "終態紀錄項目 SHA-256", execution.terminalSha256],
    ["assignment count", "派工筆數", ending.assignment_count],
    ["capture count", "擷取筆數", ending.capture_count],
  );
  return <>{rows.map(([en, zhTW, value]) => <div key={en}>
    <dt>{text({ en, zhTW })}</dt><dd>{value}</dd>
  </div>)}</>;
}
