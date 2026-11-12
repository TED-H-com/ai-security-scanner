/** Product-owned failure vocabulary; kept identical to agent_audit_failure/wording.rs. */
export const failureText = [
  ["The Cloudflare source audit did not start.", "Cloudflare 原始碼稽核未開始。"],
  ["The Cloudflare source audit ended before completion.", "Cloudflare 原始碼稽核未完成即結束。"],
  ["No source audit was performed for this asset.", "此資產未執行原始碼稽核。"],
  ["The source audit ended before completion; no audit results are available for this asset.", "原始碼稽核未完成即結束，此資產沒有可用的稽核結果。"],
  ["The audit was stopped before completion.", "稽核在完成前已停止。"],
  ["Start a new source audit when ready.", "準備好後開始新的原始碼稽核。"],
  ["The audit was interrupted.", "稽核流程中斷。"],
  ["Start a new source audit.", "開始新的原始碼稽核。"],
  ["The audit used its full invocation budget.", "稽核已用完呼叫預算。"],
  ["Start a new source audit with a larger budget.", "以較高的預算開始新的原始碼稽核。"],
  ["Source authorization was no longer available.", "原始碼授權已失效。"],
  ["Confirm source authorization, then start a new source audit.", "確認原始碼授權後，開始新的原始碼稽核。"],
  ["Files needed to finish the audit were unavailable.", "完成稽核所需的檔案無法取得。"],
  ["The audit workflow could not finish.", "稽核流程無法完成。"],
  ["The approved source snapshot was missing, not ready or changed.", "核准的原始碼快照遺失、尚未就緒或已變更。"],
  ["Prepare a new source snapshot, then start a new source audit.", "重新準備原始碼快照後，開始新的原始碼稽核。"],
  ["The audit was started from a different assistant than the approved one.", "啟動稽核的助理與核准的助理不同。"],
  ["Start a new source audit from the approved assistant.", "從核准的助理開始新的原始碼稽核。"],
  ["Independent review agents were not available.", "無法使用獨立審查代理。"],
  ["Use an assistant that supports independent agents, then start a new source audit.", "改用支援獨立代理的助理，再開始新的原始碼稽核。"],
  ["The invocation budget was too small for this audit.", "呼叫預算不足以進行此稽核。"],
  ["Source authorization was missing, expired or changed.", "原始碼授權缺失、已過期或已變更。"],
  ["The audit working folder was unavailable.", "稽核工作資料夾無法使用。"],
  ["Provide a new empty working folder, then start a new source audit.", "提供新的空白工作資料夾，再開始新的原始碼稽核。"],
  ["The scanner's pinned audit resources did not match.", "掃描工具固定的稽核資源不一致。"],
  ["Repair the scanner installation, then start a new source audit.", "修復掃描工具安裝後，開始新的原始碼稽核。"],
] as const;

export const blockerWording = {
  source_view_not_ready: [14, 15], view_missing: [14, 15], view_integrity_failed: [14, 15],
  snapshot_integrity_failed: [14, 15], source_binding_mismatch: [14, 15],
  host_mismatch: [16, 17], delegation_unavailable: [18, 19],
  budget_cannot_fund_reconnaissance_and_reserves: [20, 9],
  source_authorization_missing: [21, 11], source_authorization_expired: [21, 11], grant_changed: [21, 11],
  run_directory_unavailable: [22, 23], validator_resources_changed: [24, 25],
} as const;
export const terminationWording = {
  host_cancelled: [4, 5], host_interrupted: [6, 7], budget_exhausted: [8, 9],
  authorization_unavailable: [10, 11], required_artifacts_unavailable: [12, 7], workflow_failed: [13, 7],
} as const;
export type AuditFailureEnding =
  | { ending: "blocked"; reasons: Array<keyof typeof blockerWording> }
  | { ending: "terminated"; reason: keyof typeof terminationWording; assignment_count: number; capture_count: number };
export interface AuditFailureFields {
  preparation_request_id: string;
  preparation_receipt_sha256: string;
  asset_id: string;
  session_id?: string;
  terminal_sha256: string;
  occurred_at: string;
}
/** Outcome flattens Ending on the native wire; retain that exact DTO. */
export type AuditFailureOutcome = AuditFailureFields & AuditFailureEnding;
export interface AuditFailureTechnicalWire {
  kind: "agent_audit_failure";
  run_id: string;
  receipt_sha256: string;
  terminal_sha256: string;
  occurred_at: string;
  ending: AuditFailureEnding;
}

export function isAuditFailureOutcome(value: unknown): value is AuditFailureOutcome {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const o = value as Record<string, unknown>;
  const digest = (v: unknown) => typeof v === "string" && /^[0-9a-f]{64}$/u.test(v);
  const count = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  if (![o.preparation_request_id, o.asset_id, o.occurred_at].every((v) => typeof v === "string" && v.length > 0)
    || !Number.isFinite(Date.parse(String(o.occurred_at)))
    || (o.session_id !== undefined && (typeof o.session_id !== "string" || !o.session_id))
    || !digest(o.preparation_receipt_sha256) || !digest(o.terminal_sha256)) return false;
  return o.ending === "blocked"
    ? Array.isArray(o.reasons) && o.reasons.length > 0
      && o.reasons.every((code) => typeof code === "string" && Object.hasOwn(blockerWording, code))
    : o.ending === "terminated" && typeof o.reason === "string" && Object.hasOwn(terminationWording, o.reason)
      && count(o.assignment_count) && count(o.capture_count);
}

export const failureTranslation = (english: string): string | undefined =>
  failureText.find(([en]) => en === english)?.[1];
export function failureDescription(ending: AuditFailureEnding) {
  const terminated = ending.ending === "terminated";
  const [reason, action] = terminated ? terminationWording[ending.reason] : blockerWording[ending.reasons[0]!];
  const bilingual = (index: number) => ({ en: failureText[index]![0], zhTW: failureText[index]![1] });
  return { summary: bilingual(terminated ? 1 : 0), reason: bilingual(reason), nextAction: bilingual(action), gap: bilingual(terminated ? 3 : 2) };
}
