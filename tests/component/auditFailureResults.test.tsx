import { cleanup, fireEvent, render, within } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { FindingsPage } from "../../src/pages/FindingsPage";
import { ProgressPage } from "../../src/pages/ProgressPage";
import { VerificationPage } from "../../src/pages/VerificationPage";
import { I18nProvider, localeStorageKey, formatLocaleDateTime } from "../../src/i18n";
import { failureReport, failureRun } from "../support/auditFailure";
import { auditReport, auditRun } from "../support/sourceAudit";
import type { BeginnerMasterReport, ScanRun } from "../../src/types";

afterEach(() => { cleanup(); localStorage.clear(); vi.restoreAllMocks(); });
const show = (report: BeginnerMasterReport, runs: ScanRun[]) => render(<I18nProvider><FindingsPage
  report={report} selectedRunId={report.runId} findings={[]} findingGroups={[]} findingGroupEvents={[]} runs={runs}
  workflowEvents={[]} busy={false} onUpdateWorkflow={async () => true} onGroupFindings={async () => true}
  onUngroupFindings={async () => {}} onOpenCoverage={vi.fn()} onOpenProgress={vi.fn()} onOpenExport={vi.fn()}
/></I18nProvider>);
const forbiddenControls = /resume|retry|rescan|restart|cancel|pause|Check fixes|cleanup|clean up|continue|恢復|重試|重掃|重新|取消|暫停|確認修復|清理|繼續/iu;
const words = {
  en: {
    method: "Cloudflare source audit", term: "Source audit", gaps: "What was not tested",
    blocked: ["The Cloudflare source audit did not start. Independent review agents were not available. Use an assistant that supports independent agents, then start a new source audit.", "No source audit was performed for this asset.", "Source audit did not start"],
    terminated: ["The Cloudflare source audit ended before completion. The audit used its full invocation budget. Start a new source audit with a larger budget.", "The source audit ended before completion; no audit results are available for this asset.", "Source audit ended before completion"],
    labels: ["reason codes", "recorded time", "preparation receipt SHA-256", "terminal record entry SHA-256", "assignment count", "capture count"],
  },
  "zh-TW": {
    method: "Cloudflare 原始碼稽核", term: "原始碼稽核", gaps: "沒有測到的內容",
    blocked: ["Cloudflare 原始碼稽核未開始。無法使用獨立審查代理。改用支援獨立代理的助理，再開始新的原始碼稽核。", "此資產未執行原始碼稽核。", "原始碼稽核未開始"],
    terminated: ["Cloudflare 原始碼稽核未完成即結束。稽核已用完呼叫預算。以較高的預算開始新的原始碼稽核。", "原始碼稽核未完成即結束，此資產沒有可用的稽核結果。", "原始碼稽核未完成即結束"],
    labels: ["原因代碼", "記錄時間", "準備收據 SHA-256", "終態紀錄項目 SHA-256", "派工筆數", "擷取筆數"],
  },
};
for (const locale of ["en", "zh-TW"] as const) {
  test(`${locale}: blocked and terminated Results retain exact sentences, gaps and ordered technical details`, () => {
    localStorage.setItem(localeStorageKey, locale);
    const report = failureReport("blocked");
    const terminated = failureReport("terminated");
    terminated.actual.checks[0]!.taskId = "terminated-task";
    terminated.technicalDetails.tasks[0]!.taskId = "terminated-task";
    terminated.coverageGaps[0]!.taskId = "terminated-task";
    report.actual.checks.push(...terminated.actual.checks);
    report.technicalDetails.tasks.push(...terminated.technicalDetails.tasks);
    report.coverageGaps.push(...terminated.coverageGaps);
    report.coverageCounts.failed = 1;
    const run = failureRun("blocked");
    const task = failureRun("terminated").engineRuns[0]!;
    task.id = "terminated-task";
    run.engineRuns.push(task);
    const { container } = show(report, [run]);
    const text = words[locale];
    const failures = container.querySelectorAll('.source-audit-failure');
    expect(failures).toHaveLength(2);
    expect(container.querySelector('.source-audit')).toBeNull();
    for (const [i, ending] of (["blocked", "terminated"] as const).entries()) {
      expect(failures[i]!.querySelector('h2')!.textContent).toBe(text.method);
      expect(failures[i]!.querySelector('p')!.textContent).toBe(text[ending][0]);
      expect(container.textContent).toContain(text[ending][1]);
      const detail = [...container.querySelectorAll('.evidence-item')].find((node) => node.querySelector('dd')?.textContent === text[ending][2])!;
      expect(detail).toBeTruthy();
      expect(detail.querySelector('dt')!.textContent).toBe(text.term);
      const rows = [...detail.querySelectorAll('dl > div')];
      expect(rows.slice(1, ending === "blocked" ? 4 : 7).map((row) => row.querySelector('dt')!.textContent)).toEqual(text.labels.slice(0, ending === "blocked" ? 3 : 6));
      expect(rows[1]!.querySelector('dd')!.textContent).toBe(ending === "blocked" ? "delegation_unavailable" : "budget_exhausted");
      expect(rows[2]!.querySelector('dd')!.textContent).toBe(formatLocaleDateTime(locale, "2026-11-12T00:01:00Z"));
      expect(rows[3]!.querySelector('dd')!.textContent).toBe("a".repeat(64));
      if (ending === "terminated") {
        expect(rows.slice(4, 7).map((row) => row.querySelector('dd')!.textContent)).toEqual(["b".repeat(64), "3", "2"]);
      }
      expect(detail.closest('details')!.open).toBe(false);
    }
    expect(container.textContent).toContain(text.gaps);
    for (const ending of ["blocked", "terminated"] as const) {
      const gap = [...container.querySelectorAll('li')].find((row) => row.textContent?.includes(text[ending][1]!));
      expect(gap).toBeTruthy();
      expect(gap!.textContent).toContain(locale === "en"
        ? ending === "blocked" ? "Use an assistant that supports independent agents, then start a new source audit." : "Start a new source audit with a larger budget."
        : ending === "blocked" ? "改用支援獨立代理的助理，再開始新的原始碼稽核。" : "以較高的預算開始新的原始碼稽核。");
    }
    expect(container.textContent).not.toMatch(/retry unfinished|重試未完成/u);
    expect(container.textContent).not.toMatch(/private-provider-string|synthetic-stale-token|No confirmed findings|已記錄的檢查中未發現已確認問題|Continue with the listed paths|請從列出的路徑繼續/u);
    for (const button of container.querySelectorAll('button')) expect(button.textContent).not.toMatch(forbiddenControls);
  });

  test(`${locale}: admitted audit and scanner sibling keep their existing result and technical detail`, () => {
    localStorage.setItem(localeStorageKey, locale);
    const report = failureReport("blocked");
    const admitted = auditReport();
    admitted.sourceAudits![0]!.task_id = "admitted-task";
    admitted.actual.checks[0]!.taskId = "admitted-task";
    admitted.technicalDetails.tasks[0]!.taskId = "admitted-task";
    report.sourceAudits = admitted.sourceAudits;
    report.actual.checks.push(admitted.actual.checks[0]!, { taskId: "scanner-task", checkId: "gitleaks", resultKind: "security_check", targetAssetIds: ["asset-status"], status: "tested_complete", testedDimensions: [] });
    report.technicalDetails.tasks.push(admitted.technicalDetails.tasks[0]!, { ...admitted.technicalDetails.tasks[0]!, taskId: "scanner-task", status: "completed", execution: { kind: "catalog_engine", engineId: "gitleaks", engineVersion: "8.30.0", adapterVersion: "synthetic" } });
    const run = failureRun("blocked");
    const auditTask = { ...auditRun().engineRuns[0]!, id: "admitted-task" };
    run.engineRuns.push(auditTask, { ...auditTask, id: "scanner-task", engineId: "gitleaks", engineName: "Gitleaks", status: "completed", taskKind: { kind: "catalog_engine" } });
    const { container } = show(report, [run]);
    expect(container.querySelectorAll('.source-audit-failure')).toHaveLength(1);
    const audit = container.querySelector('.source-audit')!;
    expect(audit.textContent).toContain("Candidate title");
    expect(audit.textContent).toContain(locale === "en" ? "Source audit incomplete: 1 unit remains. Continue with the listed paths." : "原始碼稽核未完成：尚有 1 個單元未完成。請從列出的路徑繼續。");
    expect(container.textContent).toContain("admission-one");
    const scanner = within(container).getByText("8.30.0").closest('.evidence-item')!;
    expect(scanner.textContent).toContain("Gitleaks");
    expect(scanner.textContent).not.toContain(words[locale].blocked[2]);
  });

  for (const ending of ["blocked", "terminated"] as const) test(`${locale}: ${ending} has no executable progress or verification controls`, () => {
    localStorage.setItem(localeStorageKey, locale);
    const run = failureRun(ending);
    // Stale recovery metadata must not expose controls on a terminal audit failure.
    Object.assign(run.engineRuns[0]!, { resumable: true, recoveryAction: "finish_cleanup", cleanupRemoved: false });
    const execute = vi.fn(async () => {});
    const { container, unmount } = render(<I18nProvider><ProgressPage assets={[]} findings={[]} runs={[run]} report={failureReport(ending)} selectedRunId={run.id}
      onStart={execute} onRetryLocalhostQuickScan={execute} onFixSetup={vi.fn()} onPause={execute} onResume={execute} onCancel={execute}
    /></I18nProvider>);
    for (const button of container.querySelectorAll('button')) expect(button.textContent).not.toMatch(forbiddenControls);
    expect(execute).not.toHaveBeenCalled();
    expect(container.textContent).toContain(locale === "en" ? "Completed0" : "已完成0");
    unmount();
    const verification = render(<I18nProvider><VerificationPage runs={[run]} findings={[]} baselineRunId={run.id}
      onSelectBaseline={vi.fn()} onStartRescan={execute} onOpenFinding={vi.fn()} /></I18nProvider>);
    expect(verification.container.querySelector(`option[value="${run.id}"]`)).toBeNull();
    for (const button of verification.container.querySelectorAll('button')) {
      if (forbiddenControls.test(button.textContent ?? "")) {
        expect(button.disabled).toBe(true);
        fireEvent.click(button);
      }
    }
    expect(execute).not.toHaveBeenCalled();
  });
}
