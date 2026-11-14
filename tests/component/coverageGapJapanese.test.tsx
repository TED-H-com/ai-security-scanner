import { cleanup, render } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";

import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { FindingsPage } from "../../src/pages/FindingsPage";
import { failureReport, failureRun } from "../support/auditFailure";
import type { BeginnerMasterReport } from "../../src/types";

afterEach(() => { cleanup(); localStorage.clear(); });

const show = (report: BeginnerMasterReport) => render(<I18nProvider><FindingsPage
  report={report} selectedRunId={report.runId} findings={[]} findingGroups={[]} findingGroupEvents={[]}
  runs={[failureRun("blocked")]} workflowEvents={[]} busy={false} onUpdateWorkflow={async () => true}
  onGroupFindings={async () => true} onUngroupFindings={async () => {}}
  onOpenCoverage={vi.fn()} onOpenProgress={vi.fn()} onOpenExport={vi.fn()}
/></I18nProvider>);

test("Japanese findings page shows the coverage gap reason and next action in Japanese", () => {
  localStorage.setItem(localeStorageKey, "ja");
  const report = failureReport("blocked");
  delete report.actual.checks[0]!.outcome;
  const reason = "This check did not start, so it is not a pass.";
  const action = "Retry this check.";
  Object.assign(report.coverageGaps[0]!, { reason, nextAction: action });
  const { container } = show(report);
  const gap = [...container.querySelectorAll(".coverage-card li")]
    .find((row) => row.textContent?.includes("この確認は開始されなかったため、合格とは見なせません。"));
  expect(gap).toBeDefined();
  expect(gap!.textContent).toContain("この確認を再試行してください。");
  expect(container.textContent).not.toContain(reason);
  expect(container.textContent).not.toContain(action);
});

test("Japanese audit outcome sentences join without spaces", () => {
  localStorage.setItem(localeStorageKey, "ja");
  const { container } = show(failureReport("blocked"));
  expect(container.querySelector(".source-audit-failure p")?.textContent).toBe(
    "Cloudflare ソースコード監査は開始されませんでした。独立したレビューエージェントを利用できませんでした。独立したエージェントに対応するアシスタントを使用し、新しいソースコード監査を開始してください。",
  );
});
