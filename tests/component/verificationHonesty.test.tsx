import { cleanup, fireEvent, render, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { VerificationPage } from "../../src/pages/VerificationPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type {
  BeginnerReportFinding,
  BeginnerReportProblemGroup,
  Finding,
  ScanRun,
  Severity,
  VerificationDiff,
  VerificationSummary,
} from "../../src/types";
import type { VerificationProblemReport } from "../../src/verificationProblems";

// This is the surface that answers "did the fix work". A wrong claim here is
// the most damaging one the app can make: a user reads it and closes the work.
//
// Three of its honesty properties are invisible to source matching because they
// are conditions, not strings. Whether the incomplete-comparison warning fires
// depends on the run status the backend attached rather than on the comparison
// summary alone; whether a "no longer observed" item still carries its caveat
// depends on a count; and whether an outcome filter that matches nothing says
// so depends on which branch renders. Each of them fails silently -- the page
// still renders, still adds up, and simply omits the qualification.

const run = (id: string, status: ScanRun["status"]): ScanRun => ({
  id,
  caseId: "case-1",
  label: id,
  status,
  progress: status === "completed" ? 100 : 60,
  startedAt: "2026-09-01T12:00:00Z",
  finishedAt: "2026-09-01T12:05:00Z",
  knowledgeDate: "2026-09-01",
  engineRuns: [],
  coveredAssetCount: 1,
  totalAssetCount: 1,
});

const diff = (overrides: Partial<VerificationDiff> & Pick<VerificationDiff, "id" | "state">): VerificationDiff => ({
  title: `Finding ${overrides.id}`,
  assetName: "acme.example",
  explanation: "Recorded comparison detail.",
  evidenceChanged: false,
  ...overrides,
});

const summary = (overrides: Partial<VerificationSummary> = {}): VerificationSummary => ({
  baselineRunId: "run-before",
  comparisonRunId: "run-after",
  baselineAt: "2026-09-01T12:00:00Z",
  comparisonAt: "2026-09-02T12:00:00Z",
  complete: true,
  diffs: [],
  ...overrides,
});

const renderVerification = (
  verification: VerificationSummary | undefined,
  runs: ScanRun[],
  findings: Finding[] = [],
  reports: {
    baselineReport?: VerificationProblemReport;
    currentReport?: VerificationProblemReport;
    onOpenFinding?: (findingId: string) => void;
  } = {},
) =>
  render(
    <I18nProvider>
      <VerificationPage
        verification={verification}
        runs={runs}
        findings={findings}
        baselineReport={reports.baselineReport}
        currentReport={reports.currentReport}
        baselineRunId="run-before"
        onSelectBaseline={() => {}}
        onStartRescan={() => Promise.resolve()}
        onOpenFinding={reports.onOpenFinding ?? (() => {})}
      />
    </I18nProvider>,
  );

/** The diff card carrying a given title; several rows render the same phrases. */
const diffRow = (container: HTMLElement, title: string): HTMLElement => {
  const row = Array.from(container.querySelectorAll<HTMLElement>(".diff-row")).find(
    (candidate) => candidate.textContent?.includes(title),
  );
  if (!row) throw new Error(`no diff row rendered for ${title}`);
  return row;
};

const bothRunsCompleted = [run("run-before", "completed"), run("run-after", "completed")];

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test.each([
  ["running", "active-run is running. Open it from My scans."],
  ["paused", "active-run is paused. Open it from My scans to Continue or Cancel."],
] as const)("an active %s scan returns verification to Progress directly", (status, expected) => {
  const { container } = renderVerification(
    undefined,
    [run("run-before", "completed"), run("active-run", status)],
  );

  const notice = container.querySelector<HTMLElement>(".inline-notice--warning");
  expect(notice?.textContent).toContain("Another scan is active");
  expect(notice?.textContent).toContain(expected);
  expect(notice?.textContent).not.toMatch(/still running|before checking the fix/iu);
  expect(container.textContent).toContain(
    "The new scan repeats the same approved scope. The comparison binds the earlier and new run IDs.",
  );
});

test("a follow-up scan that stopped early is disclosed even when the comparison calls itself complete", () => {
  // `complete` is the backend's own verdict on the comparison. The page does not
  // take it as the last word: it independently requires the after-fix run to
  // have finished. Trusting the flag alone would present a comparison built on
  // a run that stopped part-way as a full one, and every "no longer observed"
  // count on it would really mean "we did not finish looking".
  const { container } = renderVerification(
    summary({ complete: true, diffs: [diff({ id: "a", state: "resolved", beforeSeverity: "critical" })] }),
    [run("run-before", "completed"), run("run-after", "partial")],
  );

  const notice = container.querySelector(".inline-notice--warning");
  expect(notice).not.toBeNull();
  expect(notice!.textContent).toContain("Verification comparison incomplete");
  expect(notice!.textContent).toContain("are not counted as fixed");
  // The after-fix run's own state is shown rather than left to the notice alone.
  expect(container.querySelector(".comparison-run--current")!.textContent).toContain("Partly completed");
});

test("a comparison with both runs completed and no recorded limitation does not invent a warning", () => {
  // The mirror of the test above. Without this, an implementation that always
  // warned would pass the previous assertion while telling every user their
  // comparison was unreliable, which is its own dishonesty.
  const { container } = renderVerification(
    summary({ complete: true, diffs: [diff({ id: "a", state: "persistent", beforeSeverity: "high", afterSeverity: "high" })] }),
    bothRunsCompleted,
  );

  expect(container.querySelector(".inline-notice--warning")).toBeNull();
});

test("a Traditional Chinese reader sees a changed finding's structured explanation", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const englishFrame = "The finding remains observable, but severity changed from high to critical.";
  const { container } = renderVerification(
    summary({
      diffs: [diff({
        id: "localized-change",
        state: "persistent",
        comparisonStatus: "changed",
        beforeSeverity: "high",
        afterSeverity: "critical",
        explanation: englishFrame,
        changeReasons: [{
          code: "severity_changed",
          detail: "severity changed from high to critical",
        }],
      })],
    }),
    bothRunsCompleted,
  );

  const row = diffRow(container, "Finding localized-change");
  expect(row.textContent).toContain("仍可觀察到這個問題，但嚴重程度從 high 變更為 critical。");
  expect(row.textContent).not.toContain(englishFrame);
});

test("an item that was not seen again states the exact result and next action", () => {
  const { container } = renderVerification(
    summary({ diffs: [diff({ id: "a", state: "resolved", beforeSeverity: "critical" })] }),
    bothRunsCompleted,
  );

  const row = diffRow(container, "Finding a");
  // "No longer observed" is a statement about this scan. "Fixed" or "Resolved"
  // would be a claim about the system that no scan can support.
  expect(within(row).getByText("No longer observed")).toBeTruthy();
  expect(row.textContent).not.toMatch(/\bFixed\b|\bResolved\b|\bSafe\b/u);
  expect(row.textContent).toContain("no longer found this problem");
  expect(row.textContent).toContain("Review the new evidence, then close it");
  // The severity line resolves the absent "after" value explicitly rather than
  // leaving it blank, which would read as no severity at all.
  expect(row.textContent).toContain("After: Not observed this time");

  // The page-level summary repeats the result and action without a disclaimer.
  const caution = container.querySelector(".inline-notice--info");
  expect(caution).not.toBeNull();
  expect(caution!.textContent).toContain("No longer observed in this recheck");
  expect(caution!.textContent).toContain("Review the new evidence, then close it");
  expect(caution!.textContent).not.toContain("does not mean");
});

test("an item that could not be compared is not counted among those not seen again", () => {
  // These two outcomes are adjacent and one is good news. An unverifiable item
  // folded into the not-observed count converts "we could not tell" into "it is
  // gone", which is the exact substitution this page exists to prevent.
  const { container } = renderVerification(
    summary({
      diffs: [
        diff({ id: "a", state: "resolved", beforeSeverity: "critical" }),
        diff({ id: "b", state: "unverifiable", beforeSeverity: "critical" }),
        diff({ id: "c", state: "unverifiable", beforeSeverity: "high" }),
      ],
    }),
    bothRunsCompleted,
  );

  const cardValue = (label: string): string => {
    const card = Array.from(container.querySelectorAll<HTMLElement>(".metric-card")).find(
      (candidate) => candidate.querySelector(".metric-card__label")?.textContent === label,
    );
    if (!card) throw new Error(`no metric card labelled ${label}`);
    return card.querySelector(".metric-card__value")!.textContent ?? "";
  };
  expect(cardValue("No longer observed")).toBe("1");
  expect(cardValue("Verification incomplete")).toBe("2");

  const row = diffRow(container, "Finding b");
  expect(within(row).getByText("Verification incomplete")).toBeTruthy();
  expect(row.textContent).toContain("Comparison is unavailable for this item");
  expect(row.textContent).toContain("complete its next action");
});

test("a recorded comparison limitation names the affected comparisons directly", () => {
  // The number beside a warning is a count of scanner/target comparisons that
  // failed, not of problems found. Presented bare next to a red notice it reads
  // as "you have three issues", which inflates the apparent result of a scan.
  const { container } = renderVerification(
    summary({
      complete: false,
      completenessIssues: [
        { code: "engine_did_not_complete", engineId: "prowler", detail: "prowler did not complete" },
        { code: "scope_changed", assetId: "asset-1", detail: "scope changed between runs" },
      ],
      diffs: [diff({ id: "a", state: "unverifiable" })],
    }),
    bothRunsCompleted,
  );

  const notice = container.querySelector(".inline-notice--warning")!;
  expect(notice.textContent).toContain("Scanner/target comparisons needing attention: 2");
  expect(notice.textContent).not.toContain("not a security-finding count");
});

test("a mapping-version-only limitation says the checks ran rather than implying they did not", () => {
  // Every limitation here is a catalog version change, so the checks did
  // complete. Reusing the generic "comparisons were incomplete" wording would
  // describe work that ran as work that did not, and would push a reader toward
  // rescanning something that was never the problem. The count also switches to
  // engines and says so.
  const { container } = renderVerification(
    summary({
      complete: false,
      completenessIssues: [
        { code: "mapping_version_changed", engineId: "prowler", detail: "catalog 1.2 to 1.3" },
        { code: "mapping_version_changed", engineId: "prowler", detail: "catalog 1.2 to 1.3" },
        { code: "mapping_version_changed", engineId: "trivy", detail: "catalog 1.2 to 1.3" },
      ],
      diffs: [diff({
        id: "a",
        state: "unverifiable",
        changeReasons: [{ code: "mapping_version_changed", engineId: "prowler", detail: "catalog 1.2 to 1.3" }],
      })],
    }),
    bothRunsCompleted,
  );

  const notice = container.querySelector(".inline-notice--warning")!;
  expect(notice.textContent).toContain("Scanner mappings changed between these scans");
  expect(notice.textContent).toContain("completed in both scans");
  // Two distinct engines across three recorded rows.
  expect(notice.textContent).toContain("Affected scan tools: 2");
  expect(notice.textContent).not.toContain("not a security-finding count");
  expect(notice.textContent).not.toContain("comparisons were incomplete");

  const row = diffRow(container, "Finding a");
  expect(row.textContent).toContain("different control-mapping catalog versions");
  expect(row.textContent).toContain("Comparison classification is unavailable");
});

test("an outcome filter that matches nothing offers the next filter action", () => {
  const { container } = renderVerification(
    summary({ diffs: [diff({ id: "a", state: "persistent", beforeSeverity: "high", afterSeverity: "high" })] }),
    bothRunsCompleted,
  );

  const resolvedFilter = Array.from(container.querySelectorAll<HTMLButtonElement>(".segmented-filter button"))
    .find((button) => button.textContent?.startsWith("No longer observed"));
  expect(resolvedFilter).toBeTruthy();
  fireEvent.click(resolvedFilter!);

  const empty = container.querySelector(".empty-state")!;
  expect(empty.textContent).toContain("No items match this filter");
  expect(empty.textContent).toContain("Choose another outcome to see its items");
  expect(empty.textContent).not.toContain("does not mean");
  expect(container.querySelectorAll(".diff-row").length).toBe(0);
});

test("a comparison row whose finding is gone records that rather than offering missing evidence", () => {
  // The baseline finding can be absent from the current list. Rendering the
  // evidence button anyway hands the user a control that opens nothing; saying
  // where the history actually lives is the honest substitute.
  const { container } = renderVerification(
    summary({
      diffs: [
        diff({ id: "a", state: "resolved", findingId: "finding-gone", beforeSeverity: "critical" }),
        diff({ id: "b", state: "persistent", findingId: "finding-present", beforeSeverity: "high", afterSeverity: "high" }),
      ],
    }),
    bothRunsCompleted,
    [{ id: "finding-present" } as Finding],
  );

  const gone = diffRow(container, "Finding a");
  expect(gone.querySelector(".diff-row__action")).toBeNull();
  expect(gone.textContent).toContain("no longer in the current list");
  expect(gone.textContent).toContain("remains in the case package");

  const present = diffRow(container, "Finding b");
  expect(present.querySelector(".diff-row__action")).not.toBeNull();
  expect(present.textContent).not.toContain("no longer in the current list");
});

const reportFinding = (id: string, severity: Severity): BeginnerReportFinding => ({
  findingId: id,
  severity,
  targetAssetIds: ["asset-1"],
  priority: 10,
} as BeginnerReportFinding);

const passwordGroup = (findingIds: string[], representativeFindingId: string): BeginnerReportProblemGroup => ({
  groupId: "password",
  ruleVersion: "aws-related-checks-1",
  kind: "iam_password_policy",
  title: "IAM password policy needs attention",
  targetAssetId: "asset-1",
  representativeFindingId,
  findingIds,
});

const cardValue = (container: HTMLElement, label: string): string => {
  const card = Array.from(container.querySelectorAll<HTMLElement>(".metric-card")).find(
    (candidate) => candidate.querySelector(".metric-card__label")?.textContent === label,
  );
  if (!card) throw new Error(`no metric card labelled ${label}`);
  return card.querySelector(".metric-card__value")!.textContent ?? "";
};

test.each([
  ["en", {
    title: "IAM password policy needs attention",
    count: "2 original findings",
    compared: "Original findings compared",
    resolved: "No longer observed",
    fresh: "New",
    present: "Still present",
    unverifiable: "Verification incomplete",
    severity: "Critical",
    lowerSeverity: "Low",
    after: "Not observed this time",
    all: "All",
    total: "2 of 2",
    evidence: "Open finding evidence",
    lengthDetail: "Length comparison detail.",
    symbolDetail: "Symbol comparison detail.",
  }],
  ["zh-TW", {
    title: "IAM 密碼政策需要調整",
    count: "2 筆原始發現",
    compared: "比較的原始發現",
    resolved: "這次沒有再看到",
    fresh: "新出現",
    present: "仍然存在",
    unverifiable: "驗證未完成",
    severity: "重大",
    lowerSeverity: "低",
    after: "這次沒有再觀察到",
    all: "全部",
    total: "2／2",
    evidence: "查看問題證據",
    lengthDetail: "目前掃描已針對原始座標，完成版本、知識、對照映射、範圍與目標合約完全可比較的檢查，且未再次出現這個指紋。",
    symbolDetail: "目前掃描已針對原始座標，完成版本、知識、對照映射、範圍與目標合約完全可比較的檢查，且未再次出現這個指紋。",
  }],
] as const)("a grouped resolved problem is one card in %s", (locale, phrase) => {
  window.localStorage.setItem(localeStorageKey, locale);
  const onOpenFinding = vi.fn();
  const { container } = renderVerification(
    summary({
      diffs: [
        diff({
          id: "low",
          state: "resolved",
          comparisonStatus: "resolved",
          findingId: "policy-low",
          baselineFindingId: "policy-low",
          beforeSeverity: "low",
          title: "Symbol requirement",
          assetName: "other-account",
          explanation: "Symbol comparison detail.",
        }),
        diff({
          id: "high",
          state: "resolved",
          comparisonStatus: "resolved",
          findingId: "policy-critical",
          baselineFindingId: "policy-critical",
          beforeSeverity: "critical",
          title: "Minimum length",
          assetName: "production-account",
          explanation: "Length comparison detail.",
        }),
        diff({
          id: "fresh",
          state: "new",
          comparisonStatus: "newly_observed",
          findingId: "exposed-port",
          currentFindingId: "exposed-port",
          afterSeverity: "high",
          title: "Exposed admin port",
        }),
      ],
    }),
    bothRunsCompleted,
    [{ id: "policy-critical" } as Finding],
    {
      baselineReport: {
        findings: [
          reportFinding("policy-low", "low"),
          reportFinding("policy-critical", "critical"),
        ],
        problemGroups: [passwordGroup(["policy-low", "policy-critical"], "policy-low")],
      },
      onOpenFinding,
    },
  );

  expect(container.querySelectorAll(".diff-row")).toHaveLength(2);
  expect(cardValue(container, phrase.resolved)).toBe("1");
  expect(cardValue(container, phrase.fresh)).toBe("1");
  expect(cardValue(container, phrase.present)).toBe("0");
  expect(cardValue(container, phrase.unverifiable)).toBe("0");
  expect(container.querySelector(".count-label")?.textContent).toBe(phrase.total);
  const all = Array.from(container.querySelectorAll(".segmented-filter button"))
    .find((button) => button.textContent?.includes(phrase.all));
  expect(all?.textContent).toContain("2");

  const row = diffRow(container, phrase.title);
  expect(row.querySelector("h3")?.textContent).toBe(phrase.title);
  expect(row.textContent).toContain(phrase.count);
  expect(row.textContent).toContain("production-account");
  expect(row.textContent).not.toContain("other-account");
  expect(row.querySelector(".diff-severity-change")?.textContent).toContain(phrase.severity);
  expect(row.querySelector(".diff-severity-change")?.textContent).toContain(phrase.after);
  expect(row.querySelector(".diff-severity-change")?.textContent).not.toContain(phrase.lowerSeverity);
  const pills = Array.from(row.querySelectorAll(".status-pill")).map((pill) => pill.textContent ?? "");
  expect(pills.some((pill) => pill.includes(phrase.severity))).toBe(true);
  expect(pills.some((pill) => pill.includes(phrase.lowerSeverity))).toBe(false);

  const details = row.querySelector<HTMLDetailsElement>("details.page-technical-details");
  expect(details).not.toBeNull();
  expect(details!.open).toBe(false);
  expect(details!.querySelector("summary")?.textContent).toBe(phrase.compared);
  expect(details!.textContent).toContain("Minimum length");
  expect(details!.textContent).toContain("Symbol requirement");
  expect(details!.textContent).toContain(phrase.resolved);
  expect(details!.textContent).toContain(phrase.lengthDetail);
  expect(details!.textContent).toContain(phrase.symbolDetail);

  fireEvent.click(row.querySelector(".diff-row__action")!);
  expect(onOpenFinding).toHaveBeenCalledWith("policy-critical");

  const fresh = diffRow(container, "Exposed admin port");
  expect(fresh.textContent).not.toContain(phrase.count);
  expect(fresh.querySelector("details.page-technical-details summary")?.textContent).not.toBe(phrase.compared);
});

test.each([
  ["en", "only its line moved", "The same problem is still present"],
  ["zh-TW", "只是行號改變", "相同問題仍然存在"],
] as const)("a grouped problem uses the moved summary only when every observed member moved (%s)", (locale, moved, persistent) => {
  window.localStorage.setItem(localeStorageKey, locale);
  const baselineReport: VerificationProblemReport = {
    findings: [reportFinding("left", "high"), reportFinding("right", "medium")],
    problemGroups: [passwordGroup(["left", "right"], "left")],
  };
  const member = (id: string, movedLocation: boolean): VerificationDiff => diff({
    id,
    state: "persistent",
    comparisonStatus: "still_present",
    baselineFindingId: id,
    currentFindingId: id,
    beforeSeverity: "high",
    afterSeverity: "high",
    changeReasons: movedLocation
      ? [{ code: "location_moved", detail: "location moved within the same file" }]
      : [{ code: "severity_changed", detail: "severity changed from high to critical" }],
  });
  const renderPair = (rightMoved: boolean) => renderVerification(
    summary({ diffs: [member("left", true), member("right", rightMoved)] }),
    bothRunsCompleted,
    [],
    { baselineReport, currentReport: baselineReport },
  );

  const groupTitle = locale === "zh-TW" ? "IAM 密碼政策需要調整" : "IAM password policy needs attention";
  const movedCard = renderPair(true).container;
  const movedRow = diffRow(movedCard, groupTitle);
  expect(movedCard.querySelectorAll(".diff-row")).toHaveLength(1);
  expect(movedRow.textContent).toContain(moved);
  expect(movedRow.textContent).not.toContain(persistent);
  cleanup();

  const staying = renderPair(false).container;
  const stayingRow = diffRow(staying, groupTitle);
  expect(staying.querySelectorAll(".diff-row")).toHaveLength(1);
  expect(stayingRow.textContent).toContain(persistent);
  expect(stayingRow.textContent).not.toContain(moved);
});
