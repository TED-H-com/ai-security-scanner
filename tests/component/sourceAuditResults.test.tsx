import { cleanup, fireEvent, render, within } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { FindingsPage } from "../../src/pages/FindingsPage";
import { SourceAuditResults } from "../../src/components/SourceAuditResults";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { latestProblemCount } from "../../src/latestProblemCount";
import { auditFinding, auditReport, auditRun, sourceAudit } from "../support/sourceAudit";
import type { BeginnerMasterReport } from "../../src/types";

afterEach(() => { cleanup(); localStorage.clear(); vi.restoreAllMocks(); });
const show = (report: BeginnerMasterReport) => render(<I18nProvider><FindingsPage
  report={report} selectedRunId={report.runId} findings={[]} findingGroups={[]} findingGroupEvents={[]} runs={[auditRun()]}
  focusedFindingId={report.findings[0]?.findingId} workflowEvents={[]} busy={false}
  onUpdateWorkflow={async () => true} onGroupFindings={async () => true} onUngroupFindings={async () => {}}
  onOpenCoverage={vi.fn()} onOpenProgress={vi.fn()} onOpenExport={vi.fn()}
/></I18nProvider>);

const countCases = [
  {
    units: 3, candidates: 2,
    en: ["Source audit incomplete: 3 units remain. Continue with the listed paths.", "2 candidate findings remain unresolved."],
    "zh-TW": ["原始碼稽核未完成：尚有 3 個單元未完成。請從列出的路徑繼續。", "尚有 2 個候選問題未解決。"],
    ja: ["ソースコード監査は未完了です。対象ユニットが 3 件残っています。記載されたパスから続行してください。", "検出結果の候補が 2 件未解決です。"],
  },
  {
    units: 0, candidates: 2,
    en: ["Source audit incomplete: 2 candidate findings remain unresolved.", "2 candidate findings remain unresolved."],
    "zh-TW": ["原始碼稽核未完成：尚有 2 個候選問題未解決。", "尚有 2 個候選問題未解決。"],
    ja: ["ソースコード監査は未完了です。検出結果の候補が 2 件未解決です。", "検出結果の候補が 2 件未解決です。"],
  },
  {
    units: 1, candidates: 1,
    en: ["Source audit incomplete: 1 unit remains. Continue with the listed paths.", "1 candidate finding remains unresolved."],
    "zh-TW": ["原始碼稽核未完成：尚有 1 個單元未完成。請從列出的路徑繼續。", "尚有 1 個候選問題未解決。"],
    ja: ["ソースコード監査は未完了です。対象ユニットが 1 件残っています。記載されたパスから続行してください。", "検出結果の候補が 1 件未解決です。"],
  },
  {
    units: 0, candidates: 1,
    en: ["Source audit incomplete: 1 candidate finding remains unresolved.", "1 candidate finding remains unresolved."],
    "zh-TW": ["原始碼稽核未完成：尚有 1 個候選問題未解決。", "尚有 1 個候選問題未解決。"],
    ja: ["ソースコード監査は未完了です。検出結果の候補が 1 件未解決です。", "検出結果の候補が 1 件未解決です。"],
  },
] as const;

for (const locale of ["en", "zh-TW", "ja"] as const) {
  for (const example of countCases) test(`${locale}: audit results localize ${example.units} remaining units and ${example.candidates} unresolved candidates`, () => {
    localStorage.setItem(localeStorageKey, locale);
    const audit = sourceAudit();
    const [remaining, excluded] = audit.coverage_gaps;
    audit.coverage_gaps = [
      ...Array.from({ length: example.units }, (_, i) => ({ ...remaining!, coverage_id: `unit-${i}` })),
      excluded!,
    ];
    audit.unresolved_candidates = Array.from({ length: example.candidates }, (_, i) => `candidate-${i}`);
    audit.outcome.incomplete_reason = null;
    audit.to_validate = [];
    const { container } = render(<I18nProvider><SourceAuditResults audits={[audit]} /></I18nProvider>);
    const paragraphs = [...container.querySelectorAll(".source-audit > p")].map((node) => node.textContent);
    for (const expected of example[locale]) expect(paragraphs).toContain(expected);
    if (locale === "ja") expect(paragraphs.join(" ")).not.toMatch(/Source audit incomplete|candidate findings? remain/u);
  });
}

const coverageCountCases = [
  { reason: "1 unit remains.", en: "1 unit remains.", "zh-TW": "尚有 1 個單元未完成。", ja: "対象ユニットが 1 件残っています。" },
  { reason: "3 units remain.", en: "3 units remain.", "zh-TW": "尚有 3 個單元未完成。", ja: "対象ユニットが 3 件残っています。" },
  { reason: "1 unit is outside the audit scope.", en: "1 unit is outside the audit scope.", "zh-TW": "有 1 個單元不在稽核範圍內。", ja: "対象ユニットが 1 件、監査の対象外です。" },
  { reason: "2 units are outside the audit scope.", en: "2 units are outside the audit scope.", "zh-TW": "有 2 個單元不在稽核範圍內。", ja: "対象ユニットが 2 件、監査の対象外です。" },
] as const;

for (const locale of ["en", "zh-TW", "ja"] as const) {
  for (const example of coverageCountCases) test(`${locale}: source audit coverage displays ${example.reason}`, () => {
    localStorage.setItem(localeStorageKey, locale);
    const report = auditReport();
    report.coverageGaps[0]!.reason = example.reason;
    if (example.reason.includes("outside the audit scope")) {
      report.coverageGaps[0]!.kind = "excluded";
    }
    const { container } = show(report);
    const reportText = [...container.querySelectorAll(".coverage-card, .report-outcome-strip")]
      .map((node) => node.textContent).join(" ");
    expect(reportText).toContain(example[locale]);
    if (locale === "ja") expect(reportText).not.toContain(example.reason);
  });
}

for (const locale of ["en", "zh-TW"]) {
  test(`${locale}: results show candidates separately, readable gaps, and collapsed native technical details`, () => {
    localStorage.setItem(localeStorageKey, locale);
    const report = auditReport();
    const { container } = show(report);
    const audit = container.querySelector('.source-audit')!;
    expect(audit.textContent).toContain(locale === "en" ? "Source audit incomplete: 1 unit remains. Continue with the listed paths." : "原始碼稽核未完成：尚有 1 個單元未完成。請從列出的路徑繼續。");
    expect(audit.textContent).toContain(locale === "en" ? "1 candidate finding remains unresolved." : "尚有 1 個候選問題未解決。");
    expect(audit.textContent).toContain(locale === "en" ? "No confirmed findings in the recorded checks." : "已記錄的檢查中未發現已確認問題。");
    const candidate = audit.querySelector('.source-audit-candidate')!;
    for (const value of ["Candidate title", "Candidate description", "Candidate claim", "src/example.ts:12 — Candidate evidence", "Needs a deployment", "Inspect locally", "Inspect deployment"]) expect(candidate.textContent).toContain(value);
    expect(candidate.querySelector('.status-pill')).toBeNull();
    expect(candidate.querySelector('[class*=severity]')).toBeNull();
    expect(audit.textContent).toContain(locale === "en" ? "Local check" : "本機檢查");
    expect(audit.textContent).toContain(locale === "en" ? "Deployment check" : "部署環境檢查");
    const remaining = within(audit as HTMLElement).getByText(/Injection — request handler/).closest('li')!;
    expect(remaining.textContent).toContain(locale === "en" ? "Blocked" : "受阻");
    expect(remaining.textContent).toContain("src/example.ts");
    expect(remaining.textContent).not.toContain("coverage-one");
    const excluded = within(audit as HTMLElement).getByText(/Authentication — deployment/).closest('li')!;
    expect(excluded.textContent).toContain(locale === "en" ? "Outside the audit scope" : "不在稽核範圍內");
    expect(excluded.textContent).not.toContain(locale === "en" ? "Continue with these paths" : "請從這些路徑繼續");
    const details = audit.querySelector('details')!;
    expect(details.open).toBe(false);
    for (const value of ["synthetic-upstream", "counts_by_role", "counts_by_state", "workflow_recorded", "validators_reexecuted", "projection-digest", "admission-digest", "coverage-one"]) expect(details.textContent).toContain(value);
    expect(latestProblemCount({ runs: [auditRun()], beginnerReports: [report], findings: [], isDemo: false }).count).toBe(0);
    expect(container.textContent).not.toMatch(/not executed|invalid task|retry|Check fixes|尚未執行|重試/iu);
  });

  for (const [units, candidates] of [[0, 0], [0, 1], [0, 2], [1, 0], [2, 0]] as const) {
    test(`${locale}: incomplete framing with ${units} units and ${candidates} candidates`, () => {
      localStorage.setItem(localeStorageKey, locale);
      const audit = sourceAudit();
      audit.coverage_gaps = Array.from({ length: units }, (_, i) => ({ ...audit.coverage_gaps[0]!, coverage_id: `unit-${i}` }));
      audit.unresolved_candidates = Array.from({ length: candidates }, (_, i) => `candidate-${i}`);
      audit.to_validate = [];
      const { container } = render(<I18nProvider><SourceAuditResults audits={[audit]} /></I18nProvider>);
      const expected = units ? locale === "en"
        ? `Source audit incomplete: ${units} ${units === 1 ? "unit remains" : "units remain"}. Continue with the listed paths.`
        : `原始碼稽核未完成：尚有 ${units} 個單元未完成。請從列出的路徑繼續。`
        : candidates ? locale === "en"
          ? `Source audit incomplete: ${candidates} ${candidates === 1 ? "candidate finding remains" : "candidate findings remain"} unresolved.`
          : `原始碼稽核未完成：尚有 ${candidates} 個候選問題未解決。`
          : locale === "en" ? "Source audit incomplete." : "原始碼稽核未完成。";
      expect(container.textContent).toContain(expected);
      if (!units) expect(container.textContent).not.toContain(locale === "en" ? "What was not tested" : "未測試項目");
    });
  }

  test(`${locale}: confirmed findings keep native impact and remediation in priority and detail`, () => {
    localStorage.setItem(localeStorageKey, locale);
    const report = auditReport();
    report.findings = [auditFinding()];
    report.nextSteps = [{ priority: 1, code: "review_finding", findingId: "confirmed-one", family: "source_code", action: report.findings[0]!.nextStep, reason: "Confirmed native title" }];
    const { container } = show(report);
    const priority = container.querySelector('.priority-card')!;
    expect(priority.textContent).toContain("Native impact\nsecond line");
    expect(priority.textContent).toContain("Native remediation\nsecond line");
    fireEvent.click(priority);
    const detail = container.querySelector('.finding-detail')!;
    expect(detail.textContent).toContain("Native impact\nsecond line");
    expect(detail.textContent).toContain("Native remediation\nsecond line");
    expect(detail.textContent).toContain("agent_audit");
    expect(detail.textContent).toContain("admission-one");
    expect(latestProblemCount({ runs: [auditRun()], beginnerReports: [report], findings: [], isDemo: false }).count).toBe(1);
  });
}

const hostile = '</script><script>alert(1)</script>\n<img src=x onerror=alert(1)><svg onload=alert(2)>\n[link](https://evil.example) ![image](data:image/svg+xml,x) javascript:alert(1) data:text/html,x file:///private\n\u202E\u0001\nconst x = `<tag>`;\nreturn x;';
for (const locale of ["en", "zh-TW"]) test(`${locale}: provider strings remain literal text in audit, confirmed finding, and technical details`, () => {
  localStorage.setItem(localeStorageKey, locale);
  const report = auditReport();
  const audit = report.sourceAudits![0]!;
  audit.to_validate[0]!.native_record = { title: hostile, description: hostile, claimed_root_cause: hostile, blockers: [hostile], evidence: [{ file: hostile, line: 1, description: hostile }], validation_plan: { local: hostile, deployment: hostile } };
  audit.coverage_gaps[0]!.label = hostile;
  audit.coverage_gaps[0]!.continuation_paths = [hostile];
  audit.technical_detail.lineage = { [hostile]: hostile };
  audit.method.provider = hostile;
  audit.outcome.incomplete_reason = hostile;
  const finding = auditFinding();
  finding.title = hostile; finding.possibleImpact = hostile; finding.nextStep = hostile; finding.officialReferences = [hostile];
  finding.evidenceReferences[0]!.scannerDetails = { description: hostile, remediation: hostile };
  report.findings = [finding];
  const { container } = show(report);
  expect(container.textContent).toContain(hostile);
  for (const node of container.querySelectorAll('.provider-text')) {
    if (node.textContent === hostile) expect(node.querySelector('a,img,svg,script')).toBeNull();
  }
  expect(container.querySelector('script,img,[onerror],[onload]')).toBeNull();
  for (const node of container.querySelectorAll('[href],[src]')) {
    expect(node.getAttribute('href') ?? node.getAttribute('src')).not.toMatch(/evil|javascript:|data:|file:|private/u);
  }
});

for (const [status, en, zh] of [
  ['planned', 'Not started', '尚未開始'], ['in_progress', 'In progress', '進行中'],
  ['blocked', 'Blocked', '受阻'], ['deferred', 'Deferred', '已延後'],
  ['candidate', 'Unresolved candidate', '候選問題未解決'], ['out_of_scope', 'Outside the audit scope', '不在稽核範圍內'],
] as const) test(`unit status ${status} follows the shared report in both locales`, () => {
  for (const [locale, expected] of [['en', en], ['zh-TW', zh]]) {
    localStorage.setItem(localeStorageKey, locale!);
    const audit = sourceAudit();
    audit.coverage_gaps = [{ ...audit.coverage_gaps[0]!, status }];
    const { container, unmount } = render(<I18nProvider><SourceAuditResults audits={[audit]} /></I18nProvider>);
    const gap = within(container).getByText(/Injection — request handler/).closest('li')!;
    expect(gap.textContent).toContain(expected);
    expect(gap.textContent!.includes('src/example.ts')).toBe(status !== 'out_of_scope');
    unmount();
  }
});

for (const locale of ['en', 'zh-TW']) test(`${locale}: audit progress has no start, restart, pause, cancel, retry, or recovery action`, async () => {
  const { ProgressPage } = await import('../../src/pages/ProgressPage');
  localStorage.setItem(localeStorageKey, locale);
  const execute = vi.fn(async () => {});
  const { container } = render(<I18nProvider><ProgressPage assets={[]} findings={[]} runs={[auditRun()]} report={auditReport()} selectedRunId="audit-run"
    onStart={execute} onRetryLocalhostQuickScan={execute} onFixSetup={vi.fn()} onPause={execute} onResume={execute} onCancel={execute}
  /></I18nProvider>);
  const controls = [...container.querySelectorAll('button')].map((button) => button.textContent).join(' ');
  expect(controls).not.toMatch(/start|restart|pause|cancel|retry|recover|resume|開始|重新|暫停|取消|重試|繼續/iu);
  expect(execute).not.toHaveBeenCalled();
});
