import { cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { FindingsPage } from "../../src/pages/FindingsPage";
import type { BeginnerMasterReport, BeginnerReportFinding, CorrelationReport } from "../../src/types";

const finding = (id: string, severity: BeginnerReportFinding["severity"]): BeginnerReportFinding => ({
  findingId:id, fingerprint:id, snapshotSource:"frozen_selected_run", title:`Original ${id}`,
  plainLanguageRisk:`Risk ${id}`, possibleImpact:`Impact ${id}`, severity, confidence:"high", priority:50,
  priorityReasons:[], targetAssetIds:["aws"], nextStep:`Review ${id}`, recommendedExpertType:"cloud",
  evidenceReferences:[{evidenceId:`evidence-${id}`, engineId: id === "low" ? "prowler" : "scoutsuite",
    detailsFrozen:true, sourceRule:`rule-${id}`, artifactSha256:`hash-${id}`, observedAt:"2026-10-02T12:00:00Z",
    location:`location-${id}`, summary:`Evidence ${id}`}],
  frameworkReferences:[], officialReferences:[],
});
const report = (): BeginnerMasterReport => ({
  schemaVersion:"1.1.0", caseId:"case",runId:"run",projectTitle:"AWS review",
  state:{summary:"complete",lifecycle:"final",lastDurableUpdate:"2026-10-02T12:00:00Z",explanation:"Completed"},
  requested:{targets:[{assetId:"aws",label:"AWS account",assetKind:"cloud_account",labelAvailability:"recorded",assetKindAvailability:"recorded"}],
    stage:{availability:"not_applicable",explanation:""},limits:[],requestedCheckIds:["prowler","scoutsuite"],automaticReductions:[],reductionsAvailability:"recorded",unavailableDimensions:[]},
  actual:{checks:[{taskId:"prowler",checkId:"prowler",resultKind:"security_check",targetAssetIds:["aws"],status:"tested_complete",testedDimensions:[]}],networkScopes:[],unavailableDimensions:[]},
  coverageGaps:[],coverageCounts:{testedComplete:1,testedPartial:0,failed:0,timedOut:0,cancelled:0,notTested:0,excluded:0,truncated:0,unavailable:0,unattributed:0,manualReview:0},
  findings:[finding("low","low"),finding("high","high"),finding("separate","medium")],
  problemGroups:[{groupId:"password",ruleVersion:"aws-related-checks-1",kind:"iam_password_policy",title:"IAM password policy needs attention",
    targetAssetId:"aws",representativeFindingId:"high",findingIds:["low","high"]}],
  nextSteps:[],technicalDetails:{collapsedByDefault:true,tasks:[]},frameworkNotice:{nonCertification:"",aidefendMappingStatus:""},dataQualityWarnings:[],
});
const update = vi.fn(async () => true);
const page = (value: BeginnerMasterReport, correlationReport?: CorrelationReport) => render(<I18nProvider><FindingsPage report={value} findings={[]} findingGroups={[]}
  findingGroupEvents={[]} correlationReport={correlationReport} runs={[]} workflowEvents={[]} busy={false} onUpdateWorkflow={update}
  onGroupFindings={async()=>true} onUngroupFindings={async()=>{}} onOpenCoverage={()=>{}} onOpenProgress={()=>{}} onOpenExport={()=>{}}/></I18nProvider>);
beforeEach(()=>window.localStorage.setItem(localeStorageKey,"en"));
afterEach(()=>{cleanup();window.localStorage.clear();vi.clearAllMocks();});

test("a grouped row and asset count preserve accessible source findings and distinct ratings", () => {
  const {container} = page(report());
  expect(container.querySelectorAll(".finding-row")).toHaveLength(2);
  expect(container.querySelector(".asset-result-row__outcome strong")?.textContent).toContain("2");
  expect(container.querySelector(".count-label")?.textContent).toContain("3 original findings");
  const row = container.querySelector<HTMLButtonElement>(".finding-row")!;
  expect(row.textContent).toContain("Evidence records: 2");
  expect(row.textContent).toContain("prowler");
  expect(row.textContent).toContain("scoutsuite");
  expect(row.textContent).not.toContain("High confidence");
  fireEvent.click(container.querySelector<HTMLButtonElement>(".finding-row")!);
  const detail = container.querySelector<HTMLElement>(".finding-detail")!;
  const related = detail.querySelector("details")!;
  expect(related.textContent).toContain("Original low");
  expect(related.textContent).toContain("Original high");
  expect(related.textContent).toContain("Low");
  expect(related.textContent).toContain("High");
  expect(detail.querySelector("h2")?.textContent).toBe("Original high");
  fireEvent.click(within(related).getByRole("button",{name:"Original low"}));
  expect(detail.querySelector("h2")?.textContent).toBe("Original low");
  expect(detail.textContent).toContain("location-low");
  expect(detail.textContent).toContain("rule-low");
});
test("search matches the group and originals; severity filtering preserves the matching observation", () => {
  const {container} = page(report());
  const search = container.querySelector<HTMLInputElement>('input[type="search"]')!;
  fireEvent.change(search,{target:{value:"needs attention"}});
  expect(container.querySelectorAll(".finding-row")).toHaveLength(1);
  expect(container.querySelector(".finding-row")?.textContent).toContain("IAM password policy needs attention");
  fireEvent.change(search,{target:{value:"Original low"}});
  expect(container.querySelectorAll(".finding-row")).toHaveLength(1);
  expect(container.querySelector(".finding-row")?.textContent).toContain("Original low");
  fireEvent.change(search,{target:{value:""}});
  fireEvent.change(within(container).getByRole("combobox",{name:"Severity"}),{target:{value:"low"}});
  expect(container.querySelectorAll(".finding-row")).toHaveLength(1);
  expect(container.querySelector(".finding-row")?.textContent).toContain("Original low");
  fireEvent.click(container.querySelector<HTMLButtonElement>(".finding-row")!);
  expect(container.querySelector(".finding-detail h2")?.textContent).toBe("Original low");
});
test("older reports retain separate rows", () => {
  const value = report();
  delete value.problemGroups;
  const {container} = page(value);
  expect(container.querySelectorAll(".finding-row")).toHaveLength(3);
});

test("a workflow decision updates only the selected original, never the group ID", async () => {
  const {container} = page(report());
  fireEvent.click(container.querySelector<HTMLButtonElement>(".finding-row")!);
  const detail = container.querySelector<HTMLElement>(".finding-detail")!;
  fireEvent.click(within(detail.querySelector("details")!).getByRole("button",{name:"Original low"}));
  const form = detail.querySelector("form")!;
  fireEvent.change(form.querySelector("select")!,{target:{value:"confirmed"}});
  fireEvent.change(form.querySelector("input")!,{target:{value:"Reviewer"}});
  fireEvent.change(form.querySelector("textarea")!,{target:{value:"Reviewed this source observation"}});
  fireEvent.submit(form);
  await waitFor(()=>expect(update).toHaveBeenCalledWith(expect.objectContaining({findingId:"low",status:"confirmed"})));
  expect(update).toHaveBeenCalledTimes(1);
});

const secretRemedy = {
  en: "Revoke and rotate the exposed credential, then remove it from the source and every retained history entry.",
  "zh-TW": "先撤銷並輪替這組已外洩的憑證，再從原始碼以及仍保留它的歷史紀錄中移除。",
} as const;
const codeChange = "Change the code to remove the reported unsafe pattern.";

test("an exposed secret card shows one revoke step, and a grouped correlation suggestion stays off the page", () => {
  for (const locale of ["en", "zh-TW"] as const) {
    window.localStorage.setItem(localeStorageKey, locale);
    const value = report();
    value.findings = ["s1", "s2", "s3", "s4", "s5"].map((id, index) => {
      const base = finding(id, index < 2 ? "high" : "unknown");
      return {
        ...base,
        title: `Original ${id}`,
        family: "source_code" as const,
        nextStep: codeChange,
        // A completed check keeps the step on the family's revoke sentence.
        evidenceReferences: base.evidenceReferences.map((reference) => ({
          ...reference,
          engineRunId: "prowler",
        })),
      };
    });
    value.findings.push(finding("dep-a", "medium"), finding("dep-b", "medium"), finding("dep-c", "low"), finding("loose", "low"));
    value.problemGroups = [
      {
        groupId: "secret",
        ruleVersion: "secret-location-1",
        kind: "exposed_secret",
        title: "Secret found in a file",
        targetAssetId: "aws",
        representativeFindingId: "s1",
        findingIds: ["s1", "s2", "s3", "s4", "s5"],
      },
      {
        groupId: "package",
        ruleVersion: "dependency-advisory-1",
        kind: "vulnerable_dependency",
        title: "Vulnerable package pyyaml 5.3.1 (CVE-2020-14343 / GHSA-8q59-q68h-6hv4)",
        targetAssetId: "aws",
        representativeFindingId: "dep-a",
        findingIds: ["dep-a", "dep-b"],
        packageName: "pyyaml",
        installedVersion: "5.3.1",
        advisoryIds: ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"],
      },
    ];
    value.nextSteps = [{
      priority: 0,
      code: "review_finding",
      action: codeChange,
      reason: "Original s1 — High severity, High confidence",
      findingId: "s1",
      alsoResolves: ["s2", "s3", "s4", "s5"],
      family: "secret",
      recommendedExpertType: "Secrets-response specialist",
    }];
    const correlation: CorrelationReport = {
      keyVersion: "1",
      truncatedSuggestions: 0,
      unverifiable: [],
      suggestions: [
        {
          id: "grouped",
          caseId: "case",
          comparisonKey: "grouped",
          keyVersion: "1",
          vulnerabilityId: "CVE-2020-14343",
          package: "pyyaml",
          title: "Grouped suggestion",
          basis: "same package",
          uncertainty: "not independent",
          corroboration: "not-established",
          findingIds: ["dep-a", "dep-b"],
          engineIds: ["grype", "trivy"],
        },
        {
          id: "separate",
          caseId: "case",
          comparisonKey: "separate",
          keyVersion: "1",
          vulnerabilityId: "CVE-2024-9999",
          package: "flask",
          title: "Separate suggestion",
          basis: "same package",
          uncertainty: "not independent",
          corroboration: "not-established",
          findingIds: ["dep-c", "loose"],
          engineIds: ["grype", "trivy"],
        },
      ],
    };
    const {container} = page(value, correlation);
    const secretRow = [...container.querySelectorAll(".finding-row")].find((row) =>
      row.textContent?.includes(locale === "en" ? "Secret found in a file" : "檔案中發現機密"));
    expect(secretRow?.textContent).toContain(locale === "en" ? "5 original findings" : "5 筆原始發現");
    fireEvent.click(secretRow as HTMLButtonElement);
    const detail = container.querySelector(".finding-detail")!;
    expect(detail.textContent).toContain(locale === "en" ? "Related checks (5)" : "相關檢查（5 筆）");
    expect(detail.textContent).toContain(secretRemedy[locale]);
    const nextHeading = [...container.querySelectorAll("h3")].find((heading) =>
      heading.textContent === (locale === "en" ? "What to do next" : "接下來怎麼做"));
    const nextList = nextHeading?.parentElement?.nextElementSibling;
    expect(nextList?.textContent).toContain(secretRemedy[locale]);
    expect(nextList?.textContent).not.toContain(codeChange);
    const correlations = container.querySelector("section[aria-labelledby='finding-correlations-title']");
    const visible = locale === "en"
      ? { grouped: "CVE-2020-14343 in pyyaml", separate: "CVE-2024-9999 in flask" }
      : { grouped: "CVE-2020-14343（套件：pyyaml）", separate: "CVE-2024-9999（套件：flask）" };
    expect(correlations?.textContent).not.toContain(visible.grouped);
    expect(correlations?.textContent).toContain(visible.separate);
    cleanup();
  }
});
