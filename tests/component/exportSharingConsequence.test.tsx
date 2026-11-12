import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { ExportPage } from "../../src/pages/ExportPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { CaseWorkspace, ExportPreview, ScanRun } from "../../src/types";

// The export screen is where a user decides who else may hold this data, and it
// used to answer that question with one unconditional sentence: "Passwords and
// access keys are never included."
//
// That is true under standard redaction and false without it. `export.rs`
// computes `include = include_raw_artifacts && !(Standard && sensitive)`, so
// with redaction off every captured artifact is copied into the bundle
// verbatim, and gitleaks and trufflehog ship as engines whose raw output holds
// the discovered values. The backend even writes the contradicting sentence
// itself -- it was rendered one disclosure below the promise, where a reader
// deciding whether to send the file has no reason to look.
//
// The mirror is the other half of the same predicate: every artifact the
// desktop app captures is marked sensitive, so *with* redaction on the raw-file
// option must stay disabled rather than offering a setting that does nothing.
//
// These tests pin the sentence to the settings that produce it. They render the
// page rather than matching its source because the defect was never a missing
// string -- the string was there, and said the wrong thing.
//
// The same shape appears in the summary below the toggles, which described the
// selected format using one format's properties. Those claims are pinned here
// too: this file's subject is everything the screen asserts about the file it is
// about to write.

const CHOSEN = "run-2026-08-31";

const run = (id: string): ScanRun => ({
  id,
  caseId: "case-1",
  label: id,
  status: "completed",
  progress: 100,
  startedAt: "2026-08-31T12:00:00Z",
  finishedAt: "2026-08-31T12:01:00Z",
  knowledgeDate: "2026-08-31",
  engineRuns: [],
  coveredAssetCount: 3,
  totalAssetCount: 3,
});

const workspace: CaseWorkspace = {
  case: {
    id: "case-1",
    name: "Contoso baseline",
    aiGeneratedArtifact: "no",
    organizationName: "Contoso",
    companySize: "small",
    dataClasses: [],
    requestedActivities: [],
    platforms: [],
    createdAt: "2026-08-31T11:00:00Z",
    updatedAt: "2026-09-02T11:00:00Z",
    phase: "reporting",
    latestRunId: CHOSEN,
  },
  sources: [],
  coverage: [],
  assets: [],
  scopeGrants: [],
  runs: [run(CHOSEN)],
  findings: [],
  findingGroups: [],
  findingGroupEvents: [],
  workflowEvents: [],
  exports: [],
};

/**
 * A preview that answers whatever coordinate it was asked about.
 *
 * The page discards a preview whose coordinates disagree with the current
 * selection, so a fixed answer would turn every toggle in these tests into a
 * coordinate mismatch and hide the sentence under test behind an error notice.
 */
const renderExport = ({
  demoMode = false,
  workspaceValue = workspace,
}: {
  demoMode?: boolean;
  workspaceValue?: CaseWorkspace;
} = {}) => {
  const onPreview = vi.fn((request: {
    runId: string;
    locale: "en" | "zh-Hant";
    format: string;
    includeRawEvidence: boolean;
    redactSensitiveValues: boolean;
  }) => Promise.resolve({
    caseId: "case-1",
    runId: request.runId,
    locale: request.locale,
    format: request.format,
    redactionProfile: request.redactSensitiveValues ? "standard" : "none",
    includeRawEvidence: request.includeRawEvidence,
    dataSourceCount: 2,
    coverageEntryCount: 4,
    assetCount: 3,
    candidateAssetCount: 3,
    canonicalFindingCount: 7,
    selectedRunFindingCount: 7,
    evidenceIndexCount: 7,
    selectedRunEvidenceCount: 7,
    scanRunCount: 1,
    selectedEngineRunCount: 2,
    externalScopeGrantCount: 0,
    incompleteEngineRunCount: 0,
    notExecutedEngineRunCount: 0,
    unknownSourceCount: 0,
    connectedNoAssetCount: 0,
    rawArtifactCount: 4,
    rawArtifactsIncluded: request.includeRawEvidence && !request.redactSensitiveValues ? 4 : 0,
    rawArtifactsOmitted: request.includeRawEvidence && !request.redactSensitiveValues ? 0 : 4,
    sensitiveRawArtifactsOmitted: request.includeRawEvidence && !request.redactSensitiveValues ? 0 : 4,
    sensitiveDataWarning: "backend warning",
    coverageManifestIncluded: true,
  } as ExportPreview));

  const onExport = vi.fn(() => Promise.resolve());
  const { container } = render(
    <I18nProvider>
      <ExportPage
        workspace={workspaceValue}
        selectedRunId={CHOSEN}
        exports={[]}
        demoMode={demoMode}
        onPreview={onPreview}
        onExport={onExport}
        onVerify={() => Promise.resolve()}
        onVerifyReceived={() => Promise.resolve()}
      />
    </I18nProvider>,
  );
  return { container, onPreview, onExport };
};

/** The sentence describing what the current settings leave in the file. */
const consequence = (container: HTMLElement): string => {
  const paragraph = container.querySelector<HTMLElement>(".export-sharing-consequence");
  if (!paragraph) throw new Error("no sharing-consequence sentence rendered");
  return paragraph.textContent ?? "";
};

/** The complete disclosure, scope, and integrity decision beside Save. */
const decisionSummary = (container: HTMLElement): HTMLElement => {
  const summary = container.querySelector<HTMLElement>(".export-decision-summary");
  if (!summary) throw new Error("no export decision summary rendered");
  return summary;
};

/** A toggle located by the label text next to it, not by DOM position. */
const toggle = (container: HTMLElement, label: string): HTMLInputElement => {
  const row = Array.from(container.querySelectorAll<HTMLElement>("label.toggle-row")).find(
    (candidate) => candidate.querySelector("strong")?.textContent === label,
  );
  if (!row) throw new Error(`no toggle labelled "${label}"`);
  const input = row.querySelector<HTMLInputElement>("input[type=checkbox]");
  if (!input) throw new Error(`toggle "${label}" has no checkbox`);
  return input;
};

/** The `<small>` detail text beside a toggle located by its own label text. */
const toggleDetail = (container: HTMLElement, label: string): string => {
  const row = Array.from(container.querySelectorAll<HTMLElement>("label.toggle-row")).find(
    (candidate) => candidate.querySelector("strong")?.textContent === label,
  );
  if (!row) throw new Error(`no toggle labelled "${label}"`);
  return row.querySelector("small")?.textContent ?? "";
};

const chooseCaseBundle = (container: HTMLElement, title = "Technical case bundle") => {
  const card = Array.from(container.querySelectorAll<HTMLElement>("label.format-card")).find(
    (candidate) => candidate.textContent?.includes(title),
  );
  if (!card) throw new Error("no case-bundle format card rendered");
  const input = card.querySelector<HTMLInputElement>("input");
  if (!input) throw new Error("the case-bundle card has no input");
  fireEvent.click(input);
};

/** The mechanics kept in the collapsed package-details disclosure. */
const detailNotes = (container: HTMLElement): string => {
  return Array.from(container.querySelectorAll<HTMLElement>(".export-summary__note"))
    .map((note) => note.textContent ?? "")
    .join(" ");
};

/** The asset-relationship line of that summary, located by its own wording. */
const assetRelationsLine = (container: HTMLElement): HTMLElement => {
  const line = Array.from(container.querySelectorAll<HTMLElement>(".export-contents li")).find(
    (candidate) => candidate.textContent?.includes("Asset relationships"),
  );
  if (!line) throw new Error("no asset-relationship line rendered");
  return line;
};

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("the default export states that captured source files are left out", async () => {
  const { container } = renderExport();

  await waitFor(() => expect(consequence(container)).toContain("Sensitive identifiers hidden"));
  expect(consequence(container)).toContain("source files excluded");
  expect(container.querySelector(".export-privacy-status--neutral")).not.toBeNull();
  expect(container.querySelector(".export-privacy-status--warning")).toBeNull();
  expect(container.querySelector(".export-privacy-status--danger")).toBeNull();

  // The promise that was there before, in the form that made it false.
  expect(container.textContent).not.toContain("Passwords and access keys are never included");
});

test("a connection-only export says that no vulnerability scan ran", async () => {
  const connectionRun: ScanRun = {
    ...run(CHOSEN),
    engineRuns: [{
      id: "connection-test-1",
      engineId: "built-in-localhost-tcp",
      engineName: "Localhost TCP reachability",
      category: "built_in_localhost_tcp",
      taskKind: {
        kind: "built_in_localhost_tcp",
        port: 9001,
        timeoutMs: 3_000,
        payloadBytes: 0,
      },
      localhostTcpObservation: {
        outcome: "reachable",
        observedAt: "2026-08-31T12:00:03Z",
      },
      warnings: [],
      status: "completed",
      progress: 100,
      phase: "completed",
      startedAt: "2026-08-31T12:00:00Z",
      finishedAt: "2026-08-31T12:00:03Z",
      assetIds: ["asset-1"],
      rawArtifactCount: 0,
      savedResultArtifactCount: 0,
      findingCount: 0,
      resumable: false,
    }],
  };
  const { container } = renderExport({
    workspaceValue: { ...workspace, runs: [connectionRun] },
  });

  await waitFor(() => expect(container.textContent).toContain(
    "Connection test only — no vulnerability scan ran",
  ));
  expect(container.textContent).toContain(
    "The exported file records only whether one local port accepted a bounded TCP connection.",
  );
});

test("attaching source files without redaction says the secrets are in the file", async () => {
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Sensitive identifiers hidden"));

  chooseCaseBundle(container);
  fireEvent.click(toggle(container, "Hide sensitive identifiers (recommended)"));
  await waitFor(() => expect(toggle(container, "Include original scanner files").disabled).toBe(false));
  fireEvent.click(toggle(container, "Include original scanner files"));

  await waitFor(() => expect(consequence(container)).toContain("Includes unredacted scanner files that may contain secrets"));
  expect(consequence(container)).toContain("share only with trusted recipients");

  const notice = container.querySelector(".export-privacy-status--danger");
  expect(notice?.textContent).toContain("may contain secrets");
  expect(notice?.getAttribute("role")).toBe("alert");
});

test("turning redaction off without attaching sources claims neither more nor less", async () => {
  // The third state exists because the two toggles are independent: identifiers
  // become readable, but no scanner output is copied in. Collapsing this into
  // either neighbour would overstate one way or the other.
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Sensitive identifiers hidden"));

  fireEvent.click(toggle(container, "Hide sensitive identifiers (recommended)"));

  await waitFor(() => expect(consequence(container)).toContain("Identifiers remain readable"));
  expect(consequence(container)).toContain("source files are not attached");
  expect(container.querySelector(".export-privacy-status--warning")).not.toBeNull();
  expect(container.querySelector(".export-privacy-status--danger")).toBeNull();

  // Again on the one format that *can* carry artifacts, with the option left
  // off. Without this the format clause alone suppresses the secrets sentence
  // and the source-file clause is never exercised -- a mutation dropping it
  // survived until this case existed.
  chooseCaseBundle(container);
  await waitFor(() => expect(toggle(container, "Include original scanner files").disabled).toBe(false));
  expect(toggle(container, "Include original scanner files").checked).toBe(false);
  expect(consequence(container)).toContain("source files are not attached");
  expect(consequence(container)).not.toContain("may contain secrets");
});

test("the case-bundle source-file option cannot create a redacted no-op state", async () => {
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Sensitive identifiers hidden"));

  expect(Array.from(container.querySelectorAll("label.toggle-row")).some(
    (candidate) => candidate.querySelector("strong")?.textContent === "Include original scanner files",
  )).toBe(false);

  chooseCaseBundle(container);
  const row = Array.from(container.querySelectorAll<HTMLElement>("label.toggle-row")).find(
    (candidate) => candidate.querySelector("strong")?.textContent === "Include original scanner files",
  );
  const input = row?.querySelector<HTMLInputElement>('input[type="checkbox"]');
  const detail = row?.querySelector("small")?.textContent ?? "";
  expect(input?.disabled).toBe(true);
  expect(input?.checked).toBe(false);
  expect(detail).toContain("Turn off masking");

  fireEvent.click(toggle(container, "Hide sensitive identifiers (recommended)"));
  await waitFor(() => expect(toggle(container, "Include original scanner files").disabled).toBe(false));
});

test("the recommended format says plainly that it is not signed", async () => {
  // Only the case bundle is signed. Every other format takes the path that sets
  // `signature: None` and stores UNSIGNED_SCHEMA_NOTICE -- a notice the backend
  // writes and no screen has ever shown. HTML is the default and the
  // recommended one, so this is the sentence most readers get.
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Sensitive identifiers hidden"));

  const decision = decisionSummary(container);
  expect(decision.closest("details")).toBeNull();
  expect(decision.textContent).toContain("Sensitive identifiers hidden; source files excluded");
  expect(decision.textContent).toContain("Selected-run report");
  expect(decision.textContent).toContain("Integrity: SHA-256 recorded in this scan project");
  expect(decision.textContent).not.toContain("Integrity: locally signed");

  const packageDetails = container.querySelector<HTMLDetailsElement>(".export-summary--details");
  expect(packageDetails?.open).toBe(false);
  expect(detailNotes(container)).toContain("Integrity: SHA-256 digest recorded in this scan project");
});

test("the case bundle is the one format that describes a signature", async () => {
  // The mirror. Without it the sentence above could be hard-coded and the
  // page would understate the one format that does sign.
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Sensitive identifiers hidden"));

  chooseCaseBundle(container);
  await waitFor(() => expect(decisionSummary(container).textContent).toContain("Case-wide records; reports use the selected run"));

  const decision = decisionSummary(container);
  expect(decision.textContent).toContain("Integrity: locally signed");
  expect(decision.textContent).not.toContain("SHA-256 recorded");
  expect(container.querySelector(".export-bundle-scope")).toBeNull();
  expect(detailNotes(container)).toContain("case-wide assets, grants, coverage, scan history");
  expect(detailNotes(container)).toContain("Integrity: locally signed. Detects changes after export.");
  expect(detailNotes(container)).not.toContain("SHA-256 digest recorded");
});

test("the demo decision does not claim a verifiable digest", async () => {
  const { container } = renderExport({ demoMode: true });

  await waitFor(() => expect(decisionSummary(container).textContent).toContain("Selected-run demo sample"));
  const decision = decisionSummary(container);
  expect(decision.textContent).toContain("Demo sample: integrity record unavailable");
  expect(decision.textContent).not.toContain("SHA-256 recorded");
  expect(detailNotes(container)).toBe("");
  expect(container.textContent).toContain("This downloads a sample report");
  expect(container.textContent).toContain("Browser demo export: one selected-run JSON sample");
});

test("a format that cannot carry asset relationships says so instead of showing a check", async () => {
  // `case.asset_relations` is serialized only into the bundle's assets.json;
  // OCSF names asset relationships in its own omitted list. The line was
  // rendered with a check icon for all six formats.
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Sensitive identifiers hidden"));

  const line = assetRelationsLine(container);
  expect(line.className).toContain("export-contents__excluded");
  expect(line.textContent).toContain("not carried by this format");
});

test("the case bundle still lists asset relationships as included", async () => {
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Sensitive identifiers hidden"));

  chooseCaseBundle(container);
  await waitFor(() => expect(assetRelationsLine(container).className).not.toContain("export-contents__excluded"));
  expect(assetRelationsLine(container).textContent).toContain("Asset relationships for specialist review");
  expect(assetRelationsLine(container).textContent).not.toContain("not carried by this format");
});

test("the advanced-format note names the formats that need a saved scan", async () => {
  const onPreview = vi.fn(() => Promise.resolve(undefined));
  const { container } = render(
    <I18nProvider>
      <ExportPage
        workspace={{ ...workspace, runs: [] }}
        selectedRunId={undefined}
        exports={[]}
        demoMode={false}
        onPreview={onPreview}
        onExport={() => Promise.resolve()}
        onVerify={() => Promise.resolve()}
        onVerifyReceived={() => Promise.resolve()}
      />
    </I18nProvider>,
  );

  const note = container.querySelector<HTMLElement>(".page-secondary-feature__intro");
  expect(note?.textContent).toContain("OCSF and OSCAL require a saved scan for their coverage manifest");
  expect(note?.textContent).toContain("Available now: HTML, JSON, framework report, and case bundle");
  expect(note?.textContent).not.toContain("Every format remains available");

  // The claim and the controls have to agree: those two cards really are the
  // disabled ones in this state.
  // Compared by format id rather than card title: the titles are
  // plain-language ("Send findings to a security platform"), so matching them
  // would not show that the disabled pair is the pair the sentence names.
  const disabled = Array.from(container.querySelectorAll<HTMLInputElement>("input[name=export-format]"))
    .filter((input) => input.disabled)
    .map((input) => input.value)
    .sort();
  expect(disabled).toEqual(["ocsf", "oscal"]);
});

test("with a run selected the advanced formats are introduced, not explained away", async () => {
  // The mirror. Without it the no-run sentence could render in every state,
  // telling a user with a perfectly good run that two formats are unavailable
  // while both cards sit enabled beside it -- a mutation doing exactly that
  // survived until this test existed.
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Sensitive identifiers hidden"));

  const note = container.querySelector<HTMLElement>(".page-secondary-feature__intro");
  expect(note?.textContent).toContain("specialist or standards-based workflows");
  expect(note?.textContent).not.toContain("unavailable until a saved scan is selected");

  const disabled = Array.from(container.querySelectorAll<HTMLInputElement>("input[name=export-format]"))
    .filter((input) => input.disabled)
    .map((input) => input.value);
  expect(disabled).toEqual([]);
});

// The three sharing phrases carry no sentence period of their own, so the
// " · " join never follows one. These pin the join for every phrase in both
// languages, and what the masking checkbox discloses: standard redaction also
// replaces the project, organization, and target names.

test("the default decision summary has no dangling sentence period, and the masking detail names what it replaces", async () => {
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Sensitive identifiers hidden"));

  const summaryText = decisionSummary(container).textContent ?? "";
  expect(summaryText).not.toContain(". ·");
  expect(summaryText.endsWith(".")).toBe(false);

  const detail = toggleDetail(container, "Hide sensitive identifiers (recommended)");
  expect(detail).toContain("“Asset 1”");
  expect(detail).toContain("target names");
});

test("with masking off and no raw files attached the decision summary still joins without a dangling period", async () => {
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Sensitive identifiers hidden"));

  fireEvent.click(toggle(container, "Hide sensitive identifiers (recommended)"));
  await waitFor(() => expect(consequence(container)).toContain("Identifiers remain readable"));

  const summaryText = decisionSummary(container).textContent ?? "";
  expect(summaryText).toContain("Identifiers remain readable; source files are not attached · ");
  expect(summaryText).not.toContain(". ·");
});

test("a case bundle with masking off and original scanner files included joins without a dangling period", async () => {
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("Sensitive identifiers hidden"));

  chooseCaseBundle(container);
  fireEvent.click(toggle(container, "Hide sensitive identifiers (recommended)"));
  await waitFor(() => expect(toggle(container, "Include original scanner files").disabled).toBe(false));
  fireEvent.click(toggle(container, "Include original scanner files"));
  await waitFor(() => expect(consequence(container)).toContain("Includes unredacted scanner files that may contain secrets"));

  const summaryText = decisionSummary(container).textContent ?? "";
  expect(summaryText).toContain("share only with trusted recipients · ");
  expect(summaryText).not.toContain(". ·");
});

test("in Traditional Chinese the default decision summary has no dangling sentence period, and the masking detail names what it replaces", async () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderExport();
  await waitFor(() => expect(consequence(container)).toContain("已遮罩敏感識別資訊"));

  const summaryText = decisionSummary(container).textContent ?? "";
  expect(summaryText).toContain("已遮罩敏感識別資訊；不附來源檔案 · ");
  expect(summaryText).not.toContain("。 ·");

  const detail = toggleDetail(container, "遮罩敏感識別資訊（建議）");
  expect(detail).toContain("「Asset 1」");
  expect(detail).toContain("專案、組織與目標名稱");

  fireEvent.click(toggle(container, "遮罩敏感識別資訊（建議）"));
  await waitFor(() => expect(consequence(container)).toContain("識別資訊仍可讀"));
  expect(decisionSummary(container).textContent).toContain("識別資訊仍可讀；不附來源檔案 · ");
  expect(decisionSummary(container).textContent).not.toContain("。 ·");

  chooseCaseBundle(container, "技術案件包");
  await waitFor(() => expect(toggle(container, "附上掃描工具原始檔").disabled).toBe(false));
  fireEvent.click(toggle(container, "附上掃描工具原始檔"));
  await waitFor(() => expect(consequence(container)).toContain("將附上未遮罩的掃描工具原始檔"));
  expect(decisionSummary(container).textContent).toContain("僅交付可信對象 · ");
  expect(decisionSummary(container).textContent).not.toContain("。 ·");
});

for (const [locale, masking, attachment] of [
  ["en", "Hide sensitive identifiers (recommended)", "Attach original reports at the end"],
  ["zh-TW", "遮罩敏感識別資訊（建議）", "在報告最後附上原始報告"],
] as const) {
  test(`HTML attachments follow the selected run and export choices in ${locale}`, async () => {
    window.localStorage.setItem(localeStorageKey, locale);
    const { container, onPreview, onExport } = renderExport();
    const raw = toggle(container, attachment);
    expect(raw.disabled).toBe(true);
    expect(raw.checked).toBe(false);
    fireEvent.click(toggle(container, masking));
    expect(raw.disabled).toBe(false);
    fireEvent.click(raw);
    await waitFor(() => expect(onPreview).toHaveBeenLastCalledWith({
      runId: CHOSEN, locale: locale === "en" ? "en" : "zh-Hant", format: "html",
      includeRawEvidence: true, redactSensitiveValues: false,
    }));
    const save = container.querySelector<HTMLButtonElement>(".button--primary")!;
    await waitFor(() => expect(save.disabled).toBe(false));
    fireEvent.click(save);
    expect(onExport).toHaveBeenCalledWith({
      runId: CHOSEN, locale: locale === "en" ? "en" : "zh-Hant", format: "html",
      includeRawEvidence: true, redactSensitiveValues: false,
    });
    expect(container.querySelector(".export-privacy-status--danger")).not.toBeNull();
    expect(toggleDetail(container, attachment)).toContain("ZIP");
    expect(toggleDetail(container, attachment)).toContain("PDF");
    fireEvent.click(container.querySelector<HTMLInputElement>('input[value="json"]')!);
    await waitFor(() => expect(onPreview).toHaveBeenLastCalledWith(expect.objectContaining({
      format: "json", includeRawEvidence: false,
    })));
    fireEvent.click(container.querySelector<HTMLInputElement>('input[value="html"]')!);
    expect(toggle(container, attachment).checked).toBe(false);
    fireEvent.click(toggle(container, attachment));
    fireEvent.click(toggle(container, masking));
    expect(toggle(container, attachment).checked).toBe(false);
    expect(toggle(container, attachment).disabled).toBe(true);
  });
}
