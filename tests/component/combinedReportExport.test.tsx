import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { CombinedReportExport } from "../../src/components/CombinedReportExport";
import { I18nProvider } from "../../src/i18n";
import { scannerService } from "../../src/services/scanner";
import type { EngineRun, ScanRun } from "../../src/types";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const run = (id: string, sequence: number, status: ScanRun["status"] = "completed"): ScanRun => ({
  id, caseId: "case-1", label: `Scan ${sequence}`, sequence, status, progress: 100,
  startedAt: "2026-10-22T10:00:00Z", finishedAt: "2026-10-22T10:01:00Z",
  knowledgeDate: "2026-10-22", engineRuns: [], coveredAssetCount: 0, totalAssetCount: 1,
});

test("combining requires explicit finished sources and preserves imported evidence as a selectable source", async () => {
  const importer = run("imported", 2, "partial");
  importer.engineRuns = [{ taskKind: { kind: "external_report_import", sourceFormat: "strix-vulnerabilities-json/v1",
    sourceSha256: "a".repeat(64) } }] as EngineRun[];
  const exportReport = vi.spyOn(scannerService, "exportSelectedRunReport").mockResolvedValue({ mode: "native", data: {
    case_id: "case-1", selected_run_ids: ["recorded", "imported"], format: "html", path: "/reports/combined.html",
    sha256: "b".repeat(64), created_at: "2026-10-22T10:02:00Z", redaction_profile: "standard",
  } });
  const { getByText, getByRole, queryByRole } = render(<I18nProvider><CombinedReportExport caseId="case-1"
    runs={[run("recorded", 1), importer, run("active", 3, "running")]} nativeMode /></I18nProvider>);
  fireEvent.click(getByText("Combine saved scan results"));
  expect(queryByRole("checkbox", { name: /Scan 3/u })).toBeNull();
  const button = getByRole("button", { name: "Save combined report" }) as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.click(getByRole("checkbox", { name: /Scan 1/u }));
  expect(button.disabled).toBe(true);
  fireEvent.click(getByRole("checkbox", { name: /Scan 2/u }));
  fireEvent.click(button);
  await waitFor(() => expect(exportReport).toHaveBeenCalledWith({ caseId: "case-1", runIds: ["recorded", "imported"],
    locale: "en", format: "html", redactSensitiveValues: true }));
  await waitFor(() => expect(getByRole("status").textContent).toContain("/reports/combined.html"));
});

test("browser preview cannot create a combined export", () => {
  const exportReport = vi.spyOn(scannerService, "exportSelectedRunReport");
  const { getByText, getAllByRole, getByRole } = render(<I18nProvider><CombinedReportExport caseId="case-1"
    runs={[run("first", 1), run("second", 2)]} nativeMode={false} /></I18nProvider>);
  fireEvent.click(getByText("Combine saved scan results"));
  expect(getAllByRole("checkbox").slice(0, 2).every((input) => (input as HTMLInputElement).disabled)).toBe(true);
  fireEvent.click(getByRole("button", { name: "Save combined report" }));
  expect(exportReport).not.toHaveBeenCalled();
});

test("original-file consent is explicit, HTML-only, and displays the private archive location", async () => {
  const exportReport = vi.spyOn(scannerService, "exportSelectedRunReport").mockResolvedValue({ mode: "native", data: {
    case_id: "case-1", selected_run_ids: ["first", "second"], format: "html", path: "/reports/combined.html",
    sha256: "b".repeat(64), created_at: "2026-11-10T10:02:00Z", redaction_profile: "standard",
    attachment_archive: { path: "/reports/private-originals.case.tar.gz", sha256: "c".repeat(64), byte_length: 2048 },
  } });
  const { getByText, getByRole, queryByRole } = render(<I18nProvider><CombinedReportExport caseId="case-1"
    runs={[run("first", 1), run("second", 2)]} nativeMode /></I18nProvider>);
  fireEvent.click(getByText("Combine saved scan results"));
  fireEvent.click(getByRole("checkbox", { name: /Scan 1/u }));
  fireEvent.click(getByRole("checkbox", { name: /Scan 2/u }));
  const choice = getByRole("checkbox", { name: /Include original files/u }) as HTMLInputElement;
  expect(choice.checked).toBe(false);
  fireEvent.click(choice);
  expect(getByText(/The fallback archive includes the full case/u)).toBeTruthy();
  fireEvent.click(getByRole("button", { name: "Save combined report" }));
  await waitFor(() => expect(exportReport).toHaveBeenCalledWith(expect.objectContaining({
    includeRawArtifacts: true, acknowledgeSensitiveRawArtifacts: true, acknowledgeSensitiveData: true,
  })));
  await waitFor(() => expect(getByRole("status").textContent).toContain("/reports/private-originals.case.tar.gz"));
  fireEvent.change(getByRole("combobox"), { target: { value: "json" } });
  expect(queryByRole("checkbox", { name: /Include original files/u })).toBeNull();
  fireEvent.click(getByRole("button", { name: "Save combined report" }));
  await waitFor(() => expect(exportReport).toHaveBeenLastCalledWith({
    caseId: "case-1", runIds: ["first", "second"], locale: "en", format: "json", redactSensitiveValues: true,
  }));
});

for (const locale of ["en", "zh-TW"]) test(`${locale}: admitted audit selection has its own label and can attach originals`, async () => {
  const { localeStorageKey } = await import("../../src/i18n");
  const { auditRun } = await import("../support/sourceAudit");
  localStorage.setItem(localeStorageKey, locale);
  const saved = run("saved", 2);
  const source = auditRun();
  const exportReport = vi.spyOn(scannerService, "exportSelectedRunReport").mockResolvedValue({ mode: "native", data: null });
  const { container, getByRole } = render(<I18nProvider><CombinedReportExport caseId="case-1" runs={[source, saved]} nativeMode /></I18nProvider>);
  fireEvent.click(container.querySelector('summary')!);
  const rows = container.querySelectorAll('.scope-mode-card');
  expect(rows[0]!.textContent).toContain(locale === "en" ? "Source audit" : "原始碼稽核");
  expect(rows[0]!.textContent).not.toMatch(/Imported evidence|Saved scan|匯入證據|已保存的掃描/u);
  // Select the saved scan first, request attachments, then select the audit.
  fireEvent.click(rows[1]!.querySelector('input')!);
  const originals = container.querySelectorAll('.toggle-row input')[1]!;
  fireEvent.click(originals);
  fireEvent.click(rows[0]!.querySelector('input')!);
  expect(container.textContent).toContain(locale === "en" ? "select fewer runs or export a case bundle" : "請減少選取的輪次或匯出案件包");
  expect(container.textContent).not.toContain("The fallback archive includes");
  expect(container.querySelectorAll('.toggle-row input')).toHaveLength(2);
  fireEvent.click(getByRole('button'));
  await waitFor(() => expect(exportReport).toHaveBeenCalled());
  expect(exportReport.mock.calls[0]![0]).toHaveProperty('includeRawArtifacts', true);
  localStorage.clear();
});
