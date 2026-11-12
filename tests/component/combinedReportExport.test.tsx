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
