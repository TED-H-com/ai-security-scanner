import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { ExternalScannerImport } from "../../src/components/ExternalScannerImport";
import { I18nProvider } from "../../src/i18n";
import { scannerService } from "../../src/services/scanner";
import type { Asset } from "../../src/types";

afterEach(cleanup);

test("import requires an explicit report target and asset, and binds the previewed bytes", async () => {
  vi.spyOn(scannerService, "chooseExternalScannerReport").mockResolvedValue("/reports/vulnerabilities.json");
  vi.spyOn(scannerService, "previewExternalScannerImport").mockResolvedValue({ engine_id: "strix",
    source_format: "strix-vulnerabilities-json/v1", source_sha256: "a".repeat(64),
    finding_count: 2, targets: ["https://one.example", "https://two.example"] });
  const importer = vi.spyOn(scannerService, "importExternalScannerReports").mockResolvedValue({
    mode: "native", data: { accepted: true, message: "Imported" },
  });
  const onImported = vi.fn().mockResolvedValue(undefined);
  const assets = [{ id: "asset-1", name: "Website one" }, { id: "asset-2", name: "Website two" }] as Asset[];
  const { getByRole, getByLabelText } = render(<I18nProvider><ExternalScannerImport
    caseId="case-1" assets={assets} nativeMode onImported={onImported} /></I18nProvider>);
  fireEvent.click(getByRole("group").querySelector("summary")!);
  fireEvent.click(getByRole("button", { name: "Choose Strix report" }));
  await waitFor(() => expect(getByRole("button", { name: "Import into one report" }).hasAttribute("disabled")).toBe(true));
  fireEvent.change(getByLabelText("Target in report"), { target: { value: "https://one.example" } });
  expect(getByRole("button", { name: "Import into one report" }).hasAttribute("disabled")).toBe(true);
  fireEvent.change(getByLabelText("Existing asset"), { target: { value: "asset-1" } });
  fireEvent.click(getByRole("button", { name: "Import into one report" }));
  await waitFor(() => expect(importer).toHaveBeenCalledWith("case-1", [{
    report_path: "/reports/vulnerabilities.json", source_sha256: "a".repeat(64),
    asset_id: "asset-1", upstream_target: "https://one.example",
  }]));
  expect(onImported).toHaveBeenCalledOnce();
});

test("preview mode cannot read or import reports", () => {
  const { container } = render(<I18nProvider><ExternalScannerImport caseId="case-1"
    assets={[{ id: "asset-1", name: "Website" }] as Asset[]} nativeMode={false} onImported={async () => {}} /></I18nProvider>);
  expect(container.querySelector("button")?.disabled).toBe(true);
});
