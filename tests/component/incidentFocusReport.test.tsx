import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";
import { IncidentFocusReport } from "../../src/components/IncidentFocusReport";
import { I18nProvider, localeStorageKey } from "../../src/i18n";

afterEach(() => { cleanup(); window.localStorage.removeItem(localeStorageKey); });

test("incident coverage keeps untested advisories visible without a clean verdict", () => {
  const { container, getByText } = render(<I18nProvider><IncidentFocusReport targets={[{ assetId: "asset-1", label: "Portal" }]}
    report={{ campaign_id: "october-2026", title: "October triage", reviewed_at: "2026-10-22", issues: [
      { issue_id: "php2shell", title: "PHP2Shell", asset_id: "asset-1", status: "not_tested", finding_ids: [],
        reason_code: "knowledge_not_current", reason: "Scanner knowledge predates this incident.",
        next_action: "Check the deployed PHP runtime.", sources: ["https://www.php.net/"] },
      { issue_id: "zdi-can-32005", title: "ZDI-CAN-32005 (ConnMan)", asset_id: null, status: "advisory_pending", finding_ids: [],
        reason_code: "advisory_pending", reason: "Details pending.", next_action: "Follow the vendor advisory.", sources: [] },
    ] }} /></I18nProvider>);
  expect(container.textContent).toContain("0 asset/advisory matches");
  fireEvent.click(getByText("Incident coverage and next actions"));
  expect(getByText("Not tested")).toBeTruthy();
  expect(getByText("Advisory pending")).toBeTruthy();
  expect(getByText("Portal")).toBeTruthy();
  expect(container.textContent).not.toMatch(/no problems|passed|secure/iu);
});

test("Chinese incident details show localized next actions while retaining the saved evidence", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = render(<I18nProvider><IncidentFocusReport targets={[]}
    report={{ campaign_id: "october-2026", title: "October triage", reviewed_at: "2026-10-22", issues: [
      { issue_id: "php2shell", title: "PHP2Shell", asset_id: null, status: "not_tested", finding_ids: [],
        reason_code: "knowledge_not_current", reason: "Saved English reason", next_action: "Saved English action", sources: [] },
    ] }} /></I18nProvider>);
  expect(container.textContent).toContain("未測試");
  expect(container.textContent).not.toContain("Saved English");
  expect(container.textContent).toMatch(/PHP.*修補/u);
});
