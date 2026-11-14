import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";

import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { FindingsPage } from "../../src/pages/FindingsPage";
import { auditFinding, auditReport, auditRun } from "../support/sourceAudit";

afterEach(() => { cleanup(); localStorage.clear(); });

test("Japanese findings page translates tested observations and control mapping rationale", () => {
  localStorage.setItem(localeStorageKey, "ja");
  const report = auditReport();
  report.sourceAudits = [];
  const observation = "The port accepted the bounded TCP connection.";
  const rationale = "Evidence that an identity has no registered multi-factor device is related to authenticating users and safeguarding authentication information.";
  report.actual.checks[0]!.testedDimensions = [{ dimension: "TCP reachability", value: "host:443", observation }];
  report.findings = [{ ...auditFinding(), sourceAudit: false, frameworkReferences: [{
    framework: "NIST CSF", frameworkVersion: "2.0", controlId: "PR.AA-03",
    title: "Authentication of users, services, and hardware", relationship: "related",
    rationale, mappingVersion: "1.0",
  }] }];
  const { container } = render(<I18nProvider><FindingsPage
    report={report} selectedRunId={report.runId} findings={[]} findingGroups={[]} findingGroupEvents={[]}
    runs={[auditRun()]} workflowEvents={[]} busy={false} onUpdateWorkflow={async () => true}
    onGroupFindings={async () => true} onUngroupFindings={async () => {}}
    onOpenCoverage={vi.fn()} onOpenProgress={vi.fn()} onOpenExport={vi.fn()}
  /></I18nProvider>);
  const row = container.querySelector<HTMLButtonElement>(".finding-row");
  expect(row).not.toBeNull();
  fireEvent.click(row!);
  expect(container.textContent).toContain("このポートは制限された TCP 接続を受け入れました。");
  expect(container.textContent).toContain("ID に多要素認証デバイスが登録されていない証拠は、ユーザーの認証と認証情報の保護に関連します。");
  expect(container.textContent).toContain("PR.AA-03");
  expect(container.textContent).not.toContain(observation);
  expect(container.textContent).not.toContain(rationale);
});
