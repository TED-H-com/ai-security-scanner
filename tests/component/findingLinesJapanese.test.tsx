import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";

import { ENGLISH_ROLLBACK } from "../../src/findingNarrative";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { FindingsPage } from "../../src/pages/FindingsPage";
import { auditFinding, auditReport, auditRun } from "../support/sourceAudit";

afterEach(() => { cleanup(); localStorage.clear(); });

test("Japanese findings page translates summary, impact, verification, grouped next step, and first-layer colons", () => {
  localStorage.setItem(localeStorageKey, "ja");
  const report = auditReport();
  report.sourceAudits = [];
  report.actual.checks[0]!.status = "tested_complete";

  const englishSummary =
    "Checkov reported this condition on the assessed asset without rating it. This product rated it high from a failed infrastructure-as-code policy check, rated flat because Checkov publishes no per-check severity offline.";
  const englishImpact =
    "If the scanner result is confirmed, deployed infrastructure may inherit the reported insecure configuration.";
  const englishVerification =
    "Rerun Checkov with the same scope after the change and confirm that source rule CKV_AWS_20 is no longer reported.";

  const base = auditFinding();
  report.findings = [
    {
      ...base,
      sourceAudit: false,
      findingId: "finding-1",
      fingerprint: "fp-1",
      title: "S3 Bucket ACL Allows Read Or Write to All Users",
      plainLanguageRisk: englishSummary,
      possibleImpact: englishImpact,
      severity: "high",
      confidence: "high",
      family: "infrastructure_as_code",
      severityBasisCode: "iac_policy_check",
      confidenceBasisCode: "deterministic_policy_evaluation",
      contextFactors: ["internet_exposed_asset"],
      recommendedExpertType: "Infrastructure-as-code engineer",
      rollbackConsiderations: ENGLISH_ROLLBACK,
      verificationGuidance: englishVerification,
      evidenceReferences: [{ ...base.evidenceReferences[0]!, engineId: "checkov" }],
    },
    {
      ...base,
      sourceAudit: false,
      findingId: "finding-2",
      fingerprint: "fp-2",
      title: "S3 Bucket versioning is disabled",
      plainLanguageRisk: englishSummary,
      possibleImpact: englishImpact,
      severity: "medium",
      confidence: "high",
      family: "infrastructure_as_code",
      severityBasisCode: "iac_policy_check",
      confidenceBasisCode: "deterministic_policy_evaluation",
      recommendedExpertType: "Infrastructure-as-code engineer",
      verificationGuidance: englishVerification,
      evidenceReferences: [{ ...base.evidenceReferences[0]!, evidenceId: "evidence-2", engineId: "checkov" }],
    },
  ];
  report.nextSteps = [{
    priority: 1,
    code: "remediate_finding",
    findingId: "finding-1",
    alsoResolves: ["finding-2"],
    sharedFix: false,
    family: "infrastructure_as_code",
    action: "Correct the infrastructure-as-code template so redeployment does not restore the insecure setting.",
    reason: "S3 Bucket ACL Allows Read Or Write to All Users",
    recommendedExpertType: "Infrastructure-as-code engineer",
  }];

  const { container } = render(
    <I18nProvider>
      <FindingsPage
        report={report}
        selectedRunId={report.runId}
        findings={[]}
        findingGroups={[]}
        findingGroupEvents={[]}
        runs={[auditRun()]}
        workflowEvents={[]}
        busy={false}
        onUpdateWorkflow={async () => true}
        onGroupFindings={async () => true}
        onUngroupFindings={async () => {}}
        onOpenCoverage={vi.fn()}
        onOpenProgress={vi.fn()}
        onOpenExport={vi.fn()}
      />
    </I18nProvider>,
  );

  const row = container.querySelector<HTMLButtonElement>(".finding-row");
  expect(row).not.toBeNull();
  fireEvent.click(row!);

  const text = container.textContent ?? "";
  expect(text).toContain("Checkov は評価対象の資産でこの状態を報告しましたが、深刻度は評価していません。");
  expect(text).toContain("その後デプロイされるインフラに、報告された安全でない設定が引き継がれるおそれがあります。");
  expect(text).toContain("影響を受ける資産はインターネットからアクセスできるため、到達可能な攻撃対象領域が広がります。");
  expect(text).toContain("変更後に同じ対象範囲で Checkov を再実行し、検出ルール CKV_AWS_20 が報告されなくなったことを確認してください。");
  expect(text).toContain("2 件の関連する問題にこの種類の対応が必要で、それぞれ個別に修正する必要があります。");
  expect(text).toContain("修正後に同じ範囲で再スキャンし、これらの問題が報告されなくなったことを確認してください。");
  expect(text).toContain("変更を加える前に現在の設定を記録し、復元手順をテストしてください。");

  expect(text).not.toContain(englishSummary);
  expect(text).not.toContain(englishImpact);
  expect(text).not.toContain(englishVerification);
  expect(text).not.toContain(ENGLISH_ROLLBACK);
  expect(text).not.toContain("related problems call for this kind of change");
  expect(text).not.toContain("Rerun the same scan after the changes");

  const firstLayerScope = container.querySelector(".report-first-layer-scope")?.textContent ?? "";
  expect(firstLayerScope).toContain("依頼：Example project");
  expect(firstLayerScope).toContain("実際にテスト：");
  expect(firstLayerScope).not.toContain("依頼:");
  expect(firstLayerScope).not.toContain("依頼： ");
  expect(firstLayerScope).not.toContain("実際にテスト:");
  expect(firstLayerScope).not.toContain("実際にテスト： ");
});
