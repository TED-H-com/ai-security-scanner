import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  exportFormatIsAvailable,
  resetUnavailableExportFormat,
  runSupportsFindingOnlyExport,
} from "../../src/exportFormatEligibility.ts";
import type { EngineRun, RunStatus, ScanRun } from "../../src/types.ts";

const engine = (status: EngineRun["status"] = "completed"): EngineRun => ({
  id: "engine-run-1",
  engineId: "scanner",
  engineName: "Scanner",
  category: "code",
  version: "1",
  digest: "sha256:test",
  adapterVersion: "1",
  status,
  progress: status === "completed" ? 100 : 50,
  phase: status,
  assetIds: [],
  rawArtifactCount: 0,
  savedResultArtifactCount: 0,
  findingCount: 0,
  findingCountKnown: true,
  warnings: [],
  resumable: false,
});

const run = (
  status: RunStatus,
  engineStatus: EngineRun["status"],
  options: { finished?: boolean; engineRuns?: EngineRun[] } = {},
): ScanRun => ({
  id: `run-${status}`,
  caseId: "case-1",
  label: "Scan 1",
  status,
  progress: status === "completed" ? 100 : 50,
  startedAt: "2026-08-27T00:00:00Z",
  finishedAt: options.finished === false ? undefined : "2026-08-27T00:01:00Z",
  knowledgeDate: "2026-08-27T00:00:00Z",
  engineRuns: options.engineRuns ?? [engine(engineStatus)],
  coveredAssetCount: 0,
  totalAssetCount: 0,
});

test("finding-only formats are available only for terminal runs", () => {
  assert.equal(runSupportsFindingOnlyExport(run("completed", "completed")), true);
  assert.equal(runSupportsFindingOnlyExport(run("completed", "completed", { finished: false })), true);
  assert.equal(runSupportsFindingOnlyExport(run("completed", "completed", { engineRuns: [] })), true);
  assert.equal(runSupportsFindingOnlyExport(run("running", "running", { finished: false })), false);
  assert.equal(runSupportsFindingOnlyExport(run("partial", "partial")), true);
  assert.equal(runSupportsFindingOnlyExport(run("failed", "failed")), true);
  assert.equal(runSupportsFindingOnlyExport(undefined), false);
});

test("terminal incomplete runs retain every export with coverage companions where needed", () => {
  for (const incompleteRun of [
    run("partial", "partial"),
    run("failed", "failed"),
  ]) {
    for (const format of ["case_bundle", "json", "framework_report", "html", "ocsf", "oscal"] as const) {
      assert.equal(exportFormatIsAvailable(format, incompleteRun), true);
      assert.equal(resetUnavailableExportFormat(format, incompleteRun), format);
    }
  }
});

test("active runs expose no export format", () => {
  const active = run("running", "running", { finished: false });
  for (const format of ["case_bundle", "json", "framework_report", "html", "ocsf", "oscal"] as const) {
    assert.equal(exportFormatIsAvailable(format, active), false);
  }
});

test("the export page explains mandatory coverage companions", () => {
  const source = readFileSync(new URL("../../src/pages/ExportPage.tsx", import.meta.url), "utf8");

  assert.match(source, /resetUnavailableExportFormat\(format, selectedRun\)/u);
  assert.match(source, /if \(selectedFormatUnavailable\) \{[\s\S]*setPreviewPending\(false\);[\s\S]*return;/u);
  assert.match(source, /disabled=\{unavailable\}/u);
  assert.match(source, /const unavailableInDemo = demoMode && id !== "json"/u);
  assert.match(source, /OCSF finding and service-inventory events plus a coverage manifest for missing or unfinished checks/u);
  assert.match(source, /OCSF 問題與服務盤點事件，另附涵蓋說明檔記錄未測或未完成項目/u);
  assert.match(source, /OSCAL observations plus a coverage manifest for missing or unfinished checks/u);
  assert.match(source, /OSCAL 觀察資料，另附涵蓋說明檔記錄未測或未完成項目/u);
});

test("the export page defaults to a readable report without raw source files", () => {
  const source = readFileSync(new URL("../../src/pages/ExportPage.tsx", import.meta.url), "utf8");

  assert.match(source, /useState<ExportFormat>\("html"\)/u);
  assert.match(source, /useState\(false\)/u);
  assert.match(source, /const primaryFormats = \["html", "json"\]/u);
  assert.match(source, /const advancedFormats = \[\s*"case_bundle",\s*"framework_report",\s*"ocsf",\s*"oscal",/u);
  assert.match(source, /en: "HTML report"/u);
  assert.match(source, /zhTW: "HTML 報告"/u);
  assert.match(source, /en: "\{format\} \(recommended\)"/u);
  assert.match(source, /zhTW: "\{format\}（建議）"/u);
  assert.match(source, /JSON report/u);
  assert.match(source, /JSON 報告/u);
  assert.match(source, /More formats/u);
  assert.match(source, /更多格式/u);
});

test("the technical case bundle discloses its case-wide and run-bound scope before export", () => {
  const source = readFileSync(new URL("../../src/pages/ExportPage.tsx", import.meta.url), "utf8");

  assert.match(source, /format === "case_bundle"\s*\? copy\.scopeCaseBundle\s*:\s*copy\.scopeSelectedRun/u);
  assert.match(
    source,
    /<span className="export-decision-summary">[\s\S]*text\(scopeConsequence\)[\s\S]*text\(integrityConsequence\)/u,
  );
  assert.match(source, /Case-wide records; reports use the selected run/u);
  assert.match(source, /案件全域紀錄；報告使用所選輪次/u);
  assert.doesNotMatch(source, /export-bundle-scope/u);
  assert.match(
    source,
    /<details className="export-summary export-summary--details">[\s\S]*formatIsSigned && <p className="export-summary__note">\{text\(copy\.caseBundleScopeBody\)\}<\/p>/u,
  );
  assert.match(
    source,
    /case-wide assets, grants, coverage, scan history, findings, workflow history, comparisons/u,
  );
  assert.match(source, /Reports use observations and evidence from the selected scan run/u);
  assert.match(source, /older observations without a frozen snapshot/u);
  assert.match(source, /fallback wording uses the current finding/u);
  assert.match(source, /workflow status and asset names come from the current case/u);
  assert.match(source, /包內報告使用所選掃描輪次的觀察與證據/u);
  assert.match(source, /較舊且沒有凍結快照的觀察/u);
  assert.match(source, /會以目前問題內容作為後備文字/u);
  assert.match(source, /工作流程狀態與資產名稱來自目前案件/u);
  assert.doesNotMatch(source, /Reports inside the bundle remain limited to the selected scan run/u);
  assert.doesNotMatch(source, /包內報告仍只涵蓋選定的掃描輪次/u);
  assert.match(source, /Case \/ selected-run result records/u);
  assert.match(source, /All \/ selected-run evidence records/u);
});

test("the export decision line exposes disclosure, scope, and honest integrity before Save", () => {
  const source = readFileSync(new URL("../../src/pages/ExportPage.tsx", import.meta.url), "utf8");

  assert.match(source, /<span className="export-sharing-consequence">\{text\(sharingConsequence\)\}<\/span>/u);
  assert.match(source, /\{" · "\}\{text\(scopeConsequence\)\}\{" · "\}\{text\(integrityConsequence\)\}/u);
  assert.match(source, /Integrity: SHA-256 recorded in this scan project/u);
  assert.match(source, /Integrity: locally signed/u);
  assert.match(source, /Demo sample: integrity record unavailable/u);
  assert.match(source, /<div className="export-actions">[\s\S]*aria-describedby="export-preview-status"/u);
});
