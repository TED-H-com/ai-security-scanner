import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  findRequestedExportRun,
  reconcileReportRunId,
} from "../../src/exportRunSelection.ts";
import type { ScanRun } from "../../src/types.ts";

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
  coveredAssetCount: 0,
  totalAssetCount: 0,
});

const workspace = {
  case: { id: "case-1" },
  runs: [run("run-newest"), run("run-history")],
};

test("export run selection returns the requested historical run instead of the newest run", () => {
  assert.equal(
    findRequestedExportRun({ caseId: "case-1", runId: "run-history" }, workspace)?.id,
    "run-history",
  );
});

test("export run selection fails closed for stale or cross-case coordinates", () => {
  assert.equal(
    findRequestedExportRun({ caseId: "case-1", runId: "run-missing" }, workspace),
    undefined,
  );
  assert.equal(
    findRequestedExportRun({ caseId: "case-other", runId: "run-history" }, workspace),
    undefined,
  );
});

test("UI selection initializes explicitly but retains a stale non-empty id to fail closed", () => {
  assert.equal(reconcileReportRunId(undefined, "case-1", undefined, workspace.runs), "run-newest");
  assert.equal(reconcileReportRunId("case-old", "case-1", "old-run", workspace.runs), "run-newest");
  assert.equal(reconcileReportRunId("case-1", "case-1", undefined, workspace.runs), "run-newest");
  assert.equal(reconcileReportRunId("case-1", "case-1", "run-missing", workspace.runs), "run-missing");
  assert.equal(reconcileReportRunId("case-1", "case-1", "run-history", workspace.runs), "run-history");
});

test("Findings, Export, service, and native command preserve one explicit run coordinate", () => {
  const app = readFileSync(new URL("../../src/App.tsx", import.meta.url), "utf8");
  const findings = readFileSync(new URL("../../src/pages/FindingsPage.tsx", import.meta.url), "utf8");
  const exportPage = readFileSync(new URL("../../src/pages/ExportPage.tsx", import.meta.url), "utf8");
  const scanner = readFileSync(new URL("../../src/services/scanner.ts", import.meta.url), "utf8");
  const commands = readFileSync(new URL("../../src-tauri/src/commands.rs", import.meta.url), "utf8");

  assert.match(app, /onOpenExport=\{\(runId\) => \{[\s\S]*setSelectedReportRunId\(runId\);[\s\S]*navigate\("export"\);/u);
  assert.match(
    app,
    /const selectedRun = selectedReportRunId === undefined[\s\S]*\? workspace\?\.runs\[0\][\s\S]*: workspace\?\.runs\.find\(\(run\) => run\.id === selectedReportRunId\);/u,
  );
  assert.doesNotMatch(app, /workspace\?\.runs\.find\(\(run\) => run\.id === selectedReportRunId\)\s*\?\? workspace\?\.runs\[0\]/u);
  assert.match(app, /const selectedRunLifecycle = pageForSelectedRunLifecycle\([\s\S]*workspace\?\.runs \?\? \[\]/u);
  assert.equal((app.match(/selectedRunId=\{currentRun\?\.id \?\? selectedReportRunId\}/gu) ?? []).length, 2);
  assert.match(findings, /runs\.find\(\(run\) => run\.id === selectedRunId\)/u);
  assert.match(findings, /selectedRunId === undefined[\s\S]*\? \(report \? runs\.find/u);
  assert.match(findings, /onOpenExport\(latestRun\.id\)/u);
  // The four ExportPage assertions below match source text, so they break on
  // reformatting alone. Do not simply delete one when that happens: the
  // behaviour they stand for is pinned for real by rendering the page in
  // `tests/component/exportPreviewHonesty.test.tsx`. Reconcile with that first.
  assert.match(exportPage, /workspace\.runs\.find\(\(run\) => run\.id === selectedRunId\)/u);
  assert.doesNotMatch(exportPage, /workspace\.runs\[0\]/u);
  assert.match(exportPage, /result\.runId !== selectedRun\.id/u);
  assert.match(exportPage, /onExport\(\{ runId: selectedRun\.id,/u);

  const previewStart = scanner.indexOf("async previewExport");
  const exportEnd = scanner.indexOf("async verifyCaseExport", previewStart);
  const exportFlow = scanner.slice(previewStart, exportEnd);
  assert.match(exportFlow, /findRequestedExportRun\(input, workspace\)/u);
  assert.doesNotMatch(exportFlow, /workspace\.runs\[0\]/u);

  const previewCommandStart = commands.indexOf("pub fn preview_export");
  const exportCommandEnd = commands.indexOf("pub fn verify_case_export", previewCommandStart);
  const nativeExportFlow = commands.slice(previewCommandStart, exportCommandEnd);
  assert.equal((nativeExportFlow.match(/&input\.run_id\b/gu) ?? []).length, 2);
  assert.doesNotMatch(nativeExportFlow, /\.max_by\(/u);
});

test("native and demo export filenames carry one safe stable run identity", () => {
  const scanner = readFileSync(new URL("../../src/services/scanner.ts", import.meta.url), "utf8");

  assert.match(
    scanner,
    /defaultPath: `\$\{safeName\}-\$\{exportRunFileIdentity\(run\)\}\.\$\{fileType\.suffix\}`/u,
  );
  assert.match(scanner, /createDemoExport\(demoInput, workspace, run\)/u);
  assert.match(
    scanner,
    /fileName: `\$\{safeName \|\| "case"\}-\$\{exportRunFileIdentity\(run\)\}-selected-run\.demo\.json`/u,
  );
  assert.match(scanner, /runId: input\.runId/u);
  assert.doesNotMatch(scanner, /defaultPath:[^\n]*run\.label/u);
});
