import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  isTerminalResultRun,
  isVerificationBaselineRun,
} from "../../src/runLifecycle.ts";
import type { RunStatus } from "../../src/types.ts";

test("result routes and verification baselines use distinct terminal sets", () => {
  const resultStatuses: RunStatus[] = [
    "completed",
    "no_checks_completed",
    "partial",
    "failed",
    "cancelled",
  ];
  for (const status of resultStatuses) assert.equal(isTerminalResultRun({ status }), true, status);
  for (const status of ["queued", "running", "paused"] as const) {
    assert.equal(isTerminalResultRun({ status }), false, status);
  }

  for (const status of ["completed", "partial", "failed", "cancelled"] as const) {
    assert.equal(isVerificationBaselineRun({ status }), true, status);
  }
  for (const status of ["queued", "running", "paused", "no_checks_completed"] as const) {
    assert.equal(isVerificationBaselineRun({ status }), false, status);
  }
});

test("case entry uses result eligibility while verification uses baseline eligibility", async () => {
  const [app, cases, verification] = await Promise.all([
    readFile(new URL("../../src/App.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/pages/CasesPage.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/pages/VerificationPage.tsx", import.meta.url), "utf8"),
  ]);

  assert.match(app, /workspace\.runs\.find\(isTerminalResultRun\)/u);
  assert.match(app, /workspace\?\.runs\.filter\(isVerificationBaselineRun\)/u);
  assert.match(cases, /const terminalResultRuns = runs\.filter\(isTerminalResultRun\)/u);
  assert.match(cases, /const verificationBaselineRuns = runs\.filter\(isVerificationBaselineRun\)/u);
  assert.match(verification, /runs\.filter\(isVerificationBaselineRun\)/u);
});

test("imported evidence stays a result without becoming an executable verification baseline", () => {
  const importedTask = {
    taskKind: {
      kind: "external_report_import" as const,
      sourceFormat: "strix-vulnerabilities-json/v1",
      sourceSha256: "a".repeat(64),
    },
  };
  for (const status of ["partial", "failed", "completed"] as const) {
    const run = { status, engineRuns: [importedTask] };
    assert.equal(isTerminalResultRun(run), true);
    assert.equal(isVerificationBaselineRun(run), false);
  }
  assert.equal(isVerificationBaselineRun({
    status: "partial",
    engineRuns: [importedTask, { taskKind: { kind: "catalog_engine" } }],
  }), true);
});

test("an admitted source audit is a result, and only a scanner sibling makes a verification baseline", () => {
  const taskKind = { kind: "agent_audit" as const, providerId: "cloudflare", admissionId: "admitted" };
  for (const status of ["completed", "partial"] as const) {
    assert.equal(isTerminalResultRun({ status }), true);
    assert.equal(isVerificationBaselineRun({ status, engineRuns: [{ taskKind }] }), false);
    assert.equal(isVerificationBaselineRun({ status, engineRuns: [{ taskKind }, { taskKind: { kind: "catalog_engine" } }] }), true);
  }
});

test("source audit progress never offers recovery or catalog next-step instructions", async () => {
  const { build } = await import("esbuild");
  const { auditRun } = await import("../support/sourceAudit.ts");
  const output = await build({ entryPoints: ['src/scanPresentation.ts'], bundle: true, platform: 'node', format: 'esm', write: false });
  const api = await import(`data:text/javascript;base64,${Buffer.from(output.outputFiles[0]!.text).toString('base64')}`);
  const task = auditRun().engineRuns[0]!;
  assert.equal(api.engineRecoveryModeFor({ ...task, resumable: true, recoveryAction: 'restart_check' }), undefined);
  assert.equal(api.engineOutcomeFor(task).en, 'Cloudflare source audit');
  assert.equal(api.engineNextStepFor(task).en, 'Read the source audit results.');
});

for (const ending of ["blocked", "terminated"] as const) test(`${ending} source audit is readable, never a scanner baseline or recovery task`, async () => {
  const { failureRun, failureOutcome } = await import("../support/auditFailure.ts");
  const { failureDescription } = await import("../../src/auditFailure.ts");
  const { hasSourceAudit } = await import("../../src/runLifecycle.ts");
  const { build } = await import("esbuild");
  const output = await build({ entryPoints: ["src/scanPresentation.ts"], bundle: true, platform: "node", format: "esm", write: false });
  const api = await import(`data:text/javascript;base64,${Buffer.from(output.outputFiles[0]!.text).toString("base64")}`);
  const run = failureRun(ending);
  const task = run.engineRuns[0]!;
  assert.equal(isTerminalResultRun(run), true);
  assert.equal(isVerificationBaselineRun(run), false);
  assert.equal(hasSourceAudit(run), true);
  assert.equal(hasSourceAudit(undefined), false);
  assert.equal(hasSourceAudit({ engineRuns: [] }), false);
  assert.equal(api.engineOutcomeFor(task).en, "Cloudflare source audit");
  assert.deepEqual(api.engineNextStepFor(task), failureDescription(failureOutcome(ending)).nextAction);
  for (const recoveryAction of ["continue_saved_results", "restart_check", "finish_cleanup"]) {
    assert.equal(api.engineRecoveryModeFor({ ...task, resumable: true, recoveryAction }), undefined);
  }
  const scanner = { ...task, taskKind: { kind: "catalog_engine" as const } };
  assert.equal(hasSourceAudit({ engineRuns: [scanner] }), false);
  assert.equal(hasSourceAudit({ engineRuns: [scanner, task] }), true);
  assert.equal(isVerificationBaselineRun({ status: "partial", engineRuns: [task, scanner] }), true);
});
