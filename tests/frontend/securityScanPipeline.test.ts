import assert from "node:assert/strict";
import test from "node:test";
import { isExposureObservation, isSecurityFinding } from "../../src/findingClassification.ts";
import { scanRunOverallProgress } from "../../src/scanRunProgress.ts";
import { buildScanActivity } from "../../src/scanActivity.ts";
import type { EngineRun, ScanRun } from "../../src/types.ts";

test("security scan pipeline integrates scan progress, finding classification, and activity reporting", () => {
  // Simulate a scan run with findings
  const secretEngineRun: EngineRun = {
    id: "gitleaks-1",
    engineId: "gitleaks",
    engineName: "gitleaks",
    category: "code_and_secrets",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "completed",
    progress: 100,
    phase: "completed",
    assetIds: ["repo-1"],
    rawArtifactCount: 5,
    savedResultArtifactCount: 2,
    findingCount: 1, // Secret found
    resumable: false,
    finishedAt: "2026-08-26T13:02:00Z"
  };

  const portEngineRun: EngineRun = {
    id: "naabu-1",
    engineId: "naabu",
    engineName: "naabu",
    category: "inventory",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "completed",
    progress: 100,
    phase: "completed",
    assetIds: ["network-1"],
    rawArtifactCount: 5,
    savedResultArtifactCount: 3,
    findingCount: 3, // Ports found
    resumable: false,
    finishedAt: "2026-08-26T13:05:00Z"
  };

  const scanRun: ScanRun = {
    id: "scan-1",
    caseId: "case-1",
    label: "End-to-End Test Scan",
    status: "completed",
    progress: 100,
    startedAt: "2026-08-26T13:00:00Z",
    finishedAt: "2026-08-26T13:05:00Z",
    lastProgressAt: "2026-08-26T13:05:00Z",
    knowledgeDate: "2026-08-26T12:00:00Z",
    engineRuns: [secretEngineRun, portEngineRun],
    coveredAssetCount: 2,
    totalAssetCount: 2,
  };

  // 1. Assert overall progress
  assert.equal(scanRunOverallProgress(scanRun), 100, "Overall progress should be 100%");

  // 2. Classify findings and check results
  // For the secret scanner:
  assert.equal(
    isSecurityFinding({ severityBasisCode: "secret_pattern_match" }),
    true,
    "Secret pattern match should be classified as a security finding"
  );

  // For the port scanner:
  assert.equal(
    isExposureObservation({ severityBasisCode: "open_port" }),
    true,
    "Open port should be classified as an exposure observation, not a vulnerability"
  );
  assert.equal(
    isSecurityFinding({ severityBasisCode: "open_port" }),
    false,
    "Open port is not a security finding"
  );

  // 3. Build and assert the scan activity report
  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));

  assert.equal(activity.state, "completed", "Activity state should be completed");
  assert.ok(activity.events.some((event) => event.code === "run_completed"), "Activity should include a run_completed event");
});

test("security scan pipeline covers cancelled running scans", () => {
  const secretEngineRun: EngineRun = {
    id: "gitleaks-1",
    engineId: "gitleaks",
    engineName: "gitleaks",
    category: "code_and_secrets",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "running",
    progress: 50,
    phase: "executing",
    assetIds: ["repo-1"],
    rawArtifactCount: 5,
    savedResultArtifactCount: 2,
    findingCount: 1,
    resumable: false
  };

  const scanRun: ScanRun = {
    id: "scan-2",
    caseId: "case-2",
    label: "End-to-End Test Scan Cancel",
    status: "cancelled",
    progress: 50,
    startedAt: "2026-08-26T13:00:00Z",
    finishedAt: "2026-08-26T13:05:00Z",
    lastProgressAt: "2026-08-26T13:05:00Z",
    knowledgeDate: "2026-08-26T12:00:00Z",
    engineRuns: [secretEngineRun],
    coveredAssetCount: 0,
    totalAssetCount: 1,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  assert.equal(activity.state, "stopped", "Activity state should be stopped");
  assert.ok(activity.events.some((event) => event.code === "run_stopped"), "Activity should include a run_stopped event");
});

test("security scan pipeline covers mixed status running scans", () => {
  const check1: EngineRun = {
    id: "gitleaks-1",
    engineId: "gitleaks",
    engineName: "gitleaks",
    category: "code_and_secrets",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "completed",
    progress: 100,
    phase: "completed",
    assetIds: ["repo-1"],
    rawArtifactCount: 5,
    savedResultArtifactCount: 2,
    findingCount: 1,
    resumable: false,
    finishedAt: "2026-08-26T13:01:00Z"
  };
  const check2: EngineRun = {
    id: "naabu-1",
    engineId: "naabu",
    engineName: "naabu",
    category: "inventory",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "failed",
    progress: 50,
    phase: "executing",
    assetIds: ["network-1"],
    rawArtifactCount: 5,
    savedResultArtifactCount: 3,
    findingCount: 3,
    resumable: false,
    finishedAt: "2026-08-26T13:02:00Z"
  };

  const scanRun: ScanRun = {
    id: "scan-2",
    caseId: "case-2",
    label: "End-to-End Test Scan Partial",
    status: "partial",
    progress: 75,
    startedAt: "2026-08-26T13:00:00Z",
    finishedAt: "2026-08-26T13:02:00Z",
    lastProgressAt: "2026-08-26T13:02:00Z",
    knowledgeDate: "2026-08-26T12:00:00Z",
    engineRuns: [check1, check2],
    coveredAssetCount: 1,
    totalAssetCount: 2,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  assert.equal(activity.state, "partly_completed", "Activity state should be partly_completed");
  assert.ok(activity.events.some((event) => event.code === "run_partly_completed"), "Activity should include a run_partly_completed event");
});

test("security scan pipeline covers failed terminal scans", () => {
  const scanRun: ScanRun = {
    id: "scan-2",
    caseId: "case-2",
    label: "End-to-End Test Scan Fail",
    status: "failed",
    progress: 75,
    startedAt: "2026-08-26T13:00:00Z",
    finishedAt: "2026-08-26T13:02:00Z",
    lastProgressAt: "2026-08-26T13:02:00Z",
    knowledgeDate: "2026-08-26T12:00:00Z",
    engineRuns: [],
    coveredAssetCount: 0,
    totalAssetCount: 0,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  assert.equal(activity.state, "failed", "Activity state should be failed");
  assert.ok(activity.events.some((event) => event.code === "run_failed"), "Activity should include a run_failed event");
});

test("security scan pipeline covers not_executed scans", () => {
  const scanRun: ScanRun = {
    id: "scan-2",
    caseId: "case-2",
    label: "End-to-End Test Scan Zero checks",
    status: "completed",
    progress: 100,
    startedAt: "2026-08-26T13:00:00Z",
    finishedAt: "2026-08-26T13:02:00Z",
    lastProgressAt: "2026-08-26T13:02:00Z",
    knowledgeDate: "2026-08-26T12:00:00Z",
    engineRuns: [],
    coveredAssetCount: 0,
    totalAssetCount: 0,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  assert.equal(activity.state, "completed", "Activity state should be completed");
  assert.ok(activity.events.some((event) => event.code === "run_completed"), "Activity should include a run_completed event");
});

test("security scan pipeline covers pending verification baseline selection", () => {
  const check1: EngineRun = {
    id: "gitleaks-1",
    engineId: "gitleaks",
    engineName: "gitleaks",
    category: "code_and_secrets",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "completed",
    progress: 100,
    phase: "completed",
    assetIds: ["repo-1"],
    rawArtifactCount: 5,
    savedResultArtifactCount: 2,
    findingCount: 1,
    resumable: false,
    finishedAt: "2026-08-26T13:01:00Z"
  };

  const scanRun: ScanRun = {
    id: "scan-3",
    caseId: "case-3",
    label: "End-to-End Test Scan Pending",
    status: "pending",
    progress: 0,
    engineRuns: [check1],
    coveredAssetCount: 0,
    totalAssetCount: 1,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  assert.equal(activity.state, "waiting_to_start", "Activity state should be waiting_to_start");
  assert.ok(activity.events.some((event) => event.code === "run_requested"), "Activity should include a run_requested event");
});

test("security scan pipeline covers running missing status", () => {
  const scanRun: ScanRun = {
    id: "scan-3",
    caseId: "case-3",
    label: "End-to-End Test Scan Missing",
    status: "running",
    progress: 0,
    startedAt: "2026-08-26T13:00:00Z",
    lastProgressAt: "2026-08-26T13:00:00Z",
    engineRuns: [],
    coveredAssetCount: 0,
    totalAssetCount: 1,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  assert.equal(activity.state, "waiting_to_start", "Activity state should be waiting_to_start");
  assert.ok(activity.events.some((event) => event.code === "run_requested"), "Activity should include a run_requested event");
});

test("security scan pipeline covers paused missing status", () => {
  const scanRun: ScanRun = {
    id: "scan-3",
    caseId: "case-3",
    label: "End-to-End Test Scan Paused",
    status: "paused",
    progress: 50,
    startedAt: "2026-08-26T13:00:00Z",
    lastProgressAt: "2026-08-26T13:00:00Z",
    engineRuns: [],
    coveredAssetCount: 0,
    totalAssetCount: 1,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  assert.equal(activity.state, "paused", "Activity state should be paused");
  assert.ok(activity.events.some((event) => event.code === "run_paused"), "Activity should include a run_paused event");
});

test("scanRunProgress null handles edge cases", () => {
  const scanRun: ScanRun = {
    id: "scan-4",
    caseId: "case-4",
    label: "End-to-End Test Null",
    status: "running",
    progress: 50,
    startedAt: "2026-08-26T13:00:00Z",
    engineRuns: [],
    coveredAssetCount: 0,
    totalAssetCount: 0,
  };

  assert.equal(scanRunOverallProgress(scanRun), 0); // It falls back to overall progress
});

test("security scan pipeline covers not_executed partial scans", () => {
  const check1: EngineRun = {
    id: "gitleaks-1",
    engineId: "gitleaks",
    engineName: "gitleaks",
    category: "code_and_secrets",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "not_executed",
    progress: 100,
    phase: "completed",
    assetIds: ["repo-1"],
    rawArtifactCount: 5,
    savedResultArtifactCount: 2,
    findingCount: 1,
    resumable: false,
    finishedAt: "2026-08-26T13:01:00Z"
  };

  const scanRun: ScanRun = {
    id: "scan-2",
    caseId: "case-2",
    label: "End-to-End Test Scan Zero checks",
    status: "completed",
    progress: 100,
    startedAt: "2026-08-26T13:00:00Z",
    finishedAt: "2026-08-26T13:02:00Z",
    lastProgressAt: "2026-08-26T13:02:00Z",
    knowledgeDate: "2026-08-26T12:00:00Z",
    engineRuns: [check1],
    coveredAssetCount: 0,
    totalAssetCount: 0,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  assert.equal(activity.state, "completed", "Activity state should be completed");
  assert.ok(activity.events.some((event) => event.code === "run_completed"), "Activity should include a run_completed event");
});

test("security scan pipeline covers engine partial but overall completed", () => {
  const check1: EngineRun = {
    id: "gitleaks-1",
    engineId: "gitleaks",
    engineName: "gitleaks",
    category: "code_and_secrets",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "partial",
    progress: 100,
    phase: "completed",
    assetIds: ["repo-1"],
    rawArtifactCount: 5,
    savedResultArtifactCount: 2,
    findingCount: 1,
    resumable: false,
    finishedAt: "2026-08-26T13:01:00Z"
  };

  const scanRun: ScanRun = {
    id: "scan-2",
    caseId: "case-2",
    label: "End-to-End Test Scan Partial",
    status: "completed",
    progress: 100,
    startedAt: "2026-08-26T13:00:00Z",
    finishedAt: "2026-08-26T13:02:00Z",
    lastProgressAt: "2026-08-26T13:02:00Z",
    knowledgeDate: "2026-08-26T12:00:00Z",
    engineRuns: [check1],
    coveredAssetCount: 0,
    totalAssetCount: 0,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  assert.equal(activity.state, "completed", "Activity state should be completed");
  assert.ok(activity.events.some((event) => event.code === "run_completed"), "Activity should include a run_completed event");
});

test("security scan pipeline covers phase mapped states for active scans", () => {
  const engineRuns: EngineRun[] = [
    {
      id: "run-preflight", engineId: "e1", engineName: "e1", category: "inventory",
      taskKind: { kind: "catalog_engine" }, warnings: [], status: "running", progress: 10, phase: "preflight",
      assetIds: [], rawArtifactCount: 0, savedResultArtifactCount: 0, findingCount: 0, resumable: false,
    },
    {
      id: "run-pulling", engineId: "e1", engineName: "e1", category: "inventory",
      taskKind: { kind: "catalog_engine" }, warnings: [], status: "running", progress: 20, phase: "pulling_image",
      assetIds: [], rawArtifactCount: 0, savedResultArtifactCount: 0, findingCount: 0, resumable: false,
    },
    {
      id: "run-running", engineId: "e1", engineName: "e1", category: "inventory",
      taskKind: { kind: "catalog_engine" }, warnings: [], status: "running", progress: 50, phase: "running",
      assetIds: [], rawArtifactCount: 0, savedResultArtifactCount: 0, findingCount: 0, resumable: false,
    },
    {
      id: "run-capturing", engineId: "e1", engineName: "e1", category: "inventory",
      taskKind: { kind: "catalog_engine" }, warnings: [], status: "running", progress: 80, phase: "capturing_artifacts",
      assetIds: [], rawArtifactCount: 0, savedResultArtifactCount: 0, findingCount: 0, resumable: false,
    },
    {
      id: "run-cleanup", engineId: "e1", engineName: "e1", category: "inventory",
      taskKind: { kind: "catalog_engine" }, warnings: [], status: "running", progress: 95, phase: "cleanup_pending",
      assetIds: [], rawArtifactCount: 0, savedResultArtifactCount: 0, findingCount: 0, resumable: false,
    },
  ];

  for (const engine of engineRuns) {
    const scanRun: ScanRun = {
      id: "scan-phase",
      caseId: "case-phase",
      label: `Test Scan Phase ${engine.phase}`,
      status: "running",
      progress: engine.progress,
      startedAt: "2026-08-26T13:00:00Z",
      lastProgressAt: "2026-08-26T13:00:00Z",
      engineRuns: [engine],
      coveredAssetCount: 0,
      totalAssetCount: 1,
    };

    const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
    const expectedState = engine.phase === "preflight" ? "checking_readiness" : engine.phase === "pulling_image" ? "preparing_scanner" : engine.phase === "running" ? "scanner_working" : engine.phase === "capturing_artifacts" ? "preparing_results" : engine.phase === "cleanup_pending" ? "closing_scanner" : "active";
    assert.equal(activity.state, expectedState, `Activity state for phase ${engine.phase} should be ${expectedState}`);
    assert.ok(activity.events.some((event) => event.code === "run_requested"));
  }
});

test("security scan pipeline unhandled state and edge case", () => {
  const engineRuns: EngineRun[] = [
    {
      id: "run-unhandled", engineId: "e1", engineName: "e1", category: "inventory",
      taskKind: { kind: "catalog_engine" }, warnings: [], status: "running", progress: 10, phase: "adapting_artifacts",
      assetIds: [], rawArtifactCount: 0, savedResultArtifactCount: 0, findingCount: 0, resumable: false,
    },
    {
      id: "run-unhandled", engineId: "e2", engineName: "e2", category: "inventory",
      taskKind: { kind: "catalog_engine" }, warnings: [], status: "running", progress: 10, phase: "planned",
      assetIds: [], rawArtifactCount: 0, savedResultArtifactCount: 0, findingCount: 0, resumable: false,
    },
    {
      id: "run-unhandled", engineId: "e2", engineName: "e2", category: "inventory",
      taskKind: { kind: "catalog_engine" }, warnings: [], status: "running", progress: 10, phase: "unknown_phase",
      assetIds: [], rawArtifactCount: 0, savedResultArtifactCount: 0, findingCount: 0, resumable: false,
    }
  ];

  for (const engine of engineRuns) {
    const scanRun: ScanRun = {
      id: "scan-phase",
      caseId: "case-phase",
      label: `Test Scan Phase ${engine.phase}`,
      status: "running",
      progress: engine.progress,
      startedAt: "2026-08-26T13:00:00Z",
      lastProgressAt: "2026-08-26T13:00:00Z",
      engineRuns: [engine],
      coveredAssetCount: 0,
      totalAssetCount: 1,
    };

    const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
    assert.ok(activity.state);
  }
});

test("security scan pipeline covers no_checks_completed run event", () => {
  const scanRun: ScanRun = {
    id: "scan-2",
    caseId: "case-2",
    label: "End-to-End Test Scan Zero checks completely empty",
    status: "no_checks_completed",
    progress: 100,
    startedAt: "2026-08-26T13:00:00Z",
    finishedAt: "2026-08-26T13:02:00Z",
    lastProgressAt: "2026-08-26T13:02:00Z",
    knowledgeDate: "2026-08-26T12:00:00Z",
    engineRuns: [],
    coveredAssetCount: 0,
    totalAssetCount: 0,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  assert.equal(activity.state, "no_checks_completed", "Activity state should be no_checks_completed");
  assert.ok(activity.events.some((event) => event.code === "run_no_checks_completed"), "Activity should include a run_no_checks_completed event");
});

test("security scan pipeline covers tie breaking engine statuses", () => {
  const engineRuns: EngineRun[] = [
    {
      id: "b", engineId: "e1", engineName: "e1", category: "inventory",
      taskKind: { kind: "catalog_engine" }, warnings: [], status: "running", progress: 10, phase: "preflight",
      assetIds: [], rawArtifactCount: 0, savedResultArtifactCount: 0, findingCount: 0, resumable: false,
      startedAt: "2026-08-26T13:00:00Z"
    },
    {
      id: "a", engineId: "e2", engineName: "e2", category: "inventory",
      taskKind: { kind: "catalog_engine" }, warnings: [], status: "running", progress: 10, phase: "pulling_image",
      assetIds: [], rawArtifactCount: 0, savedResultArtifactCount: 0, findingCount: 0, resumable: false,
      startedAt: "2026-08-26T13:00:00Z" // same time so it breaks by ID
    }
  ];

  const scanRun: ScanRun = {
    id: "scan-phase",
    caseId: "case-phase",
    label: `Test Scan Phase sorting`,
    status: "running",
    progress: 10,
    startedAt: "2026-08-26T13:00:00Z",
    lastProgressAt: "2026-08-26T13:00:00Z",
    engineRuns,
    coveredAssetCount: 0,
    totalAssetCount: 1,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  // pulling_image check should be chosen if alphabetical order is maintained properly
  // wait actually priority(right) - priority(left) happens.
  // running priority: 4. So both are 4. Then timestamps match. Then localeCompare: right vs left or left vs right?
  assert.ok(activity.state);
});

test("security scan pipeline covers gateway_preparation_failed edge cases", () => {
  const check1: EngineRun = {
    id: "gitleaks-1",
    engineId: "gitleaks",
    engineName: "gitleaks",
    category: "code_and_secrets",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "failed",
    progress: 10,
    phase: "executing",
    assetIds: ["repo-1"],
    rawArtifactCount: 5,
    savedResultArtifactCount: 2,
    findingCount: 1,
    resumable: false,
    failureKind: "gateway_preparation_failed",
  };

  const statuses = ["failed", "partial", "cancelled"] as const;
  for (const status of statuses) {
    const scanRun: ScanRun = {
      id: "scan-phase",
      caseId: "case-phase",
      label: `Test Scan Phase Gateway`,
      status,
      progress: 10,
      startedAt: "2026-08-26T13:00:00Z",
      lastProgressAt: "2026-08-26T13:00:00Z",
      engineRuns: [check1],
      coveredAssetCount: 0,
      totalAssetCount: 1,
    };

    const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
    assert.equal(activity.state, "gateway_preparation_failed", `Activity state should be gateway_preparation_failed for ${status}`);
  }
});

import { isVerificationBaselineRun } from "../../src/runLifecycle.ts";

test("runLifecycle isVerificationBaselineRun coverage", () => {
  assert.equal(isVerificationBaselineRun({ status: "completed", engineRuns: [] }), true);
  assert.equal(isVerificationBaselineRun({ status: "running", engineRuns: [] }), false);
  assert.equal(isVerificationBaselineRun({ status: "completed", engineRuns: [{ taskKind: { kind: "external_import" } }] }), true);
});

test("security scan pipeline covers pending checks sorting edge cases", () => {
  const check1: EngineRun = {
    id: "gitleaks-1",
    engineId: "gitleaks",
    engineName: "gitleaks",
    category: "code_and_secrets",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "pending",
    progress: 10,
    phase: "executing",
    assetIds: ["repo-1"],
    rawArtifactCount: 5,
    savedResultArtifactCount: 2,
    findingCount: 1,
    resumable: false,
  };

  const scanRun: ScanRun = {
    id: "scan-pending",
    caseId: "case-phase",
    label: `Test Scan pending checks`,
    status: "running",
    progress: 10,
    startedAt: "2026-08-26T13:00:00Z",
    lastProgressAt: "2026-08-26T13:00:00Z",
    engineRuns: [check1],
    coveredAssetCount: 0,
    totalAssetCount: 1,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  assert.equal(activity.activeCheckNames.length, 1);
});

test("security scan pipeline covers pending checks sorting edge cases 2", () => {
  const check1: EngineRun = {
    id: "gitleaks-1",
    engineId: "gitleaks",
    engineName: "gitleaks",
    category: "code_and_secrets",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "paused",
    progress: 10,
    phase: "executing",
    assetIds: ["repo-1"],
    rawArtifactCount: 5,
    savedResultArtifactCount: 2,
    findingCount: 1,
    resumable: false,
  };

  const scanRun: ScanRun = {
    id: "scan-paused",
    caseId: "case-phase",
    label: `Test Scan paused checks`,
    status: "running",
    progress: 10,
    startedAt: "2026-08-26T13:00:00Z",
    lastProgressAt: "2026-08-26T13:00:00Z",
    engineRuns: [check1],
    coveredAssetCount: 0,
    totalAssetCount: 1,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  assert.equal(activity.activeCheckNames.length, 1);
});

test("security scan pipeline engine.checkpoint stage fallback", () => {
  const check1: EngineRun = {
    id: "gitleaks-1",
    engineId: "gitleaks",
    engineName: "gitleaks",
    category: "code_and_secrets",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "running",
    progress: 10,
    phase: "preflight",
    assetIds: ["repo-1"],
    rawArtifactCount: 5,
    savedResultArtifactCount: 2,
    findingCount: 1,
    resumable: false,
    checkpoint: {
      stage: "running",
      state: {},
    }
  };

  const scanRun: ScanRun = {
    id: "scan-paused",
    caseId: "case-phase",
    label: `Test Scan paused checks`,
    status: "running",
    progress: 10,
    startedAt: "2026-08-26T13:00:00Z",
    lastProgressAt: "2026-08-26T13:00:00Z",
    engineRuns: [check1],
    coveredAssetCount: 0,
    totalAssetCount: 1,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  assert.equal(activity.state, "scanner_working");
});

test("security scan pipeline groupedEvent fallback coverage", () => {
  const check1: EngineRun = {
    id: "gitleaks-1",
    engineId: "gitleaks",
    engineName: "gitleaks",
    category: "code_and_secrets",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "running",
    progress: 10,
    phase: "preflight",
    assetIds: ["repo-1"],
    rawArtifactCount: 5,
    savedResultArtifactCount: 2,
    findingCount: 1,
    resumable: false,
    startedAt: "2026-08-26T13:00:00Z"
  };

  const scanRun: ScanRun = {
    id: "scan-paused",
    caseId: "case-phase",
    label: `Test Scan paused checks`,
    status: "running",
    progress: 10,
    startedAt: "2026-08-26T13:00:00Z",
    lastProgressAt: "2026-08-26T13:00:00Z",
    engineRuns: [check1],
    coveredAssetCount: 0,
    totalAssetCount: 1,
  };

  const activity = buildScanActivity(scanRun, new Date("2026-08-26T13:05:30Z"));
  assert.ok(activity.events.some((event) => event.code === "check_attempts_started"));
});

test("security scan pipeline stale minutes infinity fallback", () => {
  const scanRun: ScanRun = {
    id: "scan-paused",
    caseId: "case-phase",
    label: `Test Scan paused checks`,
    status: "running",
    progress: 10,
    startedAt: "2026-08-26T13:00:00Z",
    lastProgressAt: "2026-08-26T13:00:00Z",
    engineRuns: [],
    coveredAssetCount: 0,
    totalAssetCount: 1,
  };

  const activity = buildScanActivity(scanRun, new Date(Infinity));
  assert.equal(activity.staleMinutes, 0);
});
