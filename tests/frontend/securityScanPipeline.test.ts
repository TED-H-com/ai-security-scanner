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
