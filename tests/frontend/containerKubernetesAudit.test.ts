import assert from "node:assert/strict";
import test from "node:test";
import { isExposureObservation, isSecurityFinding } from "../../src/findingClassification.ts";
import { scanRunOverallProgress } from "../../src/scanRunProgress.ts";
import { buildScanActivity } from "../../src/scanActivity.ts";
import type { EngineRun, ScanRun } from "../../src/types.ts";

test("container and Kubernetes audit scanners integrate with unified report aggregation", () => {
  // Simulate a scan run with container vulnerability and Kubernetes configuration findings
  const containerScannerRun: EngineRun = {
    id: "trivy-1",
    engineId: "trivy",
    engineName: "trivy",
    category: "container_and_sbom",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "completed",
    progress: 100,
    phase: "completed",
    assetIds: ["container-image-1"],
    rawArtifactCount: 1,
    savedResultArtifactCount: 1,
    findingCount: 5, // Container vulnerabilities found
    resumable: false,
    finishedAt: "2026-09-01T10:02:00Z"
  };

  const kubernetesLinterRun: EngineRun = {
    id: "kubescape-1",
    engineId: "kubescape",
    engineName: "kubescape",
    category: "cloud_and_infrastructure",
    taskKind: { kind: "catalog_engine" },
    warnings: [],
    status: "completed",
    progress: 100,
    phase: "completed",
    assetIds: ["k8s-manifest-1"],
    rawArtifactCount: 2,
    savedResultArtifactCount: 1,
    findingCount: 3, // Manifest configuration issues found
    resumable: false,
    finishedAt: "2026-09-01T10:05:00Z"
  };

  const scanRun: ScanRun = {
    id: "audit-scan-1",
    caseId: "case-1",
    label: "Container and Kubernetes Audit",
    status: "completed",
    progress: 100,
    startedAt: "2026-09-01T10:00:00Z",
    finishedAt: "2026-09-01T10:05:00Z",
    lastProgressAt: "2026-09-01T10:05:00Z",
    knowledgeDate: "2026-09-01T09:00:00Z",
    engineRuns: [containerScannerRun, kubernetesLinterRun],
    coveredAssetCount: 2,
    totalAssetCount: 2,
  };

  // 1. Assert unified report aggregation through overall progress
  assert.equal(scanRunOverallProgress(scanRun), 100, "Overall progress should aggregate to 100%");

  // 2. Classify findings for both scanners
  // Container vulnerabilities (Trivy)
  assert.equal(
    isSecurityFinding({ severityBasisCode: "cve" }),
    true,
    "CVEs in container images should be classified as security findings"
  );

  // Kubernetes configuration (Kubescape)
  assert.equal(
    isSecurityFinding({ severityBasisCode: "misconfiguration" }),
    true,
    "Kubernetes manifest misconfigurations should be classified as security findings"
  );

  // 3. Build and assert the unified scan activity report
  const activity = buildScanActivity(scanRun, new Date("2026-09-01T10:05:30Z"));

  assert.equal(activity.state, "completed", "Unified activity state should be completed");
  assert.ok(activity.events.some((event) => event.code === "run_completed"), "Activity should include a unified run_completed event");
});
