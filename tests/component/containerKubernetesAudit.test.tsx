import { cleanup, render, screen, fireEvent } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { FindingsPage } from "../../src/pages/FindingsPage";
import { CasesPage } from "../../src/pages/CasesPage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import type { Finding, ScanRun } from "../../src/types";

// This file validates the Results page properly processes and displays container
// (e.g. Trivy) and Kubernetes audit (e.g. Kubescape) scan reports.

const mockRun: ScanRun = {
  id: "run-1",
  caseId: "case-1",
  label: "Audit test",
  status: "completed",
  progress: 100,
  startedAt: "2026-09-01T10:00:00Z",
  finishedAt: "2026-09-01T10:05:00Z",
  engineRuns: [
    {
      id: "trivy-1",
      engineId: "trivy",
      engineName: "trivy",
      category: "container_and_sbom",
      taskKind: { kind: "catalog_engine" },
      warnings: [],
      status: "completed",
      progress: 100,
      phase: "completed",
      findingCount: 1,
      rawArtifactCount: 1,
      savedResultArtifactCount: 1,
      resumable: false,
    },
    {
      id: "kubescape-1",
      engineId: "kubescape",
      engineName: "kubescape",
      category: "cloud_and_infrastructure",
      taskKind: { kind: "catalog_engine" },
      warnings: [],
      status: "completed",
      progress: 100,
      phase: "completed",
      findingCount: 1,
      rawArtifactCount: 1,
      savedResultArtifactCount: 1,
      resumable: false,
    },
  ],
  coveredAssetCount: 2,
  totalAssetCount: 2,
};

const mockFindings: Finding[] = [
  {
    id: "vuln-1",
    fingerprint: "fingerprint-vuln-1",
    title: "CVE-2026-0001",
    summary: "A simulated high-risk container vulnerability.",
    impact: "Container can be compromised.",
    recommendation: "Update the base image.",
    expertType: "Security engineer",
    severity: "high",
    nativeSeverity: "High",
    severityBasisCode: "cve",
    priority: 1,
    sourceEngine: "trivy",
    engineRunId: "trivy-1",
    tags: [],
    assetId: "container-image-1",
    assetName: "alpine:latest",
    controls: [],
    coordinates: {
      containerImage: "alpine:latest",
    },
    evidence: [{
        sourceEngine: "trivy",
        engineRunId: "trivy-1",
        location: "alpine:latest",
        summary: "A simulated high-risk container vulnerability.",
        rawTarget: "alpine:latest"
    }],
    officialReferences: [],
    frameworkReferences: [],
    createdAt: "2026-09-01T10:05:00Z",
    firstSeenAt: "2026-09-01T10:05:00Z",
    lastSeenAt: "2026-09-01T10:05:00Z",
  },
  {
    id: "config-1",
    fingerprint: "fingerprint-config-1",
    title: "Container runs as root",
    summary: "A simulated Kubernetes manifest misconfiguration.",
    impact: "Privilege escalation is possible.",
    recommendation: "Run as non-root user.",
    expertType: "Security engineer",
    severity: "medium",
    nativeSeverity: "Medium",
    severityBasisCode: "misconfiguration",
    priority: 2,
    sourceEngine: "kubescape",
    engineRunId: "kubescape-1",
    tags: [],
    assetId: "k8s-manifest-1",
    assetName: "Deployment/nginx",
    controls: [],
    coordinates: {
      kubernetesResource: "Deployment/nginx",
    },
    evidence: [{
        sourceEngine: "kubescape",
        engineRunId: "kubescape-1",
        location: "Deployment/nginx",
        summary: "A simulated Kubernetes manifest misconfiguration.",
        rawTarget: "Deployment/nginx"
    }],
    officialReferences: [],
    frameworkReferences: [],
    createdAt: "2026-09-01T10:05:00Z",
    firstSeenAt: "2026-09-01T10:05:00Z",
    lastSeenAt: "2026-09-01T10:05:00Z",
  }
];

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("findings from container and Kubernetes audit scanners are rendered accurately", () => {
  const { container } = render(
    <I18nProvider>
      <FindingsPage
        findings={mockFindings}
        findingGroups={[]}
        findingGroupEvents={[]}
        runs={[mockRun]}
        workflowEvents={[]}
        busy={false}
        onUpdateWorkflow={() => Promise.resolve(true)}
        onGroupFindings={() => Promise.resolve(true)}
        onUngroupFindings={() => Promise.resolve()}
        onOpenCoverage={() => {}}
        onOpenProgress={() => {}}
        onOpenExport={() => {}}
      />
    </I18nProvider>
  );

  // We should be able to see the titles of both findings.
  const findingRows = container.querySelectorAll(".finding-row");
  expect(findingRows.length).toBe(2);

  const textContent = Array.from(findingRows).map(row => row.textContent);
  expect(textContent.some(text => text?.includes("CVE-2026-0001"))).toBe(true);
  expect(textContent.some(text => text?.includes("Container runs as root"))).toBe(true);

  // Click on the Trivy finding to view evidence
  const trivyRow = Array.from(findingRows).find(row => row.textContent?.includes("CVE-2026-0001"));
  if (!trivyRow) throw new Error("Trivy finding row did not render");
  fireEvent.click(trivyRow);

  // Verify the evidence card is showing the right engine
  const evidenceItem = container.querySelector(".evidence-item");
  if (!evidenceItem) throw new Error("evidence card did not render");
  expect(evidenceItem.textContent?.toLowerCase()).toContain("trivy");
});

test("container and kubernetes audit scan form submission renders properly", async () => {
  const { container } = render(
    <I18nProvider>
      <CasesPage
        cases={[]}
        archived={[]}
        runs={[]}
        pendingEvents={[]}
        onRunAction={() => Promise.resolve(true)}
        onRestoreCase={() => Promise.resolve(true)}
        onDeleteCase={() => Promise.resolve(true)}
        onCreateCase={() => Promise.resolve({ ok: true, caseId: "case-1" })}
        onArchiveCase={() => Promise.resolve(true)}
        onShowBrowserPreview={() => {}}
      />
    </I18nProvider>
  );
});
