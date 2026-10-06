import assert from "node:assert/strict";
import test from "node:test";

import { readFileSync } from "node:fs";
import { build } from "esbuild";

const adapterSource = readFileSync(
  new URL("../../src/services/nativeAdapter.ts", import.meta.url),
  "utf8",
);
const scannerSource = readFileSync(
  new URL("../../src/services/scanner.ts", import.meta.url),
  "utf8",
);

const bundled = await build({
  stdin: {
    contents: 'export { adaptBeginnerMasterReport, adaptDeclaredHostScanMetadata, adaptDeclaredNetworkServiceMetadata, adaptDeclaredWebServiceMetadata, adaptLocalNetworkCandidateInventory, adaptManagedRuntimeSetupStatus, adaptNativeCase, adaptNativeExport, adaptNativeExportPreview, adaptNativeManifest, adaptNativeProviderBinding, adaptNativeSnapshot, exportRunFileIdentity } from "./src/services/nativeAdapter.ts"; export { caseDisplayLabels } from "./src/caseIdentityPresentation.ts";',
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "native-adapter-test-entry.ts",
  },
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const source = bundled.outputFiles[0]?.text;
assert.ok(source, "the native adapter test bundle should contain JavaScript");
const {
  adaptBeginnerMasterReport,
  adaptDeclaredHostScanMetadata,
  adaptDeclaredNetworkServiceMetadata,
  adaptDeclaredWebServiceMetadata,
  adaptLocalNetworkCandidateInventory,
  adaptManagedRuntimeSetupStatus,
  adaptNativeCase,
  adaptNativeExport,
  adaptNativeExportPreview,
  adaptNativeManifest,
  adaptNativeProviderBinding,
  adaptNativeSnapshot,
  caseDisplayLabels,
  exportRunFileIdentity,
} = await import(
  `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`
);

test("native report carries presentation groups while retaining original finding IDs", () => {
  const group = {group_id:"group-1",rule_version:"aws-related-checks-1",kind:"iam_policy_permissions",
    title:"Review IAM policy permissions: Policy 1",target_asset_id:"asset-status",
    representative_finding_id:"finding-high",finding_ids:["finding-low","finding-high"],policy_name:"Policy 1"};
  const report = adaptBeginnerMasterReport({...beginnerStatusReportFixture(),problem_groups:[group]});
  assert.deepEqual(report.problemGroups,[{groupId:"group-1",ruleVersion:"aws-related-checks-1",kind:"iam_policy_permissions",
    title:group.title,targetAssetId:"asset-status",representativeFindingId:"finding-high",
    findingIds:["finding-low","finding-high"],policyName:"Policy 1"}]);
  assert.deepEqual(adaptBeginnerMasterReport(beginnerStatusReportFixture()).problemGroups,[]);
});
const nativeExportPreview = (locale: string) => ({
  case_id: "case-1",
  run_id: "run-1",
  locale,
  format: "html",
  redaction_profile: "standard",
  include_raw_evidence: false,
  data_source_count: 1,
  coverage_entry_count: 1,
  asset_count: 1,
  candidate_asset_count: 0,
  canonical_finding_count: 0,
  selected_run_finding_count: 0,
  evidence_index_count: 0,
  selected_run_evidence_count: 0,
  scan_run_count: 1,
  selected_engine_run_count: 1,
  external_scope_grant_count: 0,
  incomplete_engine_run_count: 0,
  not_executed_engine_run_count: 0,
  unknown_source_count: 0,
  connected_no_asset_count: 0,
  raw_artifact_count: 0,
  raw_artifacts_included: 0,
  raw_artifacts_omitted: 0,
  sensitive_raw_artifacts_omitted: 0,
  sensitive_data_warning: "warning",
  coverage_manifest_included: false,
});

test("native export previews preserve only the closed report locale coordinate", () => {
  assert.equal(adaptNativeExportPreview(nativeExportPreview("en")).locale, "en");
  assert.equal(adaptNativeExportPreview(nativeExportPreview("zh-Hant")).locale, "zh-Hant");
  assert.throws(
    () => adaptNativeExportPreview(nativeExportPreview("fr")),
    /Unsupported report locale/u,
  );
});

const nativeExport = (signature: unknown) => adaptNativeExport({
  id: "export-1",
  case_id: "case-1",
  run_id: "run-history-2",
  created_at: "2026-09-01T01:02:03Z",
  format: "html",
  path: "C:\\reports\\report.html",
  sha256: "abc123",
  signature,
  redaction_profile: "standard",
});

test("native exports preserve their immutable scan-run coordinate", () => {
  const adapted = nativeExport(null);

  assert.equal(adapted.caseId, "case-1");
  assert.equal(adapted.runId, "run-history-2");
  assert.equal(adapted.fileName, "report.html");
});

test("export signatures claim local integrity only for the stored Ed25519 encoding", () => {
  const stored = `${"A".repeat(86)}==`;
  assert.equal(nativeExport(stored).signatureState, "local_integrity");
  assert.equal(nativeExport(null).signatureState, "unsigned");
  for (const signature of ["", " ", "signed", "true", 1, stored.slice(0, -1), ` ${stored}`]) {
    assert.equal(nativeExport(signature).signatureState, "unsigned", String(signature));
  }
});

test("suggested export filenames use a stable readable sequence and opaque short identity", () => {
  const untrustedId = "../../private/person@example.com?token=secret";
  const canonical = exportRunFileIdentity({ id: untrustedId, sequence: 7 });
  const repeated = exportRunFileIdentity({ id: untrustedId, sequence: 7 });
  const different = exportRunFileIdentity({ id: `${untrustedId}-other`, sequence: 7 });
  const legacy = exportRunFileIdentity({ id: untrustedId });

  assert.match(canonical, /^scan-7-[0-9a-f]{8}$/u);
  assert.equal(repeated, canonical);
  assert.notEqual(different, canonical);
  assert.match(legacy, /^run-[0-9a-f]{8}$/u);
  assert.doesNotMatch(`${canonical} ${legacy}`, /private|person|example|token|secret|\.\./u);
});

const localCandidate = (overrides: Record<string, unknown> = {}) => ({
  id: `local-ipv4-${"a".repeat(64)}`,
  target: "192.168.50.0/24",
  kind: "local_ipv4_subnet",
  useCase: "internal_it_environment",
  internetExposure: "internal",
  addressCount: 256,
  requiresConfirmation: true,
  ...overrides,
});

test("beginner report adapter preserves the backend's run-bound coverage semantics", () => {
  const report = adaptBeginnerMasterReport({
    schema_version: "1.1.0",
    case_id: "case-1",
    run_id: "run-1",
    project_title: "Local check",
    state: {
      summary: "partial",
      lifecycle: "final",
      last_durable_update: "2026-08-30T12:00:03Z",
      explanation: "Partial results are available.",
    },
    requested: {
      targets: [{
        asset_id: "asset-1",
        label: "127.0.0.1:9001",
        asset_kind: "web_service",
        label_availability: "recorded",
        asset_kind_availability: "recorded",
      }],
      stage: {
        value: "quick_discovery",
        availability: "recorded",
        explanation: "Frozen native task.",
      },
      limits: [{ name: "connection timeout", value: "3000 ms", source: "frozen_task_contract" }],
      requested_check_ids: ["localhost_tcp_endpoint"],
      request_outcome_code: null,
      automatic_reductions: [],
      reductions_availability: "recorded",
      unavailable_dimensions: [],
    },
    actual: {
      observed_from: "2026-08-30T12:00:00Z",
      observed_until: "2026-08-30T12:00:03Z",
      checks: [{
        task_id: "task-1",
        check_id: "localhost_tcp_endpoint",
        result_kind: "connectivity",
        target_asset_ids: ["asset-1"],
        status: "tested_partial",
        started_at: "2026-08-30T12:00:00Z",
        finished_at: "2026-08-30T12:00:03Z",
        tested_dimensions: [{
          dimension: "TCP reachability",
          value: "127.0.0.1:9001",
          observation: "The connection timed out.",
          observed_at: "2026-08-30T12:00:03Z",
        }],
      }],
      unavailable_dimensions: [],
    },
    coverage_gaps: [{
      kind: "timed_out",
      task_id: "task-1",
      target_asset_ids: ["asset-1"],
      dimension: "TCP reachability",
      reason: "The bounded attempt timed out.",
      next_action_code: "start_expected_service_and_retry",
      next_action: "Start the service and retry.",
    }],
    coverage_counts: {
      tested_complete: 0,
      tested_partial: 1,
      failed: 0,
      timed_out: 1,
      cancelled: 0,
      not_tested: 0,
      excluded: 0,
      truncated: 0,
      unavailable: 0,
    },
    inventory: {
      total: 3,
      counts: {
        services: 1,
        software_components: 0,
        cloud_resources: 0,
        workflow_components: 1,
        workflow_relationships: 1,
      },
      asset_ids: ["asset-1"],
      representative_sample: [{
        kind: "service",
        asset_id: "asset-1",
        endpoint: "127.0.0.1",
        port: 9001,
        transport: "tcp",
        schemes: ["http"],
        http_statuses: [200],
        tls_observations: [false],
        sources: [{
          observation_id: "inventory-1",
          engine_id: "httpx",
          engine_run_id: "task-1",
          artifact_id: "artifact-inventory-1",
          artifact_sha256: "b".repeat(64),
          pointer: "/items/0",
          observed_at: "2026-08-30T12:00:03Z",
        }],
      }],
      items: [{
        kind: "service",
        asset_id: "asset-1",
        endpoint: "127.0.0.1",
        port: 9001,
        transport: "tcp",
        schemes: ["http"],
        http_statuses: [200],
        tls_observations: [false],
        sources: [{
          observation_id: "inventory-1",
          engine_id: "httpx",
          engine_run_id: "task-1",
          artifact_id: "artifact-inventory-1",
          artifact_sha256: "b".repeat(64),
          pointer: "/items/0",
          observed_at: "2026-08-30T12:00:03Z",
        }],
      }, {
        kind: "workflow_component",
        asset_id: "asset-1",
        component_type: "agent",
        name: "Assistant",
        model: "local-model",
        is_guardrail: false,
        sources: [{
          observation_id: "inventory-2",
          engine_id: "agentic-radar",
          engine_run_id: "task-2",
          artifact_id: "artifact-inventory-2",
          artifact_sha256: "c".repeat(64),
          pointer: "/graph/agents/0",
          observed_at: "2026-08-30T12:00:04Z",
        }],
      }, {
        kind: "workflow_relationship",
        asset_id: "asset-1",
        source: "START",
        target: "Assistant",
        condition: null,
        sources: [{
          observation_id: "inventory-3",
          engine_id: "agentic-radar",
          engine_run_id: "task-2",
          artifact_id: "artifact-inventory-2",
          artifact_sha256: "c".repeat(64),
          pointer: "/graph/edges/0",
          observed_at: "2026-08-30T12:00:04Z",
        }],
      }],
      by_asset: [{
        asset_id: "asset-1",
        total: 3,
        counts: {
          services: 1,
          software_components: 0,
          cloud_resources: 0,
          workflow_components: 1,
          workflow_relationships: 1,
        },
        representative_sample: [],
      }],
    },
    findings: [{
      finding_id: "finding-1",
      fingerprint: "fp-1",
      snapshot_source: "frozen_selected_run",
      title: "Example problem",
      plain_language_risk: "Risk",
      possible_impact: "Impact",
      severity: "high",
      confidence: "medium",
      priority: 1,
      priority_reasons: ["Reachable service"],
      target_asset_ids: ["asset-1"],
      next_step: "Review it.",
      recommended_expert_type: "IT administrator",
      evidence_references: [{
        evidence_id: "evidence-1",
        engine_id: "cloudsplaining",
        details_frozen: true,
        source_rule: "upstream-rule-42",
        scanner_details: {
          description: "Scanner description",
          remediation: "Scanner remediation",
          installed_version: "1.0.0",
          fixed_version: "1.0.1",
          aws_iam_policy: {
            policy_source: "customer_managed",
            policy_name: "BillingReadPolicy",
            finding_identity: "PrivilegeEscalation",
            actions: ["iam:PassRole", "sts:AssumeRole"],
            actions_complete: true,
            attached_to: {
              roles: ["ApplicationRole"],
              groups: ["BillingOperators"],
              users: [],
              complete: false,
            },
          },
        },
        summary: "Frozen evidence summary",
        kind: "observation",
        engine_run_id: "task-1",
        artifact_id: "artifact-1",
        redacted: true,
        artifact_sha256: "a".repeat(64),
        observed_at: "2026-08-30T12:00:03Z",
        location: "src/config.ts:42",
        pointer: "/records/0",
      }, {
        evidence_id: "evidence-malformed-iam",
        engine_id: "cloudsplaining",
        details_frozen: true,
        source_rule: "PrivilegeEscalation",
        scanner_details: {
          description: "Sibling frozen description",
          aws_iam_policy: {
            policy_source: "aws_managed",
            policy_name: "AdministratorAccess",
            finding_identity: "PrivilegeEscalation",
            actions: ["iam:PassRole"],
            attached_to: {
              roles: [42],
              groups: [],
              users: [],
              complete: true,
            },
          },
        },
        artifact_sha256: "b".repeat(64),
        observed_at: "2026-08-30T12:00:03Z",
      }],
      official_references: ["https://example.test/frozen-rule"],
      framework_references: [{
        framework: "AIDEFEND",
        framework_version: "1.0",
        control_id: "AIDEFEND-01",
        title: "Reviewed control",
        relationship: "related",
        rationale: "Reviewed mapping rationale.",
        mapping_version: "2026-09-15.1",
        mapping_provenance: {
          mapping_version: "2026-09-15.1",
          reviewed_at: "2026-09-15",
          review_process: "two-person review",
          catalog_sha256: "d".repeat(64),
        },
      }],
    }],
    finding_groups: [{
      group_id: "group-1",
      presentation_scope: "current_case_presentation",
      title: "Related observations",
      rationale: "Review the shared path together.",
      actor: "Human reviewer",
      created_at: "2026-08-30T12:00:04Z",
      members: [{
        finding_id: "finding-1",
        observed_in_selected_run: true,
      }, {
        finding_id: "finding-history",
        observed_in_selected_run: false,
      }],
    }],
    next_steps: [{
      priority: 1,
      code: "start_expected_service_and_retry",
      action: "Start the service and retry.",
      reason: "The endpoint timed out.",
      finding_id: null,
      task_id: "task-1",
      recommended_expert_type: "IT administrator",
      family: null,
      unattributed: null,
      also_resolves: [],
    }, {
      priority: 2,
      code: "review_finding",
      action: "Review the shared finding evidence.",
      reason: "The same action covers two findings.",
      finding_id: "finding-1",
      task_id: null,
      recommended_expert_type: "Security reviewer",
      family: "network_exposure",
      unattributed: null,
      also_resolves: ["finding-history"],
    }],
    technical_details: {
      collapsed_by_default: true,
      tasks: [{
        task_id: "task-1",
        target_asset_ids: ["asset-1"],
        status: "partially_completed",
        phase: "completed",
        progress_percent: 100,
        started_at: "2026-08-30T12:00:00Z",
        finished_at: "2026-08-30T12:00:03Z",
        exit_code: 0,
        cleanup_removed: true,
        cleanup_detail: {
          availability: "recorded",
          value: "Disposable runtime removed.",
          explanation: "Cleanup outcome was recorded.",
        },
        error_code: null,
        redacted_scanner_message: {
          availability: "recorded",
          value: "The bounded connection timed out.",
          explanation: "Redacted scanner message was recorded.",
        },
        redacted_diagnostic_log: {
          availability: "unavailable",
          value: null,
          explanation: "No diagnostic log was retained.",
        },
        evidence_sha256: ["a".repeat(64)],
        execution: {
          kind: "built_in_localhost_tcp",
          endpoint: "127.0.0.1:9001",
          timeout_ms: 3000,
          payload_bytes: 0,
          observation: {
            outcome: "timed_out",
            observed_at: "2026-08-30T12:00:03Z",
          },
          contract: "connect_only_no_payload",
        },
      }],
    },
    framework_notice: {
      non_certification: "Not certification.",
      aidefend_mapping_status: "Independent mapping.",
    },
    data_quality_warnings: [],
  });

  assert.equal(report.state.summary, "partial");
  assert.equal(report.requested.targets[0]?.label, "127.0.0.1:9001");
  assert.equal(report.actual.checks[0]?.status, "tested_partial");
  assert.equal(report.actual.checks[0]?.resultKind, "connectivity");
  assert.equal(report.technicalDetails.tasks[0]?.status, "partial");
  assert.deepEqual(report.technicalDetails.tasks[0]?.execution, {
    kind: "built_in_localhost_tcp",
    endpoint: "127.0.0.1:9001",
    timeoutMs: 3000,
    payloadBytes: 0,
    observation: {
      outcome: "timed_out",
      observedAt: "2026-08-30T12:00:03Z",
    },
    contract: "connect_only_no_payload",
  });
  assert.deepEqual(report.technicalDetails.tasks[0]?.cleanupDetail, {
    availability: "recorded",
    value: "Disposable runtime removed.",
    explanation: "Cleanup outcome was recorded.",
  });
  assert.deepEqual(report.technicalDetails.tasks[0]?.redactedScannerMessage, {
    availability: "recorded",
    value: "The bounded connection timed out.",
    explanation: "Redacted scanner message was recorded.",
  });
  assert.deepEqual(report.technicalDetails.tasks[0]?.redactedDiagnosticLog, {
    availability: "unavailable",
    value: undefined,
    explanation: "No diagnostic log was retained.",
  });
  assert.deepEqual(report.inventory?.counts, {
    services: 1,
    softwareComponents: 0,
    cloudResources: 0,
    workflowComponents: 1,
    workflowRelationships: 1,
  });
  assert.deepEqual(report.inventory?.items[0], {
    kind: "service",
    assetId: "asset-1",
    endpoint: "127.0.0.1",
    port: 9001,
    transport: "tcp",
    schemes: ["http"],
    httpStatuses: [200],
    tlsObservations: [false],
    sources: [{
      observationId: "inventory-1",
      engineId: "httpx",
      engineRunId: "task-1",
      artifactId: "artifact-inventory-1",
      artifactSha256: "b".repeat(64),
      pointer: "/items/0",
      observedAt: "2026-08-30T12:00:03Z",
    }],
  });
  assert.deepEqual(report.inventory?.items[1], {
    kind: "workflow_component",
    assetId: "asset-1",
    componentType: "agent",
    name: "Assistant",
    model: "local-model",
    isGuardrail: false,
    sources: [{
      observationId: "inventory-2",
      engineId: "agentic-radar",
      engineRunId: "task-2",
      artifactId: "artifact-inventory-2",
      artifactSha256: "c".repeat(64),
      pointer: "/graph/agents/0",
      observedAt: "2026-08-30T12:00:04Z",
    }],
  });
  assert.deepEqual(report.inventory?.items[2], {
    kind: "workflow_relationship",
    assetId: "asset-1",
    source: "START",
    target: "Assistant",
    condition: undefined,
    sources: [{
      observationId: "inventory-3",
      engineId: "agentic-radar",
      engineRunId: "task-2",
      artifactId: "artifact-inventory-2",
      artifactSha256: "c".repeat(64),
      pointer: "/graph/edges/0",
      observedAt: "2026-08-30T12:00:04Z",
    }],
  });
  assert.equal(report.coverageGaps[0]?.nextActionCode, "start_expected_service_and_retry");
  assert.equal(report.findings[0]?.findingId, "finding-1");
  assert.equal(report.findings[0]?.evidenceReferences[0]?.location, "src/config.ts:42");
  assert.equal(report.findings[0]?.evidenceReferences[0]?.sourceRule, "upstream-rule-42");
  assert.deepEqual(report.findings[0]?.evidenceReferences[0], {
    evidenceId: "evidence-1",
    engineId: "cloudsplaining",
    detailsFrozen: true,
    sourceRule: "upstream-rule-42",
    scannerDetails: {
      description: "Scanner description",
      remediation: "Scanner remediation",
      installedVersion: "1.0.0",
      fixedVersion: "1.0.1",
      awsIamPolicy: {
        policySource: "customer_managed",
        policyName: "BillingReadPolicy",
        findingIdentity: "PrivilegeEscalation",
        actions: ["iam:PassRole", "sts:AssumeRole"],
        actionsComplete: true,
        attachedTo: {
          roles: ["ApplicationRole"],
          groups: ["BillingOperators"],
          users: [],
          complete: false,
        },
      },
    },
    summary: "Frozen evidence summary",
    kind: "observation",
    engineRunId: "task-1",
    artifactId: "artifact-1",
    redacted: true,
    artifactSha256: "a".repeat(64),
    observedAt: "2026-08-30T12:00:03Z",
    location: "src/config.ts:42",
    pointer: "/records/0",
  });
  assert.deepEqual(report.findings[0]?.officialReferences, ["https://example.test/frozen-rule"]);
  assert.equal(
    report.findings[0]?.evidenceReferences[1]?.scannerDetails?.description,
    "Sibling frozen description",
  );
  assert.equal(
    report.findings[0]?.evidenceReferences[1]?.scannerDetails?.awsIamPolicy,
    undefined,
  );
  assert.equal(report.nextSteps[0]?.taskId, "task-1");
  assert.deepEqual(report.nextSteps[1], {
    priority: 2,
    code: "review_finding",
    action: "Review the shared finding evidence.",
    reason: "The same action covers two findings.",
    findingId: "finding-1",
    taskId: undefined,
    recommendedExpertType: "Security reviewer",
    family: "network_exposure",
    unattributed: undefined,
    alsoResolves: ["finding-history"],
    sharedFix: undefined,
  });
  assert.deepEqual(report.findingGroups, [{
    groupId: "group-1",
    presentationScope: "current_case_presentation",
    title: "Related observations",
    rationale: "Review the shared path together.",
    actor: "Human reviewer",
    createdAt: "2026-08-30T12:00:04Z",
    members: [{
      findingId: "finding-1",
      observedInSelectedRun: true,
    }, {
      findingId: "finding-history",
      observedInSelectedRun: false,
    }],
  }]);
  assert.deepEqual(report.findings[0]?.frameworkReferences[0]?.mappingProvenance, {
    mappingVersion: "2026-09-15.1",
    reviewedAt: "2026-09-15",
    reviewProcess: "two-person review",
    catalogSha256: "d".repeat(64),
  });
});

const beginnerStatusReportFixture = (overrides: {
  resultKind?: unknown;
  gapKind?: unknown;
  gapClass?: unknown;
} = {}) => ({
  schema_version: "1.1.0",
  case_id: "case-status",
  run_id: "run-status",
  project_title: "Status boundary",
  state: {
    summary: "partial",
    lifecycle: "final",
    last_durable_update: "2026-09-15T12:00:00Z",
    explanation: "Some work needs attention.",
  },
  requested: {
    targets: [{
      asset_id: "asset-status",
      label: "Status target",
      asset_kind: "repository",
      label_availability: "recorded",
      asset_kind_availability: "recorded",
    }],
    stage: { value: "deep", availability: "recorded", explanation: "Recorded before execution." },
    limits: [],
    requested_check_ids: ["status-check"],
    request_outcome_code: null,
    automatic_reductions: [],
    reductions_availability: "recorded",
    unavailable_dimensions: [],
  },
  actual: {
    observed_from: "2026-09-15T11:59:00Z",
    observed_until: "2026-09-15T12:00:00Z",
    checks: [{
      task_id: "task-status",
      check_id: "status-check",
      result_kind: overrides.resultKind,
      target_asset_ids: ["asset-status"],
      status: "tested_complete",
      started_at: "2026-09-15T11:59:00Z",
      finished_at: "2026-09-15T12:00:00Z",
      tested_dimensions: [],
    }],
    unavailable_dimensions: [],
  },
  coverage_gaps: [{
    kind: Object.prototype.hasOwnProperty.call(overrides, "gapKind") ? overrides.gapKind : "failed",
    ...(Object.prototype.hasOwnProperty.call(overrides, "gapClass")
      ? { class: overrides.gapClass }
      : {}),
    task_id: "task-status",
    target_asset_ids: ["asset-status"],
    dimension: "Status boundary",
    reason: "The status needs attention.",
    next_action_code: "review_coverage",
    next_action: "Review coverage.",
  }],
  coverage_counts: {
    tested_complete: 1,
    tested_partial: 0,
    failed: 1,
    timed_out: 0,
    cancelled: 0,
    not_tested: 0,
    excluded: 0,
    truncated: 0,
    unavailable: 0,
  },
  findings: [],
  next_steps: [],
  technical_details: { collapsed_by_default: true, tasks: [] },
  framework_notice: { non_certification: "Not certification.", aidefend_mapping_status: "Not mapped." },
  data_quality_warnings: [],
});

test("shared_fix is kept only when it is exactly true", () => {
  const step = (sharedFix: boolean | undefined, include: boolean) => ({
    priority: 1,
    code: "review_finding" as const,
    action: "Remove iam:PassRole from policy Admin.",
    reason: "The policy grants PassRole.",
    finding_id: "finding-1",
    task_id: null,
    recommended_expert_type: null,
    family: "cloud_identity",
    unattributed: null,
    also_resolves: [] as string[],
    ...(include ? { shared_fix: sharedFix } : {}),
  });
  const adapted = (sharedFix: boolean | undefined, include: boolean) =>
    adaptBeginnerMasterReport({
      ...beginnerStatusReportFixture(),
      next_steps: [step(sharedFix, include)],
    }).nextSteps[0]?.sharedFix;

  assert.equal(adapted(true, true), true);
  assert.equal(adapted(false, true), undefined);
  assert.equal(adapted(undefined, false), undefined);
});

test("scanner benchmarks and lowered password-policy groups keep only exact values", () => {
  const benchmarks = [
    { name: " CIS Amazon Web Services Foundations ", version: " 1.2.0 ", reference: " 1.5 " },
    { name: "", version: "1.0.0", reference: "1.1" },
    { name: "A", version: "   ", reference: "r" },
    { name: "A", version: 1, reference: "r" },
    null,
    "nope",
    { name: "B", version: "2", reference: "r3" },
  ];
  const evidence = (scannerDetails: Record<string, unknown> | null | undefined) => ({
    evidence_id: "evidence-uppercase",
    engine_id: "scoutsuite",
    details_frozen: true,
    source_rule: "iam-password-policy-uppercase",
    ...(scannerDetails === undefined ? {} : { scanner_details: scannerDetails }),
    summary: "ScoutSuite reported the password policy.",
    artifact_sha256: "a".repeat(64),
    observed_at: "2026-10-06T12:00:00Z",
  });
  const finding = (scannerDetails: Record<string, unknown> | null | undefined) => ({
    finding_id: "finding-uppercase",
    fingerprint: "fp-uppercase",
    snapshot_source: "frozen_selected_run",
    title: "Password Policy Lacks Uppercase Requirement",
    plain_language_risk: "Risk",
    possible_impact: "Impact",
    severity: "high",
    confidence: "medium",
    priority: 35,
    priority_reasons: [],
    target_asset_ids: ["asset-status"],
    next_step: "Review it.",
    recommended_expert_type: "Cloud identity specialist",
    evidence_references: [evidence(scannerDetails)],
    framework_references: [],
  });
  const group = (lowerPriorityMembers: unknown, include: boolean) => ({
    group_id: "group-password",
    rule_version: "aws-related-checks-1",
    kind: "iam_password_policy" as const,
    title: "IAM password policy needs attention",
    target_asset_id: "asset-status",
    representative_finding_id: "finding-uppercase",
    finding_ids: ["finding-uppercase"],
    policy_name: null,
    ...(include ? { lower_priority_members: lowerPriorityMembers } : {}),
  });
  const adapted = (
    scannerDetails: Record<string, unknown> | null | undefined,
    lowerPriorityMembers: unknown,
    includeGroupFlag: boolean,
  ) => adaptBeginnerMasterReport({
    ...beginnerStatusReportFixture(),
    findings: [finding(scannerDetails)],
    problem_groups: [group(lowerPriorityMembers, includeGroupFlag)],
  });

  const kept = adapted({ description: "Uppercase is not required.", benchmarks }, "partial", true);
  assert.deepEqual(kept.findings[0]?.evidenceReferences[0]?.scannerDetails?.benchmarks, [
    { name: "CIS Amazon Web Services Foundations", version: "1.2.0", reference: "1.5" },
    { name: "B", version: "2", reference: "r3" },
  ]);
  assert.equal(kept.findings[0]?.evidenceReferences[0]?.scannerDetails?.description, "Uppercase is not required.");
  assert.equal(kept.problemGroups?.[0]?.lowerPriorityMembers, "partial");

  const malformed = adapted({
    description: "The description remains.",
    benchmarks: [{ name: " ", version: "1", reference: "r" }, { name: 1, version: "1", reference: "r" }],
  }, "all", true);
  assert.equal(malformed.findings[0]?.evidenceReferences[0]?.scannerDetails?.benchmarks, undefined);
  assert.equal(Object.hasOwn(malformed.findings[0]?.evidenceReferences[0]?.scannerDetails ?? {}, "benchmarks"), false);
  assert.equal(malformed.findings[0]?.evidenceReferences[0]?.scannerDetails?.description, "The description remains.");
  assert.equal(malformed.problemGroups?.[0]?.lowerPriorityMembers, "all");

  for (const scannerDetails of [
    { description: "No benchmark list." },
    { description: "Empty benchmark list.", benchmarks: [] },
    null,
  ]) {
    const report = adapted(scannerDetails, "some", true);
    assert.equal(report.findings[0]?.evidenceReferences[0]?.scannerDetails?.benchmarks, undefined);
    assert.equal(report.problemGroups?.[0]?.lowerPriorityMembers, undefined);
    assert.equal(Object.hasOwn(report.problemGroups?.[0] ?? {}, "lowerPriorityMembers"), false);
  }

  const absentFlag = adapted({ description: "No flag." }, undefined, false);
  assert.equal(absentFlag.problemGroups?.[0]?.lowerPriorityMembers, undefined);
  assert.equal(Object.hasOwn(absentFlag.problemGroups?.[0] ?? {}, "lowerPriorityMembers"), false);

  const workspace = adaptNativeCase(platformCaseFixture({
    findings: [{
      id: "finding-uppercase",
      case_id: "case-platforms-1",
      first_seen_run_id: "run-1",
      last_seen_run_id: "run-1",
      fingerprint: "fp-uppercase",
      title: "Password Policy Lacks Uppercase Requirement",
      plain_language_summary: "Review this scanner observation.",
      possible_impact: "Impact",
      severity: "high",
      confidence: "medium",
      priority: 35,
      priority_reasons: [],
      asset_ids: ["repository-asset"],
      evidence: [{
        id: "evidence-uppercase",
        finding_id: "finding-uppercase",
        run_id: "run-1",
        engine_run_id: "task-scout",
        kind: "configuration",
        engine_id: "scoutsuite",
        source_rule: "iam-password-policy-uppercase",
        scanner_details: { benchmarks },
        observed_at: "2026-10-06T12:00:00Z",
        summary: "ScoutSuite reported the password policy.",
        artifact_id: "artifact-1",
        artifact_sha256: "a".repeat(64),
        pointer: null,
        redacted: false,
      }],
      control_references: [],
      recommendation: "Review the password policy.",
      official_references: [],
      recommended_expert_type: "Cloud identity specialist",
      status: "unreviewed",
      tags: [],
    }],
  }));
  assert.deepEqual(workspace.findings[0]?.evidence[0]?.scannerDetails?.benchmarks, [
    { name: "CIS Amazon Web Services Foundations", version: "1.2.0", reference: "1.5" },
    { name: "B", version: "2", reference: "r3" },
  ]);
});

test("frozen evidence redaction claims only the exact boolean and preserves absence", () => {
  const redactedFor = (redacted: unknown, omit = false) => adaptBeginnerMasterReport({
    ...beginnerStatusReportFixture(),
    findings: [{
      finding_id: "finding-redaction",
      fingerprint: "fp-redaction",
      snapshot_source: "frozen_selected_run",
      title: "Redaction claim",
      plain_language_risk: "Risk",
      possible_impact: "Impact",
      severity: "low",
      confidence: "low",
      priority: null,
      priority_reasons: [],
      target_asset_ids: ["asset-status"],
      next_step: "Review it.",
      recommended_expert_type: "IT administrator",
      evidence_references: [{
        evidence_id: "evidence-redaction",
        engine_id: "gitleaks",
        artifact_sha256: "a".repeat(64),
        observed_at: "2026-09-15T12:00:00Z",
        ...(omit ? {} : { redacted }),
      }],
      framework_references: [],
    }],
  }).findings[0]?.evidenceReferences[0]?.redacted;

  assert.equal(redactedFor(true), true);
  assert.equal(redactedFor(false), false);
  assert.equal(redactedFor(undefined, true), undefined);
  assert.equal(redactedFor(null), undefined);
  for (const redacted of [1, "false", {}, "true"]) {
    assert.equal(redactedFor(redacted), undefined);
  }
});

test("beginner check result kinds preserve known values, legacy absence, and fail closed on unknown values", () => {
  const known = adaptBeginnerMasterReport(beginnerStatusReportFixture({ resultKind: "security_check" }));
  assert.equal(known.actual.checks[0]?.resultKind, "security_check");

  for (const resultKind of [undefined, null]) {
    const report = adaptBeginnerMasterReport(beginnerStatusReportFixture({ resultKind }));
    assert.equal(report.actual.checks[0]?.resultKind, undefined);
  }

  for (const resultKind of ["future_result", true]) {
    const report = adaptBeginnerMasterReport(beginnerStatusReportFixture({ resultKind }));
    assert.equal(report.actual.checks[0]?.resultKind, "unknown");
  }
});

test("report target and stage availability fail closed on unknown required values", () => {
  const adaptedFor = (availability: unknown) => {
    const fixture = beginnerStatusReportFixture();
    return adaptBeginnerMasterReport({
      ...fixture,
      requested: {
        ...fixture.requested,
        targets: fixture.requested.targets.map((target) => ({
          ...target,
          label_availability: availability,
          asset_kind_availability: availability,
        })),
        stage: { ...fixture.requested.stage, availability },
      },
    });
  };

  for (const availability of ["recorded", "current_case_fallback", "unavailable", "not_applicable"]) {
    const report = adaptedFor(availability);
    assert.equal(report.requested.targets[0]?.labelAvailability, availability);
    assert.equal(report.requested.targets[0]?.assetKindAvailability, availability);
    assert.equal(report.requested.stage.availability, availability);
  }
  for (const availability of [undefined, null, "future_provenance", true, 1]) {
    const report = adaptedFor(availability);
    assert.equal(report.requested.targets[0]?.labelAvailability, "unavailable");
    assert.equal(report.requested.targets[0]?.assetKindAvailability, "unavailable");
    assert.equal(report.requested.stage.availability, "unavailable");
  }
});

test("unknown beginner inventory kinds cannot become named cloud resources", () => {
  const fixture = beginnerStatusReportFixture();
  const source = {
    observation_id: "inventory-unknown",
    engine_id: "future-engine",
    engine_run_id: "task-status",
    artifact_id: "artifact-unknown",
    artifact_sha256: "f".repeat(64),
    pointer: "/items/0",
    observed_at: "2026-09-15T12:00:00Z",
  };
  const unknownItem = {
    kind: "future_inventory_kind",
    asset_id: "asset-status",
    resource_type: "misleading-resource",
    native_id: "misleading-id",
    display_name: "Misleading cloud resource",
    sources: [source],
  };
  const cloudResource = {
    kind: "cloud_resource",
    asset_id: "asset-status",
    resource_type: "aws_s3_bucket",
    native_id: "bucket-1",
    display_name: "Known bucket",
    sources: [{ ...source, observation_id: "inventory-known", pointer: "/items/1" }],
  };
  const report = adaptBeginnerMasterReport({
    ...fixture,
    inventory: {
      total: 2,
      counts: {
        services: 0,
        software_components: 0,
        cloud_resources: 1,
        workflow_components: 0,
        workflow_relationships: 0,
      },
      asset_ids: ["asset-status"],
      representative_sample: [unknownItem],
      items: [unknownItem, cloudResource],
      by_asset: [{
        asset_id: "asset-status",
        total: 2,
        counts: {
          services: 0,
          software_components: 0,
          cloud_resources: 1,
          workflow_components: 0,
          workflow_relationships: 0,
        },
        representative_sample: [unknownItem],
      }],
    },
  });

  assert.deepEqual(report.inventory?.representativeSample, []);
  assert.equal(report.inventory?.items.length, 1);
  assert.equal(report.inventory?.items[0]?.kind, "cloud_resource");
  assert.deepEqual(report.inventory?.byAsset[0]?.representativeSample, []);
  assert.doesNotMatch(JSON.stringify(report.inventory), /Misleading cloud resource/u);
});

test("workflow component guardrail claims require exact booleans and preserve absence", () => {
  const isGuardrailFor = (is_guardrail: unknown) => {
    const fixture = beginnerStatusReportFixture();
    const item = {
      kind: "workflow_component",
      asset_id: "asset-status",
      component_type: "agent",
      name: "Assistant",
      model: null,
      is_guardrail,
      sources: [],
    };
    return adaptBeginnerMasterReport({
      ...fixture,
      inventory: {
        total: 1,
        counts: {
          services: 0,
          software_components: 0,
          cloud_resources: 0,
          workflow_components: 1,
          workflow_relationships: 0,
        },
        asset_ids: ["asset-status"],
        representative_sample: [item],
        items: [item],
        by_asset: [],
      },
    }).inventory?.items[0]?.isGuardrail;
  };

  assert.equal(isGuardrailFor(true), true);
  assert.equal(isGuardrailFor(false), false);
  assert.equal(isGuardrailFor(null), undefined);
  for (const isGuardrail of ["true", 1, {}, []]) {
    assert.equal(isGuardrailFor(isGuardrail), undefined);
  }
});

test("beginner report cleanup claims require exact booleans and preserve absence", () => {
  const cleanupRemovedFor = (cleanup_removed: unknown) => {
    const fixture = beginnerStatusReportFixture();
    return adaptBeginnerMasterReport({
      ...fixture,
      technical_details: {
        collapsed_by_default: true,
        tasks: [{
          task_id: "task-status",
          target_asset_ids: ["asset-status"],
          status: "completed",
          phase: "completed",
          progress_percent: 100,
          started_at: "2026-09-15T11:59:00Z",
          finished_at: "2026-09-15T12:00:00Z",
          exit_code: 0,
          cleanup_removed,
          cleanup_detail: {
            availability: "recorded",
            value: "Cleanup outcome recorded.",
            explanation: "Cleanup outcome was recorded.",
          },
          error_code: null,
          redacted_scanner_message: {
            availability: "unavailable",
            value: null,
            explanation: "No scanner message was retained.",
          },
          redacted_diagnostic_log: {
            availability: "unavailable",
            value: null,
            explanation: "No diagnostic log was retained.",
          },
          evidence_sha256: [],
          execution: {
            kind: "invalid_built_in_task",
            explanation: "Test-only invalid task.",
          },
        }],
      },
    }).technicalDetails.tasks[0]?.cleanupRemoved;
  };

  assert.equal(cleanupRemovedFor(true), true);
  assert.equal(cleanupRemovedFor(false), false);
  assert.equal(cleanupRemovedFor(null), undefined);
  for (const cleanupRemoved of ["true", 1, {}, []]) {
    assert.equal(cleanupRemovedFor(cleanupRemoved), undefined);
  }
});

test("catalog engine knowledge_date maps to knowledgeDate and an absent key stays undefined", () => {
  const executionFor = (knowledgeDate: "present" | "null" | "absent") => {
    const fixture = beginnerStatusReportFixture();
    return adaptBeginnerMasterReport({
      ...fixture,
      technical_details: {
        collapsed_by_default: true,
        tasks: [{
          task_id: "task-status",
          target_asset_ids: ["asset-status"],
          status: "completed",
          phase: "completed",
          progress_percent: 100,
          started_at: "2026-09-15T11:59:00Z",
          finished_at: "2026-09-15T12:00:00Z",
          exit_code: 0,
          cleanup_removed: null,
          cleanup_detail: {
            availability: "recorded",
            value: "Cleanup outcome recorded.",
            explanation: "Cleanup outcome was recorded.",
          },
          error_code: null,
          redacted_scanner_message: {
            availability: "unavailable",
            value: null,
            explanation: "No scanner message was retained.",
          },
          redacted_diagnostic_log: {
            availability: "unavailable",
            value: null,
            explanation: "No diagnostic log was retained.",
          },
          evidence_sha256: [],
          execution: {
            kind: "catalog_engine",
            engine_id: "prowler",
            engine_version: "0.74.0",
            image_digest: null,
            command_sha256: null,
            runtime_provider: null,
            runtime_version: null,
            runtime_security_options: null,
            distribution_mode: null,
            image_repository: null,
            adapter_version: "1.0.0",
            rule_version: null,
            ...(knowledgeDate === "present"
              ? { knowledge_date: "2026-08-24" }
              : knowledgeDate === "null"
                ? { knowledge_date: null }
                : {}),
          },
        }],
      },
    }).technicalDetails.tasks[0]?.execution;
  };

  const present = executionFor("present");
  assert.equal(present?.kind, "catalog_engine");
  assert.equal(present?.kind === "catalog_engine" ? present.knowledgeDate : undefined, "2026-08-24");
  const absent = executionFor("absent");
  assert.equal(absent?.kind === "catalog_engine" ? absent.knowledgeDate : "missing", undefined);
  const cleared = executionFor("null");
  assert.equal(cleared?.kind === "catalog_engine" ? cleared.knowledgeDate : "missing", undefined);
});

test("catalog engine reported_version maps to reportedVersion and an absent key stays undefined", () => {
  const executionFor = (reportedVersion: "present" | "null" | "blank" | "absent") => {
    const fixture = beginnerStatusReportFixture();
    return adaptBeginnerMasterReport({
      ...fixture,
      technical_details: {
        collapsed_by_default: true,
        tasks: [{
          task_id: "task-status",
          target_asset_ids: ["asset-status"],
          status: "completed",
          phase: "completed",
          progress_percent: 100,
          started_at: "2026-09-15T11:59:00Z",
          finished_at: "2026-09-15T12:00:00Z",
          exit_code: 0,
          cleanup_removed: null,
          cleanup_detail: {
            availability: "recorded",
            value: "Cleanup outcome recorded.",
            explanation: "Cleanup outcome was recorded.",
          },
          error_code: null,
          redacted_scanner_message: {
            availability: "unavailable",
            value: null,
            explanation: "No scanner message was retained.",
          },
          redacted_diagnostic_log: {
            availability: "unavailable",
            value: null,
            explanation: "No diagnostic log was retained.",
          },
          evidence_sha256: [],
          execution: {
            kind: "catalog_engine",
            engine_id: "trufflehog",
            engine_version: "source@3ab759fef4bb5935d4fe9ac68b503d05346b8364",
            image_digest: null,
            command_sha256: null,
            runtime_provider: null,
            runtime_version: null,
            runtime_security_options: null,
            distribution_mode: null,
            image_repository: null,
            adapter_version: "1.0.0",
            rule_version: null,
            ...(reportedVersion === "present"
              ? { reported_version: "3.97.0" }
              : reportedVersion === "null"
                ? { reported_version: null }
                : reportedVersion === "blank"
                  ? { reported_version: "   " }
                  : {}),
          },
        }],
      },
    }).technicalDetails.tasks[0]?.execution;
  };

  const present = executionFor("present");
  assert.equal(present?.kind, "catalog_engine");
  assert.equal(present?.kind === "catalog_engine" ? present.reportedVersion : undefined, "3.97.0");
  const absent = executionFor("absent");
  assert.equal(absent?.kind === "catalog_engine" ? absent.reportedVersion : "missing", undefined);
  const cleared = executionFor("null");
  assert.equal(cleared?.kind === "catalog_engine" ? cleared.reportedVersion : "missing", undefined);
  const blank = executionFor("blank");
  assert.equal(blank?.kind === "catalog_engine" ? blank.reportedVersion : "missing", undefined);
});

test("beginner coverage gap kinds preserve known values and fail closed to unavailable", () => {
  const known = adaptBeginnerMasterReport(beginnerStatusReportFixture({ gapKind: "failed" }));
  assert.equal(known.coverageGaps[0]?.kind, "failed");

  for (const gapKind of [undefined, null, "future_gap", true]) {
    const report = adaptBeginnerMasterReport(beginnerStatusReportFixture({ gapKind }));
    assert.equal(report.coverageGaps[0]?.kind, "unavailable");
  }
});

test("an older coverage-gap class is coverage loss, a present class round-trips, and an unrecognized class fails closed", () => {
  const absent = adaptBeginnerMasterReport(beginnerStatusReportFixture());
  assert.equal(absent.coverageGaps[0]?.class, "coverage_loss");

  for (const gapClass of [undefined, null]) {
    const report = adaptBeginnerMasterReport(beginnerStatusReportFixture({ gapClass }));
    assert.equal(report.coverageGaps[0]?.class, "coverage_loss");
  }

  const coverageLoss = adaptBeginnerMasterReport(
    beginnerStatusReportFixture({ gapClass: "coverage_loss" }),
  );
  assert.equal(coverageLoss.coverageGaps[0]?.class, "coverage_loss");

  const recordNote = adaptBeginnerMasterReport(
    beginnerStatusReportFixture({ gapClass: "record_note" }),
  );
  assert.equal(recordNote.coverageGaps[0]?.class, "record_note");

  // Unrecognized is not absence. The kind mapper's unrecognized path is
  // `includes() ? value : unavailable` — fail closed to the value that still
  // means coverage needs attention. The class mapper uses the same shape with
  // `coverage_loss` as that conservative fallback, never `record_note`.
  for (const gapClass of ["future_class", true]) {
    const report = adaptBeginnerMasterReport(beginnerStatusReportFixture({ gapClass }));
    assert.equal(report.coverageGaps[0]?.class, "coverage_loss");
  }
});

// Exactly the keys of `severityMeta` in src/lib.ts, which every severity
// lookup on the findings page indexes without optional chaining.
const RENDERABLE_SEVERITIES = ["critical", "high", "medium", "low", "unknown", "info"];

test("the report the findings list is built from carries severity and codes the list can read", () => {
  // This is the path the findings list actually uses: the page projects its
  // rows from the frozen beginner report, not from the canonical findings.
  // The canonical mapper normalizes severity and reads both codes; this one
  // did neither, and the raw payload type annotated this field as the
  // TypeScript `Severity` union when the backend fills it from a Rust enum,
  // so the compiler could not see the difference.
  //
  // naabu and httpx always rate Informational, which Rust serializes as
  // "informational" -- absent from that union and from `severityMeta`.
  const report = adaptBeginnerMasterReport({
    schema_version: "1.1.0",
    case_id: "case-1",
    run_id: "run-1",
    project_title: "Port scan",
    state: {
      summary: "partial",
      lifecycle: "final",
      last_durable_update: "2026-08-30T12:00:03Z",
      explanation: "Partial results are available.",
    },
    requested: {
      targets: [{
        asset_id: "asset-1",
        label: "192.0.2.10",
        asset_kind: "ip_address",
        label_availability: "recorded",
        asset_kind_availability: "recorded",
      }],
      stage: { value: "quick_discovery", availability: "recorded", explanation: "Frozen task." },
      limits: [],
      requested_check_ids: ["naabu"],
      request_outcome_code: null,
      automatic_reductions: [],
      reductions_availability: "recorded",
      unavailable_dimensions: [],
    },
    actual: {
      observed_from: "2026-08-30T12:00:00Z",
      observed_until: "2026-08-30T12:00:03Z",
      checks: [],
      unavailable_dimensions: [],
    },
    coverage_gaps: [],
    coverage_counts: {
      tested_complete: 1,
      tested_partial: 0,
      failed: 0,
      timed_out: 0,
      cancelled: 0,
      not_tested: 0,
      excluded: 0,
      truncated: 0,
      unavailable: 0,
    },
    findings: [{
      finding_id: "finding-naabu",
      fingerprint: "fp-naabu",
      snapshot_source: "frozen_selected_run",
      title: "Open TCP port",
      plain_language_risk:
        "naabu reported this condition on the assessed asset without rating it. This product rated it informational from an open port observation, not a defect.",
      possible_impact:
        "If the scanner result is confirmed, an internet-reachable service may expose unintended functionality.",
      severity: "informational",
      confidence: "confirmed",
      priority: 15,
      priority_reasons: [
        "Confidence derived from a response this product observed directly; naabu reports no confidence of its own.",
        "Direct scanner evidence is attached.",
      ],
      target_asset_ids: ["asset-1"],
      next_step: "Have the recommended specialist (Network security engineer) review it.",
      recommended_expert_type: "Network security engineer",
      family: "network_exposure",
      severity_basis_code: "open_port",
      confidence_basis_code: "observed_response",
      observation_details: ["port:443", "protocol:tcp"],
      evidence_references: [{
        evidence_id: "evidence-1",
        engine_id: "naabu",
        artifact_sha256: "a".repeat(64),
        observed_at: "2026-08-30T12:00:03Z",
      }],
      framework_references: [],
    }],
    next_steps: [],
    technical_details: { collapsed_by_default: true, tasks: [] },
    framework_notice: {
      non_certification: "Not certification.",
      aidefend_mapping_status: "Independent mapping.",
    },
    data_quality_warnings: [],
  });

  const finding = report.findings[0];
  assert.ok(finding, "the report dropped its only finding");

  assert.equal(finding.severity, "info");
  assert.equal(finding.confidence, "confirmed");
  assert.ok(
    RENDERABLE_SEVERITIES.includes(finding.severity),
    `severityMeta has no "${finding.severity}" entry, so every row renderer reads .label of undefined`,
  );

  // Without these the zh-TW page falls back to English for the impact and
  // action sentences -- and the summary composer takes its no-basis branch,
  // which states that the engine rated the finding when the English it
  // replaces says the engine did not rate it and this product did.
  assert.equal(finding.family, "network_exposure");
  assert.equal(finding.severityBasisCode, "open_port");
  assert.equal(finding.confidenceBasisCode, "observed_response");
  assert.equal(finding.evidenceReferences[0]?.detailsFrozen, false);
  assert.equal(finding.officialReferences, undefined);
  assert.deepEqual(finding.observationDetails, ["port:443", "protocol:tcp"]);
  assert.equal(report.inventory, undefined, "legacy reports must not invent typed inventory");
});

test("beginner report adapter preserves exact tested and untested network scope slices", () => {
  const report = adaptBeginnerMasterReport({
    schema_version: "1.0.0",
    case_id: "case-network",
    run_id: "run-network",
    project_title: "Exact network coverage",
    state: {
      summary: "partial",
      lifecycle: "final",
      last_durable_update: "2026-08-30T13:00:00Z",
      explanation: "One port was tested and one was not tested.",
    },
    requested: {
      targets: [{
        asset_id: "asset-network",
        label: "192.168.50.10",
        asset_kind: "ip_address",
        label_availability: "recorded",
        asset_kind_availability: "recorded",
      }],
      stage: {
        value: "inventory",
        availability: "recorded",
        explanation: "Frozen network plan.",
      },
      limits: [],
      requested_check_ids: ["naabu"],
      request_outcome_code: null,
      automatic_reductions: [],
      reductions_availability: "recorded",
      unavailable_dimensions: [],
    },
    actual: {
      observed_from: "2026-08-30T12:59:00Z",
      observed_until: "2026-08-30T13:00:00Z",
      checks: [],
      network_scopes: [{
        task_id: "task-naabu",
        check_id: "naabu",
        work_unit_id: "wu_tested_443",
        target_asset_id: "asset-network",
        target: "192.168.50.10",
        address_ranges: ["192.168.50.10"],
        port_ranges: ["443"],
        transport: "tcp",
        stage: "quick_discovery",
        outcome: "tested_complete",
        observed_at: "2026-08-30T12:59:30Z",
      }, {
        task_id: "task-naabu",
        check_id: "naabu",
        work_unit_id: "wu_not_tested_8443",
        target_asset_id: "asset-network",
        target: "192.168.50.10",
        address_ranges: ["192.168.50.10"],
        port_ranges: ["8443"],
        transport: "tcp",
        stage: "inventory",
        outcome: "not_tested",
        observed_at: null,
      }],
      unavailable_dimensions: [],
    },
    coverage_gaps: [],
    coverage_counts: {
      tested_complete: 1,
      tested_partial: 0,
      failed: 0,
      timed_out: 0,
      cancelled: 0,
      not_tested: 1,
      excluded: 0,
      truncated: 0,
      unavailable: 0,
    },
    findings: [],
    next_steps: [],
    technical_details: { collapsed_by_default: true, tasks: [] },
    framework_notice: {
      non_certification: "Not certification.",
      aidefend_mapping_status: "Independent mapping.",
    },
    data_quality_warnings: [],
  });

  assert.deepEqual(report.actual.networkScopes, [{
    taskId: "task-naabu",
    checkId: "naabu",
    workUnitId: "wu_tested_443",
    targetAssetId: "asset-network",
    target: "192.168.50.10",
    addressRanges: ["192.168.50.10"],
    portRanges: ["443"],
    transport: "tcp",
    stage: "quick_discovery",
    outcome: "tested_complete",
    observedAt: "2026-08-30T12:59:30Z",
  }, {
    taskId: "task-naabu",
    checkId: "naabu",
    workUnitId: "wu_not_tested_8443",
    targetAssetId: "asset-network",
    target: "192.168.50.10",
    addressRanges: ["192.168.50.10"],
    portRanges: ["8443"],
    transport: "tcp",
    stage: "inventory",
    outcome: "not_tested",
    observedAt: undefined,
  }]);
});

test("local network candidate adapter accepts one canonical private range", () => {
  assert.deepEqual(adaptLocalNetworkCandidateInventory({
    status: "ready",
    candidates: [localCandidate()],
  }), {
    status: "ready",
    candidates: [localCandidate()],
  });
});

test("local network candidate adapter fails closed for widened or malformed suggestions", () => {
  for (const candidate of [
    localCandidate({ target: "203.0.113.0/24" }),
    localCandidate({ target: "192.168.50.1/24" }),
    localCandidate({ target: "10.0.0.0/16", addressCount: 65_536 }),
    localCandidate({ requiresConfirmation: false }),
  ]) {
    assert.deepEqual(adaptLocalNetworkCandidateInventory({
      status: "ready",
      candidates: [candidate],
    }), { status: "unavailable", candidates: [] });
  }
  assert.deepEqual(adaptLocalNetworkCandidateInventory({
    status: "ambiguous",
    candidates: [localCandidate()],
  }), { status: "unavailable", candidates: [] });
});

const runtimeSetupDto = (overrides: Record<string, unknown> = {}) => ({
  phase: "failed",
  active: false,
  prerequisite_repair_active: false,
  cancel_requested: false,
  received_bytes: 0,
  total_bytes: null,
  progress_percent: null,
  resumed_from_bytes: 0,
  can_cancel: false,
  can_retry: true,
  failure_reason: "windows_wsl_optional_feature_disabled",
  next_action: "enable_wsl_optional_features",
  detail: "bounded technical detail",
  ...overrides,
});

test("managed runtime setup adapter preserves the exact failed recovery contract", () => {
  assert.deepEqual(adaptManagedRuntimeSetupStatus(runtimeSetupDto()), {
    phase: "failed",
    active: false,
    prerequisiteRepairActive: false,
    cancelRequested: false,
    receivedBytes: 0,
    totalBytes: undefined,
    progressPercent: undefined,
    resumedFromBytes: 0,
    canCancel: false,
    canRetry: true,
    failureReason: "windows_wsl_optional_feature_disabled",
    nextAction: "enable_wsl_optional_features",
    detail: "bounded technical detail",
  });

  for (const [failureReason, nextAction] of [
    ["windows_wsl_not_installed", "install_wsl"],
    ["windows_wsl_optional_feature_disabled", "enable_wsl_optional_features"],
    ["windows_wsl_update_required", "update_wsl"],
    ["windows_restart_required", "restart_windows"],
    ["windows_wsl_command_failed", "retry_wsl_check"],
  ] as const) {
    const adapted = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
      failure_reason: failureReason,
      next_action: nextAction,
    }));
    assert.equal(adapted.failureReason, failureReason);
    assert.equal(adapted.nextAction, nextAction);
  }
});

test("managed runtime control claims require exact booleans", () => {
  for (const malformed of [undefined, null, "true", 1, {}]) {
    const active = adaptManagedRuntimeSetupStatus(runtimeSetupDto({ active: malformed }));
    assert.equal(active.active, false);

    const cancel = adaptManagedRuntimeSetupStatus(runtimeSetupDto({ can_cancel: malformed }));
    assert.equal(cancel.canCancel, false);

    const retry = adaptManagedRuntimeSetupStatus(runtimeSetupDto({ can_retry: malformed }));
    assert.equal(retry.canRetry, false);
    assert.equal(retry.failureReason, "windows_wsl_optional_feature_disabled");
    assert.equal(retry.nextAction, "enable_wsl_optional_features");
  }
});

test("managed runtime setup adapter rejects the retired manual WSL distribution contract", () => {
  const adapted = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    failure_reason: "windows_wsl_distribution_requires_manual_action",
    next_action: "resolve_wsl_distribution_manually",
    detail: "Windows still reports WSL distribution podman-assm1-win-x64-0123456789ab",
  }));

  assert.equal(adapted.failureReason, undefined);
  assert.equal(adapted.nextAction, undefined);
});

test("managed runtime setup adapter preserves only the bounded non-retryable package failures", () => {
  for (const failureReason of [
    "packaged_runtime_missing",
    "packaged_runtime_verification_failed",
    "developer_build_without_packaged_runtime",
    "developer_build_packaged_runtime_verification_failed",
  ] as const) {
    const adapted = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
      can_retry: false,
      failure_reason: failureReason,
      next_action: null,
    }));

    assert.equal(adapted.failureReason, failureReason);
    assert.equal(adapted.nextAction, undefined);
    assert.equal(adapted.canRetry, false);
  }

  const retryableMismatch = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    can_retry: true,
    failure_reason: "packaged_runtime_missing",
    next_action: null,
  }));
  assert.equal(retryableMismatch.failureReason, undefined);
});

test("managed runtime setup adapter preserves active automatic workspace recovery", () => {
  const adapted = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    phase: "recovery",
    active: true,
    can_cancel: true,
    failure_reason: null,
    next_action: null,
    detail: "saving a bounded recovery copy",
  }));

  assert.equal(adapted.phase, "recovery");
  assert.equal(adapted.active, true);
  assert.equal(adapted.canCancel, true);
  assert.equal(adapted.failureReason, undefined);
  assert.equal(adapted.nextAction, undefined);
});

test("managed runtime setup adapter preserves bounded backend operation authority", () => {
  const adapted = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    phase: "start",
    active: true,
    operation_id: "runtime-operation-42",
    started_at: "2026-08-30T12:00:00Z",
    last_heartbeat_at: "2026-08-30T12:00:05Z",
    stale: false,
    failure_reason: null,
    next_action: null,
  }));

  assert.equal(adapted.operationId, "runtime-operation-42");
  assert.equal(adapted.startedAt, "2026-08-30T12:00:00Z");
  assert.equal(adapted.lastHeartbeatAt, "2026-08-30T12:00:05Z");
  assert.equal(adapted.stale, false);

  const malformed = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    operation_id: `bad\0${"x".repeat(200)}`,
    started_at: "x".repeat(65),
    last_heartbeat_at: "",
    stale: "yes",
  }));
  assert.equal(malformed.operationId, undefined);
  assert.equal(malformed.startedAt, undefined);
  assert.equal(malformed.lastHeartbeatAt, undefined);
  assert.equal(malformed.stale, false);
});

test("managed runtime setup adapter hides recovery fields outside failed or when mismatched", () => {
  const unwinding = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    phase: "prerequisite",
    active: true,
  }));
  assert.equal(unwinding.failureReason, undefined);
  assert.equal(unwinding.nextAction, undefined);

  const mismatched = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    next_action: "install_wsl",
  }));
  assert.equal(mismatched.failureReason, undefined);
  assert.equal(mismatched.nextAction, undefined);
});

test("managed runtime setup adapter hides unknown, missing, or unpaired recovery values", () => {
  const unknownReason = adaptManagedRuntimeSetupStatus(runtimeSetupDto({
    failure_reason: "not_a_setup_failure_reason",
    next_action: "enable_wsl_optional_features",
  }));
  assert.equal(unknownReason.failureReason, undefined);
  assert.equal(unknownReason.nextAction, undefined);

  const { next_action: _omitted, ...missingActionPayload } = runtimeSetupDto({
    failure_reason: "not_a_setup_failure_reason",
  });
  const missingAction = adaptManagedRuntimeSetupStatus(missingActionPayload);
  assert.equal(missingAction.failureReason, undefined);
  assert.equal(missingAction.nextAction, undefined);

  const missingKnownAction = adaptManagedRuntimeSetupStatus({
    ...runtimeSetupDto({ failure_reason: "windows_wsl_not_installed" }),
    next_action: undefined,
  });
  assert.equal(missingKnownAction.failureReason, undefined);
  assert.equal(missingKnownAction.nextAction, undefined);
});

test("declared website metadata adapts a bounded preset", () => {
  assert.deepEqual(adaptDeclaredWebServiceMetadata({
    declared_web_service: { protocol: "https", port: 8443, path: "/login" },
  }), { protocol: "https", port: 8443, path: "/login" });

  assert.deepEqual(adaptDeclaredWebServiceMetadata({
    declared_web_service: {
      protocol: "https",
      port: 8080,
      path: "/",
      scan_profile: "internal_device_https",
    },
  }), {
    protocol: "https",
    port: 8080,
    path: "/",
    scanProfile: "internal_device_https",
  });
});

test("declared website metadata rejects malformed or query-bearing values", () => {
  assert.equal(adaptDeclaredWebServiceMetadata({
    declared_web_service: { protocol: "https", port: 443, path: "/?token=secret" },
  }), undefined);
  assert.equal(adaptDeclaredWebServiceMetadata({
    declared_web_service: { protocol: "ftp", port: 21, path: "/" },
  }), undefined);
  assert.equal(adaptDeclaredWebServiceMetadata({
    declared_web_service: { protocol: "http", port: 0, path: "/" },
  }), undefined);
  assert.equal(adaptDeclaredWebServiceMetadata({
    declared_web_service: {
      protocol: "https",
      port: 443,
      path: "/",
      scan_profile: "website_quick",
    },
  }), undefined, "an unknown profile must not silently become a website quick scan");
});

test("declared endpoint metadata adapts only the fixed SSH, RDP, VNC, SMTP, and Telnet profiles", () => {
  assert.deepEqual(adaptDeclaredNetworkServiceMetadata({
    declared_network_service: {
      protocol: "tcp",
      port: 2222,
      scan_profile: "internal_endpoint_ssh",
    },
  }), {
    protocol: "tcp",
    port: 2222,
    scanProfile: "internal_endpoint_ssh",
  });
  assert.deepEqual(adaptDeclaredNetworkServiceMetadata({
    declared_network_service: {
      protocol: "tcp",
      port: 3389,
      scan_profile: "internal_endpoint_rdp_tls",
    },
  }), {
    protocol: "tcp",
    port: 3389,
    scanProfile: "internal_endpoint_rdp_tls",
  });
  assert.deepEqual(adaptDeclaredNetworkServiceMetadata({
    declared_network_service: {
      protocol: "tcp",
      port: 5900,
      scan_profile: "internal_endpoint_vnc",
    },
  }), {
    protocol: "tcp",
    port: 5900,
    scanProfile: "internal_endpoint_vnc",
  });
  assert.deepEqual(adaptDeclaredNetworkServiceMetadata({
    declared_network_service: {
      protocol: "tcp",
      port: 587,
      scan_profile: "internal_endpoint_smtp",
    },
  }), {
    protocol: "tcp",
    port: 587,
    scanProfile: "internal_endpoint_smtp",
  });
  assert.deepEqual(adaptDeclaredNetworkServiceMetadata({
    declared_network_service: {
      protocol: "tcp",
      port: 23,
      scan_profile: "internal_endpoint_telnet",
    },
  }), {
    protocol: "tcp",
    port: 23,
    scanProfile: "internal_endpoint_telnet",
  });
  for (const declared_network_service of [
    { protocol: "udp", port: 22, scan_profile: "internal_endpoint_ssh" },
    { protocol: "tcp", port: 0, scan_profile: "internal_endpoint_ssh" },
    { protocol: "tcp", port: 22, scan_profile: "unknown_profile" },
  ]) {
    assert.equal(adaptDeclaredNetworkServiceMetadata({ declared_network_service }), undefined);
  }
});

test("declared host metadata adapts only the generic exact-host profile and bounded ports", () => {
  assert.deepEqual(adaptDeclaredHostScanMetadata({
    declared_host_scan: {
      protocol: "tcp",
      ports: [8443, 22, 443],
      profile: "greenbone_remote_safe_v1",
    },
  }), {
    protocol: "tcp",
    ports: [22, 443, 8443],
    scanProfile: "internal_host_greenbone_remote_safe",
  });
  assert.equal(adaptDeclaredHostScanMetadata({
    declared_host_scan: {
      protocol: "tcp",
      ports: [22, 22],
      profile: "greenbone_remote_safe_v1",
    },
  }), undefined);
  assert.equal(adaptDeclaredHostScanMetadata({
    declared_host_scan: {
      protocol: "tcp",
      ports: [22],
      profile: "internal_endpoint_ssh",
    },
  }), undefined);
});

test("native case summaries, workspaces, and case creation preserve AI applicability provenance", () => {
  assert.ok(adapterSource.includes("assessment_intent?: string | null"));
  assert.ok(adapterSource.includes("ai_generated_artifact?: string | null"));
  assert.equal((adapterSource.match(/const assessmentIntent = mapAssessmentIntent/g) ?? []).length, 2);
  assert.ok(scannerSource.includes("assessment_intent: input.assessmentIntent ?? null"));
  assert.ok(scannerSource.includes("ai_generated_artifact: input.aiGeneratedArtifact"));
});

const summaryFixture = (overrides: Record<string, unknown> = {}) => ({
  id: "case-summary-1",
  title: "Summary case",
  assessment_intent: "source_code",
  ai_generated_artifact: "yes",
  organization_name: "Example",
  employee_range: "small",
  data_classes: [],
  requested_activities: ["local_artifact_analysis"],
  source_kinds: [
    "aws_organization",
    "azure_tenant",
    "gcp_organization",
    "microsoft365_tenant",
    "git_repository",
    "container_registry",
    "kubernetes_cluster",
  ],
  applicable_source_kinds: ["git_repository", "container_registry", "kubernetes_cluster"],
  notes: null,
  status: "scope_review",
  created_at: "2026-08-26T00:00:00Z",
  updated_at: "2026-08-26T00:00:00Z",
  is_demo: false,
  asset_count: 2,
  finding_count: 0,
  latest_run_id: null,
  ...overrides,
});

const snapshotFixture = (cases: ReturnType<typeof summaryFixture>[]) => ({
  product_name: "ai-security-scanner",
  product_version: "test",
  storage_path: "redacted",
  cases,
  selected_case: null,
  runtime: {
    provider: "managed",
    available: false,
    phase: "unavailable",
    version: null,
    prerequisite: null,
    detail: "test",
  },
  artifact_cleanup_obligations: [],
  engine_count: 0,
});

const nativeManifestFixture = (overrides: Record<string, unknown> = {}) => ({
  id: "example-engine",
  display_name: "Example engine",
  category: "cloud_configuration",
  distribution_mode: "pull_pinned_image",
  image: { digest: "sha256:example" },
  engine_version: "1.0.0",
  rule_version: "rules-1",
  license_spdx: "Apache-2.0",
  supported_providers: ["aws"],
  supported_asset_kinds: ["cloud_account"],
  status: "integrated",
  compatibility: {
    knowledge_date: "2026-01-01",
    support_until: "9999-12-31",
    runnable: true,
    blocked_by: [],
  },
  ...overrides,
});

test("native manifests safely project exact release availability and provider profiles", () => {
  const m365 = adaptNativeManifest(nativeManifestFixture({
    id: "scubagear",
    display_name: "ScubaGear",
    supported_providers: ["microsoft365"],
    supported_asset_kinds: ["tenant"],
    status: "experimental",
    compatibility: {
      knowledge_date: "2026-01-01",
      support_until: "9999-12-31",
      runnable: false,
      blocked_by: ["not released"],
    },
  }));
  assert.equal(m365.status, "not_downloaded");
  assert.equal(m365.runnable, false);
  assert.equal(m365.compatibilityValid, true);
  assert.deepEqual(m365.blockedBy, ["not released"]);
  assert.deepEqual(m365.supportedProviders, ["m365"]);

  const prowlerManifest = adaptNativeManifest(nativeManifestFixture({
    id: "prowler",
    supported_providers: ["aws", "azure", "gcp"],
    supported_asset_kinds: ["cloud_account", "subscription", "project"],
    provider_execution_contracts: [
      { provider: "aws", asset_kind: "cloud_account", profile: "aws_iam_service_exact_account" },
      { provider: "azure", asset_kind: "subscription", profile: "azure_iam_service_static_token_exact_subscription" },
      { provider: "gcp", asset_kind: "project", profile: "gcp_iam_four_checks_exact_project" },
      { provider: "other", asset_kind: "project", profile: "broad_profile" },
      { provider: "gcp", asset_kind: "organization", profile: "wrong_asset_kind" },
    ],
  }));
  assert.deepEqual(prowlerManifest.providerExecutionProfiles, [
    { provider: "aws", assetKind: "cloud_account", profile: "aws_iam_service_exact_account" },
    { provider: "azure", assetKind: "subscription", profile: "azure_iam_service_static_token_exact_subscription" },
    { provider: "gcp", assetKind: "project", profile: "gcp_iam_four_checks_exact_project" },
  ]);
});

test("missing or malformed manifest compatibility fails soft instead of inventing availability", () => {
  const missing = adaptNativeManifest(nativeManifestFixture({
    compatibility: { knowledge_date: "2026-01-01", support_until: "9999-12-31", blocked_by: [] },
  }));
  assert.equal(missing.runnable, undefined);
  assert.equal(missing.compatibilityValid, true);

  for (const compatibility of [
    { runnable: "yes", blocked_by: [] },
    { runnable: true, blocked_by: ["safe blocker", 7] },
    { runnable: true, blocked_by: ["contradicts runnable"] },
  ]) {
    const malformed = adaptNativeManifest(nativeManifestFixture({ compatibility }));
    assert.equal(malformed.runnable, undefined);
    assert.equal(malformed.compatibilityValid, false);
  }

  const futureVocabulary = adaptNativeManifest(nativeManifestFixture({
    category: "future_category",
    distribution_mode: "future_distribution",
    status: "future_status",
  }));
  assert.equal(futureVocabulary.category, "unknown");
  assert.equal(futureVocabulary.redistribution, "unknown");
  assert.equal(futureVocabulary.status, "unsupported");
});

test("manifest knowledge dates are kept and support dates are not projected", () => {
  const known = adaptNativeManifest(nativeManifestFixture({
    compatibility: { knowledge_date: "2026-01-01", support_until: "9999-12-31", runnable: true, blocked_by: [] },
  }));
  assert.equal(known.knowledgeDate, "2026-01-01");
  assert.equal(Object.hasOwn(known, "supportUntil"), false);
  assert.equal(Object.hasOwn(known, "supportStatus"), false);

  for (const support_until of [undefined, null, "not-a-date", "2026-02-30", true]) {
    const manifest = adaptNativeManifest(nativeManifestFixture({
      compatibility: { knowledge_date: "2026-01-01", support_until, runnable: true, blocked_by: [] },
    }));
    assert.equal(manifest.knowledgeDate, "2026-01-01");
    assert.equal(Object.hasOwn(manifest, "supportUntil"), false);
    assert.equal(Object.hasOwn(manifest, "supportStatus"), false);
  }

  const missing = adaptNativeManifest(nativeManifestFixture({
    compatibility: { support_until: "9999-12-31", runnable: true, blocked_by: [] },
  }));
  assert.equal(missing.knowledgeDate, undefined);
});

test("case summaries display only applicable source platforms and preserve real multi-platform scope", () => {
  const snapshot = adaptNativeSnapshot(snapshotFixture([summaryFixture()]), []);

  assert.deepEqual(snapshot.cases[0]?.platforms, ["code", "container", "kubernetes"]);
  assert.equal(snapshot.cases[0]?.aiGeneratedArtifact, "yes");

  const withoutOrganizationSize = adaptNativeSnapshot(snapshotFixture([summaryFixture({
    employee_range: "Not provided",
  })]), []);
  assert.equal(withoutOrganizationSize.cases[0]?.companySize, "unknown");
});

test("native snapshot preserves beginner-safe diagnostics for unreadable saved projects", () => {
  const snapshot = adaptNativeSnapshot({
    ...snapshotFixture([summaryFixture()]),
    case_recovery_diagnostics: [{
      case_id: "damaged-case",
      title: "Older scan project",
      updated_at: "2026-08-26T00:00:00Z",
      revision: 7,
      document_bytes: 2048,
      code: "case_document_unreadable",
      message: "The original local bytes were preserved.",
      preserved: true,
    }],
  }, []);

  assert.deepEqual(snapshot.caseRecoveryDiagnostics, [{
    caseId: "damaged-case",
    title: "Older scan project",
    updatedAt: "2026-08-26T00:00:00Z",
    revision: 7,
    documentBytes: 2048,
    code: "case_document_unreadable",
    message: "The original local bytes were preserved.",
    preserved: true,
  }]);
  assert.equal(snapshot.provenance, "native");
});

test("case recovery preservation claims require exact booleans", () => {
  const preservedFor = (preserved: unknown) => adaptNativeSnapshot({
    ...snapshotFixture([summaryFixture()]),
    case_recovery_diagnostics: [{
      case_id: "damaged-case",
      title: "Older scan project",
      updated_at: "2026-08-26T00:00:00Z",
      revision: 7,
      document_bytes: 2048,
      code: "case_document_unreadable",
      message: "Recovery status recorded.",
      preserved,
    }],
  }, []).caseRecoveryDiagnostics?.[0]?.preserved;

  assert.equal(preservedFor(true), true);
  assert.equal(preservedFor(false), false);
  for (const preserved of [undefined, null, "true", 1, {}, []]) {
    assert.equal(preservedFor(preserved), false);
  }
});

test("native runtime availability preserves booleans and fails closed on malformed values", () => {
  assert.equal(adaptNativeSnapshot({
    ...snapshotFixture([]),
    runtime: { ...snapshotFixture([]).runtime, available: true },
  }, []).runtime?.available, true);
  assert.equal(adaptNativeSnapshot(snapshotFixture([]), []).runtime?.available, false);

  for (const available of [undefined, null, "true", 1]) {
    const snapshot = adaptNativeSnapshot({
      ...snapshotFixture([]),
      runtime: { ...snapshotFixture([]).runtime, available },
    }, []);
    assert.equal(snapshot.runtime?.available, false);
  }
});

test("native snapshot retains packaged scanner issues only as technical structured data", () => {
  const snapshot = adaptNativeSnapshot({
    ...snapshotFixture([summaryFixture()]),
    engine_admission_issues: [{
      engine_id: "gitleaks",
      code: "engine_contract_invalid",
      detail: "test-only catalog detail",
    }, {
      engine_id: null,
      code: "catalog_container_invalid",
      detail: "test-only root detail",
    }],
  }, []);

  assert.deepEqual(snapshot.engineAdmissionIssues, [{
    engineId: "gitleaks",
    code: "engine_contract_invalid",
    detail: "test-only catalog detail",
  }, {
    engineId: undefined,
    code: "catalog_container_invalid",
    detail: "test-only root detail",
  }]);
});

test("missing or malformed AI-generated answers fail closed to unknown", () => {
  for (const ai_generated_artifact of [undefined, null, "maybe", true]) {
    const snapshot = adaptNativeSnapshot(snapshotFixture([summaryFixture({
      ai_generated_artifact,
    })]), []);
    assert.equal(snapshot.cases[0]?.aiGeneratedArtifact, "unknown");
  }
});

test("unknown native assessment intents never select a guided scan route", () => {
  const snapshot = adaptNativeSnapshot(snapshotFixture([summaryFixture({
    assessment_intent: "future_assessment_intent",
  })]), []);
  const workspace = adaptNativeCase(platformCaseFixture({
    assessment_intent: "future_assessment_intent",
  }));

  assert.equal(snapshot.cases[0]?.assessmentIntent, undefined);
  assert.equal(workspace.case.assessmentIntent, undefined);
});

test("draft summaries with no assets or applicable sources fall back to the selected assessment route", () => {
  const snapshot = adaptNativeSnapshot(snapshotFixture([summaryFixture({
    assessment_intent: "deployed_website",
    applicable_source_kinds: [],
    status: "draft",
    asset_count: 0,
  })]), []);

  assert.deepEqual(snapshot.cases[0]?.platforms, ["external"]);
});

test("unknown native case and coverage statuses fail closed", () => {
  const snapshot = adaptNativeSnapshot(snapshotFixture([summaryFixture({
    status: "future_case_status",
  })]), []);
  const workspace = adaptNativeCase(platformCaseFixture({
    status: "future_case_status",
    coverage: [{
      id: "coverage-future",
      label: "Future coverage state",
      source_kind: "user_declared",
      asset_id: null,
      status: "future_coverage_status",
      explanation: "A newer backend value must not imply completed coverage.",
      observed_at: null,
    }],
  }));

  assert.equal(snapshot.cases[0]?.phase, "needs_attention");
  assert.equal(workspace.case.phase, "needs_attention");
  assert.equal(workspace.coverage[0]?.state, "source_unavailable_unknown");
});

const platformCaseFixture = (overrides: Record<string, unknown> = {}) => ({
  id: "case-platforms-1",
  title: "Platform display case",
  assessment_intent: "deployed_website",
  profile: {
    organization_name: "Example",
    employee_range: "small",
    data_classes: [],
    notes: null,
  },
  status: "scope_review",
  created_at: "2026-08-26T00:00:00Z",
  updated_at: "2026-08-26T00:00:00Z",
  is_demo: false,
  requested_activities: ["local_artifact_analysis"],
  data_sources: [
    {
      id: "aws-placeholder",
      kind: "aws_organization",
      label: "AWS not used",
      status: "not_applicable",
      connected_at: null,
      last_discovered_at: null,
      read_only: true,
    },
    {
      id: "azure-planned",
      kind: "azure_tenant",
      label: "Azure planned",
      status: "not_connected",
      connected_at: null,
      last_discovered_at: null,
      read_only: true,
    },
    {
      id: "kubernetes-connected",
      kind: "kubernetes_cluster",
      label: "Kubernetes connected",
      status: "connected",
      connected_at: "2026-08-26T00:00:00Z",
      last_discovered_at: "2026-08-26T00:00:00Z",
      read_only: true,
    },
  ],
  assets: [{
    id: "repository-asset",
    kind: "repository",
    name: "Repository",
    provider: null,
    region: null,
    identifiers: [],
    discovered_from: [],
    candidate: false,
    owner_confirmed: true,
    metadata: {},
  }],
  scope_grants: [],
  coverage: [],
  scan_runs: [],
  findings: [],
  exports: [],
  comparisons: [],
  ...overrides,
});

test("native verification diffs retain their five-way status and structured reasons", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    comparisons: [{
      id: "comparison-1",
      case_id: "case-platforms-1",
      baseline_run_id: "run-before",
      current_run_id: "run-after",
      created_at: "2026-08-26T01:00:00Z",
      complete: true,
      completeness_issues: [],
      diffs: [{
        fingerprint: "fingerprint-verbatim",
        baseline_finding_id: null,
        current_finding_id: null,
        status: "changed",
        explanation: "The finding remains observable, but severity changed from high to critical.",
        baseline_severity: "high",
        current_severity: "critical",
        evidence_changed: false,
        reasons: [{
          code: "severity_changed",
          engine_id: null,
          asset_id: null,
          detail: "severity changed from high to critical",
        }],
      }],
    }],
  }));

  assert.equal(workspace.verification?.diffs[0]?.comparisonStatus, "changed");
  assert.deepEqual(workspace.verification?.diffs[0]?.changeReasons, [{
    code: "severity_changed",
    engineId: undefined,
    assetId: undefined,
    detail: "severity changed from high to critical",
  }]);
});

const snapshotSha = (character: string) => character.repeat(64);

const folderAsset = (id: string, metadata: Record<string, unknown>) => ({
  id,
  kind: "repository",
  name: id,
  provider: null,
  region: null,
  identifiers: [],
  discovered_from: [],
  candidate: false,
  owner_confirmed: true,
  metadata,
});

test("native local folder copies and comparison hashes keep only well-typed values", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [
      folderAsset("kept", {
        workspace_snapshot_sha256: snapshotSha("a"),
        workspace_snapshot_saved_at: "2026-10-06T01:02:03Z",
        workspace_snapshot_previous_sha256: snapshotSha("b"),
        workspace_snapshot_change: { changed: 2, added: 1, removed: 0, unchanged: 4 },
      }),
      folderAsset("partial", {
        workspace_snapshot_sha256: snapshotSha("c"),
        workspace_snapshot_saved_at: 12,
        workspace_snapshot_previous_sha256: null,
        workspace_snapshot_change: { changed: 1, added: "2", removed: 0, unchanged: 0 },
      }),
      folderAsset("redacted-previous", {
        workspace_snapshot_sha256: snapshotSha("d"),
        workspace_snapshot_previous_sha256: "[redacted snapshot hash]",
        workspace_snapshot_change: { changed: 0, added: 0, removed: 0, unchanged: 9 },
      }),
      folderAsset("uppercase", {
        workspace_snapshot_sha256: "A".repeat(64),
        workspace_snapshot_saved_at: "2026-10-06T01:02:03Z",
      }),
      folderAsset("short", { workspace_snapshot_sha256: "a".repeat(63) }),
    ],
    comparisons: [{
      id: "comparison-copies",
      baseline_run_id: "run-before",
      current_run_id: "run-after",
      created_at: "2026-10-06T02:00:00Z",
      complete: true,
      diffs: [],
      local_input_changes: [
        {
          asset_id: "kept",
          baseline_sha256: snapshotSha("a"),
          current_sha256: snapshotSha("e"),
          changed: true,
        },
        {
          asset_id: "redacted",
          baseline_sha256: "[redacted snapshot hash]",
          current_sha256: "[redacted snapshot hash]",
          changed: false,
        },
        { asset_id: 4, baseline_sha256: snapshotSha("a"), current_sha256: snapshotSha("e"), changed: true },
        { asset_id: "bad-flag", baseline_sha256: snapshotSha("a"), current_sha256: snapshotSha("e"), changed: "true" },
        null,
        { asset_id: "missing" },
      ],
    }],
  }));

  assert.deepEqual(workspace.assets.find((asset) => asset.id === "kept")?.localCopy, {
    sha256: snapshotSha("a"),
    savedAt: "2026-10-06T01:02:03Z",
    previousSha256: snapshotSha("b"),
    change: { changed: 2, added: 1, removed: 0, unchanged: 4 },
  });
  assert.deepEqual(workspace.assets.find((asset) => asset.id === "partial")?.localCopy, {
    sha256: snapshotSha("c"),
  });
  assert.deepEqual(workspace.assets.find((asset) => asset.id === "redacted-previous")?.localCopy, {
    sha256: snapshotSha("d"),
    previousSha256: "[redacted snapshot hash]",
    change: { changed: 0, added: 0, removed: 0, unchanged: 9 },
  });
  assert.equal(workspace.assets.find((asset) => asset.id === "uppercase")?.localCopy, undefined);
  assert.equal(workspace.assets.find((asset) => asset.id === "short")?.localCopy, undefined);
  assert.deepEqual(workspace.verification?.localInputChanges, [
    {
      assetId: "kept",
      baselineSha256: snapshotSha("a"),
      currentSha256: snapshotSha("e"),
      changed: true,
    },
    {
      assetId: "redacted",
      baselineSha256: "[redacted snapshot hash]",
      currentSha256: "[redacted snapshot hash]",
      changed: false,
    },
  ]);

  for (const change of [
    { changed: -1, added: 0, removed: 0, unchanged: 0 },
    { changed: 1.5, added: 0, removed: 0, unchanged: 0 },
    { changed: 1, added: 0, removed: 0 },
    { changed: true, added: 0, removed: 0, unchanged: 0 },
    null,
    [1, 0, 0, 0],
  ]) {
    const dropped = adaptNativeCase(platformCaseFixture({
      assets: [folderAsset("repo", {
        workspace_snapshot_sha256: snapshotSha("f"),
        workspace_snapshot_change: change,
      })],
    }));
    assert.equal(dropped.assets[0]?.localCopy?.sha256, snapshotSha("f"));
    assert.equal(dropped.assets[0]?.localCopy?.change, undefined);
  }

  for (const localInputChanges of [[], { asset_id: "kept" }, undefined]) {
    const omitted = adaptNativeCase(platformCaseFixture({
      comparisons: [{
        id: "comparison-omitted",
        baseline_run_id: "run-before",
        current_run_id: "run-after",
        created_at: "2026-10-06T02:00:00Z",
        diffs: [],
        ...(localInputChanges === undefined ? {} : { local_input_changes: localInputChanges }),
      }],
    }));
    assert.equal(Object.hasOwn(omitted.verification ?? {}, "localInputChanges"), false);
  }
});

test("native sources expose only an exact non-secret provider binding", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    data_sources: [{
      id: "gcp-source",
      kind: "gcp_organization",
      label: "GCP organization",
      status: "connected",
      connected_at: "2026-08-26T00:00:00Z",
      last_discovered_at: "2026-08-26T00:00:00Z",
      read_only: true,
      metadata: {
        provider_profile: "gcp_organization_read_only_access_token",
        provider_resource_scope: "gcp-organization:123456789012",
        provider_identity: "MUST_NOT_SURVIVE",
        access_token: "SECRET",
        verification_evidence_sha256: "MUST_NOT_SURVIVE_EITHER",
      },
    }],
  }));

  assert.deepEqual(workspace.sources[0]?.providerBinding, {
    profile: "gcp_organization_read_only_access_token",
    resourceScope: "gcp-organization:123456789012",
  });
  assert.doesNotMatch(
    JSON.stringify(workspace.sources[0]),
    /MUST_NOT_SURVIVE|SECRET|"provider_identity"|"access_token"|"verification_evidence_sha256"/u,
  );
});

test("provider binding projection fails closed for incomplete, mismatched, or malformed metadata", () => {
  const invalid: Array<[string, Record<string, unknown> | undefined]> = [
    ["missing scope", { provider_profile: "aws_organization_read_only_session" }],
    ["missing profile", { provider_resource_scope: "aws-account:123456789012" }],
    ["non-string scope", { provider_profile: "aws_organization_read_only_session", provider_resource_scope: 123456789012 }],
    ["unknown profile", { provider_profile: "administrator", provider_resource_scope: "aws-account:123456789012" }],
    ["wrong source profile", { provider_profile: "gcp_organization_read_only_access_token", provider_resource_scope: "gcp-organization:123" }],
    ["wrong scope prefix", { provider_profile: "aws_organization_read_only_session", provider_resource_scope: "gcp-organization:123456789012" }],
    ["short AWS account", { provider_profile: "aws_organization_read_only_session", provider_resource_scope: "aws-account:123" }],
    ["malformed UUID", { provider_profile: "azure_tenant_read_only_access_token", provider_resource_scope: "azure-subscription:not-a-uuid" }],
    ["long GCP organization", { provider_profile: "gcp_organization_read_only_access_token", provider_resource_scope: `gcp-organization:${"1".repeat(33)}` }],
    ["suffix", { provider_profile: "aws_organization_read_only_session", provider_resource_scope: "aws-account:123456789012\n<script>" }],
  ];

  for (const [label, metadata] of invalid) {
    const sourceKind = label === "wrong source profile"
      ? "aws_organization"
      : label === "malformed UUID" ? "azure_tenant"
        : label === "long GCP organization" ? "gcp_organization"
          : "aws_organization";
    assert.equal(adaptNativeProviderBinding(sourceKind, metadata), undefined, label);
  }
});

const localhostSelectedCaseFixture = ({
  id,
  title,
  createdAt,
  port,
}: {
  id: string;
  title: string;
  createdAt: string;
  port: number;
}) => platformCaseFixture({
  id,
  title,
  created_at: createdAt,
  updated_at: createdAt,
  data_sources: [],
  assets: [{
    id: `${id}-asset`,
    kind: "web_service",
    name: `127.0.0.1:${port}`,
    provider: null,
    region: null,
    identifiers: [{ namespace: "localhost_tcp_endpoint", value: `127.0.0.1:${port}` }],
    discovered_from: [],
    candidate: false,
    owner_confirmed: true,
    internet_exposed: false,
    metadata: {},
  }],
  scan_runs: [{
    id: `${id}-run`,
    case_id: id,
    sequence: 1,
    created_at: createdAt,
    completed_at: createdAt,
    knowledge_cutoff: createdAt,
    engine_runs: [{
      id: `${id}-task`,
      engine_id: "built-in-localhost-tcp",
      task_kind: {
        kind: "built_in_localhost_tcp",
        port,
        timeout_ms: 3000,
        payload_bytes: 0,
      },
      localhost_tcp_observation: {
        outcome: "reachable",
        observed_at: createdAt,
      },
      asset_ids: [`${id}-asset`],
      status: "completed",
      progress_percent: 100,
      phase: "completed",
      started_at: createdAt,
      finished_at: createdAt,
      resume_token: null,
      engine_version: null,
      image_digest: null,
      rule_version: null,
      adapter_version: "",
      raw_artifact_ids: [],
      error_code: null,
      error_message: null,
    }],
  }],
});

test("structured localhost identities remain stable while switching selected cases", () => {
  const createdAt = "2026-08-30T12:00:00Z";
  const summaries = [
    summaryFixture({
      id: "quick-a",
      title: "Persisted legacy name A",
      created_at: createdAt,
      product_identity: { kind: "localhost_quick_scan", port: 9001 },
    }),
    summaryFixture({
      id: "quick-b",
      title: "Persisted legacy name B",
      created_at: createdAt,
      product_identity: { kind: "localhost_quick_scan", port: 9001 },
    }),
  ];
  const selectedA = adaptNativeSnapshot({
    ...snapshotFixture(summaries),
    selected_case: localhostSelectedCaseFixture({
      id: "quick-a",
      title: "Persisted legacy name A",
      createdAt,
      port: 9001,
    }),
  }, []);
  const selectedB = adaptNativeSnapshot({
    ...snapshotFixture(summaries),
    selected_case: localhostSelectedCaseFixture({
      id: "quick-b",
      title: "Persisted legacy name B",
      createdAt,
      port: 9001,
    }),
  }, []);

  for (const snapshot of [selectedA, selectedB]) {
    assert.deepEqual(snapshot.cases.map((assessmentCase: { productIdentity?: unknown }) => (
      assessmentCase.productIdentity
    )), [
      { kind: "localhost_quick_scan", port: 9001 },
      { kind: "localhost_quick_scan", port: 9001 },
    ]);
  }

  const labelsA = [...caseDisplayLabels(selectedA.cases, "zh-TW", (value: string) => value.slice(0, 16))];
  const labelsB = [...caseDisplayLabels(selectedB.cases, "zh-TW", (value: string) => value.slice(0, 16))];
  assert.deepEqual(labelsA, labelsB);
  assert.notEqual(labelsA[0]?.[1], labelsA[1]?.[1]);
  assert.match(labelsA[0]?.[1] ?? "", /quick-a$/u);
  assert.match(labelsA[1]?.[1] ?? "", /quick-b$/u);
});

test("malformed summary product identities fail closed", () => {
  for (const product_identity of [
    { kind: "localhost_quick_scan", port: 0 },
    { kind: "localhost_quick_scan", port: 65_536 },
    { kind: "localhost_quick_scan", port: 9001.5 },
    { kind: "lookalike", port: 9001 },
  ]) {
    const snapshot = adaptNativeSnapshot(snapshotFixture([summaryFixture({ product_identity })]), []);
    assert.equal(snapshot.cases[0]?.productIdentity, undefined);
  }
});

test("full cases combine asset and applicable source platforms without questionnaire placeholders", () => {
  const workspace = adaptNativeCase(platformCaseFixture());

  assert.deepEqual(workspace.case.platforms, ["code", "azure", "kubernetes"]);
});

test("a native SSH host remains an external service with its exact declared port", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [{
      id: "ssh-host",
      kind: "host",
      name: "server.example.test",
      provider: null,
      region: null,
      identifiers: [{ namespace: "dns_name", value: "server.example.test" }],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
      internet_exposed: false,
      metadata: {
        declared_network_service: {
          protocol: "tcp",
          port: 2222,
          scan_profile: "internal_endpoint_ssh",
        },
      },
    }],
  }));

  assert.equal(workspace.assets[0]?.type, "service");
  assert.equal(workspace.assets[0]?.platform, "external");
  assert.deepEqual(workspace.assets[0]?.declaredNetworkService, {
    protocol: "tcp",
    port: 2222,
    scanProfile: "internal_endpoint_ssh",
  });
});

test("known network-facing kinds still group as the external platform", () => {
  const snapshot = adaptNativeSnapshot(snapshotFixture([summaryFixture({
    applicable_source_kinds: ["dns", "certificate_transparency", "billing", "user_declared"],
    status: "scope_review",
    asset_count: 1,
  })]), []);
  assert.deepEqual(snapshot.cases[0]?.platforms, ["external"]);

  const workspace = adaptNativeCase(platformCaseFixture({
    data_sources: [{
      id: "declared",
      kind: "user_declared",
      label: "Added websites",
      status: "connected",
      connected_at: "2026-08-26T00:00:00Z",
      last_discovered_at: "2026-08-26T00:00:00Z",
      read_only: true,
    }],
    assets: [{
      id: "host-asset",
      kind: "host",
      name: "server.example.test",
      provider: null,
      region: null,
      identifiers: [],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
    }],
    coverage: [{
      id: "coverage-declared",
      label: "Added websites",
      source_kind: "user_declared",
      asset_id: "host-asset",
      status: "authorized_scan_incomplete",
      explanation: "Authorized.",
      observed_at: "2026-08-26T00:00:00Z",
    }],
  }));
  assert.equal(workspace.assets[0]?.platform, "external");
  assert.equal(workspace.assets[0]?.type, "service");
  assert.equal(workspace.coverage[0]?.platform, "external");
  assert.deepEqual(workspace.case.platforms, ["external"]);

  const manifest = adaptNativeManifest(nativeManifestFixture({
    supported_providers: [],
    supported_asset_kinds: ["host", "web_service"],
  }));
  assert.deepEqual(manifest.platforms, ["external"]);
});

test("unrecognized source and asset kinds cannot establish the external platform", () => {
  const snapshot = adaptNativeSnapshot(snapshotFixture([summaryFixture({
    applicable_source_kinds: ["future_source_kind"],
    status: "scope_review",
    asset_count: 1,
  })]), []);
  assert.deepEqual(snapshot.cases[0]?.platforms, []);

  const workspace = adaptNativeCase(platformCaseFixture({
    data_sources: [{
      id: "future-source",
      kind: "future_source_kind",
      label: "Future source",
      status: "connected",
      connected_at: "2026-08-26T00:00:00Z",
      last_discovered_at: "2026-08-26T00:00:00Z",
      read_only: true,
    }, {
      id: "declared",
      kind: "user_declared",
      label: "Added websites",
      status: "connected",
      connected_at: "2026-08-26T00:00:00Z",
      last_discovered_at: "2026-08-26T00:00:00Z",
      read_only: true,
    }],
    assets: [{
      id: "future-asset",
      kind: "future_asset_kind",
      name: "Unknown asset",
      provider: null,
      region: null,
      identifiers: [],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
    }, {
      id: "host-asset",
      kind: "host",
      name: "server.example.test",
      provider: null,
      region: null,
      identifiers: [],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
    }],
    coverage: [{
      id: "coverage-future",
      label: "Future coverage",
      source_kind: "future_source_kind",
      asset_id: "future-asset",
      status: "discovered_authorized_scanned",
      explanation: "A newer backend value must not imply external coverage.",
      observed_at: "2026-08-26T00:00:00Z",
    }, {
      id: "coverage-declared",
      label: "Added websites",
      source_kind: "user_declared",
      asset_id: "host-asset",
      status: "authorized_scan_incomplete",
      explanation: "Authorized.",
      observed_at: "2026-08-26T00:00:00Z",
    }],
  }));
  assert.deepEqual(workspace.assets.map((asset) => asset.id), ["host-asset"]);
  assert.equal(workspace.assets[0]?.platform, "external");
  assert.deepEqual(workspace.coverage.map((entry) => entry.id), ["coverage-declared"]);
  assert.equal(workspace.coverage[0]?.platform, "external");
  assert.deepEqual(workspace.case.platforms, ["external"]);

  const manifest = adaptNativeManifest(nativeManifestFixture({
    supported_providers: [],
    supported_asset_kinds: ["future_asset_kind", "host"],
  }));
  assert.deepEqual(manifest.platforms, ["external"]);

  const unknownOnly = adaptNativeManifest(nativeManifestFixture({
    supported_providers: [],
    supported_asset_kinds: ["future_asset_kind"],
  }));
  assert.deepEqual(unknownOnly.platforms, []);

  const unknownOnlyCase = adaptNativeCase(platformCaseFixture({
    data_sources: [{
      id: "future-source",
      kind: "future_source_kind",
      label: "Future source",
      status: "connected",
      connected_at: "2026-08-26T00:00:00Z",
      last_discovered_at: "2026-08-26T00:00:00Z",
      read_only: true,
    }],
    assets: [{
      id: "future-asset",
      kind: "future_asset_kind",
      name: "Unknown asset",
      provider: null,
      region: null,
      identifiers: [],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
    }],
    coverage: [{
      id: "coverage-future",
      label: "Future coverage",
      source_kind: "future_source_kind",
      asset_id: "future-asset",
      status: "discovered_authorized_scanned",
      explanation: "A newer backend value must not imply external coverage.",
      observed_at: "2026-08-26T00:00:00Z",
    }],
  }));
  assert.deepEqual(unknownOnlyCase.assets, []);
  assert.deepEqual(unknownOnlyCase.coverage, []);
  assert.deepEqual(unknownOnlyCase.case.platforms, []);
});

test("dropping an unrecognized asset preserves its findings and known sibling results", () => {
  const finding = (id: string, assetId: string) => ({
    id,
    case_id: "case-platforms-1",
    first_seen_run_id: "run-1",
    last_seen_run_id: "run-1",
    fingerprint: `fingerprint-${id}`,
    title: id,
    plain_language_summary: "Review this scanner observation.",
    possible_impact: "Impact",
    severity: "medium",
    confidence: "medium",
    priority: 30,
    priority_reasons: [],
    asset_ids: [assetId],
    evidence: [],
    control_references: [],
    recommendation: "Review the source evidence.",
    verification_guidance: "Run the check again.",
    rollback_considerations: null,
    official_references: [],
    recommended_expert_type: "Security reviewer",
    status: "unreviewed",
    tags: [],
  });
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [{
      id: "future-asset",
      kind: "future_asset_kind",
      name: "Future backend asset",
      provider: null,
      region: null,
      identifiers: [],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
    }, {
      id: "host-asset",
      kind: "host",
      name: "server.example.test",
      provider: null,
      region: null,
      identifiers: [],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
    }],
    findings: [
      finding("finding-on-dropped-asset", "future-asset"),
      finding("finding-on-known-asset", "host-asset"),
    ],
  }));

  assert.deepEqual(
    workspace.findings.map(({ id }) => id),
    ["finding-on-dropped-asset", "finding-on-known-asset"],
  );
  assert.deepEqual(workspace.findings[0] && {
    assetId: workspace.findings[0].assetId,
    assetIds: workspace.findings[0].assetIds,
    assetName: workspace.findings[0].assetName,
  }, {
    assetId: "future-asset",
    assetIds: ["future-asset"],
    assetName: "未知資產",
  });
  assert.equal(workspace.findings[1]?.assetName, "server.example.test");
  assert.equal(workspace.case.findingCount, 2);
});

test("native findings preserve unknown confidence instead of substituting a band", () => {
  const finding = (id: string, confidence: string) => ({
    id,
    case_id: "case-platforms-1",
    first_seen_run_id: "run-1",
    last_seen_run_id: "run-1",
    fingerprint: `fingerprint-${id}`,
    title: id,
    plain_language_summary: "Greenbone did not report detection quality.",
    possible_impact: "Impact",
    severity: "medium",
    confidence,
    priority: 30,
    priority_reasons: ["Greenbone did not report detection quality."],
    asset_ids: ["host-asset"],
    evidence: [],
    control_references: [],
    recommendation: "Review the source evidence.",
    verification_guidance: "Run the check again.",
    rollback_considerations: null,
    official_references: [],
    recommended_expert_type: "Vulnerability manager",
    status: "unreviewed",
    tags: [],
    confidence_basis_code: "missing_detection_quality_score",
  });
  const workspace = adaptNativeCase(platformCaseFixture({
    findings: [finding("missing-qod", "unknown"), finding("future-value", "future")],
  }));

  assert.deepEqual(workspace.findings.map((item: { confidence: string }) => item.confidence), [
    "unknown",
    "unknown",
  ]);
});

test("an omitted unrecognized coverage row still informs its known asset", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [{
      id: "host-asset",
      kind: "host",
      name: "server.example.test",
      provider: null,
      region: null,
      identifiers: [],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
    }],
    coverage: [{
      id: "coverage-future-source",
      label: "Future source coverage",
      source_kind: "future_source_kind",
      asset_id: "host-asset",
      status: "discovered_authorized_scanned",
      explanation: "The known asset retains this coverage state.",
      observed_at: "2026-08-26T01:02:03Z",
    }],
  }));

  assert.deepEqual(workspace.coverage, []);
  assert.equal(workspace.assets[0]?.coverageState, "discovered_authorized_scanned");
  assert.equal(workspace.assets[0]?.lastObservedAt, "2026-08-26T01:02:03Z");
});

test("a native generic host remains one external asset with its exact Greenbone profile", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [{
      id: "generic-host",
      kind: "host",
      name: "host.example.test",
      provider: null,
      region: null,
      identifiers: [{ namespace: "dns_name", value: "host.example.test" }],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
      internet_exposed: false,
      metadata: {
        declared_host_scan: {
          target: "host.example.test",
          protocol: "tcp",
          ports: [22, 25, 443, 445, 3389],
          profile: "greenbone_remote_safe_v1",
        },
      },
    }],
  }));

  assert.equal(workspace.assets[0]?.platform, "external");
  assert.deepEqual(workspace.assets[0]?.declaredHostScan, {
    protocol: "tcp",
    ports: [22, 25, 443, 445, 3389],
    scanProfile: "internal_host_greenbone_remote_safe",
  });
});

test("a native RDP transport host remains an external service with its exact declared port", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [{
      id: "rdp-host",
      kind: "host",
      name: "desktop.example.test",
      provider: null,
      region: null,
      identifiers: [{ namespace: "dns_name", value: "desktop.example.test" }],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
      internet_exposed: false,
      metadata: {
        declared_network_service: {
          protocol: "tcp",
          port: 3389,
          scan_profile: "internal_endpoint_rdp_tls",
        },
      },
    }],
  }));

  assert.equal(workspace.assets[0]?.type, "service");
  assert.equal(workspace.assets[0]?.platform, "external");
  assert.deepEqual(workspace.assets[0]?.declaredNetworkService, {
    protocol: "tcp",
    port: 3389,
    scanProfile: "internal_endpoint_rdp_tls",
  });
});

test("a native VNC host remains an external service with its exact declared port", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [{
      id: "vnc-host",
      kind: "host",
      name: "workstation.example.test",
      provider: null,
      region: null,
      identifiers: [{ namespace: "dns_name", value: "workstation.example.test" }],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
      internet_exposed: false,
      metadata: {
        declared_network_service: {
          protocol: "tcp",
          port: 5900,
          scan_profile: "internal_endpoint_vnc",
        },
      },
    }],
  }));

  assert.equal(workspace.assets[0]?.type, "service");
  assert.equal(workspace.assets[0]?.platform, "external");
  assert.deepEqual(workspace.assets[0]?.declaredNetworkService, {
    protocol: "tcp",
    port: 5900,
    scanProfile: "internal_endpoint_vnc",
  });
});

test("identity and cloud resources keep their own asset types", () => {
  const asset = (id: string, kind: string, provider: string | null) => ({
    id,
    kind,
    name: id,
    provider,
    region: null,
    identifiers: [],
    discovered_from: [],
    candidate: true,
    owner_confirmed: false,
  });
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [
      asset("m365-user", "identity", "microsoft365"),
      asset("aws-role", "cloud_resource", "aws"),
      asset("ssh-host", "host", null),
      asset("website", "web_service", null),
    ],
  }));
  const typeById = new Map(workspace.assets.map((item: { id: string; type: string }) => [item.id, item.type]));
  assert.equal(typeById.get("m365-user"), "identity");
  assert.equal(typeById.get("aws-role"), "cloud_resource");
  assert.equal(typeById.get("ssh-host"), "service");
  assert.equal(typeById.get("website"), "service");
});

test("native findings keep unknown severity distinct from informational", () => {
  const finding = (id: string, severity: string) => ({
    id,
    case_id: "case-platforms-1",
    first_seen_run_id: "run-1",
    last_seen_run_id: "run-1",
    fingerprint: `fingerprint-${id}`,
    title: id,
    plain_language_summary: "Review this scanner observation.",
    possible_impact: "Impact was not rated by the source.",
    severity,
    confidence: "medium",
    priority: 20,
    priority_reasons: [`Source severity: ${severity}`],
    asset_ids: ["repository-asset"],
    evidence: [],
    control_references: [],
    recommendation: "Ask a qualified reviewer.",
    verification_guidance: "Review the source evidence.",
    rollback_considerations: null,
    official_references: [],
    recommended_expert_type: "Security reviewer",
    status: "unreviewed",
    tags: [],
  });
  const workspace = adaptNativeCase(platformCaseFixture({
    findings: [
      finding("backend-unknown", "unknown"),
      finding("unrecognized", "vendor-special"),
      finding("explicit-info", "informational"),
    ],
  }));

  assert.deepEqual(
    workspace.findings.map(({ id, severity }: { id: string; severity: string }) => [id, severity]),
    [
      ["backend-unknown", "unknown"],
      ["unrecognized", "unknown"],
      ["explicit-info", "info"],
    ],
  );
});

test("canonical evidence retains scanner-authored detail and typed AWS IAM context", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    findings: [{
      id: "finding-scanner-detail",
      case_id: "case-platforms-1",
      first_seen_run_id: "run-1",
      last_seen_run_id: "run-1",
      fingerprint: "fingerprint-scanner-detail",
      title: "Scanner detail",
      plain_language_summary: "Review this scanner observation.",
      possible_impact: "Impact",
      severity: "high",
      confidence: "medium",
      priority: 50,
      priority_reasons: [],
      asset_ids: ["repository-asset"],
      evidence: [{
        id: "evidence-scanner-detail",
        finding_id: "finding-scanner-detail",
        run_id: "run-1",
        engine_run_id: "task-1",
        kind: "configuration",
        engine_id: "cloudsplaining",
        source_rule: "DataExfiltration",
        scanner_details: {
          description: "Scanner description",
          remediation: "Scanner remediation",
          installed_version: "1.0.0",
          fixed_version: "1.0.1",
          aws_iam_policy: {
            policy_source: "inline",
            policy_name: "DeploymentInlinePolicy",
            finding_identity: "DataExfiltration",
            actions: ["s3:GetObject"],
            actions_complete: true,
            attached_to: {
              roles: ["DeploymentRole"],
              groups: [],
              users: ["release-user"],
              complete: true,
            },
          },
        },
        observed_at: "2026-09-04T12:00:00Z",
        summary: "Evidence summary",
        artifact_id: "artifact-1",
        artifact_sha256: "a".repeat(64),
        pointer: null,
        redacted: false,
      }],
      control_references: [],
      recommendation: "Use the product recommendation.",
      verification_guidance: "Rerun the check.",
      rollback_considerations: null,
      official_references: [],
      recommended_expert_type: "Security reviewer",
      status: "unreviewed",
      tags: [],
    }],
  }));

  assert.deepEqual(workspace.findings[0]?.evidence[0]?.scannerDetails, {
    description: "Scanner description",
    remediation: "Scanner remediation",
    installedVersion: "1.0.0",
    fixedVersion: "1.0.1",
    awsIamPolicy: {
      policySource: "inline",
      policyName: "DeploymentInlinePolicy",
      findingIdentity: "DataExfiltration",
      actions: ["s3:GetObject"],
      actionsComplete: true,
      attachedTo: {
        roles: ["DeploymentRole"],
        groups: [],
        users: ["release-user"],
        complete: true,
      },
    },
  });
  assert.deepEqual(workspace.findings[0]?.awsIamPolicy, {
    policySource: "inline",
    policyName: "DeploymentInlinePolicy",
    findingIdentity: "DataExfiltration",
    actions: ["s3:GetObject"],
    actionsComplete: true,
    attachedTo: {
      roles: ["DeploymentRole"],
      groups: [],
      users: ["release-user"],
      complete: true,
    },
  });
  assert.equal(workspace.findings[0]?.recommendation, "Use the product recommendation.");
});

test("canonical evidence redaction claims only the exact boolean and preserves absence", () => {
  const redactedFor = (redacted: unknown, omit = false) => adaptNativeCase(platformCaseFixture({
    findings: [{
      id: "finding-redaction",
      case_id: "case-platforms-1",
      first_seen_run_id: "run-1",
      last_seen_run_id: "run-1",
      fingerprint: "fingerprint-redaction",
      title: "Redaction claim",
      plain_language_summary: "Review this scanner observation.",
      possible_impact: "Impact",
      severity: "low",
      confidence: "medium",
      priority: 20,
      priority_reasons: [],
      asset_ids: ["repository-asset"],
      evidence: [{
        id: "evidence-redaction",
        finding_id: "finding-redaction",
        run_id: "run-1",
        engine_id: "gitleaks",
        observed_at: "2026-09-04T12:00:00Z",
        summary: "Evidence summary",
        artifact_sha256: "a".repeat(64),
        pointer: null,
        ...(omit ? {} : { redacted }),
      }],
      control_references: [],
      recommendation: "Ask a qualified reviewer.",
      official_references: [],
      recommended_expert_type: "Security reviewer",
      status: "unreviewed",
    }],
  })).findings[0]?.evidence[0]?.redacted;

  assert.equal(redactedFor(true), true);
  assert.equal(redactedFor(false), false);
  assert.equal(redactedFor(undefined, true), undefined);
  for (const redacted of [1, "false", {}, "true"]) {
    assert.equal(redactedFor(redacted), undefined);
  }
});

test("native AWS IAM detail mapping drops malformed context without dropping sibling evidence", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    findings: [{
      id: "finding-malformed-iam-detail",
      case_id: "case-platforms-1",
      first_seen_run_id: "run-1",
      last_seen_run_id: "run-1",
      fingerprint: "fingerprint-malformed-iam-detail",
      title: "Malformed IAM detail",
      plain_language_summary: "Review this scanner observation.",
      possible_impact: "Impact",
      severity: "high",
      confidence: "medium",
      priority: 50,
      priority_reasons: [],
      asset_ids: ["repository-asset"],
      evidence: [{
        id: "evidence-malformed-iam-detail",
        finding_id: "finding-malformed-iam-detail",
        run_id: "run-1",
        engine_run_id: "task-1",
        kind: "configuration",
        engine_id: "cloudsplaining",
        source_rule: "PrivilegeEscalation",
        scanner_details: {
          description: "The scanner description remains useful.",
          aws_iam_policy: {
            policy_source: "product_guessed",
            policy_name: "UnsafePolicy",
            finding_identity: "PrivilegeEscalation",
            actions: ["iam:PassRole"],
            attached_to: {
              roles: ["ApplicationRole"],
              groups: [],
              users: [],
              complete: true,
            },
          },
        },
        observed_at: "2026-09-04T12:00:00Z",
        summary: "Evidence summary",
        artifact_id: "artifact-1",
        artifact_sha256: "a".repeat(64),
        pointer: "/CustomerManagedPolicies/UnsafePolicy/PrivilegeEscalation/0",
        redacted: false,
      }, {
        id: "evidence-non-cloud-iam-detail",
        finding_id: "finding-malformed-iam-detail",
        run_id: "run-1",
        engine_run_id: "task-1",
        kind: "configuration",
        engine_id: "trivy",
        source_rule: "CVE-2026-12345",
        scanner_details: {
          description: "The non-cloud scanner description remains useful.",
          aws_iam_policy: {
            policy_source: "aws_managed",
            policy_name: "MustNotDriveNarrative",
            finding_identity: "CreateAccessKey",
            actions: ["iam:CreateAccessKey"],
            actions_complete: true,
            attached_to: {
              roles: ["BuildRole"],
              groups: [],
              users: [],
              complete: true,
            },
          },
        },
        observed_at: "2026-09-04T12:00:00Z",
        summary: "Non-cloud evidence summary",
        artifact_id: "artifact-1",
        artifact_sha256: "b".repeat(64),
        pointer: "/Results/0",
        redacted: false,
      }],
      control_references: [],
      recommendation: "Use the product recommendation.",
      verification_guidance: "Rerun the check.",
      rollback_considerations: null,
      official_references: [],
      recommended_expert_type: "Cloud identity specialist",
      status: "unreviewed",
      tags: [],
    }],
  }));

  assert.equal(workspace.findings[0]?.awsIamPolicy, undefined);
  assert.equal(
    workspace.findings[0]?.evidence[0]?.scannerDetails?.description,
    "The scanner description remains useful.",
  );
  assert.equal(workspace.findings[0]?.evidence[0]?.scannerDetails?.awsIamPolicy, undefined);
  assert.equal(
    workspace.findings[0]?.evidence[1]?.scannerDetails?.description,
    "The non-cloud scanner description remains useful.",
  );
  assert.equal(workspace.findings[0]?.evidence[1]?.scannerDetails?.awsIamPolicy, undefined);
});

test("draft full cases with no assets or applicable sources use the assessment route fallback", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assessment_intent: "source_code",
    status: "draft",
    data_sources: [{
      id: "aws-placeholder",
      kind: "aws_organization",
      label: "AWS not used",
      status: "not_applicable",
      connected_at: null,
      last_discovered_at: null,
      read_only: true,
    }],
    assets: [],
  }));

  assert.deepEqual(workspace.case.platforms, ["code"]);
});

test("an unknown source connection status never claims that the source is connected", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    data_sources: [{
      id: "future-source",
      kind: "aws_organization",
      label: "Future source",
      status: "connected_by_future_build",
      connected_at: "2026-08-26T00:00:00Z",
      last_discovered_at: "2026-08-26T00:00:00Z",
      read_only: true,
    }],
  }));

  assert.equal(workspace.sources[0]?.status, "not_connected");
});

test("native source read-only claims require exact booleans", () => {
  const readOnlyFor = (read_only: unknown) => adaptNativeCase(platformCaseFixture({
    data_sources: [{
      id: "source-read-only-boundary",
      kind: "aws_organization",
      label: "AWS source",
      status: "connected",
      connected_at: "2026-08-26T00:00:00Z",
      last_discovered_at: "2026-08-26T00:00:00Z",
      read_only,
    }],
  })).sources[0]?.readOnly;

  assert.equal(readOnlyFor(true), true);
  assert.equal(readOnlyFor(false), false);
  for (const readOnly of [undefined, null, "true", 1, {}, []]) {
    assert.equal(readOnlyFor(readOnly), false);
  }
});

test("questionnaire-only local names stay distinct from attached workspace snapshots", () => {
  assert.ok(adapterSource.includes("localQuestionnaireKinds"));
  assert.ok(adapterSource.includes("questionnairePlaceholder:"));
  assert.ok(adapterSource.includes('asset.metadata?.workspace_snapshot_id === "string"'));
});

test("native assets preserve the exact data-source provenance used for cloud binding", () => {
  const workspace = adaptNativeCase({
    id: "case-1",
    title: "Two AWS accounts",
    assessment_intent: "cloud_account",
    profile: {
      organization_name: "Example",
      employee_range: "small",
      data_classes: [],
      notes: null,
    },
    status: "scope_review",
    created_at: "2026-08-26T00:00:00Z",
    updated_at: "2026-08-26T00:00:00Z",
    is_demo: false,
    requested_activities: ["configuration_assessment"],
    data_sources: [
      {
        id: "aws-source-a",
        kind: "aws_organization",
        label: "AWS account A",
        status: "connected",
        connected_at: "2026-08-26T00:00:00Z",
        last_discovered_at: "2026-08-26T00:00:00Z",
        read_only: true,
      },
      {
        id: "aws-source-b",
        kind: "aws_organization",
        label: "AWS account B",
        status: "connected",
        connected_at: "2026-08-26T00:00:00Z",
        last_discovered_at: "2026-08-26T00:00:00Z",
        read_only: true,
      },
    ],
    assets: [{
      id: "aws-account-a",
      kind: "cloud_account",
      name: "AWS account A",
      provider: "aws",
      region: null,
      identifiers: [{ namespace: "aws_account_id", value: "111111111111" }],
      discovered_from: ["aws-source-a"],
      candidate: true,
      owner_confirmed: false,
      internet_exposed: null,
      contains_sensitive_data: null,
      metadata: {},
    }],
    scope_grants: [],
    coverage: [],
    scan_runs: [],
    findings: [],
    exports: [],
    comparisons: [],
  });

  assert.deepEqual(workspace.assets[0]?.discoveredFromSourceIds, ["aws-source-a"]);
});

test("native adapter repairs stale public display for an explicit loopback asset", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [{
      id: "loopback-asset",
      kind: "ip_address",
      name: "127.0.0.1",
      provider: null,
      region: null,
      identifiers: [{ namespace: "ip_address", value: "127.0.0.1" }],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
      internet_exposed: true,
      metadata: { questionnaire_kind: "external_target" },
    }],
    data_sources: [],
  }));

  assert.equal(workspace.assets[0]?.internetExposed, false);
});

test("native adapter repairs stale public display for an explicit private CIDR", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [{
      id: "private-network-asset",
      kind: "ip_address",
      name: "192.168.102.0/23",
      provider: null,
      region: null,
      identifiers: [{ namespace: "ip_address", value: "192.168.102.0/23" }],
      discovered_from: [],
      candidate: true,
      owner_confirmed: false,
      internet_exposed: true,
      metadata: { questionnaire_kind: "external_target" },
    }],
    data_sources: [],
  }));

  assert.equal(workspace.assets[0]?.internetExposed, false);
});

test("owner confirmation becomes an authorized coverage state only as an exact boolean", () => {
  const coverageFor = (owner_confirmed: unknown) => adaptNativeCase(platformCaseFixture({
    assets: [{
      id: "repository-asset",
      kind: "repository",
      name: "Repository",
      provider: null,
      region: null,
      identifiers: [],
      discovered_from: [],
      candidate: false,
      owner_confirmed,
      metadata: {},
    }],
    coverage: [],
  })).assets[0]?.coverageState;

  assert.equal(coverageFor(true), "authorized_incomplete");
  assert.equal(coverageFor(false), "source_unavailable_unknown");
  assert.equal(coverageFor(undefined), "source_unavailable_unknown");
  for (const owner_confirmed of [1, "false", {}, "true"]) {
    assert.equal(coverageFor(owner_confirmed), "source_unavailable_unknown");
  }
});

test("authorized coverage distinguishes a saved permission from an attempted scan", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [{
      id: "loopback-asset",
      kind: "ip_address",
      name: "127.0.0.1",
      provider: null,
      region: null,
      identifiers: [{ namespace: "ip_address", value: "127.0.0.1" }],
      discovered_from: [],
      candidate: false,
      owner_confirmed: true,
      internet_exposed: false,
      metadata: { questionnaire_kind: "external_target" },
    }],
    data_sources: [],
    scope_grants: [{
      id: "scope-loopback",
      asset_id: "loopback-asset",
      permission: "low_impact_external_connection",
      confirmed_by: "Owner",
      confirmed_at: "2026-08-26T00:00:00Z",
      notes: null,
      external_scope: null,
    }],
    coverage: [{
      id: "coverage-loopback",
      label: "127.0.0.1",
      source_kind: "user_declared",
      asset_id: "loopback-asset",
      status: "authorized_scan_incomplete",
      explanation: "Authorized, but no scan plan exists yet.",
      last_run_id: null,
      observed_at: "2026-08-26T00:00:00Z",
    }],
    scan_runs: [],
  }));

  assert.equal(workspace.assets[0]?.authorizationState, "authorized");
  assert.equal(workspace.assets[0]?.scanAttempted, false);
  assert.equal(workspace.coverage[0]?.scanAttempted, false);
  assert.equal(workspace.coverage[0]?.assetId, "loopback-asset");
});

test("unknown native scope permissions cannot create authorization", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    scope_grants: [{
      id: "scope-future",
      asset_id: "repository-asset",
      permission: "future_permission",
      confirmed_by: "Owner",
      confirmed_at: "2026-08-26T00:00:00Z",
      notes: null,
      external_scope: null,
    }],
  }));

  assert.equal(workspace.assets[0]?.authorizationState, "unknown");
  assert.deepEqual(workspace.assets[0]?.allowedModes, []);
  assert.deepEqual(workspace.scopeGrants, []);
});

const frozenExternalScopeFixture = (overrides: Record<string, unknown> = {}) => {
  const templatePolicy = {
    revision: "nuclei-safe-v1",
    profile_id: "nuclei_safe_http",
    allowed_template_ids: [],
    allow_headless: false,
    allow_out_of_band: false,
    allow_fuzzing: false,
    allow_file_upload: false,
    allow_denial_of_service: false,
    allow_credential_attacks: false,
    ...(overrides.template_policy as Record<string, unknown> | undefined),
  };
  return {
    id: "external-scope-1",
    case_id: "case-platforms-1",
    asset_id: "repository-asset",
    target: { kind: "hostname", value: "example.test" },
    ports: [443],
    protocol: "https",
    activity: "active_external",
    rate_policy: { requests_per_second: 5, concurrency: 2, timeout_seconds: 10 },
    asserted_authority: "Approved test target",
    approved_by: "Owner",
    approved_at: "2026-08-26T00:00:00Z",
    expires_at: "2026-09-26T00:00:00Z",
    allow_sensitive_networks: false,
    ...overrides,
    template_policy: templatePolicy,
  };
};

const caseWithExternalScope = (externalScope: unknown, omit = false) => adaptNativeCase(platformCaseFixture({
  scope_grants: [{
    id: "scope-external",
    asset_id: "repository-asset",
    permission: "active_external_testing",
    confirmed_by: "Owner",
    confirmed_at: "2026-08-26T00:00:00Z",
    notes: null,
    ...(omit ? {} : { external_scope: externalScope }),
  }],
}));

test("frozen external scopes preserve absence and drop malformed authorization claims", () => {
  assert.equal(caseWithExternalScope(undefined, true).scopeGrants[0]?.externalScope, undefined);
  assert.equal(caseWithExternalScope(null).scopeGrants[0]?.externalScope, undefined);
  assert.deepEqual(caseWithExternalScope(frozenExternalScopeFixture()).scopeGrants[0]?.externalScope, {
    id: "external-scope-1",
    caseId: "case-platforms-1",
    assetId: "repository-asset",
    target: "example.test",
    targetKind: "hostname",
    ports: [443],
    protocol: "https",
    activity: "active_external",
    ratePolicy: { requestsPerSecond: 5, concurrency: 2, timeoutSeconds: 10 },
    templatePolicy: {
      revision: "nuclei-safe-v1",
      profileId: "nuclei_safe_http",
      allowedTemplateIds: [],
      allowHeadless: false,
      allowOutOfBand: false,
      allowFuzzing: false,
      allowFileUpload: false,
      allowDenialOfService: false,
      allowCredentialAttacks: false,
    },
    assertedAuthority: "Approved test target",
    approvedBy: "Owner",
    approvedAt: "2026-08-26T00:00:00Z",
    expiresAt: "2026-09-26T00:00:00Z",
    allowSensitiveNetworks: false,
  });

  const malformedScopes = [
    frozenExternalScopeFixture({ target: { kind: "future_target", value: "example.test" } }),
    frozenExternalScopeFixture({ protocol: "future_protocol" }),
    frozenExternalScopeFixture({ activity: "future_activity" }),
    ...[
      "allow_headless",
      "allow_out_of_band",
      "allow_fuzzing",
      "allow_file_upload",
    ].map((field) => frozenExternalScopeFixture({ template_policy: { [field]: "false" } })),
    frozenExternalScopeFixture({ template_policy: { allow_denial_of_service: true } }),
    frozenExternalScopeFixture({ template_policy: { allow_credential_attacks: true } }),
    frozenExternalScopeFixture({ allow_sensitive_networks: "false" }),
  ];
  const siblingFinding = {
    id: "finding-kept",
    case_id: "case-platforms-1",
    first_seen_run_id: "run-1",
    last_seen_run_id: "run-1",
    fingerprint: "fingerprint-finding-kept",
    title: "Retained finding",
    plain_language_summary: "Review this scanner observation.",
    possible_impact: "Impact was not rated by the source.",
    severity: "high",
    confidence: "medium",
    priority: 50,
    priority_reasons: [],
    asset_ids: ["repository-asset"],
    evidence: [],
    control_references: [],
    recommendation: "Ask a qualified reviewer.",
    verification_guidance: "Review the source evidence.",
    rollback_considerations: null,
    official_references: [],
    recommended_expert_type: "Security reviewer",
    status: "unreviewed",
    tags: [],
  };
  for (const scope of malformedScopes) {
    const workspace = adaptNativeCase(platformCaseFixture({
      scope_grants: [{
        id: "scope-external",
        asset_id: "repository-asset",
        permission: "active_external_testing",
        confirmed_by: "Owner",
        confirmed_at: "2026-08-26T00:00:00Z",
        notes: null,
        external_scope: scope,
      }, {
        id: "scope-sibling",
        asset_id: "repository-asset",
        permission: "local_artifact_read",
        confirmed_by: "Owner",
        confirmed_at: "2026-08-26T00:00:00Z",
        notes: null,
        external_scope: null,
      }],
      findings: [siblingFinding],
    }));
    const malformedGrant = workspace.scopeGrants.find((grant) => grant.id === "scope-external");
    const siblingGrant = workspace.scopeGrants.find((grant) => grant.id === "scope-sibling");
    assert.equal(workspace.scopeGrants.length, 2);
    assert.equal(malformedGrant?.externalScope, undefined);
    assert.deepEqual(malformedGrant?.modes, ["active_external"]);
    assert.deepEqual(siblingGrant?.modes, ["local_artifact"]);
    assert.equal(siblingGrant?.externalScope, undefined);
    assert.equal(workspace.findings.length, 1);
    assert.equal(workspace.findings[0]?.id, "finding-kept");
    assert.equal(workspace.findings[0]?.title, "Retained finding");
  }
});

const engineRunFixture = (id: string, status: string) => ({
  id,
  engine_id: id,
  asset_ids: ["repository-asset"],
  status,
  progress_percent: status === "queued" ? 0 : 100,
  phase: status,
  started_at: status === "queued" ? null : "2026-08-26T00:00:00Z",
  finished_at: status === "queued" ? null : "2026-08-26T00:01:00Z",
  resume_token: null,
  engine_version: "test",
  image_digest: null,
  rule_version: null,
  adapter_version: "test",
  raw_artifact_ids: [],
  error_code: status === "failed" ? "execution_failed" : null,
  error_message: status === "failed" ? "bounded test failure" : null,
});

test("engine run reported_version maps to reportedVersion and an absent key stays undefined", () => {
  const runFor = (reportedVersion: "present" | "padded" | "null" | "blank" | "absent") => adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "run-reported-version",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-26T00:00:00Z",
      completed_at: "2026-08-26T00:01:00Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      engine_runs: [{
        ...engineRunFixture("trufflehog", "completed"),
        ...(reportedVersion === "present"
          ? { reported_version: "3.97.0" }
          : reportedVersion === "padded"
            ? { reported_version: "  3.97.0  " }
            : reportedVersion === "null"
              ? { reported_version: null }
              : reportedVersion === "blank"
                ? { reported_version: "   " }
                : {}),
      }],
    }],
  })).runs[0]?.engineRuns[0];

  assert.equal(runFor("present")?.reportedVersion, "3.97.0");
  assert.equal(runFor("padded")?.reportedVersion, "3.97.0");
  assert.equal(runFor("absent")?.reportedVersion, undefined);
  assert.equal(runFor("null")?.reportedVersion, undefined);
  assert.equal(runFor("blank")?.reportedVersion, undefined);

  const localhost = adaptLocalhostCoverageFixture({ reported_version: "3.97.0" }).runs[0]?.engineRuns[0];
  assert.equal(localhost?.version, undefined);
  assert.equal(localhost?.reportedVersion, undefined);
});

test("engine result artifact counts exclude only backend stream captures and fail closed", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    raw_artifacts: [{
      id: "stdout-capture",
      relative_path: "case/run/engine/attempt-1/raw/stdout.log",
    }, {
      id: "stderr-capture",
      relative_path: "case/run/engine/attempt-1/raw/stderr.log",
    }, {
      id: "engine-output",
      relative_path: "case/run/engine/attempt-1/output/raw/stdout.log",
    }, {
      id: "malformed-path",
      relative_path: 42,
    }],
    scan_runs: [{
      id: "run-result-artifacts",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-26T00:00:00Z",
      completed_at: "2026-08-26T00:01:00Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      engine_runs: [{
        ...engineRunFixture("engine-stream-captures", "failed"),
        raw_artifact_ids: ["stdout-capture", "stderr-capture"],
      }, {
        ...engineRunFixture("engine-result-artifacts", "failed"),
        raw_artifact_ids: [
          "engine-output",
          "missing-record",
          "malformed-path",
        ],
      }],
    }],
  }));

  assert.equal(workspace.runs[0]?.engineRuns[0]?.rawArtifactCount, 2);
  assert.equal(workspace.runs[0]?.engineRuns[0]?.savedResultArtifactCount, 0);
  assert.equal(workspace.runs[0]?.engineRuns[1]?.rawArtifactCount, 3);
  assert.equal(workspace.runs[0]?.engineRuns[1]?.savedResultArtifactCount, 1);
});

test("scan attempts require a valid task that entered execution", () => {
  const attemptedFor = (engineRun: Record<string, unknown> | undefined, lastRunId: unknown = null) => {
    const workspace = adaptNativeCase(platformCaseFixture({
      coverage: [{
        id: "coverage-attempt",
        label: "Repository",
        source_kind: "file_system",
        asset_id: "repository-asset",
        status: "authorized_scan_incomplete",
        explanation: "Attempt state under test.",
        last_run_id: lastRunId,
        observed_at: "2026-08-26T00:01:00Z",
      }],
      scan_runs: engineRun ? [{
        id: "run-attempt",
        case_id: "case-platforms-1",
        sequence: 1,
        created_at: "2026-08-26T00:00:00Z",
        completed_at: "2026-08-26T00:01:00Z",
        knowledge_cutoff: "2026-08-24T00:00:00Z",
        engine_runs: [engineRun],
      }] : [],
    }));
    return [workspace.assets[0]?.scanAttempted, workspace.coverage[0]?.scanAttempted];
  };

  assert.deepEqual(
    attemptedFor(undefined, "run-attempt"),
    [true, true],
    "a retained last-run ID remains an attempt when the run is not in the loaded set",
  );
  assert.deepEqual(attemptedFor(undefined, undefined), [false, false], "legacy absence remains non-assertive");
  assert.deepEqual(attemptedFor(undefined, null), [false, false]);
  assert.deepEqual(attemptedFor(undefined, ""), [false, false]);
  for (const standIn of [1, true, {}]) {
    assert.deepEqual(attemptedFor(undefined, standIn), [false, false]);
  }
  assert.deepEqual(attemptedFor(engineRunFixture("queued-task", "queued")), [false, false]);
  assert.deepEqual(attemptedFor({
    ...engineRunFixture("unknown-status", "completed"),
    status: "future_status",
  }), [false, false]);
  assert.deepEqual(attemptedFor({
    ...engineRunFixture("invalid-task", "completed"),
    task_kind: { kind: "future_task" },
  }), [false, false]);
  assert.deepEqual(attemptedFor({
    ...engineRunFixture("missing-start", "completed"),
    started_at: null,
  }), [false, false]);
  assert.deepEqual(
    attemptedFor(engineRunFixture("legacy-catalog-task", "completed")),
    [true, true],
    "an absent legacy task kind keeps its defined catalog-engine meaning",
  );
});

test("mixed terminal and queued engine work keeps the scan queued for downstream pages", () => {
  for (const terminalStatus of [
    "completed",
    "partially_completed",
    "failed",
    "not_executed",
    "cancelled",
  ]) {
    const workspace = adaptNativeCase(platformCaseFixture({
      status: "scanning",
      scan_runs: [{
        id: `run-${terminalStatus}`,
        case_id: "case-platforms-1",
        sequence: 1,
        created_at: "2026-08-26T00:00:00Z",
        completed_at: null,
        knowledge_cutoff: "2026-08-24T00:00:00Z",
        engine_runs: [
          engineRunFixture(`engine-${terminalStatus}`, terminalStatus),
          engineRunFixture("engine-queued", "queued"),
        ],
      }],
    }));

    assert.equal(workspace.runs[0]?.engineRuns[1]?.status, "pending", terminalStatus);
    assert.equal(workspace.runs[0]?.status, "queued", terminalStatus);
  }
});

test("a completed check beside settled-skip checks still reports the run as completed, but settled skips alone do not", () => {
  const settledSkip = (id: string, errorCode: string) => ({
    ...engineRunFixture(id, "not_executed"),
    task_kind: { kind: "catalog_engine" },
    error_code: errorCode,
  });

  const withCompletedSibling = adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "run-settled-skip-status",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-26T00:00:00Z",
      completed_at: "2026-08-26T00:01:00Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      engine_runs: [
        { ...engineRunFixture("trivy-task", "completed"), task_kind: { kind: "catalog_engine" } },
        settledSkip("mcp-armor", "mcp_configuration_absent"),
        settledSkip("agentic-radar", "engine_release_unavailable"),
      ],
    }],
  }));
  assert.equal(
    withCompletedSibling.runs[0]?.status,
    "completed",
    "a completed check beside two settled skips is a completed run",
  );

  const onlySettledSkips = adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "run-only-settled-skips",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-26T00:00:00Z",
      completed_at: "2026-08-26T00:01:00Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      engine_runs: [
        settledSkip("mcp-armor", "mcp_configuration_absent"),
        settledSkip("agentic-radar", "engine_release_unavailable"),
      ],
    }],
  }));
  assert.equal(
    onlySettledSkips.runs[0]?.status,
    "failed",
    "a run made only of settled skips has done no security work and is not completed",
  );
});

test("present catalog engine tasks preserve scanner completion and coverage", () => {
  const known = adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "run-catalog-task",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-26T00:00:00Z",
      completed_at: "2026-08-26T00:01:00Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      engine_runs: [{
        ...engineRunFixture("catalog-task", "completed"),
        task_kind: { kind: "catalog_engine" },
      }],
    }],
  }));
  assert.deepEqual(known.runs[0]?.engineRuns[0]?.taskKind, { kind: "catalog_engine" });
  assert.equal(known.runs[0]?.engineRuns[0]?.status, "completed");
  assert.equal(known.runs[0]?.coveredAssetCount, 1);
});

test("coveredAssetIds excludes settled skips: they neither grant coverage alone nor block a completed sibling's coverage", () => {
  const settledSkip = (id: string, errorCode: string) => ({
    ...engineRunFixture(id, "not_executed"),
    task_kind: { kind: "catalog_engine" },
    error_code: errorCode,
    asset_ids: ["repository-asset"],
  });

  const skipAlone = adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "run-settled-skip-coverage-alone",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-26T00:00:00Z",
      completed_at: "2026-08-26T00:01:00Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      engine_runs: [settledSkip("mcp-armor", "mcp_configuration_absent")],
    }],
  }));
  assert.equal(skipAlone.runs[0]?.totalAssetCount, 1);
  assert.equal(skipAlone.runs[0]?.coveredAssetCount, 0, "a settled skip alone grants no coverage");

  const skipWithCompletedSibling = adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "run-settled-skip-coverage-with-sibling",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-26T00:00:00Z",
      completed_at: "2026-08-26T00:01:00Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      engine_runs: [
        {
          ...engineRunFixture("trivy-task", "completed"),
          task_kind: { kind: "catalog_engine" },
          asset_ids: ["repository-asset"],
        },
        settledSkip("mcp-armor", "mcp_configuration_absent"),
      ],
    }],
  }));
  assert.equal(
    skipWithCompletedSibling.runs[0]?.coveredAssetCount,
    1,
    "a settled skip beside a completed check on the same asset does not block coverage",
  );
});

test("unevaluated targets preserve known causes, legacy absence, and fail closed on unknown values", () => {
  const adapted = (unevaluatedTargets: unknown, omit = false) => adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "run-unevaluated",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-26T00:00:00Z",
      completed_at: "2026-08-26T00:01:00Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      engine_runs: [{
        ...engineRunFixture("greenbone-task", "completed"),
        ...(omit ? {} : { unevaluated_targets: unevaluatedTargets }),
      }],
    }],
  })).runs[0]?.engineRuns[0]?.unevaluatedTargets;

  assert.equal(adapted(undefined, true), undefined);
  assert.equal(adapted(null), undefined);
  assert.equal(adapted([]), undefined);
  assert.equal(adapted([{ cause: "target_did_not_respond", result_count: 1 }]), undefined);
  assert.equal(adapted([{ asset_id: "", cause: "target_did_not_respond" }]), undefined);
  assert.equal(adapted([{ asset_id: null, cause: "scanner_error" }]), undefined);

  assert.deepEqual(adapted([
    { asset_id: "host-dead", cause: "target_did_not_respond", result_count: 1 },
    { asset_id: "host-error", cause: "scanner_error", result_count: 2 },
    { asset_id: "host-template", cause: "no_security_template_execution_evidence", result_count: 0 },
    { asset_id: "host-future", cause: "future_cause", result_count: 4 },
    { asset_id: "host-absent-cause", result_count: 1 },
    { asset_id: "host-non-string-cause", cause: true, result_count: 1 },
    { cause: "target_did_not_respond", result_count: 3 },
    { asset_id: "", cause: "scanner_error" },
  ]), [
    { assetId: "host-dead", cause: "target_did_not_respond" },
    { assetId: "host-error", cause: "scanner_error" },
    { assetId: "host-template", cause: "no_security_template_execution_evidence" },
    { assetId: "host-future", cause: "unknown" },
    { assetId: "host-absent-cause", cause: "unknown" },
    { assetId: "host-non-string-cause", cause: "unknown" },
  ]);
});

test("a completed catalog run leaves a recorded unevaluated asset uncovered and still covers its evaluated sibling", () => {
  const coverageFor = (cause: string) => {
    const workspace = adaptNativeCase(platformCaseFixture({
      scan_runs: [{
        id: "run-unevaluated-coverage",
        case_id: "case-platforms-1",
        sequence: 1,
        created_at: "2026-08-26T00:00:00Z",
        completed_at: "2026-08-26T00:01:00Z",
        knowledge_cutoff: "2026-08-24T00:00:00Z",
        engine_runs: [{
          ...engineRunFixture("greenbone-task", "completed"),
          task_kind: { kind: "catalog_engine" },
          asset_ids: ["dead-host", "checked-host"],
          unevaluated_targets: [{ asset_id: "dead-host", cause }],
        }],
      }],
    }));
    const scan = workspace.runs[0];
    return {
      covered: scan?.coveredAssetCount,
      total: scan?.totalAssetCount,
      cause: scan?.engineRuns[0]?.unevaluatedTargets?.[0]?.cause,
    };
  };

  const named = coverageFor("target_did_not_respond");
  assert.equal(named.total, 2);
  assert.equal(named.cause, "target_did_not_respond");
  assert.equal(named.covered, 1);

  // An "unknown" cause keeps today's coverage. The parity test is what binds
  // a new Rust variant before it can reach users unnamed.
  const unrecognized = coverageFor("future_cause");
  assert.equal(unrecognized.total, 2);
  assert.equal(unrecognized.cause, "unknown");
  assert.equal(unrecognized.covered, 2);
});

test("legacy engine tasks without provenance preserve catalog completion and coverage", () => {
  const legacy = adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "run-legacy-catalog-task",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-26T00:00:00Z",
      completed_at: "2026-08-26T00:01:00Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      engine_runs: [engineRunFixture("legacy-catalog-task", "completed")],
    }],
  }));
  assert.deepEqual(legacy.runs[0]?.engineRuns[0]?.taskKind, { kind: "catalog_engine" });
  assert.equal(legacy.runs[0]?.engineRuns[0]?.status, "completed");
  assert.equal(legacy.runs[0]?.coveredAssetCount, 1);
});

test("unknown or malformed native tasks never claim scanner completion or coverage", () => {
  for (const task_kind of [
    { kind: "future_task" },
    { kind: "built_in_localhost_tcp", port: 9001, timeout_ms: 4_000, payload_bytes: 0 },
  ]) {
    const workspace = adaptNativeCase(platformCaseFixture({
      scan_runs: [{
        id: "run-invalid-task",
        case_id: "case-platforms-1",
        sequence: 1,
        created_at: "2026-08-26T00:00:00Z",
        completed_at: "2026-08-26T00:01:00Z",
        knowledge_cutoff: "2026-08-24T00:00:00Z",
        engine_runs: [{
          ...engineRunFixture("invalid-task", "completed"),
          task_kind,
        }],
      }],
    }));

    assert.deepEqual(workspace.runs[0]?.engineRuns[0]?.taskKind, { kind: "invalid_task" });
    assert.equal(workspace.runs[0]?.engineRuns[0]?.status, "not_executed");
    assert.equal(workspace.runs[0]?.coveredAssetCount, 0);
    assert.equal(workspace.runs[0]?.status, "failed");
  }
});

test("engine knowledge metadata accepts only the closed Rust wire vocabularies", () => {
  const validManifest = adaptNativeManifest(nativeManifestFixture({ id: "valid-knowledge" }));
  const invalidManifest = adaptNativeManifest(nativeManifestFixture({ id: "future-knowledge" }));
  const workspace = adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "knowledge-run",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-26T00:00:00Z",
      completed_at: "2026-08-26T00:01:00Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      engine_runs: [{
        ...engineRunFixture("valid-knowledge", "completed"),
        distribution_mode: "pull_pinned_image",
        knowledge_input: {
          kind: "external_pinned",
          identifier: "rules",
          version: "2026.08",
          acquisition_source: "managed image",
          pin_state: "pinned_or_not_applicable",
          knowledge_date: "2026-08-24",
          support_until: "2026-12-31",
        },
      }, {
        ...engineRunFixture("future-knowledge", "completed"),
        distribution_mode: "future_distribution",
        knowledge_input: {
          kind: "future_kind",
          identifier: "untrusted",
          version: null,
          acquisition_source: null,
          pin_state: "future_pin_state",
        },
      }],
    }],
  }), [validManifest, invalidManifest]);

  assert.deepEqual(workspace.runs[0]?.engineRuns[0]?.knowledgeInput, {
    kind: "external_pinned",
    identifier: "rules",
    version: "2026.08",
    acquisitionSource: "managed image",
    pinState: "pinned_or_not_applicable",
    knowledgeDate: "2026-08-24",
    supportUntil: "2026-12-31",
  });
  assert.equal(workspace.runs[0]?.engineRuns[0]?.distributionMode, "pull_pinned_image");
  assert.equal(workspace.runs[0]?.engineRuns[1]?.knowledgeInput, undefined);
  assert.equal(workspace.runs[0]?.engineRuns[1]?.distributionMode, undefined);
});

test("run-bound packaged scanner issues remain available to technical diagnostics", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    status: "needs_attention",
    scan_runs: [{
      id: "run-catalog-limitation",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-26T00:00:00Z",
      completed_at: "2026-08-26T00:00:01Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      request_outcome: {
        status: "no_checks_completed",
        code: "no_applicable_checks",
        requested_asset_ids: [],
        requested_engine_ids: [],
        explanation: "No available check could be planned.",
      },
      engine_admission_issues: [{
        engine_id: "gitleaks",
        code: "engine_contract_invalid",
        detail: "test-only catalog detail",
      }],
      engine_runs: [],
    }],
  }));

  assert.deepEqual(workspace.runs[0]?.engineAdmissionIssues, [{
    engineId: "gitleaks",
    code: "engine_contract_invalid",
    detail: "test-only catalog detail",
  }]);
});

test("native engine cleanup claims require exact booleans and preserve absence", () => {
  const cleanupRemovedFor = (cleanup_removed: unknown) => adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "run-cleanup-boundary",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-26T00:00:00Z",
      completed_at: "2026-08-26T00:00:01Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      engine_runs: [{
        id: "task-cleanup-boundary",
        engine_id: "gitleaks",
        task_kind: { kind: "catalog_engine" },
        asset_ids: ["repository-asset"],
        status: "completed",
        progress_percent: 100,
        phase: "completed",
        started_at: "2026-08-26T00:00:00Z",
        finished_at: "2026-08-26T00:00:01Z",
        resume_token: null,
        engine_version: "8.27.2",
        image_digest: "sha256:test",
        rule_version: null,
        adapter_version: "test",
        raw_artifact_ids: [],
        error_code: null,
        error_message: null,
        cleanup_removed,
      }],
    }],
  })).runs[0]?.engineRuns[0]?.cleanupRemoved;

  assert.equal(cleanupRemovedFor(true), true);
  assert.equal(cleanupRemovedFor(false), false);
  assert.equal(cleanupRemovedFor(null), undefined);
  for (const cleanupRemoved of ["true", 1, {}, []]) {
    assert.equal(cleanupRemovedFor(cleanupRemoved), undefined);
  }
});

const adaptGatewayFailure = (
  message: string,
  errorCode = "execution_failed",
  checkpointStage = "failed",
  phase = "failed",
  warnings = errorCode === "resume_release_incompatible" ? [message] : [],
  cleanupDetail?: string,
  status = "failed",
) => {
  const checkpoint = JSON.stringify({
    case_id: "case-1",
    scan_run_id: "run-1",
    engine_run_id: "engine-run-1",
    engine_id: "naabu",
    attempt: 1,
    stage: checkpointStage,
    container_name: null,
    scope_sha256: null,
    artifact_ids: [],
    cleanup_completed: true,
    last_error: message,
  });
  return adaptNativeCase({
    id: "case-1",
    title: "Internal IP scan",
    assessment_intent: "internal_it_environment",
    profile: {
      organization_name: "Example",
      employee_range: "small",
      data_classes: [],
      notes: null,
    },
    status: "needs_attention",
    created_at: "2026-08-26T12:01:00Z",
    updated_at: "2026-08-26T12:02:00Z",
    is_demo: false,
    requested_activities: ["low_impact_external_checks"],
    data_sources: [],
    assets: [],
    scope_grants: [],
    coverage: [],
    scan_runs: [{
      id: "run-1",
      case_id: "case-1",
      sequence: 1,
      created_at: "2026-08-26T12:02:00Z",
      completed_at: "2026-08-26T12:02:01Z",
      knowledge_cutoff: "2026-08-24T00:00:00Z",
      engine_runs: [{
        id: "engine-run-1",
        engine_id: "naabu",
        task_kind: { kind: "catalog_engine" },
        asset_ids: ["private-asset-id"],
        status,
        progress_percent: 0,
        phase,
        started_at: "2026-08-26T12:02:00Z",
        finished_at: "2026-08-26T12:02:01Z",
        resume_token: checkpoint,
        engine_version: "2.6.1",
        image_digest: "sha256:redacted",
        rule_version: null,
        adapter_version: "0.1.1",
        scope_contract_sha256: "a".repeat(64),
        raw_artifact_ids: [],
        error_code: errorCode,
        error_message: message,
        cleanup_detail: cleanupDetail,
        warnings,
      }],
    }],
    findings: [],
    exports: [],
    comparisons: [],
  });
};

test("native gateway failures preserve frozen authorization but restart before runtime scope", () => {
  const workspace = adaptGatewayFailure("runtime error: egress gateway exited before becoming ready");

  const failed = workspace.runs[0]?.engineRuns[0];
  assert.deepEqual(failed?.taskKind, { kind: "catalog_engine" });
  assert.equal(failed?.scopeContractBound, true);
  assert.equal(failed?.checkpoint?.scopeBound, false);
  assert.equal(failed?.failureKind, "gateway_preparation_failed");
  assert.equal(failed?.message, "專用掃描連線無法使用。");
  assert.equal(failed?.recoveryAction, "restart_check");
  assert.equal(failed?.resumable, true);
});

test("terminal partial-result outcomes do not reopen an exhausted or cancelled scan", () => {
  for (const [errorCode, status, phase] of [
    ["coverage_incomplete_after_bounded_retries", "partially_completed", "results_partial"],
    ["cancelled_after_partial_results", "cancelled", "cancelled_after_partial_results"],
  ] as const) {
    const terminal = adaptGatewayFailure(
      "Saved partial results remain available.",
      errorCode,
      "failed",
      phase,
      [],
      undefined,
      status,
    ).runs[0]?.engineRuns[0];

    assert.equal(terminal?.errorCode, errorCode);
    assert.equal(terminal?.recoveryAction, "none");
    assert.equal(terminal?.resumable, false);
  }
});

test("built-in localhost work exposes its exact task and observation without catalog provenance", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    data_sources: [],
    assets: [{
      id: "localhost-asset",
      kind: "web_service",
      name: "127.0.0.1:9001",
      provider: null,
      region: null,
      identifiers: [{ namespace: "localhost_tcp_endpoint", value: "127.0.0.1:9001" }],
      discovered_from: [],
      candidate: false,
      owner_confirmed: true,
      internet_exposed: false,
      metadata: {},
    }],
    scan_runs: [{
      id: "localhost-run",
      case_id: "case-platforms",
      sequence: 1,
      created_at: "2026-08-30T12:00:00Z",
      completed_at: "2026-08-30T12:00:01Z",
      knowledge_cutoff: "2026-08-30T00:00:00Z",
      engine_runs: [{
        id: "localhost-task",
        engine_id: "built-in-localhost-tcp",
        task_kind: {
          kind: "built_in_localhost_tcp",
          port: 9001,
          timeout_ms: 3000,
          payload_bytes: 0,
        },
        localhost_tcp_observation: {
          outcome: "reachable",
          observed_at: "2026-08-30T12:00:01Z",
        },
        asset_ids: ["localhost-asset"],
        status: "completed",
        progress_percent: 100,
        phase: "completed",
        started_at: "2026-08-30T12:00:00Z",
        finished_at: "2026-08-30T12:00:01Z",
        resume_token: null,
        engine_version: "must-not-be-used",
        image_digest: "sha256:must-not-be-used",
        rule_version: "must-not-be-used",
        adapter_version: "must-not-be-used",
        manifest_schema_version: "must-not-be-used",
        source_revision: "must-not-be-used",
        repository_url: "https://invalid.example/must-not-be-used",
        distribution_mode: "pull_pinned_image",
        image_repository: "invalid.example/must-not-be-used",
        command_sha256: "must-not-be-used",
        knowledge_input: {
          kind: "must-not-be-used",
          identifier: "must-not-be-used",
          version: "must-not-be-used",
          acquisition_source: "must-not-be-used",
          pin_state: "must-not-be-used",
        },
        runtime_provider: "must-not-be-used",
        runtime_version: "must-not-be-used",
        runtime_security_options: "must-not-be-used",
        exit_code: 0,
        cleanup_removed: true,
        cleanup_detail: "must-not-be-used",
        warnings: [],
        raw_artifact_ids: [],
        error_code: null,
        error_message: null,
      }],
    }],
  }), [{
    id: "built-in-localhost-tcp",
    name: "Fake catalog scanner",
    category: "fake-category",
    version: "fake-version",
    imageDigest: "sha256:fake-manifest",
  }]);

  const task = workspace.runs[0]?.engineRuns[0];
  assert.equal(workspace.runs[0]?.sequence, 1);
  assert.deepEqual(workspace.case.productIdentity, {
    kind: "localhost_quick_scan",
    port: 9001,
  });
  assert.equal(workspace.runs[0]?.coveredAssetCount, 1);
  assert.deepEqual(task?.taskKind, {
    kind: "built_in_localhost_tcp",
    port: 9001,
    timeoutMs: 3000,
    payloadBytes: 0,
  });
  assert.deepEqual(task?.localhostTcpObservation, {
    outcome: "reachable",
    observedAt: "2026-08-30T12:00:01Z",
  });
  assert.equal(task?.category, "built_in_localhost_tcp");
  for (const field of [
    "version",
    "digest",
    "ruleVersion",
    "adapterVersion",
    "manifestSchemaVersion",
    "sourceRevision",
    "repositoryUrl",
    "distributionMode",
    "imageRepository",
    "commandSha256",
    "knowledgeInput",
    "runtimeProvider",
    "runtimeVersion",
    "runtimeSecurityOptions",
    "exitCode",
    "cleanupRemoved",
    "cleanupDetail",
  ]) {
    assert.equal(task?.[field], undefined, `${field} must not be synthesized for a built-in task`);
  }
  assert.doesNotMatch(JSON.stringify(task), /Fake catalog scanner|fake-version|fake-manifest|must-not-be-used/u);
});

const adaptLocalhostCoverageFixture = (
  engineOverrides: Record<string, unknown>,
  assetOverrides: Record<string, unknown> = {},
  manifests: Array<Record<string, unknown>> = [],
) => adaptNativeCase(platformCaseFixture({
  data_sources: [],
  assets: [{
    id: "localhost-asset",
    kind: "web_service",
    name: "127.0.0.1:9001",
    provider: null,
    region: null,
    identifiers: [{ namespace: "localhost_tcp_endpoint", value: "127.0.0.1:9001" }],
    discovered_from: [],
    candidate: false,
    owner_confirmed: true,
    internet_exposed: false,
    metadata: {},
    ...assetOverrides,
  }],
  scan_runs: [{
    id: "localhost-coverage-run",
    case_id: "case-platforms",
    sequence: 1,
    created_at: "2026-08-30T12:00:00Z",
    completed_at: "2026-08-30T12:00:01Z",
    knowledge_cutoff: "2026-08-30T00:00:00Z",
    engine_runs: [{
      id: "localhost-coverage-task",
      engine_id: "built-in-localhost-tcp",
      task_kind: {
        kind: "built_in_localhost_tcp",
        port: 9001,
        timeout_ms: 3000,
        payload_bytes: 0,
      },
      localhost_tcp_observation: null,
      asset_ids: ["localhost-asset"],
      status: "completed",
      progress_percent: 100,
      phase: "completed",
      started_at: "2026-08-30T12:00:00Z",
      finished_at: "2026-08-30T12:00:01Z",
      resume_token: null,
      engine_version: null,
      image_digest: null,
      rule_version: null,
      adapter_version: "",
      raw_artifact_ids: [],
      error_code: null,
      error_message: null,
      ...engineOverrides,
    }],
  }],
}), manifests);

test("a non-boolean owner confirmation cannot complete a localhost coverage binding", () => {
  const observation = {
    localhost_tcp_observation: {
      outcome: "reachable",
      observed_at: "2026-08-30T12:00:01Z",
    },
  };
  assert.equal(adaptLocalhostCoverageFixture(observation).runs[0]?.coveredAssetCount, 1);
  assert.equal(adaptLocalhostCoverageFixture(observation, { owner_confirmed: false }).runs[0]?.coveredAssetCount, 0);
  for (const owner_confirmed of [1, "false", "true"]) {
    assert.equal(
      adaptLocalhostCoverageFixture(observation, { owner_confirmed }).runs[0]?.coveredAssetCount,
      0,
    );
  }
});

test("completed status alone never gives a built-in localhost task covered-target credit", () => {
  assert.equal(adaptLocalhostCoverageFixture({}).runs[0]?.coveredAssetCount, 0);
  assert.equal(adaptLocalhostCoverageFixture({
    localhost_tcp_observation: {
      outcome: "reachable",
      observed_at: "2026-08-30T12:00:01Z",
    },
  }).runs[0]?.coveredAssetCount, 1);
  assert.equal(adaptLocalhostCoverageFixture({
    localhost_tcp_observation: {
      outcome: "reachable",
      observed_at: "2026-08-30T12:00:01Z",
    },
  }, {
    identifiers: [{ namespace: "ip_address", value: "127.0.0.2" }],
  }).runs[0]?.coveredAssetCount, 0);
  assert.equal(adaptLocalhostCoverageFixture({
    status: "partially_completed",
    localhost_tcp_observation: {
      outcome: "timed_out",
      observed_at: "2026-08-30T12:00:01Z",
    },
  }).runs[0]?.coveredAssetCount, 0);
});

test("a lookalike engine cannot claim built-in localhost provenance or coverage", () => {
  const workspace = adaptLocalhostCoverageFixture({
    engine_id: "lookalike-localhost-engine",
    engine_version: "1.2.3",
    image_digest: "sha256:lookalike",
    localhost_tcp_observation: {
      outcome: "reachable",
      observed_at: "2026-08-30T12:00:01Z",
    },
  }, {}, [{
    id: "lookalike-localhost-engine",
    name: "Catalog lookalike",
    category: "network",
    version: "1.2.3",
    imageDigest: "sha256:lookalike",
  }]);

  const task = workspace.runs[0]?.engineRuns[0];
  assert.equal(task?.engineName, "Catalog lookalike");
  assert.equal(task?.category, "network");
  assert.equal(task?.version, "1.2.3");
  assert.equal(task?.digest, "sha256:lookalike");
  assert.equal(task?.localhostTcpObservation, undefined);
  assert.equal(workspace.runs[0]?.coveredAssetCount, 0);
  assert.equal(workspace.case.productIdentity, undefined);
});

test("a durable no-checks request is terminal and excludes the raw backend explanation", () => {
  const workspace = adaptNativeCase(platformCaseFixture({
    assets: [],
    data_sources: [],
    scan_runs: [{
      id: "no-checks-run",
      case_id: "case-platforms",
      sequence: 1,
      created_at: "2026-08-30T12:00:00Z",
      completed_at: "2026-08-30T12:00:00Z",
      knowledge_cutoff: "2026-08-30T00:00:00Z",
      request_outcome: {
        status: "no_checks_completed",
        code: "no_applicable_checks",
        requested_asset_ids: ["private-asset-id"],
        requested_engine_ids: [],
        explanation: "RAW_BACKEND_EXPLANATION_MUST_NOT_REACH_FIRST_LAYER",
      },
      engine_runs: [],
    }],
  }));

  const run = workspace.runs[0];
  assert.equal(run?.status, "no_checks_completed");
  assert.equal(run?.progress, 0);
  assert.equal(run?.coveredAssetCount, 0);
  assert.equal(run?.totalAssetCount, 1);
  assert.deepEqual(run?.requestOutcome, {
    status: "no_checks_completed",
    code: "no_applicable_checks",
    requestedAssetIds: ["private-asset-id"],
    requestedEngineIds: [],
  });
  assert.doesNotMatch(JSON.stringify(run), /RAW_BACKEND_EXPLANATION/u);
});

test("contradictory no-check outcomes never hide actual or unfinished engine work", () => {
  const noChecksOutcome = {
    status: "no_checks_completed",
    code: "no_applicable_checks",
    requested_asset_ids: ["repository-asset"],
    requested_engine_ids: ["engine-completed"],
    explanation: "contradictory fixture",
  };

  const completedWork = adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "contradictory-completed-run",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-30T12:00:00Z",
      completed_at: "2026-08-30T12:00:01Z",
      knowledge_cutoff: "2026-08-30T00:00:00Z",
      request_outcome: noChecksOutcome,
      engine_runs: [engineRunFixture("engine-completed", "completed")],
    }],
  })).runs[0];
  assert.equal(completedWork?.status, "completed");
  assert.equal(completedWork?.requestOutcome, undefined);
  assert.equal(completedWork?.engineRuns.length, 1);

  const unfinishedOutcome = adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "contradictory-unfinished-run",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-30T12:00:00Z",
      completed_at: null,
      knowledge_cutoff: "2026-08-30T00:00:00Z",
      request_outcome: noChecksOutcome,
      engine_runs: [engineRunFixture("engine-failed", "failed")],
    }],
  })).runs[0];
  assert.equal(unfinishedOutcome?.status, "failed");
  assert.equal(unfinishedOutcome?.requestOutcome, undefined);
  assert.equal(unfinishedOutcome?.engineRuns.length, 1);
});

test("an uncompleted empty run cannot claim that no checks completed", () => {
  const run = adaptNativeCase(platformCaseFixture({
    scan_runs: [{
      id: "uncompleted-no-checks-run",
      case_id: "case-platforms-1",
      sequence: 1,
      created_at: "2026-08-30T12:00:00Z",
      completed_at: null,
      knowledge_cutoff: "2026-08-30T00:00:00Z",
      request_outcome: {
        status: "no_checks_completed",
        code: "no_effective_scope_grants",
        requested_asset_ids: [],
        requested_engine_ids: [],
        explanation: "not durable yet",
      },
      engine_runs: [],
    }],
  })).runs[0];

  assert.equal(run?.status, "queued");
  assert.equal(run?.requestOutcome, undefined);
});

test("release-incompatible saved work is static, redacted, and not resumable", () => {
  const rawBackendText = "RAW_BACKEND_SENTINEL mapping 2026-old target-private";
  const failed = adaptGatewayFailure(rawBackendText, "resume_release_incompatible")
    .runs[0]?.engineRuns[0];

  assert.equal(failed?.errorCode, "resume_release_incompatible");
  assert.equal(failed?.recoveryAction, "none");
  assert.equal(failed?.resumable, false);
  assert.equal(
    failed?.message,
    "這項已保存的檢查由不同版本的應用程式建立；請使用目前版本開始新的掃描。",
  );
  assert.equal(failed?.checkpoint?.lastError, undefined);
  assert.deepEqual(failed?.warnings, []);
  assert.doesNotMatch(JSON.stringify(failed), /RAW_BACKEND_SENTINEL|target-private/u);
});

test("an invalid saved work plan preserves data without offering another resume loop", () => {
  const rawBackendText = "RAW_PLAN_SENTINEL 10.44.55.66 work-plan-secret.example.test";
  const failed = adaptGatewayFailure(
    rawBackendText,
    "resume_work_plan_invalid",
    "planned",
    "resume_work_plan_invalid",
    [rawBackendText],
    rawBackendText,
  ).runs[0]?.engineRuns[0];

  assert.equal(failed?.errorCode, "resume_work_plan_invalid");
  assert.equal(failed?.recoveryAction, "none");
  assert.equal(failed?.resumable, false);
  assert.equal(
    failed?.message,
    "這項已保存的檢查已無法對應原本的目標計畫；請開始新的掃描。",
  );
  assert.equal(failed?.checkpoint?.lastError, undefined);
  assert.deepEqual(failed?.warnings, []);
  assert.equal(failed?.cleanupDetail, undefined);
  assert.doesNotMatch(JSON.stringify(failed), /RAW_PLAN_SENTINEL|10\.44\.55\.66|work-plan-secret/u);
});

test("ambiguous cleanup identity never offers an unsafe cleanup retry", () => {
  const rawBackendText = "RAW_CLEANUP_SENTINEL private-runtime-path";
  const failed = adaptGatewayFailure(
    rawBackendText,
    "runtime_cleanup_identity_unavailable",
    "cleanup_pending",
  ).runs[0]?.engineRuns[0];

  assert.equal(failed?.checkpoint?.stage, "cleanup_pending");
  assert.equal(failed?.errorCode, "runtime_cleanup_identity_unavailable");
  assert.equal(failed?.recoveryAction, "none");
  assert.equal(failed?.resumable, false);
  assert.equal(failed?.checkpoint?.lastError, undefined);
  assert.deepEqual(failed?.warnings, []);
  assert.equal(
    failed?.message,
    "請開始新的掃描取得新結果。",
  );
  assert.doesNotMatch(failed?.message ?? "", /runtime|identity|cleanup|執行環境|識別|清理|安全|保留/iu);
  assert.doesNotMatch(JSON.stringify(failed), /RAW_CLEANUP_SENTINEL|private-runtime-path/u);
});

test("preserved-cleanup phases override a legacy error code without leaking or offering restart", () => {
  for (const phase of [
    "cleanup_identity_unavailable",
    "interrupted_restart_cleanup_identity_unavailable",
  ]) {
    const rawBackendText = `egress gateway exited before becoming ready RAW_PHASE_SENTINEL ${phase}`;
    const failed = adaptGatewayFailure(
      rawBackendText,
      "execution_failed",
      "cleanup_pending",
      phase,
      [rawBackendText],
      rawBackendText,
    ).runs[0]?.engineRuns[0];

    assert.equal(failed?.phase, phase);
    assert.equal(failed?.errorCode, "runtime_cleanup_identity_unavailable");
    assert.equal(failed?.failureKind, undefined);
    assert.equal(failed?.recoveryAction, "none");
    assert.equal(failed?.resumable, false);
    assert.equal(failed?.checkpoint?.lastError, undefined);
    assert.equal(failed?.cleanupDetail, undefined);
    assert.deepEqual(failed?.warnings, []);
    assert.equal(
      failed?.message,
      "請開始新的掃描取得新結果。",
    );
    assert.doesNotMatch(failed?.message ?? "", /runtime|identity|cleanup|執行環境|識別|清理|安全|保留/iu);
    assert.doesNotMatch(JSON.stringify(failed), /RAW_PHASE_SENTINEL|egress gateway exited/u);
  }
});

test("every product-owned gateway preparation marker maps to one redacted failure category", () => {
  const markers = [
    "pinned egress gateway image pull",
    "managed gateway uplink creation",
    "egress gateway container creation",
    "egress gateway container start",
    "egress gateway container exited",
    "egress gateway container did not report",
    "egress gateway container reported",
    "egress gateway internal-network attachment",
  ];

  for (const marker of markers) {
    const secret = `private-target-${marker.replaceAll(" ", "-")}`;
    const failed = adaptGatewayFailure(`runtime error: ${marker}: ${secret}`)
      .runs[0]?.engineRuns[0];
    assert.equal(failed?.failureKind, "gateway_preparation_failed", marker);
    assert.equal(failed?.recoveryAction, "restart_check", marker);
    assert.doesNotMatch(JSON.stringify(failed), new RegExp(secret, "u"), marker);
  }
});

test("package and secret problem groups keep their fields and omit empty ones", () => {
  const fixture = beginnerStatusReportFixture();
  const report = adaptBeginnerMasterReport({
    ...fixture,
    problem_groups: [
      {
        group_id: "group-package",
        rule_version: "dependency-advisory-1",
        kind: "vulnerable_dependency",
        title: "Vulnerable package pyyaml 5.3.1 (CVE-2020-14343 / GHSA-8q59-q68h-6hv4)",
        target_asset_id: "asset-status",
        representative_finding_id: "finding-1",
        finding_ids: ["finding-1", "finding-2"],
        package_name: "pyyaml",
        installed_version: "5.3.1",
        advisory_ids: ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"],
      },
      {
        group_id: "group-secret",
        rule_version: "secret-location-1",
        kind: "exposed_secret",
        title: "Secret found in a file",
        target_asset_id: "asset-status",
        representative_finding_id: "finding-3",
        finding_ids: ["finding-3", "finding-4"],
        package_name: null,
        installed_version: "",
        advisory_ids: [],
      },
    ],
  });
  assert.deepEqual(report.problemGroups?.[0], {
    groupId: "group-package",
    ruleVersion: "dependency-advisory-1",
    kind: "vulnerable_dependency",
    title: "Vulnerable package pyyaml 5.3.1 (CVE-2020-14343 / GHSA-8q59-q68h-6hv4)",
    targetAssetId: "asset-status",
    representativeFindingId: "finding-1",
    findingIds: ["finding-1", "finding-2"],
    policyName: undefined,
    packageName: "pyyaml",
    installedVersion: "5.3.1",
    advisoryIds: ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"],
  });
  const secret = report.problemGroups?.[1];
  assert.equal(secret?.kind, "exposed_secret");
  assert.equal(Object.hasOwn(secret ?? {}, "packageName"), false);
  assert.equal(Object.hasOwn(secret ?? {}, "installedVersion"), false);
  assert.equal(Object.hasOwn(secret ?? {}, "advisoryIds"), false);
});
