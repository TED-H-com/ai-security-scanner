import type { SourceAuditReportWire } from "../../src/sourceAuditTypes.ts";

export const sourceAudit = (): SourceAuditReportWire => ({
  task_id: "audit-task", asset_ids: ["asset-status"], admission_id: "admission-one",
  method: {
    provider: "cloudflare", upstream_commit: "synthetic-upstream", validator_resources_sha256: "validator-digest",
    profile: "quick", declared_invocation_limit: 5, issued_invocations: 3, remaining_invocations: 2,
    counts_by_role: { scout: 1, verifier: 2 }, counts_by_state: { complete: 2, blocked: 1 },
    provenance: "workflow_recorded", verification_scope: "retained bytes and relationships", validators_reexecuted: false,
  },
  outcome: { state: "incomplete", incomplete_reason: "Budget exhausted\nContinue later", audit_performed: true },
  counts: { confirmed: 0, needs_validation: 1, rejected: 0, unresolved_candidates: 1 },
  coverage_by_status: { blocked: 1, out_of_scope: 1 },
  to_validate: [{
    native_record: {
      title: "Candidate title", description: "Candidate description", claimed_root_cause: "Candidate claim",
      evidence: [{ file: "src/example.ts", line: 12, description: "Candidate evidence" }],
      blockers: ["Needs a deployment"], validation_plan: { local: "Inspect locally", deployment: "Inspect deployment" },
    },
    native_record_index: 0, native_record_sha256: "candidate-digest",
    source_locations: [{ path: "src/example.ts", line: 12, view_file_sha256: "file-digest" }],
    coverage_ids: ["coverage-one"], reported_verifier_assignments: ["verifier-one"],
  }],
  coverage_gaps: [
    { coverage_id: "coverage-one", status: "blocked", label: "Injection — request handler", continuation_paths: ["src/example.ts"], unresolved: ["candidate-one"] },
    { coverage_id: "coverage-out", status: "out_of_scope", label: "Authentication — deployment", continuation_paths: [], unresolved: [] },
  ],
  unresolved_candidates: ["candidate-one"],
  technical_detail: {
    confirmed: [], rejected: [], coverage_ledger: [{ coverage_id: "coverage-one", attempts: [{ status: "blocked", reason: "Missing environment" }] }],
    lineage: { source: "view-one", canonical: "source-one" }, custody_digests: { projection: "projection-digest" },
    admission_sha256: "admission-digest", originals: [{ member: "findings.json" }],
  }, withheld_code_fields: 0, withheld_text_fields: 0,
});

import type { BeginnerMasterReport, BeginnerReportFinding, ScanRun } from "../../src/types.ts";

export const auditRun = (): ScanRun => ({
  id: "audit-run", caseId: "audit-case", label: "Scan 1", sequence: 1,
  status: "partial", progress: 100, startedAt: "2026-11-12T00:00:00Z", finishedAt: "2026-11-12T00:01:00Z",
  knowledgeDate: "2026-11-12", coveredAssetCount: 0, totalAssetCount: 1,
  engineRuns: [{
    id: "audit-task", engineId: "cloudflare", engineName: "Cloudflare source audit", category: "unknown",
    taskKind: { kind: "agent_audit", providerId: "cloudflare", admissionId: "admission-one" },
    status: "partial", progress: 100, phase: "admitted", assetIds: ["asset-status"], warnings: [],
    rawArtifactCount: 2, savedResultArtifactCount: 2, findingCount: 0, resumable: false, recoveryAction: "none",
  }],
});

export const auditFinding = (): BeginnerReportFinding => ({
  sourceAudit: true, findingId: "confirmed-one", fingerprint: "native-one", snapshotSource: "frozen_selected_run",
  title: "Confirmed native title", plainLanguageRisk: "Cloudflare source audit reported this condition.",
  possibleImpact: "Native impact\nsecond line", nextStep: "Native remediation\nsecond line",
  severity: "high", confidence: "medium", priority: 80, priorityReasons: [], family: "source_code",
  targetAssetIds: ["asset-status"], recommendedExpertType: "Application developer",
  evidenceReferences: [{
    evidenceId: "evidence-one", engineId: "cloudflare", engineRunId: "audit-task", detailsFrozen: true,
    artifactSha256: "artifact-digest", observedAt: "2026-11-12T00:01:00Z", summary: "Native evidence",
    scannerDetails: { description: "Native description", remediation: "Native remediation\nsecond line" },
    providerRecord: { admission_id: "admission-one", native_record_index: 0, native_record_sha256: "record-digest",
      native_fingerprint: "native-one", source_locators: [{ path: "src/example.ts", line: 12, view_file_sha256: "file-digest" }] },
  }], officialReferences: [], frameworkReferences: [],
});

export const auditReport = (): BeginnerMasterReport => ({
  schemaVersion: "1.1.0", caseId: "audit-case", runId: "audit-run", projectTitle: "Synthetic source audit",
  state: { summary: "partial", lifecycle: "final", lastDurableUpdate: "2026-11-12T00:01:00Z", explanation: "Recorded source audit" },
  sourceAudits: [sourceAudit()],
  requested: {
    targets: [{ assetId: "asset-status", label: "Example project", assetKind: "repository", labelAvailability: "recorded", assetKindAvailability: "recorded" }],
    stage: { value: "deep", availability: "recorded", explanation: "Recorded audit" }, limits: [],
    requestedCheckIds: ["Cloudflare source audit"], automaticReductions: [], reductionsAvailability: "recorded", unavailableDimensions: [],
  },
  actual: { checks: [{ taskId: "audit-task", checkId: "Cloudflare source audit", resultKind: "security_check",
    targetAssetIds: ["asset-status"], status: "tested_partial", testedDimensions: [{ dimension: "Source audit coverage", value: "1", observation: "Recorded source audit" }] }],
    networkScopes: [], unavailableDimensions: [],
  },
  coverageGaps: [{ kind: "not_tested", class: "coverage_loss", taskId: "audit-task", targetAssetIds: ["asset-status"],
    dimension: "Source audit coverage", reason: "1 unit remains.", nextActionCode: "retry_check", nextAction: "Continue the source audit from the listed paths." }],
  coverageCounts: { testedComplete: 0, testedPartial: 1, failed: 0, timedOut: 0, cancelled: 0, notTested: 1, excluded: 1, truncated: 0, unavailable: 0, unattributed: 0, manualReview: 0 },
  findings: [], findingGroups: [], nextSteps: [{ priority: 1, code: "retry_check", taskId: "audit-task", action: "Continue the source audit from the listed paths.", reason: "1 unit remains." }],
  technicalDetails: { collapsedByDefault: true, tasks: [{
    taskId: "audit-task", targetAssetIds: ["asset-status"], status: "partial", phase: "admitted", progressPercent: 100,
    cleanupDetail: { availability: "not_applicable", explanation: "Not applicable" },
    redactedScannerMessage: { availability: "not_applicable", explanation: "Not applicable" },
    redactedDiagnosticLog: { availability: "not_applicable", explanation: "Not applicable" }, evidenceSha256: ["artifact-digest"],
    execution: { kind: "agent_audit", providerId: "cloudflare", admissionId: "admission-one" },
  }] }, frameworkNotice: { nonCertification: "Not a certification.", aidefendMappingStatus: "Not mapped." }, dataQualityWarnings: [],
});

import type { NativeAssessmentCase, NativeBeginnerMasterReport } from "../../src/services/nativeAdapter.ts";

export const nativeAuditReport = (): NativeBeginnerMasterReport => ({
  schema_version: "1.1.0", case_id: "audit-case", run_id: "audit-run", project_title: "Synthetic source audit",
  state: { summary: "partial", lifecycle: "final", last_durable_update: "2026-11-12T00:01:00Z", explanation: "Recorded source audit" },
  source_audits: [sourceAudit()],
  requested: { targets: [{ asset_id: "asset-status", label: "Example project", asset_kind: "repository", label_availability: "recorded", asset_kind_availability: "recorded" }],
    stage: { value: "deep", availability: "recorded", explanation: "Recorded audit" }, limits: [], requested_check_ids: ["Cloudflare source audit"], request_outcome_code: null,
    automatic_reductions: [], reductions_availability: "recorded", unavailable_dimensions: [] },
  actual: { observed_from: null, observed_until: null, checks: [{ task_id: "audit-task", check_id: "Cloudflare source audit", result_kind: "security_check",
    target_asset_ids: ["asset-status"], status: "tested_partial", started_at: null, finished_at: null, tested_dimensions: [] }], unavailable_dimensions: [] },
  coverage_gaps: [], coverage_counts: { tested_complete: 0, tested_partial: 1, failed: 0, timed_out: 0, cancelled: 0, not_tested: 1, excluded: 1, truncated: 0, unavailable: 0 },
  findings: [{
    source_audit: true, finding_id: "confirmed-one", fingerprint: "native-one", snapshot_source: "frozen_selected_run", title: "Confirmed native title",
    plain_language_risk: "Recorded source audit", possible_impact: "Native impact", next_step: "Native remediation", severity: "high", confidence: "medium", priority: 80,
    priority_reasons: [], target_asset_ids: ["asset-status"], recommended_expert_type: "Application developer", family: "source_code",
    evidence_references: [{ evidence_id: "evidence-one", engine_id: "cloudflare", engine_run_id: "audit-task", details_frozen: true,
      provider_record: auditFinding().evidenceReferences[0]!.providerRecord, artifact_sha256: "artifact-digest", observed_at: "2026-11-12T00:01:00Z" }], framework_references: [],
  }], next_steps: [],
  technical_details: { collapsed_by_default: true, tasks: [{ task_id: "audit-task", target_asset_ids: ["asset-status"], status: "partially_completed", phase: "admitted", progress_percent: 100,
    started_at: null, finished_at: null, exit_code: null, cleanup_removed: null, error_code: null,
    cleanup_detail: { availability: "not_applicable", value: null, explanation: "Not applicable" },
    redacted_scanner_message: { availability: "not_applicable", value: null, explanation: "Not applicable" },
    redacted_diagnostic_log: { availability: "not_applicable", value: null, explanation: "Not applicable" }, evidence_sha256: [],
    execution: { kind: "agent_audit", provider_id: "cloudflare", admission_id: "admission-one" },
  }] }, framework_notice: { non_certification: "Not certification", aidefend_mapping_status: "Not mapped" }, data_quality_warnings: [],
});

export const nativeAuditCase = (): NativeAssessmentCase => ({
  id: "audit-case", title: "Synthetic source audit", profile: { organization_name: "Example", employee_range: "small", data_classes: [], notes: null },
  status: "needs_attention", created_at: "2026-11-12T00:00:00Z", updated_at: "2026-11-12T00:01:00Z", is_demo: false,
  data_sources: [], assets: [], scope_grants: [], coverage: [], findings: [], exports: [], comparisons: [],
  scan_runs: [{ id: "audit-run", case_id: "audit-case", sequence: 1, created_at: "2026-11-12T00:00:00Z", completed_at: "2026-11-12T00:01:00Z", knowledge_cutoff: "2026-11-12",
    engine_runs: [{ id: "audit-task", engine_id: "cloudflare", task_kind: { kind: "agent_audit", provider_id: "cloudflare", admission_id: "admission-one" },
      asset_ids: ["asset-status"], status: "partially_completed", progress_percent: 100, phase: "admitted", started_at: null, finished_at: "2026-11-12T00:01:00Z",
      resume_token: null, engine_version: null, image_digest: null, rule_version: null, error_code: null, error_message: null }],
  }],
});
