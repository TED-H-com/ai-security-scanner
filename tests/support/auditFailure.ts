import { failureDescription, type AuditFailureOutcome } from "../../src/auditFailure.ts";
import { nativeAuditCase, nativeAuditReport, auditReport, auditRun } from "./sourceAudit.ts";
import type { BeginnerMasterReport, ScanRun } from "../../src/types.ts";

export const failureOutcome = (ending: "blocked" | "terminated" = "blocked"): AuditFailureOutcome => ({
  preparation_request_id: "preparation-one", preparation_receipt_sha256: "a".repeat(64), asset_id: "asset-status",
  terminal_sha256: (ending === "blocked" ? "a" : "b").repeat(64), occurred_at: "2026-11-12T00:01:00Z",
  ...(ending === "blocked" ? { ending, reasons: ["delegation_unavailable"] }
    : { ending, session_id: "audit-one", reason: "budget_exhausted", assignment_count: 3, capture_count: 2 }),
});
export const failureCase = (ending: "blocked" | "terminated") => {
  const value = nativeAuditCase();
  value.assets.push({ id: "asset-status", kind: "repository", name: "Example project", provider: null, region: null,
    identifiers: [], discovered_from: [], candidate: false, owner_confirmed: true });
  Object.assign(value.scan_runs[0]!.engine_runs[0]!, {
    engine_id: "private-provider-string", task_kind: { kind: "agent_audit_failure", provider_id: "cloudflare-security-audit", outcome: failureOutcome(ending) },
    status: ending === "blocked" ? "not_executed" : "failed", started_at: "2026-11-12T00:00:00Z",
    phase: "terminal", resume_token: "synthetic-stale-token",
  });
  return value;
};
export const nativeFailureReport = (ending: "blocked" | "terminated") => {
  const report = nativeAuditReport();
  const outcome = failureOutcome(ending);
  const words = failureDescription(outcome);
  report.source_audits = []; report.findings = [];
  const check = report.actual.checks[0]!;
  check.status = ending === "blocked" ? "not_tested" : "failed";
  check.outcome = { summary: words.summary.en, reason: words.reason.en, next_action: words.nextAction.en };
  const { preparation_receipt_sha256, terminal_sha256, occurred_at, ...rest } = outcome;
  report.technical_details.tasks[0]!.execution = { kind: "agent_audit_failure", run_id: report.run_id,
    receipt_sha256: preparation_receipt_sha256, terminal_sha256, occurred_at,
    ending: rest.ending === "blocked" ? { ending: rest.ending, reasons: rest.reasons }
      : { ending: rest.ending, reason: rest.reason, assignment_count: rest.assignment_count, capture_count: rest.capture_count } };
  return report;
};
export const failureRun = (ending: "blocked" | "terminated"): ScanRun => {
  const run = auditRun();
  run.id = `failure-${ending}`;
  run.status = ending === "blocked" ? "no_checks_completed" : "failed";
  Object.assign(run.engineRuns[0]!, { taskKind: { kind: "agent_audit_failure", providerId: "cloudflare-security-audit", outcome: failureOutcome(ending) },
    status: ending === "blocked" ? "not_executed" : "failed", rawArtifactCount: 0, savedResultArtifactCount: 0 });
  return run;
};
export const failureReport = (ending: "blocked" | "terminated"): BeginnerMasterReport => {
  const report = auditReport();
  const run = failureRun(ending);
  const outcome = failureOutcome(ending);
  const words = failureDescription(outcome);
  report.runId = run.id;
  report.sourceAudits = []; report.findings = []; report.nextSteps = [];
  report.state.summary = "no_checks_completed";
  Object.assign(report.actual.checks[0]!, { status: ending === "blocked" ? "not_tested" : "failed", testedDimensions: [],
    outcome: { summary: words.summary.en, reason: words.reason.en, nextAction: words.nextAction.en } });
  Object.assign(report.coverageGaps[0]!, { kind: ending === "blocked" ? "not_tested" : "failed", reason: words.gap.en,
    nextActionCode: "preserve_visible_limitation", nextAction: `${words.reason.en} ${words.nextAction.en}` });
  report.coverageCounts.testedPartial = 0;
  report.coverageCounts.excluded = 0;
  const task = report.technicalDetails.tasks[0]!;
  task.status = run.engineRuns[0]!.status;
  task.execution = { kind: "agent_audit_failure", runId: run.id, receiptSha256: outcome.preparation_receipt_sha256,
    terminalSha256: outcome.terminal_sha256, occurredAt: outcome.occurred_at,
    ending: outcome.ending === "blocked" ? { ending: "blocked", reasons: outcome.reasons }
      : { ending: "terminated", reason: outcome.reason, assignment_count: outcome.assignment_count, capture_count: outcome.capture_count } };
  return report;
};
