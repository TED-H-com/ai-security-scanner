import type { ScanRun } from "./types";

const terminalResultStatuses = new Set<ScanRun["status"]>([
  "completed",
  "no_checks_completed",
  "partial",
  "failed",
  "cancelled",
]);

const verificationBaselineStatuses = new Set<ScanRun["status"]>([
  "completed",
  "partial",
  "failed",
  "cancelled",
]);

export const isTerminalResultRun = (run: Pick<ScanRun, "status">): boolean =>
  terminalResultStatuses.has(run.status);

/** Imported evidence cannot recreate an executable scan for Check fixes. */
export const isVerificationBaselineRun = (
  run: Pick<ScanRun, "status"> & {
    engineRuns?: ReadonlyArray<Pick<ScanRun["engineRuns"][number], "taskKind">>;
  },
): boolean =>
  verificationBaselineStatuses.has(run.status)
  && (!run.engineRuns?.length
    || run.engineRuns.some((task) => task.taskKind?.kind !== "external_report_import"));
