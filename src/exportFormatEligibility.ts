import type { ExportFormat, ScanRun } from "./types";
import { isTerminalResultRun } from "./runLifecycle.ts";

export type FindingOnlyExportFormat = "ocsf" | "oscal";

export const isFindingOnlyExportFormat = (
  format: ExportFormat,
): format is FindingOnlyExportFormat => format === "ocsf" || format === "oscal";

/** OCSF and OSCAL are paired with a mandatory coverage manifest by the backend. */
export const runSupportsFindingOnlyExport = (run: ScanRun | undefined): boolean =>
  Boolean(run && isTerminalResultRun(run));

export const exportFormatIsAvailable = (
  format: ExportFormat,
  run: ScanRun | undefined,
): boolean => Boolean(
  run
  && isTerminalResultRun(run)
  && (!isFindingOnlyExportFormat(format) || runSupportsFindingOnlyExport(run)),
);

export const resetUnavailableExportFormat = (
  format: ExportFormat,
  run: ScanRun | undefined,
): ExportFormat => exportFormatIsAvailable(format, run) ? format : "html";
