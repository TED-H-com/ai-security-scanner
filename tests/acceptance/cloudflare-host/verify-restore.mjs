#!/usr/bin/env node
// Lead-only acceptance tooling. No model, network, target execution or direct database access.
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { prepareOutputDirectory, privateProcessEnvironment, validateOutputDirectory } from "./setup.mjs";

const usage = "Usage: node verify-restore.mjs --cli CLI --context HOST_CONTEXT_JSON --archive HOST_ARCHIVE --output NEW_DIR";
const omission = "Source snapshots were not included in the archive this case was restored from; source bytes cannot be rechecked here.";
const archiveOmission = "Source snapshots inside source-audit packages were not included; their bytes cannot be rechecked from this archive.";

export function parseArguments(args) {
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i].slice(2);
    if (!["--cli", "--context", "--archive", "--output"].includes(args[i])
        || !args[i + 1] || args[i + 1].startsWith("--") || Object.hasOwn(options, key)) {
      throw new Error(usage);
    }
    options[key] = args[i + 1];
  }
  if (["cli", "context", "archive", "output"].some((key) => !options[key])) throw new Error(usage);
  return options;
}

function contains(parent, child) {
  const path = relative(parent, child);
  return !path || (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}
function digest(bytes) {
  return { sha256: createHash("sha256").update(bytes).digest("hex"), byte_length: bytes.length };
}
function equalDigest(a, b) {
  return a?.sha256 === b?.sha256 && a?.byte_length === b?.byte_length;
}
// Case and scan reads list the same snapshot reference with different key order, so compare the
// fields that identify the saved bytes instead of serialized objects.
export function sameSnapshotReference(a, b) {
  return ["snapshot_id", "relative_path", "sha256", "byte_length", "source_case_revision"]
    .every((field) => a?.[field] !== undefined && a[field] === b?.[field]);
}
function snapshotPath(data, record) {
  const root = join(data, "artifacts");
  const path = record?.relative_path;
  if (typeof path !== "string" || !path || isAbsolute(path)
      || path.split(/[\\/]/u).some((part) => ["", ".", ".."].includes(part))) {
    throw new Error("CLI returned an unsafe snapshot relative_path");
  }
  return join(root, path);
}

export async function verifyRestore(options) {
  const { cli, context, archive, output } = options;
  if ([cli, context, archive, output].some((value) => typeof value !== "string" || !value)) throw new Error(usage);
  // Refuse before resolving a CLI or creating anything; share setup's path policy.
  await validateOutputDirectory(output);
  const host = JSON.parse(await readFile(context, "utf8"));
  const data = host.data_directory;
  const caseId = host.case_id;
  if (typeof data !== "string" || !isAbsolute(data) || await realpath(data) !== data
      || !(await lstat(data)).isDirectory() || typeof caseId !== "string" || !caseId) {
    throw new Error("Host context requires a canonical existing data_directory and case_id");
  }
  for (const protectedPath of [data, host.tree_path, host.run_directory]) {
    if (typeof protectedPath === "string") {
      const canonical = await realpath(protectedPath).catch((error) => {
        if (error.code !== "ENOENT") throw error;
        return resolve(protectedPath); // Old host working copies need not survive.
      });
      if (contains(canonical, output) || contains(output, canonical)) {
        throw new Error("--output must be separate from the original data, source view and host run directory");
      }
    }
  }
  const cliPath = await realpath(resolve(cli));
  const archivePath = await realpath(resolve(archive));
  for (const [name, path] of [["cli", cliPath], ["archive", archivePath]]) {
    if (!(await lstat(path)).isFile()) throw new Error(`--${name} must name a regular file`);
  }
  const root = await prepareOutputDirectory(output);
  const processDirectory = join(root, "process");
  await mkdir(processDirectory, { mode: 0o700 });
  const environment = privateProcessEnvironment(processDirectory);
  const report = { schema_version: "cloudflare-host-restore-verification/v1", passed: false, commands: [], checks: [] };
  let original;
  let originalState;
  let sessions = [];
  function check(name, passed, details = {}) {
    report.checks.push({ name, passed: Boolean(passed), ...details });
  }
  function command(dataDirectory, args, expectedExit = 0) {
    const argv = [...(dataDirectory ? ["--data-dir", dataDirectory] : []), "--json", ...args];
    const result = spawnSync(cliPath, argv, {
      cwd: root, env: environment, encoding: "utf8", timeout: 120_000,
      maxBuffer: 32 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
    });
    let value;
    let parseError;
    try { value = JSON.parse(result.stdout); } catch (error) { parseError = error.message; }
    const passed = !result.error && result.status === expectedExit && !parseError;
    report.commands.push({ command: [cliPath, ...argv], exit_code: result.status, expected_exit: expectedExit,
      passed, response: value ?? null, ...(parseError ? { stdout: result.stdout ?? "" } : {}), stderr: result.stderr ?? "", error: result.error?.message ?? parseError ?? null });
    if (!passed) throw new Error(`CLI ${args.slice(0, 3).join(" ")} failed: exit ${result.status}; ${value?.error_code ?? result.error?.message ?? parseError ?? "unexpected exit"}`);
    return value;
  }
  const show = (directory) => command(directory, ["case", "show", caseId]);
  const provider = (directory, operation, session) => command(directory,
    ["provider", "cloudflare", operation, "--case-id", caseId, "--session-id", session]);
  // The CLI exposes no current case revision outside foreground scan envelopes, so "unchanged"
  // means every public read of the case is byte-identical: the case, its scan status with saved
  // command receipts and report snapshots, and each audit's provider status.
  function publicState(directory, sessions) {
    return JSON.stringify({
      case: show(directory),
      scan: command(directory, ["scan", "status", "--case-id", caseId]),
      audits: sessions.map((session) => provider(directory, "status", session)),
    });
  }
  function stateUnchanged(name, before, after) {
    check(name, before === after, before === after ? {} : { reason: "a public read of the case changed" });
  }
  async function retrieveSnapshot(directory, record, name, operation, format) {
    const destination = join(root, `${name}-${operation}.${format}`);
    const receipt = command(null, ["report", operation, "--snapshot", snapshotPath(directory, record),
      "--format", format, "--destination", destination]);
    const actual = digest(await readFile(destination));
    check(`${name} ${operation} ${format} receipt`, equalDigest(actual, receipt), { actual, receipt });
    return actual;
  }
  async function captured(directory, session, assignment, name) {
    const destination = join(root, `${name}-captured.txt`);
    command(directory, ["provider", "cloudflare", "retrieve-captured", "--case-id", caseId,
      "--session-id", session, "--assignment-id", assignment.assignment_id,
      "--expected-sha256", assignment.output.sha256, "--destination", destination]);
    const actual = digest(await readFile(destination));
    check(`${name} captured output`, equalDigest(actual, assignment.output), { actual, expected: assignment.output });
    return actual;
  }
  try {
    original = show(data);
    const admissions = original.agent_audit_admissions ?? [];
    if (!admissions.length) throw new Error("Case has no admitted Cloudflare audit; finish host admission before verification");
    if (original.id !== caseId) throw new Error("case show returned a different case");
    const audits = [];
    sessions = admissions.map((admission) => admission.identities.session_id);
    originalState = publicState(data, sessions);
    for (const admission of admissions) {
      const session = admission.identities.session_id;
      const status = provider(data, "status", session).result;
      const inspected = provider(data, "inspect-sealed", session).result;
      check(`${session} original admission`, status.admission_state === "admitted"
        && status.admission?.admission_id === admission.admission_id
        && status.admission?.admission_sha256 === admission.admission_sha256
        && status.admission?.run_id === admission.identities.run_id
        && inspected.admission_state === "admitted");
      check(`${session} original seal`, inspected.verification?.state === "verified"
        && inspected.verification?.scope === "full_payload" && !status.restored);
      const assignment = status.assignments.find((item) => item.output?.disposition === "accepted");
      if (!assignment) throw new Error(`No accepted captured output for admitted audit ${session}`);
      audits.push({ session, admission: status.admission, inspected, assignment,
        captured: await captured(data, session, assignment, `original-${audits.length}`) });
    }
    const scan = command(data, ["scan", "status", "--case-id", caseId]);
    const runIds = scan.runs.map((run) => run.id);
    const admittedIds = audits.map((audit) => audit.admission.run_id);
    const scannerIds = scan.runs.filter((run) => run.engine_runs.some((engine) =>
      engine.task_kind?.kind === "catalog_engine")).map((run) => run.id);
    report.identities = { case_id: caseId, sessions: audits.map((audit) => audit.session),
      admitted_run_ids: admittedIds, scanner_run_ids: scannerIds, run_ids: runIds };
    check("case and scan status runs agree", JSON.stringify(original.scan_runs.map((run) => run.id)) === JSON.stringify(runIds));
    const snapshots = new Map();
    function add(record) {
      if (!record) return;
      snapshotPath(data, record);
      const previous = snapshots.get(record.relative_path);
      if (previous && !sameSnapshotReference(previous, record)) throw new Error("Conflicting recorded snapshot references");
      snapshots.set(record.relative_path, record);
    }
    for (const record of original.run_report_snapshots ?? []) add(record.snapshot);
    for (const record of scan.run_report_snapshots ?? []) add(record.snapshot);
    for (const item of [...(original.exports ?? []), ...(original.combined_exports ?? [])]) add(item.report_snapshot);
    for (const id of [...admittedIds, ...scannerIds]) {
      check(`${id} terminal report recorded`, (scan.run_report_snapshots ?? []).some((record) => record.run_id === id));
    }
    for (const combined of original.combined_exports ?? []) {
      check(`${combined.id} combined report recorded`, Boolean(combined.report_snapshot));
    }
    const originals = [];
    for (const record of snapshots.values()) {
      const name = `original-report-${originals.length}`;
      const formats = {};
      for (const format of ["html", "json"]) formats[format] = await retrieveSnapshot(data, record, name, "retrieve", format);
      originals.push({ record, formats });
    }
    report.snapshots = originals;
    const excluded = join(root, "source-excluded.scanner-archive.tar.gz");
    const hostVerified = command(null, ["archive", "verify", "--archive", archivePath]);
    check("host archive verified", hostVerified.integrity_valid === true && hostVerified.case_id === caseId
      && hostVerified.case_data_restore_available === true && hostVerified.source_snapshots_included === true);
    command(data, ["archive", "create", "--case-id", caseId, "--destination", excluded, "--acknowledge-sensitive-data"]);
    const excludedVerified = command(null, ["archive", "verify", "--archive", excluded]);
    check("source-excluded archive verified", excludedVerified.integrity_valid === true
      && excludedVerified.case_id === caseId && excludedVerified.case_data_restore_available === true
      && excludedVerified.source_snapshots_included === false && excludedVerified.omissions?.includes(archiveOmission));
    for (const [label, file, scope] of [["with-sources", archivePath, "full_payload"], ["source-excluded", excluded, "included_payload"]]) {
      // A failure in one restore must not suppress evidence from the other archive.
      try {
        const restored = join(root, `${label}-data`);
        command(null, ["archive", "restore-preview", "--archive", file, "--destination", restored]);
        command(null, ["archive", "restore", "--archive", file, "--destination", restored, "--acknowledge-sensitive-data"]);
        for (const [index, audit] of audits.entries()) {
          const status = provider(restored, "status", audit.session).result;
          const inspected = provider(restored, "inspect-sealed", audit.session).result;
          check(`${label} ${audit.session} restored admission`, status.restored === true
            && status.admission_state === "admitted"
            && status.admission?.admission_id === audit.admission.admission_id
            && status.admission?.admission_sha256 === audit.admission.admission_sha256);
          check(`${label} ${audit.session} verification scope`, status.sealed_state === "verified"
            && status.sealed_verification_scope === scope && inspected.verification?.state === "verified"
            && inspected.verification?.scope === scope && inspected.restored === true,
          { status_scope: status.sealed_verification_scope, inspection_scope: inspected.verification?.scope });
          check(`${label} ${audit.session} source omission`, scope === "included_payload"
            ? status.source_snapshot_notice === omission && inspected.source_snapshot_notice === omission
            : !status.source_snapshot_notice && !inspected.source_snapshot_notice);
          const actual = await captured(restored, audit.session, audit.assignment, `${label}-${index}`);
          check(`${label} ${audit.session} captured bytes unchanged`, equalDigest(actual, audit.captured), { original: audit.captured, restored: actual });
          const before = publicState(restored, audits.map((item) => item.session));
          const request = join(root, `${label}-${index}-admit.json`);
          const digests = audit.inspected.digests;
          await writeFile(request, `${JSON.stringify({
            schema_version: "ai-security-scanner.cloudflare-audit-admit-request/v1",
            request_id: `restore-check-${randomUUID()}`, case_id: caseId, session_id: audit.session,
            expected_sealed_entry_sha256: digests.sealed_entry_sha256,
            expected_bundle_sha256: digests.bundle_sha256, expected_projection_sha256: digests.projection_sha256,
          }, null, 2)}\n`, { flag: "wx", mode: 0o600 });
          const refused = command(restored, ["provider", "cloudflare", "admit", "--request", request], 2);
          check(`${label} ${audit.session} fresh admission refused`, refused.error_code === "restored_session_inert", { error_code: refused.error_code });
          stateUnchanged(`${label} ${audit.session} refusal leaves the restored case unchanged`, before,
            publicState(restored, audits.map((item) => item.session)));
        }
        for (const [index, saved] of originals.entries()) {
          for (const format of ["html", "json"]) {
            for (const operation of ["retrieve", "replay"]) {
              const actual = await retrieveSnapshot(restored, saved.record, `${label}-report-${index}`, operation, format);
              check(`${label} report ${index} ${operation} ${format} matches original`, equalDigest(actual, saved.formats[format]),
                { original: saved.formats[format], restored: actual });
            }
          }
        }
      } catch (error) { check(`${label} restore journey`, false, { error: error.message }); }
    }
  } catch (error) {
    check("verification journey", false, { error: error.message });
  } finally {
    if (originalState) {
      try {
        stateUnchanged("original case unchanged", originalState, publicState(data, sessions));
      } catch (error) { check("original unchanged check", false, { error: error.message }); }
    }
    report.passed = report.commands.every((item) => item.passed) && report.checks.every((item) => item.passed);
    await writeFile(join(root, "verify-restore.json"), `${JSON.stringify(report, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  }
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const report = await verifyRestore(options);
    process.stdout.write(`${join(options.output, "verify-restore.json")}\n`);
    if (!report.passed) {
      process.stderr.write(`${report.checks.filter((item) => !item.passed).map((item) => `${item.name}: ${item.error ?? item.reason ?? "failed"}`).join("\n")}\n`);
      process.exitCode = 1;
    }
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
