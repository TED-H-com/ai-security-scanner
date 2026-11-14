# Foreground scans in the development CLI

This source checkout adds foreground execution through the same coordinator and
scanner adapters as the desktop. The published desktop remains the default
operator entry. The [pinned development bootstrap](skill-bootstrap.md) now builds
the core and prepares selected scanner images through the same runtime resolver.
Automatic managed-bundle acquisition remains pending; Cloudflare source audits follow the [host procedure](cloudflare-provider.md). See [publication status](release-model.md); the repository operator skill being public does not release these newer commands.

Use an existing case with reviewed assets and effective scope grants. A run does
not create or widen authorization. Provider and model credentials remain bound
to their supported local authorization flows; do not put credentials in command
arguments. Select the intended data directory explicitly when working alongside
an installed desktop.

To set up a case in a new skill data directory, the user runs
`case create --title TITLE`, then
`source attach-workspace --case-id CASE_ID --label LABEL --path ABSOLUTE_DIR --profile repository-working-tree`,
reviews the asset in `case show CASE_ID` and records their own decision with
`scope approve --case-id CASE_ID --asset-id ASSET_ID --permission local-artifact-read --confirmed-by NAME`
(network permissions also need `--external-scope FILE`). `scope list CASE_ID`
shows the result. An agent may prepare these commands but never confirms scope
for the user.

For lost Cloudflare host copies, use `provider cloudflare status`, then the read-only
`provider cloudflare retrieve-captured` command with a recorded document revision
or accepted assignment ID and a new private destination. See [custody recovery](cloudflare-provider.md#recovering-lost-host-copies)
for its exact options and exit codes. Further recording still requires current
authority; retrieval creates no scan, event or permission.

Before scanning, `runtime prepare --engine semgrep,gitleaks` can prepare those
exact pinned images with the same explicit `--data-dir` and optional
`--managed-runtime-bundle`. It reports per-image readiness without creating a case
or scan and saves a receipt when possible.
For `runtime prepare` and `scan run`, add `--expected-managed-runtime-manifest-sha256`
with the bundle manifest's lowercase SHA-256 to require that exact bundle.
`runtime_unavailable_reason` is `managed_bundle_rejected`, `no_runtime`, or
`managed_runtime_unavailable` when runtime resolution fails, and `null` otherwise.
Its `--offline` mode uses only running runtimes and existing or verified local
images; it does not change the later scan's scope or network behavior.

```sh
ai-security-scanner-cli --data-dir /private/scanner-data --json \
  scan run --case-id CASE_ID --engine semgrep,gitleaks --wait
```

Omitting `--engine` selects applicable catalog checks within the existing scope.
`--campaign` selects an existing supported incident campaign. `scan run` creates
a new durable run; `scan plan` remains a planning operation and does not start a
background worker. `--wait` is required. Keep the owning process running until it
returns.

Without `--json`, foreground commands emit NDJSON progress records and a terminal
envelope. `--ndjson` makes that choice explicit. With `--json`, stdout contains
only the terminal envelope. Diagnostics use stderr. Command completion, task
statuses, findings, coverage and pending cleanup are separate facts: a completed
command does not mean that every check ran or that the target is secure.

Progress records use `schema_version: ai-security-scanner.scan-event/v1` and
`type: event`; the one terminal record uses
`schema_version: ai-security-scanner.scan-command/v1` and `type: terminal`.
The terminal record separates `command_outcome`, `exit_code`, `error_code`,
`retryable`, the saved run summary and the exact durable `receipt`.
`scan status` exposes those saved receipts in `command_receipts`. It also lists
`run_report_snapshots`. Once results and cleanup have settled, the terminal response
includes the automatically saved private report in `result.report_snapshot`; details,
retrieval and storage-failure recovery are in [saved report snapshots](report-snapshots.md#reopen-a-completed-scan).
These reports preserve failed, cancelled and no-check outcomes as well as completed
checks. A report-save failure keeps the findings and returns
`terminal_report_snapshot_failed`; `result.report_snapshot_retry_command` selects the
same run for recovery without a fresh scanner execution.

Once `scan run` has saved or may have saved a run, `retryable` is false: repeating
that command could create another scan. Use `scan status` to inspect saved runs;
`result.recovery.next_command` is present only for supported captured-result or
cleanup recovery. A failed `scan recover` is retryable only while that same
recovery remains supported.

The owner retains its worker and the data-directory lease through terminal
persistence and reconciliation. Ctrl+C requests cancellation, stops new work and
waits for the owned work to settle. Output failure follows the same ownership
path. Saved evidence and completed sibling results remain available. A command
receipt is stored in case history before successful delivery; it travels with a
complete case archive.

For foreground scans and runtime preparation, Unix handles SIGINT (130) and
SIGTERM or SIGHUP (143). Windows handles Ctrl+C or Ctrl+Break (130) and console
close, logoff or shutdown (143). The first interruption sets the exit code;
later events are absorbed while work settles.

When started through the development bootstrap, the parent uses a fixed private
pipe to request cancellation for both `scan run` and `scan recover`. The core also
settles owned work if the bootstrap exits unexpectedly. It runs detached on all
platforms, including Windows, so parent exit closes the pipe without killing the
core. Standard output and standard error remain inherited. Repeated interruption
does not force termination. After losing the bootstrap connection, use
`scan status` to read the saved result before requesting any new work. The pipe
accepts only cancellation controls; it is not an input for targets or credentials.

Read saved status and receipts, including while another process owns the data:

```sh
ai-security-scanner-cli --data-dir /private/scanner-data --json \
  scan status --case-id CASE_ID --run-id RUN_ID
```

Status opens an existing compatible database read-only. It does not create a
workspace, migrate data, acquire the writer lease or recover an active run. Other
CLI commands that still use writable initialization acquire the lease, including
older management commands. A desktop or foreground owner therefore makes those
commands return busy. Offline report and archive readers retain their separate
read-only paths.

Recover the exact saved run after its prior owner has ended:

```sh
ai-security-scanner-cli --data-dir /private/scanner-data --json \
  scan recover --case-id CASE_ID --run-id RUN_ID --wait
```

This first recovery interface performs recorded-resource cleanup and reparses
verified captured artifacts. It never substitutes a different runtime identity
for cleanup. A checkpoint requiring a new target-facing attempt is refused.
Retain its saved state and inspect it through `scan status`; target-facing
continuation still uses the desktop's existing recovery controls. A nonterminal
run can prevent a new scan from starting. Damaged captured evidence remains a
failed check and does not advertise an immediate recovery retry. Recovery does
not change unselected runs or cases. Cross-process `scan start`, `pause` and
`resume` remain unsupported.

Run/recover use these exit codes; older command conventions remain unchanged:

| Code | Meaning |
| --- | --- |
| 0 | A durable result and command receipt were delivered; inspect coverage and task outcomes |
| 2 | Invalid or unsupported request |
| 3 | Another owner holds the data directory, or an optimistic revision conflicts |
| 4 | Execution coordination, persistence, output or unresolved cleanup requires attention |
| 130 | Interrupted by SIGINT, Ctrl+C, Ctrl+Break or bootstrap cancellation, after settling owned work |
| 143 | Termination requested by SIGTERM, SIGHUP, a Windows close, logoff or shutdown event, or the bootstrap control pipe, after settling owned work |

Findings alone never select an error exit code. Reopen status after a lost output
acknowledgement instead of immediately repeating `scan run`.

A finished run saves its report automatically (see `result.report_snapshot`
above); use the [report snapshot commands](report-snapshots.md) to retrieve or
replay it. Create a [private archive](case-archives.md) when the case must be
restored elsewhere; archives are never created automatically. Platform and end-to-end acceptance are tracked in the
[development status](development-status.md) and [migration specification](plans/skill-first-cloudflare-migration.md).

For an audit that cannot be sealed and will not continue, use
`--json --data-dir DATA provider cloudflare terminate --request REQUEST.json`
with its exact recorded head and a typed reason. Termination is final; captured
retrieval remains available. Follow the [host closure procedure](cloudflare-provider.md#ending-an-audit-that-will-not-be-sealed).
