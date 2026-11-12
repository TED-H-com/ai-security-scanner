# Saved report snapshots in the development CLI

[Documentation](README.md) · [文件](README.zh-TW.md) · [Migration plan](plans/skill-first-cloudflare-migration.md)

The current development source automatically preserves snapshots after terminal scans and when
exporting single-run or selected-run combined HTML/JSON reports. It also supports manual snapshots, inspection,
original-file retrieval, exact-compatible replay, and read-only scan status.
These additions are not part of the published v0.6.0 installers. The released
desktop and its operator skill remain the default way to complete a scan.

Prefer the [pinned development bootstrap](skill-bootstrap.md) and pass these CLI arguments after its `run ... --` separator. The direct-binary examples use `./target/debug/ai-security-scanner-cli` from a contributor build with the existing `cli` feature; see [source prerequisites](getting-started.md#build-from-source). See [delivery status](release-model.md) for the distinction from the public operator skill. On Windows, use the corresponding `.exe` path.
The commands below operate on saved results; they do not start a scan.

## Admitted source audits

Single-run HTML and canonical JSON, combined HTML/JSON, and manual or automatic
report snapshots now include admitted Cloudflare source audits. Confirmed records
appear in the ordinary asset and priority lists, with the native impact and
remediation. **To validate** keeps leads separate from vulnerabilities and has no
severity. **What was not tested** lists uncovered units, their native status,
continuation paths and unresolved candidates. An incomplete audit can still have
confirmed findings. The first layer names the method “Cloudflare source audit” (“Cloudflare 原始碼稽核” in Traditional Chinese); each audit has one aggregated remaining-units gap without an extra Not tested count, and one excluded gap when units are outside scope. Remaining units share one next step: "Continue the source audit from the listed paths." Standard keeps this product sentence; paths remain under **What was not tested** and in technical detail, with location markers in Standard. Provider text remains unchanged under English or Traditional
Chinese labels; technical details keep method, issued invocation budget, role/state
counts, native attempts, lineage, custody digests and copied-original identities.

Admission automatically retains its terminal report after the case transaction.
The admit result includes `report_snapshot_state: "retained"` and `report_snapshot`
in the same record shape as foreground scans. Snapshot failure leaves admission
successful (exit 0), with `report_snapshot_state: "pending"` and
`report_snapshot_retry_command` for the same admit request. Replay preserves the
original receipt and retries the missing snapshot. Audit status reports
`next_operation: "retrieve_report"` or `"admit_replay"`. `scan recover` on an
admitted run saves only its missing snapshot; it never starts audit or scanner work.

Replay uses the frozen admission and case without source files, current grants,
provider workspace or catalog manifests. Standard redaction applies the shared masking policy to provider prose, trace and evidence descriptions, remediation, ledger text and incomplete reasons, with separate withheld-text and withheld-code counts. Provider files, paths, source scope and source references use the location marker; titles replace known private literals. Standard replaces provider coverage identifiers with `unit-` and provider fingerprints with `fp-`, followed by the first twelve lowercase hexadecimal characters of the original value’s SHA-256; product-generated identities, timestamps, enums, scores and digests remain unchanged. Confirmed findings use the localized SourceCode family summary, impact and action in Standard. The `none` profile preserves native text and code verbatim.
Private snapshot inputs retain their full context as described below.

Framework reports include the profile-redacted shared `source_audits` extension. OCSF and OSCAL export confirmed findings with provider identity and retain the full shared audit report in their mandatory hash-bound companion; provider identity is not a control conclusion. See [export details](results-and-exports.md#development-preservation-and-restore). Single-run and combined HTML attachments now accept admitted source audits. Only `none` plus the raw-artifact option includes their exact original bytes and nested names, with provider/admission/method attribution and original digests in each ZIP manifest. Standard omits provider originals without reading them and records sensitive omissions. A frozen snapshot retains selected ZIP bytes: retrieval and exact-compatible replay continue after source originals disappear; creating a new unmasked attachment export then refuses. Signed case bundles now carry the profile-aware case-wide admission document. Combined attachment overflow uses the explicitly acknowledged private archive fallback for all cases. Complete archives support read-only audit restore; run comparisons involving an audit remain unavailable. Unknown case format requirements still block report
creation and replay; intact original snapshot documents remain retrievable.

## Read current scan status

Use an existing application data directory and case ID:

```sh
./target/debug/ai-security-scanner-cli --json --data-dir /path/to/existing-data \
  scan status --case-id CASE_ID

./target/debug/ai-security-scanner-cli --json --data-dir /path/to/existing-data \
  scan status --case-id CASE_ID --run-id RUN_ID
```

Omitting `--run-id` returns all saved runs for the case. The response contains
`case_id`, `case_status`, `runs`, `run_report_snapshots`, and `coverage`; each run retains its recorded
task progress and outcomes. Status reads the existing database without schema
migration, scan recovery, or taking an execution-owner lease. It can read saved
progress while another process owns the workspace. It does not create a missing
data directory or database. Active work remains progress, not a final report.

## Reopen a completed scan

The shared scan coordinator retains private HTML and JSON snapshots after a run
finishes, fails, or is cancelled and its captured results and resource cleanup
have settled. A request that ran no checks preserves that outcome too; a saved
report is not evidence that a security check succeeded. Active work and pending
recovery do not produce interim reports.

The foreground terminal response includes `result.report_snapshot`; `scan status`
and `case show` expose `run_report_snapshots`. Each record binds the exact run
outcome to a snapshot ID, source case revision, digest, length and artifact-relative
path. Open `DATA_DIR/artifacts/RELATIVE_PATH` with `report inspect`, `retrieve` or
`replay`. Automatic snapshots use English, Standard redaction and no raw attachments;
export a report below to choose another locale or attachment setting.

Repeated terminal reconciliation retains the same original. Subsequent case edits
or triage do not replace it. If recovery settles a different outcome on the same
run, a new snapshot is appended while the earlier original remains available.
Complete archives retain all these recorded originals and restore their relative
paths. Portable report exports omit these private storage references.

If snapshot publication fails, completed findings remain saved and the foreground
command reports `terminal_report_snapshot_failed`. Once the local storage problem
is fixed, run `scan recover --case-id CASE_ID --run-id RUN_ID --wait` to finish saving
the missing report without starting a scanner or contacting the target. The response
supplies this command in `result.report_snapshot_retry_command` when applicable.
A damaged or missing *previously recorded* snapshot is rejected rather than replaced
with a new presentation. Restore its original bytes from an archive.

Status reads never create snapshots for legacy runs. Explicit recovery of an old
terminal run can save a snapshot of the context available **now**, with its actual
creation time and source revision; it cannot reconstruct an unsaved historical view.
A crash between file publication and reference commit can leave an unreferenced
private file; a later explicit recovery saves a new recorded snapshot.

## Reopen an exported report

Single-run HTML and JSON exports through the shared desktop/CLI backend now save
a private snapshot in the case's artifact directory. The exported document uses
the exact bytes retained in that snapshot, including the selected locale,
redaction and HTML attachments. Each new export gets a new snapshot; subsequent
case or triage changes leave earlier snapshots unchanged.

```sh
./target/debug/ai-security-scanner-cli --json --data-dir /path/to/existing-data \
  export create --case-id CASE_ID --run-id RUN_ID --format html \
  --locale zh-Hant --redaction standard --destination /path/to/report.html
```

The export response and saved `case show` export history include `report_snapshot`
with its ID, source case revision, digest, length and `relative_path`. Its local
filename is `DATA_DIR/artifacts/RELATIVE_PATH`. Pass that filename to `report
inspect`, `retrieve` or `replay` below. The private snapshot contains full render
context; share the selected HTML/JSON document, not that snapshot.

Complete case archives automatically retain these snapshots, even without
`--include-export-files`. Their references work under the new workspace after
restore. Missing or changed recorded snapshots cause archive creation or
verification to fail. Legacy exports without a snapshot reference remain legacy;
the product does not reconstruct their original presentation from current data.

Snapshot or history-write failure rejects the export and removes newly created
documents from that attempt. Existing destinations are preserved. A process
crash between file publication and the database commit may leave an unreferenced
private file; it is not a successful export or a recorded historical snapshot.

## Preserve a combined report

`export combine` saves the exact HTML/JSON composition and its ordered source
list in a private snapshot. Select two to sixteen distinct terminal runs in one
case. Each source keeps its own time, findings and coverage gaps; combining reports
does not merge repeated observations or mark historical findings resolved.

```sh
./target/debug/ai-security-scanner-cli --json --data-dir /path/to/existing-data \
  export combine --case-id CASE_ID --run-id FIRST_RUN_ID,SECOND_RUN_ID \
  --format html --locale zh-Hant --redaction standard \
  --destination /path/to/combined.html
```

The response includes `id`, the ordered `selected_run_ids`, `created_at` and
`report_snapshot`. `case show` retains these receipts in `combined_exports`.
Publication writes the private snapshot and selected document before committing
history. Failure removes only files created by that attempt; existing destinations
remain intact. The desktop uses the same service.

Use the recorded snapshot's artifact-relative path with `report inspect`,
`retrieve` and `replay`, just as for a single-run report. Combined snapshots use
`ai-security-scanner.report-snapshot/v2`; inspection returns `selected_run_ids`
and omits the single-source `run_id`. Existing single-run v1 snapshots remain
readable. The complete composition and its generation time are frozen, so replay
needs neither the current case nor the original workspace. An unavailable renderer
can retrieve originals without decoding newer domain variants.

A private manual snapshot can select multiple runs too:

```sh
./target/debug/ai-security-scanner-cli --json --data-dir /path/to/existing-data \
  report snapshot --case-id CASE_ID --run-id FIRST_RUN_ID --run-id SECOND_RUN_ID \
  --acknowledge-private-context --locale zh-Hant \
  --destination /private/path/combined.snapshot.json
```

Manual snapshots do not append export history; select them with
`archive create --report-snapshot PATH` when archiving. Automatically recorded
combined snapshots always travel with the archive. `--include-export-files`
additionally preserves the selected shared files and rebinds their paths after
restore; without it, historical external paths are cleared while the original
snapshot remains available.

### Include original files

In the desktop combined-export panel, select the original-file option to permit
attachments and a private overflow archive. It is off by default and available
only for HTML; switching to JSON clears the choice. The result shows the archive
location when one was created.

Combined HTML can include one downloadable ZIP per source run and task. Each ZIP
retains original file bytes, relative directories, timestamps and a SHA-256 manifest.
Upstream HTML stays inside the ZIP; it is never inserted as executable report markup.
Standard redaction excludes artifacts marked sensitive. JSON exports do not embed
originals; the snapshot's JSON records attachment accounting for its HTML document.

```sh
./target/debug/ai-security-scanner-cli --json --data-dir /path/to/existing-data \
  export combine --case-id CASE_ID --run-id FIRST_RUN_ID,SECOND_RUN_ID \
  --format html --destination /private/path/combined.html \
  --include-raw-artifacts --acknowledge-sensitive-raw-artifacts \
  --acknowledge-sensitive-data
```

The last acknowledgement explicitly permits the **full private case archive** used
if attachments exceed the HTML budget. It may contain sensitive evidence from other
runs in the same case, even when the shared HTML uses Standard redaction. Keep that
archive private. It is created only if needed, beside the requested document; its
name and exact path/hash/length appear in `original_files` and `attachment_archive`
on the export receipt. The readable HTML shows its filename and omission counts.

The selected original files share a 64 MiB / 10,000-file budget across all sources.
The final HTML and JSON each also stay within the existing 64 MiB document limit,
including ZIP, base64 and markup overhead. If either attachment budget is exceeded,
all eligible originals move to the archive and the report remains readable. Sensitive
files excluded by redaction are counted separately from files omitted for size.
Oversized report text itself is still rejected; selecting fewer sources is required.

The fallback archive preserves the case revision before the export-history commit,
all recorded evidence, and the newly frozen combined report. Existing archive rules
still apply: all runs must be terminal and retained evidence must be intact. Source
trees and prior external exports remain separate selections. Any publication or
history-write failure removes the new HTML, snapshot and fallback archive together.

Subsequent `archive create --include-export-files` retains the fallback archive as
an export companion and rebinds its path after restore. Without that selection,
its historical hash/length remain while its external path is cleared; the complete
case archive still contains the raw evidence and saved combined report. Embedded
ZIPs remain self-contained in the report snapshot and replay after the old workspace
is removed. Manual multi-run snapshots also accept `--include-raw-artifacts` within
these limits; use `export combine` for automatic oversized-file archive fallback.

## Save a terminal report snapshot manually

Choose one finished, failed, or cancelled run that is eligible for a final
report, and a new private destination filename:

```sh
./target/debug/ai-security-scanner-cli --json --data-dir /path/to/existing-data \
  report snapshot --case-id CASE_ID --run-id RUN_ID \
  --destination /private/path/report.snapshot.json \
  --acknowledge-private-context --locale zh-Hant --redaction standard
```

`--case-id`, `--run-id`, `--destination`, and `--acknowledge-private-context` are
required. `--locale` accepts `en` (default) or `zh-Hant`; `--redaction` accepts
`standard` (default) or `none`. Snapshot creation reads the existing case
database and writes a new snapshot file. It does not append an export-history
record or automatically attach a snapshot to the run. Active runs are rejected.

**Keep the snapshot private even when `--redaction standard` is selected.** The
file contains the complete frozen case context needed by the shared renderer,
including context that is hidden in the redacted HTML or JSON. The required
acknowledgement explicitly selects this private export. Redaction controls the
saved report documents; it does not redact the frozen inputs. To share a report,
retrieve its chosen HTML or JSON document rather than sharing the snapshot.

Original scanner attachments are excluded by default. To select them, add both:

```text
--include-raw-artifacts --acknowledge-sensitive-raw-artifacts
```

The existing single-run attachment policy still applies: Standard excludes raw
artifacts marked sensitive; `none` permits those selected originals. The raw
selection is limited to 64 MiB and 10,000 files before ZIP encoding. A selected
artifact must exist and match its recorded identity and digest. The HTML embeds
the resulting per-task ZIP attachments; the JSON remains a report projection.

The complete serialized snapshot is limited to **256 MiB**, including encoded
frozen inputs and original documents. An oversized snapshot or attachment set
is rejected; this implementation does not silently omit selected attachments.
Snapshot creation preserves the exact original HTML/JSON bytes, their SHA-256
digests, locale and disclosure choices, case revision, and renderer identity.
Later changes to the case or triage require a new snapshot to appear in a new
saved report.

## Inspect, retrieve, or replay offline

Once saved, these operations need only the snapshot and the trusted CLI binary.
They do not open the case database or require the original workspace, scanner
runtime, model service, network, or a `--data-dir`. Supplying `--data-dir` does
not make them create or open that directory.

```sh
./target/debug/ai-security-scanner-cli --json \
  report inspect --snapshot /private/path/report.snapshot.json

./target/debug/ai-security-scanner-cli --json \
  report retrieve --snapshot /private/path/report.snapshot.json \
  --format html --destination /path/to/retrieved-report.html

./target/debug/ai-security-scanner-cli --json \
  report replay --snapshot /private/path/report.snapshot.json \
  --format json --destination /path/to/replayed-report.json
```

Both `retrieve` and `replay` require `--snapshot`, `--format html|json`, and
`--destination`. They use the snapshot's saved locale and redaction; they do not
accept new presentation settings. `--json` is a global output option and emits
compact machine-readable status or receipts; it does not select the saved
document format.

| Operation | Result |
| --- | --- |
| `inspect` | Verifies saved lengths and digests, identifies the case/run and renderer, and reports `replay_available`, any `replay_unavailable_reason`, document hashes, and disclosure settings. |
| `retrieve` | Writes the exact saved HTML or JSON bytes, including when the current CLI lacks a compatible renderer. |
| `replay` | Re-renders frozen inputs using the exact compatible trusted renderer built into this CLI, checks equality with the saved document, then writes it. A mismatch publishes no output. |

An unsupported renderer reports `replay_available: false` while intact original
documents remain retrievable. That is a retrieve-only snapshot, not a promise
that another renderer can recreate it. This implementation does not download or
execute renderer code from a snapshot. An unsupported snapshot container schema
is rejected.

Snapshot, retrieve, and replay return a receipt containing `snapshot_id`,
`operation`, `path`, `sha256`, and `byte_length`. All three refuse to overwrite an
existing destination. A corrupt saved digest rejects inspection, retrieval,
and replay. Integrity checks detect inconsistent bytes; they do not authenticate
the producer or validate the original security findings.

## Current boundary

A report snapshot preserves a **single run's presentation**. `inspect` reports
`contains_sensitive_context: true` and
`case_restore_available: false`. It does not restore a case database, renew scan
authorization, or recreate excluded source files. Existing six-format exports
and selected-run HTML/JSON composition retain their separate behavior.

Complete case preservation uses the separate [archive commands](case-archives.md),
which include saved snapshots and restore into a new workspace.

Admitted source audits use the shared report surfaces listed above; other provider outputs and complete archives remain pending. The [pinned bootstrap](skill-bootstrap.md)
and [foreground scan execution](foreground-scans.md) are available in development.
The accepted [migration specification](plans/skill-first-cloudflare-migration.md)
and [report fidelity/archive contract](specs/report-fidelity-and-archive.md)
define that remaining work. The source commands documented here do not switch
the public skill's default away from the released desktop.

For the exact flags exposed by a particular development binary:

```sh
./target/debug/ai-security-scanner-cli report snapshot --help
./target/debug/ai-security-scanner-cli report inspect --help
./target/debug/ai-security-scanner-cli report retrieve --help
./target/debug/ai-security-scanner-cli report replay --help
./target/debug/ai-security-scanner-cli scan status --help
```


## Failure-run snapshots

A blocked source-audit preparation or explicit termination commits an ordinary
failure run atomically with custody, then retains its terminal report snapshot
through the same shared path as admission. `outcome_run.report_snapshot_state`
is `retained` or `pending`; snapshot publication failure leaves the committed
outcome successful. Replay the identical preparation or termination request to
retry a pending snapshot. A retained replay adds no event or revision. Earlier
run snapshots remain byte-for-byte unchanged. Complete archives preserve these
snapshots, and restored audit history cannot replay mutations.
