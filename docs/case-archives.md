# Private case archives in the development CLI

[Documentation](README.md) · [文件](README.zh-TW.md) · [Report snapshots](report-snapshots.md)

The development source can preserve a saved case and restore it into a new
workspace without the original machine, a scanner runtime, or a model service.
These commands are not in the published v0.6.2 installers. The released desktop
and its operator skill remain the default scan entry.

Prefer the CLI from the [pinned development bootstrap](skill-bootstrap.md), forwarding arguments after `run ... --`. Direct contributor builds use the existing `cli` feature; see [source prerequisites](getting-started.md#build-from-source) and [delivery status](release-model.md). Examples use
`./target/debug/ai-security-scanner-cli` (`.exe` on Windows). These operations
read saved results and never execute a scan or source file.

## Create a private archive

```sh
./target/debug/ai-security-scanner-cli --json --data-dir /path/to/existing-data \
  archive create --case-id CASE_ID \
  --destination /private/path/case.scanner-archive.tar.gz \
  --acknowledge-sensitive-data
```

Every recorded run and task must be terminal, with no pending execution cleanup.
Choose an existing private destination parent; the CLI does not create missing
parent directories for an archive or restore.
An empty case can also be preserved; that does not represent a completed scan.
Creation reads one consistent saved case and event history without migrating the
source database, recovering a scan, or taking its writer lease. It checks the
case revision again after reading the selected files. A conflict requires retry.

The archive includes the exact original case JSON, the full portable case and
event history, all recorded raw evidence, automatically retained terminal-run, single-run and combined HTML/JSON export
snapshots, and a newly frozen default report snapshot for every terminal run.
Missing or corrupted recorded evidence or report snapshots
cause failure. Findings, inventory, frozen observations, triage, grouping,
comparisons, export history and historical scope remain preserved.

**This is a private export.** Case context and original evidence may contain
secrets even when a saved report uses Standard redaction. The required flag
explicitly selects that data. Credential-vault material, signing private keys,
execution leases and live workers are excluded. There is no redacted archive
mode; use a retrieved report document for a sharing view.

Select additional retained content when needed:

| Option | Preserved content |
| --- | --- |
| `--include-source-snapshots` | Recorded immutable workspace trees and connector captures, checked against their saved digests. It never reads the current target tree. |
| `--include-export-files` | Exact previously exported files and their recorded coverage companions. Their original signatures remain historical data. |
| `--report-snapshot /path/to/earlier.snapshot.json` | Exact bytes of an earlier saved report snapshot for a run in this case. Repeat to retain multiple views. |

Unselected source and external export files are listed as omissions. Recorded
export snapshots are always included, with their exact original HTML/JSON bytes
and selected attachments. A newly generated snapshot is a view saved today,
not a reconstructed historical export. Select any earlier manually saved snapshot
explicitly with `--report-snapshot`. Unsupported historical renderer identities
remain retrieve-only.

If a source refresh left only an old snapshot ID or hash without its full
retained reference, source inclusion fails rather than claiming that the latest
tree preserves that history. Archiving without source selection still preserves
the case, evidence and reports with the source omission recorded.

Combined reports retain embedded original-file ZIPs in their snapshots. When an
export used a private overflow archive, `--include-export-files` also preserves
that companion and verifies its recorded hash and length. Restore rebinds selected
companion paths and clears unselected external paths. See [combined originals](report-snapshots.md#include-original-files).

## Archives containing admitted source audits

A case with at least one stored Cloudflare admission can be archived and verified.
Its archive adds `provider-history.json`, referenced by `archive-index.json`, with
schema `ai-security-scanner.provider-archive-history/v1` ([schema](../schemas/provider-archive-history.schema.json)).
The inventory covers every recorded audit preparation: admitted, sealed without
admission, unsealed, or blocked. Unsealed work is inert historical custody; an
interrupted assignment does not invent a terminal audit outcome.

Each prepared audit retains its exact `session.json`, every sealed package document,
all recorded document revisions, and every accepted output, including outputs that
the seal did not select. Discarded outputs are marked unavailable without a file.
Unrecorded files and orphan objects are excluded. Task originals keep their existing
paths and must match their corresponding package members by SHA-256 and length.
Seals, retention documents, provider documents and `admission_ready` remain unchanged.
Every included file also appears in the outer manifest with its hash and length.

`--include-source-snapshots` includes the sealed package's `retained/source-view/`
bodies as well as the existing retained source selections. Without it, those bodies
appear only in the typed omission inventory, with path, hash and length. The manifest
states: “Source snapshots inside source-audit packages were not included; their bytes
cannot be rechecked from this archive.” Source manifests, digests and lineage remain.
Live product-generated source views retain their existing omission. Source exclusion
is not redaction: provider documents and evidence may still contain source excerpts.

The transport stays `ai-security-scanner.archive/v1`. Provider-aware manifests declare
sorted `required_capabilities`: `cloudflare_audit_admission/v1` and
`provider_archive_history/v1`. Readers reject unknown capabilities before staging;
older strict readers reject the added manifest field. Cases without admissions or failure rows keep
the legacy members and omission wording, including cases with audit preparations.

Creation and verification share offline admission, evidence, event-chain, captured
inventory and sealed-package checks. They never execute a provider, validator or
model. Creation verifies its staged snapshot before publishing the archive.
`archive verify` reports `case_data_restore_available: true` after those checks.
Preview and restore accept the known capability set. Restore stages every member
at its original relative path, verifies provider history and packages again over
those staged bytes, imports the case, checkpoints the database, and publishes the
new workspace with its receipt. It invokes no provider, validator, model or
admission transaction and does not regenerate reports. Failed staging publishes
nothing; retry against an unchanged published destination returns its saved receipt.

Restored audits are read-only history. Reports, exports, bundles, original downloads
and `retrieve-captured` remain available, including superseded revisions and accepted
outputs omitted from a seal. Discarded outputs still have no recoverable bytes.
Preparation replay, checkpoints, validation, finalization and admission (including replay) refuse
with `restored_session_inert`, even after a fresh scope grant. Start a new audit with
a new request ID and current authorization. The boundary is the preparation's terminal
event preceding the latest `case.restored` event, including in legacy archives.

Provider restores add a strict `provider_history` object to that event with schema
`ai-security-scanner.restored-provider-history/v1`, the history file's SHA-256 and a
sorted `source_bodies_omitted_sessions` list. Database migrations remain [1, 2].
Only listed restored audits use contextual `included_payload` verification and explain
that source bytes cannot be rechecked; all others stay strict. Standalone retained
package inspection and retrieval remain strict. Missing unlisted source bodies fail.

Rearchiving preserves sealed package bytes and inherited source-body omissions,
even with source inclusion selected. Each sealed package omits either its entire
indexed source-body set or none; completeness reflects actual omissions. The source
omission sentence appears once when sources are excluded or an omission is inherited.
When sources are selected but an inherited workspace snapshot remains missing, a
separate manifest omission states: “Source snapshots that were not included in the
archive this case was restored from are still missing; this archive does not preserve
the full assessed source tree.” Verification and restore require this sentence exactly
once when the inherited snapshot inventory and indexed source files show that gap,
and refuse an inconsistent omission with `archive_omission_mismatch`.
Disabled current source capabilities stay disabled; pinned historical archive references
retain the source inventory for rearchiving. Provider previews and receipts add
“restored source audits kept as read-only history” after the existing five transformations.
Legacy preview fields, transformations and event payload keys stay unchanged.
Admitted-run comparisons and unsealed terminal failure rows remain unavailable.

Archive commands retain exit 1 for errors. The JSON error object's `error_code` identifies:

| Code | Refusal |
| --- | --- |
| `archive_duplicate_admission` | Ambiguous admission, audit, run or task identity |
| `archive_original_missing` | A required task original or binding is missing |
| `archive_original_extra` | Extra or duplicate task originals or bindings |
| `archive_content_mismatch` | Bytes, length, digest or retained projection differ |
| `archive_admission_binding_mismatch` | Admission, case, run, task or original ownership differs |
| `archive_provider_unsupported` | Unsupported provider or projection schema |
| `archive_evidence_mismatch` | Confirmed evidence does not resolve to its retained record |
| `archive_history_mismatch` | Invalid history, package, inventory or unreferenced provider member |
| `archive_omission_mismatch` | Source-body omissions differ from the indexed set or overlap included files |
| `archive_capability_unsupported` | Unknown required reader capability |

## Verify and preview offline

```sh
./target/debug/ai-security-scanner-cli --json \
  archive verify --archive /private/path/case.scanner-archive.tar.gz

./target/debug/ai-security-scanner-cli --json \
  archive restore-preview --archive /private/path/case.scanner-archive.tar.gz \
  --destination /private/path/restored-workspace
```

For legacy archives, both commands verify all selected bytes, lengths, hashes and case references.
They need only the archive and a trusted CLI binary. They do not open the
original database or create the destination. Preview reports destination
availability and the operational changes that restore will make.

`integrity_valid: true` means internal consistency. This archive format has no
new producer signature; `authenticity: "not_authenticated"` states that boundary.
Hashes do not establish authorship, scan authorization or finding correctness.
The existing signed `.case.tar.gz` report bundle keeps its separate meaning.

## Restore and reopen

```sh
./target/debug/ai-security-scanner-cli --json \
  archive restore --archive /private/path/case.scanner-archive.tar.gz \
  --destination /private/path/restored-workspace \
  --acknowledge-sensitive-data

./target/debug/ai-security-scanner-cli --json \
  --data-dir /private/path/restored-workspace scan status --case-id CASE_ID
```

The destination must be a new directory inside an existing real parent. Restore
rejects a parent namespace that another untrusted local user could replace.
An archive may hold only the case documents and the `artifacts/`, `exports/` and
`report-snapshots/` folders that archive creation writes. Verify, restore preview
and restore refuse any other top-level name, so an archive can never supply the
restored workspace's database, receipt or runtime files.
It validates into private staging on the destination filesystem, creates and closes
the new database, saves the restore intent and receipt, then publishes the
complete directory atomically without replacing another path. It retains the
case and record IDs, assigns a new workspace identity, and starts local storage
revision 1. The historical event sequence remains intact with a new restore
event appended.

The operational copy removes current scope grants and resume tokens, clears
asset owner confirmations, disables source connections and capability metadata,
and rebinds selected exports to their restored copies. Unselected export paths
are cleared. These transformations are recorded in the receipt. The original
case documents and frozen run context preserve historical values; they grant
no new execution authority. A future scan needs fresh valid scope and connections.

A failure before publication leaves no destination. If publication succeeded
but its acknowledgement was lost, repeating the same restore returns its saved
receipt only when the workspace still matches the retained inventory, hashes
and intent. Changed data or a different existing directory is rejected without
overwrite. There is no merge into an existing workspace.

Restored files include `casework.db`, `case.json`, `original-case.json`,
`archive-index.json`, `artifacts/`, `report-snapshots/`, selected `exports/`, and
`restore-receipt.json`. Use a snapshot listed in `archive-index.json` with
[`report inspect`, `retrieve`, or `replay`](report-snapshots.md#inspect-retrieve-or-replay-offline).
Retrieval preserves exact HTML/JSON bytes. Replay requires an exact compatible
trusted renderer and checks byte equality. Restore does not execute code from
the archive or retrieve a renderer from it.

## Supported boundaries

- Schema: `ai-security-scanner.archive/v1`; unknown schemas or case fields that
  this core would discard are rejected before destination publication.
- Limits: 50 GiB decompressed, 100,000 physical tar entries including metadata,
  512 MiB per file, 16 MiB manifest, 64 MiB portable case, and 256 MiB per report
  snapshot. Staging also enforces an early conservative total-size budget.
- Portable paths are bounded to 4,096 bytes and 255 bytes per component.
  Traversal, absolute paths, links, devices, reserved Windows names, duplicate
  entries and case-folded or file/directory collisions are rejected. Long names
  use bounded GNU tar metadata; arbitrary tar extensions are unsupported.
- Existing legacy data must have a verifiable reference graph. Missing history
  remains unknown; an incomplete graph cannot be labeled a complete restore.
- Temporary storage must also have a trusted parent. An unsafe temporary directory
  returns `unsafe_temporary_directory`; point `TMPDIR` at a private directory.
  Windows uses the existing product namespace verifier and rejects unsafe `TEMP`.
- The current format preserves the existing domain, including terminal-run and
  combined report snapshots. Admitted Cloudflare archives support creation and
  verification and read-only restore; the complete skill workflow remains pending. The development
  [core bootstrap](skill-bootstrap.md) can run these offline archive commands.

`case archive CASE_ID` still changes a case's lifecycle status. The new top-level
`archive` commands preserve files; neither the old status command nor the old
signed report bundle has been redefined.

## Terminated audit custody

An explicit host termination remains in the `unsealed` archive state. In a
provider-aware archive, `provider-history.json` adds the optional strict object
`termination: {entry_sha256, occurred_at, reason}` for that preparation. The
recorded head is the terminal entry; seal and admission fields remain null and
sealed-package completeness remains false. All prior captures and document
revisions retain their existing custody semantics.

If any inventoried preparation is terminated, the manifest also requires
`cloudflare_audit_terminal/v1`. Verification reconstructs termination from the
archived events and requires exact inventory equality; a missing, wrong or
unexpected termination is `archive_history_mismatch`. Restored terminated audits
stay inert, including identical termination replays; captured retrieval remains
available when the captured bytes were included.

Provider-aware selection requires an admission or a failure task. Cases without either
keep their legacy archive members and omission sentences. Archives without
termination or failure tasks keep their existing capability list and history bytes;
the legacy archive byte pin is unchanged. Termination adds an ordinary failed check
to the case and shared report.


## Failure-only source-audit cases

An admitted audit or an `agent_audit_failure` task makes an archive provider-aware,
including a case containing only failed/not-executed source-audit checks. The
strict optional `outcome_run: {run_id, task_id}` in `provider-history.json` binds
each blocked or terminated preparation to its case row. Verification reconstructs
this inventory from `case.json` and archived events, checks the outcome digest,
and rejects missing, extra or mismatched bindings with `archive_history_mismatch`.

Required capabilities are sorted and derived from contents:
`provider_archive_history/v1` is always required for provider-aware archives;
`cloudflare_audit_admission/v1` is required only for admissions;
`cloudflare_audit_terminal/v1` is required for a termination or a failure task.
Admitted archives without either retain their existing capabilities and history
bytes. The legacy archive byte pin is unchanged. Failure rows restore only through
the verified provider path, remain historical and cannot replay preparation or
termination (`restored_session_inert`). Restore never materializes or backfills rows.
