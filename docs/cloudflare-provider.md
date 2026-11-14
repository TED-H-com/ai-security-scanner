# Cloudflare source views and reported-bundle validation

These are unreleased development capabilities; see [publication status](release-model.md).

The development CLI validates individual Cloudflare documents or cross-checks a
reported bundle against an explicitly selected source view, and can preserve a
validated bundle for offline retrieval. Both validation entries use the
pinned upstream validators. They do not run an audit, grant scan authorization,
import findings, or establish that a reported vulnerability is true.

The single-document command below checks only its document. The
[reported-bundle command](#reported-bundle-validation) additionally checks files,
source locations, coverage links and supplied verifier output. For a captured audit
record, [terminal validation](#terminal-validation-from-the-audit-record) generates
the bundle from product-held bytes and adds the record checks;
[finalize](#sealing-the-audit-record) seals a matching result and commits workflow provenance.

Use the CLI produced by the [pinned source bootstrap](skill-bootstrap.md), with
Node.js 24 available on an absolute `PATH` entry:

```sh
ai-security-scanner-cli --json provider cloudflare validate-document \
  --document findings --input /private/audit/findings.json

ai-security-scanner-cli --json provider cloudflare validate-document \
  --document coverage-ledger --input /private/audit/coverage-ledger.json
```

The same arguments can follow the bootstrap's `run ... --` separator. On
PowerShell, use one line and an absolute Windows input path. Validation requires
no scanner runtime, data directory, case, credential or network connection.
It can run while another process holds the case writer lease.

The JSON receipt identifies the document kind, exact input SHA-256 and byte
length, upstream revision, and the digest of the embedded validator resources.
`validation.valid` records the document decision; `validation.phase` distinguishes
input, preflight, parse and upstream validation. The receipt always reports
`validation_scope: "single_document"`, `audit_performed: false` and
`admission_ready: false`. Even a valid empty array does not establish completed
coverage or absence of vulnerabilities. The input is never rewritten.

| Exit code | Meaning |
| --- | --- |
| 0 | The document passed the input checks and upstream validator. |
| 2 | The document was rejected; stdout contains a receipt with errors. |
| 1 | File access, UTF-8, runtime or transport failure; stderr contains the error. |

Invalid command syntax also exits with code 2, following the CLI parser's existing
contract; it has no validation receipt.

## Reported bundle validation

```sh
ai-security-scanner-cli --json provider cloudflare validate-bundle \
  --bundle /private/audit/retained --source-view /private/audit/reviewed-view
```

Use real directory paths: every root ancestor and member component is opened
without following symbolic links or reparse points. Unix reads use directory
handles and `openat`; Windows keeps directory handles that deny deletion and
rename while opening children. Device/UNC paths and unsafe portable member names
are refused. Each file must have one physical link, stable identity, matching
length and matching SHA-256. The reader checks all selected files again before
returning. Native documents and source-view files must be valid UTF-8.

The bundle contains `provider-manifest.json`, the seven native documents listed
in the migration plan, and explicitly indexed files under
`agents/<agent-id>/artifacts/`. The manifest names the selected files; the command
does not recursively discover, copy or execute other files, including scratch
entries. The selected source view is a separate directory with its own indexed
file set. Rust alone reads the source-view files and checks their hashes and
locations; Node receives only report and verifier JSON.

[The complete synthetic fixture](../tests/fixtures/cloudflare/bundle/provider-manifest.json)
and [its source view](../tests/fixtures/cloudflare/source-view/) demonstrate the
wire contract. They contain fabricated assessment statements for reference
validation tests; they are not evidence of a real vulnerability or audit.

| Manifest field | Contract |
| --- | --- |
| `schema_version` | `ai-security-scanner.cloudflare-bundle/v1` |
| `provider_id`, `upstream_commit` | The exact pinned provider and revision. |
| `binding` | Case, asset, run, task, session and attempt IDs. These are declarations, not authority to create or change a case. |
| `source` | Canonical snapshot ID/digest (both nullable), view ID/digest, source ref, declared policy ID and indexed files. |
| `files` | Relative path, SHA-256 and byte length for each native document or retained artifact. |
| `verifier_assignments` | Assignment/agent identity, full binding, role, fingerprint, view/record digest, owned output path and start/end timestamps. |
| `reported_counts` | Separate confirmed, needs-validation and rejected totals; severity counts only for reported confirmed records. |

Unknown product-manifest fields, duplicate decoded JSON keys, repeated paths,
case aliases, file/directory collisions, and unsupported versions are rejected.
The source-view index and each selected file are verified; canonical source
lineage and the declared view policy remain unverified. Missing canonical lineage
is represented by nulls, never fabricated. Native `run-metadata.json` must agree
with the run/source binding, terminal status, declared scope and profile, and
supply a repository, target and nullable invocation budget.

The file-index digest uses recipe `ai-security-scanner.file-index/v1`: SHA-256 of
that UTF-8 recipe followed by a NUL byte, then entries sorted by UTF-8 path bytes.
Each entry contributes the path byte length as u64 little-endian, path bytes,
32 raw SHA-256 bytes, and file byte length as u64 little-endian. The source view
uses this digest. The bundle digest uses the same recipe over all indexed bundle
files plus the original manifest itself, so identity, scope declarations, counts
and source binding participate in the preview identity. Raw document bytes are
never rewritten.

The command checks every trace/evidence line against the actual source-view file,
including the candidate verifier's record. Reviewed paths must resolve to an
indexed file or directory prefix. Starting paths have the same rule, except an
`out_of_scope` unit may name paths absent from the view; those paths must still
be safe relative paths. Current and archived local checks must
reference retained files owned by the stated agent. Unowned retained artifacts
are rejected. Ledger fingerprints must link every retained finding; a candidate
without a record requires an incomplete run and a specific ledger blocker.
A `candidate` unit with finalized records is not automatically treated as failed.
A complete run cannot retain planned/in-progress units or an empty ledger;
blocked/deferred/excluded coverage remains visible in the native ledger.

A candidate verifier output is the upstream `decision`/`record` object. Its
record is validated with the pinned findings validator. A final verifier output
must be the upstream `verified`/`fingerprint` object for the exact current record.
Record digests use compact `serde_json` serialization with sorted object keys;
string values, payload whitespace and code contents stay intact. Receipts must
bind the current run/task/view, have distinct assignment and agent identities,
use their own retained output path, and respect candidate/final time order.
Current and archived hunters cannot verify their own candidate. The pinned
carried-record owner exception is preserved. `standard` and `deep` require
separate candidate/final verifiers for `confirmed` and `needs_validation` records.
A `rejected` record requires only its candidate decision. `quick` uses its one combined candidate
verifier and must retain that verifier's exact record. Unresolved final
replacements and prose-wrapped or malformed verifier JSON are refused.

A successful receipt has `validation_scope: "reported_bundle"` and contains a
versioned `ProviderReportProjection`. It preserves native records, original
indexes and record digests, evidence locations and view-file hashes, all ledger
history, coverage counts, unresolved candidates and verifier assignment links.
Reported confirmed severity counts are separate from needs-validation and
rejected records. It creates no `FindingStatus::Confirmed`, case, writer lease,
report export or database entry. Invalid references return no projection.

All supplied receipts remain `provenance: "reported_only"`, even when their
relationships pass. `audit_performed`, `admission_ready`,
`canonical_snapshot_binding_verified` and `source_authorization_verified` stay
false. The tool cannot authenticate external agent independence, inspect what an
agent actually saw, verify sandbox execution, or certify prose accuracy. It does
not parse Markdown claims into product findings; the native JSON governs counts.
This is the validation and report-data foundation for the later trusted workflow,
not that workflow's final admission command.

| Bound | Limit |
| --- | --- |
| Manifest | 4 MiB |
| Selected bundle files | 4,096 files / 64 MiB total |
| Selected source-view files | 10,000 files / 128 MiB total |
| One file | 8 MiB; native findings/ledger remain 5 MiB each |
| Current verifier assignments | 2,000 |
| Candidate records passed to upstream together | 5 MiB total |
| Product JSON | Depth 64, 10,000 array items, 1,000 object fields, 500,000 values |
| Reference diagnostics | 100 entries |

The existing Node deadline, output and preflight bounds also apply. Product JSON
also rejects unpaired Unicode surrogate escapes instead of retaining ambiguous
strings. Exit 0 means the reported bundle passed mechanical checks; exit 2
returns a receipt for upstream/reference rejection. Unsafe files, invalid
manifests, malformed JSON or runtime failures exit 1 with a diagnostic. The CLI
parser uses its existing exit 2 for invalid command syntax without a receipt.

## Private retention and offline retrieval

After inspecting `validate-bundle`, preserve the exact selected bundle using its
`bundle_sha256`. Choose a new destination beneath an existing private parent:

```sh
ai-security-scanner-cli --json provider cloudflare retain-bundle \
  --bundle /private/audit/retained --source-view /private/audit/reviewed-view \
  --expected-bundle-sha256 EXPECTED_BUNDLE_SHA256 \
  --destination /private/audit/saved-provider
```

Retention captures only indexed native files and source-view files into private
staging, verifies their hashes and unchanged input identities, then validates
those captured bytes. It writes `bundle/`, `source-view/`, `projection.json`,
`validation.json` and `retention.json` before publishing the whole directory
atomically without replacement. Invalid data, a stale preview digest, failed
validation or a missing Node runtime leaves no published destination. Concurrent
writers to one destination can publish only one complete result. Existing
folders/files are never replaced, and existing parent permissions are not changed.

The returned `inspection.retention_sha256` binds the saved index. Keep this digest
with the caller's record; it is required when retrieving a member. Raw files and
the reviewed source view may contain sensitive content. This private directory
is not a redacted handoff, a full canonical-repository backup or a case archive.
No unindexed scratch file is copied. The application provides no in-place editing
command; a changed bundle is preserved as another new destination.

The directory can be moved and the original bundle/view removed. These commands
then work without Node, containers, a model, the original workspace or the case
database:

```sh
ai-security-scanner-cli --json provider cloudflare inspect-retained \
  --input /private/archive/saved-provider \
  --expected-retention-sha256 EXPECTED_RETENTION_SHA256

ai-security-scanner-cli --json provider cloudflare retrieve-retained \
  --input /private/archive/saved-provider \
  --expected-retention-sha256 EXPECTED_RETENTION_SHA256 \
  --member projection.json --destination /private/export/provider-projection.json
```

Any indexed native document, retained artifact, source-view file or saved JSON
can be retrieved with its full relative member path, for example
`bundle/findings.json` or `source-view/src/handler.c`. Retrieval verifies the
complete indexed payload and the saved receipt/projection relationships before
publishing the selected bytes as a new private file. All retrieved bytes match
the stored original; Markdown and command strings are never executed.

Inspection may omit the expected digest to check a directory's internal
consistency, in which case `expected_identity_verified` is false. Passing a digest
compares against that supplied identity; it is not an authenticity signature.
Inspection always reports `validation_reperformed: false`. It checks hashes and
saved contracts rather than rerunning validators or certifying reported claims.
A different producer-core digest is reported by `producer_core_matches: false`
and does not prevent retrieval of the supported format. Unknown format versions
are rejected; no saved code or validator is loaded.

`retention.json` uses `ai-security-scanner.cloudflare-retained/v1`. It contains the
producer-core identity, bundle/view binding, separate bundle/source/document
indexes, and a combined file-index digest using the recipe above. Its own exact
bytes are bound by the externally retained `retention_sha256`. The index is
limited to 8 MiB, each saved projection/validation JSON to 64 MiB, and total
indexed payload to 328 MiB. Product JSON structural limits still apply. Coverage
ID expansion into report references is capped at 8 MiB before allocation; a
native-valid document can exceed this additional product projection bound.
All limits are checked before publication, including the ability to read the
saved format offline. Retain/inspect/retrieve failures exit 1; successful
operations exit 0 (CLI syntax errors retain the parser's exit 2).

Retention does not write a case, change human finding status, acquire a case
writer lease, grant authorization or create trusted workflow provenance.
`reported_only`, `audit_performed: false` and `admission_ready: false` remain
unchanged. The product-owned source-view core is described below. Durable case
admission is available through the separate admit command below; the audit record can now be sealed, and one supported host
has completed a synthetic acceptance run.

## Pinned upstream and adapter

[The provider manifest](../providers/cloudflare/provider.json) records the current
capabilities. [The lock](../providers/cloudflare/upstream.lock.json) records all 22
files at commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` of
[`cloudflare/security-audit-skill`](https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8).
The vendor recipe copies each regular Git blob at that exact revision without
editing its bytes, retaining its path, Git object ID, original mode, SHA-256 and
length in the lock. The MIT license, method documents, schema, validators and
their tests remain intact. The inventory test rejects changed, missing or extra
vendor files. Prompt documents are reference material, not executable product
instructions or evidence that an audit occurred.

The separate product wrapper calls the exported upstream validators and retains
their verdict and schema semantics. The ledger's exported text preflight runs
unchanged. The findings validator does not export its CLI preflight; the wrapper
contains an attributed verbatim copy, checked against the pinned source by a
parity test. The wrapper additionally rejects duplicate decoded JSON keys.
It does not execute commands, payloads, validation plans or module paths found
inside a report. `needs_validation` findings continue to reject severity fields.

The Rust reader rejects non-regular files, final-component symbolic links or
reparse points, physical hard links, oversized input and files that change while
being read. The selected file is checked again against its open handle after
reading; this standalone entry does not resolve relative bundle members or
validate ancestor symlinks. UTF-8 must be valid. Each document is limited to
5 MiB, with the upstream preflight's depth,
collection, canonical-key, memory and error-count limits preserved.
Windows device/UNC paths, reserved names and alternate streams are refused
before opening a file.

Embedded code and schema are extracted to an owned private temporary directory;
raw document bytes travel through stdin. Node starts from that directory with
an empty environment except required Windows OS directory variables, a 128 MiB
V8 old-space limit, and no native addons or global module lookup. `NODE_OPTIONS`,
`NODE_PATH` and dynamic-loader variables are not inherited. The process has a
15-second deadline, bounded concurrent input/output, and 256 KiB per output
stream. Failure terminates and waits for the owned process; a cleanup wait is
bounded to two additional seconds. Diagnostics are limited to 100 entries and
2,048 code units each, with terminal-control characters escaped. V8 old-space is
not a total OS memory limit, and this validator process is not an audit sandbox.

The embedded adapter, validators, schema and license participate in the core
bootstrap cache key and core identity. Method-only changes do not rebuild the
native core. Only the locally installed trusted Node executable is used; no
runtime or upstream dependency is downloaded by validation.

## Validation and remaining work

Run the unchanged upstream tests, adapter contract tests and CLI subprocess tests:

```sh
node --test providers/cloudflare/upstream/skills/security-audit/*.test.cjs
node --test tests/skill/cloudflare-provider.test.mjs
cargo test --locked --no-default-features --features cli \
  --test cli_cloudflare_provider --test cli_cloudflare_bundle
cargo test --locked --no-default-features --features cli --lib cloudflare_provider::tests
```

Linux execution is recorded in [development status](development-status.md).
The native CI matrix runs the document, bundle, source-view and audit tests on
Linux, macOS and Windows; real-host journeys on macOS and Windows have not been
run yet. The source-view core below does
not promote external bundle trust. Audit custody through finalization and host
instructions are available in development, and one supported host has completed a
synthetic acceptance run; durable case admission is implemented below, with shared report integration now available,
as described in the [accepted migration plan](plans/skill-first-cloudflare-migration.md).


## Product-owned source views

`prepare-source-view` copies an approved frozen repository into a model-readable
tree. It requires a repository-profile v3 snapshot, an owner-confirmed asset that
is no longer a candidate, and an effective `LocalArtifactRead` grant. Every preparation request,
including retries, requires explicit scope and model-processing acknowledgement.
The host ID is caller-declared. Preparation performs no audit or model call.

```sh
ai-security-scanner-cli --data-dir /private/case-data --json provider cloudflare prepare-source-view \
  --case-id CASE_ID --asset-id ASSET_ID --expected-snapshot-sha256 SNAPSHOT_SHA256 \
  --scope-path src --scope-path tests --request-id REQUEST_ID \
  --acknowledge-model-processing --confirmed-by OPERATOR --host-id DECLARED_HOST

ai-security-scanner-cli --json provider cloudflare inspect-source-view \
  --input /private/case-data/artifacts/CASE_ID/source-views/VIEW_ID \
  --expected-manifest-sha256 MANIFEST_SHA256

ai-security-scanner-cli --data-dir /private/case-data --json provider cloudflare source-view-status \
  --case-id CASE_ID --request-id REQUEST_ID
```

An effective grant matches the asset and permission, has a nonblank confirmer,
has already started and has not expired. Selection prefers no expiry, then the
latest expiry, then the smallest grant ID. No qualifying grant gives
`source_authorization_missing`; qualifying grants that are all expired or
future-dated give `source_authorization_expired`. Only the grant that authorized
the read is recorded. Authorization is checked again immediately before
publication, after any damaged or obstructing entry is set aside, and as the last
step before recording the receipt inside the transaction. Expiry produces a durable blocked receipt;
already published bytes remain unreferenced derived data.

Use `--scope-path .` for the entire snapshot or repeat the flag for exact
canonical files/directories. When a request reaches snapshot evaluation, every
supplied selector must exist with exact case, even if redundant. An earlier
blocker or a saved blocked receipt returns that blocker without checking selectors
against the snapshot. Traversal, globs, empty selectors and trailing slashes are
invalid. Selectors are sorted and deduplicated, redundant
descendants removed, and any selection containing `.` becomes exactly `["."]`.
`src` never selects `src2`. Repository content cannot configure scope or policy.
`--host-id` accepts 1–128 ASCII letters, digits, underscores or hyphens;
`--confirmed-by` accepts nonblank text up to 200 bytes without control characters.

### Receipts, retries and exit codes

The terminal envelope is `ai-security-scanner.source-view-command/v1`.
Success has `result.status: ready|blocked` and `result.replayed: true|false`.
Receipts bind the view ID, manifest digest, selected grant and a separately hashed
acknowledgement scoped to case, asset, snapshot, normalized scope, policy and
declared host. They use the existing transactional case-event store.

Identical normalized inputs under a saved blocked request return that receipt
unchanged; use a new request ID after fixing its cause. A saved ready request repeats authorization, binding, snapshot and
publication checks. It returns the saved receipt without a new event only when
the view ID, manifest digest, file-index digest and effective grant digest still
match. A different effective grant is rejected before any staging or publication.
A missing directory is rebuilt from verified canonical bytes. Otherwise,
`error_code: saved_receipt_not_current`, `retryable: false` and a machine-readable
`reason` identify the blocker, `identity_changed` or `grant_changed`. No view or
manifest paths are returned. Different inputs under the same request ID conflict.
A receipt that appears during evaluation causes a retryable conflict; retrying
takes the replay path. `source-view-status` retrieves historical receipts without
asserting readiness.

| Exit | Meaning |
| --- | --- |
| 0 | Durable ready or blocked receipt, newly committed or replayed; inspection/status succeeded |
| 2 | Invalid or unsupported input; no receipt committed |
| 3 | Writer contention, stale expected snapshot, request conflict or saved receipt no longer current |
| 4 | Persistence, I/O, serialization or output delivery failure |
| 130 / 143 | Preparation stopped for SIGINT / Unix SIGTERM before committing |

A completed commit is delivered as success even if a signal arrives afterward.
Output write/flush failures leave committed receipts available through status.
Inspect and status are read-only and lease-free; status never creates or migrates
a database. Invalid command-line syntax uses the standard parser: exit 2, usage
on stderr and empty stdout. Validation after parsing keeps the JSON envelope.

### Policy and limits

`ai-source-view-v1` applies these rules in order: preserve canonical exclusions;
exclude outside-scope subtrees; exclude sensitive names; exclude unsupported
portable paths; exclude oversized files; require UTF-8; reject binary controls;
exclude whole files containing a private-key marker. Included bytes and line
numbers are unchanged, and empty UTF-8 files are allowed.

The shared, versioned sensitive-name classifier applies to filenames and every
ancestor directory component, case-insensitively:

- `.env`, `.env.*`, `.envrc`, `.npmrc`, `.yarnrc`, `.pypirc`, `.netrc`, `.pgpass`,
  `.my.cnf`, `.git-credentials`, `.htpasswd`;
- `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `terraform.tfstate`,
  `terraform.tfstate.backup`, `application_default_credentials.json`;
- names ending in `.tfvars`, `.tfvars.json`, `.pem` or `.key`;
- `secret`, `secrets`, `credential`, `credentials`, or those names followed by a dot.

Unsupported paths include reserved names and every spelling in a case collision.
Binary controls are NUL, ASCII controls other than TAB/LF/CR, and DEL. These exact
markers exclude the whole file wherever they occur, including in examples:

```text
-----BEGIN PRIVATE KEY-----
-----BEGIN ENCRYPTED PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN DSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
```

This policy is not a secret-free guarantee. It performs no masking, entropy scan
or credential validation. Every canonical file is included or covered by exactly
one exclusion. Pruned directories use one subtree record. Content, size and path
rules use file records; `no_included_descendants` directory records never cover
already classified files.

| Bound | Limit and outcome |
| --- | --- |
| Included files / total bytes | 10,000 / 128 MiB; exceeding either blocks preparation |
| Included file bytes / path components | 8 MiB / 32; exceeding either excludes that file |
| Explicit scope selectors | 256; excess is invalid input |
| Compact source metadata / view manifest | 2 MiB / 128 MiB; excess blocks preparation |
| Copied canonical manifest | 64 MiB, with canonical hard limits of 200,000 files and 100,000 directories |

An empty view blocks preparation; nothing is truncated. Inspection enforces
fixed policy counts and declared byte bounds immediately after typed parsing,
before constructing canonical bytes or reading content. The view manifest must
exactly match its canonical encoding and reconstructed
partition. Bundle validation limits remain unchanged. Authorization blockers ask
for approval; binding/snapshot blockers ask to refresh the snapshot; empty/limit
blockers ask to adjust/narrow scope; unsupported asset kinds ask to select a repository.

### Identity, inspection and preservation

Views live at
`artifacts/CASE_ID/source-views/VIEW_ID/{view.json,canonical-manifest.json,tree/}`;
only `tree/` is model-readable source. Private staging, no-follow reads, verified
copies and staged inspection protect the derived bytes. Contents are sealed before
atomic no-replace publication; the root is sealed at its final path. Managed readers
refuse an interrupted publication with a writable root; prepare replaces it. An existing destination is fully verified. A damaged
copy or obstructing file or symlink is moved aside within the private `source-views`
directory under a reserved non-view name before the verified replacement is
published. Moving a sealed directory temporarily opens only its root for writing and restores
its permissions at the retained path. Moving a symlink preserves the link itself
and leaves its target untouched. Set-aside copies are
never returned or reused; case-artifact deletion removes them.

View identity binds canonical snapshot identity, capture `not_recorded`, policy
with normalized scope, file index, exclusion audit and `source_ref`. Authorization,
actors, hosts, timestamps, request IDs and host paths stay in receipts. The source
reference is exactly `snapshot:<canonical snapshot id>;git:not_recorded`. Git
capture remains deferred; missing Git provenance does not block preparation.

Offline inspection uses anchored no-follow handles for inventory and reads,
rechecks directory stamps without retaining per-directory handles, and verifies included bytes,
canonical membership, partition, policy, lineage and identity. Inventory stability
means one consistent instant existed during inspection. It works after
moving the directory. `policy_check: included_files_only` means excluded content
is unavailable; `--canonical-payload DIR` additionally replays content decisions
against frozen canonical bytes and reports `policy_check: replayed`. Neither mode
authenticates the producer or renews authorization. External bundles remain
`reported_only` with all trust, audit and admission flags false.

Scan status and report snapshot/replay remain compatible. Archives retain
preparation receipts as historical events and explicitly omit live product source-view bytes,
even with `--include-source-snapshots`. Restore does not renew authorization;
re-approve the source and use a new request ID to prepare it again. Case deletion
removes sealed and set-aside views. No database migration or archive-format change
is required. Sealed audits are admitted and reported as described below. Native
results are recorded in [development status](development-status.md); real-host
runs on macOS and Windows have not been done yet.

## Running an audit from a host

For an explicitly requested Cloudflare source audit in a development checkout,
use the [shared host protocol](../skills/ai-security-scanner/references/cloudflare-source-audit.md).
It maps all six pinned method phases to preparation, assignment/output and shared
document checkpoints, terminal validation, sealing and automatic case admission.
After a verified seal, the host inspects its full payload, admits it and delivers
the shared report; requested scanner checks produce one combined report, and a
request to keep the case produces a verified private archive. It requires an already
approved repository and native independent delegation; the human confirms exact
model-processing scope. Agents read only the ready source tree, and target
execution remains forbidden. The [synthetic acceptance kit](../tests/acceptance/cloudflare-host/README.md)
prepares a ready view for host acceptance runs; setup is not an audit. One supported
host has completed such a run, recorded in [development status](development-status.md).
The command formats below remain the reference. Released desktop operation is unchanged.

## Audit preparation and status

The development CLI can bind an audit run to an existing ready product source
view and record its preparation. **Preparation performs no audit and calls no
model.** It does not execute target code. The host's declared run directory is
untrusted and host-owned: the product checks its location and directory type,
records the path, and neither reads its contents nor writes to it.

```sh
ai-security-scanner-cli provider cloudflare prepare \
  --data-dir /private/scanner --request /private/prepare.json --json
ai-security-scanner-cli provider cloudflare status \
  --data-dir /private/scanner --case-id CASE --prepare-request-id REQUEST --json
ai-security-scanner-cli provider cloudflare status \
  --data-dir /private/scanner --case-id CASE --session-id SAVED_ID --json
```

The request is strict JSON, at most 1 MiB. Unknown fields and duplicate keys are
rejected. Example (replace the identifiers, digest and path):

```json
{
  "schema_version": "ai-security-scanner.cloudflare-audit-prepare-request/v1",
  "request_id": "audit-request",
  "case_id": "CASE",
  "asset_id": "ASSET",
  "source_view_request_id": "view-request",
  "expected_source_view_receipt_sha256": "SOURCE_VIEW_RECEIPT_SHA256",
  "profile": "quick",
  "invocation_budget": null,
  "host": {"host_id": "acknowledged-host", "delegation": "available"},
  "run_directory": "/private/host-audit"
}
```

Identifiers use 1–128 ASCII letters, digits, underscores or hyphens. The expected
digest is 64 lowercase hexadecimal characters. Profiles are `quick`, `standard`
and `deep`; the invocation budget is required and is either null or an unsigned
integer. Preparation requires at least 6 invocations for quick and 7 for standard
or deep when a budget is supplied. Delegation is `available`, `unavailable` or
`unknown`; only available permits preparation. The host declaration may include
an optional `model` string of 1–200 bytes without control characters.
`run_directory` must be absolute, normalized, an existing real directory with no
link in any path component, and neither contain nor be contained in the data directory or
source view. Credentials, prompts, document bodies and replacement source paths
have no request field.

The prepared receipt binds the request digest, case revision, source-view receipt and
view hashes, canonical snapshot lineage, scope, policy, source reference,
recorded grant and model-processing acknowledgement, pinned upstream revision
and embedded validator-resource digest, profile, budget, host and run directory.
The product supplies four independent identities and the preparation time;
`target_execution_allowed` is always false. For a prepared receipt, the command
envelope's top-level `session_id` is the product-minted identity on first commit,
replay and status. It is null for blocked receipts. The envelope's `run_id` and
`task_id` remain null because no case run/task rows exist yet.
The record begins at sequence 0 with a null predecessor digest.
Blocked receipts preserve the validated request in `result.request`, covered by
the receipt digest. Reads reject an embedded request that differs from the
receipt's request ID, case ID, asset ID or canonical request digest.

| Outcome | Exit | Durable result |
| --- | --- | --- |
| Prepared | 0 | Receipt committed, then private descriptor published |
| Blocked | 0 | Receipt with the validated request, typed blockers, stage and next action; no identities or audit directory |
| Invalid request | 2 | No preparation receipt |
| Writer busy, changed request or saved receipt no longer current | 3 | Existing receipt preserved |
| Persistence, file or output failure | 4 | Use status to recover any committed receipt |

Blocked reasons include a non-ready source receipt, host mismatch, unavailable
or unknown delegation, insufficient budget, ineffective or changed grant,
snapshot binding drift, or missing/damaged view bytes. Source problems direct
the host to `prepare-source-view`; audit preparation never repairs a view.
The budget blocker is `budget_cannot_fund_reconnaissance_and_reserves`.

A repeated request with the same canonical digest returns the saved identities.
Blocked receipts remain blocked; use a new request ID after fixing the cause.
Prepared replays check the host directory rules, current authorization and source bytes before returning
or recovering a missing descriptor. Failure returns `saved_receipt_not_current`
with its reason (exit 3). A host directory that no longer satisfies the rules
returns reason `run_directory_unavailable`; an unacceptable directory in a new
request remains an invalid request (exit 2), with nothing recorded.
Different request IDs may prepare independent runs on one view.

The event is authoritative. Its derived canonical descriptor is
`artifacts/<case-id>/cloudflare-sessions/<session-id>/session.json`; its SHA-256
is in the receipt. Recovery never overwrites different descriptor bytes.
Status uses an existing read-only database without a writer lease or migration,
returns the receipt and record head, and reports the descriptor as `verified`,
`missing` or `mismatch` for prepared receipts; `descriptor_state` is null for
blocked receipts. Authorization and source state are historical in status.
For a prepared run the next operation is `checkpoint`, with `issue`, `interrupt`,
`submit_documents` and `submit_output` available until sealing. After sealing it reports
the package state and admission or report retrieval as the next operation. Status verifies the complete record chain and returns its head, entry
count and entries, assignments with product identities, role fields, issuance time,
open/closed/interrupted/discarded state, closing time, interruption reason and
replacement links, counts by role and state,
and the budget view. For each shared document it reports the current revision,
digest, byte length, acceptance time and revision count, plus the cumulative
captured-bytes view (`limit`, `used`). Status reads neither objects nor the source
view. Each submitted output includes its path, digest, length and disposition;
verifiers also report their decision and returned fingerprint and record digest.
Final-verifier assignments include the bound findings revision and record digest.

For cases without admissions or failure rows, archives preserve preparation, assignment, output and document-revision events as history and explicitly
list the existing audit-record omission (private descriptors and captured
objects are not included). The omission also appears when only record entries exist. Restored events cannot resume a run: status reports a
missing descriptor for prepared receipts and preparation replay creates nothing. Confirmed case
artifact deletion removes the audit directory. Checkpoint after restore returns `run_sealed` for a sealed run, or
`saved_receipt_not_current` for an unsealed run, including replays; saved entries remain readable.
Sealing is available through `finalize`; case admission and shared reports are available below; exports and complete archive creation/verification are available; read-only archive restore is available. Externally
reported bundles retain their existing `reported_only` classification.

### Recovering lost host copies

Use status to discover the exact captured selectors, retrieve the missing copies,
then continue only with current authority:

1. Run `--json --data-dir DATA provider cloudflare status --case-id CASE --session-id SESSION`.
   `result.documents[NAME].current` gives the current `revision`, `sha256` and
   `byte_length`. `result.assignments` gives each `assignment_id`, `role`, and
   accepted `output.sha256`. Earlier `submit_documents` entries retain superseded
   revisions and their digests. The preparation receipt supplies the provider run
   and task identities; the session identifier is not the scan-run identifier.
2. Recover each required file to a new private destination:

   ```sh
   ai-security-scanner-cli --json --data-dir DATA provider cloudflare retrieve-captured \
     --case-id CASE --session-id SESSION --document REPORT.md --revision 2 \
     --destination NEW_PRIVATE_FILE --expected-sha256 SHA256 --expected-head-sha256 HEAD
   ```

   For an accepted assignment output, replace `--document NAME --revision N` with
   `--assignment-id ASSIGNMENT`. Both expected-digest flags are optional. A document
   revision must be positive. Superseded revisions and accepted outputs omitted
   from a sealed package remain retrievable; discarded outputs have metadata only.
3. Restore the host's working copies from the recovered exact bytes. Further
   checkpoints still require the current recorded head, effective authorization,
   prepared source and canonical run directory. Retrieval grants no authority and
   cannot reopen sealed work. Never reconstruct accepted evidence from chat.

`retrieve-captured` works for active, sealed and abandoned recorded audits. It
requires an explicit existing data directory and reads the preparation receipt
and validated event chain together in one read snapshot. It does not initialize
storage, acquire a writer lease, write a database row or event, run a validator,
read credentials or contact a target. Enumeration comes only from validated
history, never directory listings or orphan objects. Document/output limits,
the 512 MiB capture budget, and entry/history bounds apply before allocation.
Anchored reads verify exact object length and SHA-256. The snapshot boundary is
rechecked immediately before publication; a busy database or concurrent change
returns conflict without an automatic retry.

The destination must not exist and must be outside the data directory and product
storage. Publication pins and rechecks its parent namespace, creates a private
regular file without replacement, and refuses links and special files. Exact
captured text may contain sensitive material; bytes go only to this destination,
never to stdout. The single terminal envelope uses
`ai-security-scanner.cloudflare-audit-command/v1` and operation
`provider.cloudflare.retrieve-captured`. It includes `command_outcome`,
`exit_code`, `error_code`, `retryable`, `case_id`, `session_id`, `run_id`, `task_id`,
`observed_head_sha256`, `selector`, `destination`, `sha256` and `byte_length`.
Unknown facts remain null. A document selector is
`{"type":"document","name":"REPORT.md","revision":2}`; an output selector is
`{"type":"assignment","assignment_id":"ASSIGNMENT"}`.

| Exit | Meaning |
| --- | --- |
| 0 | Exact bytes published to the new private file |
| 2 | Invalid/unknown selector, unavailable discarded output, caller digest mismatch, unsafe or existing destination |
| 3 | Expected-head mismatch, changed snapshot or busy database; read status before deciding whether to retry |
| 4 | Missing/corrupt committed storage, I/O or terminal-envelope delivery failure |

A caller digest mismatch is a refusal; committed bytes that do not match their
recorded digest or length are a storage failure. This recovery command does not
enable restore or comparisons for admitted audits. Complete archive creation and verification are available separately.

### Assignment issuance and interruption

Before delegating, the host can obtain product-minted assignment identities:

```sh
ai-security-scanner-cli provider cloudflare checkpoint \
  --data-dir /private/scanner --request /private/checkpoint.json --json
```

```json
{
  "schema_version": "ai-security-scanner.cloudflare-audit-checkpoint-request/v1",
  "request_id": "issue-first-batch",
  "case_id": "CASE",
  "session_id": "SAVED_ID",
  "expected_head_sha256": "CURRENT_HEAD_SHA256",
  "action": {
    "type": "issue",
    "assignments": [
      {"role": "reconnaissance_baseline"},
      {"role": "hunter", "wave": 1},
      {"role": "candidate_verifier", "fingerprint": "example:input"}
    ]
  }
}
```

The envelope uses the same bounded identifiers and digest format as preparation.
Strict JSON rejects duplicate keys, unknown fields, null role fields and
caller-supplied identities, ordinals or times. One request creates one entry,
with assignments evaluated in request order. Each assignment has a new
`assignment_id`, a run-wide ordinal starting at 1, `issued_at`, and an `agent_id`
such as `a0001-recon` or `a0005-hunter`. Agent roots satisfy
`^[a-z0-9][a-z0-9_-]{0,63}$` and are unique within the run.

**Issuing an assignment records the product's side only. It neither starts an
agent nor shows that one ran.** The host decides what to delegate and when.
Checkpoint performs no model call, target execution, view hashing, or read/write
of the host's run directory. It leaves the preparation descriptor unchanged.

| Role | Required fields and rules | Agent suffix |
| --- | --- | --- |
| `reconnaissance_baseline` | No role fields | `recon` |
| `reconnaissance_focused` | No role fields; must leave reserves | `focus` |
| `hunter` | `wave` ≥ 1, no more than one above the highest issued hunter wave; cannot add to a wave after its critic was issued; quick permits only wave 1 | `hunter` |
| `post_wave_critic` | `wave` with at least one previously issued hunter, including earlier in this request | `critic` |
| `final_clean_critic` | No role fields; standard/deep only | `clean` |
| `candidate_verifier` | `fingerprint`: 1–4,096 ASCII bytes matching `^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$` | `verify` |
| `final_verifier` | `fingerprint` with the same syntax; standard/deep only, subject to the binding rules below | `final` |

Fields belonging to another role are rejected.
Every role may optionally include `replaces`, naming an interrupted or discarded assignment
of this run with exactly the same role and wave or fingerprint. An assignment
can be replaced only once. The old assignment and reason remain in history, with
links in both directions.

To abandon an open assignment, use a fresh request ID and the current head with:

```json
{"type":"interrupt","assignment_id":"ASSIGNMENT_ID","reason":"Host abandoned delegation"}
```

The reason is 1–512 bytes without control characters. This closes the assignment
as `interrupted`; it still consumes budget. Interrupting a closed or unknown
assignment is rejected. The product makes no claim about an agent's activity.

A null invocation budget disables arithmetic. Otherwise all issued assignments,
including interrupted and discarded ones, consume the limit. A request containing a hunter or
focused reconnaissance must also leave enough budget for any missing baseline
reconnaissance (four total), one candidate verifier, and the method's critics.
Quick reserves one post-wave critic. Standard/deep reserve a critic for the
highest active hunter wave (also owed before any hunter exists), plus a final-clean
critic. Assignments in this request count toward these obligations; interrupted
and discarded ones satisfy none. Final-verifier assignments consume budget without
changing these reserve terms. For example, after four baseline assignments, quick with a
budget of 6 refuses a hunter because it would leave only one slot for the critic
and verifier; a budget of 7 allows it. There are no priorities or estimates.

Entries are domain-separated SHA-256 records in the existing case event log.
Preparation is sequence 0; sequence 1 links to its receipt digest. Later entries
link to the preceding entry digest, record the request ID and canonical digest,
case revision, product content and time. Every reader verifies the whole chain;
broken digests, order, links or run identity fail closed. Appends use an immediate
transaction with a case revision check and the data-directory writer lease.
Status remains read-only and lease-free.

`expected_head_sha256` must equal the current head. A stale head returns exit 3
without recording anything: read status and retry with its head. Within a run,
the same `request_id` and canonical request digest returns the original entry
unchanged with `replayed: true`, regardless of the current head; a different digest
returns `request_conflict`. Changing the expected head changes the request digest.
A successful envelope includes the committed entry, current verified head
(`sequence`, `entry_sha256`), budget (`limit`, `issued`, `remaining`), top-level
`session_id`, recorded case revision and preparation receipt reference. Unbounded
budgets have null `limit` and `remaining`. A failed output write exits 4; status
retrieves any committed entry.

Before sealing, new checkpoint requests and replays check current case/asset binding and that the same
recorded grant is still selected and effective. The effectiveness check occurs
inside the transaction immediately before insertion. An outdated preparation
returns exit 3 `saved_receipt_not_current`, with a typed reason:
`source_authorization_missing`, `source_authorization_expired`, `grant_changed`,
`source_binding_mismatch`, `run_directory_unavailable` or `validator_resources_changed`.
The last reason means the build's validator-resource digest differs from the
preparation. It is not retryable: no action, including replay, records anything
under that outdated preparation. Before sealing, every checkpoint action, including
replay, opens the recorded run directory through the anchored reader; removed
directories, file replacements and linked path components are refused. Historical entries remain available through status.
Full snapshot/view byte verification runs at preparation and terminal validation.

Limits are 64 assignments per request, 2,000 per run, 4,096 entries per run,
1 MiB per request file and per entry, and 4 MiB of entries per run. Refusals add
no entry and do not change the case revision. Assignment and shared checkpoint rule codes follow; capture codes appear below.

| Exit | `error_code` | Meaning |
| --- | --- | --- |
| 2 | `invalid_request` | Invalid strict JSON, schema, identifiers, digest, action or field types; unsupported role/field; explicit data directory missing |
| 2 | `request_file_limit` | Request is not a readable bounded regular file, or exceeds 1 MiB |
| 2 | `unknown_preparation` | No prepared run has this identifier |
| 2 | `blocked_preparation` | Identifier names a blocked preparation request, which has no run identity |
| 2 | `assignment_batch_limit` | Request has zero or more than 64 assignments |
| 2 | `assignment_run_limit` | More than 2,000 assignments would be issued |
| 2 | `record_entry_limit` | More than 4,096 entries would be recorded |
| 2 | `entry_bytes_limit` | Entry exceeds 1 MiB |
| 2 | `record_bytes_limit` | Run entries would exceed 4 MiB |
| 2 | `role_fields_invalid` | Missing or foreign role fields, or zero wave |
| 2 | `wave_skipped` | Hunter skips past the next wave |
| 2 | `wave_closed` | Hunter wave already has an issued critic |
| 2 | `quick_wave_limit` | Quick hunter requested a wave other than 1 |
| 2 | `quick_final_clean_unavailable` | Quick does not permit a final-clean critic |
| 2 | `critic_requires_hunters` | No hunter has been issued for that wave |
| 2 | `fingerprint_invalid` | Fingerprint violates the pattern or byte limit |
| 2 | `invocation_budget_exhausted` | Issued plus requested assignments exceeds the budget |
| 2 | `budget_cannot_reserve_critics_and_validation` | Hunter/focused request leaves insufficient reserves |
| 2 | `interruption_reason_invalid` | Empty, overlong or control-containing reason |
| 2 | `unknown_assignment` | Output submission, interrupt or replacement names no assignment in this run |
| 2 | `assignment_closed` | Assignment is closed, interrupted or discarded |
| 2 | `replacement_not_interrupted` | Replacement names an assignment that is neither interrupted nor discarded |
| 2 | `replacement_mismatch` | Replacement role, wave or fingerprint differs |
| 2 | `assignment_already_replaced` | Interrupted or discarded assignment already has a replacement |
| 3 | `stale_head` | Expected head differs; read status and retry |
| 3 | `request_conflict` | Request ID was used with a different canonical digest |
| 3 | `saved_receipt_not_current` | Preparation authority no longer current, including on replay |

Shared command errors also include exit 2 `unsafe_temporary_directory` (not
retryable: point TMPDIR at a private directory; no permissions are changed and
nothing is recorded), exit 2 `case_not_found`, exit 3
`data_directory_busy` or `conflict` (case changed during evaluation), and exit 4
`storage_failed` or `internal_failed` for database, chain or internal failures.

### Shared document capture

The host can submit one to seven distinct root-level documents in a single
checkpoint. Use the existing request envelope and this action:

```json
{
  "type": "submit_documents",
  "documents": [
    {"name": "coverage-ledger.json"},
    {"name": "run-metadata.json", "sha256": "CAPTURED_SHA256", "byte_length": 123}
  ]
}
```

The optional digest is 64 lowercase hexadecimal characters. Replace the example
digest and length with the document's actual values, or omit either field. The
canonical request digest includes all declarations. Declared values must match
what the product captures; absent values are computed from the captured bytes.

| Accepted name | Maximum size | Acceptance check |
| --- | --- | --- |
| `run-metadata.json` | 1 MiB | Strict JSON object matching the prepared run ID, profile, budget, source reference and execution policy |
| `coverage-ledger.json` | 5 MiB | Pinned coverage-ledger validator |
| `findings.json` | 5 MiB | Pinned findings validator |
| `architecture.md` | 8 MiB | UTF-8 text |
| `REPORT.md` | 8 MiB | UTF-8 text |
| `FINDINGS-DETAIL.md` | 8 MiB | UTF-8 text |
| `NEEDS-VALIDATION.md` | 8 MiB | UTF-8 text |

All seven documents must be valid UTF-8. Metadata `run_id` is the product's
`provider_run_id`; `budget` must equal the prepared invocation budget, including
an explicit null when unbounded. `source_ref` must match the prepared source
reference, and `execution_policy` must be `sandboxed-source-and-local-only`.
Capture does not check `run_status`: `in_progress` is accepted. The terminal
status requirement is checked at terminal validation. No cross-document or semantic
checks occur during capture.

The product reads only the named files, without listing or searching the host
directory. It follows no links in any path component and accepts only regular
files with one link. Identity and size must remain stable across reading, with
a final stability check. The product never writes into the host directory.
Validators consume the captured bytes, without reopening host files.

A batch is accepted together or refused together. A document refusal keeps no
bytes or entry, so the host can correct the file and reuse the request ID.
Document refusals name the document; validator refusals include bounded
`validation` diagnostics. Empty or oversized batches have no individual document.

| Exit | `error_code` | Meaning |
| --- | --- | --- |
| 2 | `document_batch_limit` | Empty list or more than seven documents |
| 2 | `document_invalid` | Unknown or repeated name, malformed digest, invalid UTF-8 or metadata JSON, or a pinned validator refusal |
| 2 | `document_mismatch` | Declared digest or length differs from captured bytes |
| 2 | `document_unreadable` | Missing, unsafe, changing or oversized file; includes directories, FIFOs, symlinks and multiply linked files |
| 2 | `metadata_binding_mismatch` | Metadata differs from the preparation or lacks a bound field |
| 2 | `captured_bytes_limit` | Captured document revisions and submitted outputs would exceed 512 MiB for this run |

Missing Node returns the existing `not_available` error; a validator that cannot
run, times out or exceeds its output bound returns `runtime_failed` (exit 4).
These are environment failures, not document verdicts, and record nothing.

Accepted bytes are private content-addressed objects at
`artifacts/<case-id>/cloudflare-sessions/<session-id>/objects/<sha256>`.
Publication uses private staging, flushed writes and publication without
replacement. Existing objects are re-read through the anchored reader and must
hash to their names; corrupt bytes cause a storage failure and are preserved.
Objects are published before the entry commits. An unreferenced object from an
interrupted attempt conveys no acceptance and can be reused on retry.

One request commits one entry containing each document's name, revision, digest
and length, with the validator-resource digest and `valid: true` for ledger and
findings. Revisions start at one and increment separately per name. Identical
bytes submitted under a new request ID create another revision and reuse the
object. Captured-byte accounting counts every accepted revision, including
repeats, up to 512 MiB. The existing entry count and record-size limits also apply.
The response includes the entry, new head and `captured_bytes` (`limit`, `used`).

Before sealing, same-request checkpoint replay returns the saved entry after authority and directory checks,
even if named files have changed or disappeared; it reads no documents or objects
and runs no validators. New captures check authority and head before reading,
then recheck request identity, head, revisions, limits and effective authority in
the write transaction. File reads and validators run outside that transaction.
Cancellation before the transaction records nothing. Lost output exits 4; use
status to retrieve any committed entry.

A captured document is **accepted into the record**. Capture establishes custody
of its bytes; it is not a judgement about its content. Sealing is available through `finalize`; admission of sealed audits and terminal failure rows integrate with cases and shared reports.


### Assignment output capture

After delegation, submit exactly one returned output for an open assignment:

```json
{
  "type": "submit_output",
  "assignment_id": "ASSIGNMENT_ID",
  "output": {
    "path": "agents/a0009-verify/artifacts/decision.json",
    "sha256": "SHA256_OF_OUTPUT",
    "byte_length": 123
  }
}
```

Use the checkpoint envelope, a fresh request ID and the current head. The path
must be `agents/<assignment-agent-id>/artifacts/<name>`, with the product-minted
agent ID and one safe filename (ASCII letters, digits, dot, underscore or hyphen;
not `.` or `..`). Other agents, scratch paths, subdirectories, absolute paths and
traversal are refused. The optional digest and length declarations must match.
Reconnaissance outputs are bounded to 1 MiB; other outputs to 5 MiB. The shared
anchored reader rejects linked, special, changing and oversized files. This
source-only build captures no promoted evidence: an `artifacts` request field
is unknown and refused.

| Role | Returned output contract |
| --- | --- |
| `reconnaissance_baseline`, `reconnaissance_focused` | Non-empty UTF-8 text |
| `hunter`, `post_wave_critic`, `final_clean_critic` | One strict JSON object |
| `candidate_verifier` | Exactly `decision` and `record`; decision is `confirmed`, `needs_validation` or `rejected`, equals `record.verdict`, and `[record]` passes the pinned findings validator |
| `final_verifier` | Exactly `{"decision":"verified","fingerprint":F}` for its assigned fingerprint, or exactly `decision: "replace"`, a non-blank `reason`, and a `record` whose one-element array passes the pinned findings validator |

JSON outputs permit whitespace, but no surrounding prose, code fences, duplicate
keys, arrays or trailing data. These checks do not evaluate what a record claims.
A candidate may return a genuinely different fingerprint: both the assigned and
returned fingerprints remain recorded, and that output decides nothing for the
assigned fingerprint.

A read or declaration failure returns exit 2 (`output_unreadable`,
`output_mismatch` or `output_invalid`) without recording anything. A non-verifier
contract failure also returns `output_invalid` and leaves the assignment open.
The host can submit again. Missing Node or a validator runtime failure records
nothing and leaves the assignment open; it never becomes a contract rejection.

A successfully read verifier output that fails its contract is **permanently
discarded**. The pinned method forbids repairing malformed or prose-wrapped
verifier results. The command commits with exit 0 and `disposition: "discarded"`,
recording the path, digest, length and typed reason `output_invalid`, without
publishing output bytes. The assignment becomes `discarded`; a fresh assignment
may name it in `replaces` under the same role/wave/fingerprint rules as an
interrupted assignment, consuming another invocation.

Accepted bytes are published through the shared object store before commit. The
entry records disposition `accepted`, assignment ID, output path, digest and
length; verifier outputs also record `decision`, `returned_fingerprint` and
`record_sha256`. The record digest uses the same serialized JSON record recipe
as bundle validation. The assignment becomes `closed`. A final `replace` is a
recorded replacement proposal; it does not edit findings or establish final
verification. The response contains the entry, head, resulting `assignment`,
`disposition` and captured-byte view. Each committed output's length, including
discarded outputs, counts toward the existing run limit. A second submission to
a closed, interrupted or discarded assignment is refused with exit 2.

Replay returns the saved entry without reopening output files or running
validators. Authority, validator-resource currency, head, lease, cancellation,
record limits and lost-output recovery follow the shared checkpoint rules.
“Accepted” means taken into the record under these rules; it does not mean
verified, confirmed or audited by the product.

### Final-verifier issuance

```json
{"type":"issue","assignments":[{"role":"final_verifier","fingerprint":"FINGERPRINT"}]}
```

The profile must be standard or deep. The current accepted `findings.json`
revision must contain that fingerprint with verdict `confirmed` or
`needs_validation`, and an accepted candidate-verifier output must have returned
a record with that fingerprint. An open or discarded candidate assignment is
insufficient, as is an output that returned a different fingerprint.

The product reads the findings bytes from its digest-checked object store before
the transaction. It binds the new assignment to `findings_revision` and
`bound_record_sha256`, returning both with the product-minted `final` agent ID.
These are product fields, not request inputs. The transaction's head check keeps
the revision current at insert. A later findings revision requires a newly bound
final assignment for its changed record; previous bindings remain historical.
A `verified` output records the assignment's bound digest.

| Exit | `error_code` | Meaning |
| --- | --- | --- |
| 2 | `quick_final_verifier_unavailable` | Quick merges candidate and final verification |
| 2 | `final_findings_required` | No accepted findings revision exists |
| 2 | `final_record_ineligible` | Fingerprint is absent or its current verdict is rejected |
| 2 | `final_candidate_required` | No accepted candidate output returned this fingerprint |

Issuance consumes the normal assignment budget. It neither starts a verifier nor
changes the existing reserve rules. Use terminal validation followed by `finalize` to seal the run.


### Terminal validation from the audit record

After capturing all seven shared documents and closing or interrupting every
assignment, the host can ask whether the run can be sealed:

```sh
ai-security-scanner-cli --json --data-dir /private/scanner-data \
  provider cloudflare validate --request /private/validate-request.json
```

The request is strict JSON. Only the expected head is optional:

```json
{
  "schema_version": "ai-security-scanner.cloudflare-audit-validate-request/v1",
  "case_id": "CASE_ID",
  "session_id": "AUDIT_ID",
  "expected_head_sha256": "EXPECTED_RECORD_HEAD_SHA256"
}
```

The command takes the writer lease for a consistent record, verifies the record
chain, current authorization and validator resources, and fully checks the source
view and canonical snapshot bytes as preparation does. It never opens the host
working directory: the host may remove it after the last capture. Documents and
selected assignment outputs are reread from the product object store through the
anchored reader and checked against their recorded hashes and lengths.

The host wrote the native documents and assignment outputs. The product generates
`provider-manifest.json` itself, using its case, asset, provider run/task, audit and
attempt identities and the verified source view's own index. It selects the current
revision of each shared document and closed outputs named by live or archived
ledger unit/check owners or selected verifier receipts. For each current finding,
it selects the latest accepted candidate assignment issued for that fingerprint
whose returned record has that fingerprint. Under non-quick profiles, confirmed
and needs-validation records also select the latest accepted final verification
that verified the exact current record digest. Missing receipts stay absent so the
existing bundle checks report them. Counts come from current findings JSON.
Unselected superseded verifier outputs and unreferenced reconnaissance or critic
outputs are excluded. Issuance and closing times become the verifier timestamps.

The product assembles this bundle in a private temporary directory inside the audit
directory, runs the existing structural, pinned upstream and reference validation,
and removes staging before returning, including on failure. Identical record heads
produce identical manifest bytes and manifest/bundle digests. The existing bundle
limits apply; exceeding them returns an invalid bundle receipt rather than sealing.
No file is published, no record entry is appended and the case revision is unchanged.

Separate `record_errors` answer only questions supported by the product record:

- Every agent named by a live or archived ledger unit or check was issued as a
  hunter, candidate verifier or final verifier in this run.
- Every check owner and every owner of a blocked, covered or candidate unit or
  archived attempt has a closed assignment.
- A native `complete` run has four closed baseline reconnaissance assignments,
  a closed post-wave critic for every wave with a closed hunter, and a closed
  final-clean critic unless the profile is quick. These completion requirements
  do not apply to an `incomplete` run with its native reason.

The terminal envelope's `result` contains `sealable`, `record_head`,
`manifest_sha256`, `bundle_sha256`, `bundle_receipt`, `record_errors`,
`counts_by_role`, `counts_by_state`, `run_status` and `incomplete_reason`.
`sealable` is true exactly when the bundle receipt is valid and the record-error
list is empty. Exit 0 means validation completed, including a non-sealable answer.
The embedded bundle receipt is returned unchanged: it remains `reported_only`
with all trust flags false. No trust flags appear elsewhere in this result.
A sealable answer is not a sealed result. Supply both the returned record head and
bundle digest to `finalize`; case admission and shared reports are available below; exports and complete archive creation/verification are available; read-only archive restore is available.

| Exit | Typed refusal | Meaning |
| --- | --- | --- |
| 2 | `invalid_request`, `request_file_limit` | Strict request or explicit data-directory requirement failed. |
| 2 | `unknown_preparation`, `blocked_preparation` | No usable prepared run was selected. |
| 2 | `record_invalid` | The stored preparation or record chain could not be verified. |
| 2 | `documents_required` | At least one shared document has no accepted revision. |
| 2 | `assignments_open` | An assignment remains open; capture its output or interrupt it. |
| 3 | `stale_head` | The optional expected head differs from the current record head. |
| 3 | `saved_receipt_not_current` | Authorization, source/view integrity or validator resources no longer match preparation; the envelope includes the typed reason. |

Object integrity failures use the existing storage-failure envelope. Validator
availability/runtime failures remain command failures and leave no record change.

### Sealing the audit record

After `validate` returns `sealable: true`, seal exactly that head and bundle:

```sh
ai-security-scanner-cli --json --data-dir /private/scanner-data \
  provider cloudflare finalize --request /private/finalize-request.json
```

The strict JSON request requires all five identifiers and digests below, as well
as the schema; unknown fields, duplicate keys and null digests are rejected:

```json
{
  "schema_version": "ai-security-scanner.cloudflare-audit-finalize-request/v1",
  "request_id": "SEAL_REQUEST_ID",
  "case_id": "CASE_ID",
  "session_id": "AUDIT_ID",
  "expected_head_sha256": "HEAD_RETURNED_BY_VALIDATE",
  "expected_bundle_sha256": "BUNDLE_RETURNED_BY_VALIDATE"
}
```

`finalize` takes the data-directory writer lease and reruns the same terminal
assembly and validation path. It verifies the current authorization, pinned
validator resources, complete source view and canonical snapshot bytes. It never
opens the host working directory. A changed head returns exit 3 `stale_head`; a
changed bundle digest returns exit 3 `bundle_mismatch`; a validation result with
`sealable: false` returns exit 2 `not_sealable` with that same result body.
Missing documents or open assignments retain the validation refusals above.
These refusals publish nothing and append no entry. A lapsed grant leaves an
unsealed historical run. Writer contention returns exit 3 `data_directory_busy`.

The immutable package is stored beneath the selected data directory:

```text
artifacts/<case-id>/cloudflare-sessions/<session-id>/sealed/<bundle-sha256>/
  retained/
  workflow.json
  workflow-projection.json
```

`retained/` is the existing retained-bundle format, including the captured source
view, validation receipt and report projection; its provenance remains
`reported_only` and its trust flags remain false. `workflow.json` contains the
preparation receipt and every record entry through the validated head, unchanged
and in order, plus that head. It excludes the subsequent terminal entry.

`workflow-projection.json` uses schema
`ai-security-scanner.cloudflare-workflow-projection/v1`. It binds the case, asset,
provider run/task, audit and attempt, source identities, upstream revision,
validator resource digest, profile and invocation budget. It references the
retained projection by digest instead of repeating findings. It preserves native
run status, incomplete reason, verdict and severity counts, coverage counts and
unresolved candidates, and records assignment counts by role and state and total
issued assignments. Its digests bind the retention index, retained projection,
workflow record and validated record head.

Each statement has a specific meaning:

| Field | Meaning |
| --- | --- |
| `provenance: "workflow_recorded"` | The product recorded this workflow and committed its sealed package. |
| `canonical_snapshot_binding_verified: true` | During sealing, the product verified the full source-view and canonical-snapshot bytes against the prepared binding. |
| `source_authorization_verified: true` | The recorded grant was effective at preparation, at every recorded entry and at the sealing transaction. |
| `audit_performed` | True means at least one issued hunter assignment is closed; otherwise it is false. |
| `admission_ready: false` | A frozen seal-time statement that never changes; admission into a case will be recorded separately. |
| `target_execution_allowed: false` | Sealing grants no permission to execute target code. |

These statements describe what the product recorded. They do not establish that
an agent ran, that a model was independent or that a finding is true. Externally
supplied bundles, even copies of the sealed payload, cannot obtain workflow
provenance through document validation, bundle validation, retention or retrieval.

The product builds the package in private staging inside the audit directory,
flushes it, seals its contents, publishes without replacement, then seals its root
and flushes the parent. If interrupted after publication, finalize verifies the
orphan package and finishes sealing before committing. One transaction then rechecks the head, case revision, request identity
and effective authority and appends `sealed`. That entry is the commit point:
it records the bundle and manifest digests, hashes and lengths of
`retained/retention.json`, `workflow.json` and `workflow-projection.json`, and the
projection with its flags, native outcome and counts. A directory without the
terminal entry conveys no committed provenance.

After sealing, every checkpoint action and `validate` returns exit 2 `run_sealed`.
A different finalize request also returns `run_sealed`. Repeating the saved
request and digest returns the saved entry with `replayed: true` after verifying
the three recorded files; replay requires no current authority and publishes
nothing. Missing or changed recorded files cause a storage failure, preserving
existing bytes.

If interrupted after publication but before the transaction, retry the original
request or use a new request with the same expected head and bundle. The existing
directory is accepted only when all three recorded file hashes and lengths match
what would be published; different bytes cause a storage failure without
replacement. If output delivery fails, exit 4 can follow a successful commit:
use `status` to recover the result, then replay the same request if needed.

`status` remains lease-free and read-only. A sealed result includes the terminal
entry, digests, projection, package path and `sealed_state`: `verified`, `missing`
or `mismatch`, beside `sealed_verification_scope: "committed_files"`. This checks
only the three recorded files for live audits; restored-history verification is
described below. Use `inspect-sealed` for full payload and custody
verification against the product records. A fully verified, not-admitted audit
offers admit; an admitted audit offers `retrieve_report` when its terminal snapshot is retained or `admit_replay` while pending.

Cases without admissions or failure rows preserve the terminal entry as history and explicitly omit the
audit package with the existing omission line. Restored status therefore reports
`sealed_state: missing`; restore does not grant authority or reconstruct the
package. Confirmed case artifact deletion removes the read-only package with the
other case-owned files. Complete archive creation and verification are available for admitted cases; their read-only restore is available.

### Verifying a sealed audit

```sh
ai-security-scanner-cli --json --data-dir /private/scanner-data \
  provider cloudflare inspect-sealed --case-id CASE_ID --session-id AUDIT_ID
```

This read-only command uses the shared offline verifier and remains available
while another process holds the writer lease. It verifies the preparation receipt,
full record chain and unique terminal seal; the three committed files; every
indexed retained bundle and source-view file; saved validation and projection
relationships; the exact workflow history through the seal's predecessor; and
method, profile, budget, counts, terminal outcome and audit-performed bindings.
The retained view's file set and canonical identity are checked against the
source-view receipt bound at preparation, including its manifest identity,
asset, policy and scope. The receipt authenticates the manifest identity; the
original view manifest is not required. Exact anchored package inventory checks
reject extra entries, links and special files. Held filesystem identities and
stored custody identities are rechecked at the end.

The bounded result includes `verification.state: "verified"`,
`verification.scope: "full_payload"`, separate committed-file, full-payload,
workflow-history and view-lineage verification flags, identities and digests,
the exact package member list with sizes and hashes, aggregate member count and
bytes, method and budget, role/state counts, and complete or incomplete outcome
with its reason. `asset_binding` reports the original asset and source IDs and
whether each still exists in the case; absence is informational at this stage.
Provenance is `workflow_recorded`.

Node, the target working tree, the original product view directory, canonical
snapshot bytes, current grants, the host run directory and the writer lease are
not required. `validators_reexecuted: false` means saved pinned-validator receipts
are checked as saved bytes. The projection is not regenerated with current code.
Verification establishes custody and consistency, not agent execution, model
independence, finding truth or case admission. SQLite read-only access retains
its existing WAL coordination behavior: when absent, WAL/SHM sidecars may be
created; the command does not change case or package records.

| Exit | `error_code` | Meaning |
| --- | --- | --- |
| 2 | `run_not_sealed` | The stored audit has no terminal seal |
| 2 | `unknown_preparation` / `case_not_found` | The selected audit or case does not exist |
| 2 | `sealed_package_missing` | The package directory is absent |
| 2 | `sealed_package_mismatch` | A named `failed_check` failed; includes missing members or changed package or record identities |
| 2 | `unsafe_filesystem_entry` | A required package path is a link or unsafe filesystem entry; never reported as absence |
| 3 | `case_changed` | The case changed while verification ran; retry |

Exit 2 refusals are not retryable and expose no file content. Database opening and
output failures retain the common provider error classification. Inspection
neither repairs nor removes damaged data. Admission uses this verifier as described below. Shared reports include admitted audits as described below; complete package archives can be created and verified; read-only archive restore is available.


## Admitting a sealed audit

The development command admits one product-recorded sealed audit into its existing
open case. The development host skill does this automatically after `finalize`
commits the seal and `status` reports `next_operation: "admit"`. Obtain the three
verified digests from `inspect-sealed`, then save this strict request with a new
request ID as a private JSON file:

```json
{
  "schema_version": "ai-security-scanner.cloudflare-audit-admit-request/v1",
  "request_id": "admit-review-one",
  "case_id": "CASE_ID",
  "session_id": "SESSION_ID",
  "expected_sealed_entry_sha256": "SEALED_ENTRY_SHA256",
  "expected_bundle_sha256": "BUNDLE_SHA256",
  "expected_projection_sha256": "WORKFLOW_PROJECTION_SHA256"
}
```

Replace each digest placeholder with its 64-character lowercase SHA-256 value.
No additional fields, paths, findings, credentials or caller-selected run/task
identities are accepted.

```sh
ai-security-scanner-cli --data-dir /private/workspace --json provider cloudflare admit --request /private/admit.json
```

Admission requires the original asset and canonical source binding, an open case,
and no active scan. It verifies the entire sealed package and saved custody chain,
then copies verified non-source originals into the case/run/task artifact directory.
Source-view trees remain in the sealed package. Only confirmed records become
findings and frozen observations; needs-validation, rejected, unresolved records
and coverage remain in the stored provider projection. Complete and incomplete
native outcomes are preserved; incomplete work becomes a `PartiallyCompleted`
task with its reason.

One immediate transaction compares the case revision, checks admission identity,
saves the whole case through the ordinary save invariants, and appends exactly one
`cloudflare_audit.admitted` event containing the immutable receipt. It adds the
`cloudflare_audit_admission/v1` format requirement. The Cloudflare chain stays
sealed; its frozen `admission_ready: false` never changes. No report snapshot is
created. Admission and replay never invoke Node or validators:
`validators_reexecuted: false` refers to verification of saved validator receipts.

The terminal envelope uses operation `provider.cloudflare.admit`, outcome
`committed` or `replayed`, case/run/task identities, the original commit revision
and receipt. Its result includes admission ID/digest, `admission_state: "admitted"`,
`provenance: "workflow_recorded"`, replay status, native outcome and counts.
Later human triage does not change the receipt.

After the admission transaction commits, the command retains an English, Standard
terminal HTML/JSON snapshot. `result.report_snapshot_state` is `"retained"`, with
`result.report_snapshot` in the same run record shape as a foreground scan. A
snapshot publication failure does not roll back admission: exit remains 0 and the
original committed receipt is returned, with `report_snapshot_state: "pending"`
and `report_snapshot_retry_command` containing the same admit request. Replay
retains the missing snapshot without replacing that receipt. A retained snapshot
is reused and verified; damaged recorded originals are refused rather than replaced.
`scan recover` on an admitted run can retain the missing snapshot without starting
or contacting anything; a saving failure directs the caller to admit replay.

| Exit | `error_code` | Meaning / retry |
| --- | --- | --- |
| 0 | null | Committed or verified same-request replay |
| 2 | `invalid_request` | Invalid schema, fields, identifiers or digests; explicit data directory required |
| 2 | `request_file_limit` | Request is not a readable bounded regular file |
| 2 | `case_not_found` / `unknown_preparation` | Case or audit identity is absent |
| 2 | `case_archived` | Open case required |
| 3 | `active_scan` | A scan is active; retryable after it finishes |
| 2 | `not_available` | Unknown case format requires a newer version |
| 2 | `session_already_admitted` | Another request already admitted this audit |
| 2 | `expected_digest_mismatch` | One of the three expected digests differs |
| 2 | `run_not_sealed` | No committed seal |
| 2 | `sealed_package_missing` | Sealed package directory is absent |
| 2 | `sealed_package_mismatch` | Package bytes, inventory or custody records fail verification |
| 2 | `unsafe_filesystem_entry` | Verification encountered an unsafe file or linked path |
| 2 | `binding_not_provable` | Asset/source is missing or the canonical binding changed |
| 2 | `admission_too_large` | Admission or resulting case exceeds its bounded size |
| 2 | `admission_mismatch` | Replay admission digest, receipt or copied originals fail verification |
| 2 | `not_authorized` / `unsafe_temporary_directory` | Common private-filesystem boundary refusal |
| 3 | `request_conflict` / `identity_conflict` | Conflicting request or generated identity; not retryable unchanged |
| 3 | `data_directory_busy` / `conflict` | Writer contention; retryable |
| 3 | `case_changed` | Verification or revision compare-and-set lost its case revision; retryable |
| 4 | `artifact_conflict` | A planned original has different bytes or unsafe identity; non-retryable, never overwritten |
| 4 | `storage_failed` / `runtime_failed` / `internal_failed` | Operational failure; retryable |
| 4 | `engine_registry_failed` | Common provider infrastructure classification; non-retryable |

All exit 2 refusals are non-retryable. Output delivery failure can produce exit 4
without a delivered envelope even after commit: rerun the same request.
Same-ID, same-digest replay recomputes the admission digest and verifies every
copied original, then returns the original receipt without a new admission event or triage change. Retaining a previously missing snapshot appends its own snapshot event and case revision. A different digest for the same request ID returns
exit 3 before new work.

If interrupted after originals are published but before commit, retry the same
request. Stable run/task paths allow exact-length, exact-hash orphan reuse;
different bytes cause `artifact_conflict` and no admission is committed.
Transaction failure leaves no partial case or receipt. The command writes each
original to a private temporary file, syncs it, then publishes without replacement,
cleaning stale `.admission-*.tmp` regular files while preserving planned members.
Confirmed case-artifact deletion removes these originals with the rest of the case.

Both `status` and `inspect-sealed` expose `admission_state` and, after admission,
an `admission` object containing admission ID/digest, request ID, run/task IDs and
admitted-at. A sealed audit that is not yet admitted and whose three committed
files verify has `next_operation: "admit"`; an admitted audit reports
`report_snapshot_state` and `report_snapshot`, with `next_operation: "retrieve_report"`
when retained or `"admit_replay"` while pending. Status checks the three committed seal files and any recorded report snapshot; `admit` and
`inspect-sealed` verify the whole audit package, so `admit` can still refuse. No mutable
ready flag is added.

An admitted audit cannot authorize Check fixes; start a separately reviewed scan.
Run comparisons involving an admitted audit are unavailable in this build.
Single-run HTML/canonical JSON, combined HTML/JSON, and report snapshot capture,
retention and replay include admitted source audits. Confirmed findings use the selected redaction profile
in the priority list; validation leads, uncovered units
and continuation paths remain separate. Collapsed technical detail retains native
records, ordered ledger attempts, method/budget, role/state counts, lineage and
custody/original digests. Provider text is inert text, never markup or links. Only planned, in-progress, blocked, deferred and unresolved candidate units carry continuation paths. Out-of-scope units are disclosed without continuation; not-applicable units stay in counts and technical detail. Unresolved candidate fingerprints stay in technical detail, with their count in the first layer. Empty validation and gap sections are omitted. The first layer names the method “Cloudflare source audit” (“Cloudflare 原始碼稽核” in Traditional Chinese); each audit has one aggregated remaining-units gap without an extra Not tested count, and one excluded gap when units are outside scope. Remaining units share one next step: "Continue the source audit from the listed paths." Standard keeps this product sentence; paths remain under **What was not tested** and in technical detail, with location markers in Standard.
Standard redaction applies the shared masking policy to provider prose, trace and evidence descriptions, remediation, ledger text and incomplete reasons, with separate withheld-text and withheld-code counts. Provider files, paths, source scope and source references use the location marker; titles replace known private literals. Standard replaces provider coverage identifiers with `unit-` and provider fingerprints with `fp-`, followed by the first twelve lowercase hexadecimal characters of the original value’s SHA-256; product-generated identities, timestamps, enums, scores and digests remain unchanged. Confirmed findings use the localized SourceCode family summary, impact and action in Standard. The `none` profile preserves native text and code verbatim.

Framework reports include an optional `source_audits` extension copied from the shared report after profile redaction. It preserves method, outcome, separate counts, validation leads, aggregated status counts, per-unit gaps and technical provenance. Audit tasks do not enter scanner counts or engine-state lists; confirmed observations carry `source_audit_not_mapped` and produce no framework control conclusion.

OCSF Detection Finding events and OSCAL `EXAMINE` observations contain only confirmed admitted findings. Provider identity appears under OCSF `unmapped.ai_security_scanner.source_audit` and OSCAL namespaced `source-audit-*` observation/evidence properties: provider and admission IDs, native fingerprint, record digest/index, `provider_verdict: "confirmed"`, method “Cloudflare source audit” and upstream commit. The verdict is resolved from the admission, not human triage or compliance. Existing human workflow status is preserved. Needs-validation, rejected and candidate records remain outside finding events/observations. The mandatory OCSF/OSCAL companion contains the shared report, including zero-confirmed incomplete audits and their leads, gaps, method and outcome, and binds the main file by SHA-256. Publication failure rolls back files created by that export.

All three formats support Standard and `none`. Standard uses the redacted case/report: provider text/code withheld, locations marked, coverage IDs and fingerprints pseudonymized, IDs/digests/enums preserved. `unresolved` and `unresolved_candidates` use identical `fp-` pseudonyms; neither identifiers nor derived gap labels inflate withheld-text counts. `none` retains native values. Every selected audit task must resolve to one stored admission for the same case, run, task and provider, with confirmed evidence bound to registered artifacts; otherwise no files are written. Schema constants and notices remain unchanged, and scanner-only documents retain their bytes.

Signed case bundles now include a case-wide `source-audit-admissions.json` with retained projections, bindings and provider task provenance; their framework audit extension equals the chosen-profile shared report. Standard withholds text/code with counts, marks locations, pseudonymizes coverage IDs/fingerprints and preserves identities/digests. `none` retains native values. Admission/native digests commit to original material; the manifest hashes the exported document. Catalog engine versions and built-in task records exclude audit tasks.

Single-run and combined HTML attachments now support admitted audits, preserving nested original bytes with provider/admission/method attribution and file/ZIP digests. Only `none` plus the raw-artifact option includes provider originals in bundles or attachments. Standard excludes them without reading bytes and accounts for sensitive omissions; no derived originals are produced. Combined attachments keep run/task namespaces. Combined attachment overflow uses the same explicitly acknowledged private complete-archive fallback for admitted cases and scanner-only cases: retrieve the originals from that private archive. See [profiles, originals and limits](results-and-exports.md#development-preservation-and-restore).
Complete archives of admitted audits support creation, verification, restore preview and read-only restore. Unknown format requirements still
block these operations except listing, viewing, deletion and intact original
snapshot retrieval. See [report snapshots](report-snapshots.md#admitted-source-audits).
Builds without admission support do not list a case that contains an admitted
audit and refuse to open, change, compare, archive or plan deletion of it; they
leave its saved data unchanged.


## Complete archives of admitted audits

Admitted audits now support `archive create`, `archive verify`, `archive restore-preview` and `archive restore` through the shared
[private archive path](case-archives.md#archives-containing-admitted-source-audits).
Alongside reports, exports, signed case bundles and attachments, complete archives
preserve every recorded preparation, descriptor, sealed package, captured document
revision and accepted output, including outputs not selected by a seal. Discarded
outputs remain unavailable inventory entries; orphan files are excluded. Unsealed
history stays inert and does not imply completion.

Source selection includes sealed source bodies; otherwise typed omissions retain
their hashes and lengths. Manifests and lineage stay present, and provider originals
may still contain source excerpts. The shared offline verifier checks admission,
evidence and history bindings without provider or validator execution. Provider-aware
archives declare two required capabilities; legacy archives remain unchanged.
Restore verifies staged packages before importing and publishing a new workspace.
Restored audits are read-only history: `prepare` replay, source-view preparation replay,
all checkpoint actions and replays, `validate`, `finalize`, and `admit` (including replay) refuse
with `restored_session_inert` (exit 2, not retryable): “This audit was restored from an
archive and is read-only history. Start a new audit with current authorization.”
Library guards check preparation event order against the latest `case.restored`
event before accessing old run, audit or source-view directories. A fresh grant
does not reactivate history; a new request ID can start new work under current authorization.

`status` and `inspect-sealed` mark restored history with `restored: true` and offer no
write operation. Unsealed history disables checkpoint and sealing; sealed history
has no next operation; admitted history offers `retrieve_report` only when its
snapshot is retained. Reports, exports, bundles, original downloads and captured
retrieval continue to work without the original host or data directory.

For restored audits explicitly listed as source-omitted, contextual verification uses
`included_payload` and says: “Source snapshots were not included in the archive this
case was restored from; source bytes cannot be rechecked here.” Other restored audits
use strict `full_payload` scope; a missing source body is a failure. Restored `status`
reports `full_payload` or `included_payload` only after that verification passes;
otherwise its scope remains `committed_files`. A failed restored-package verification
keeps status successful (exit 0), with `sealed_state: "mismatch"`, the check name in
`sealed_failed_check`, and no next operation. `inspect-sealed` still refuses with
exit 2. Live status scope is unchanged. Standalone
`inspect-retained` and `retrieve-retained` remain strict and publish nothing on such
an omission. Rearchiving keeps inherited omissions even with sources selected.
Admitted-run comparisons remain refused.

## Ending an audit that will not be sealed

When an audit cannot be sealed and will not continue, the host explicitly records
its end. If the documents required for sealing exist, validate and seal instead;
an incomplete sealed audit retains its recorded gaps. Never terminate because of
inactivity alone. A crash, elapsed time, rejected validation or exhausted budget
does not automatically end an audit.

Read `provider cloudflare status`, preserve the current record head, then submit:

```sh
ai-security-scanner-cli --json --data-dir DATA provider cloudflare terminate --request REQUEST.json
```

```json
{
  "schema_version": "ai-security-scanner.cloudflare-audit-terminate-request/v1",
  "request_id": "end-audit-one",
  "case_id": "CASE_ID",
  "session_id": "SESSION_ID",
  "expected_head_sha256": "CURRENT_RECORD_HEAD_SHA256",
  "reason": "host_cancelled"
}
```

The head is required and must be the exact 64-character lowercase SHA-256 from
status. The strict request accepts only these fields. Choose the closest reason:
`host_cancelled`, `host_interrupted`, `budget_exhausted`,
`authorization_unavailable`, `required_artifacts_unavailable`, or `workflow_failed`.
Caller prose, timestamps, paths, assets and outcome claims are not accepted.

The command requires an existing workspace, its writer lease, a verified
preparation receipt and event chain, and a transactional case-revision check.
Current source authorization, a validator and the host run directory are not
required. Termination does not open, list, create, repair or remove host or audit
storage directories. It appends one product-timed `terminated` entry to the
existing custody chain, with the reason, predecessor, request digest, sequence
and case revision. Assignments, document revisions and output captures remain
unchanged; no case check row or report outcome is added in this slice.

The response is one `ai-security-scanner.cloudflare-audit-command/v1` terminal
envelope with operation `provider.cloudflare.terminate`, using the ordinary
provider delivery path.

| Exit | Outcome |
| --- | --- |
| 0 | Termination committed, or identical request ID and digest replayed with the saved entry and `result.replayed: true`. |
| 2 | Invalid request, unknown or blocked preparation, `run_sealed`, `run_terminated`, or `restored_session_inert`; not retryable. |
| 3 | Same request ID with different inputs (`request_conflict`, not retryable), stale head (`stale_head`, retryable), busy writer or revision conflict (retryable). |
| 4 | Corrupt committed history, persistence, I/O or output-delivery failure. |

After a lost response, read status and replay the identical request, retaining its
original expected head. A changed request needs a new request ID. Restored history
is checked before replay and always refuses termination. A different termination
after the end is refused with `run_terminated`.

Termination is final. Every checkpoint action, validation, finalize and admission
refuses with `run_terminated` before side effects, including earlier-request
replays. Start a new preparation with current authorization for a new audit.
Status adds `terminated: {reason, occurred_at, entry_sha256}`, disables checkpoint,
sealing, document capture and output capture. Its next operation is null after
the outcome report snapshot is retained, or `terminate_replay` while pending.
`status` and `retrieve-captured` remain available for current and superseded
revisions and accepted outputs.

Even a record at the ordinary 4,096-entry or 4 MiB limit can end: exactly one
terminal entry, no larger than 4 KiB, may exceed those limits. Every later entry
is rejected. Recording, captured-history recovery and archive verification use
the same rule. See [terminated custody in archives](case-archives.md#terminated-audit-custody).


### Blocked and terminated check rows

Development Rust records one ordinary check run when preparation is blocked or an
unsealed audit is explicitly terminated. The check binds only the receipt's asset.
Blocked checks are `not_executed`, have no start time, and use deterministic product
run/task IDs derived from the case and receipt digest. Terminated checks are
`failed` and reuse the reserved provider run/task IDs. Creation and completion
times come from custody; no model execution is inferred. Removed assets retain
their recorded identity. No finding, observation, original, admission or seal is
created. Captured audit files remain in provider history.

The receipt or terminating entry, case row, `cloudflare_audit_terminal/v1`
requirement and `cloudflare_audit.outcome_recorded` event commit in one transaction.
The event carries preparation request ID, terminal digest, run/task IDs and outcome
SHA-256. A failed write rolls everything back. Errors before a receipt exists
record nothing. Older custody is not backfilled, and restore never creates rows.

Prepare/terminate command results and status add `outcome_run` with `run_id`,
`task_id` and `report_snapshot_state` (`retained` or `pending`). Snapshot retention
happens after commit; pending retention does not change the committed command's
exit code. Pending results also carry `report_snapshot_error_code` and
`report_snapshot_retryable`. Replay the identical request to retry only pending
snapshot retention; a retained replay adds no event or revision. Status advertises
`prepare_replay` or `terminate_replay` while pending, otherwise null. Restored
history remains `restored_session_inert`, including identical replays.

Shared reports and exports include these checks as incomplete coverage. Their
technical detail retains typed reasons, custody digests/times, run/task identity,
and recorded assignment/capture counts for termination. The first layer uses fixed
product wording, never host or provider prose. Desktop parity follows in B2; its
current reader uses the existing `invalid_task` fallback for this new kind.
