# Development status

[繁體中文](development-status.zh-TW.md) · [Documentation](README.md)

_Updated 2026-11-13._

**The latest release is desktop v0.6.2 for Linux, macOS and Windows.** It remains the default for beginners. Its public operator skill helps install the app, check readiness, guide scans in the app window and save reports.

## New in development

These features are implemented in source on this branch and are not in any release:

- [Skill-first execution](skill-bootstrap.md): pinned source bootstrap and preparation of selected scanner engines.
- [Foreground scans and recovery](foreground-scans.md): run approved checks, read saved status and recover captured results.
- [Cloudflare source audits](cloudflare-provider.md): host-led preparation, recorded assignments and outputs, checkpoints, validation, sealing, case admission and shared reporting, with explicit termination when an audit will not continue.
- [Unfinished audit checks](results-and-exports.md#source-audits-that-did-not-finish): blocked preparation and terminated audits appear as not-started or failed check rows in the case, desktop Results and shared report.
- [Saved reports and offline replay](report-snapshots.md): preserve reports, retrieve their original files and replay them with an exactly compatible renderer.
- [Complete private case archives](case-archives.md): create, verify and restore cases, evidence, saved reports and recorded audit history into a new workspace; restored audits remain read-only.

**Not finished**

- Real-host acceptance has covered one Linux host on a synthetic repository, from an empty pinned-bootstrap cache through restore; a second host, several assets and macOS/Windows hosts remain.
- The default skill has not switched from the released desktop.
- Automatic managed-bundle acquisition and verification across the declared platforms remain unfinished. On macOS and Windows, CI covers the bootstrap, Cloudflare audits, saved reports and archives; foreground scans and engine preparation are not yet fully covered there.

The dated sections below preserve observations at each milestone. [The product specification](product-spec.md) defines product behavior; [the migration plan](plans/skill-first-cloudflare-migration.md) and [report and archive contract](specs/report-fidelity-and-archive.md) describe the accepted work. See [publication status](release-model.md) for availability.

CI document and contract tests: 124 tests cover the current source boundaries.

## November 13 report and archive gates — 27

A new, empty bootstrap cache at the same pinned revision rebuilt the CLI with `--offline` in under four minutes while the earlier cache was unreadable, and the new binary's digest equals the earlier build's. With that core the restore verifier again passed all 78 checks on the host archive from the 26 journey: both source selections restored into fresh workspaces, and the saved reports retrieved and replayed byte for byte. Connection tracing recorded no network connection attempts during the build or the restore. The Rust dependencies were already on the machine; nothing was downloaded.

An automated test now covers an audit that could not start because its budget was too small and an audit that was stopped. Before archiving, the saved report names the ending and its reason, with the task's technical record collapsed under Technical details. Exports after reopening the case and after restoring the archive show the same reason and disclosure, and the restored snapshot bytes equal the originals.

Source audits in the host flow may not run target code, with or without a sandbox; the preparation receipt and the sealed record both say so. Facts that would need execution stay as To validate records without severity, and an audit with an unvalidated candidate stays incomplete. Reports now name those records as a next step. The first layer of a single-run or combined report says how many source-audit items under To validate need validation, first when nothing else was found and after the main action otherwise. An asset whose completed checks found no problems but that has such records shows the next action “validate the listed source-audit items first”. Counts, severities, status labels and JSON output are unchanged.

Evidence: `b27b-01` passed the failure-row group (11 tests); `b27e-01` passed the report tests (11) and `b27e-02` the whole Cloudflare audit target (157 tests). On the final tree, `b27-lead-01` passed the library, CLI and Cloudflare targets (2,020 tests), `b27-lead-02` the snapshot, archive, foreground, runtime and baseline targets (56 passed, 2 ignored), and `b27-lead-03` and `b27-lead-04` the all-engine report and case lifecycle targets; `b27-lead-05` passed repository checks (2 frozen cases, 26 document snapshots, 36 payload hashes, 20 screenshots) and `b27-lead-06` all 114 CI tests.

## November 13 bootstrap-first real-host journey — 26

A Linux host received only the operator skill, a clean product checkout at a pinned, committed revision and an empty private cache location. It ran the pinned bootstrap itself: `doctor`, then `prepare` with the default release profile and `--offline`, which built the CLI from existing Rust dependencies in about three and a half minutes, then Gitleaks scan preparation through the existing Docker compatibility runtime. Every scanner command after that went through `bootstrap.mjs run`.

The build receipt records the pinned revision with a clean source and dirty builds not allowed, and its CLI digest matches the cached binary; the checkout stayed clean. The host then completed the 25b journey in the same order: a Gitleaks scan with no secrets found, a quick Cloudflare source audit with seven of seven delegations, sealing, automatic admission, one combined Traditional Chinese report and a complete archive with source snapshots, which it verified. All seven delegated outputs matched their captured artifacts byte for byte, each delegation followed the checkpoint that issued it, and no delegated reader went outside the approved source view. The approval runner refused one request that left out the data directory; the host corrected it and continued. The run took about 19 minutes. A separate restore check with the bootstrap-built CLI passed all 78 checks.

Evidence: native checks `b26-01` passed (2 frozen cases, 26 document snapshots, 36 payload hashes, 20 screenshots); CI document tests `b26-02` passed all 114 tests.

## November 13 real-host journey — 25b

One request to a Linux host (synthetic repository, quick profile, budget seven) ran the development skill journey end to end: the Gitleaks secret scan first, then the Cloudflare source audit through sealing, automatic admission with the three verified digests, one combined Traditional Chinese report of both runs, and a complete private archive with source snapshots that the host verified. All 33 approved commands succeeded with no refusals, and the scan never overlapped audit custody or admission. All seven assignments were issued before delegation, and each captured output equals the sub-agent's final message; no agent read data outside the source view or executed the target. Gitleaks found no secrets; the audit has no confirmed findings and one To validate lead without severity (concurrent redemption can issue two vouchers for one credit).

The lead's restore verifier then passed 78 checks over 68 public CLI commands. The host archive and a second, source-excluded archive verify and restore into fresh workspaces with `full_payload` and `included_payload` scope. All three saved reports (scan, admitted audit and combined) retrieve and replay byte-identically from both restores, and the combined one equals the HTML the host saved. The captured output matches, a fresh admission of a restored audit is refused because restored audits are read-only, and public reads of the original and restored cases are unchanged. The first verifier attempt stopped because it compared snapshot references by key order; it now compares their identifying fields, with a unit test. The published v0.6.2 CLI lists no cases in a copy of the restored workspace and refuses to open, export, compare, archive or plan deletion of the case; every data file is unchanged.

Native Linux evidence for the verifier fix: `b25b-lead-07` passed repository checks (2 frozen cases, 26 document snapshots, 36 payload hashes, 20 screenshots); `b25b-lead-08` ran 75 skill tests (74 passed, 1 platform skip); `b25b-lead-09` passed all 114 CI tests. All returned zero with no temporary entries left.

## November 13 host journey — Brief 25a

The development host skill now automatically admits a verified seal, explains and saves the shared report, combines requested scanner checks without interleaving them with the audit, and creates/verifies a complete private archive on request. The released desktop remains the default. The lead-only restore verifier checks both source selections, saved HTML/JSON retrieval and replay, captured outputs and inert restored admissions through public CLI commands. Because the CLI exposes no current case revision outside foreground scan responses, the verifier treats a case as unchanged when every public read of it is identical. Its first real-host use is recorded in the 25b entry above.

Native Linux evidence on the reviewed tree: `b25a-lead-01` synchronized and checked 6 skill files; `b25a-lead-02` passed repository checks (2 frozen cases, 26 document snapshots, 36 payload hashes, 20 screenshots); `b25a-lead-03` ran 74 skill tests (73 passed, 1 platform skip); `b25a-lead-04` passed all 114 CI tests; `b25a-lead-05` passed two setup scenarios and the non-empty-output refusal. All returned zero; the runner removed the two setup entries the last request left. These checks do not execute the new verifier's full restore journey.

## November 12 native macOS and Windows CI

The source bootstrap, Cloudflare audit, saved-report and case-archive tests now pass natively in CI on macOS 15 and Windows Server 2025 as well as Linux. These development features had run only on Linux before. Foreground scans are still tested on Linux only, and selected-engine preparation on Linux and macOS.

- **Read-only publication.** Source views and audit packages make their contents read-only, move to their final name, then make the root read-only, because macOS refuses to rename a directory its owner cannot write. Readers refuse a publication that stopped before its root was protected, and the next attempt replaces or completes it. The product applies the same rule on Linux, so Linux tests catch a wrong order.
- **Windows paths.** Product-internal paths keep the ordinary `C:\…` form, so internal destinations pass the same checks as user-supplied ones and the Node.js validator starts. Direct Windows calls use the extended-length form only for paths past the legacy length limit.
- **Windows file rules.** Restore closes the staged database, then flushes it through a writable handle. Archives with connector sources resolve the connector root before checking containment.
- **ZAP report directory.** It is validated as the container path it is, so the ZAP passive website check can be planned on a Windows host.
- **Bootstrap and bundling.** The bootstrap staging directory has a short name, which keeps the Windows build inside the linker's path limit. Every entry in the binary source directory is a declared binary, so desktop bundling no longer takes a module directory for a program.

Native Linux verification passed **2,727 Rust tests**, **114 CI contract tests** and **67 skill tests**; three Rust tests remain ignored and one platform-specific skill test remains skipped. Formatting, Clippy and the release tooling self-test passed.

## November 12 desktop results for unfinished audits — B2

Desktop Results now show blocked source audits as “The Cloudflare source audit did not start.” and terminated audits as “The Cloudflare source audit ended before completion.” Each includes the shared report's reason, next action and asset gap in English and Traditional Chinese. Collapsed technical details begin with the outcome under “Source audit”, followed by codes, time, digests and termination counts. Failure-only results omit generic scanner retry guidance; admitted audits and scanner siblings retain their existing presentation.

Native task status is preserved, recovery is unavailable, and these tasks grant neither attempted scanner work nor completed coverage. Progress controls, verification baselines and Check fixes exclude them; export previews count them separately from scanner jobs. Both failure labels remain selectable in combined reports through the existing native export command.

Synthetic tests cover valid and malformed wire outcomes, recovery and control guards, attempted/completed coverage, verification baselines, bilingual rendered Results and technical detail order, unchanged admitted/scanner siblings, combined selection and command forwarding, demo preview counts, and Rust/TypeScript field, code and sentence parity. This continuation adds **71 frontend tests and 10 component tests**. Production changes are limited to `AuditFailureDetails.tsx` and `FindingsPage.tsx`: **6 added lines and 1 removed line**, retaining the earlier B2 implementation.

The final native Linux requests below ran in order after the last edit, all returned zero and left zero temporary entries. Frontend tests retain 33 environment-dependent skips. The desktop application itself was not launched; native macOS/Windows execution remains unverified.

| Suite | Native request | Total tests | Passed | Failed | Ignored or skipped | Temporary entries left |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Typecheck | b2c-final-01 | — | Check passed | 0 | — | 0 |
| Node frontend | b2c-final-02 | 1066 | 1033 | 0 | 33 | 0 |
| Components | b2c-final-03 | 622 | 622 | 0 | 0 | 0 |
| Node CI | b2c-final-04 | 113 | 113 | 0 | 0 | 0 |
| Repository checks | b2c-final-05 | — | Check passed | 0 | — | 0 |
| Formatting | b2c-final-06 | — | Check passed | 0 | — | 0 |
| Clippy | b2c-final-07 | — | Check passed | 0 | — | 0 |
| Rust A | b2c-final-08 | 2009 | 2009 | 0 | 0 | 0 |

## November 12 terminal audit check rows — Rust B1

Blocked preparations now add an ordinary not-executed source-audit check; explicit terminations add a failed check. The immutable typed outcome, case row, format requirement and outcome event commit with custody in one transaction. Receipt-derived product IDs distinguish blocked checks; terminated checks retain reserved provider run/task IDs. Exact replay adds no row or outcome event and retries only pending report snapshot retention. Old custody is not backfilled; restored history remains inert.

EN and Traditional Chinese shared reports include one check and one asset gap, fixed reason/action wording, typed technical detail and no completed coverage, findings or validation leads. Framework counts, OCSF/OSCAL companions, bundles and combined reports preserve incomplete coverage. Failure-only and mixed archives verify exact outcome inventory and content-derived capabilities before restore. Scanner dispatch, resume, captured recovery, rescan, cleanup and Check fixes exclude these tasks; comparisons refuse them. Desktop parity remains B2; no TypeScript source changed.

Ordinary case saves now require failure runs to already exist in the stored case without reading custody events; ordinary cases without audit metadata also skip decoding the previous document.

Native Linux verification: **2,540 Rust test executions and 179 CI/skill Node tests passed** in the final requests below. Three Rust tests remain ignored and one platform-specific Node test remains skipped. Every final request passed and left zero temporary entries. Frozen report-fidelity baselines and the legacy archive byte pin remain unchanged. Native macOS/Windows compilation and execution remain unverified.

Synthetic coverage includes every blocker code and termination reason, ordered multiple blockers, removed assets, strict DTOs, atomic row-write rollback, revision and event preservation, pending snapshot repair, replay and no backfill, inert restore, bilingual HTML/JSON and Standard redaction, mixed scanner/admitted/blocked/terminated siblings, unchanged originals and earlier snapshots, framework counts, zero-observation exports and companion rows, bundles, preview counts, scanner refusals, failure-only and mixed archives, and missing/wrong/extra outcome bindings, digest and capability rejection.

This slice changes 24 Rust production files: **774 added and 33 removed lines**, plus **18 schema lines**. Core changes are in `domain.rs`, `agent_audit_failure.rs`, `agent_audit_failure/wording.rs`, `agent_audit_admission.rs`, `storage.rs`, and `storage/cloudflare_audit.rs`; custody and command changes are in audit `prepare.rs`, `record.rs`, `terminate.rs`, `restored.rs`, and CLI routing. Shared-report changes are in `beginner_report.rs`, `report_renderer.rs`, `finding_narrative.rs`, `export.rs`, and `selected_run_report.rs`; archive changes are in `case_archive.rs` and its history/provider modules. `case_service.rs`, `scan_coordinator.rs`, and `diff.rs` contain the exclusions; `lib.rs` wires the new module. The canonical skill and both generated host copies are synchronized. Database migrations remain [1, 2].

| Suite | Native request | Total tests | Passed | Failed | Ignored or skipped | Temporary entries left |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Formatting | b1fix-final-01 | — | Check passed | 0 | — | 0 |
| Clippy | b1fix-final-02 | — | Check passed | 0 | — | 0 |
| Rust A | b1fix-final-03 | 2009 | 2009 | 0 | 0 | 0 |
| Rust B | b1fix-final-04 | 58 | 56 | 0 | 2 | 0 |
| Node CI | b1fix-final-05 | 113 | 113 | 0 | 0 | 0 |
| Node skill | b1fix-final-06 | 67 | 66 | 0 | 1 | 0 |
| Repository checks | b1fix-final-07 | — | Check passed | 0 | — | 0 |
| Skill synchronization | b1fix-final-08 | — | Check passed | 0 | — | 0 |
| TypeScript typecheck | b1fix-final-09 | — | Check passed | 0 | — | 0 |
| All-engine report audit | b1fix-final-10 | 8 | 7 | 0 | 1 | 0 |
| Local case lifecycle | b1fix-final-11 | 5 | 5 | 0 | 0 | 0 |
| Engine execution | b1fix-final-12 | 438 | 438 | 0 | 0 | 0 |
| Job manager | b1fix-final-13 | 25 | 25 | 0 | 0 | 0 |


## November 12 explicit audit termination

Hosts can now explicitly end an audit that cannot be sealed and will not continue. The strict `terminate` command records one typed reason in the existing custody chain, supports exact replay and stale-head conflicts, and needs neither current authorization nor a surviving host directory. Inactivity never ends an audit automatically. One bounded terminal entry remains available even at the ordinary record limits.

Termination preserves assignments and captures while refusing every subsequent checkpoint, validation, sealing and admission operation, including prior-request replays. Status identifies the recorded end and offers no next operation. Current and superseded captures remain retrievable. Admitted-case archives retain terminated audits as unsealed custody with a conditional reader capability; verification reconstructs the exact inventory and restored audits remain inert. Cases without admissions retain their existing archive omissions, and the legacy byte pin is unchanged. Failed check rows in cases and reports remain for the next slice.

Native Linux verification: **2,070 Rust and 179 CI/skill Node tests passed** across the complete suites below. Three Rust tests remain ignored and one platform-specific skill test remains skipped. No tests failed or were cancelled in these successful requests; every request left zero temporary entries. Formatting, Clippy, repository checks and skill synchronization passed. Native macOS/Windows compilation and execution remain unverified.

Synthetic coverage includes every reason, empty and populated custody, both record limits, strict input rejection, replay and conflicts, busy writers, blocked/unknown preparation, sealed and repeated termination refusals, expired authorization and missing directories, all mutation routes, preserved capture retrieval, corrupt chains, persistence rollback, delivery-loss replay, restored live and terminated history, archive round trips and wrong or missing termination metadata. No case-document, report, export, desktop or TypeScript behavior changed.

| Suite | Native request | Total tests | Passed | Failed | Ignored or skipped | Temporary entries left |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Formatting | 23xa-22 | — | Check passed | 0 | — | 0 |
| Clippy | 23xa-14 | — | Check passed | 0 | — | 0 |
| Rust A | 23xa-15 | 2002 | 2002 | 0 | 0 | 0 |
| Rust B | 23xa-16 | 58 | 56 | 0 | 2 | 0 |
| Node CI | 23xa-17 | 113 | 113 | 0 | 0 | 0 |
| Node skill | 23xa-18 | 67 | 66 | 0 | 1 | 0 |
| Repository checks | 23xa-19 | — | Check passed | 0 | — | 0 |
| Skill synchronization | 23xa-12 | — | 6 files checked | 0 | — | 0 |
| All-engine report audit | 23xa-20 | 8 | 7 | 0 | 1 | 0 |
| Local case lifecycle | 23xa-21 | 5 | 5 | 0 | 0 | 0 |


## November 12 read-only audit restore

Complete archives with admitted source audits now restore into a new workspace after staged provider verification. Preserved findings, reports, exports, bundles, original downloads and captured revisions remain usable after original data and host copies are removed. Restored preparations are read-only history: preparation replay, checkpoints, validation, sealing and admission refuse before old directories or case history can change, even with fresh grants. New preparations remain available under current authorization.

Provider restore events retain typed omission metadata without a database migration. Contextual reads identify omitted source bodies; standalone retained-package reads remain strict. Rearchiving preserves sealed bytes and inherited omissions, even with sources selected. Provider previews and receipts add one read-only transformation; legacy fields and the fixed archive byte pin stay unchanged. Combined attachment overflow now uses the private complete-archive fallback for admitted cases. Admitted-run comparisons and unsealed terminal failure rows remain unavailable.

Native Linux verification: **2,060 Rust and 179 CI/skill Node tests passed** across the full suites below. Three Rust tests remain ignored and one platform-specific skill test remains skipped. No tests failed or were cancelled in these successful requests; every request left zero temporary entries. Formatting, Clippy, repository checks and skill synchronization passed. Restored-history coverage includes the validation guard, accurate verification scopes, successful mismatch status and the inherited workspace-snapshot omission.

Synthetic coverage includes sources included and omitted, source deletion followed by restore, exact capture retrieval and original downloads, actual exports, inert writes and replays, fresh grants, unchanged logical database content, strict unlisted-source failure, inherited omissions, stable crafted-archive refusals, staged-byte mismatch, publication recovery, preview transformations and attachment overflow. Native macOS/Windows builds and execution remain unverified.

| Suite | Native request | Total tests | Passed | Failed | Ignored or skipped | Temporary entries left |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Formatting | b24cf-20-final | — | Check passed | 0 | — | 0 |
| Clippy | b24cf-21-final | — | Check passed | 0 | — | 0 |
| Rust A | b24cf-22-final | 1992 | 1992 | 0 | 0 | 0 |
| Rust B | b24cf-23-final | 58 | 56 | 0 | 2 | 0 |
| Node CI | b24cf-24-final | 113 | 113 | 0 | 0 | 0 |
| Node skill | b24cf-25-final | 67 | 66 | 0 | 1 | 0 |
| Repository checks | b24cf-26-final | — | Check passed | 0 | — | 0 |
| Skill synchronization | b24cf-27-final | — | 6 files checked | 0 | — | 0 |
| All-engine report audit | b24cf-28-final | 8 | 7 | 0 | 1 | 0 |
| Local case lifecycle | b24cf-29-final | 5 | 5 | 0 | 0 | 0 |

## November 12 admitted audit archives

Complete archives now preserve admitted source audits and every recorded preparation, including sealed, unsealed and blocked history. Inventories retain current and superseded documents, accepted outputs omitted from a seal, and unavailable discarded-output metadata. Unrecorded objects are excluded. Source selection includes sealed source bodies; without it, typed omissions retain their paths, digests and lengths while documents and lineage remain unchanged. Provider text may still contain source excerpts.

Creation and verification share offline admission, original-file, evidence, event-chain and sealed-package checks. Required reader capabilities prevent silent data loss. Restore and restore preview refuse these archives before staging; admitted-case import, comparisons and combined-attachment overflow remain refused. Legacy archive bytes remain pinned, and legacy restore behavior is unchanged. The canonical skill reference was synchronized through the native suite.

Native Linux verification: **2,057 Rust and 179 CI/skill Node tests passed**. Three Rust tests remain ignored and one platform-specific skill test remains skipped. No tests failed or were cancelled; every request left zero temporary entries. Formatting, Clippy, repository checks and skill synchronization passed. The fixed legacy archive pin was established natively before the builder changes and remains unchanged. Synthetic coverage includes every stable refusal code, rehashed malformed archives, schema validation, duplicate original/package bytes, omitted sources, inert unfinished history and publication refusal. Native macOS/Windows builds and execution remain unverified.

| Suite | Native request | Total tests | Passed | Failed | Ignored or skipped | Temporary entries left |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Formatting | b24b-50-final | — | Check passed | 0 | — | 0 |
| Clippy | b24b-51-final | — | Check passed | 0 | — | 0 |
| Rust A | b24b-52-final | 1989 | 1989 | 0 | 0 | 0 |
| Rust B | b24b-53-final | 58 | 56 | 0 | 2 | 0 |
| Node CI | b24b-54-final | 113 | 113 | 0 | 0 | 0 |
| Node skill | b24b-55-final | 67 | 66 | 0 | 1 | 0 |
| Repository checks | b24b-56-final | — | Check passed | 0 | — | 0 |
| Skill synchronization | b24b-57-final | — | 6 files checked | 0 | — | 0 |
| All-engine report audit | b24b-58-final | 8 | 7 | 0 | 1 | 0 |
| Local case lifecycle | b24b-59-final | 5 | 5 | 0 | 0 | 0 |


## November 12 captured-history recovery

The development core now enumerates captured audit history directly from validated events, including superseded document revisions, all accepted assignment outputs and unavailable discarded-output metadata. `retrieve-captured` recovers exact bytes to a new private file after host copies are lost. Current document revisions and digests, plus accepted assignment IDs, roles and digests, remain available through the existing status fields.

Recovery reads one bounded database snapshot without initialization, a writer lease, database changes or new authority. It verifies object lengths and digests, pins the destination namespace and rechecks the snapshot before publication. Caller digest mismatches and unsafe destinations are refused; changed history and busy storage return conflict without automatic retries; missing or corrupt committed bytes return storage failure. Active, sealed and abandoned audits remain readable. Further recording still requires current authority.

Synthetic native tests cover current and superseded documents, accepted outputs omitted from sealed bundles, discarded output refusal, orphan exclusion, wrong-case isolation, invalid selectors, digest/head mismatches, private files, existing/link/special/storage destinations, parent replacement, missing/corrupt/oversized objects, stored-length bounds, busy storage, concurrent history changes, unchanged logical database content and existing discovery fields. The canonical skill recovery reference was regenerated into both host copies by the native synchronization suite. Complete archives, restore and comparisons for admitted audits remain refused; reports, exports and bundles retain their existing behavior.

Native Linux verification: **2,045 Rust and 179 CI/skill Node tests passed** across the full suites below. Three Rust tests remain ignored and one platform-specific skill test remains skipped. The focused unselected-output check also passed and is already included in the full Rust test count. No tests failed or were cancelled, and every request left zero temporary entries. Formatting, Clippy, repository checks and skill synchronization passed. No TypeScript changed in this slice. Native macOS/Windows builds and execution remain unverified.

| Suite | Native request | Total tests | Passed | Failed | Ignored or skipped | Temporary entries left |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Formatting | 24a-20-verify | — | Check passed | 0 | — | 0 |
| Clippy | 24a-21-verify | — | Check passed | 0 | — | 0 |
| Rust A | 24a-22-verify | 1982 | 1982 | 0 | 0 | 0 |
| Rust B | 24a-23-verify | 58 | 56 | 0 | 2 | 0 |
| Node CI | 24a-24-verify | 113 | 113 | 0 | 0 | 0 |
| Node skill | 24a-25-verify | 67 | 66 | 0 | 1 | 0 |
| Repository checks | 24a-26-verify | — | Check passed | 0 | — | 0 |
| All-engine report audit | 24a-27-verify | 8 | 7 | 0 | 1 | 0 |
| Skill synchronization | 24a-13-skill-sync | — | 6 files checked | 0 | — | 0 |
| Unselected captured output | 24a-28-unselected | 1 | 1 | 0 | 0 | 0 |


## November 12 admitted audit bundles and attachments

Signed case bundles now include the case-wide admission projection, artifact bindings and explicit provider task provenance, including when their report selects a scanner run. Standard withholds provider text/code with counts, masks locations and pseudonymizes coverage IDs/fingerprints; `none` keeps native values. The bundle framework extension equals the shared report's audit extension. Admission and native digests commit to original material, while the signed manifest hashes the exported document. Audit tasks are excluded from catalog engine versions and product-owned built-in task records.

Single-run and combined HTML attachments now preserve source audit originals with nested member names, provider/admission/method attribution and file/ZIP digests. Only `none` plus the raw-artifact choice includes provider originals; Standard excludes and counts them without reading bytes. Frozen attachments replay after originals disappear. Combined overflow in an admitted case refuses before file or history publication with `source_audit_attachment_overflow` and “Select fewer runs or export a case bundle.” Scanner-only cases retain the existing private archive fallback. Preview counts audits separately; desktop eligibility offers attachments and bundles. Complete audit archives, restore and comparisons remain refused.

Synthetic tests cover both profiles and raw choices, scanner-selected bundles in admitted cases, masked admissions and original commitments, framework/shared-report equality, exact originals and ZIP digests, deleted/tampered originals, admission graph mutations, signed-document tampering/removal/addition, collisions, individual and aggregate limits, encoded-document overflow, no publication/history on refusal, omission counts, offline replay, preview and desktop eligibility. Fixed-input/time/key bundles match pre-change bytes in all four profile/raw combinations. Existing archive fallback and frozen report baselines remain unchanged.

Native Linux verification: **2,035 Rust, 179 CI/skill Node, 957 frontend and 612 component tests passed**. Three Rust tests remain ignored, with 33 frontend skips and one platform-specific skill skip. No tests failed or were cancelled; every request left zero temporary entries. Formatting, Clippy, repository checks and desktop typechecking passed. Native macOS/Windows execution and packaged desktop execution remain unverified.

| Suite | Native request | Total tests | Passed | Failed | Ignored or skipped | Temporary entries left |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Formatting | b23b2-final-01 | — | Check passed | 0 | — | 0 |
| Clippy | b23b2-final-02 | — | Check passed | 0 | — | 0 |
| Rust A | b23b2-final-03 | 1967 | 1967 | 0 | 0 | 0 |
| Rust B | b23b2-final-04 | 58 | 56 | 0 | 2 | 0 |
| Node CI | b23b2-final-05 | 113 | 113 | 0 | 0 | 0 |
| Node skill | b23b2-final-06 | 67 | 66 | 0 | 1 | 0 |
| Repository checks | b23b2-final-07 | — | Check passed | 0 | — | 0 |
| All-engine report audit | b23b2-final-08 | 8 | 7 | 0 | 1 | 0 |
| Local case lifecycle | b23b2-final-09 | 5 | 5 | 0 | 0 | 0 |
| Desktop typecheck | b23b2-final-10 | — | Check passed | 0 | — | 0 |
| Frontend Node | b23b2-final-11 | 990 | 957 | 0 | 33 | 0 |
| Components | b23b2-final-12 | 612 | 612 | 0 | 0 | 0 |

## November 12 source audit schema exports

Admitted source audits now export through framework reports, OCSF and OSCAL in both Standard and `none` profiles. Framework reports carry the shared report's redacted `source_audits` extension, exclude audit tasks from scanner counts and engine states, and mark their findings `source_audit_not_mapped`. OCSF Detection Finding events and OSCAL `EXAMINE` observations include confirmed findings only, with provider identity and unchanged human workflow status. Provider confirmation is not a control or compliance conclusion. The mandatory OCSF/OSCAL companion preserves leads, gaps, method and outcome even with zero finding events, binds the main file hash, and retains publication rollback.

The export gate validates unique admission and case/run/task/provider/artifact bindings before writing. Standard masks unresolved fingerprints consistently, omits derived gap labels from withheld-text counts, and preserves exact text/code counts from the shared report. Desktop eligibility offers the three formats; attachments retain the unavailable message. Case bundles, single and combined attachments, complete archives and comparisons still refuse audits. Schema definitions are additive; constants, notices, frozen report baselines and host skills are unchanged.

Final native Linux verification passed **2,021 Rust tests, 179 CI/skill Node tests, 956 frontend tests and 612 component tests**. Three Rust tests remain ignored; the frontend retains 33 skips and the skill suite one platform skip. All checks passed with no failed or cancelled tests and zero temporary entries left by every request. Native macOS/Windows execution and packaged desktop execution remain unverified.

| Suite | Request ID | Total tests | Passed | Failed | Ignored or skipped | Temporary entries left |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Formatting | b23b1-final-01 | — | Check passed | 0 | — | 0 |
| Clippy | b23b1-final-02 | — | Check passed | 0 | — | 0 |
| Rust A | b23b1-final-03 | 1958 | 1958 | 0 | 0 | 0 |
| Rust B | b23b1-final-04 | 58 | 56 | 0 | 2 | 0 |
| Node CI | b23b1-final-05 | 113 | 113 | 0 | 0 | 0 |
| Node skill | b23b1-final-06 | 67 | 66 | 0 | 1 | 0 |
| Repository checks | b23b1-final-07 | — | Checks passed | 0 | — | 0 |
| All-engine report audit | b23b1-final-08 | 8 | 7 | 0 | 1 | 0 |
| Desktop typecheck | b23b1-final-09 | — | Check passed | 0 | — | 0 |
| Frontend Node | b23b1-final-10 | 989 | 956 | 0 | 33 | 0 |
| Components | b23b1-final-11 | 612 | 612 | 0 | 0 | 0 |

## November 12 desktop source audit view

Admitted source audits now appear in desktop Results with the shared report's English and Traditional Chinese wording. Confirmed findings retain native impact and remediation, while To validate stays separate from problem counts. Remaining units show readable labels, localized states and continuation paths; out-of-scope units have no continuation. Method, attempts, lineage, digests and provider evidence remain in collapsed technical details. Provider strings stay literal text, including multiline code and link-like values.

Audit tasks are recognized without catalog execution or recovery controls. Audit-only runs are excluded from Check fixes; scanner siblings still qualify a mixed baseline. Single-run HTML/JSON and combined reports are offered with a Source audit selection label. Framework reports, OCSF, OSCAL and attachments are unavailable for audits; case bundles, complete archives and comparisons retain backend refusals. Rust production code, frozen baselines and host skills are unchanged.

Final native Linux verification passed all seven previously failing frontend parity tests, with **956 frontend, 612 component, 113 CI and 66 skill tests passed**. The 33 frontend skips and one platform-specific skill skip remain; no tests failed or were cancelled. Typechecking and repository checks passed. Every final request left zero temporary entries. The packaged desktop build, visual checks at device widths, and native macOS/Windows execution remain unverified.

| Suite | Request | Total tests | Passed | Failed | Skipped | Temporary entries left |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Desktop typecheck | b23c-final-01 | — | Check passed | 0 | — | 0 |
| Frontend Node | b23c-final-02 | 989 | 956 | 0 | 33 | 0 |
| Components | b23c-final-03 | 612 | 612 | 0 | 0 | 0 |
| Node CI | b23c-final-04 | 113 | 113 | 0 | 0 | 0 |
| Node skill | b23c-final-05 | 67 | 66 | 0 | 1 | 0 |
| Repository checks | b23c-final-06 | — | Checks passed | 0 | — | 0 |

## November 11 admitted source audit reports

Admitted source audits appear in single-run and combined HTML/JSON reports and frozen snapshots. Standard uses the shared masking policy: provider prose and code are withheld with separate counts, file and scope values use location markers, titles replace known private literals, provider coverage identifiers and fingerprints use deterministic SHA-256 pseudonyms, and product-generated identities, scores and digests remain unchanged. Confirmed findings use the localized source-code family narrative. The `none` profile retains native descriptions, impact and remediation verbatim, including text resembling product markers.

Only planned, in-progress, blocked, deferred and unresolved candidate units count as remaining and carry continuation paths. Each audit aggregates its remaining units into one coverage gap without adding a second Not tested count, and its out-of-scope units into one excluded gap. The first layer names the method Cloudflare source audit, with localized unit statuses and validation labels. Remaining units share one next step: "Continue the source audit from the listed paths." Standard preserves this product sentence; paths stay under What was not tested and in technical detail. Out-of-scope units produce no next step. Out-of-scope units are listed without continuation; not-applicable units remain in counts and technical detail. Incomplete audits with no remaining units show the unresolved-candidate count or the concise incomplete outcome. Candidate fingerprints stay in technical detail. Empty validation and gap sections are omitted. Traditional Chinese product vocabulary and markers are localized. Stored provenance and validator facts are preserved. The framework section stays omitted for admitted audits, and the closing text no longer points to it.

Admission retains a terminal snapshot after committing its receipt. Pending snapshots and foreground commands now share one library error classification, with all thirteen variants covered by a regression test. Pending snapshots report the actual failure code and retryability; recovery returns exit four for retryable storage or I/O failures and exit two when a report is unavailable. Recovery never starts audit work. Framework reports, OCSF, OSCAL, attachments, case bundles and complete archives retain their existing admission boundaries. Audit comparisons remain unavailable. Host skills are unchanged.

Final native Linux verification passed **2,013 Rust tests, 179 CI/skill Node tests and 584 component tests**. Desktop typechecking passed. Frontend Node tests passed 935, skipped 33 and retained seven known failures in vocabulary and backend/frontend kind parity; the audit product labels and continuation sentence also await desktop translation. Three existing Rust tests remained ignored and one Windows ACL Node test was skipped. Formatting, warning-free Clippy, diff, skill sync, site locale and the unchanged report-fidelity verifier passed. The full final request totals are below; every request left **zero temporary entries**. Native macOS and Windows execution remain unverified.

| Native suite | Request ID | Passed | Failed | Ignored or skipped | Temporary entries |
| --- | --- | ---: | ---: | ---: | ---: |
| Formatting | 23af3-final-01 | Check passed | 0 | — | 0 |
| Clippy | 23af3-final-02 | Check passed | 0 | — | 0 |
| Rust A | 23af3-final-03 | 1,950 | 0 | 0 | 0 |
| Rust B | 23af3-final-04 | 56 | 0 | 2 | 0 |
| Node CI | 23af3-final-05 | 113 | 0 | 0 | 0 |
| Node skill | 23af3-final-06 | 66 | 0 | 1 | 0 |
| Repository checks | 23af3-final-07 | Checks passed | 0 | — | 0 |
| All-engine report audit | 23af3-final-08 | 7 | 0 | 1 | 0 |
| Desktop typecheck | 23af3-final-09 | Check passed | 0 | — | 0 |
| Frontend Node | 23af3-final-10 | 935 | 7 | 33 | 0 |
| Components | 23af3-final-11 | 584 | 0 | 0 | 0 |

## November 11 sealed audit admission

The development command now admits verified sealed audits with copied originals, one atomic receipt, replay and interrupted-publication recovery. At that earlier checkpoint, Check fixes and comparisons refused admitted audit runs, and reports, exports and complete archives still refused affected cases. Host skills are unchanged. Native Linux passed 1,991 Rust tests across the two required Rust suites and 179 Node tests across the CI and skill suites, plus a repeat of all 10 admission CLI tests; two existing Rust tests remained ignored and one Windows ACL Node test was skipped. Formatting, warning-free Clippy, diff, skill sync, site locale and report-fidelity checks passed, with zero temporary entries left by every final request. Native macOS and Windows execution remain unverified.

## November 11 test temporary cleanup

Tests that create read-only product data now use one shared temporary-root helper; cleanup restores directory owner access without following links, and a remaining cleanup failure fails the test on Unix. Native Linux passed 2,606 Rust tests and 241 Node tests with zero temporary entries left by every final request; three existing Rust tests remained ignored and one Windows ACL Node test was skipped. Formatting, warning-free Clippy and repository checks passed; native macOS and Windows execution remain unverified.

## November 11 Cloudflare audit preparation

A sealed record can now be fully verified offline against the product’s own custody and source-view records, without rerunning validators.

The development skill now carries [host instructions](../skills/ai-security-scanner/references/cloudflare-source-audit.md)
for the pinned source-audit method, from readiness and human model-processing
confirmation through native delegation, captured outputs, validation and sealing.
A [synthetic acceptance kit](../tests/acceptance/cloudflare-host/README.md) prepares
a ready source view through public CLI commands; setup alone performs no audit. In a
real acceptance run on Linux, a development host with native sub-agents followed these
instructions through a quick audit of that synthetic repository with a budget of seven
invocations: four reconnaissance roles, one hunter, one coverage critic and one verifier.
Each assignment was issued before delegation, each returned output was captured byte for
byte, all seven shared documents were accepted, and the record validated and sealed. The
host reported one needs-validation lead for the repository's concurrency defect, without
severity, no confirmed or rejected records, and partial coverage. One of the two
supported hosts has run this acceptance. Released desktop operation is unchanged.

The development core can prepare, keep and seal an audit record against a ready
product source view, with product-generated identities and durable receipts. It checks
the host declaration, budget, current grant and source integrity. Preparation
performs no audit, model call or target execution. It requires a real host working
directory with no linked path components, without reading its contents or writing
to it. Before sealing, every checkpoint, including replay, rechecks that directory and
authority.

The host can request assignment identities before delegation and record abandoned
assignments with an interruption reason. The product records role, order and time,
checks wave and budget rules, and preserves replacement links. Issuance does not
start an agent or establish that one ran. Each request extends the hash chain using
the expected head; identical retries return the saved entry.

The host can now submit the seven shared documents in atomic batches. The product
captures only named files, checks optional declared digests and lengths, UTF-8 and
size bounds, runs the pinned ledger and findings validators on captured bytes, and
checks metadata against the preparation. In-progress metadata is accepted.
Document refusals retain nothing. Accepted bytes enter a private content-addressed
store before one entry records their numbered revisions. Identical bytes can reuse
an object while still counting as another revision toward the 512 MiB run limit.
Capture establishes custody of bytes, not a judgement about their content.

The host can submit one output per open assignment, under that assignment's own
agent directory. Reconnaissance requires non-empty text; hunters and critics
require one strict JSON object. Candidate-verifier decisions must match a record
that passes the pinned findings validator. Accepted outputs close assignments
and retain exact bytes and verifier decision metadata. Malformed verifier outputs
are permanently discarded with their digest, length and typed reason, without
storing bytes; a replacement assignment consumes another invocation. Read and
validator runtime failures leave assignments open.

Standard and deep profiles can issue final-verifier assignments for eligible
findings with an accepted candidate output. The product binds each assignment to
the current stored findings revision and exact record digest. Final outputs either
verify that fingerprint or propose a schema-valid replacement; proposals do not
edit findings. Changed revisions require new bindings. Before sealing, every checkpoint action, including replay, refuses an outdated
preparation if validator resources have changed.

The host can now validate a terminal run from captured product bytes. The product
generates the manifest, selects current verifier receipts, checks the full source
view and canonical snapshot, and runs the existing bundle validators. It also
checks issued ledger owners, closed evidence owners and completed-run
reconnaissance and critic requirements. The host working directory is not needed.
The answer includes whether the run can be sealed, deterministic manifest and
bundle digests, the unchanged reported-only bundle receipt and separate record
errors. Validation holds the writer lease but records nothing and removes its
private temporary bundle. A sealable answer is not a sealed result.

The host can seal that result by supplying both expected digests. Finalization
reruns terminal validation, builds a private read-only package and commits one
terminal entry after rechecking the head, case revision, request identity and
effective authorization. The package preserves the unchanged reported-only
retained payload, the preparation and ordered record, and a separate workflow
projection. Only that projection and its terminal entry state recorded workflow
provenance and verified source binding and authorization. Audit performed means
at least one hunter assignment is closed; it establishes neither agent execution,
model independence nor the truth of a finding. Admission and target execution
remain false.

Sealed records reject further checkpoints, validation and different finalize
requests. The saved finalize request replays without current authority after a
cheap check of the three recorded files. An interrupted publication can be reused
only when its file digests match; changed bytes are preserved and rejected.
Read-only status reports the package path, recorded outcome and counts, and a
verified, missing or mismatched package state, with no next operation. Archives
preserve the terminal event but explicitly omit the package; restored status
reports it missing. Confirmed artifact deletion removes the read-only package.

Read-only status works while another writer is active and reports the head,
assignments in open, closed, interrupted or discarded states, closing times, output
metadata, counts by state, budget, current document revisions, acceptance times, revision counts
and captured-byte usage without reading objects. Checkpoint replays before sealing check authority and the directory but never
reopen documents. Current preparation requests can recover a
missing descriptor; changed bytes are never overwritten. Archives retain events
as history with an explicit omission of the audit directory and objects. Restored
history cannot resume a run. Confirmed case artifact deletion removes the objects.

This offline-verification round passed 1,967 native Linux Rust tests: 1,911 in the
core and provider group and 56 in the archive, foreground and report group; two
existing fidelity tests remained ignored. Node passed 244 tests (113 CI, 66 skill,
65 upstream), with one existing Windows ACL test skipped. Formatting, Clippy with
warnings denied, the diff check, skill-copy parity, site locales and the
report-fidelity verifier passed. Every completed native request left zero
temporary entries. Native macOS and Windows execution remain unverified.

Earlier custody validation on native Linux passed 1,957 Rust tests: 1,659 library units, 75 CLI units, 77 audit
CLI tests, 24 source-view CLI tests, 29 workspace snapshot tests, 24 bundle tests,
six provider tests, six read-only status tests, one build-identity check, 14
archive tests, 14 foreground tests, 13 report snapshot tests, seven runtime
preparation tests and eight report fidelity tests. Two existing fidelity tests
remained ignored. All 244 applicable Node tests passed: 113 CI, 66 skill and 65
upstream; one existing Windows ACL test was skipped. Formatting, warning-free
Clippy, diff check, skill sync, site locale and the fidelity verifier passed.
Native acceptance setup passed in two fresh directories and refused a non-empty
directory. Native macOS and Windows execution remain unverified.
Remaining work is acceptance on the second supported host, and case, report and
complete audit-package archive integration.
See [preparation and status](cloudflare-provider.md#audit-preparation-and-status)
and [sealing](cloudflare-provider.md#sealing-the-audit-record).

## November 11 Git tracked-file probe hardening

When a project snapshot is captured, the development core asks the host's
trusted Git which files the repository tracks. That child process now denies
every Git transport and never fetches a missing object on demand, in addition
to its existing fixed environment. A scanned repository's own configuration
therefore cannot make the scanner start a program or contact a network during
capture. Every Git invocation is built by one shared constructor.

A repository whose tracked-file list cannot be read without fetching follows
the existing rule for an unavailable probe: capture completes and that
repository boundary keeps every file. Ordinary repositories and ordinary
partial clones keep the same inventory and snapshot content.

Native Linux tests build local repositories whose configuration names a marker
program that only an object fetch would start, confirm that each fixture is
live, capture it through the product and require that no marker appears.
Another test compares an ordinary partial clone with a full clone. Native Linux
passed 1,861 Rust tests, including 1,642 library units and 29 workspace
snapshot tests, with the other suites unchanged, and 113 CI document tests.
Formatting, warning-free Clippy and the repository checks passed. Native macOS
execution has not been verified; Windows does not run this probe.

## November 10 product-owned source views

The development core prepares a model-readable tree from an approved frozen
repository, inspects it offline and retrieves its preparation receipt. Explicit
scope and model-processing acknowledgement are required for each preparation request. The fixed
policy preserves included bytes and line numbers, excludes sensitive names and
private-key markers, and accounts for every canonical file. It does not guarantee
secret-free content or perform an audit or model call.

Preparation checks current authorization, snapshot binding and integrity. Authorization
is rechecked before publication and as the last step before recording the receipt.
Selectors are checked against the frozen manifest when evaluation reaches it;
earlier blockers return without that check. Ready
replays recheck those conditions and the published bytes; stale receipts remain
historical records without usable paths. Blocked retries return the recorded blocker;
a new request ID is needed after fixing its cause. Missing views are rebuilt, and
damaged copies or obstructing files/symlinks are set aside before replacement
without following links. Offline inspection verifies one consistent instant of
inventory, policy, partition and content identity without authenticating a producer.
Externally supplied bundles remain reported-only, including bundles that name an
actually prepared product view.

Native Linux passed 1,857 Rust tests: 1,641 library units, 75 CLI units, 24
source-view CLI tests, 26 workspace snapshot tests, 22 bundle tests, six provider
tests, six read-only status tests, one build-identity check, 14 archive tests,
14 foreground tests, 13 report snapshot tests, seven runtime preparation tests
and eight report fidelity tests. Two existing fidelity tests remained ignored.
All 241 applicable Node tests passed: 113 CI, 63 skill and 65 upstream; one
existing Windows ACL test was skipped. Formatting, warning-free Clippy, diff
check, skill sync, site locale and the fidelity verifier passed.

Archives preserve receipts as historical events and explicitly omit source-view
bytes; restore does not renew authorization. Confirmed case artifact deletion
removes sealed and set-aside views. Git capture, host coordination, bundle
admission and case/report integration remain pending. Native macOS and Windows
execution has not been verified. See the [source-view guide](cloudflare-provider.md#product-owned-source-views).

## November 10 private Cloudflare retention and offline retrieval

Validated reported bundles can now be preserved with `retain-bundle`, inspected
with `inspect-retained` and read back with `retrieve-retained`. Retention requires
the preview's bundle digest, captures indexed originals and the source view into
private staging, validates those captured bytes, saves the projection/validation
receipts and publishes one complete directory without replacement. The index
binds all payloads, original manifest and source identity. Unindexed scratch is
excluded. Concurrent writers cannot replace a completed result.

Saved directories can move, and originals can be removed, before offline
inspection and exact-byte retrieval. These reads require no Node, model, scanner
runtime or case database. They check integrity and saved receipt relationships;
they do not rerun validation or authenticate supplied workflow claims. Retrieval
requires the retained-index digest. A different producer core is reported without
blocking retrieval of the supported format. The command does not mutate case
state or acquire its writer lease, and all results remain reported-only.

Linux passed 1,724 Rust tests: 1,616 core units, 74 CLI units, one build-identity
check, 21 bundle/retention subprocess tests, six document subprocess tests and six
read-only status tests. Tests retrieve every indexed member after moving the
saved directory and deleting originals, reject tampering and stale input,
preserve existing destinations, exclude scratch, and arbitrate concurrent saves
while a case writer is active. They also exercise the additional bounded coverage
projection against an upstream-valid input. All 240 applicable Node/upstream/CI
tests passed; one Windows ACL test is explicitly skipped on Linux. CLI-feature
Clippy across all workspace targets passed with warnings denied, along with
formatting and skill-copy synchronization.

This is private provider-data preservation, not a full canonical repository or
case backup. At that milestone, trusted source/view policy, authenticated host coordination, durable
case admission and case/report integration remain pending. Windows/macOS native
execution is still unverified for this milestone. See the
[retention instructions](cloudflare-provider.md#private-retention-and-offline-retrieval).

## November 10 reported Cloudflare bundles and report projections

`provider cloudflare validate-bundle` now verifies a versioned manifest and
explicit source view, runs the pinned validators, and checks source locations,
current/historical coverage evidence, fingerprint links, declared counts and
supplied verifier output. A root-relative reader rejects symlinks, reparse points,
physical links, unsafe aliases and changing file identity. The manifest and all
selected file/source hashes bind the returned bundle digest. Unindexed scratch
files are neither read nor copied.

Successful validation returns a shared provider report projection with the exact
native records, source hashes, coverage/attempt history and separate confirmed,
needs-validation, rejected and unvalidated-candidate counts. It preserves payload
and proposed-code strings. Incomplete runs retain completed sibling records and
explicit candidates without fabricating findings. Quick-profile combined review
and carried-record owner rules follow the pinned method.

All results remain reported-only. Supplied receipts cannot grant workflow trust,
source authorization or a verified canonical-snapshot lineage. No case, human
triage state, scanner execution, report export or admission receipt is created.
The completed boundary and manifest recipe are in the
[bundle guide](cloudflare-provider.md#reported-bundle-validation). Trusted source
views, coordination receipts, durable admission and case/report integration remain
pending; this milestone does not complete the host audit workflow.

Linux passed 1,716 Rust tests: 1,616 core units, 74 CLI units, one build-identity
check, 13 bundle subprocess tests, six document subprocess tests and six read-only
status tests. Bundle cases cover all three verdicts, unresolved candidates,
missing and cross-task evidence, source/file tampering, duplicate manifests,
self-verification, malformed output and preservation of raw strings. All 240
applicable Node/upstream/CI tests passed; one Windows ACL test is explicitly
skipped on Linux. CLI-feature Clippy across all workspace targets passed with
warnings denied. The native CI matrix includes bundle validation, but Windows
and macOS execution remain unverified. The released default skill is unchanged.

## November 10 pinned Cloudflare document validation

The complete 22-file Cloudflare dependency is vendored unchanged at the
[documented upstream revision](cloudflare-provider.md), with MIT licensing,
per-file Git blob identities, SHA-256 and byte lengths. The provider manifest advertises only the
implemented capability. `provider cloudflare validate-document` validates native
findings or a coverage ledger, returns a receipt bound to the original bytes and
embedded validator resources, and exits 2 for an invalid document. It does not
create case state, acquire the data writer lease, contact targets or admit findings.

The adapter preserves upstream schema/verdict checks and CLI preflight limits,
adds duplicate-key rejection, and runs embedded code from private staging with
bounded stdin, output and execution time. Node preload/module/loader environment
variables are removed. The standalone reader rejects physical links, special
files, invalid UTF-8, oversized files and changed file identity. It does not yet
provide a bundle root or evidence/source traversal policy. Prompt documents stay
outside the native cache key; executable validator/schema changes invalidate it.

Linux passed 1,700 Rust tests: 1,613 core units, 74 CLI units, one build-identity
check, six Cloudflare CLI subprocess tests and six read-only status tests. The
owned-process test starts a real Node process for stalled input and excess
stdout/stderr, then verifies termination and reaping. The standalone commands
also produced valid receipts for the three-verdict findings fixture and native
coverage-ledger fixture. CLI-feature Clippy across all workspace targets passed
with warnings denied, as did formatting and skill-copy synchronization.

All 65 unchanged upstream validator tests, 62 applicable skill/bootstrap tests
and 113 CI contracts passed (240 Node tests; the Windows ACL test is explicitly
skipped on Linux). The native CI matrix includes the new command, but Windows
and macOS execution remains unverified for this milestone.

At this first single-document milestone, bundle checks, report mapping and host
orchestration were still pending; the later bundle work is recorded above.
See [the command and exact boundary](cloudflare-provider.md).

## November 9 selected-engine runtime preparation

The development bootstrap now accepts `prepare --capability scan --engine ID
--data-dir DIR`. It reuses the verified core cache and prepares only the selected
catalog-pinned images, plus the shared gateway image when required. The CLI
validates the complete selection before runtime work, requires an explicit data
directory, takes its writer lease, and saves an independent preparation receipt
before stdout delivery. Preparation creates no case, permission or target-facing
work. Failed images retain completed siblings.

Preparation uses the same managed-runtime and compatibility selection as scans.
Offline mode requires a running runtime and existing images or verified local
archives; it cannot start a VM or contact a registry. Parent cancellation uses a
fixed pipe, including EOF when the parent exits. Managed startup and image
operations join their owned subprocesses; stalled managed-image reads have a
30-second I/O bound and retain resumable partials. Preparation does not enter the
desktop's automatic Windows prerequisite-repair loop.

Linux validation passed 1,611 core unit tests, 74 CLI unit tests, one build-identity
test, seven runtime-preparation subprocess tests, 25 job-manager tests, nine
foreground tests, seven archive tests, six status tests, five report-snapshot
tests and eight report-fidelity tests (1,753 total; two explicit output generators
ignored). These include cancellation before setup, retained partial downloads,
owned-process cleanup, no automatic Windows prerequisite repair, offline image
selection and preservation of successful sibling outcomes. All 48 portable Node
skill/bootstrap tests passed; one Windows ACL test is explicitly skipped on Linux.
CLI-feature Clippy across all workspace targets passed with warnings denied.
Formatting, all 112 CI contracts, the frozen report baseline, canonical skill
validation and host-copy synchronization passed.

A fresh Linux x86_64 dev bootstrap was built offline with Node 24.22.1 and
Rust 1.98.0. The opt-in [runtime smoke](../scripts/ci/skill-runtime-smoke.py)
then reused that cache and the exact existing Gitleaks image through Docker
29.1.3. It scanned only a copied, owned synthetic fixture, produced one expected
secret finding, and verified fully redacted raw evidence. No container remained
for the completed run. After moving away the original workspace, source and
snapshot, full archive restore retained findings, all evidence, source snapshots
and the foreground receipt while disabling scan authority. Every restored payload
hash passed; restored HTML/JSON retrieval and replay matched the original bytes.
Exact source, fixture and artifact identities are in the
[bootstrap validation record](skill-bootstrap.md#november-9-selected-engine-and-real-scan-validation).
This proves the owned local-project path on Linux; it does not establish the full
multi-asset, Cloudflare or three-platform journey.

Automatic acquisition of the managed bundle on a cold host remains pending.
Windows/macOS execution, desktop comparison and Cloudflare integration still need
their own implementation or evidence. Bootstrap foreground cancellation now uses
the shared control pipe described below; native Windows evidence remains pending.
The default operator route remains the released desktop.

Reproduce the source regression checks with:

```sh
cargo test --locked -p ai-security-scanner --no-default-features --features cli \
  --lib --bin ai-security-scanner-cli --test cli_build_identity \
  --test cli_runtime_prepare --test job_manager --test cli_foreground_scan \
  --test cli_case_archive --test cli_read_only_status \
  --test cli_report_snapshot --test report_fidelity_baseline
cargo clippy --locked --workspace --no-default-features --features cli --all-targets -- -D warnings
cargo fmt --all --check
node --test tests/skill/*.test.mjs
node --test tests/ci/*.test.mjs
node scripts/skill/sync-skill.mjs --check
```

## November 9 bootstrap foreground cancellation

Bootstrap `run` now gives `scan run`, `scan recover` and `runtime prepare` a
private cancellation pipe. These resource-owning commands share the bounded
Rust reader already used for selected runtime preparation. Ctrl+C and termination
requests are sent once; the bootstrap waits for the core's close and preserves
its exit code. Unexpected parent exit also cancels through pipe EOF. Malformed
control input stops owned work and records `cancellation_control_failed` instead
of misreporting an output failure. Normal completion does not wait for pipe EOF.

Linux validation passed 74 CLI unit tests, 13 foreground subprocess tests, seven
runtime preparation tests, six read-only status tests and seven archive tests
(107 total). The foreground tests include the actual Node launcher and compiled
CLI: interrupt, terminate and killed-parent cases all preserve the exact saved
receipt, finish recorded-resource cleanup, reap the controlled runtime and release
the data-directory lease. Direct pipe tests cover EOF, malformed/overlong messages
and normal completion. These use synthetic runtime fixtures, not an upstream scan.

All 54 applicable Node skill/bootstrap tests passed; the Windows ACL test remains
explicitly skipped on Linux. Six new portable tests cover command selection,
repeated cancellation, parent death, normal exit and failed spawn. The native CI
matrix now runs these Node tests on all three operating systems. Targeted
CLI/foreground/runtime-preparation Clippy passed with warnings denied, along with
formatting, skill-copy synchronization and all 112 CI contracts. Windows/macOS
native execution and the full skill-to-restore acceptance remain pending.

Reproduce the focused checks with:

```sh
cargo test --locked -p ai-security-scanner --no-default-features --features cli \
  --bin ai-security-scanner-cli --test cli_foreground_scan \
  --test cli_runtime_prepare --test cli_read_only_status --test cli_case_archive
cargo clippy --locked -p ai-security-scanner --no-default-features --features cli \
  --bin ai-security-scanner-cli --test cli_foreground_scan \
  --test cli_runtime_prepare -- -D warnings
node --test tests/skill/*.test.mjs
node --test tests/ci/*.test.mjs
```

## November 10 combined original files and overflow archives

Combined HTML now supports source/task ZIP downloads using the existing verified
original-file reader. Relative directories, exact bytes, hashes and source timestamps
are retained. Standard redaction excludes sensitive originals from shared HTML.
The frozen snapshot retains the selected ZIPs; offline replay and complete archive
restore preserve them after the original workspace disappears. Single-run attachment
selection and report output remain unchanged.

The aggregate original-file budget is 64 MiB / 10,000 files across all selected
sources. The final document also retains its separate 64 MiB limit, including ZIP,
base64 and markup. Exceeding either attachment limit produces readable HTML and a
private complete case archive beside it. The receipt records included/omitted counts,
reason, archive filename/path/hash/length. Full-case fallback requires explicit consent:
it can contain sensitive evidence from other runs. The archive captures the pre-export
case revision and includes the new frozen combined report, all recorded evidence and
existing archive omissions. It does not invent original source trees or scan authority.
Publication/history failure rolls back the new report, snapshot and archive together.

The desktop panel reuses existing controls and exposes the original-file/private-archive
choice only for HTML. Switching to JSON clears consent; success displays the actual
archive location. English, Traditional Chinese and Japanese copy is provided. CLI flags
and manual snapshot limits are documented in [combined originals](report-snapshots.md#include-original-files).
Later complete archives can include the fallback archive via `--include-export-files`;
restore verifies and rebinds its path. Without that selection the historical path is
cleared while the case archive still retains raw evidence and the combined snapshot.

Linux validation passed 2,179 Rust tests: 1,612 core unit, 74 CLI unit, 438 standalone
engine/domain, 14 foreground subprocess, 14 archive, 13 snapshot, six read-only status
and eight fidelity tests; two explicit output generators remain ignored. Tests exercise
a 65 MiB original, 48 MiB of incompressible data that overflows after ZIP/base64 encoding,
10,002 files spread across sources, sensitive-file exclusion, corrupt originals,
publication rollback, full archive verification/restoration and companion preservation.
CLI-feature all-target Clippy, TypeScript checking and 112 CI contracts pass. The
frontend suite passes 942 tests with 33 explicit skips. Three
rendered component tests cover selection/consent/JSON reset and displayed archive paths.
Chromium rendered the actual component and CSS at 390, 768 and 1440px in all three
languages with long paths: nine layouts, no horizontal overflow or page errors. The
mocked export in this visual fixture contacts no targets. Report baseline bytes and
host skill copies remain unchanged. Native desktop execution and Windows/macOS checks
remain separate from these Linux/browser validations.

## November 9 combined report snapshots

Combined HTML/JSON exports now retain a private snapshot and a `combined_exports`
history record through the shared desktop/CLI service. The existing two-to-sixteen
terminal-source selection, source order, independent findings and coverage gaps
are preserved. A snapshot freezes the complete selected-run projection, generation
time, locale, redaction, original document bytes and case context. The same
renderer produces both exports and offline replay; no current case, scanner or
model is consulted during replay.

`report snapshot --run-id FIRST --run-id SECOND` also supports manual composition
without changing case history. Combined snapshots use a v2 envelope with ordered
`selected_run_ids`; single-run v1 remains supported. Unknown renderers can retrieve
originals even when frozen domain variants cannot be decoded by this core. A
snapshot with mismatched ordered sources or a mismatched known report schema is
rejected. Combined raw attachments remain unsupported in this step.

Publication commits both private snapshot and shared document before recording
history; output or database failure rolls back only new files. Full archives
retain recorded combined snapshots automatically, verify every source/reference,
and optionally include original external export files. Restore retains portable
snapshot paths, clears unselected external paths and rebinds selected verified
files. Missing recorded snapshots reject verify/restore even when transport
hashes have been recomputed. Restored projects can be archived again.

Linux validation passed 2,175 Rust tests: 1,611 core unit, 74 CLI unit, 438
standalone engine/domain, 14 foreground subprocess, 11 archive, 13 report snapshot,
six read-only status and eight report-fidelity tests; two explicit output generators
remained ignored. New subprocess tests cover bilingual combined exports, reversed
source order, later case/triage changes, missing original workspaces, manual snapshots,
future domain/renderer retrieve-only behavior, publication rollback, omitted archive
snapshots, optional export-file restoration and re-archiving. All-workspace
CLI-feature Clippy passed with warnings denied; formatting, 112 CI contracts,
frozen report baseline verification and host skill-copy synchronization passed.
The baseline corpus was not regenerated. These are Linux checks with saved synthetic
cases; native desktop and Windows/macOS execution remain unverified for this change.
Use the same regression commands recorded in the terminal-run milestone below.

## November 9 automatic terminal-run snapshots

The shared service now freezes private HTML/JSON reports when scan results and
cleanup have settled. The coordinator invokes it for ordinary terminal workers,
zero-check admission outcomes and desktop cancellation cleanup; the foreground
owner also finalizes reports after captured-result or cleanup-only recovery.
The synchronous desktop Cancel path schedules report rendering on its tracked
background finisher. Pending evidence or cleanup stays in Progress.

`run_report_snapshots` retains the exact run outcome, source revision and portable
snapshot reference. The foreground receipt exposes `result.report_snapshot`, and
read-only status lists the saved records. Automatic views use English, Standard
redaction and no raw attachments. Repeated reconciliation, receipt writes and
later triage retain the same original. A changed recovered outcome appends a new
snapshot. Run hashes sort JSON objects independently of desktop/CLI serializer
features; archive verification hashes the frozen run without reserializing it
through the current domain.

Failed snapshot publication leaves findings intact and rolls back newly created
files if history cannot commit. The CLI reports `terminal_report_snapshot_failed`
and supplies a report-only `scan recover` command when the record is absent.
Retrying does not detect a runtime or start a new scan. Previously recorded
originals that are missing or corrupt are rejected rather than regenerated.
Legacy status reads remain read-only; explicit recovery can only freeze currently
available context with its actual creation time. Demo and archived cases remain
immutable.

Archives automatically retain all terminal originals and validate their recorded
run bindings. A manifest that removes a referenced snapshot is rejected even if
its transport hashes are internally consistent. After moving away the original
workspace, restored report retrieval and exact-compatible replay preserve the
same HTML/JSON bytes. Report exports omit private snapshot storage references.

Linux validation passed 2,171 Rust tests: 1,611 core unit, 74 CLI unit, 438
standalone engine/domain, 14 foreground subprocess, ten archive, ten report
snapshot, six read-only status and eight report-fidelity tests; two explicit
output generators stayed ignored. Tests cover completed/failed siblings,
cancellation, no-check requests, pending cleanup, captured recovery, storage
failure/retry without runtime contact, idempotency after triage, historical
snapshot corruption and archive omission/restore. All-workspace CLI-feature
Clippy passed with warnings denied, along with formatting, 112 CI contracts,
frozen baseline verification and skill-copy synchronization. No baseline bytes
were regenerated. These checks use Linux synthetic fixtures; native desktop,
Windows/macOS execution, combined snapshots and Cloudflare remained separate work
at that milestone.
The published default was not changed.

```sh
cargo test --locked -p ai-security-scanner --no-default-features --features cli \
  --lib --bin ai-security-scanner-cli --test engine_execution \
  --test cli_foreground_scan --test cli_report_snapshot --test cli_case_archive \
  --test cli_read_only_status --test report_fidelity_baseline
cargo clippy --locked --workspace --no-default-features --features cli --all-targets -- -D warnings
node --test tests/ci/*.test.mjs
node scripts/verify-report-fidelity-baseline.mjs
node scripts/skill/sync-skill.mjs --check
```

## November 9 automatic export snapshots

Single-run HTML and canonical JSON exports now preserve a private snapshot in
`artifacts/CASE_ID/report-snapshots/`. The shared desktop/CLI export service
renders once from frozen context and uses those exact bytes for the selected
output. Export history records the snapshot identity, source revision, relative
path, length and digest. Each later export records a new context without
rewriting prior snapshots; historical exports without references stay unchanged.

The snapshot is local private data, even when the shared report uses Standard
redaction. Original attachments follow the existing explicit selection and
redaction policy. Publication failure, occupied destinations or an export-history
write failure remove newly created files from that attempt. Existing user files
are preserved. A crash before history commit can leave an unreferenced local
file; no successful export is inferred from its presence.

Complete archives automatically include all recorded export snapshots, even when
external export files were not selected. Archive verification binds each snapshot
to its recorded export document, case/run, redaction, source revision and exact
bytes. Restore keeps the relative references under the new workspace. Missing or
corrupt recorded snapshots reject archive creation or restoration. The current
archive-time default views and separately selected manual snapshots remain
available.

The added subprocess tests cover exact bilingual report bytes, retained private
context after case/triage changes, publication rollback, and automatic archive
preservation without extra snapshot flags. After the original workspace and
shared files are removed or moved away, restored HTML/JSON retrieval and replay
match the original bytes, including selected HTML attachments. A second archive
from the restored workspace also retains the references. Removing a historical
snapshot from an otherwise internally consistent archive is rejected.

Linux validation passed 2,153 Rust tests: 1,611 core unit, 74 CLI unit, 438
standalone engine/domain, nine archive, seven report-snapshot, six read-only
status and eight report-fidelity tests; two explicit output generators remained
ignored. CLI-feature Clippy across all workspace targets passed with warnings
denied. Formatting, all 112 CI contracts, frozen baseline verification and
canonical host-skill synchronization passed. The fixed report outputs and
baseline corpus were preserved.

At that milestone, run-completion snapshots, combined snapshots and Cloudflare
remained pending. No
scanner behavior, public default entry, installer or release changed. This batch
uses synthetic saved cases on Linux; Windows/macOS native execution remains a
separate acceptance item. Reproduce the focused regression checks with:

```sh
cargo test --locked -p ai-security-scanner --no-default-features --features cli \
  --lib --bin ai-security-scanner-cli --test engine_execution \
  --test cli_report_snapshot --test cli_case_archive \
  --test cli_read_only_status --test report_fidelity_baseline
cargo clippy --locked --workspace --no-default-features --features cli --all-targets -- -D warnings
node --test tests/ci/*.test.mjs
node scripts/verify-report-fidelity-baseline.mjs
```

## November 8 report preservation implementation

The [baseline corpus](../tests/fixtures/report-fidelity/README.md) was generated from the recorded original core before renderer extraction. It contains two frozen cases using all 25 adapter fixtures, 26 document snapshots, 36 signed-bundle payload hashes and 20 Chromium screenshots. Mixed terminal outcomes preserve completed siblings. This is fixture execution, not a scan of a live target.

The shared renderer preserves the original HTML and canonical JSON implementation. A report snapshot retains its complete private case context, settings, selected attachment ZIPs and exact original HTML/JSON. It can replay without the original database, workspace, runtime or model service. Replay requires the exact compiled renderer/source identity and byte equality; an unavailable renderer permits original-file retrieval only. This manual single-run snapshot is not a restorable case archive and does not modify export history.

Local Linux checks used Rust 1.98.0 with `--locked --no-default-features --features cli`: 1,506 core unit tests (including seven new snapshot cases), 70 CLI unit tests, six read-only status tests, five CLI snapshot subprocess tests and eight report-fidelity integration tests passed (1,595 total; two explicit output generators ignored). Coverage includes live-owner WAL reads, no migration or workspace creation, changed source/triage, deleted original data, exact attachment bytes, Standard attachment selection, future renderer/domain/report shapes, corrupt hashes and refusal to overwrite. The baseline verifier passed; 120 report-related frontend tests and all 106 CI contract tests passed. Formatting and Clippy with warnings denied also passed; the CI path classifier now schedules report replay when its frozen corpus changes, and verifies corpus receipts on every run. Commands for reproducing the report baseline are in its README; this is source validation, not three-platform migration or archive/restore acceptance. The current local environment lacks GTK/WebKit development packages, so no desktop compilation or desktop execution is claimed for this batch.

## November 8 private case archive implementation

The development CLI adds `archive create`, `verify`, `restore-preview` and
`restore`. The existing `case archive` lifecycle command and signed report bundle
retain their meanings. A new private package preserves the original persisted
case bytes, every current domain field, ordered event history, all recorded raw
evidence and frozen terminal report snapshots. Retained source snapshots and
previous export files are separate explicit selections. Missing selected data,
unresolved historical source references and incompatible case fields fail closed.

Restore creates a new workspace through private same-filesystem staging and a
no-replace atomic publish, with the intent and receipt saved before publication.
It preserves historical identity and evidence while disabling current grants,
owner confirmations, source capabilities and continuation tokens. The original
DTO remains intact. The package proves internal byte consistency, not producer
identity; it does not introduce archive signing or import private signing keys.
The [archive guide](case-archives.md) records limits, omissions and retry behavior.
Windows/macOS execution and the complete skill-to-restore flow remain unverified.

Linux validation with Rust 1.98.0 and `--locked --no-default-features --features cli`
passed 1,544 core unit tests, 70 CLI unit tests, seven archive CLI integration
tests, six status tests, five snapshot CLI tests and eight report-fidelity tests
(1,640 total; two explicit output generators ignored). Archive checks cover
source removal, held source leases, complete DTO/event/blob retention, source
history omissions, unknown fields, corrupt packages, directory expansion limits,
private staging, unsafe destination parents, interruption before/after publish
and unchanged-workspace retries. All 106 CI contracts and the frozen baseline
verifier passed. No new UI or scanner execution behavior changed in this batch.
Formatting and Clippy with warnings denied passed for the same Rust targets.

Reproduce the Rust checks with:

```sh
cargo test --locked -p ai-security-scanner --no-default-features --features cli \
  --lib --bin ai-security-scanner-cli --test cli_case_archive \
  --test cli_read_only_status --test cli_report_snapshot --test report_fidelity_baseline
```

## November 8 shared foreground execution

The development CLI adds `scan run --wait` and `scan recover --wait` through the
same coordinator, workers and upstream adapters used by the desktop. The CLI
owns and joins its exact worker generation and runtime preparers, reconciles the
saved outcome, then commits a versioned command receipt. JSON provides a terminal
envelope; NDJSON adds progress events. Signals and failed or blocked output
request cancellation without abandoning execution ownership. Cancellation still
waits for underlying runtime operations to settle.

All CLI paths using writable initialization now acquire the data-directory
writer lease. Read-only status stays available alongside a live owner and checks
that the case and its command receipts share one observed revision. Receipts
survive reopen and case archive/restore. If only final delivery fails, the CLI
exits 4 while the already committed receipt remains available through status.

Recovery selects one exact saved run, validates checkpoint identity before
mutation, cleans only recorded resources and reparses verified captured bytes.
It preserves completed or failed siblings, refuses new target-facing attempts
and prevents automatic Naabu continuation. Damaged evidence retains its failed
outcome and checkpoint without suggesting an immediate retry. See the
[foreground guide](foreground-scans.md) for commands and exit codes.

Linux validation with Rust 1.98.0 and locked dependencies passed 1,597 core unit
tests, 73 CLI unit tests, 25 job-manager tests, nine foreground subprocess tests,
seven archive tests, six status tests, five snapshot tests and eight report
fidelity tests (1,730 total; two explicit output generators ignored). Foreground
checks cover SIGINT/SIGTERM, writer contention, broken and unread stdout,
immutable receipts after final-delivery failure, preserved sibling failures,
captured recovery without the source or runtime, interrupted capture and
altered-evidence refusal. All 106 CI contracts, the frozen report baseline,
formatting and CLI-feature Clippy across all workspace targets with warnings
denied passed.
The separate egress-gateway configuration also passed all-target Clippy with
warnings denied and its 20 binary tests.

These are Linux source and fixture checks. The subprocess suite uses a controlled
local runtime executable with the real orchestrator and Gitleaks adapter; it does
not establish execution with a pinned upstream scanner image. Desktop/pinned
scanner comparison, Windows/macOS execution and the complete skill-to-restore
flow remain pending. A desktop `cargo check` stopped in `libdbus-sys` because
`dbus-1` development files are absent; GTK/WebKit development files are also
unavailable. Desktop compilation and execution are therefore unverified here.

Reproduce the foreground and preservation regression checks with:

```sh
cargo test --locked -p ai-security-scanner --no-default-features --features cli \
  --lib --bin ai-security-scanner-cli --test job_manager --test cli_foreground_scan \
  --test cli_case_archive --test cli_read_only_status \
  --test cli_report_snapshot --test report_fidelity_baseline
cargo clippy --locked --workspace --no-default-features --features cli --all-targets -- -D warnings
cargo fmt --all --check
cargo clippy --locked --workspace --no-default-features --features egress-gateway --all-targets -- -D warnings
cargo test --locked --workspace --no-default-features --features egress-gateway --bin ai-security-scanner-egress-gateway
node --test tests/ci/*.test.mjs
node scripts/verify-report-fidelity-baseline.mjs
```

## November 8 pinned core bootstrap and skill entry

`scripts/skill/bootstrap.mjs` now provides `doctor`, `prepare` and `run` for the
trusted product checkout at an explicit full Git revision. It stages controlled
build inputs, uses Rust 1.98.0 and the native compiler, and produces a CLI-only
cache with a versioned receipt. Reuse verifies the receipt, executable hash and
compiled identity. Prompt-only changes can reuse the core; changed embedded
inputs or recipes cannot. Failed builds preserve the previous ready entry.
Development changes require `--allow-dirty` and retain their actual input digest.
The new `build-identity` CLI path does not initialize case or runtime state.

The canonical skill is now `skills/ai-security-scanner/`. A checked synchronizer
produces both host copies, including their relative documentation links. The
development route uses the bootstrap; normal operator use still starts with the
released desktop. Forwarded stateful commands require an explicit data directory.
See the [bootstrap guide](skill-bootstrap.md) for the implemented commands.

CI now distinguishes skill wording/contracts, native core inputs and installer
inputs. New Linux, macOS and Windows lanes build and execute the native bootstrap,
reuse its cache, replay saved reports, and test archive round trips. Windows
runtime validation remains; its NSIS step runs only for installer changes.
These lanes do not establish platform execution until their results are observed.

Linux x86_64 validation used Node 24.22.1 and Rust 1.98.0 with pre-existing Cargo
dependencies and `--offline`. Fresh dev and default release builds completed;
each second prepare reused its verified cache, and the cached CLI created a synthetic demo
report snapshot. After deleting that synthetic workspace, retrieved and replayed
HTML/JSON matched byte for byte without recreating the workspace. No target was
contacted and no scanner runtime or image was downloaded. The build receipt
records the base revision and explicitly dirty development input digest;
the [bootstrap validation record](skill-bootstrap.md#observed-local-validation)
preserves the exact identities.

The targeted Rust checks passed 73 CLI unit tests, one build-identity subprocess
test, seven archive tests, five snapshot tests and eight report-fidelity tests
(94 distinct tests; two explicit output generators ignored). CLI-feature
Clippy across all workspace targets passed with warnings denied; formatting passed.
All 38 portable Node skill/bootstrap tests passed; the additional real Windows
ACL test is explicitly skipped on Linux and scheduled on the Windows native lane.
All 112 CI contract tests, canonical skill validation, and host-copy synchronization
checks passed. Windows cache admission now verifies owners and ACLs, rejecting
foreign access, unsafe ancestors and unverifiable permissions before using code.

Per-engine runtime preparation, Cloudflare orchestration, Windows/macOS native
execution and the complete skill-to-restore journey remain pending. Core
preparation explicitly reports scan preparation as unavailable. The default
operator entry has not switched, and this work does not require a new installer
or release publication.

Reproduce the native smoke with an exact committed checkout, or explicitly add
`--allow-dirty` for development inputs:

```sh
node scripts/ci/skill-bootstrap-smoke.mjs --offline --allow-dirty
node scripts/ci/skill-bootstrap-smoke.mjs --offline --allow-dirty --release
node --test tests/skill/*.test.mjs
node --test tests/ci/*.test.mjs
node scripts/skill/sync-skill.mjs --check
cargo test --locked -p ai-security-scanner --no-default-features --features cli \
  --bin ai-security-scanner-cli --test cli_build_identity \
  --test cli_case_archive --test cli_report_snapshot --test report_fidelity_baseline
```

## At a glance

- [v0.6.2 Windows website scan fix](release/v0.6.2.md) is the current stable/latest release for Windows, macOS and Linux. It fixes starting Page response checks (ZAP) on Windows and includes the v0.6.1 security update; the release record lists the observed verification.

- [v0.6.1 security update](release/v0.6.1.md) is the preceding stable release for Windows, macOS and Linux. Update before scanning a repository you did not create; the release record links the advisory and records the changes and observed verification.

- [v0.6.0 upstream and runtime refresh](release/v0.6.0.md) is an earlier stable release for Windows, macOS and Linux. All 25 engines were reviewed; eighteen managed images, KICS, offline data, the private runtime and application dependencies are updated. Exact delivery and platform limits are recorded with the release.

- [v0.5.3 October 21 incident scan pack](release/v0.5.3.md) is an earlier stable release for Windows, macOS and Linux. Standard and focused incident checks share the actionable HTML / JSON report with ISO and NIST references. Trivy databases, Nuclei templates and Vite development tooling are updated; public artifacts and platform observations are recorded with the release.

- [v0.5.2 upstream engine updates](release/v0.5.2.md) is an earlier stable release for Windows, macOS and Linux. It updates ten engines and offline data and repairs bounded Windows runtime execution on recent WSL. Public bytes, updater signatures, source provenance, exact-source CI and CodeQL passed; installer observations and limitations are in the release record.

- The earlier stable release, [v0.4.1](release/v0.4.1.md), retains its original installer and updater observations.
- The released desktop includes Prowler failure headlines, approved AWS report grouping, reconnect-and-rescan, blocked-scan continuations, Semgrep `1.184.0-1`, and explicit kube-bench/KICS incomplete-coverage handling.
- A fresh owner-signed-in Microsoft 365 live rerun remains unobserved. Garak model checks and Agentic Radar offline inventory are optionally dispatchable in v0.4.0.
- The paired repository [Agent Skills](getting-started.md#use-with-an-agent-skill) install the
  desktop release, check that a computer can scan, guide a scan in the app, and save its report;
  the Linux source build is documented there for changing the product.
- The engine catalog contains 25 records: 25 integrated, runnable engines and 0 experimental
  integrations that remain non-runnable.
- Repository, website/API, infrastructure, cloud, Microsoft 365, and Kubernetes paths use bounded
  upstream checks and feed one product-owned report.
- Report presentation distinguishes measured zero findings from an asset that was not measured, and
  keeps compact document identity in printed headers and footers.
- The v0.4.0 shared HTML exporter contains wide check tables within their scroll areas, stacks report cards at tablet widths, and wraps long technical identifiers. The original v0.3.1 observations remain in its historical release record.
- v0.4.0 also recognizes the native `microsoft365` provider value when displaying identity assets, so they retain their Microsoft 365 platform instead of appearing as public websites and IP addresses. A fresh owner-signed-in live Microsoft 365 rerun remains unobserved.
- The offline adapter refresh pipeline produces reviewable proposals; deterministic generation is the
  default, AI edits require explicit opt-in and digest attribution, and the person running it chooses
  whether to open a pull request while the pipeline executes no commands.
- Native report, case, coverage, route, permission, and engine-task vocabularies are bound to their Rust
  wire contracts; unknown permissions and tasks cannot claim authorization, execution, or coverage.
- No owner or hosted model-provider endpoint was contacted during development; Garak native QA used owned TLS fixtures.

**v0.4.1 stable** adds optional original scanner ZIP attachments to English and Traditional Chinese HTML reports, clearer results, temporary credential-file cleanup on failed creation, and recorded AWS/Microsoft 365 access cleanup helpers. Exact delivery and limitations are in the [release record](release/v0.4.1.md).

**v0.4.0 stable** delivers the owner-selected result-integrity work, engine build/patch maintenance and optional integrations. Result-integrity work now separates Greenbone tasks by exact grant, freezes task grant membership for resume, rejects malformed or unevaluated Kubescape output as complete coverage, and streams large reports within the 512 MiB evidence budget. These changes are included in v0.4.0. The Gitleaks fixture rebuild and complete recipe/patch audit are finished. ZAP now has an explicit passive website choice, per-grant dispatch and native per-request pacing; Agentic Radar is published and optionally dispatchable offline; Garak is published and optionally dispatchable with exact HTTPS/model consent and a one-shot local key; v0.4.0 is published; exact source, frozen artifact selectors, installer observations and anonymous public-byte verification are in the [delivery record](release/v0.4.0.md).

## AI integration work

| Integration | Implemented | Current fail-closed boundary |
| --- | --- | --- |
| Garak | Exact HTTPS/model input, one-shot local key, bounded native REST execution and four preserved detector counts are implemented; six controlled TLS scenarios passed locally. | Published, digest-pinned and optionally dispatchable on main. Both anonymous platform bytes and signed source evidence are verified; six native TLS cases passed again by public amd64 digest. No arm64 native run is claimed. |
| Agentic Radar | The dedicated offline image, typed framework selection and native static graph contract are implemented. Controlled amd64 runs cover all five frameworks, empty input and environment/target-code isolation. CrewAI diagnostics remain incomplete inventory; graphs never become vulnerability findings. | Published, digest-pinned and optionally dispatchable offline in v0.4.0. Both anonymous platform bytes and signed source evidence are verified. The audited machine-output exception remains unsent. |
| MCP Armor | One exact MCP configuration file can be selected from an immutable repository snapshot and checked by a restricted, model-free configuration launcher. The local image produced a complete two-check report and an excessive-permission finding from a synthetic fixture with networking disabled. | The image is published, digest-pinned, and dispatchable, but not default-enabled. It runs with networking disabled over one approved MCP configuration snapshot; it does not start or contact an MCP server or load a model. |
| Augustus | Research-only, pure-data 14-rule preflight contracts and rejection fixtures define the required endpoint, cost, request, deadline, sandbox, and output boundaries. | No production catalog entry, adapter, launcher, provider connection, credential path, or dispatch path exists yet. |

Garak is explicitly selected per model-check run; ordinary rescans omit it. Agentic Radar has a verified published digest and an optional immutable-snapshot framework path. Research artifacts and local image identifiers alone do not establish dispatch.

## Other experimental engine integrations

Not every experimental record is an AI integration. A verified upstream artifact can exist before the
product is able to dispatch it; the catalog blockers, not the artifact, decide whether a record is a
current scan capability.

| Integration | Implemented | Current fail-closed boundary |
| --- | --- | --- |
| ZAP | The reviewed `zap_passive_v1` profile derives a passive-only plan from one exact frozen grant. Native network add-on 0.29.0 paces every HTTP request, including keep-alive requests, at 5/s with five spider threads and a 10-second request timeout. The orchestrator mounts and hashes the private plan, and saves its digest for recovery and cleanup. Website Advanced and mixed-environment website settings explicitly select it; Nuclei remains the default. | Dispatchable in v0.4.0. Crawl is bounded to two minutes, depth five and 100 children per page; response processing is bounded to two minutes. No authentication, form submission, active attack jobs or other origins. Empty unobserved-site reports are incomplete. |

## Grype repository scan

A historical controlled Linux repository scan using Grype `0.117.0-4` recorded 81 Grype
findings (10 critical, 32 high, 33 medium, 6 low), with Grype completed and exit code 0. The full run
recorded 192 findings, 8 completed checks, and 2 not executed: Agentic Radar had no runnable release,
and MCP Armor had no selected MCP configuration. These are results for that fixture, not promised
counts for other repositories. See [the exact pin and recorded result](engine-catalog.md#grype-repository-support).

## Recorded verification baseline

The October 4 Garak admission and v0.4.0 source checks passed 2,114 Rust tests, 527 component tests, 91 CI contracts and 203 release contracts. A case audit using saved fixtures verifies all 25 engine report paths; exact model coordinates and native counts survive case save/reopen and bilingual exports. The feature-source frontend CI passed 806 tests without skips; the final release-copy source CI passed separately. Both public platform bytes and source/SBOM signatures, six native amd64 TLS cases, formatting, Clippy and the production build were verified. Installer delivery remains a separate observation.

The October 4 Agentic Radar integration passed 2,097 Rust tests, 798 frontend tests (six explicit skips), 522 component tests, 91 CI contracts and 19 publication-verifier tests, plus formatting, Clippy, desktop compile and the production build. Seven native offline cases passed again using the published amd64 image; both platform bytes, source-bound signatures and four SBOMs were independently verified. Inventory never becomes a security result.

The October 4 ZAP integration passed 2,092 Rust tests, 798 frontend tests (six explicit skips), 518 component tests, formatting, Clippy, and the production build. Controlled native amd64 scans verified frozen hostname resolution, origin boundaries, keep-alive request pacing and cancellation; the report regression preserves all native alert instances. This verifies the current source and controlled fixtures, not a published v0.4.0 installer.

The October 3 source-readiness audit recorded 2,072 passing Rust tests, 798 frontend tests (six explicit skips), 515 component tests, 89 CI contracts and 202 release contracts. Formatting, Clippy, production build, engine admission and release identity passed. The v0.3.1 preparation also passed the full release self-test and the three gateway identity/security tests. Exact installer observations are recorded separately in [v0.3.1](release/v0.3.1.md); source tests do not substitute for installation or human-path evidence.


The following test counts are the successful local baseline recorded on September 19, 2026; they
are not a new test run for this documentation update:

- Rust core and CLI: 1,752 tests.
- Frontend unit tests: 696 tests.
- Component rendering: 322 tests across 20 files.
- CI document and contract tests: 81 tests.
- Engine catalog validation: 8 tests.
- TypeScript type checking, Rust formatting, and Clippy: passed.

CI document and contract tests: 83 tests passed on September 20, 2026, including the adapter refresh
CLI missing-value regression (`node --test tests/ci/*.test.mjs`).

CI document and contract tests: 84 tests passed on September 21, 2026 (`node --test tests/ci/*.test.mjs`),
including the beginner HTML locale contract and the published MCP Armor distribution decision.

CI document and contract tests: 89 tests include four scoped engine-publication selection checks
added on October 3, 2026. Two workflow checks run in the release-contract suite after dependency
installation. Native Semgrep image verification runs separately before publication.

CI document and contract tests: 85 tests passed on October 1, 2026 (`node --test tests/ci/*.test.mjs`),
including the check that the gateway image's startup smoke expects the status schema the gateway writes.

After removing credential-shaped text from an upstream test fixture, the MCP Armor image was rebuilt,
published, and pinned. Its offline synthetic smoke test produced one finding, two completed checks, no
warning, and `complete: true` under `network=none`.

## Current blockers

- No catalog release blockers remain. The owner-signed-in Microsoft 365 rerun and disclosed platform observations remain separate follow-ups.

These blockers describe fail-closed admission state; they do not authorize a publication or release
plan. Publication, packaging, signing, versioning, and compliance posture remain product-owner
decisions.
Real endpoint scans require explicit scope and must never infer authorization or accept credentials
through chat or command arguments.

## Supporting records

- [Engine catalog](engine-catalog.md)
- [MCP Armor research decision](research/mcp-armor-evaluation.md)
- [Agentic Radar research decision](research/agentic-radar-evaluation.md)
- [Augustus research decision](research/augustus-evaluation.md)
- [Product doctrine](PRODUCT-DOCTRINE.md)

CI document and contract tests: 91 tests now include exact old-image/new-candidate separation and rejection of executable inputs hidden in publication history. Engine maintenance records actual hashes for the former uncovered baseline, reviews six downstream exception families and has verified the fresh Gitleaks native amd64 recipe and redacted synthetic scan. Signed Gitleaks `8.30.1-2` is now published and catalog-pinned, after verifying anonymous access, exact source/workflow provenance and both platform SBOM attestations.

CI document and contract tests: 94 tests now include the two publication origins, refusal of mixed origins, and numeric repository ID checks.

CI document and contract tests: 97 tests include upstream replacement metadata checks. The October 14 source update keeps the published catalog intact while validating new engine recipes; candidate metadata cannot change scan permissions or conceal executable build inputs. See the [upstream update record](engines/updates/2026-10-14.md) for versions and verification.

CI document and contract tests: 102 tests include rejection of substituted Windows runtime source, patches, toolchains and nonreproducible build settings. The [Windows runtime source record](../runtime/podman-wsl-native-systemd.md) describes the native systemd backport and its locked build inputs.
