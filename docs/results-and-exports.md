# Read and share your results

[繁體中文](results-and-exports.zh-TW.md) · [Documentation](README.md)

When a scan finishes or stops, open **Results**. Start with the summary: which systems or files need attention, what matters first and what to do next. While a scan is running, follow it in **Scan progress**.

An admitted source audit appears in **Results** with confirmed findings, a separate **To validate** list, remaining units and continuation paths, and collapsed method, evidence and provenance details. Candidates do not count as problems. The desktop offers single-run HTML and JSON, combined reports, framework reports, OCSF, OSCAL and signed case bundles. Single-run and combined HTML can include original source audit files.

## Understand each result

| What the report says | What it means |
| --- | --- |
| Problems found | A security check found at least one issue affecting this item. Open it to see the evidence and suggested next step. |
| No problems in completed checks | The checks that finished found no problems within their stated scope. This does not rule out every possible risk. |
| Incomplete or failed | Some requested checks did not finish. Results from completed checks are still available. |
| Not tested | No applicable security check finished for this item. |

The report may also list services, open ports or installed software. These help describe what you have; they are not counted as vulnerabilities.

## Decide what to do first

Read the highest-priority problems first. For each one, the report explains what is affected, why it matters and a practical next step. When available, it also explains how to verify a fix or undo a change.

If someone else will investigate, expand the technical details. They contain the original scanner, rule number, evidence, severity rating and recommendation. “Unknown” means the tool did not provide a severity rating; it does not mean the problem is minor.

The app provides guidance. It does not apply fixes to your systems.

## Check what is still missing

Look at **What was actually tested** and **What was not tested**. A report can contain useful findings even when some work is unfinished. A successful connection or a list of systems does not mean a security check ran.

For unfinished checks, follow the next step shown in the app. Some need a new sign-in or different input before they can run.

## Return later and compare

Open **My scans** to return to a project. Its targets, findings, evidence and report history stay available. Select the scan you want before reading or exporting the report.

When two scans can be compared, the app shows which problems are new, still present or resolved. It marks results that cannot be compared, so missing coverage is not mistaken for a fix.

## Save a report to share

From **Results**, choose **Save or share report**, then **HTML report (recommended)**. Keep sensitive identifiers hidden unless the recipient needs them. Save the file and open it in a browser to check it before sharing.

The report uses the app language, English or Traditional Chinese. It follows the same order as the screen. Technical evidence is available in expandable sections, with formal terms at the end. Saving the report creates a local file; it does not send it to anyone.

To keep the original reports in that same HTML file, turn off **Hide sensitive identifiers** and select **Attach original reports at the end**. The final section offers one ZIP per scanner check. Download and extract the entire ZIP to open its original reports with their images and other supporting files. Tools that did not produce an HTML report may have JSON, XML or logs instead; unfinished checks keep their recorded status. Original files may contain sensitive information.

Keep the HTML when sharing attachments: printing or saving it as a PDF does not include them. The HTML attachment limit is 64 MiB of original files or 10,000 files; use a technical case bundle for larger collections.

<details>
<summary>Formats for technical teams</summary>

- JSON keeps the product's structured report data.
- OCSF provides findings in a common security-data format.
- OSCAL and framework reports include reviewed control references where a mapping exists.
- A case bundle contains the selected project data and evidence allowed by its export options.

All formats use the same finished or stopped scan. SHA-256 hashes identify the exported files. CLI HTML exports use English by default; choose `--locale en` for English or `--locale zh-Hant` for Traditional Chinese. The scan facts remain the same.

</details>

## Development preservation and restore

The unreleased development core adds [automatic terminal/export report snapshots and offline retrieval/replay](report-snapshots.md), combined original-file downloads and [private case archive/restore](case-archives.md). Archive restore preserves the existing case domain and does not restore permission to scan. Original attachments and private archives require the documented explicit sensitive-data choice.

Admitted [Cloudflare source audits](cloudflare-provider.md#admitting-a-sealed-audit) now appear in single-run and combined HTML/JSON reports and saved snapshots. Confirmed findings stay in the asset and priority lists with the narrative selected by the redaction profile. **To validate** lists leads without severity or vulnerability counts; **What was not tested** gives uncovered units and continuation paths. When an audit has To validate records, the first layer names them as a next step: first when nothing else was found, otherwise after the main action. An asset with no problems in its completed checks but with such records shows the next action “validate the listed source-audit items first”. An incomplete audit keeps its completed findings. The first layer names the method “Cloudflare source audit” (“Cloudflare 原始碼稽核” in Traditional Chinese); each audit has one aggregated remaining-units gap without an extra Not tested count, and one excluded gap when units are outside scope. Remaining units share one next step: "Continue the source audit from the listed paths." Standard keeps this product sentence; continuation paths stay under **What was not tested** and in technical detail, with location markers in Standard. English and Traditional Chinese labels do not translate provider text. Expand technical details for method, issued invocations, role/state counts, attempts, lineage and original-file digests.

Standard redaction applies the shared masking policy to provider prose, trace and evidence descriptions, remediation, ledger text and incomplete reasons, with separate withheld-text and withheld-code counts. Provider files, paths, source scope and source references use the location marker; titles replace known private literals. Standard replaces provider coverage identifiers with `unit-` and provider fingerprints with `fp-`, followed by the first twelve lowercase hexadecimal characters of the original value’s SHA-256; product-generated identities, timestamps, enums, scores and digests remain unchanged. Confirmed findings use the localized SourceCode family summary, impact and action in Standard. The `none` profile preserves native text and code verbatim. Admission saves a terminal snapshot; if saving fails, the committed audit remains available and the admit response supplies the replay command.

Framework reports now include the profile-redacted shared `source_audits` extension: identity, method, outcome, counts, To validate records, gaps and technical provenance. Audit tasks are excluded from scanner counts and engine-state lists. Confirmed audit observations use `source_audit_not_mapped`: source audit findings are intentionally not mapped to framework controls.

OCSF exports confirmed audit findings as Detection Finding events; OSCAL exports them as observations with `EXAMINE`. OCSF adds provider identity under `unmapped.ai_security_scanner.source_audit`; OSCAL adds namespaced `source-audit-*` properties on the observation and its evidence. These carry provider/admission IDs, native fingerprint, record digest/index, the admitted confirmed verdict, method label and upstream commit. This identity is not human confirmation, a compliance result or a control conclusion. Human workflow status is unchanged. Needs-validation, rejected and candidate records never become events or observations. The mandatory hash-bound OCSF/OSCAL companion keeps the shared audit report, including leads, gaps, method and outcome when there are zero confirmed findings. Keep the companion with the main file.

Both profiles preserve IDs, enums and digests. Standard uses the shared redaction above, including identical `fp-` pseudonyms for unresolved fingerprint lists. Derived gap labels and identifier masks do not increase withheld-text counts; those counts cover only provider prose or code actually withheld. `none` retains native values. Missing or mismatched admission/task/artifact bindings refuse export before files are written.

Signed case bundles include a case-wide `source-audit-admissions.json` when the case has admissions, even when the selected report is a scanner run. It preserves retained projections, artifact bindings and explicit provider task provenance. Standard withholds provider prose/code with counts, uses location markers and `unit-`/`fp-` pseudonyms, and retains identities and digests; `none` retains native values. Admission and native digests commit to the original material; the signed manifest separately hashes the exported document. The bundle's framework `source_audits` equals its shared report's extension, including withheld counts. Provider tasks appear separately from catalog engine versions and product-owned built-in tasks. The new document and schema entry are absent from bundles of cases without admissions.

Single-run and combined HTML attachments preserve exact original bytes and nested member names in downloadable ZIPs. Audit ZIP manifests name the provider, admission and “Cloudflare source audit” method, with original digests and per-file hashes; each ZIP also has its own hash. Combined downloads retain run/task namespaces. Originals are included only with profile `none` and the explicit raw-artifact choice. Standard always omits every provider original, even when raw artifacts are requested, counts them as sensitive omissions, and does not read their bytes. No sanitized copies are generated. Missing, changed or mismatched originals refuse unmasked attachment or bundle exports. Export preview counts source audit tasks separately from scanner engine jobs.

Attachments retain the 64 MiB / 10,000-file limits; combined reports apply those limits across the selection and also bound the encoded HTML/JSON documents. If limits are exceeded, an explicitly acknowledged private complete archive preserves originals for both admitted cases and scanner-only cases. Complete archives can be created, verified and restored as read-only history; comparisons involving audits remain unavailable. See [snapshot behavior](report-snapshots.md#admitted-source-audits) and [release definitions and current availability](release-model.md).


### Source audits that did not finish

Blocked preparation appears as a not-executed **Cloudflare source audit** check:
“The Cloudflare source audit did not start.” A terminated audit appears as failed:
“The Cloudflare source audit ended before completion.” Each row includes one typed
reason and a next action. For example, an interrupted audit says “The audit was
interrupted.” and “Start a new source audit.”

Each failure has exactly one asset-bound gap: “No source audit was performed for
this asset.” for blocked preparation, or “The source audit ended before completion;
no audit results are available for this asset.” for termination. These checks add
no tested dimensions, completed coverage, findings or validation leads. Technical
detail contains codes, custody times and digests, run/task IDs and recorded counts;
Standard redaction applies. Combined reports preserve each selected run and asset.

Framework reports count these as incomplete checks without creating control
verdicts or findings. OCSF and OSCAL create no observations for them; their required
coverage companions carry the shared report rows. Case bundles retain their runs
and tasks, and export previews do not count them as scanner engine jobs. Scanner
resume, recovery, rescan, cleanup and check-fix work exclude these tasks; comparisons
involving them remain unavailable. Desktop Results show the same outcome, reason, next action and asset gap, with outcome-first technical details under “Source audit”. Both endings are selectable in combined reports, without scanner recovery or Check fixes controls.
