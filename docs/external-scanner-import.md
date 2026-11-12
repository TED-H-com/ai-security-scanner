# External AI scanner evidence

Strix findings can be imported into an existing project's unified report without running Strix. In the project's advanced coverage controls, select the native `vulnerabilities.json`, select one target found in that file, associate it with an existing asset, and import. Imported evidence appears in a new terminal report alongside its original finding IDs, ratings, timestamps, remediation and raw JSON attachment. Scan coverage remains unverified; an import does not produce a clean scan verdict.

The CLI exposes the same boundary:

```sh
ai-security-scanner-cli external-report-preview --report /path/to/vulnerabilities.json --json
ai-security-scanner-cli external-report-import --case-id CASE --asset-id ASSET \
  --report /path/to/vulnerabilities.json --upstream-target '/workspace/app' \
  --source-sha256 SHA256_FROM_PREVIEW --json
```

For independently authorized upstream jobs, an external scheduler can run its jobs and hand their finished report files to one bounded import batch. Preview each report, write the exact asset/target/hash bindings into a local JSON manifest, then run:

```sh
ai-security-scanner-cli external-report-import-batch --case-id CASE --manifest imports.json --json
```

```json
[
  {
    "report_path": "/path/to/vulnerabilities.json",
    "asset_id": "EXISTING_ASSET_ID",
    "upstream_target": "/workspace/app",
    "source_sha256": "SHA256_FROM_PREVIEW"
  }
]
```

This command schedules local report readers. Upstream execution, its authorization, and provider configuration remain outside this product command.

The preview hash binds the import to the exact reviewed bytes. The desktop API can import up to sixteen explicitly selected report/target/asset bindings in one terminal run, with two concurrent bounded file readers. A failed report retains its own failure outcome without removing successful siblings. Every file is limited to 4 MiB and 1,000 findings. Linked files, devices, pipes, excessive JSON depth, duplicate IDs and malformed identities are rejected. Empty files cannot establish which target was checked and cannot imply no vulnerabilities. Reimporting identical findings preserves their canonical identity and prior workflow decision.

Only the explicitly chosen upstream target produces findings for the selected existing asset. Importing never creates a target, scope grant or authorization. The original JSON bytes are retained locally as sensitive evidence. Proof-of-concept scripts, patch proposals, arbitrary attachment paths and URLs are never followed or executed. The normal report displays selected descriptive fields; original evidence is available only through the existing explicit attachment/export controls. The product does not infer a Strix binary version from a report that does not contain one.

## Combine local checks and imported reports

In Export, open **Combine saved scan results** and explicitly select two to sixteen finished reports from the same project. Export one HTML document for reading or JSON for automation. The combined document shows their assets, source times, and coverage limits. The consolidated priority list uses the existing shared report grouping within each source; observations from different source runs remain separate and retain their original evidence, run IDs, and timestamps. Each source retains its own failed or untested checks.

The CLI uses the same projection:

```sh
ai-security-scanner-cli export combine --case-id CASE \
  --run-id LOCAL_RUN_ID,IMPORTED_RUN_ID --format html \
  --destination /path/to/combined-report.html --locale en --json
ai-security-scanner-cli export combine --case-id CASE \
  --run-id LOCAL_RUN_ID --run-id IMPORTED_RUN_ID --format json \
  --destination /path/to/combined-report.json --json
```

Standard redaction is the default; `--redaction none` keeps original identifiers and `--locale zh-Hant` localizes readable HTML. JSON uses `ai-security-scanner.selected-run-report/v1`, embedding each selected source's canonical shared report and an asset/source index. The export receipt contains the selected run IDs and the written file's SHA-256. Existing files are never overwritten. This is a read-only composition: it does not create a scan run, alter saved findings or coverage, add a single-run export history entry, infer current clean status, or infer that a historical finding was fixed. Evidence references are included; sensitive original files remain available through their individual source report exports.

## Upstream integration decisions

| Upstream | Verified interface | Product boundary |
| --- | --- | --- |
| [Anthropic OSS Scanner](https://github.com/anthropics/oss-scanner) | Hosted service enrollment through project configuration and a pull request; findings delivered to the project's contact. The public repository supplies enrollment validation and build checks. | No public local scanning engine or structured findings API was established. The product does not submit enrollment, publish a contact, execute `tools/check`, upload source, or invent a report schema. Hosted service use remains a separate owner choice. |
| [Strix](https://github.com/usestrix/strix) | Autonomous penetration-testing CLI with Docker and an LLM provider. Its native report writer stores `vulnerabilities.json`. | Native report import is available. Live autonomous testing and source execution are excluded from ordinary read-only scans. No provider credentials, model calls or sandbox images are required to import. |

Reviewed source revisions on 2026-10-22:

- OSS Scanner: `7ef7e1fe3147f858e2213693ace698891811e4d5`, [README](https://github.com/anthropics/oss-scanner/blob/7ef7e1fe3147f858e2213693ace698891811e4d5/README.md), [Apache-2.0 license](https://github.com/anthropics/oss-scanner/blob/7ef7e1fe3147f858e2213693ace698891811e4d5/LICENSE). The hosted service has separate [terms](https://red.anthropic.com/oss-scanner/terms).
- Strix: `0f81f40765f0329006a9a7d2eb97513f56743a9b`, [native report writer](https://github.com/usestrix/strix/blob/0f81f40765f0329006a9a7d2eb97513f56743a9b/strix/report/writer.py), [finding fields](https://github.com/usestrix/strix/blob/0f81f40765f0329006a9a7d2eb97513f56743a9b/strix/tools/reporting/tool.py), [Apache-2.0 license](https://github.com/usestrix/strix/blob/0f81f40765f0329006a9a7d2eb97513f56743a9b/LICENSE).

These are source review records, not a claim that either scanner was executed by this integration or packaged as a supported native engine. The bounded concurrent work described above imports local reports; it does not schedule autonomous external scans.
