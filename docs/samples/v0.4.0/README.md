# Standard report examples · v0.4.0

[繁體中文](README.zh-TW.md) · [View on the website](https://ted-h-com.github.io/ai-security-scanner/sample-reports.html)

Published snapshot: **October 4, 2026**, product **v0.4.0**. Two disclosure levels, each in English and Traditional Chinese. These are self-contained HTML files: open in a browser, save or print.

| Edition | English | 繁體中文 |
| --- | --- | --- |
| Redacted | [View](https://ted-h-com.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-en.html) · [Download from GitHub](https://raw.githubusercontent.com/TED-H-com/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-redacted-en.html) | [View](https://ted-h-com.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-zh-TW.html) · [Download from GitHub](https://raw.githubusercontent.com/TED-H-com/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-redacted-zh-TW.html) |
| Fully disclosed | [View](https://ted-h-com.github.io/ai-security-scanner/samples/v0.4.0/sample-report-full-en.html) · [Download from GitHub](https://raw.githubusercontent.com/TED-H-com/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-full-en.html) | [View](https://ted-h-com.github.io/ai-security-scanner/samples/v0.4.0/sample-report-full-zh-TW.html) · [Download from GitHub](https://raw.githubusercontent.com/TED-H-com/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-full-zh-TW.html) |

All **25 adapters** contribute visible results: **62 original findings and 42 inventory observations**. Related findings share 56 problem cards in the standard report. Six tools provide inventory only: CloudQuery, Steampipe, Naabu, httpx, Syft and Agentic Radar. The example includes incomplete checks and retains their completed sibling results. It does not turn inventory into vulnerabilities or claim every check passed.

The scenario and identities are simulated. Inputs use the actual adapter-supported upstream output structures: JSON, JSONL/NDJSON and Greenbone XML. Some are reduced representative fixtures, while others were captured from controlled native runs. ScubaGear and Maester use the integration’s envelopes around native verdicts; MCP Armor and Agentic Radar use documented output patches. This is **not a claim that 25 live scanners ran against a real organization**. No customer data, customer credentials or live target contact was used to generate these reports.

Redacted exports use the product’s `standard` redaction profile. Fully disclosed exports use `none`, retaining fictional asset names, endpoints and account context. Both preserve intrinsic adapter secret masking and exclude raw logs. Findings, priorities, sources and coverage are the same. Full disclosure does not undo secret filtering that happened before export.

## How the examples are produced

1. The [all-engine audit](../../../src-tauri/tests/all_engine_report_audit.rs) supplies upstream-format fixture output through a simulated execution transport. Real production adapters, scope planning, orchestration, persistence and the terminal report model run normally. Synthetic asset/grant IDs and reserved example hostnames bind fixture records to the scenario.
2. The [public sample generator](../../../src-tauri/tests/support/public_sample_reports.rs) marks the saved case as a demo, names the fictional organization and invokes `CaseService.export_case` for both disclosure profiles and languages. Every dispatchable adapter must contribute a finding or inventory observation. It checks identifying-field redaction and secret masking.
3. The [showcase publisher](../../../scripts/build-public-showcase.mjs) adds a visible sample label and a scanner source/purpose appendix. **The standard report body stays byte-for-byte unchanged.** `standardExportSha256` is the original export hash; `sha256` is the downloadable edition’s hash. Stripping the three `public-sample` comment-delimited additions reproduces the original hash. The sample-only appendix is not presented as a feature of the installed v0.4.0 exporter.
4. [manifest.json](manifest.json) records each scanner’s result count, input fixture path/hash, version and each file hash. [SHA256SUMS.txt](SHA256SUMS.txt) verifies the four downloads. Fixture hashes identify the template before scenario substitutions; evidence hashes inside the report identify the ingested bytes after substitution. Execution timestamps and runtime receipts in the sample are simulated, not live-scan evidence.

The report implementation and engine catalog are from the [v0.4.0 source snapshot](https://github.com/TED-H-com/ai-security-scanner/tree/335d0666bdc63eb86e6c8c4cddeae110db893397). The public generator and presentation additions are maintained in this repository. The [scanner guide](../../scanner-guide.md) records source dates, enabled features, exclusions, selection reasons and SWOT for every tool.

## Reproduce and update

From the repository root, choose a new empty local output directory. No container, account login or network scan is required:

```bash
AI_SCANNER_PUBLIC_SAMPLE_DIR=/absolute/path/to/new-empty-directory \
  cargo test -j 4 -p ai-security-scanner --no-default-features --features cli \
  --test all_engine_report_audit public_sample_reports::generate_public_sample_reports \
  -- --ignored --exact --test-threads=4
node scripts/build-public-showcase.mjs --samples /absolute/path/to/new-empty-directory
node scripts/build-public-showcase.mjs --check
node --experimental-strip-types --test tests/frontend/publicShowcase.test.ts
```

A fresh case has new IDs and timestamps, so a new generation is semantically reproducible, not byte-identical. To rebuild the exact published snapshot and guide from checked-in inputs, run `node scripts/build-public-showcase.mjs` without `--samples`; it validates the preserved standard export hashes before applying the sample additions again.

Update narrative text in `docs/scanner-guide.content.json`, reviewed official-source and catalog facts in `docs/scanner-guide.sources.json`, then regenerate. Source commit dates come from the official repositories’ commit metadata; README URLs point to those exact commits. Do not relabel a source commit date as an upstream release date, or a catalog baseline date as the date of every database. Recheck the corresponding `docs/engines/<id>.md` and actual launcher/profile before changing enabled-feature claims. Keep the English and Traditional Chinese records together.

For a different product release, preserve this dated sample directory and create a new versioned snapshot with matching catalog, fixtures, source dates and generator inputs. Review all adapters with changed formats, result types, masking or completion semantics. Verify desktop/mobile rendering, all download hashes and the deployed website after publication. Updating a public sample does not authorize publishing new engine images or installers.
