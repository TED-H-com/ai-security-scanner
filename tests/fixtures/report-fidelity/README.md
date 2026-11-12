# Report fidelity baseline

This is the RF-01 compatibility corpus, freshly generated from production core
`6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7` on 2026-11-08. It is not a copy of the
older public sample reports, a live security scan, or evidence that the planned
snapshot/archive/restore features exist.

The generator reuses `src-tauri/tests/all_engine_report_audit.rs`, including the
same production adapters and persisted-case export path used by its
`support/public_sample_reports.rs` generator. Only the execution transport is
`FakeContainerRuntime`; no target is contacted. Each scenario records all 25
adapter fixture hashes. The source receipt identifies the exact core and the
sources used to capture these outputs.

| Scenario | Findings in canonical report | Inventory observations | Outcomes |
| --- | ---: | ---: | --- |
| `all-detectors` | 62 | 42 | Every detector returns; actual coverage gaps remain partial |
| `mixed-terminal` | 56 | 40 | Complete siblings survive failed, cancelled, timed-out, and partial checks |

These are fixture counts, not promised results for any project. Presentation
problem counts intentionally differ from canonical finding counts because
inventory and product grouping retain their existing meaning.

## What is frozen

`case.json.gz` is a fixed `AssessmentCase` input. The initial capture freezes
timestamps to `2026-11-08T12:00:00Z` (scope expiry to 2027-11-08), replaces its
temporary directory with `/report-fidelity-fixture`, and labels the fictional
organization. It preserves generated IDs verbatim: evidence identities bind
engine-run IDs, so rewriting UUIDs would invalidate their provenance. Subsequent
comparisons load this saved input; they do not generate a new case or call the
adapters again. This corpus is a report input, not an executable scan workspace.

Every output is produced by the unchanged production exporter. Output IDs,
timestamps, ordering, wording, and HTML are **never normalized after rendering**.
The files are gzip-compressed only to keep the checked-in corpus small; hashes
in `receipt.json` cover the exact decompressed bytes.

Each scenario has EN and Traditional Chinese (`zh-Hant`), Standard and full
disclosure HTML/canonical JSON, plus framework, OCSF, and OSCAL documents. OCSF
and OSCAL keep their mandatory coverage companions. The sixth format, the
signed case bundle, is created with the existing timestamp-injectable production
bundle creator, verified with the normal verifier, and compared through all 18
deterministic payload entries. A new local signing identity is used each time;
the identity document, manifest, signature, and compressed archive bytes are not
claimed to be identical. No private signing key is saved in this corpus.

Original artifacts and source snapshots are not included. This is not an
attachment/restore corpus and does not satisfy RF-03/AR-01 or the full RF-09
long-trace/provider acceptance criteria.

## Verify and replay

Check the committed corpus without Rust, AI, network, or scanner runtime:

```sh
node scripts/verify-report-fidelity-baseline.mjs
```

Compare the current production exporters with the fixed baseline:

```sh
cargo test --locked --manifest-path src-tauri/Cargo.toml --no-default-features \
  --test report_fidelity_baseline report_fidelity::frozen_report_outputs_match_baseline -- --exact
```

To retain fresh rendered documents for inspection, set
`AI_SCANNER_REPORT_BASELINE_OUTPUT` to a new empty output directory before that
command. Existing documents are never overwritten. A dependency cache and a
compatible Rust toolchain are required to compile; the compiled replay itself
uses no network or scanner runtime.

Initial capture was run with:

```sh
AI_SCANNER_REPORT_BASELINE_WRITE=/tmp/ai-scanner-report-fidelity-baseline-20261108-v2 \
  cargo test --locked --manifest-path src-tauri/Cargo.toml --no-default-features \
  --test report_fidelity_baseline report_fidelity::capture_report_fidelity_baseline \
  -- --exact --ignored --nocapture
```

Capture refuses a nonempty destination and changes to the named baseline core.
Do not update expected outputs to make a renderer extraction pass. Intentional
product changes need a separately reviewed replacement corpus and receipt.

## Rendered evidence

`visual/` contains 20 fresh Chromium screenshots: both scenarios and locales at
390, 768, and 1440 CSS pixels, plus expanded evidence and print-media views at
1440 pixels. The receipt records browser revision, exact source HTML hash,
viewport, image hash, font readiness, and measured horizontal overflow. All 20
captures have loaded fonts and no horizontal overflow. The English 390px cover
and Traditional Chinese expanded evidence were also visually inspected.

This captures a representative viewport, not every report page or a PDF. It is
a rendering reference; identical pixels on another browser/font installation
are not promised. To capture a fresh comparison without installing a browser:

```sh
node scripts/report-fidelity-visual-baseline.mjs \
  --browser /absolute/path/to/chromium \
  --reports /absolute/path/to/verified-output \
  --output /absolute/path/to/new-visual-output
```

The script opens local files and blocks HTTP(S) page requests. It preserves the
report HTML, opens one existing evidence disclosure for the expanded view, and
uses Chromium print media for the print view. Screenshots do not imply that a
new scanner, provider, or restore workflow has been executed.
