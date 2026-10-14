# Development status

[繁體中文](development-status.zh-TW.md) · [Documentation](README.md)

_Updated 2026-10-12._

This page summarizes current engineering status for contributors. It is not a product specification
or release declaration. [The product specification](product-spec.md) remains the source of truth for
product behavior, and the [current product review](product-audit.md) tracks the broader user journey.

## At a glance

- [v0.5.1 Japanese support](release/v0.5.1.md) is the current stable/latest release for Windows, macOS and Linux. It packages the Japanese UI, README and website, including follow-up onboarding translations. Public bytes, updater signatures, source CI and CodeQL passed; exact evidence and platform limitations are in the release record.

- The earlier stable release, [v0.4.1](release/v0.4.1.md), retains its original installer and updater observations.
- The released desktop includes Prowler failure headlines, approved AWS report grouping, reconnect-and-rescan, blocked-scan continuations, Semgrep `1.174.0-4`, and explicit kube-bench/KICS incomplete-coverage handling.
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

The current catalog pins Grype to `0.117.0-4`. A controlled Linux repository scan recorded 81 Grype
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
