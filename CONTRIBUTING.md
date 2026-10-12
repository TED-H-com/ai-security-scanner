# Contributing

Contributions should make the product faster to understand, easier to start, and more useful after the first scan. Read the [product specification](docs/product-spec.md) before changing user-visible behavior.

## Product priorities

Use these priorities when choosing and reviewing work:

1. A beginner can quickly start a meaningful scan and understand the result.
2. Scanner integrations stay close to upstream behavior and data.
3. The product combines engine output into one clear, professional report.
4. Versioning, release timing, publication, and compliance positioning are product-owner decisions. Do not expand work into those areas unless the owner explicitly requests it.
5. Primary choices, progress, and reports stay concise and action-led; detail is available on demand.

A connectivity check, process launch, or empty report is not meaningful scan value. Product-facing work should help the user discover a real exposure, vulnerability, secret, risky configuration, or other actionable security signal, or clearly explain why a requested check could not run.

## Product changes

Prefer the shortest complete beginner journey:

- let one environment project contain multiple repositories, internal devices or endpoints, and websites, while retaining single-target shortcuts;
- ask only for information needed to start checks for the selected assets;
- provide useful defaults and keep advanced controls out of the primary path;
- route each upstream engine to only its applicable approved asset IDs;
- show which assets were scanned, the most important results, their impact, and the next action in one report;
- distinguish no findings from checks that did not run; and
- preserve saved work and allow unaffected checks to continue when one scanner fails.

Active scans remain in Progress. Results and Export open only for a terminal run. Do not add live/interim reports, defensive caveat walls, implementation-defect or test-harness explanations, or prose that transfers product responsibility to the user. Put required formal terms at the end or footer of the final report and keep technical evidence in collapsed detail.

Inventory, service discovery, port reachability, and connectivity may prepare an internal target, but they cannot satisfy vulnerability-scan value by themselves.

Test rendered behavior and a real user path where practical. Source-text assertions and schema checks can support that evidence, but they do not replace exercising the interaction they describe.

## Scanner integrations

Keep adapters thin. Let the upstream scanner own detection, rule behavior, severities, and scanner-specific evidence. Product code should concentrate on:

- converting the user's approved target and options into typed scanner input;
- launching without shell interpolation and with bounded resources;
- preserving upstream identifiers, versions, evidence, and raw output references;
- translating execution outcomes into consistent task and coverage states; and
- normalizing results for the shared report without inventing findings.

Avoid duplicating upstream detection logic or maintaining product-specific rewrites of titles, severity, and remediation when the upstream scanner already supplies them.

An engine contribution should include its official source and license, a supported version or digest, input and permission requirements, a typed launcher, redacted fixtures, parser tests, and honest completed/partial/failed/timed-out/cancelled behavior. An unavailable scanner should leave sibling checks usable and its coverage visibly untested.

## Professional reporting

All scanners feed one report model. A report contribution should improve the shared presentation of:

- scope and checks actually run, grouped by affected repository, internal device or endpoint, and website;
- prioritized findings with evidence and impact;
- recommended next actions;
- coverage gaps, failures, and exclusions; and
- technical details available when needed;
- cross-engine correlation or deduplication without losing any source finding or evidence.

Framework mappings may enrich a report, but they do not replace findings and should not control whether a scan can run.

## Reviewing user-facing claims

User-facing copy must not claim behavior that a different layer does not implement. A beginner cannot detect that mismatch, so a precise false claim is worse than a plainly disclosed limit. Trace every important promise to the data and execution that make it true, then confirm the rendered user state as Product changes already requires.

Look for these defect families:

- Failed or missing runs presented with completed-looking language.
- Report identity and history that borrow current-case values instead of the selected run's saved facts.
- Export copy that overstates redaction, source attachment, signatures, relationships, or format availability.
- Setup and authorization copy that offers actions or outcomes the backend cannot provide.
- Scanner output that is dropped, flattened, or assigned product-authored severity while appearing upstream-authored.
- English technical prose leaking into the Traditional Chinese first layer.
- Coverage gaps that collapse different causes into one misleading sentence.

When reviewing a user-facing claim:

1. Identify the decision the user will make from a sentence or status.
2. Trace the underlying target, task, scanner output, report record, and export path.
3. Fix the product behavior or replace the claim directly.
4. Render the affected state and assert the decision-relevant outcome.
5. When the change concerns a scan, exercise the real upstream path when practical.

## Verification

Japanese website copy lives in `docs/locales/ja.json`. After editing it, run
`node scripts/localize-public-site.mjs` for the homepage and fix-comparison page,
then `node scripts/build-public-showcase.mjs` for the guide and sample index.
Both commands accept `--check` to verify the generated markup. Keep scanner
identifiers, versions and archived report evidence unchanged; Japanese pages link
to the existing English reports with their language labeled explicitly.

Run checks proportional to the changed boundary. Common commands include:

```bash
npm run test:frontend
npm run test:component
npm run typecheck
npm run build
cargo fmt --all -- --check
cargo clippy --locked --workspace --no-default-features --features cli --all-targets -- -D warnings
cargo test --locked --workspace --no-default-features --features cli
```

For a small copy or documentation change, focused tests and link checks are enough. For a changed scan path, exercise the affected input, execution, saved result, and report flow. Release packaging, signing, publication, and compliance work are outside ordinary contribution scope unless explicitly requested by the product owner.

## Data and scope safety

- Never commit credentials, tokens, customer findings, personal data, internal addresses, or real scan reports.
- Use synthetic, redacted fixtures and reserved example domains or address ranges.
- Never contact a target without the user's explicit scope authorization.
- Do not execute remediation commands.
- Explain new network, process, filesystem, credential, or data-retention behavior in the pull request.

Keep each change focused and rewrite obsolete guidance where it lives instead of adding contradictory correction sections.
