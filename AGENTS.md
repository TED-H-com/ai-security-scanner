# Product direction

Use [`docs/product-spec.md`](docs/product-spec.md) as the product source of truth. Work in this order:

1. Help a beginner finish a meaningful security scan quickly and understand the result.
2. Keep scanners close to upstream; product adapters stay thin.
3. Combine scanner output in one professional report layer using the product team's decisions.
4. Leave versioning, release timing, packaging, signing, and compliance posture to the product owner.

For app UI changes, reuse the existing tokens and components documented in [`DESIGN.md`](DESIGN.md).

## What this means

- A meaningful scan performs a real security, vulnerability, secret, dependency, configuration, or exposure check. Process completion, setup checks, and a single TCP connection do not count.
- Lead with one compact IT-environment path that can combine multiple repositories, internal devices or endpoints, and websites. Keep website-only and project-only shortcuts for users who need just one target type. Ask only for information needed by the selected assets and derive safe defaults where possible.
- A connectivity-only utility may remain available, but label it plainly and keep it out of the primary scan path.
- Inventory and service discovery prepare an internal target for an applicable security check; they are not vulnerability results or successful scan outcomes by themselves.
- Bind each scanner to only its applicable approved assets. A mixed run produces one report organized by asset, and one failed check does not erase completed sibling results.
- Preserve upstream detector behavior, identifiers, severity, evidence, and remediation. Adapters may translate typed inputs, enforce scope and resource boundaries, invoke upstream, and normalize output; do not rebuild detection logic in wrappers.
- Put product-owned prioritization, deduplication, plain-language explanation, cross-engine correlation, and report presentation in the shared report layer.
- The report's first layer answers: what was scanned, what was found, what matters first, why it matters, what to do next, and what was not tested. Keep evidence and upstream provenance available as technical detail.
- Keep the primary path concise and action-led. Do not ship live/interim reports, defensive caveat walls, implementation-defect or test-harness explanations, or prose that transfers product responsibility to the user. Active work stays in Progress; terminal Results carry concise outcomes, with formal terms at the report end or footer and technical evidence in collapsed detail.
- Test the rendered beginner path and real execution result in proportion to the changed risk. Tests support product decisions; test gates do not choose the roadmap.

## Owner authority

Do not initiate or expand version classification, release qualification, packaging, signing, publication, or compliance work unless the product owner explicitly requests it in the current task. Existing release records are historical context, not standing instructions or a backlog.

Security boundaries still apply: never invent authorization, widen a scan target, handle credentials through chat or command arguments, run destructive checks, or hide incomplete coverage.

## Running the scanner for someone

When someone asks to install, run, or try the scanner rather than change it, use the `ai-security-scanner` skill: install the desktop app from the current release and start scans in the app window. Do not build from source to run a scan.
