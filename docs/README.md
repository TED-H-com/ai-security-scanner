# Documentation

[Project website](https://ted-h-com.github.io/ai-security-scanner/) · [繁體中文](README.zh-TW.md)

**The latest release is desktop v0.6.2 for Linux, macOS and Windows.** It remains the default for beginners. Its public operator skill helps install the app, check readiness, guide scans in the app window and save reports.

## Use the product

- [Publication and release definitions](release-model.md): published desktop and operator skill, unreleased development work, and the proposed skill preview/stable distinction.
- [Getting started](getting-started.md): install the v0.6.2 desktop app for Linux, macOS, or Windows and complete the first scan.
- [Agent Skills](getting-started.md#use-with-an-agent-skill): use Claude Code or Codex on the same computer to check readiness, guide a scan in the app, and save the final report.
- [Scanning scope](scanning-scope.md): exact target boundaries, profiles, and scanner behavior.
- [Results and exports](results-and-exports.md): interpret priorities, coverage, evidence, and saved reports.
- [v0.6.2 release record](release/v0.6.2.md): current changes, exact delivery evidence, and remaining platform observations.

- [Standard report examples](samples/v0.4.0/README.md): redacted and fully disclosed, in both languages; 25 adapters, real formats, simulated data.
- [Fix and check again](demos/check-fixes/README.md): two real scans of a small demo project, before and after a fix, in both languages.
- [All-scanner guide](scanner-guide.md): detailed SWOT, selection rationale, use cases, enabled features and the 2026-10-04 version snapshot.

## New in development

These features are implemented in source on this branch and are not in any release:

- [Skill-first execution](skill-bootstrap.md): pinned source bootstrap and preparation of selected scanner engines.
- [Foreground scans and recovery](foreground-scans.md): run approved checks, read saved status and recover captured results.
- [Cloudflare source audits](cloudflare-provider.md): host-led preparation, recorded assignments and outputs, checkpoints, validation, sealing, case admission and shared reporting, with explicit termination when an audit will not continue.
- [Unfinished audit checks](results-and-exports.md#source-audits-that-did-not-finish): blocked preparation and terminated audits appear as not-started or failed check rows in the case, desktop Results and shared report.
- [Saved reports and offline replay](report-snapshots.md): preserve reports, retrieve their original files and replay them with an exactly compatible renderer.
- [Complete private case archives](case-archives.md): create, verify and restore cases, evidence, saved reports and recorded audit history into a new workspace; restored audits remain read-only.

**Not finished**

- Real-host acceptance has covered one Linux host through restore on a synthetic repository; a second host, several assets and macOS/Windows hosts remain.
- The default skill has not switched from the released desktop.
- Automatic managed-bundle acquisition and verification across the declared platforms remain unfinished. On macOS and Windows, CI covers the bootstrap, Cloudflare audits, saved reports and archives; foreground scans and engine preparation are not yet fully covered there.

## Understand the product

- [Product specification](product-spec.md): canonical product behavior and acceptance.
- [Skill-first and Cloudflare migration specification](plans/skill-first-cloudflare-migration.md): accepted next-phase direction, current gaps, staged implementation and pending acceptance (Traditional Chinese).
- [Report fidelity and archive contract](specs/report-fidelity-and-archive.md): frozen report inputs, provider records, offline replay, portable restore and traceable acceptance (Traditional Chinese).
- [Current product review](product-audit.md): implemented paths and remaining product work.
- [Architecture](architecture.md): components, trust boundaries, data model, orchestration, and report pipeline.
- [Engine catalog](engine-catalog.md): integrated upstream scanners and capability vocabulary.
- [Managed runtime](managed-runtime.md): runtime lifecycle, isolation, repair, and cleanup.
- [Provider authorization](provider-authorization.md): cloud authorization and isolated bootstrap.

## Build and maintain

- [API reference](api-reference.md): core modules, usage examples, and API specifications for backend-frontend interactions.
- [Development status](development-status.md): current implementation, recorded verification, and remaining work.
- [Contributing](../CONTRIBUTING.md): product priorities, implementation rules, and verification.
- [Engine maintenance](engine-maintenance.md): upstream updates, adapter boundaries, and patch exceptions.
- [Engine reference](engines/README.md): one page per engine and launcher: how it runs, what its adapter keeps, how to update it, and what real runs taught.
- [Engine and report-layer contracts](engine-alignment-handover.zh-TW.md): current engine semantics, asset paths, report behavior, and completion criteria.
- [Threat model](threat-model.md): protected assets, threats, and required controls.
- [Security policy](../SECURITY.md): private vulnerability reporting and operating rules.
- [Third-party inventory](../THIRD_PARTY.md): licenses, notices, and distribution records.
- [Release operations](releasing.md): candidate preparation, platform qualification, and publication. ([繁體中文](releasing.zh-TW.md))

## Historical and research records

- [Release records](release/README.md) preserve shipped-version facts and evidence formats.
- [Research](research/) records evaluated integrations and product studies.
- [Usability studies](usability/) contains study protocols and evidence-handling rules.

The product specification controls current behavior. Historical records describe their recorded version or commit.
