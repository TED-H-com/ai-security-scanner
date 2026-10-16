# Documentation

[Project website](https://ted-h-com.github.io/ai-security-scanner/) · [繁體中文](README.zh-TW.md)

Use the shortest path that matches the task.

## Use the product

- [Getting started](getting-started.md): install the v0.5.2 desktop app for Linux, macOS, or Windows and complete the first scan.
- [Agent Skills](getting-started.md#use-with-an-agent-skill): use Claude Code or Codex on the same computer to check readiness, guide a scan in the app, and save the final report.
- [Scanning scope](scanning-scope.md): exact target boundaries, profiles, and scanner behavior.
- [Results and exports](results-and-exports.md): interpret priorities, coverage, evidence, and saved reports.
- [v0.5.2 release record](release/v0.5.2.md): current changes, exact delivery evidence, and remaining platform observations.

- [Standard report examples](samples/v0.4.0/README.md): redacted and fully disclosed, in both languages; 25 adapters, real formats, simulated data.
- [Fix and check again](demos/check-fixes/README.md): two real scans of a small demo project, before and after a fix, in both languages.
- [All-scanner guide](scanner-guide.md): detailed SWOT, selection rationale, use cases, enabled features and the 2026-10-04 version snapshot.

## Understand the product

- [Product specification](product-spec.md): canonical product behavior and acceptance.
- [Current product review](product-audit.md): implemented paths and remaining product work.
- [Architecture](architecture.md): components, trust boundaries, data model, orchestration, and report pipeline.
- [Engine catalog](engine-catalog.md): integrated upstream scanners and capability vocabulary.
- [Managed runtime](managed-runtime.md): runtime lifecycle, isolation, repair, and cleanup.
- [Provider authorization](provider-authorization.md): cloud authorization and isolated bootstrap.

## Build and maintain

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
