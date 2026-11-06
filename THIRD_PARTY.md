# Third-party inventory for ai-security-scanner

Status: current source and artifact inventory

Last updated: 2026-11-06

Exact engine artifacts: [`engines/catalog.json`](engines/catalog.json)

`ai-security-scanner` orchestrates independent upstream projects. This file records their source, artifact, license, notice, and distribution relationships, including research projects that are not product dependencies. Platform runtime files are recorded by the managed-runtime manifest.

Release automation generates locked dependency notices, engine notices, managed-runtime inventories, and SPDX/CycloneDX SBOMs from the resolved release bytes. The root Apache License 2.0 covers project-owned work; each third-party source and artifact retains its own terms.

## Disposition labels

- `ALLOW`: the engineering record has an allow disposition for the exact project-managed artifact with its required license texts, notices, and dependency obligations.
- `SOURCE_OFFER`: the artifact record identifies a project-managed copyleft artifact and its corresponding-source or source-offer path.
- `SOURCE_ARCHIVE`: a managed-runtime record binds a distributed copyleft binary to an exact corresponding-source archive URL, digest, and size.
- `UPSTREAM_PINNED`: the product retrieves an exact verified upstream artifact by digest and does not republish it as a project-managed engine image.
- `GENERATED_INVENTORY`: the resolved release graph, notices, and SBOM (not this row) enumerate the artifact-specific dependency terms.
- `NOT_DISTRIBUTED`: tracked or referenced source that is not shipped by the described component.
- `MANUAL`: repository metadata did not provide an unambiguous SPDX identifier or the project has special terms requiring manual review.
- `RESEARCH`: tracked for evaluation; not a committed release dependency.
- `ARCHIVED`: upstream is archived and requires a maintenance/replacement decision.

`ALLOW`, `SOURCE_OFFER`, and `SOURCE_ARCHIVE` apply only to the exact recorded artifact and are engineering dispositions rather than legal advice. `UPSTREAM_PINNED` is not a blanket permission or a statement that the artifact is inside the desktop installer. `MANUAL`, `RESEARCH`, `ARCHIVED`, and `NOT_DISTRIBUTED` never imply release approval.

## Catalog engine inventory

| Component | Official source | Pinned license record | Current relationship | Disposition |
|---|---|---|---|---|
| CloudQuery | [cloudquery/cloudquery](https://github.com/cloudquery/cloudquery) | MPL-2.0 | Project-managed image with exact public CLI and provider-plugin source closure | SOURCE_OFFER |
| Steampipe | [turbot/steampipe](https://github.com/turbot/steampipe) | AGPL-3.0-only plus separately pinned plugin/FDW terms | Project-managed image with source and build material | SOURCE_OFFER |
| Prowler | [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) | Apache-2.0 | Project-managed image with exact AWS-account, Azure-subscription, and GCP-project IAM profiles and required notices | ALLOW |
| ScoutSuite | [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) | GPL-2.0-only | Project-managed image carrying exact source, patch, build recipe, and notices | SOURCE_OFFER |
| Cloudsplaining | [salesforce/cloudsplaining](https://github.com/salesforce/cloudsplaining) | BSD-3-Clause | Project-managed image with the upstream notice | ALLOW |
| ScubaGear | [cisagov/ScubaGear](https://github.com/cisagov/ScubaGear) | CC0-1.0 plus pinned module terms | Wrapper-hardened project-managed image published at immutable `2.0.0-1` digest; anonymous pull verified; module source and notices retained | ALLOW |
| Maester | [maester365/maester](https://github.com/maester365/maester) | MIT plus pinned module terms | Wrapper-hardened project-managed image published at immutable `2.3.0-1` digest; anonymous pull verified; module source and notices retained | ALLOW |
| Naabu | [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) | MIT upstream; Apache-2.0 launcher | Project-managed image with fixed bounded launcher | ALLOW |
| httpx | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) | MIT upstream; Apache-2.0 launcher | Project-managed image with fixed bounded launcher | ALLOW |
| Nuclei and selected templates | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei), [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | MIT upstream; Apache-2.0 launcher | Project-managed image with one pinned snapshot and an upstream-driven read-only profile | ALLOW |
| Greenbone scanner and feed | [greenbone/openvas-scanner](https://github.com/greenbone/openvas-scanner) | GPL-2.0-only scanner; pinned feed GPL/ODbL terms; Apache-2.0 launcher | Project-managed direct-`openvasd` image carrying exact scanner/feed source and notices; no gvmd, GSA, OSPd, or feed-sync runtime | SOURCE_OFFER |
| OWASP ZAP 2.17.0 | [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy/tree/2665d972f6d587ba4773a95053ac39af3fdf8df9) | Apache-2.0 | Verified upstream image used by the explicitly approved passive website profile, with bounded native request pacing and preserved upstream alerts | UPSTREAM_PINNED |
| Semgrep | [semgrep/semgrep](https://github.com/semgrep/semgrep), [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules) | LGPL-2.1-or-later scanner; Apache-2.0 product rules/launcher; legacy rules retain LGPL 2.1 plus Commons Clause | Published `1.184.0-1` combines 1,493 selected legacy upstream rules with four product rules and retains selected originals, notices and ID provenance | SOURCE_OFFER |
| Gitleaks 8.30.1 | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks/tree/v8.30.1) | MIT upstream; Apache-2.0 project launcher | Project-managed source build with a fixed non-shell launcher, scanner-owned rules, and redacted directory-scan output | ALLOW |
| TruffleHog | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | AGPL-3.0; Apache-2.0 launcher | Project-managed source build restricted to offline filesystem scanning | SOURCE_OFFER |
| Checkov | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 plus dependency/policy terms | Project-managed image with dependency notices | ALLOW |
| KICS | [Checkmarx/kics](https://github.com/Checkmarx/kics) | Apache-2.0 | Exact verified upstream image acquired by digest | UPSTREAM_PINNED |
| Trivy | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) | Apache-2.0; advisory-provider terms remain applicable | Project-managed image with one immutable offline DB snapshot and notice | ALLOW |
| Grype | [anchore/grype](https://github.com/anchore/grype) | Apache-2.0; advisory-provider terms remain applicable | Project-managed image with one checksum-pinned offline DB snapshot and notice | ALLOW |
| Syft | [anchore/syft](https://github.com/anchore/syft) | Apache-2.0 | Project-managed image with required notices | ALLOW |
| Kubescape | [kubescape/kubescape](https://github.com/kubescape/kubescape) | Apache-2.0 scanner and pinned regolibrary artifacts | Project-managed offline manifest scanner image | ALLOW |
| kube-bench | [aquasecurity/kube-bench](https://github.com/aquasecurity/kube-bench) | Apache-2.0 | Project-managed source build with benchmark configuration over a bounded node snapshot | ALLOW |
| garak | [NVIDIA/garak](https://github.com/NVIDIA/garak/tree/7aa740fe7412cc9bc33cdc39ca211843223cd3e1) | Apache-2.0 at the audited revision | Unchanged native REST/DAN/ANSI source in published immutable `0.17.1-1`; fixed-profile HTTPS wrapper, typed exact input and one-shot local key. Anonymous platform bytes, signed source/SBOM evidence and six-case native TLS QA verified | ALLOW |
| Agentic Radar | [splx-ai/agentic-radar](https://github.com/splx-ai/agentic-radar/tree/65a7e4bd01e2034c7cb52e9620eeed287688cc53) | Apache-2.0 at the audited revision | Published offline workflow-inventory image with an audited machine-output patch; typed framework selection, no hosted assessment or target execution | ALLOW — Apache-2.0 |
| MCP Armor | [aira-security/mcp-armor](https://github.com/aira-security/mcp-armor/tree/6af4cee4665ab6242f02a88952f9127b6a04922a) | Apache-2.0 source at the audited revision; model terms are separate and excluded | Project-managed configuration-only image published at immutable `1.0.2-config-only.1` digest; dispatchable, not default-enabled; model files excluded | ALLOW |

## Research inventory

| Component | Official source | Observed license | Candidate relationship | Review |
|---|---|---|---|---|
| Powerpipe | [turbot/powerpipe](https://github.com/turbot/powerpipe) | AGPL-3.0 | Compliance query and dashboard research | RESEARCH |
| Monkey365 | [silverhack/monkey365](https://github.com/silverhack/monkey365) | Apache-2.0 | Microsoft 365/Azure assessment research | RESEARCH |
| OWASP Amass | [owasp-amass/amass](https://github.com/owasp-amass/amass) | NOASSERTION | External discovery research | MANUAL / RESEARCH |
| OpenSCAP | [OpenSCAP/openscap](https://github.com/OpenSCAP/openscap) | LGPL-2.1 | Host posture and SCAP research | RESEARCH |
| Wazuh | [wazuh/wazuh](https://github.com/wazuh/wazuh) | NOASSERTION | Host/SIEM research | MANUAL / RESEARCH |
| Lynis | [CISOfy/lynis](https://github.com/CISOfy/lynis) | GPL-3.0 | Linux host posture research | RESEARCH |
| tfsec | [aquasecurity/tfsec](https://github.com/aquasecurity/tfsec) | MIT | Terraform scanner research | RESEARCH |
| DefectDojo | [DefectDojo/django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | BSD-3-Clause | Import/deduplication/workflow reference | RESEARCH |
| Cartography | [cartography-cncf/cartography](https://github.com/cartography-cncf/cartography) | Apache-2.0 | Asset graph research | RESEARCH |
| PMapper | [nccgroup/PMapper](https://github.com/nccgroup/PMapper) | AGPL-3.0 | AWS IAM path research | RESEARCH |
| BloodHound CE | [SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) | Apache-2.0 | AD/Entra path research | RESEARCH |
| ROADtools | [dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools) | MIT | Entra identity research | RESEARCH |
| kubeaudit | [Shopify/kubeaudit](https://github.com/Shopify/kubeaudit) | MIT | Kubernetes posture research | ARCHIVED / RESEARCH |
| Falco | [falcosecurity/falco](https://github.com/falcosecurity/falco) | Apache-2.0 | Runtime security research | RESEARCH |
| testssl.sh | [testssl/testssl.sh](https://github.com/testssl/testssl.sh) | GPL-2.0 | TLS assessment research | RESEARCH |
| Subfinder | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) | MIT | External discovery research | RESEARCH |
| OSV-Scanner | [google/osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 | Dependency scanner research | RESEARCH |
| Nikto | [sullo/nikto](https://github.com/sullo/nikto) | NOASSERTION | Authorized web-server assessment research | MANUAL / RESEARCH |
| VibeScan | [Armur-Ai/vibescan](https://github.com/Armur-Ai/vibescan/tree/52efb12fdcd8118c6f0f2b642558b2f335e7bf66) | MIT at audited revision `52efb12fdcd8118c6f0f2b642558b2f335e7bf66` | Vibe-coding journey and normalized multi-tool-report research only; no code, binary, image, or package is shipped | RESEARCH / NOT_DISTRIBUTED |

The VibeScan integration decision and security review are recorded in
[`docs/research/vibescan-evaluation.md`](docs/research/vibescan-evaluation.md). Its useful guided
journey and common-results-envelope ideas are being implemented independently over this project's
existing scanners; VibeScan itself is not a release dependency.

## Supporting standards and runtime inventory

The platform-specific managed-runtime manifest records every bundled file, first-setup download, source revision, license expression, size, and SHA-256. For an artifact the product owner chooses to distribute, the artifact workflow emits the applicable manifest, runtime notices, and SPDX/CycloneDX SBOMs. An absent platform remains `not-offered`; evidence for one platform does not describe another. The relationships below summarize current source records rather than claiming that every research repository is packaged.

| Component | Official source | Pinned license record | Current relationship | Disposition |
|---|---|---|---|---|
| OCSF schema | [ocsf/ocsf-schema](https://github.com/ocsf/ocsf-schema) | Apache-2.0 | Versioned interchange reference implemented by project-owned export code; no upstream schema artifact is bundled | NOT_DISTRIBUTED |
| OSCAL | [usnistgov/OSCAL](https://github.com/usnistgov/OSCAL) | NIST publication terms | Versioned exchange reference implemented by project-owned export code; no upstream repository artifact is bundled | NOT_DISTRIBUTED |
| Tauri and resolved desktop dependencies | [tauri-apps/tauri](https://github.com/tauri-apps/tauri) | Apache-2.0 OR MIT for Tauri; per-package terms in the resolved graph | Compiled desktop dependency; release notices and desktop SBOM enumerate the exact graph | GENERATED_INVENTORY |
| glib 0.18.5 security backport | [gtk-rs/gtk-rs-core](https://github.com/gtk-rs/gtk-rs-core/tree/0.18.5/glib) | MIT; exact crates.io artifact and license retained under [`vendor/glib-0.18.5/`](vendor/glib-0.18.5/) | Linux desktop dependency with the two-line upstream `gtk-rs/gtk-rs-core#1343` fix; provenance verification enforces zero additional source drift | ALLOW |
| Podman machine client | [containers/podman](https://github.com/containers/podman) | Apache-2.0 | Exact platform client files bundled in the desktop managed-runtime resource | ALLOW |
| podman-machine-os | [containers/podman-machine-os](https://github.com/containers/podman-machine-os) | Apache-2.0 project; contained packages retain their own terms | Exact VM image downloaded on first managed-runtime setup by URL, size, and digest | UPSTREAM_PINNED |
| gvisor-tap-vsock | [containers/gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock) | Apache-2.0 | Exact `gvproxy` and, on Windows, SSH proxy helpers bundled per platform | ALLOW |
| QEMU system emulator | [qemu-project/qemu](https://gitlab.com/qemu-project/qemu) | GPL-2.0-only | Linux-only static system emulator built from a checksum-pinned source archive recorded in runtime evidence | SOURCE_ARCHIVE |
| Device Tree Compiler | [qemu-project/dtc](https://gitlab.com/qemu-project/dtc) | GPL-2.0-or-later AND BSD-2-Clause | Exact source incorporated into the Linux QEMU build; source archive URL and digest recorded | SOURCE_ARCHIVE |
| vfkit | [crc-org/vfkit](https://github.com/crc-org/vfkit) | Apache-2.0 | Exact macOS Apple Virtualization.framework helper bundled in the universal runtime | ALLOW |
| Moby | [moby/moby](https://github.com/moby/moby) | Apache-2.0 | Architecture research only; not used by the packaged managed runtime | NOT_DISTRIBUTED |
| Docker CLI and Compose | [docker/cli](https://github.com/docker/cli), [docker/compose](https://github.com/docker/compose) | Apache-2.0 | Optional user-installed compatibility provider; not bundled or required by the product | NOT_DISTRIBUTED |

## Redistributed framework reference data

| Component | Official source | Pinned license record | Relationship | Disposition |
|---|---|---|---|---|
| AIDEFEND selected actionable-control metadata | [edward-playground/aidefense-framework](https://github.com/edward-playground/aidefense-framework/tree/e10c1678ee49f03f8fb0c97d446ba3fbc3543655) | CC-BY-4.0 framework content at version `1.20260805`; source `data/data.json` SHA-256 `ee0db6542fe28bcb3bd9ead0fba0fb69884b6cb765f2a1a420ceaf119a472786` | Modified six-record metadata selection with pinned provenance, attribution, and full content-license text under [`mappings/vendor/aidefend/1.20260805/`](mappings/vendor/aidefend/1.20260805/) | ALLOW |

The selected AIDEFEND snapshot contains only control ID, name, tactic, parent,
pillar, phase, and upstream `contentHash` fields. It does not copy source code,
descriptions, implementation guidance, code examples, tool lists, keywords,
external-framework mapping strings, logos, badges, or other trademark assets.
AIDEFEND is used nominatively to identify the source. This is an independent,
unofficial integration and is not affiliated with, approved, certified,
sponsored, or endorsed by AIDEFEND or its owner. The selected coordinates are
navigation and classification metadata, not evidence of control
implementation, effectiveness, certification, or compliance.

## Docker Desktop is separate

[Docker Desktop licensing](https://docs.docker.com/subscription/desktop-license/) is not the same as the Apache-2.0 licenses on Moby, Docker CLI, or Docker Compose. `ai-security-scanner` must not bundle, redistribute, or require an enterprise user to use Docker Desktop based only on those repository licenses.

The product's private runtime design uses Podman with QEMU on Linux, Apple Virtualization.framework through vfkit on macOS, and WSL 2 capability on Windows. Runtime preparation remains behind the user's selected scan task; this inventory makes no claim about installer behavior. Docker or a user-installed Podman remains an optional compatibility provider and is not treated as part of the application.

## Rules, feeds, plugins, and databases

Rules, feeds, plugins, and databases remain independently identified artifacts even when they share an engine image. The desktop installers contain none of them. Each currently admitted engine artifact uses only the exact data closure recorded by its plan and catalog; an unavailable or unadmitted entry is not implied to have been published:

- CloudQuery and Steampipe carry only their pinned provider/plugin closure; Powerpipe and other compliance mods are not shipped.
- Nuclei carries one pinned template snapshot. Its automatic profile derives the read-only candidate set from that snapshot and leaves technology applicability to Nuclei; private, live, destructive, and out-of-band template packs are not shipped or automatically enabled.
- Greenbone carries one digest-pinned Community Feed snapshot, executable NASL source, data, declared license texts, revision, checksum manifest, and upstream detached signature; it performs no live feed synchronization.
- Trivy and Grype each carry one immutable offline vulnerability database with its digest, timestamp, and attribution notice; automatic database updates are disabled.
- Semgrep's pinned `1.174.0-4` has 1,493 selected legacy upstream rules plus four product rules: 1,497 unique IDs in 1,478 configurations. The [publication record](docs/engines/semgrep-publication-2026-10-03.md) contains native amd64/ARM64 verification, actual platform digests and signed evidence. Upstream IDs are qualified with modification notices and byte-exact originals; detector bodies and native ratings remain unchanged. Legacy rules retain LGPL 2.1 plus Commons Clause, including restrictions on paid products/services whose value derives entirely or substantially from the rules. The excluded proprietary rule and unfiltered archive are absent from the selected source attachment and copied rule-pack layers. No Pro component or token-driven installer is included. The old `1.174.0-3` source attachment issue remains in the [historical inspection](docs/engines/semgrep-combination-review.md#published-source-attachment-inspection); this free public image distribution does not authorize restricted paid uses.
- Gitleaks is built from the pinned 8.30.1 source under its MIT license and paired with a project-owned Apache-2.0 non-shell launcher. The launcher performs a current-worktree directory scan using only the scanner-owned configuration, ignores repository `.gitleaksignore` and `gitleaks:allow` suppressions, treats findings as results with `--exit-code 0`, and requires 100% secret redaction before output becomes evidence. The workspace is read-only and engine networking is disabled.
- Checkov's packaged policies, the KICS upstream-image query pack, Kubescape's three checksum-pinned offline policy assets, and kube-bench's benchmark configuration stay bound to their exact engine artifacts.

No statement above claims that a newer feed, database, policy, plugin, user-supplied pack, or language advisory index is shipped. Replacing any one requires a new source, terms, version/date, digest, update method, disposition, evidence set, and support window. An engine's source license does not automatically license its data.

## General obligations by license family

This section is an engineering checklist, not legal advice.

### Permissive licenses

MIT, BSD-3-Clause, and Apache-2.0 generally permit redistribution with preservation of copyright, license, attribution, and applicable NOTICE material. Apache-2.0 also contains patent and NOTICE provisions. Dependency licenses still apply.

### CC0

CC0-1.0 is a public-domain dedication/fallback license. Retaining provenance and the upstream license text is still project policy.

### MPL-2.0

MPL-2.0 has file-level source obligations for covered files and modifications. A distributed binary or image requires a corresponding-source path and required notices for covered code.

### LGPL-2.1

LGPL obligations depend on whether the project links, modifies, or merely distributes a separate executable. Distribution still requires the license and applicable source/relinking obligations. For any distribution the product owner requests, review the actual wrapper and artifact rather than relying on the words “separate process.”

### GPL-2.0 and GPL-3.0

Distribution requires the applicable GPL materials, complete corresponding source or a compliant source offer, notices, and license-compatible treatment of modifications. Packaging multiple programs as an aggregate does not remove obligations for the GPL programs.

### AGPL-3.0

AGPL includes GPL distribution obligations and a network-interaction source provision for modified covered software used over a network. Running an AGPL component locally or in a separate container is not a blanket exception. Each actual integration and modification must be reviewed.

### NOASSERTION and special terms

`NOASSERTION` means the automated repository metadata was not sufficient. It does not mean no license or unrestricted use. These components remain non-redistributable until a human reviews the pinned revision and records a decision.

## Artifact notice requirements when distribution work is requested

When the product owner requests distribution work, the artifact workflow uses the mechanical evidence below. It supports license review but does not replace qualified legal analysis:

1. Resolve every included artifact to a source revision, version, and digest.
2. Generate an SBOM for the desktop application, broker, runtime, images, adapters, and bundled data.
3. Re-evaluate licenses from the pinned artifacts rather than copying this narrative unchanged.
4. Produce required license texts, attribution, NOTICE files, corresponding source, patches, and source offers.
5. Verify trademarks and naming restrictions separately from copyright licenses.
6. Confirm whether each artifact is bundled, built by the project, or downloaded on demand.
7. Confirm that on-demand download terms allow the proposed use; downloading later is not a license bypass.
8. Record the artifact facts in the engine catalog, plan, generated notices, and artifact evidence.
9. Exclude only the exact engine artifact from the requested distribution and execution when its catalog entry is non-runnable, blocked, lacks an immutable artifact digest, or lacks an `allow`/`source_offer` disposition. Do not infer a decision for the application or unaffected engines.

Update this file when a catalog engine, runtime component, ruleset, feed, database, plugin, or
license relationship changes. That source-record maintenance does not initiate distribution work.
