# ai-security-scanner engine catalog

Status: current source catalog companion

Last updated: 2026-10-04

Exact artifact facts: [`engines/catalog.json`](../engines/catalog.json)

Product behavior: [Product specification](product-spec.md)

This document answers two questions: what each upstream engine actually checks, and what the product adapter is allowed to do around it. An engine being present does not mean every product path performs a vulnerability scan.

## 1. Upstream-first integration rule

The scanner is the upstream project. ai-security-scanner supplies a thin adapter and a common report; it does not become a fork of the scanner.

A thin adapter may only:

- translate an already-authorized product target or local artifact into the upstream CLI/API input;
- enforce target, credential, network, timeout, rate, filesystem, process, and resource boundaries;
- pin and verify the upstream executable, image, rules, templates, feed, or database;
- capture upstream output and diagnostics without loss, then convert their structure into the common result schema;
- report unsupported input, incomplete coverage, malformed output, timeout, cancellation, or engine failure explicitly.

A thin adapter must not:

- replace, add, or reinterpret the upstream detection algorithm inside the wrapper;
- silently broaden or narrow the selected target, rule set, template set, provider, or scan mode;
- rewrite severity, finding title, or remediation in the wrapper;
- turn connectivity, inventory, an empty result, or an unknown value into a vulnerability conclusion;
- emulate an unsupported upstream provider or feature through an accumulating private fork.

Professional wording, localization, deduplication, prioritization, and product-authored guidance belong to the shared normalization/report layer. That layer must retain the upstream engine, rule/check identifier, original title, original severity, original message/evidence, and exact version. A normalized severity or product recommendation must be separately identifiable and must never erase the upstream value.

Downstream scanner patches are exceptions, not the normal integration model. Each exception must be minimal, hash-bound, documented beside the affected engine, tested against upstream behavior, submitted upstream when practical, and assigned a removal condition. New product capability should prefer an upstream-supported interface or a different upstream engine over extending a private detector fork.

## 2. Honest capability vocabulary

The product and reports use these terms narrowly:

- **Connectivity:** whether a connection can be attempted or accepted.
- **Exposure:** a reachable service, port, or HTTP endpoint. Exposure alone is not a vulnerability.
- **Vulnerability:** an upstream check matched a known vulnerable condition, package, or authorized active-test template.
- **Configuration:** an upstream policy or posture check found a risky setting.
- **Secrets:** an upstream detector found secret-like material. Offline detection does not prove that a credential is live.
- **Inventory:** observed assets, packages, components, identities, or metadata without a security conclusion.

`Yes` below means the current profile can produce that kind of result. `Limited` means only the exact stated subset. A dash means the path must not claim that capability.

| Product path / current profile | Connectivity | Exposure | Vulnerability | Configuration | Secrets | Inventory | Honest description |
|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| Local service connection test | Yes | Limited | - | - | - | - | One TCP connection attempt to `127.0.0.1:<port>`; accepted, refused, timeout, or failure. It does not inspect a protocol or test a vulnerability. |
| Website, guided `low_impact_external` | Yes | Yes | - | - | - | Limited | Naabu checks the declared TCP port and httpx records bounded HTTP reachability/status metadata. It does not crawl or establish that the site is secure or vulnerable. |
| Website, authorized `active_external` | Yes | Yes | Yes | Limited | - | Limited | Nuclei derives 4,674 bounded read-only candidates from the pinned upstream snapshot, detects technology, and runs matching templates against the exact origin. Completion does not imply every candidate executed. |
| Public host or internal CIDR, guided | Yes | Yes | - | - | - | Limited | Naabu reports reachable selected TCP ports. An open port is an exposure fact, not by itself a vulnerability. |
| Exact internal host, remote-safe profile | Yes | Yes | Limited | Limited | - | Limited | Greenbone receives the exact approved host and ports, derives current non-deprecated remote `gather_info` VTs from the pinned feed, and applies upstream prerequisites. A completed scan does not prove that every scheduled VT executed. |
| Source repository / AI-project repository | - | - | Yes | Yes | Yes | Limited | Gitleaks and TruffleHog inspect secrets; Semgrep checks a pinned offline pack of 1,493 legacy upstream rules and four product rules; Trivy and Grype inspect recognized dependencies; Checkov and KICS inspect applicable configuration. The AI label does not add live model or jailbreak testing. |
| IaC working tree | - | - | Limited | Yes | Limited | Yes | Checkov uses its bundled upstream framework detection over the selected snapshot, while KICS supplies its query pack. Trivy contributes only its declared recognized-package profile. |
| Single-image OCI layout | - | - | Yes | - | - | Yes | Trivy and Grype match offline OS/language packages against pinned vulnerability data. This is not registry, runtime, or live-workload testing. |
| Kubernetes manifests | - | - | - | Yes | - | Yes | Kubescape checks supplied local YAML/JSON manifests against pinned offline framework inputs; it does not connect to a cluster. |
| Kubernetes node snapshot | - | - | - | Yes | - | Yes | kube-bench checks an explicitly prepared immutable node-configuration snapshot; it does not mount or inspect a live node. |
| Cloud provider profiles | - | - | - | Limited | - | Yes | Read-only provider discovery and narrow IAM/identity/configuration profiles after provider authorization. No general vulnerability, storage, logging, or network-exposure coverage is implied. |

A report must name both checked and untested areas. Zero findings means only that the executed checks produced no matches; it is never equivalent to “secure.”

## 3. Integrated upstream engines

The source and license below identify the pinned engine family. Exact release, source SHA, artifact digest, rules/feed/database closure, and disposition remain in `engines/catalog.json` and the corresponding engine plan. A different revision or data closure requires its own record.

| Capability | Upstream engine / source | Pinned license record | Integration and exact released scope |
|---|---|---|---|
| AWS inventory | [CloudQuery](https://github.com/cloudquery/cloudquery) | MPL-2.0 | Managed OCI image using the public CLI, AWS source plugin, file destination, and a fixed seven-table IAM inventory. |
| AWS IAM user inventory | [Steampipe](https://github.com/turbot/steampipe) | AGPL-3.0-only | Managed OCI image with independently pinned AWS plugin/FDW components that queries `aws_iam_user`. Returned rows are normalized as inventory; policy-shaped status, control, severity, and MFA columns are ignored rather than presented as vulnerability or configuration findings. |
| Cloud configuration | [Prowler](https://github.com/prowler-cloud/prowler) | Apache-2.0 | Managed OCI image with narrow, exact-asset IAM profiles for AWS, Azure, and GCP. The Azure static-token and GCP exact-project paths currently depend on six hash-bound downstream runtime patches and are an explicit upstream-first exception, not native Prowler 5.44.0 behavior. |
| AWS configuration | [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | GPL-2.0-only | Managed OCI image built from pinned source; the current profile is a reduced AWS IAM assessment, not full ScoutSuite coverage. |
| AWS IAM | [Cloudsplaining](https://github.com/salesforce/cloudsplaining) | BSD-3-Clause | Managed OCI image over bounded IAM evidence for excessive-permission analysis. |
| Microsoft 365 configuration | [ScubaGear](https://github.com/cisagov/ScubaGear) | CC0-1.0 | Managed PowerShell/OCI image; the current profile is fixed and leaves upstream unknown values unknown. Immutable image revision `1.8.0-8`. |
| Microsoft 365 configuration | [Maester](https://github.com/maester365/maester) | MIT | Managed PowerShell/OCI image; the current profile is fixed and preserves upstream severity and unknown values. Immutable image revision `2.0.0-9`. |
| External exposure | [Naabu](https://github.com/projectdiscovery/naabu) | MIT | Bounded-launcher managed OCI image for selected TCP-port reachability. Its results are exposure observations, not vulnerability findings. |
| HTTP exposure | [httpx](https://github.com/projectdiscovery/httpx) | MIT | Bounded-launcher managed OCI image for HTTP reachability/status metadata with redirect and resolved-IP enforcement. It is not a web vulnerability scanner. |
| Active HTTP testing | [Nuclei](https://github.com/projectdiscovery/nuclei) | MIT | Bounded-launcher managed OCI image with a 4,674-template read-only pool mechanically derived from the pinned upstream snapshot. Nuclei automatic scan owns technology detection and applicable-template selection; legacy explicit allowlists remain supported. |
| Network scanner | [OpenVAS Scanner](https://github.com/greenbone/openvas-scanner) | GPL-2.0-only; pinned feed also carries GPL/ODbL terms | Managed direct `openvasd` image with a digest-pinned Community Feed snapshot. The generic internal-host profile mechanically derives non-deprecated unauthenticated remote `gather_info` VTs, excludes local, credential, policy, brute-force, alternate-scanner, and active/destructive categories, and leaves service/product applicability to Greenbone. Legacy explicit-OID profiles remain supported. |
| Source analysis | [Semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1-or-later scanner; Apache-2.0 product rules; legacy rules retain LGPL 2.1 plus Commons Clause | Published `1.181.0-1`: 1,493 selected legacy upstream rules plus four product rules, with qualified upstream IDs and retained original-source provenance. The [current publication record](engines/updates/2026-10-14.md#verified-publication-and-catalog-activation) includes native verification, signed evidence and exact digest bindings. Detector bodies, native ratings, messages and fixes remain unchanged. |
| Secret scanning | [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Project-managed pinned-source OCI image, filesystem mode, fixed offline launcher. Results are sensitive secret-pattern matches. |
| Secret scanning | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | AGPL-3.0 | Managed pinned-source OCI image, filesystem mode only; verification, update, and engine-network paths disabled. Results do not prove a credential is live. |
| Infrastructure as code | [Checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 | Managed OCI image with read-only input and external integrations disabled. The fixed offline invocation uses Checkov's `all` framework selection so bundled runners detect applicable Terraform, CloudFormation, Dockerfile, Kubernetes, workflow, policy, secret, and other supported files instead of forcing every repository through Terraform. |
| Infrastructure as code | [KICS](https://github.com/Checkmarx/kics) | Apache-2.0 | Exact verified upstream OCI image pulled by digest for local IaC configuration checks. |
| Dependency/OS vulnerability | [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Managed OCI image with pinned offline vulnerability and Java index databases. Repository/IaC mode covers recognized language-package manifests and JAR archives identified with the embedded Java index; OCI mode covers recognized OS packages. OCI language packages, IaC misconfiguration, secrets, licenses, and all update paths are excluded. |
| Repository/container vulnerability | [Grype](https://github.com/anchore/grype) | Apache-2.0 | Managed OCI image with checksum-pinned offline vulnerability data. It uses upstream `dir:` cataloging for repository snapshots and `oci-dir:` for backend-validated single-image OCI layouts, including recognized language and JAR packages. |
| Component inventory | [Syft](https://github.com/anchore/syft) | Apache-2.0 | Managed OCI image producing a preserved SBOM artifact. Inventory is not a vulnerability conclusion. |
| Kubernetes posture | [Kubescape](https://github.com/kubescape/kubescape) | Apache-2.0 | Managed OCI image with pinned offline framework inputs over explicit local manifests; submission and host scanning disabled. |
| Kubernetes CIS | [kube-bench](https://github.com/aquasecurity/kube-bench) | Apache-2.0 | Managed OCI image over an immutable, digest-verified node configuration snapshot; no privileged live-host mounts. |
| MCP configuration | [MCP Armor](https://github.com/aira-security/mcp-armor/tree/6af4cee4665ab6242f02a88952f9127b6a04922a) | Apache-2.0 source; model terms separately excluded | Published, digest-pinned configuration-only image; dispatchable but not default-enabled. A retained patch runs only the existing hardcoded-secret and excessive-tool-permission checks against one exact configuration snapshot. It cannot contact or start an MCP server and does not import or download the prompt-injection model. Findings from completed checks survive partial coverage; a clean result requires the exact two-check ledger to complete. Missing configuration is not tested. See the [pinned decision](research/mcp-armor-evaluation.md). |
| Agent workflow inventory | [Agentic Radar](https://github.com/splx-ai/agentic-radar/tree/65a7e4bd01e2034c7cb52e9620eeed287688cc53) | Apache-2.0 | Published offline native static workflow inventory over one typed framework and immutable repository snapshot; preserves incomplete diagnostics and produces observations only, never vulnerability findings. |
| Website passive findings | [OWASP ZAP](https://github.com/zaproxy/zaproxy/tree/2665d972f6d587ba4773a95053ac39af3fdf8df9) | Apache-2.0 | Explicit advanced passive website choice in v0.4.0. Crawls one exact authorized origin at 5 requests/s, preserving upstream alert identity, severity, remediation and per-instance evidence. Native per-request pacing, bounded automation-plan dispatch and recovery ownership are implemented. |
| Model behavior probes | [Garak](https://github.com/NVIDIA/garak/tree/93aa9cdec309ec4170559676f1826ea2a679920c) | Apache-2.0 | Published `0.17.0-1`; optional exact HTTPS/model checks with 54 native DAN/ANSI prompts, unchanged detectors, Unknown severity, one-shot local keys and explicit inference limits/provider charges. |

### Grype repository support

The current catalog pins `ghcr.io/ted-h-com/ai-security-scanner-engine-grype:0.120.1-1` to `sha256:9f030366bc950d408762adb2d641d70220fd6cee0175cbc5202e9418dbb05870`, with the October 14 schema v6.1.10 database. The [verified publication record](engines/updates/2026-10-14.md#verified-publication-and-catalog-activation) binds source provenance and both platform digests. The bounded native OCI fixture emits six Java vulnerability matches with original advisory IDs preserved.

The earlier source catalog at [commit 3990168](https://github.com/TED-H-com/ai-security-scanner/commit/3990168be5154804c8a70c97f8c8f6e827221cbc) pinned
`ghcr.io/teddashh/ai-security-scanner-engine-grype:0.117.0-4` to
`sha256:56b0d675e3b8d539890e853699c114493a72a54cca0bbe254eceee7ec2b4c517`.
The launcher accepts repository working-tree snapshots, allowing upstream Grype to report known
package vulnerabilities from recognized dependencies as well as single-image OCI inputs.

A controlled Linux repository scan after rebuilding that source recorded 81 Grype findings
(10 critical, 32 high, 33 medium, 6 low), status `completed`, exit code 0, and the pinned digest.
Its final HTML report preserved those results. Counts depend on the selected repository and pinned
database; this fixture result is not a coverage guarantee for another project.

Those 81 findings belong to the earlier fixture and database. Its pin commit recorded publication-metadata inconsistencies; the replacement above has separately verified signed provenance. Historical scan counts are not reused as measurements of the new image.


### Image admission

All 25 current catalog records are integrated and runnable. Research-only candidates are not current scan capabilities. A local build candidate is build evidence only and does not make a record dispatchable; registry blockers remain enforced until public artifact and execution evidence are admitted.

### Provider scope and credentials

An empty `supported_providers` list means provider-agnostic, not “all cloud providers.” CloudQuery, Steampipe, ScoutSuite, and Cloudsplaining are AWS-only; ScubaGear and Maester are Microsoft 365-only. Prowler accepts exactly one native asset and one complete, case-scoped ephemeral credential profile:

| Provider | Exact asset/profile | Credential consumed by engine | Fixed endpoint closure |
|---|---|---|---|
| AWS | One `cloud_account`; `aws_iam_service_exact_account` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`; STS identity must match the selected account | `iam.amazonaws.com:443`, `sts.us-east-1.amazonaws.com:443`, `ec2.us-east-1.amazonaws.com:443`, `organizations.us-east-1.amazonaws.com:443` |
| Azure | One enabled `subscription`; `azure_iam_service_static_token_exact_subscription` | `AZURE_ACCESS_TOKEN`; ARM must return the selected subscription | `management.azure.com:443` |
| GCP | One active `project`; `gcp_iam_four_checks_exact_project` | `GOOGLE_OAUTH_ACCESS_TOKEN`; exact-project permission and identity checks must pass | `cloudresourcemanager.googleapis.com:443` |

Bootstrap credentials never enter an engine.

### Greenbone components

The managed image uses only the direct scanner and pinned feed, not the broader Greenbone product stack:

| Component | Official source | License | Product use |
|---|---|---|---|
| OpenVAS Scanner | [greenbone/openvas-scanner](https://github.com/greenbone/openvas-scanner) | GPL-2.0-only | Included as pinned `openvasd`; source and project patches accompany the image. |
| Manager | [greenbone/gvmd](https://github.com/greenbone/gvmd) | AGPL-3.0 | Not used or distributed. |
| Web UI/API client | [greenbone/gsa](https://github.com/greenbone/gsa) | AGPL-3.0 | Not used or distributed. |
| Scanner protocol daemon | [greenbone/ospd-openvas](https://github.com/greenbone/ospd-openvas) | AGPL-3.0 | Not used or distributed. |
| Feed synchronization | [greenbone/greenbone-feed-sync](https://github.com/greenbone/greenbone-feed-sync) | GPL-3.0 | Not used at runtime; build imports one signed, checksum-verified, digest-pinned feed snapshot. |

The feed snapshot includes its executable NASL source, data, declared GPL/ODbL texts, revision, checksum manifest, and upstream detached signature. A new feed is a new pinned artifact; source-code licensing alone does not determine feed distribution.

## 4. Integration modes

1. **Verified upstream artifact:** preferred when upstream publishes a suitable image or binary. Retrieve only an exact digest/checksum; never `latest`.
2. **Project-built upstream image:** use when upstream has no suitable distributable image. Build the unmodified pinned upstream source plus the smallest launcher needed for the four adapter duties above.
3. **On-demand exact retrieval:** use for large or separately distributed artifacts. Show download size and preparation progress; failure affects only that engine’s coverage.
4. **Bundled offline data:** include only exact approved rules, templates, feeds, and databases with their hashes, notices, source/source offer where required, and SBOM.
5. **Host-native adapter:** use only when installation, isolation, update, and removal are product-managed. A beginner must not have to configure a language runtime or shell environment.

Process or container separation does not change upstream licensing. Every distributed engine, dependency, rule, template, feed, and database keeps its own obligations.

## 5. Research-only upstream candidates

These are evaluation references, not current capabilities or hidden dependencies.

| Area | Upstream source | Observed license | Evaluation question |
|---|---|---|---|
| Compliance queries | [Powerpipe](https://github.com/turbot/powerpipe) | AGPL-3.0 | Query-pack value, overlap, and redistribution. |
| Microsoft 365 | [Monkey365](https://github.com/silverhack/monkey365) | Apache-2.0 | Permission model and overlap. |
| External discovery | [OWASP Amass](https://github.com/owasp-amass/amass) | NOASSERTION | License and bounded discovery model. |
| Host posture | [OpenSCAP](https://github.com/OpenSCAP/openscap) | LGPL-2.1 | Content licensing and safe host access. |
| Host/SIEM | [Wazuh](https://github.com/wazuh/wazuh) | NOASSERTION | Whether continuous telemetry fits a snapshot case. |
| Host posture | [Lynis](https://github.com/CISOfy/lynis) | GPL-3.0 | Host execution and distribution model. |
| Terraform | [tfsec](https://github.com/aquasecurity/tfsec) | MIT | Overlap and upstream maintenance direction. |
| Finding workflow | [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | BSD-3-Clause | Import/deduplication reference; not a bundled server. |
| Asset graph | [Cartography](https://github.com/cartography-cncf/cartography) | Apache-2.0 | Graph weight and inventory overlap. |
| AWS IAM graph | [PMapper](https://github.com/nccgroup/PMapper) | AGPL-3.0 | Permissions and privilege-path value. |
| Identity paths | [BloodHound CE](https://github.com/SpecterOps/BloodHound) | Apache-2.0 | Deployment complexity and sensitive data. |
| Entra identity | [ROADtools](https://github.com/dirkjanm/ROADtools) | MIT | Permission and bounded-query profile. |
| Kubernetes posture | [kubeaudit](https://github.com/Shopify/kubeaudit) | MIT | Archived-upstream risk and overlap. |
| Runtime security | [Falco](https://github.com/falcosecurity/falco) | Apache-2.0 | Continuous monitoring versus snapshot lifecycle. |
| TLS | [testssl.sh](https://github.com/testssl/testssl.sh) | GPL-2.0 | Authorized-contact boundary and distribution. |
| External discovery | [Subfinder](https://github.com/projectdiscovery/subfinder) | MIT | Provider keys and passive/active source classification. |
| Dependency vulnerability | [OSV-Scanner](https://github.com/google/osv-scanner) | Apache-2.0 | Overlap and a lighter source first pass. |
| Web server testing | [Nikto](https://github.com/sullo/nikto) | NOASSERTION | License and active-test boundary. |
| Source-scan UX reference | [VibeScan](https://github.com/Armur-Ai/vibescan/tree/52efb12fdcd8118c6f0f2b642558b2f335e7bf66) | MIT at `52efb12fdcd8118c6f0f2b642558b2f335e7bf66` | Research only; `NOT_DISTRIBUTED`, not an engine. |

License identifiers for research entries are observations, not release approval. Re-evaluate the exact revision, dependencies, data, and redistribution terms before integration.

## 6. Supporting projects

OCSF and OSCAL are optional export/interchange coordinates, not scanners or security conclusions. AIDEFEND metadata is a versioned relationship aid for applicable AI-system findings, not a scanner, audit, certification, or affiliation. Tauri is the desktop shell. Podman is the packaged rootless runtime; QEMU/DTC, gvisor-tap-vsock, and vfkit are pinned platform components. Docker CLI/Compose are optional user-installed compatibility paths; Docker Desktop is neither bundled nor required. Exact sources and licenses remain in the generated notices, SBOMs, runtime manifest, and machine catalog.

## 7. Minimum engine record

Every runnable entry records:

- official upstream source, exact revision/version, retrieval URL, and immutable digest/checksum;
- `reported_version` for a source-built engine only: the release version the built scanner binary reports about itself, with no leading `v`;
- engine, dependency, image, rule/template/feed/database licenses and required notices or source offer;
- supported input kinds, providers, operating systems, and CPU architectures;
- truthful capability categories from section 2 and important exclusions;
- allowed targets, mounts, credentials, outbound endpoints, time/rate/output/resource limits;
- upstream raw-output retention and a versioned structural adapter fixture;
- knowledge date, support-until date, update owner, and replacement path.

The maintenance procedure is defined in [engine-maintenance.md](engine-maintenance.md).
