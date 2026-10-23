# October 2026 incident triage

The optional **October incident triage** mode selects only applicable **Trivy
package checks** from the existing authorized local-asset plan. It uses the same
app and unified terminal report. The owner-requested v0.5.3 incident scan pack publishes this mode alongside the standard scan in the same cross-platform app. See [the download entry](../incident-october-21.html).

Repositories, IaC copies and supported OCI image layouts use their existing
Trivy package profiles. Websites and internal hosts are excluded: the latest
4,775 safe Nuclei templates have no intersection with this campaign's CVEs,
and the new PHP template is an intrusive crash probe. No verified applicable
Community Feed check justifies adding Greenbone to this focused plan. The
mixed-environment setup lists excluded assets and their count before starting;
they receive no authorization or scanner route in this run. Website-only setup
does not offer this mode. Existing general scan profiles remain available.

The campaign filter never adds an asset, port, credential, scope grant, template,
network destination or remediation action. Upstream package detection remains
unchanged; exact incident correlation happens in the shared report. This is
package triage, not a promised execution time or a custom exploit detector.

The report records the campaign with the run and gives each published advisory
an asset-specific coverage row. An exact advisory identifier in current-run
upstream evidence links the original finding. Severity, evidence, fixed-version
data and remediation remain owned by the upstream finding. A linked finding for
one member of a multi-CVE incident does not prove the entire chain was exercised.
No match means **Not tested** for the specific incident: ordinary engine success
or zero findings cannot establish that its detector ran. The report distinguishes
an absent applicable check, old or undated scanner knowledge, and an unverified
specific check. General security findings remain in the unified report.

Account and supply-chain investigations get separate **Investigation needed**
rows. ZDI candidates awaiting verified CVE/package mappings get **Advisory pending** rows. These are
coverage and next-action records, not synthetic vulnerabilities. An imported
external scanner report retains its own provenance and cannot become proof of a
locally executed campaign check.

## Evidence reviewed on 2026-10-22

The machine-readable source of incident context is
[`engines/campaigns/october-2026.json`](../../engines/campaigns/october-2026.json).
Its versions are advisory context, not product-owned version comparators.
Distribution backports and actual deployed runtime versions still matter.

| Requested issue | Verified primary-source facts | Coverage in this mode |
| --- | --- | --- |
| PHP2Shell | PHP CVE-2026-109618 and CVE-2026-109619; fixed 8.2.35, 8.3.36, 8.4.27 and 8.5.12; CVSS 4.0 9.2. [PHP Foundation](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/) | Correlates an exact upstream advisory finding. Trivy 0.76.1 with the October 22 upstream DB detected both IDs in an inert Ubuntu package fixture. The latest Nuclei template is an intrusive crash probe and is excluded. |
| Plex2Shell | Plex identifies CVE-2026-96652, -96654, -96655 and -96656; fixed 1.43.3.10861; vendor describes active exploitation. Its update is dated October 19, not October 21. [Plex](https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319/3) | Exact upstream findings only; version inventory does not establish compromise. |
| eMudhra | Vendor confirms eight weak intermediate keys and distinguishes these from other CA keys. [eMudhra](https://emudhra.com/en/press-release/emudhra-statement-distrust-global-tls-intermediate-root-ca) | Client trust-store and certificate investigation; a web scan cannot audit every consuming client. |
| CyberCartel / Claude / Grok | Straiker describes a threat actor's use of AI services. [Original researcher](https://www.straiker.ai/blog/inside-carliy0s-how-cybercartel-used-multiple-ai-models-to-attack-latin-american-banks) | Incident investigation, not a vulnerability in every installation of a named AI service. |
| Railway | Provider discloses possible access to customer environment variables. [Railway](https://blog.railway.com/p/security-disclosure-wednesday-october-21st) | Account and service audit investigation; no account contact or credential collection in this mode. |
| LiteLLM | Vendor confirms 1.107.0 compromise and cautions against starting Python/pip in affected environments. [LiteLLM](https://docs.litellm.ai/blog/security-incident-oct-21-2026) | Offline inventory and incident investigation; a repository manifest cannot establish past execution or credential theft. |
| Storm-0940 / ARTEX / ConnectWise / M365 | Microsoft describes compromised application identities and provides tenant investigation guidance. [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/) | Tenant sign-in/audit investigation; no posture result is relabeled as compromise detection. |
| Node.js updates | Fixed 22.23.4, 24.22.1, 26.12.1; vendor's highest severity is High. [Node.js](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) | Exact upstream advisory findings; deployed runtime can be absent from a source snapshot. |
| Go distrust update | CVE-2026-111943; crypto/x509 rejects affected intermediate chains; releases 1.26.10 and 1.27.3 dated October 19. [Go issue](https://github.com/golang/go/issues/82345), [release history](https://go.dev/doc/devel/release#go1.27.3) | Exact upstream advisory findings for supported artifacts; deployed Go applications need their own rebuild/deployment review. |
| GitLab emergency update | CVE-2026-110264, CVSS 3.1 10.0; seven branch fixes listed by GitLab. [GitLab](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/) | Exact upstream advisory findings; no crafted-regex payload. |
| Onamae breach | Notice concerns Desktop Cloud; provider reports unauthorized programs on some servers. [Onamae](https://www.onamae.com/news/article/11584) | Provider and endpoint investigation, not all domains registered through Onamae. |
| ZDI-CAN-33549 / -33774 / -33367 / -34068 / -34076 | ZDI lists Linux candidates with October 21 vendor-contact dates; original reports also appeared on public kernel mailing lists. [ZDI upcoming advisories](https://www.zerodayinitiative.com/advisories/upcoming/) | Primary ZDI/maintainer mail confirms all five mechanisms; no verified public CVE or distribution fixed-package mapping. KSMBD has a maintainer-referenced fix commit. |
| ZDI-CAN-32005 | ZDI lists **ConnMan**, with October 19 vendor contact. [ZDI upcoming advisories](https://www.zerodayinitiative.com/advisories/upcoming/) | Userspace ConnMan is not a Linux-kernel CVE. No verified public mapping or detector. |

The original reports and maintainer replies now verify five Linux mechanisms:

| Candidate | Primary mailing-list evidence | Patch mapping as checked October 22 |
| --- | --- | --- |
| ZDI-CAN-33549 | [ZDI report](https://lists.openwall.net/linux-kernel/2026/10/21/2666), [maintainer reply](https://lists.openwall.net/linux-kernel/2026/10/21/2732) | Maintainer asks for retesting the `for-7.5/smbdirect` development branch; this is not a released-fix guarantee. |
| ZDI-CAN-33774 | [ZDI report](https://lists.openwall.net/linux-kernel/2026/10/21/2694), [maintainer fix reference](https://lists.openwall.net/linux-kernel/2026/10/22/1149) | Maintainer identifies `68f410faedaf6ee74d81e574733c50ebcc1bd8ed` in the SMB tree. No distribution package or stable release mapping verified. |
| ZDI-CAN-33367 | [ZDI report](https://lists.openwall.net/linux-kernel/2026/10/21/2711), [network maintainer reply](https://lists.openwall.net/linux-kernel/2026/10/22/297) | Maintainer says a separately submitted patch will be available; no released-fix mapping verified. |
| ZDI-CAN-34068 | [Maintainer reply quoting the ZDI report](https://lists.openwall.net/linux-kernel/2026/10/22/308) | Confirms vmwgfx dirty-tracking out-of-bounds write; no patch supplied in that report. |
| ZDI-CAN-34076 | [Maintainer reply quoting the ZDI report](https://lists.openwall.net/linux-kernel/2026/10/22/310) | Confirms nvmet Get Log Page uninitialized resource; no patch supplied in that report. |

These are original messages archived by Openwall, not third-party descriptions.
Direct lore.kernel.org retrieval returned HTTP 403 during this review. The
ConnMan detailed report was not retrieved, so its supplied mechanism remains
unverified. All six candidates still lack a verified public CVE mapping and
stay **Advisory pending**. ZDI's scheduled disclosure dates are not evidence
that the mailing-list reports are private, and a development-branch fix does
not determine a distribution package's patch status.

## Upstream execution verified October 22

The current official Nuclei tree at
[`f938a3dd530c283e9387b518b97911152ff5846c`](https://github.com/projectdiscovery/nuclei-templates/tree/f938a3dd530c283e9387b518b97911152ff5846c)
contains `CVE-2026-109618.yaml`. Its upstream `intrusive` tag and active memory
exhaustion/crash behavior exclude it from this mode. It was inspected, not run.
No local substitute or header-version comparator was authored. The checked
safe-profile intersection is recorded in
[`2026-10-22-runtime-inputs.json`](updates/2026-10-22-runtime-inputs.json),
including all 18 campaign CVEs and the excluded PHP match. Only Trivy is
selectable for new campaign runs; per-issue Nuclei/Greenbone identifiers are
retained solely for interpreting immutable historical evidence.

[Greenbone's October 22 update](https://www.greenbone.net/en/blog/php2shell-remote-code-execution-cve-2026-109618-cve-2026-109619/)
announces Enterprise Feed PHP version and distribution-package checks. This
announcement does not verify their availability in the product's packaged
Community Feed, nor their execution for any asset. Existing Greenbone coverage
therefore remains evidence-dependent.

[Trivy DB](https://github.com/aquasecurity/trivy-db) aggregates distribution
advisories. The official DB dated `2026-10-22T13:15:26.425424764Z`, OCI manifest
`sha256:4bf3ae89527fbbb3596748b1c9d294a8b240c49edc9f87e65947e42291bb0bf6`,
was tested with the official Trivy 0.76.1 binary and the same OS-only arguments
used by the existing managed OCI profile. [Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1)
provides the package-specific fix; upstream PHP version arithmetic is not used.

| Inert Ubuntu 24.04 fixture | Actual upstream result |
| --- | --- |
| `php8.3-cli` `8.3.6-0ubuntu0.24.04.12` | Both CVE-2026-109618 and CVE-2026-109619; upstream fixed version `8.3.6-0ubuntu0.24.04.13` |
| `php8.3-cli` `8.3.6-0ubuntu0.24.04.13` | Neither of those two CVEs returned |

The fixtures contain only Ubuntu release files and dpkg package metadata. They
contain no PHP executable or exploit and contact no scan target. Reproduce with
[`generate-php-oci.py`](../../tests/fixtures/incident-triage/generate-php-oci.py)
and [`verify-trivy-php.py`](../../tests/fixtures/incident-triage/verify-trivy-php.py).
This confirms upstream package matching for these fixtures; a user's assets
still require their own immutable scan evidence. The campaign does not turn a
zero-finding run into an all-incident clean verdict.

## Offline Linux inventory boundary

The existing **OCI image layout** input is reusable for OS package assessment:
Trivy reads the selected image's release metadata and package database without
starting it. Distribution backports are evaluated by Trivy's distribution feed.
A container-image result describes that image, not the host's running kernel.

There is no existing general host-inventory/SBOM import profile for managed
Trivy scans. Repository and IaC profiles deliberately select library packages;
the Kubernetes node snapshot is a configuration-check input. Selecting a
repository containing `uname` output or a copied package list therefore does
not establish kernel-vulnerability coverage. The fixture generator is test
support, not an automatic conversion of a live host into an authorized asset.
No candidate-specific Linux detector or package comparator is added. Even a
complete kernel package inventory cannot resolve these six candidates until
upstream public advisory and distribution mappings are available.

## Implementation and validation

For an existing case with an approved repository, the CLI can persist a focused
plan with an explicit engine selection:

```sh
ai-security-scanner-cli scan plan --case-id CASE_ID --campaign october-2026 --engine trivy
```

Non-Trivy engines and empty selections are rejected for this campaign.
The planner still checks applicability and scope. `scan plan` records the plan
without starting scanners; use the desktop scan controls for execution. An
empty engine selection is rejected when a campaign is specified. To plan a
repeat of a terminal focused run, `scan rescan-plan --case-id CASE_ID
--baseline-run-id RUN_ID` preserves its campaign and original asset routing.

`src/incidentFocusProfile.ts` restricts existing frontend engine routes and
provides localized labels. `src-tauri/src/incident_focus.rs` validates the same
selection against the shared JSON and projects incident coverage into the shared
beginner report. The normal planner continues to enforce authorization and
per-asset applicability. Traditional Chinese incident explanations and next
actions come from that same JSON in the app and HTML export; original upstream
evidence remains unchanged.

Tests exercise route narrowing, unknown/empty selections, exact current-run
identifier matching, asset and engine identity, legacy and imported evidence,
inventory-only observations, misleading titles/tags, and unavailable candidates.
These tests validate reporting semantics; they are not proof that an upstream
feed contains newly disclosed detectors. Do not promote a pending row to tested
without upstream execution evidence.

## Local incident candidate

The owner-requested Linux candidate is assembled from an isolated working-tree
snapshot, leaving the stable version and installed engine catalog unchanged.
`scripts/release/prepare-incident-candidate.mjs` requires the two genuinely built
and exercised local engine images, verifies their OCI archives and execution
evidence, and checks every staged runtime file against its manifest. It then
patches the snapshot's prerelease version, candidate catalog and Nuclei revision,
with automatic updates disabled.

After rebuilding the desktop and all three sidecars from that snapshot,
`scripts/release/assemble-incident-candidate.mjs` takes its Debian package and
creates a portable directory containing the app, exact digest-keyed local OCI
archives, original qualification output, source hashes and `SHA256SUMS`.
Its `launch.sh` uses a separate version-specific data directory and points at
those bundled resources. A bare Debian package is an intermediate build output;
the local images travel with the portable candidate. The candidate remains
unpublished and unsigned, with its Linux build and smoke evidence recorded
separately from any future public release decision.
