# Current product review

Reviewed: 2026-10-03

Canonical behavior: [Product specification](product-spec.md)

## Product outcome

The desktop app provides one primary IT-environment path and two single-target shortcuts:

- combine multiple repository folders, website URLs, and approved internal systems in one scan;
- check one website or API origin;
- check one local project folder.

The user reviews the exact assets once and starts one run. Applicable scanners receive only their assigned assets. Completed sibling outcomes survive an independent check failure. Terminal results, reopen, comparison, and readable HTML export use the same report model.

## Beginner journey

| Stage | Current behavior |
| --- | --- |
| Home | Leads with IT environment, website, and project-folder outcomes. Advanced sources and localhost connectivity remain secondary. |
| Setup | Accepts repeatable folders, complete URLs, and exact internal hosts. Internal hosts receive common ports by default; Advanced can replace them with up to 64 exact ports. |
| Review | Groups exact assets, assigns applicable security checks, shows network boundaries, and provides one Start action. |
| Progress | Shows the active asset and check, confirmed problem count, completed, remaining, and attention-needed work. Tool preparation uses the same view. |
| Results | Opens only for terminal runs and gives every selected asset one result state. Problems, actions, coverage, and observed services remain distinct. |
| Export | Produces readable HTML and specialist formats from the terminal report model. |

Inventory-only input remains in Setup until a scan-ready asset is selected. The localhost TCP utility reports only connectivity. Results require a security-relevant upstream check or a terminal record that identifies the untested work.

## Repository checks

The app creates a bounded private snapshot and runs applicable upstream tools:

- Gitleaks and TruffleHog for secrets;
- Semgrep for risky code patterns;
- Trivy and Grype for vulnerable dependencies;
- Checkov and KICS for infrastructure configuration;
- Syft for component inventory.

Adapters preserve upstream identifiers, severity, locations, evidence, and remediation. Repository ignore rules remove generated, dependency, build, cache, and VCS trees while retaining common secret-bearing source files for secret inspection.

The published and catalog-pinned Trivy `0.74.0-4` image includes checksum-pinned offline JAR identification through Trivy's standard Java index and vulnerability database. Semgrep `1.174.0-4` combines 1,493 legacy upstream rules with four product rules; its dated LGPL and Commons Clause notices and original rule sources are retained. See the [image build and update notebook](engines/image-build-index.md) and [Semgrep publication record](engines/semgrep-publication-2026-10-03.md).

## Website checks

The website path runs pinned Nuclei automatic scan against the confirmed origin. Nuclei performs upstream technology detection and chooses matching vulnerability and exposure templates from the pinned read-only snapshot. Each selected website receives its own engine run, so one website failure does not remove another website's result.

The adapter distinguishes a completed non-match from an empty or failed execution record. Positive findings preserve the upstream template ID, severity, evidence, and remediation.

## Internal-system checks

Each internal system is one exact hostname or IP address with confirmed ports. The generic Greenbone profile derives current, non-deprecated, unauthenticated remote `gather_info` VTs from the pinned Community Feed. Greenbone controls service detection, product detection, dependencies, prerequisites, severity, evidence, and solution.

Only `alarm` records become vulnerability findings. Unrated alarms remain **Unknown**. Scanner errors and non-responsive hosts become incomplete asset coverage with a direct next action. Informational `log` records remain technical evidence. Saved legacy single-service profiles retain their original host, protocol, and port boundaries.

The published and catalog-pinned Greenbone `23.50.24-feed202610010558-1` image carries the typed result contract and the current feed snapshot.

## Advanced sources

Infrastructure files, Kubernetes manifests, exported container images, cloud accounts, and live clusters remain available as secondary sources. Each uses its selected artifact, resource, account, subscription, project, or cluster scope.

The published and catalog-pinned kube-bench `0.16.0-4` image uses the unmodified upstream CIS 1.11 node profile. The v0.3.1 desktop adapter records WARN checks as incomplete automated coverage without turning them into failed findings. KICS similarly withholds completion when its declared file or query failure counters are positive or malformed.

The published and catalog-pinned Maester `2.0.0-9` image preserves upstream `Investigate` as a no-verdict control instead of a failed finding. ScubaGear `1.8.0-8` and the revised Microsoft 365 setup include the approved PIM read permissions. A fresh owner-run Microsoft 365 acceptance scan has not yet been observed.

GCP Prowler currently uses its reviewed four-check permission and endpoint closure. Widening that profile requires one coordinated product decision covering checks, permissions, assets, endpoints, and report wording.

Prowler headlines describe the failed condition. The approved AWS grouping combines findings with the same practical action while retaining every underlying identifier and evidence record. Expired read-only connections offer reconnect-and-rescan directly.

## Unified report

The first layer answers:

1. Which assets have problems?
2. What matters first and what is the impact?
3. What is the smallest next action and how is the fix verified?
4. Which checks completed for each asset?
5. Which requested work is incomplete or untested?

Findings retain scanner provenance under the product explanation. Each completed check shows its scanner version and last-updated date; scanner age is never reported as expiry or incomplete coverage. Cross-engine ordering, grouping, deduplication, localization, and framework references belong to the shared report layer. Observed services appear in their own non-vulnerability section. Formal report terms and technical records appear at the end.

Terminal runs include completed, completed with gaps, no checks completed, failed, and cancelled outcomes. Runs without a comparable completed check remain visible in Results and Export but are not offered as verification baselines.

## Engineering closure

The in-repository beginner journey and its native report boundary were re-audited through case setup,
scope review, progress, terminal results, reopen, comparison, and export. Cross-language tests now bind
every closed report vocabulary plus the case, coverage, guided-route, source, permission, engine-status,
task-provenance, and packaged-engine metadata used to decide what the reader sees. Unknown native
permissions and task kinds fail closed: they cannot create authorization, scanner provenance, completed
work, or covered-asset credit.

The 2026-09-15 automated baseline completed with 1,691 Rust tests, 678 frontend tests, 263 component tests, 46 CI
contract tests, and 8 engine-catalog tests, together with TypeScript checking, production build, Rust
formatting, Clippy, mapping validation, and the five-scenario usability-evidence contract. The usability
record contains no human session, and this review does not claim installed-product acceptance.

## Current acceptance work

The next installed-product acceptance uses the published desktop installer to complete one controlled mixed IT-environment run through Setup, Review, Progress, Results, reopen, and readable HTML export. It records time from asset entry to the first useful security result.

The [desktop release readiness record](release/desktop-readiness-2026-10-03.md) tracks the candidate build, installed check and Microsoft 365 follow-up. Image-source updates enter a release only after their new immutable coordinates are published and selected in the engine catalog. GCP Prowler remains at its current reviewed scope until the wider product contract is selected.
