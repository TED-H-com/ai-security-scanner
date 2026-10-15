# Engine image build and update notebook

Recipe and patch records reviewed on 2026-10-03, with the [October 14 upstream source refresh](updates/2026-10-14.md) incorporated below. The earlier maintenance baseline is `38f912f`. This index describes the recipes that exist; it does not certify that every current recipe builds or matches its published image. The per-engine pages contain the detailed invocation, adapter fields, fixtures, downstream changes and incident history.

There are **25 catalog engines with 25 distinct primary upstream repositories**, **23 scanner Dockerfiles**, and **one additional egress gateway Dockerfile**. KICS and ZAP use upstream images. Garak has a published and independently verified dedicated HTTPS model-probe image. Agentic Radar has a published and independently verified dedicated offline image. Plugins, rule repositories, Semgrep submodules, PowerShell modules, feeds, vulnerability databases and toolchains add more upstream inputs; 25 is not the count of the complete dependency closure.

The checked-in Semgrep lock now declares **one additional repository URL**, the reviewed legacy rules archive, disjoint from those 25 primary URLs: **26 declared repositories** before counting the other engines' secondary sources or package dependencies. Semgrep 1.181.0 vendors the 35 compiler/parser source trees previously acquired separately. This count describes source acquisition; the vendored components and their notices remain part of the dependency closure.

## Start an update here

1. Read the engine page's **Downstream changes**, **Lessons from real runs** and **Updating this engine**. Read its shared launcher page too. These explain why a customization exists and when it can be removed.
2. Establish two baselines: the catalog's digest-qualified **published image**, and the **current build inputs**. Compare the plan's publication source commit with current Dockerfile, patches, launcher and data locks. A current plan hash or documentation claim alone does not prove what is in an older image. Research checkouts in `engines/upstreams.lock.json` can differ from image-source pins.
3. Review the upstream change for CLI, report schema, rule IDs, severity, messages, fixes, dependencies and offline support. Re-evaluate each patch against unmodified upstream before rebasing it. Record a missing upstream issue/removal condition as missing; do not invent one.
4. Change the source/archive checksums, dependency locks, rule/data closure and the corresponding runtime verification hashes together. Use the table below to find engine-specific coupling, then the engine page for exact files and tests.
5. Validate locally with bounded synthetic fixtures. Keep native output, normalized results, errors and omissions. Version output or valid JSON alone does not show that a meaningful check ran. Never replace a failed pinned acquisition with a floating input.
6. Add a dated record using the template below. Publishing, new tags, signing and release timing remain the owner's separate decision; a local recipe is not permission to publish.

See the [maintenance procedure](../engine-maintenance.md) for adapter/report boundaries and the separate [publication procedure](README.md#shipping-an-engine-image-change) when publication is requested.

## Local build contexts and host preparation

Run these from the repository root. **Dockerfile location is not the build context.** The root context is needed whenever a Dockerfile copies a shared launcher, root license, patch under `docs/`, or prepared cache. Checkov and Syft are the two narrow-context exceptions.

| Engine / detailed notes | Dockerfile / context | Host preparation before a build |
| --- | --- | --- |
| [CloudQuery](cloudquery.md) | [Dockerfile](../../engines/images/cloudquery/Dockerfile) / `.` | None; checksum-pinned binaries and three component source archives are acquired in the build. |
| [Steampipe](steampipe.md) | [Dockerfile](../../engines/images/steampipe/Dockerfile) / `.` | None; CLI/plugin/FDW source and architecture-specific PostgreSQL closure are acquired in the build. |
| [Prowler](prowler.md) | [Dockerfile](../../engines/images/prowler/Dockerfile) / `.` | None; rebase on a pinned upstream image and apply the six local patches. |
| [ScoutSuite](scoutsuite.md) | [Dockerfile](../../engines/images/scoutsuite/Dockerfile) / `.` | None; source preparation, patch and dependency install run inside the build. |
| [Cloudsplaining](cloudsplaining.md) | [Dockerfile](../../engines/images/cloudsplaining/Dockerfile) / `.` | None; source archive contains the upstream `uv.lock`. |
| [ScubaGear](scubagear.md) | [Dockerfile](../../engines/images/scubagear/Dockerfile) / `.` | None; shared source preparer verifies the locked engine/modules; OPA is bundled. |
| [Maester](maester.md) | [Dockerfile](../../engines/images/maester/Dockerfile) / `.` | None; shared source preparer verifies the locked engine/modules. |
| [Naabu](naabu.md) | [Dockerfile](../../engines/images/naabu/Dockerfile) / `.` | None; pinned source build. |
| [httpx](httpx.md) | [Dockerfile](../../engines/images/httpx/Dockerfile) / `.` | None; pinned source build and local DNS patch. |
| [Nuclei](nuclei.md) | [Dockerfile](../../engines/images/nuclei/Dockerfile) / `.` | None; scanner and template archives are acquired in the build. |
| [Greenbone](greenbone.md) | [Dockerfile](../../engines/images/greenbone/Dockerfile) / `.` | None; source, native dependencies, feed and Notus are acquired in the build. |
| [Semgrep](semgrep.md) | [Dockerfile](../../engines/images/semgrep/Dockerfile) / `.` | `node scripts/prepare-offline-engine-data.mjs semgrep`; published legacy + four-rule pack retains Commons Clause. See the [publication and native verification recipe](semgrep-publication-2026-10-03.md). |
| [Gitleaks](gitleaks.md) | [Dockerfile](../../engines/images/gitleaks/Dockerfile) / `.` | None; fixture copy restored and clean native amd64 build/meaningful redacted scan verified on 2026-10-03. Signed `8.30.1-2` publication and both platform evidence verified; catalog pinned. |
| [TruffleHog](trufflehog.md) | [Dockerfile](../../engines/images/trufflehog/Dockerfile) / `.` | None; pinned source build. |
| [Checkov](checkov.md) | [Dockerfile](../../engines/images/checkov/Dockerfile) / `engines/images/checkov` | None; `prepare_source.py` runs inside the build. |
| [Trivy](trivy.md) | [Dockerfile](../../engines/images/trivy/Dockerfile) / `.` | `node scripts/prepare-offline-engine-data.mjs trivy` |
| [Grype](grype.md) | [Dockerfile](../../engines/images/grype/Dockerfile) / `.` | `node scripts/prepare-offline-engine-data.mjs grype` |
| [Syft](syft.md) | [Dockerfile](../../engines/images/syft/Dockerfile) / `engines/images/syft` | None; rebase on a pinned upstream image. |
| [Kubescape](kubescape.md) | [Dockerfile](../../engines/images/kubescape/Dockerfile) / `.` | None; three checksum-pinned policy files are acquired in the build. |
| [kube-bench](kube-bench.md) | [Dockerfile](../../engines/images/kube-bench/Dockerfile) / `.` | None; upstream benchmark files plus the product's snapshot path config are bundled. |
| [MCP Armor](mcp-armor.md) | [Dockerfile](../../engines/images/mcp-armor/Dockerfile) / `.` | None; source, config-only patch and requirements lock are build inputs. |
| [KICS](kics.md) | No local Dockerfile | Pull the catalog's upstream image by digest; queries belong to that image. |
| [ZAP](zap.md) | No local Dockerfile | Digest-pinned native passive website execution; bounded automation plan and exact gateway scope. |
| [garak](garak.md) | [Dockerfile](../../engines/images/garak/Dockerfile) / `.` | None; unchanged native source, 36 hash-locked runtime wheels, separate build tools, pinned langdetect source wheel, dedicated scope/credential launcher and bounded native REST transport. Six-case TLS QA passed locally and again by public amd64 digest; public dual-platform bytes and signed provenance are independently verified. |
| [Agentic Radar](agentic-radar.md) | [Dockerfile](../../engines/images/agentic-radar/Dockerfile) / `.` | None; hashed native source, machine-output patch, dedicated launcher and separate runtime/build wheel locks. Published `0.14.1-1`; native five-framework, empty-state and dotenv/code-isolation QA repeated with the public image, anonymous bytes and signed source evidence verified. |
| [Egress gateway](egress-gateway.md) | [Dockerfile](../../engines/images/egress-gateway/Dockerfile) / `.` | None; project Rust source. Runtime pin is in [managed-egress-gateway.json](../../runtime/managed-egress-gateway.json), outside the scanner catalog. |

For an engine with a Dockerfile, this builds a **local, single-platform review image**:

```sh
# Run from the repository root. Choose an engine from the table above.
engine_id=prowler
build_context=.
case "$engine_id" in
  checkov|syft) build_context="engines/images/$engine_id" ;;
esac
test -f "engines/images/$engine_id/Dockerfile" || exit 1
case "$engine_id" in
  semgrep|trivy|grype)
    node scripts/prepare-offline-engine-data.mjs "$engine_id" || exit 1 ;;
esac
nice -n 10 docker buildx build \
  --platform linux/amd64 --load \
  --file "engines/images/$engine_id/Dockerfile" \
  --tag "aiss-local/$engine_id:review" "$build_context"
```

Use `linux/arm64` for a separate arm64 review. One local platform proves only that platform; `--load` here does not publish a multi-platform index. Run one heavy build at a time on a shared machine. Some stages download pinned dependencies; **offline scanner execution does not mean an offline image build**. Check each Dockerfile's `RUN --network=none` smoke separately.

`nice` on the Docker client does not bound the daemon's build workers. Use a task-owned builder with explicit CPU/memory limits, and constrain its CPU affinity when an upstream recipe uses `make -j"$(nproc)"` (Greenbone does). A CPU quota alone can still leave `nproc` seeing more processors and launching too many compilers. The [Semgrep ARM64 example](semgrep-combination-review.md#arm64-local-validation-attempt) shows an isolated builder; its four-CPU affinity was checked with `nproc`. Do not reconfigure another project's builder or install global emulation interpreters for a local review.

Separate architecture evidence into source/config assembly, actual binary execution, a fresh image build and native managed execution. Reusing a published binary with new read-only inputs does not prove a new image compiled. Before trusting an emulator for safety checks, test read-only and writable mounts plus child execution/status propagation; the [Semgrep helper follow-up](semgrep-combination-review.md#follow-up-local-glibc-helper) records a measured statfs limitation, a local testing workaround and its remaining constraints.

Only Semgrep, Trivy and Grype consume host `.engine-cache/offline/` inputs today. The preparation script checks download size and digest; the image build also verifies the inputs it consumes. Trivy needs **both** its vulnerability DB and Java DB. Grype needs the archive and matching `import.json`. Cache availability is not proof that the data matches a newly edited pin.

## Secondary inputs to inspect with the scanner

An engine-source update does not automatically update its rules, plugins or data. These records show where the additional inputs are acquired and why they need their own review; the per-engine page supplies the full recipe.

| Engine | Additional sources and acquisition record | Update detail to retain |
| --- | --- | --- |
| CloudQuery | [Three-component lock](../../engines/images/cloudquery/dependencies.lock.json): CLI, AWS source and file destination come from three different revisions of one repository. | Match every architecture-specific binary to its own source archive; a shared repository URL does not mean one source revision covers all three. |
| Steampipe | [Dockerfile](../../engines/images/steampipe/Dockerfile): `turbot/steampipe-plugin-aws`, `turbot/steampipe-postgres-fdw`, embedded PostgreSQL and its installer. | Scanner, plugin and native database closure can change independently; retain architecture-specific installation and ownership checks. |
| ScubaGear / Maester | Separate [ScubaGear lock](../../engines/images/scubagear/dependencies.lock.json) and [Maester lock](../../engines/images/maester/dependencies.lock.json): PowerShell runtime, Graph SDK packages and their source/notices; ScubaGear also uses YAML and OPA, Maester uses Pester. | Package version/hash, source revision and license bytes are separate fields. The two engines use different Graph SDK versions and module selections. |
| Nuclei | [Dockerfile](../../engines/images/nuclei/Dockerfile): `projectdiscovery/nuclei-templates` has a separate archive pin. | Preserve the selected HTTP template/dependency closure and original template IDs; changing scanner source alone does not advance template knowledge. |
| Semgrep | [Legacy-rule archive lock](../../engines/images/semgrep/submodules.lock), vendored compiler/parser sources, upstream opam locks and static-curl hook; [source refresh](updates/2026-10-14.md). | The 1.181.0 recipe uses vendored compiler/parser trees and retains the reviewed 1,493 upstream rules plus four product rules. Check runtime configs, attached originals and intermediate cache layers separately. |
| Greenbone | [Dockerfile](../../engines/images/greenbone/Dockerfile): separate VT-feed and Notus images, scanner archive with vendored Kerberos/libpcap, and native build/runtime packages. | Feed and Notus signatures/content must agree with their own acquisition records. A scanner rebuild does not establish that an older feed can still be retrieved. |
| Trivy / Grype | [Host acquisition script](../../scripts/prepare-offline-engine-data.mjs), separate [Trivy notice](../../engines/images/trivy/DATABASE-NOTICE.md) and [Grype notice](../../engines/images/grype/DATABASE-NOTICE.md). | Trivy's vulnerability/Java DB pair and Grype's schema/import metadata are independently pinned data, with dates distinct from scanner versions. |
| Kubescape | [Dockerfile](../../engines/images/kubescape/Dockerfile): three `kubescape/regolibrary` assets. | The release URL is mutable; checksum, launcher and notice must identify the same NSA framework, inputs and exceptions. |
| Source-built engines and gateway | Upstream `go.sum`, `uv.lock`, opam dependency locks or `Cargo.lock` inside the pinned source; local Python requirement locks where supplied; gateway [Cargo.lock](../../Cargo.lock). | Record the package/toolchain lock and actual install mode as part of the build. Transitive packages and OS repositories extend this inventory beyond explicitly listed Git repositories. |

For each changed input, retain its acquisition URL, immutable revision/digest, original bytes or cache location, data date, runtime use and source/notice destination. A byte-identical compiler cache can be reused for a rule-only change only when the recipe keeps those stages independent. Record native versus emulated execution explicitly; a successful emulated smoke does not establish native performance.

## Rules, customizations and edits that move together

Common to every update: actual acquisition pin, catalog/provenance and plan facts must agree with the tested closure. Base images, source archive hashes, dependency locks, source/notices and smoke expectations need review when their bytes change. Inspect the contents of attached source archives as well as runtime inputs: Semgrep's published four-rule runtime already contained newer restricted rules in its source attachment ([verified evidence](semgrep-combination-review.md#published-source-attachment-inspection)). The table adds engine-specific work; exact hashes stay in the machine-readable files rather than being copied here.

| Engine | Rules or data used | Customization to re-check; coupled edits and pitfalls |
| --- | --- | --- |
| CloudQuery | CLI + AWS source + file destination; seven IAM parent tables and dependent table evidence | **Frozen public closure**, not a routine move to latest. Keep `dependencies.lock.json`, `plugins.yml`, `cloudQueryConfiguration()`, allowed AWS actions/endpoints and validator constants in step. CLI/plugin binary hashes are per architecture. Three source archives must correspond to the shipped binaries. It is inventory; credential-report rows lack `account_id`, and dependent tables stay raw. |
| Steampipe | CLI, AWS plugin, FDW/PostgreSQL installation; fixed `aws_iam_user` query | Re-check `installprep`, seeded installation, FDW/source notices, non-root ownership and writable runtime directories. CLI, plugin and embedded PostgreSQL versions are separate. Preserve inventory semantics and exact AWS-account checking. |
| Prowler | Checks bundled in the upstream image; fixed AWS/Azure/GCP product profiles | Six ordered runtime patches are hash-bound in the applicator, patch series, plan and validator. Azure static-token IAM and GCP exact-project behavior are downstream exceptions. Try removing each patch first; keep organization/subscription enumeration disabled. Status detail supplies the finding title; original description remains evidence. |
| ScoutSuite | Checks bundled in the source archive | Rebase the JSON-only patch, source preparer's expected hashes and hashed Python lock together. Preserve the fixed provider scope and pinned source offer. JSON-only reporting must still contain completed checks and expose provider failures. |
| Cloudsplaining | Upstream IAM policy risk logic and dependency lock | Move the archive, upstream `uv.lock` hash, labels/plan and shared launcher together. Re-check downloaded authorization details, nested policy/principal output, and pass-through network bridge. Equivalent risks are grouped by the shared report layer, not detector changes. |
| ScubaGear | Source Rego/baselines, OPA, Graph authentication and YAML module | `dependencies.lock.json`, shared `prepare_source.py` contracts, Dockerfile, wrapper provenance and notices must agree. Re-derive read permissions from upstream's BOM-prefixed API catalog and synchronize the five product permission lists. AAD-only scope, criticality mapping, disputed verdicts and badge removal are explicit customizations. Live completion is not established by the workflow's fake-token rejection smoke. |
| Maester | Upstream test suite, Pester, Graph authentication | Move lock, preparer contract, Dockerfile/module licenses and both PowerShell runner files together. Retain the approved test selection and structured skipped/not-evaluated counters. Re-check tenant verification, read permissions and token expiry. Graph versions differ from ScubaGear; do not merge their locks. |
| Naabu | Compiled upstream service discovery | Preserve connect scanning, frozen targets/ports and gateway journal contract. Update source/go.sum/version fields and launcher fixtures. Port discoveries remain inventory, never vulnerability findings. |
| httpx | Compiled upstream HTTP/TLS inspection | `patch_live_dns.go` is tied to pre/post hashes of upstream `runner.go`; re-check the matching function and no live DNS before rebasing. Keep origin/redirect scope and gateway behavior. Output remains inventory. |
| Nuclei | Pinned `nuclei-templates` archive; only HTTP templates copied | Scanner and templates have separate revisions. Move the template marker, policy revision in grants, plan/catalog, labels and source notices together. Re-check read-only template selection, dependencies, excluded protocols/payloads and original template IDs. A template count change requires inspecting selection, not just changing a smoke count. |
| Greenbone | Scanner/openvasd, signed VT feed, Notus and native dependency sources | Seven patches apply in order at zero fuzz; some touch the same interpreter files. Feed revision is also bound into launcher, validator, product profiles/OID lists and grants. Review signature/metadata, safe dependency closure, result port/QoD and service identification. Historical feed digests disappeared quickly: measure all feed components together and preserve evidence of exactly what was acquired. A failure still deletes that grant's XML; new product tasks isolate each exact grant so completed siblings survive. Legacy combined batches require a new scan before replay. |
| Semgrep | Published `1.174.0-4`: [legacy + four rules](semgrep-publication-2026-10-03.md), 1,497 unique IDs | Rule pack and engine licenses differ; legacy rules retain Commons Clause. Runtime manifest, ID provenance, file count, launcher constants, Docker smoke and source attachments must agree. Inspect per-file licenses and the complete source archive as well as runtime configs. No license substitution or newer knowledge date just because the engine was rebuilt. |
| Gitleaks | Upstream `gitleaks.toml`, hash-verified at runtime | Keep default config digest, scanner-owned ignore patch, CLI/version/source hashes, own launcher and plan in step. Source-controlled suppression is intentionally disabled; re-check redaction in native output. Fixture copying is required by launcher tests and was restored in the 2026-10-03 recipe. Clean native amd64 build and one real synthetic finding verified; `8.30.1-2` is published, verified and catalog-pinned. |
| TruffleHog | Compiled upstream detectors; no embedded external rule pack | Keep source/go.sum/build-version and source offer together. Verification stays disabled with network off; an unverified match is not a proven live credential. Re-check JSONL detectors and redaction; preserve native confidence without exposing secret material. |
| Checkov | Checks and dependency lock in the source archive | Narrow context is required. `prepare_source.py` checks source/lock and generates hash-pinned wheel requirements. Re-check the reason for using a source image, CLI flags, framework output shape and output-path comma convention. Preserve absent native severity as absent; platform downloads stay disabled. |
| KICS | Queries bundled in its official image | No local build. Re-check upstream digest/labels, bundled query IDs and JSON parsing. Offline execution blocks network, but upstream startup can still attempt metadata/version requests; do not describe it as making no network attempts. |
| Trivy | Pinned vulnerability DB **and Java DB**; source-built scanner | Move preparation script, archive/internal DB/metadata hashes, `DATABASE-NOTICE.md`, plan and source/go.sum fields together. Preserve filesystem + rootfs repository passes and OS-only OCI image pass. Lockfile, standalone JAR and OCI fixtures test different paths. Scanner age and data age are separate. |
| Grype | Embedded schema-v6 vulnerability DB and `import.json` | Move acquisition/internal DB digests, schema/build metadata, import config, notice and launcher together. Check directory and OCI-layout matching, disabled DB updates and raw vulnerability ratings. Historical publication evidence for the current tag is incomplete; a matching source file is not proof of a workflow publication. |
| Syft | Catalogers bundled in the official image; no vulnerability DB | Narrow context; rebase `FROM` digest and upstream provenance labels together. Retain non-root cache paths and no update check. SBOM inventory is not vulnerability output. |
| Kubescape | NSA framework, control inputs and exceptions from regolibrary | All three `ADD --checksum` values must equal launcher constants and notice. Mutable `v2` asset URLs must still match their hashes; do not silently acquire replacements. Re-check offline flags, manifest marker and nested v2 `status.status`/per-resource results. Published/source launcher identity and tag reuse are separate from policy-byte compatibility. |
| kube-bench | Upstream `cis-1.11` node benchmark; product snapshot path config | Preserve the benchmark and snapshot profile together. Shared launcher also answers `ps`/`stat` from exported facts; it must never switch to host probes. Re-check required files, process/stat facts and all fail/pass/WARN/manual/not-done outcomes. WARN/manual/not-done statuses withhold complete coverage; a zero-finding report is not full node coverage. |
| MCP Armor | Two existing static configuration checks | Config-only patch, source digest, requirements lock, own launcher, version-bound adapter, research fixtures and validator hashes are coupled. Re-check no server/model contact, selected configuration path/hash, redaction and complete-check ledger. Copied upstream license text must be reviewed independently of the image's declared license label. |
| ZAP | Upstream passive scan add-ons; product-generated passive work plan | No local build; preserve the execution blockers. Re-check plan schema/add-on revisions, origin/redirect scope, actual crawl coverage and gateway request/rate limits before enabling it. An upstream image pin alone does not resolve those blockers. |
| garak | Native REST generator, fixed DAN/ANSI probes and primary detectors; never enumerate unused provider/ML plugins | Preserve the native plugin-cache mtimes at SOURCE_DATE_EPOCH. Keep build tools and optional provider SDKs out of runtime. Rebuild the exact langdetect source wheel; Python 2 wheel is unsuitable. Repeat positive/clean/redirect/TLS/deadline/cancellation QA with task-owned TLS trust only; production TLS verification stays on. Fixed profile, endpoint/model, one-shot local key, retry-inclusive attempts and output receipts must agree across Rust, UI and launcher. |
| Agentic Radar | Static native framework/tool inventory | Dedicated offline recipe; machine-output patch, typed framework selector, launcher and both wheel locks move together. Re-run five frameworks, empty state and dotenv/code isolation. Inventory does not count as a security result. |
| Egress gateway | Project Rust code; no scanner rule pack | Root context includes library `include_str!`/`include_bytes!` inputs beyond Rust source. A new embed needs a COPY and contract test. Runtime policy/status schema must remain compatible with the pinned gateway. Embedded catalog/mappings are build inputs, but a catalog-only edit does not itself justify publication; assess whether gateway behavior uses the changed fields. |

## Shared launchers and workflow reach

| Shared code | Engine images containing it | Workflow |
| --- | --- | --- |
| [Cloud launcher](cloud-launcher.md) | CloudQuery, Steampipe, Prowler, ScoutSuite, Cloudsplaining | [engine-images-cloud.yml](../../.github/workflows/engine-images-cloud.yml), changed-engine selection |
| [M365 launcher and source preparer](m365-launcher.md) | ScubaGear, Maester | [engine-images-m365.yml](../../.github/workflows/engine-images-m365.yml) |
| [External launcher](external-launcher.md) | Naabu, httpx, Nuclei | [engine-images-external.yml](../../.github/workflows/engine-images-external.yml) |
| [Local launcher](local-launcher.md) | Semgrep, TruffleHog, Trivy, Grype, Kubescape, kube-bench | [engine-images-local-k8s.yml](../../.github/workflows/engine-images-local-k8s.yml), **explicitly new tags selected from six declared entries**, two native Semgrep validation jobs |
| [Greenbone launcher](greenbone-launcher.md) | Greenbone | [engine-image-greenbone.yml](../../.github/workflows/engine-image-greenbone.yml) |

Gitleaks and MCP Armor have their own launchers. Checkov, KICS and Syft use upstream entrypoints. ZAP's passive work plan is generated from one frozen grant by the host; the official image has no Entrypoint, so its program is an explicit command token. The reviewed native rate keys, literal-IP SOCKS DNS distinction and recovery digest are recorded on the ZAP page.

A shared launcher edit changes the inputs of every image that would embed it on rebuild, even if only one engine branch changed. Keep affected source hashes and test selections in step, and retain historical artifact receipts. The local/Kubernetes workflow selects owner-assigned new tags rather than automatically rebuilding all six consumers. An unsuccessful native Semgrep check fails its publication before registry mutation; it does not block selected siblings. A later sibling rebuild still needs a new tag if its recorded inputs changed. Keep unapproved image-input work isolated; pushing approved new tags and build inputs to `main` can publish images automatically. Documentation edits under `docs/engines/` do not trigger these image workflows.

Do not fix a historical pin/source disagreement by rewriting the publication commit or assuming all images were rebuilt. Record what the pinned digest runs and what a new local build would run, separately. Documentation/source-offer changes copied into an image also change its bytes, even where the current hash policy omits `.md` inputs.

## Validation and update record

Use the engine page's named launcher tests, adapter fixtures, real-output comparison and workflow smoke. Add tests for the changed risk; do not run every scanner or require a live cloud sign-in for a documentation edit. Synthetic fixtures must never carry real credentials. A runtime or feed change needs actual bounded execution, with CPU/memory/time limits and the same network boundary as the product. Scope for external/provider tests must already be approved.

Before declaring an updated engine complete, compare native IDs, messages, severity, confidence, locations and remediation with normalization. Check errors, skipped/manual checks, service-identification failures and output truncation. The launchers' large artifact bounds and adapters' smaller parse bounds can differ; native exit zero is not sufficient evidence of complete product coverage.

Append this to the relevant engine page after each update or useful run:

```text
Date / reason:
Previous published image: repository@digest; publication source commit
Candidate source: full revision; archive URL + SHA-256
Rules / plugins / feed / DB: revisions, hashes, data dates; exclusions
Build: Dockerfile + context; preparation command; platform + build args
Customization: upstream files changed; reason; patch hash/order
Upstream issue or reason absent; removal condition; next review date
Files moved together: recipe, locks, launcher constants, plan, adapter, notices
Validation: exact commands; synthetic/approved fixture; native vs normalized
Observed result: findings/inventory/errors/skips; meaningful check evidence
Limits / remaining blockers:
Publication: local only, or owner-approved artifact + evidence link
Fix / documentation commit:
```

Keep exact pins in [catalog.json](../../engines/catalog.json), the engine's plan and the relevant locks. Keep **why**, **how to repeat it**, **what failed**, and **when to revisit it** in these pages. Historical records stay historical; a newer build does not rewrite old scan provenance or advance old data dates.

## Desktop patches that reuse the gateway

A desktop patch updates `runtime/managed-egress-gateway.json` → `product_version` with the application, but retains the existing gateway image tag, digest and source revision when its behavior is unchanged. Desktop 0.3.1 uses the verified `0.3.0-1` image. A new gateway publication must update both exact `GATEWAY_PUBLICATION_TAG` constants (`src-tauri/src/gateway_release.rs` and `scripts/release/platform-qualification.mjs`) together with its manifest and publication records. Run the release self-test and real installed-runtime qualification; do not rebuild an unchanged gateway just to match a desktop version. See the [gateway update notes](egress-gateway.md#updating-this-engine).

### Maintenance review — 2026-10-03

The executable-input gate now records the actual bytes of every former uncovered baseline input in the consuming engine plan. Its exclusions and shared support directories remain explicit. Seven current downstream source exceptions (Gitleaks, Greenbone, Prowler, ScoutSuite, MCP Armor, httpx and Agentic Radar) have plan-bound applicability, source pre/post hashes, owners, contribution rationale, fixture references, removal conditions and review dates. Greenbone and Prowler hashes are sequential in declared patch order; new files have a null original hash/reference. ScoutSuite's review patch and actual source preparer were compared independently and agree byte for byte. No upstream issue or contribution has been submitted by this review.

Current recipe records remain distinct from historical publication. Gitleaks was rebuilt as signed `8.30.1-2` in this maintenance step; the other unchanged image bytes retain their existing catalog digests. Any later byte change needs a new tag and a fresh publication record.
