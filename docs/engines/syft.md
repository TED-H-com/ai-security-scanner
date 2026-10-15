# Syft

Runs Syft over a `repository` snapshot (`dir:`) or a single-image OCI layout (`oci-dir:`) and records the software components it finds. This is inventory: the report lists components and never turns them into findings. Vulnerability matching is left to [Grype](grype.md) and [Trivy](trivy.md).

| Item | Value |
| --- | --- |
| Upstream | [anchore/syft](https://github.com/anchore/syft) 1.51.0 (`source_ref` `v1.51.0`), revision `2293641e3bd628a01bb37639318d62c0ebe89b39`. Upstream image `anchore/syft:v1.51.0` at digest `678bfa56…`, recorded in plan `verified_upstream_artifact` (`docker_buildx_imagetools_inspect`, `attested_match`, 2026-08-24). |
| Image | `ghcr.io/teddashh/ai-security-scanner-engine-syft:1.51.0-1` (`plan_kind: managed_rebase`, Apache-2.0), published from 122f3c2 (run 32754480561). The digest is pinned in `engines/catalog.json`. |
| Build inputs | `engines/images/syft/Dockerfile` and `plan.json` only. The Dockerfile is `FROM` the upstream image by digest and adds labels, `HOME`, `XDG_CACHE_HOME`, `SYFT_CACHE_DIR=/tmp/ai-security-scanner-cache/syft`, `SYFT_CHECK_FOR_APP_UPDATE=false` and `USER 65532:65532`. Nothing is compiled or downloaded (`build_recipe: null`). |
| Launcher | None: upstream `ENTRYPOINT ["/syft"]` receives the catalog `command`. The [local launcher](local-launcher.md) is not used. |
| Adapter | `extract_syft_inventory` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-image-syft.yml` |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/syft/Dockerfile) and context `engines/images/syft`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Input.** One asset: a `repository` (`repository_working_tree`) or a `container_image` (`container_image_oci_layout`). No launcher checks the input inside the container; the host routes by the catalog contracts. Networking is disabled. Catalog resources: 1024 MB memory, 1024 MB disk, 1000 CPU millis, 3600 s.
- **Invocation.** Repository: the catalog `command`, `dir:/workspace -o syft-json=/output/syft.json --quiet`. OCI layout: the contract's own `command`, `oci-dir:/workspace -o syft-json=/output/syft.json --quiet`, which `execution_manifest_for_verified_single_asset` in `src-tauri/src/case_service.rs` puts in place of the catalog `command`. `validate_static_manifest_command` (`src-tauri/src/container_runtime.rs`) rejects a contract command that starts a shell or holds a placeholder.
- **Output.** `/output/syft.json` in Syft's own JSON format. Nothing checks it inside the container; the host stores it as a raw artifact.
- **Mapping.** `extract_syft_inventory` reads `artifacts[]` into `SoftwareComponent` observations: `name` (required), `version`, `type` and `purl`. Locations, licenses and CPEs stay in the raw artifact only.
  - No findings are produced. Every run carries the note "syft output is inventory evidence; no security issue was invented from inventory rows", shown as "output contains inventory, not security findings" (`src/engineWarningPresentation.ts`). The note does not make the run partial.
  - The report counts the run as an inventory check (`task_result_kind` in `src-tauri/src/beginner_report.rs`). It merges components by asset and `purl`, or by name, version and type when there is no `purl`.
- **Failed or partial.** A non-zero exit fails the run. These make it partial:
  - a root that is not an object, or no `artifacts` array;
  - a component that is not an object or has no `name`;
  - a run bound to more than one asset;
  - a `syft.json` over 16 MiB (`MAX_ARTIFACT_BYTES`), which stays raw and is not read at all;
  - 10,000 components.

  `{"artifacts":[]}` is a finished run with nothing found.

## Downstream changes

None. The image is the upstream image by digest. The rebase only sets a non-root user, keeps the cache under the `/tmp` tmpfs, and turns off the update check.

## Lessons from real runs

- 2026-09-25: after a real eight-check project scan, the Results tile "What was actually tested" read "Syft · Completed · +7 more" -> it named whichever check came first, and a beginner cannot tell what Syft is -> the tile counts completed checks instead (5e2c013).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Base image.** Verify the new upstream image digest and its source revision, then update together:
  - `FROM` and the labels (`org.opencontainers.image.version`, `ai.security-scanner.upstream.revision`, `ai.security-scanner.upstream.image`);
  - plan `source`, `verified_upstream_artifact` and `dockerfile.sha256`;
  - catalog `engine_version`, `source_revision`, `rule_version` (the upstream revision), `provenance.engine` and `provenance.rules`.

  `validateManagedRebase` in `scripts/validate-engine-catalog.mjs` requires `FROM` to equal the verified repository and digest, `USER 65532:65532`, `ENTRYPOINT ["/syft"]`, every plan `managed_runtime.environment` entry in the Dockerfile, and `SYFT_CHECK_FOR_APP_UPDATE` `false`.
- **CLI and output shape.** Re-check the `dir:` and `oci-dir:` schemes, `-o syft-json=<file>` and `--quiet`, and `artifacts[].{name,version,type,purl}`.
- **Tests.**
  - In `src-tauri/tests/adapter_fixtures.rs` (fixture `syft.json`): `inventory_fixtures_preserve_typed_upstream_facts_and_exact_provenance` and `inventory_schema_and_asset_boundaries_fail_closed_but_known_empty_shapes_complete`.
  - In `src-tauri/tests/local_case_lifecycle.rs`: `typed_container_and_kubernetes_inputs_complete_the_product_lifecycle`, which checks the OCI command and that components attach to the OCI asset, and `local_case_lifecycle_preserves_scope_evidence_and_comparison_truth`.
  - `unsafe_typed_input_commands_isolate_only_their_engine` in `src-tauri/src/registry.rs`.
  - The publish workflow never runs the image. Before pinning, run it by hand over a repository snapshot and an OCI layout.
- **Hard-coded values.** `1.51.0-1` appears in the workflow `concurrency.group` and `IMAGE_TAG`, catalog `image.tag`, plan `final_artifact.tag` and the Dockerfile label. Find them with `grep -rn "1.51.0" --exclude-dir=node_modules --exclude-dir=target --exclude-dir=.git --exclude-dir=.upstreams --exclude-dir=.engine-cache`. That search also finds the same upstream version and digest pinned as the SBOM generator in `scripts/engine-image-evidence.mjs` (`SYFT`), `scripts/release/verify-publication-artifact.mjs`, `tests/release/verifyPublicationArtifact.test.mjs`, `docs/release/engine-image-supply-chain.schema.json` and `.github/workflows/release.yml`. Those pin the evidence tooling, not this engine. `support_until` is 2026-11-22.
- **Compare with raw output.** `jq '.artifacts | length' syft.json` should equal the normalized component count. List with `jq -r '.artifacts[] | [.name, .version, .type, .purl] | @tsv' syft.json | sort | uniq -c`; rows with the same `purl` show as one component in the report.
- **Publishing.** The workflow runs only when `engines/images/syft/Dockerfile` changes on `main`, or by manual dispatch. The plan at the publishing commit 122f3c2 records the same inputs as today, so a dispatch reuses `1.51.0-1`. A Dockerfile change needs a new tag.

## 2026-10-14 source update

The replacement recipe targets `1.54.1-1` at upstream commit `b254e6d92f28c3868a755f62fb3ca8f26e9fee76`. The catalog still names the previously published image until replacement publication is verified. See the [batch update record](updates/2026-10-14.md) for changed inputs, retained rules and verification.
