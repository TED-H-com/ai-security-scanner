# Syft

Runs Syft over a `repository` snapshot (`dir:`) or a single-image OCI layout (`oci-dir:`) and records the software components it finds. This is inventory: the report lists components and never turns them into findings. Vulnerability matching is left to [Grype](grype.md) and [Trivy](trivy.md).

| Item | Value |
| --- | --- |
| Upstream | [anchore/syft](https://github.com/anchore/syft), version `1.54.1`, source ref `v1.54.1`, revision `b254e6d92f28c3868a755f62fb3ca8f26e9fee76`. The official `anchore/syft:v1.54.1` base is pinned by index digest. Both platform OCI revision labels match this source; no upstream signature verification is claimed. |
| Image | `ghcr.io/ted-h-com/ai-security-scanner-engine-syft:1.54.1-1` (`plan_kind: managed_rebase`), published for linux/amd64 and linux/arm64 by [this run](https://github.com/TED-H-com/ai-security-scanner/actions/runs/38704467877) from `c989e75e1c3be7e7abad3395dcf5539cf2a96832`. Exact index/platform digests and verified evidence are in `engines/catalog.json` and `plan.json`. |
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
- **Hard-coded values.** Keep managed tag `1.54.1-1`, reported version `1.54.1`, full source revision, workflow selector, Dockerfile labels, catalog/plan identity and publication verifier aligned. Search current source with `rg` when updating; preserve dated records and captured fixtures. `support_until` is 2027-01-04.
- **Compare with raw output.** `jq '.artifacts | length' syft.json` should equal the normalized component count. List with `jq -r '.artifacts[] | [.name, .version, .type, .purl] | @tsv' syft.json | sort | uniq -c`; rows with the same `purl` show as one component in the report.
- **Publishing.** The current `1.54.1-1` publication binds the recorded inputs at `c989e75e1c3be7e7abad3395dcf5539cf2a96832` in [this run](https://github.com/TED-H-com/ai-security-scanner/actions/runs/38704467877). Existing-tag reuse requires verified provenance and matching executable inputs. Any changed image input requires a new immutable tag.

The release/SBOM evidence generator remains separately pinned to Syft 1.51.0. Its tool version and digest are independent of the scanner image described here.

## 2026-10-14 source update

The replacement recipe targets `1.54.1-1` at upstream commit `b254e6d92f28c3868a755f62fb3ca8f26e9fee76`. The replacement is now published and pinned in the current catalog; the verified publication is recorded below. See the [batch update record](updates/2026-10-14.md) for changed inputs, retained rules and verification.

## 2026-10-15 verified publication

[Publication run](https://github.com/TED-H-com/ai-security-scanner/actions/runs/38704467877) binds both platform images to `c989e75e1c3be7e7abad3395dcf5539cf2a96832`. Five source/SBOM attestations, four SBOMs, checksums and anonymous index, version tag, platform manifest and config bytes were independently verified before catalog activation. See the [batch verification record](updates/2026-10-14.md#verified-publication-and-catalog-activation) for native execution results and the remaining scope limits.
