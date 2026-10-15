# Kubescape

Runs Kubescape's NSA framework (`scan framework nsa`) offline over an immutable snapshot of local Kubernetes YAML or JSON manifests attached to a `kubernetes_cluster` asset (input profile `kubernetes_manifests`). No live cluster is contacted; the framework, control inputs and exceptions are embedded in the image.

| Item | Value |
| --- | --- |
| Upstream | [kubescape/kubescape](https://github.com/kubescape/kubescape) 4.0.12, revision `469969f6bebf46bef5e808b91a4bb46fb2bbf4ed`. Rules: [kubescape/regolibrary](https://github.com/kubescape/regolibrary) release `v2`, annotated tag object `844c0de2436a45c58bdb669052ac20ca53c8a327`, commit `a12188c49147bb6ec379b42a4159d3d5852634b8` (catalog `rule_version`). |
| Image | `ghcr.io/teddashh/ai-security-scanner-engine-kubescape:4.0.12-3` (`plan_kind: managed_build`, Apache-2.0, runtime `FROM scratch`), linux/amd64 and linux/arm64. The published digest is pinned in `engines/catalog.json`. |
| Build inputs | `engines/images/kubescape/`: `Dockerfile`, `ARTIFACT-NOTICE.md`, `plan.json`, `testdata/` (input marker and `pod.yaml`); the shared launcher `engines/images/local-launcher/` (`go.mod`, `main.go`, `main_test.go`) |
| Launcher | Shared [local launcher](local-launcher.md), `engines/images/local-launcher/main.go`: the `kubescape` branches of `validateEngineInputProfile`, `verifyEngineInputs` and `planInvocation` |
| Wrapper | None beyond the launcher. The three regolibrary files are hash-pinned build inputs. |
| Adapter | `extract_kubescape` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-local-k8s.yml`, matrix entry `kubescape` |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/kubescape/Dockerfile) and context `.`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Input.** "Kubernetes configuration" in `src/localInputProfiles.ts`: a folder of exported YAML or JSON settings, which the form says must not contain kubeconfig files, tokens or certificates. `validate_copied_input_files` in `src-tauri/src/workspace_snapshot.rs` requires at least one `.json`, `.yaml` or `.yml` file, the snapshot carries the marker `.ai-security-scanner-input.json` with `input_profile` `kubernetes_manifests`, and `expected_input_profile` in `src-tauri/src/registry.rs` binds `kubernetes_cluster` to that profile. `localInputEngineIds` routes the profile to Kubescape, and without explicit routes the backend default plan (`default_plan_includes_manifest` in `src-tauri/src/case_service.rs`) includes it whenever an authorized asset carries such a snapshot; the catalog `default_enabled` (true) is not read by the planner.
- **Network and resources.** Engine networking disabled. Catalog `execution.resources`: 2048 MB memory, 2048 MB disk, 2000 CPU millis, 256 pids, 3600 s. Read-only root filesystem and `/workspace`, all capabilities dropped (`src-tauri/src/container_runtime.rs`).
- **Invocation.** The launcher accepts only `--engine kubescape --workspace /workspace --output /output`, refuses a writable workspace, allows Kubescape only with the `kubernetes_manifests` marker, and checks `nsa.json`, `controls-inputs.json` and `exceptions.json` in `/opt/ai-security-scanner/kubescape-artifacts/` against `kubescapeNSASHA256`, `kubescapeControlsSHA256` and `kubescapeExceptionsSHA256` (each at most 4 MiB). Then, with a fixed environment plus `KS_SUBMIT=false OTEL_SDK_DISABLED=true` and a 1 h timeout: `kubescape scan framework nsa /workspace --use-from <artifacts>/nsa.json --controls-config <artifacts>/controls-inputs.json --exceptions <artifacts>/exceptions.json --keep-local --submit=false --host-scan=false --omit-raw-resources --format json --format-version v2 --scan-timeout 45m --control-timeout 2m --output /output/kubescape.json`.
- **Output.** `/output/kubescape.json`. `validateEvidence` requires one JSON value of at most 512 MiB with nothing after it; the file is then set to 0600. Diagnostics are capped at 8 MiB. Only JSON is produced.
- **Mapping.** `extract_kubescape` walks `results[]` (location `resourceID`, else `resource`, else `kubernetes-resource`) and each entry's `controls[]`.
  - Status is the v2 object `status.status`, or a plain `status` string from older shapes; only a failing status becomes a finding.
  - Rule id `controlID`; title is the control `name`, else the `summaryDetails.controls` name. References come from the control's `rules`.
  - Severity is the roll-up's 1-10 `scoreFactor` from `summaryDetails.controls.<id>` through `parse_severity` (9 and above Critical, 7 High, 4 Medium, above 0 Low), else Unknown. Confidence basis `DeterministicPolicyEvaluation`, evidence kind Configuration.
  - Only when `results` yields no finding do failing `summaryDetails.controls` entries become findings, located at `kubernetes-cluster`; the missing resource correspondence makes coverage incomplete. Summary verdicts support both native `statusInfo.status` and the legacy `status` field.
- **Failed, partial, not tested.** A wrong marker (reported as `local_input_profile_unsupported`), an artifact hash mismatch, a non-zero Kubescape exit, the timeout, log overflow or invalid JSON makes the container exit 126, and `src-tauri/src/orchestrator.rs` fails the run without adapting. Missing or malformed results, controls, verdicts or control IDs withhold complete coverage without discarding valid siblings. Native `skipped` and deprecated `error` verdicts describe incomplete evaluation; they do not become vulnerabilities. A resource may omit its empty `controls` array, as upstream specifies, but a report containing no evaluated resource controls cannot claim a clean check. The 10,000-record bound also makes coverage partial. Reports larger than 16 MiB use the bounded streaming reader described in [engine maintenance](../engine-maintenance.md#9-large-report-normalization).

## Downstream changes

- No source patches: `go.sum` is hash-checked, then `go mod verify` and `go build -mod=readonly`. The ldflags stamp `main.version=v4.0.12`, `main.commit` and `main.date`.
- Offline operation is upstream flags only: `--use-from`, `--controls-config`, `--exceptions`, `--keep-local`, `--submit=false` and `--host-scan=false`, plus `KS_SUBMIT=false` and `OTEL_SDK_DISABLED=true` in both the image `ENV` and the launcher environment.
- The NSA framework, control inputs and exceptions come from `https://github.com/kubescape/regolibrary/releases/download/v2/{nsa,default_config_inputs,exceptions}` with `ADD --checksum`. The same three hashes are in the launcher constants and `ARTIFACT-NOTICE.md`, which ships in the image.

## Lessons from real runs

- 2026-09-05: on v2 output every per-resource control fell back to the summary roll-up, one finding per control with no resource -> the adapter read a flat string `status`, and the fixture had been invented to match the code -> nested `status.status`, `scoreFactor` severity, `resourceID` location, a fixture in the v2 shape and mutation tests (696183c).
- 2026-09-11: a real all-engine run reported Kubescape `C-0009` and `C-0017` with no framework coordinate -> only one representative rule had been mapped -> both mapped (5128304).
- 2026-09-17: the local/k8s publish job failed for Kubescape with "version tag is already bound to a different source commit or workflow" although its inputs had not changed -> the guard bound a tag to the commit that first published it -> it now compares the plan's recorded input hashes (415ab1b).
- 2026-10-03: malformed reports could read as zero findings, and a failed control without its ID silently disappeared -> adapter contract 0.2.4 checks the pinned [OPA-utils verdicts](https://github.com/kubescape/opa-utils/blob/v0.0.303/reporthandling/apis/statuses.go) and [resource/control schema](https://github.com/kubescape/opa-utils/blob/v0.0.303/reporthandling/results/v1/resourcesresults/datastructures.go), keeps valid siblings and withholds completion for missing evaluations. No detector or image change.

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Next publish needs a new tag.** The pinned `4.0.12-3` was published from 2641850 (plan `publication`) with a launcher whose `main.go` hashes to `8ae5ab14…`. The plan's `wrapper.launcher_sha256` was re-pointed to `e5b1c32b…` by ef1c653, 0e4dd55, f6b6171 and 686e427, and to `ddd57759…` (the current `engines/images/local-launcher/main.go`) by b0c4ed4, each time without a rebuild; `plan.json` at 2641850 still binds `4.0.12-2`. `publicationPreflight` in `scripts/engine-image-evidence.mjs` therefore refuses `4.0.12-3` on the next run of the matrix entry; move to a new tag in the same change. The Kubescape invocation, marker rule and artifact checks are identical in the published launcher and the current source, so the pinned image behaves like the current Kubescape path.
- **Source.** Change the archive URL and `ADD --checksum`, the `go.sum` hash, the ldflags, the `org.opencontainers.image.revision` label, the plan `source` and `build_recipe`, and the catalog `source_revision`, `engine_version`, `provenance`. `engines/upstreams.lock.json` records a different research checkout (`fdd64f43…` on `master`), not the image pin.
- **Rule artifacts.** The `v2` release assets can be replaced upstream; a changed file fails `ADD --checksum`. To move, re-hash all three files and update the Dockerfile, the three launcher constants, `ARTIFACT-NOTICE.md` (tag object and commit), the `io.ai-security-scanner.regolibrary-revision` label, catalog `rule_version` and `provenance.rules.revision`.
- **Output shape.** Re-check the v2 report: `results[].resourceID`, `results[].controls[].controlID`, `name`, `status.status`, `rules`, and `summaryDetails.controls.<id>.name`, `scoreFactor` and `status`. Re-check that every flag in the invocation still exists.
- **Tests.** Fixture `src-tauri/tests/fixtures/adapters/kubescape.json` (two resources, three failing and one passing control). `kubescape_per_resource_results_are_read_not_only_the_summary_rollup` expects `c-0002` Medium, `c-0009` High, `c-0017` Low and exactly three findings; `fingerprints_are_stable_across_repeat_runs` also uses it. Launcher test `TestKubescapeIsOfflineManifestOnly`. The fixture is hand-made in the v2 shape; prefer replacing it with a real run of the new image.
- **Mapping.** `mappings/control-mappings.json` maps `C-0002`, `C-0009` and `C-0017`. Kubescape ids have no shape check in `engine_rule_identifiers_have_the_shape_their_engine_actually_emits`, so check each against `nsa.json` and a real run. A content change needs a `mapping_version` bump.
- **Hard-coded tag.** `4.0.12-3` is in `engines/catalog.json`, `plan.json`, the Dockerfile version label, the workflow matrix, `scripts/validate-engine-catalog.mjs`, `scripts/release/verify-publication-artifact.mjs` and `tests/release/verifyPublicationArtifact.test.mjs`; `4.0.12` is also the workflow `version`, the ldflag and the catalog `engine_version`. Check with `grep -rn "4.0.12-3" --exclude-dir=node_modules --exclude-dir=target --exclude-dir=.git --exclude-dir=.upstreams`. `support_until` is 2026-11-22.
- **Publishing.** `ARTIFACT-NOTICE.md` is copied into the image but, like every `.md` file, has no digest in `plan.json` (`engines/image-input-hash-policy.json`), so the publication guard would reuse the old image after a notice-only change; advance the tag by hand. A shared-launcher change moves `wrapper.launcher_sha256` in all six local plans. The workflow smoke runs the managed scan over `testdata/` (a privileged pod) but checks only the version string and that `kubescape.json` parses.
- **Compare with raw output.** In the raw `kubescape.json`, every `results[].controls[]` entry with `status.status` `failed` should be one finding at its `resourceID`, with the severity its `summaryDetails.controls.<id>.scoreFactor` implies. Findings located at `kubernetes-cluster` mean the per-resource results were not read.

## 2026-10-14 source update

The replacement recipe targets `4.0.16-1` at upstream commit `d0ea07bcd9d7ab1640dcd6527d0e68a34f10da0e`. The catalog still names the previously published image until replacement publication is verified. See the [batch update record](updates/2026-10-14.md) for changed inputs, retained rules and verification.
