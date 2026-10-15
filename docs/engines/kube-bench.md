# kube-bench

Runs kube-bench's unmodified upstream CIS Kubernetes 1.11 node profile (`--benchmark cis-1.11 --targets node`) over an exported node-facts snapshot attached to a `host` asset (input profile `kubernetes_node_snapshot`). Nothing touches a live node or cluster: kube-bench reads the snapshot files, and the `ps` and `stat` answers it asks for are replayed from the snapshot's recorded facts.

| Item | Value |
| --- | --- |
| Upstream | [aquasecurity/kube-bench](https://github.com/aquasecurity/kube-bench) revision `9f133cb7509ce1dbedfc860e94474588000e25ac` (catalog `source_ref` `main`, `engine_version` `source@9f133cb…`). The build stamps `KubeBenchVersion=v0.16.0` through `-ldflags`. Catalog `reported_version` is `0.16.0`, with no leading `v`; pinned commit `9f133cb` is 1 commit after `v0.16.0` on `main`. |
| Image | `ghcr.io/teddashh/ai-security-scanner-engine-kube-bench:0.16.0-4` (`plan_kind: managed_build`, Apache-2.0), linux/amd64 and linux/arm64. The published digest is pinned in `engines/catalog.json`. |
| Build inputs | `engines/images/kube-bench/`: `Dockerfile`, `cfg/config.yaml`, `SNAPSHOT-PROFILE.md`, `plan.json`, `testdata/` (input marker and a five-file `node-snapshot/`); the shared launcher `engines/images/local-launcher/` (`go.mod`, `main.go`, `main_test.go`) |
| Launcher | Shared [local launcher](local-launcher.md), `engines/images/local-launcher/main.go`: `planInvocation`, `verifyEngineInputs`, `loadNodeSnapshot`, `validateNodeSnapshot`, `runSnapshotPS`, `runSnapshotStat`, `rewriteSnapshotPaths`, `execute`, `validateEvidence` |
| Wrapper | `cfg/config.yaml`, a product-owned kube-bench config that points the kubelet and proxy files at `/workspace/node-snapshot/`; the launcher binary doubles as `ps` and `stat` |
| Adapter | `extract_kube_bench` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-local-k8s.yml`, matrix entry `kube-bench` |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/kube-bench/Dockerfile) and context `.`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Input.** The user chooses the parent folder of `node-snapshot/` ("Exported Kubernetes node settings" in `src/localInputProfiles.ts`, routed to kube-bench by `localInputEngineIds`). `expected_input_profile` in `src-tauri/src/registry.rs` binds `host` to `kubernetes_node_snapshot`. Without explicit routes, the backend default plan (`default_plan_includes_manifest` in `src-tauri/src/case_service.rs`) includes kube-bench whenever an authorized `host` asset carries such a snapshot; the catalog `default_enabled` (false) is not read by the planner.
  - `node-snapshot/` holds `profile.json` and exactly `kubelet-config.yaml`, `kubelet.service`, `kubelet.conf`, `kube-proxy.yaml` and `ca.crt`. `profile.json` (schema `2.0.0`, profile `cis-kubernetes-node-facts`, benchmark `cis-1.11`, `captured_at`) records each file's original absolute `source_path`, SHA-256, octal mode, owner and group, plus one single-line command for `kubelet` and one for `kube-proxy`. Format: `SNAPSHOT-PROFILE.md`; non-secret example: `testdata/node-snapshot/profile.json`.
  - `src-tauri/src/workspace_snapshot.rs` checks the same facts at attach time (at most 256 KiB, digests equal to the copied files, no extra files) and writes the marker `.ai-security-scanner-input.json` with `input_profile` `kubernetes_node_snapshot`.
- **Network and resources.** Engine networking disabled. Catalog `execution.resources`: 512 MB memory, 512 MB disk, 1000 CPU millis, 256 pids, 3600 s. Read-only root filesystem and `/workspace`, all capabilities dropped (`src-tauri/src/container_runtime.rs`).
- **Invocation.** The launcher accepts only `--engine kube-bench --workspace /workspace --output /output`, refuses a writable workspace, allows kube-bench only with the `kubernetes_node_snapshot` marker (`validateEngineInputProfile`), and re-validates the snapshot (`loadNodeSnapshot`: unknown fields rejected, exactly five files and two processes, each file at most 8 MiB and matching its digest, nothing else in the directory). Then, with a fixed environment and a 1 h timeout: `kube-bench run --benchmark cis-1.11 --targets node --config-dir /opt/ai-security-scanner/kube-bench/cfg --config /opt/ai-security-scanner/kube-bench/cfg/config.yaml --json --outputfile /output/kube-bench.json --exit-code 0`.
- **Replay.** The Dockerfile deletes `/bin/ps` and installs the launcher as `/bin/ps`, `/usr/local/bin/ps` and `/usr/local/bin/stat`; `main` dispatches on its own name.
  - `ps` answers only `-ef`, `-fC <name>` and `-C <name> -o cmd --no-headers`, for `kubelet` and `kube-proxy`, with the recorded command line after `rewriteSnapshotPaths` replaces each original path with its snapshot copy.
  - `stat` answers only `-c permissions=%a <snapshot file>` and `-c %U:%G <snapshot file>` from the recorded mode, owner and group.
  - Any other form exits 126. Recorded command lines are never executed.
- **Output.** kube-bench writes `/output/kube-bench.json` itself. `validateEvidence` requires one JSON value of at most 512 MiB with nothing after it; the file is then set to 0600. Diagnostics are capped at 8 MiB and overflow fails the run.
- **Mapping.** `extract_kube_bench` walks `Controls[].tests[].results[]` (`controls` also accepted).
  - Only a failing `status` (FAIL) becomes a finding. PASS and INFO produce no findings. WARN is kube-bench's state for manual checks and checks it could not carry out (upstream `check/check.go`); one counted disclosure marks the run partial and adds the untested checks and a manual-review action to the shared report. Upstream remediation stays in scan evidence. WARN checks never become failed findings.
  - Rule id `test_number` (or `id`), title `test_desc`, location `resource` or `node_type`, else `kubernetes-cluster`. `remediation` goes into the scanner details.
  - Severity is Unknown with basis `CisKubernetesBenchmark`, because kube-bench's JSON `Check` has no severity field. Confidence basis is `DeterministicPolicyEvaluation`.
- **Failed, partial, not tested.** A launcher refusal (wrong marker, altered or extra snapshot file, invalid `profile.json`), a non-zero kube-bench exit, the timeout, log overflow or invalid JSON makes the container exit 126, and `src-tauri/src/orchestrator.rs` fails the run without adapting; a marker refusal is reported as `local_input_profile_unsupported`. The run is partial when WARN checks are present, when `Controls` is missing ("kube-bench output lacked its Controls array…") or the 10,000-record bound is reached. A result without `test_number` or `id` is skipped without a warning.

## Downstream changes

- No source patches. Upstream `cfg/cis-1.11/node.yaml` and `cfg/cis-1.11/config.yaml` are copied unmodified after SHA-256 checks in the Dockerfile (`276ade4e…`, `f8beefa9…`), as is `go.sum` (`b9bb74a6…`), followed by `go mod verify`.
- The product's `cfg/config.yaml` replaces upstream's top-level `cfg/config.yaml`: `target_mapping` limits `cis-1.11` to `node`, only the `kubelet` and `proxy` components exist, and their `confs`, `svc`, `kubeconfig` and `cafile` paths point into `/workspace/node-snapshot/`.
- Host access is replaced by the snapshot and the `ps`/`stat` replay above. Recorded facts are answered verbatim; nothing is re-derived.
- The version label `v0.16.0` comes from the ldflag, not from a release archive: the archive is the `main` commit above.

## Lessons from real runs

- 2026-09-05 (found in review): the kube-bench control mapping could never match -> it was keyed on `1.2.1`, a control-plane check that `--targets node` cannot emit, and the fixture had been invented -> re-keyed to `4.2.1` and the fixture replaced with a full run of the then six-check profile (1da78c3). The same commit rated every failure High; that was reverted to Unknown because kube-bench publishes no rating (97093ae, 2026-09-08).
- 2026-09-09: the image ran a product-written six-check subset (`cfg/ai-security-scanner-snapshot/`, snapshot schema `1.0.0`, profile `cis-kubernetes-node-config`) -> replaced by the unmodified upstream CIS 1.11 node profile, `ps`/`stat` replay and snapshot schema `2.0.0`; the fixture became a real 26-check run (f6b6171).
- 2026-09-11: a real all-engine run reported kube-bench `4.1.1`, `4.1.9`, `4.1.10`, `4.2.10` and `4.3.1` with no framework coordinate -> only one representative rule had been mapped -> all five mapped (5128304).
- 2026-10-03: release review replayed the real 26-check fixture (15 PASS, 6 FAIL, 5 WARN), which previously claimed complete automated coverage -> adapter contract 0.2.3 discloses manual/unexecuted checks once, keeps all six failures and their evidence, and prevents WARN-only results from becoming a clean zero-finding outcome. No image change.
- 2026-09-17: that change had never reached users -> the published tag was never advanced -> `0.16.0-4` scheduled with the catalog entry withdrawn (9ee5257), then published and pinned (85f92b1).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Source.** Change the archive URL and `ADD --checksum`, the `go.sum`, `node.yaml` and `config.yaml` hashes (Dockerfile and `immutableDockerfileInputs` in `scripts/validate-engine-catalog.mjs`), the `KubeBenchVersion` ldflag, the `org.opencontainers.image.revision` label, the plan `source` and `build_recipe`, and the catalog `source_revision`, `engine_version`, `rule_version` and provenance. Prefer a release tag: the workflow's version check greps the ldflag-stamped string, so it cannot catch a wrong label.
- **Benchmark.** `cis-1.11` is hard-coded in `nodeSnapshotBench` (launcher), the Dockerfile paths, `cfg/config.yaml`, the benchmark check in `src-tauri/src/workspace_snapshot.rs`, `SNAPSHOT-PROFILE.md`, the validator's Dockerfile strings and `kube_bench_cis_1_11_check_ids` in `src-tauri/src/adapters/control_mapping.rs`. Moving to another benchmark changes all of them and the snapshot schema together.
- **Snapshot schema.** `validate_copied_input_files` in `workspace_snapshot.rs` still accepts the retired schema `1.0.0` profile `cis-kubernetes-node-config` without checks; its comment says the catalog pins the schema-1 image, which stopped being true at 85f92b1. The `0.16.0-4` launcher rejects that profile, so such a run fails with exit 126. No tool in the repository captures a snapshot; `SNAPSHOT-PROFILE.md` is the only format reference.
- **Audit commands.** Read every `audit:` in the new node profile. A `ps` or `stat` form other than the five above exits 126 and fails the run. Only `ps` at `/bin/ps` or on `PATH` and `stat` on `PATH` are replayed (`/usr/local/bin` comes first in the launcher's fixed `PATH`); an audit that calls another binary or an absolute `stat` path is not replayed. A new file the profile reads must be added to the launcher's inventory, `workspace_snapshot.rs`, `SNAPSHOT-PROFILE.md` and `cfg/config.yaml`.
- **Output shape.** Re-check `Controls[].tests[].results[]` with `test_number`, `test_desc`, `status` and `remediation`, the `Totals` block, and that `Check` still has no severity field (if upstream adds one, read it).
- **Tests.** Fixture `src-tauri/tests/fixtures/adapters/kube-bench.json`, a real CIS 1.11 node run: 26 results (15 PASS, 6 FAIL, 5 WARN), `Controls[0].version` `cis-1.11`. `kube_bench_failures_remain_findings_without_an_invented_rating` expects 6 Unknown findings with partial coverage; `kube_bench_manual_checks_never_become_a_clean_zero_finding_result` checks WARN-only and PASS-only outcomes; `engine_rule_identifiers_have_the_shape_their_engine_actually_emits` requires exactly 26 ids and every kube-bench mapping among them. Launcher tests `TestKubeBenchKeepsUpstreamRemediationInItsReport`, `TestNodeSnapshotRejectsUninventoriedAndAlteredFiles`, `TestNodeSnapshotToolsReplayOnlyValidatedFacts`, `TestEngineProfilesRejectCrossTypeExecution`. Replace the fixture with a real run of the new image over `testdata/` instead of editing it.
- **Mapping.** `mappings/control-mappings.json` maps `4.1.1`, `4.1.9`, `4.1.10`, `4.2.1`, `4.2.10` and `4.3.1`. Renumbered checks need a mapping change and a `mapping_version` bump.
- **Hard-coded tag.** `0.16.0-4` is in `engines/catalog.json`, `plan.json`, the Dockerfile version label, the workflow matrix, `scripts/validate-engine-catalog.mjs`, `scripts/release/verify-publication-artifact.mjs` and `tests/release/verifyPublicationArtifact.test.mjs`; `0.16.0` is also the workflow `version` and the ldflag. Check with `grep -rn "0.16.0-4" --exclude-dir=node_modules --exclude-dir=target --exclude-dir=.git --exclude-dir=.upstreams`. `support_until` is 2026-11-22.
- **Publishing.** Any change to the Dockerfile, `cfg/config.yaml`, `SNAPSHOT-PROFILE.md` or the shared launcher needs a new tag. `cfg/config.yaml` and `.md` files have no digest in `plan.json` (`engines/image-input-hash-policy.json`), so the publication guard cannot see them and would reuse the old image; advance the tag by hand. A shared-launcher change moves `wrapper.launcher_sha256` in all six local plans, so every local engine needs a new tag. The workflow smoke checks only the version string and that `kube-bench.json` parses.
- **Compare with raw output.** In the raw `kube-bench.json`, every FAIL result should be one finding with the same `test_number`, `test_desc` and `remediation`, and `Totals.total_fail` should equal the finding count. `Totals.total_warn` counts the WARN results, which produce no findings and now withhold completion. Each WARN check's identity and remediation remain in the original JSON evidence.

## 2026-10-14 source update

The replacement recipe targets `0.16.0-5` at upstream commit `9f133cb7509ce1dbedfc860e94474588000e25ac`. The catalog still names the previously published image until replacement publication is verified. See the [batch update record](updates/2026-10-14.md) for changed inputs, retained rules and verification.
