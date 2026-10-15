# External engine launcher

The project-owned Go entrypoint in the Naabu, httpx and Nuclei images. It turns the frozen scope document into one bounded scanner process per grant (Naabu) or per grant port (httpx, Nuclei), checks every output record against that grant, and writes the evidence the adapters read. It detects nothing itself.

| Item | Value |
| --- | --- |
| Upstream | None. Project code using only the Go standard library (`go.mod`: `go 1.26`, no requirements) |
| Image | Built into `ghcr.io/teddashh/ai-security-scanner-engine-naabu:2.6.1-7`, `ghcr.io/ted-h-com/ai-security-scanner-engine-httpx:1.12.0-1`, `ghcr.io/teddashh/ai-security-scanner-engine-nuclei:3.11.1-7`. The catalog pins each digest; the corresponding engine plan records its own publication source and evidence. |
| Build inputs | `engines/images/external-launcher/`: `main.go`, `main_test.go`, `go.mod`, `testdata/naabu-launcher-plan-v2.json`, `testdata/naabu-launcher-plan-v3.json`, `NOTICE.md`. Each engine Dockerfile runs `go test ./...`, then builds `/usr/local/bin/ai-security-scanner-engine-entrypoint` |
| Launcher | `--engine <id> --scope /run/ai-security-scanner/scope.json --output /output`. Naabu adds `--journal-version 2 --journal-plan /run/ai-security-scanner/execution-journal-v2.json` |
| Adapter | `extract_naabu_inventory`, `extract_httpx_inventory` and `extract_nuclei` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-external.yml`: job `launcher-tests` (gofmt and `go test -v ./...` in the pinned `golang:1.26.0-alpine` image), then one `publish` matrix entry per engine |

## How it is wired

- **Inputs.** `run` accepts only the flags above and the exact mount paths. `AI_SECURITY_SCANNER_PROXY` must be `socks5h://<gateway-ip>:1080` with a literal IP (`managedProxy`). `loadScope` reads at most 4 MiB with `DisallowUnknownFields` and requires `schema_version` `"2"` and the matching `engine_id`. The host writes that document as `ScopeDocument` in `src-tauri/src/orchestrator.rs` (`"2"` only for the engines `uses_external_launcher` names).
- **Grant checks** (`validateAndPlan`, `validateGrant`). Nuclei needs `active_external_testing`/`active_external`; Naabu and httpx need `low_impact_external_connection`/`low_impact_external`. Every grant needs an authorization reference, at most 30 days of validity, no UDP, asset identifiers equal to the canonical target, canonical frozen addresses inside the target, and a rate policy within 25 requests/s, 10 concurrent, 1,800 s (low impact) or 10, 5, 3,600 s (active) (`validateRatePolicy`). httpx and Nuclei need an `http`/`https` grant and refuse `network` targets; Naabu accepts `tcp`, `tls`, `http` and `https`. All grants in one run must belong to one case.
- **Units.** Naabu runs one process per grant over its frozen address list; httpx and Nuclei run one per grant port. Units are sorted by asset, grant and port. Frozen addresses are used as given; nothing resolves DNS (822a67a).
- **Child process** (`runCommand`). No stdin, stderr capped at 64 KiB, its own process group killed with SIGKILL at the deadline, which is the earlier of the invocation timeout and the grant expiry. `childEnvironment` points every proxy variable at the gateway, empties `NO_PROXY`, and moves `HOME` and caches into a private `/tmp` directory.
- **Evidence** (`normalizeEvidence`, `validateEvidenceObject`). Every line must be a JSON object inside its unit's grant: port and frozen address for Naabu; scheme, host and port for httpx and Nuclei; an allowlisted template ID for Nuclei. Each record gains `asset_id`, `scope_grant_id` and `scope_target` and loses `request`, `response`, `template`, `curl-command`, `body` and `raw`. Caps: 16 MiB per line, 512 MiB per run.
- **Exit contract.** Legacy mode (httpx, Nuclei) writes `/output/<engine>.jsonl` exclusively and deletes it unless every unit completed. Any error prints `external engine launcher: <reason>` (with up to 1 KiB of the scanner's stderr) and exits 126, and `orchestrator.rs` fails the check with "scanner container exited with status Some(126)". Journal mode (Naabu only) exits 0 when the only problem is incomplete units (`launcherOutcomeIsProcessSuccess`); see [naabu.md](naabu.md).
- **Runtime.** The images are `FROM scratch` with `USER 65532:65532`. The container runtime adds `--read-only --cap-drop=ALL --security-opt=no-new-privileges:true`, a `/tmp` tmpfs, a writable `/output` mount, read-only scope and plan mounts, and only the internal network behind the [egress gateway](egress-gateway.md).

## Downstream changes

None to upstream detection; the launcher only enforces the [section 2](../engine-maintenance.md#2-thin-adapter-boundary) boundaries. The per-engine workarounds it carries are listed on the [Naabu](naabu.md), [httpx](httpx.md) and [Nuclei](nuclei.md) pages.

## Lessons from real runs

- 2026-08-28: the process deadline equaled the per-connection `timeout_seconds`, and pinned Naabu halves `-rate` behind a proxy -> workload-sized deadlines and a compensated Naabu rate (f50d967). One Naabu process per frozen address paid startup for every address of a /24 -> one process per grant reading a private `-list` file, with deadlines capped at 4 h (Naabu) and 2 h (httpx, Nuclei) (2641850).
- 2026-08-31: the Dockerfiles copied only `go.mod`, `main.go` and `main_test.go`, but the build's `go test ./...` reads `testdata/` -> all three copy `testdata/` (7514fd0).
- 2026-09-30: the published `-5` images (built from 7514fd0) rejected scopes carrying `template_policy.profile_id` (added in ef1c653) as malformed, and website checks ended without a result. The push-triggered rebuilds on 2026-09-08 and 2026-09-09 had stopped at the guard that refuses to overwrite an existing tag -> all three moved to `-6` (1614d72).
- 2026-09-30: a launcher fix for Nuclei alone still moved all three images to `-7` (51b8abf, pinned in a493929).

## Updating this engine

- **Any change to `main.go`, `main_test.go`, `go.mod` or `testdata/` changes all three images.** Give all three new tags and update every site: the workflow matrix, catalog `image.tag`, each `plan.json` `final_artifact.tag`, each Dockerfile `org.opencontainers.image.version`, `managedExternalContracts` in `scripts/validate-engine-catalog.mjs`, `scripts/release/verify-publication-artifact.mjs`, `tests/release/verifyPublicationArtifact.test.mjs`, and the three engine pages. Find them with `grep -rn "<tag>" --exclude-dir=node_modules --exclude-dir=target --exclude-dir=.git --exclude-dir=.upstreams`. A push without a new tag stops at the publication guard and rebuilds nothing.
- **A passing validator does not prove the pinned image has your change.** `validate-engine-catalog.mjs` compares `wrapper.launcher_sha256` with the source `main.go`, not with the image. Compare each plan's `publication.source_revision` with `git log -- engines/images/external-launcher`.
- **Scope fields.** Before the host adds a field to the scope document (`ScopeDocument` in `orchestrator.rs`; `ExternalScopeGrant`, `RatePolicy` and `TemplatePolicy` in `src-tauri/src/external_scope.rs`), publish and pin a launcher that accepts it, or omit it when unset with `skip_serializing_if`. Tests: `TestScopeDecoderRejectsUnknownFields`, `TestScopeDecoderRequiresWireVersionTwoForEveryExternalEngine`, and `scope_document_preserves_only_the_exact_structured_external_grant` in `orchestrator.rs`.
- **Cross-language contract.** `testdata/naabu-launcher-plan-v2.json` and `-v3.json` are read by the Go tests and by `legacy_launcher_v2_fixture_bytes_and_digest_remain_frozen` and `launcher_v3_wire_contract_matches_the_shared_go_fixture` in `src-tauri/src/naabu_work_plan.rs`. The golden journal between `// LAUNCHER_V2_RUST_GOLDEN_START` and `// LAUNCHER_V2_RUST_GOLDEN_END` in `main_test.go` is read by `accepts_the_exact_go_emitted_golden_journal_contract` in `src-tauri/src/execution_coverage.rs`. Change both sides in one commit.
- **Files the tests read must be copied into each Dockerfile** (7514fd0), because the image build runs `go test ./...`.
- **Run the checks in the pinned toolchain**, as `launcher-tests` does: `gofmt -d main.go main_test.go` and `go test -v ./...` in `golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5`.
