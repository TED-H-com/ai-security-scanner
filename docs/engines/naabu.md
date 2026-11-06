# Naabu

Finds open TCP ports with a connect scan through the managed gateway on authorized `ip_address`, `host` and `domain` assets (hostname, address or network targets), under `low_impact_external_connection`. Results are typed service inventory, not findings; Naabu emits no severity (b8b989a). It is the only engine that runs in launcher journal mode.

| Item | Value |
| --- | --- |
| Upstream | [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu), version `2.7.0`, revision `041b70fd396e95b5ed2c19f879c18247078243bc`. Rules/data identities are pinned in `engines/catalog.json`. |
| Image | `ghcr.io/ted-h-com/ai-security-scanner-engine-naabu:2.7.0-1`, published for linux/amd64 and linux/arm64 by [run 42186918910](https://github.com/TED-H-com/ai-security-scanner/actions/runs/42186918910) from `5ba7d2e20f6eb8913aeb3097bed43860451ee522`. Exact digests and verified attestations are in [the publication record](updates/2026-11-06-publications.json). |
| Build inputs | `engines/images/naabu/Dockerfile` (checksum-pinned source archive, version and `go.sum` checks, `go mod verify`, `-mod=readonly`, `CGO_ENABLED=0`, `FROM scratch`), `SOURCE.md`, `plan.json`, and the [external launcher](external-launcher.md) |
| Launcher | `naabuInvocation` and `runNaabuLauncherV2` in `engines/images/external-launcher/main.go`; command `--engine naabu --scope /run/ai-security-scanner/scope.json --output /output --journal-version 2 --journal-plan /run/ai-security-scanner/execution-journal-v2.json` |
| Adapter | `extract_naabu_inventory` in `src-tauri/src/adapters/mod.rs`; journal reconciliation in `apply_naabu_launcher_v2_execution_report` and `adapt_and_persist_naabu_attempt` (`src-tauri/src/case_service.rs`) |
| Publish workflow | `.github/workflows/engine-images-external.yml`, matrix entry `naabu` / `2.7.0-1` |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/naabu/Dockerfile) and context `.`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Work plan.** `build_naabu_work_plan` (`src-tauri/src/naabu_work_plan.rs`) freezes grants and addresses once, with no DNS, and splits them into work units: quick-discovery units first, then inventory units. `select_naabu_attempt` takes the next prefix of unfinished units that fits one outer host timeout, at most 128 units and 10,000 address-port pairs. The host writes it as a schema-3 plan (`launcher_plan_v3`; attempts recorded with the older request schema re-derive the schema-2 plan with `legacy_launcher_plan_v2`), mounted read-only at `/run/ai-security-scanner/execution-journal-v2.json` with the label `ai.security-scanner.naabu-launcher-plan-sha256`; `materializeLauncherV2Plan` checks it against the scope.
- **Scope and network.** A `low_impact_external_connection` grant declaring `tcp`, `tls`, `http` or `https`, with at most 25 requests/s, 10 concurrent and a 1,800 s timeout. Naabu gets the gateway as `-proxy <gateway-ip>:1080`.
- **Invocation** per unit: `-list targets-<index>.txt` (the frozen addresses), `-port <grant ports> -scan-type c -proxy <gateway-ip>:1080 -rate <2 x min(rps, concurrency)> -c <concurrency> -timeout <timeout> -retries 0 -json -output <unit file> -no-stdin -disable-update-check -silent`. The process deadline is the unit's `conservative_deadline_seconds` from the plan.
- **Output.** Each record needs a granted `port` and a `host` or `ip` from the frozen set; `protocol` must be absent or `tcp` and is set to `tcp`. A completed unit is published to `/output/launcher-v2/units/unit-<index>/attempt-<n>.jsonl` and recorded in `/output/launcher-v2/journal.jsonl`; raw output that fails validation goes to `launcher-v2/quarantine/`.
- **Outcomes and exit.** Each unit ends `tested_complete`; `tested_partial` with `incomplete_reason` `failed` or `timed_out`, keeping the valid observations; `failed` or `timed_out` when nothing valid could be published (raw output quarantined); or `not_tested` when the grant expired or setup failed. The launcher exits 0 when only units are incomplete and 126 on a fatal error. The host treats the journal as authoritative whatever the exit code: it accepts the longest complete journal prefix with matching finals, and missing units stay not tested (comment in `orchestrator.rs`).
- **Mapping.** Only `validated_artifact_bindings` reach the adapter; if no unit published a final, the adapter is skipped. Each record becomes one service observation `<host or ip>:<port>` with transport `tcp`, `tls` if present, and the asset from `asset_id`.
- **Legacy mode.** Without the journal flags the launcher writes one `/output/naabu.jsonl` and discards it on any failure. The catalog and `plan.json` `output.path` describe only this mode; the shipped command always passes the journal flags.

## Downstream changes

No upstream source patch. The launcher works around two pinned behaviors:

- **Rate doubling** (f50d967). Pinned Naabu halves `-rate` whenever a proxy is set, so a 1 request/s grant would fall to its zero-rate behavior. The launcher passes `2 x min(rps, concurrency)`. Remove when upstream stops halving, together with `TestNaabuProxyRateNeverFallsToZeroOrExceedsGrant`.
- **Process deadline.** Naabu's `-timeout` is per connection, so the launcher sets a total deadline from the workload (f50d967, 2641850) and, in journal mode, from the plan.
- **Private target list** (2641850). `-list` keeps the exact frozen set without DNS and avoids the per-argument length limit for a large IPv6 set (`TestNaabuLargeIPv6SetUsesAPrivateListInsteadOfOneOversizedArgument`).

## Lessons from real runs

- 2026-08-28: the total process deadline was the per-connection `timeout_seconds`, and the proxy halving could take a 1 request/s grant to zero -> workload-sized deadline and doubled rate (f50d967); one process per address became one per grant with `-list` (2641850).
- 2026-08-30: in legacy mode one failed unit removes the whole `naabu.jsonl` and exits 126, discarding completed work -> per-unit finals, exact work units and the journal (5891d58, 1719405, 50bbe29).
- 2026-09-05: Naabu records reached the report tagged `source-severity:` although Naabu has no severity -> derived severity basis (b8b989a); since 2026-09-08 open ports are typed inventory, not findings (d8fe70b).
- 2026-09-30: the published `-5` image predated the shared launcher changes of ef1c653 and 601da4b, because push-triggered rebuilds stopped at the existing-tag guard -> `-6` (1614d72), then `-7` for a Nuclei-only launcher fix (51b8abf, pinned in a493929).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Output shape.** Re-check `host`, `ip`, `port`, `protocol` and `tls`. Confirm that Naabu still halves `-rate` behind a proxy, that `-scan-type c` works with `-proxy host:port`, and that `-list` reads one address per line.
- **Cross-language contract.** The plan and journal formats are shared with Rust: `testdata/naabu-launcher-plan-v2.json` and `-v3.json`, and the golden journal in `main_test.go` (see [external launcher](external-launcher.md#updating-this-engine)). Change both sides together.
- **Tests.** Launcher: the `TestNaabu*`, `TestLauncherV2*` and `TestLauncherV3*` tests, for example `TestNaabuTotalDeadlineCoversTheBoundedPortWorkload`, `TestLauncherV2KeepsCompletedSiblingWhenLaterUnitFails` and `TestLauncherV2PreservesValidObservationsFromFailedScannerAsTestedPartial`. Adapter: `src-tauri/tests/adapter_fixtures.rs` with `fixtures/adapters/naabu.jsonl` (`native_fixtures_normalize_without_inventing_inventory_findings`, `inventory_fixtures_preserve_typed_upstream_facts_and_exact_provenance`, `service_inventory_uses_a_path_free_endpoint_that_report_code_can_correlate`, `provably_complete_empty_released_jsonl_streams_are_zero_finding_results`). Plan: the tests in `src-tauri/src/naabu_work_plan.rs`.
- **Hard-coded tag.** `2.6.1-7` appears in the workflow matrix, catalog `image.tag`, `plan.json` `final_artifact.tag`, the Dockerfile version label, `scripts/validate-engine-catalog.mjs`, `scripts/release/verify-publication-artifact.mjs`, `tests/release/verifyPublicationArtifact.test.mjs` and this page. A launcher change moves all three external tags. `support_until` is 2026-11-22.
- **Compare with raw output.** Run the pinned image with `--entrypoint /usr/local/bin/naabu` and the flags above against `<local-test-host>`, then compare with `launcher-v2/units/unit-<index>/attempt-<n>.jsonl`: the same open ports, with only `asset_id`, `scope_grant_id` and `scope_target` added and `protocol` set to `tcp`. Each port should appear as a service observation with the same host and port, and each unit's journal outcome should match what the scanner did.
