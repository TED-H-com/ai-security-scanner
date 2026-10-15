# httpx

Collects HTTP service facts (status code, scheme, port, TLS) from one approved origin per grant port, under `low_impact_external_connection`. Results are typed service inventory, not findings; httpx emits no severity (b8b989a).

| Item | Value |
| --- | --- |
| Upstream | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx), version `1.12.0`, source ref `v1.12.0`, revision `4b6a9a9d476f94a4f3a630f37051f5671ecfb1f8`. |
| Image | `ghcr.io/ted-h-com/ai-security-scanner-engine-httpx:1.12.0-1` (`plan_kind: managed_source_image`), published for linux/amd64 and linux/arm64 by [this run](https://github.com/TED-H-com/ai-security-scanner/actions/runs/38761785926) from `f4489920283b9d897a8183469c9637f778e1310f`. Exact index/platform digests and verified evidence are in `engines/catalog.json` and `plan.json`. |
| Build inputs | `engines/images/httpx/Dockerfile` (checksum-pinned source archive, version and `go.sum` checks, `go mod verify`, the DNS patch below, `-mod=readonly`, `CGO_ENABLED=0`, `FROM scratch`), `patch_live_dns.go`, `patch_live_dns_test.go`, `SOURCE.md`, `plan.json`, and the [external launcher](external-launcher.md) |
| Launcher | `httpxInvocation` in `engines/images/external-launcher/main.go`; command `--engine httpx --scope /run/ai-security-scanner/scope.json --output /output` |
| Adapter | `extract_httpx_inventory` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-external.yml`, matrix entry `httpx` / `1.12.0-1` |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/httpx/Dockerfile) and context `.`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Scope.** A `low_impact_external_connection` grant whose external scope declares `http` or `https`, on a `domain`, `ip_address` or `web_service` asset, with at most 25 requests/s, 10 concurrent and a 1,800 s timeout. A `tcp` grant is refused for httpx and planned for Naabu, and the planner names the protocol mismatch (3b4b25e).
- **Network.** httpx gets `socks5h://<gateway-ip>:1080`, so the approved hostname travels to the gateway unchanged and keeps its HTTP Host and TLS SNI.
- **Invocation.** `-target <scheme>://<host>:<port> -proxy <gateway> -rate-limit -threads -timeout` from the grant, `-retries 0 -json -output <unit file> -status-code -omit-body -no-fallback-scheme -no-stdin -disable-update-check -silent -no-color`. The process deadline is the timeout plus 1 s plus 5 s.
- **Output.** Each record's `url` (or `input`) must have the grant's scheme, host and port. The launcher adds `asset_id`, `scope_grant_id` and `scope_target`, removes `request`, `response`, `template`, `curl-command`, `body` and `raw`, and for httpx also the DNS fields `host_ip`, `a`, `aaaa`, `cname` and `resolvers`. Result: `/output/httpx.jsonl`.
- **Mapping.** Each record becomes one service observation: endpoint from `host`, then `input`, then the URL host; status from `status_code` or `status-code` (100 to 599); port from `port`, else the URL default; scheme from `scheme`, else the URL; transport `tcp`; `tls` if present; asset from `asset_id`. A record without a target or status is skipped with a warning and stays in the raw artifact.
- **Failed or partial.** A launcher error exits 126 and the check fails. An empty `httpx.jsonl` from a completed run is a complete zero-observation result (`provably_complete_empty_released_jsonl_streams_are_zero_finding_results`).

## Downstream changes

- **Post-request DNS removed** (206ed74). `patch_live_dns.go` replaces the `getDNSData(hp, onlyHost)` block in `runner/runner.go` with empty `ips4`, `ips6`, `cnames` and `resolvers`, so httpx performs no second, live DNS lookup outside the gateway. The Dockerfile checks the file's SHA-256 before (`649a47aac12f176000b3ea26fb62e1a395e30d6009fd2bee3fb5285b9943daa2`) and after (`712382a9145071c020ee4f75ac71218e8bb9687dbab5980a813a1e59a00b6cfe`), runs the patch tests against the pinned file, and greps that the call is gone. The patch binary accepts only `--source /src/httpx/runner/runner.go`.
- **DNS fields stripped** from evidence by the launcher, as above.
- Plan `build_recipe.patch_audit` binds the exact 1.12.0 source pin, verified pre/post hashes, source reference, no-contribution rationale, owners and dedicated patch fixtures. Upstream standalone users rely on DNS enrichment, so a general removal would be inappropriate; seek a native opt-out that preserves proxy Host/SNI before removing this guard. Reviewed 2026-10-14; recheck on the next source update or by 2026-11-14.

## Lessons from real runs

- 2026-08-26: httpx's own DNS enrichment was a second lookup path outside the frozen addresses -> the source patch and DNS field stripping, together with scope schema `"2"` (206ed74).
- 2026-09-05: httpx records reached the report tagged `source-severity:` although httpx has no severity field -> derived severity basis (b8b989a); since 2026-09-08 they are typed inventory, not findings (d8fe70b).
- 2026-09-19: a domain whose grant declared `tcp` was reported as missing ownership for httpx while the same grant was planning Naabu -> each refusal cause now names the observed protocol (3b4b25e).
- 2026-09-30: the published `-5` image predated the shared launcher changes of ef1c653 and 601da4b, because push-triggered rebuilds stopped at the guard that refuses to overwrite an existing tag -> `-6` (1614d72), then `-7` for a Nuclei-only launcher fix (51b8abf, pinned in a493929).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Patch first.** If the new revision changes `runner/runner.go`, the pre-patch hash check stops the build. Check whether upstream can now skip post-request DNS; if so, drop the patch and its Dockerfile steps. Otherwise re-derive `liveDNSBlock`, both hashes (in `patch_live_dns.go`, the Dockerfile and `SOURCE.md`), and run `HTTPX_PINNED_RUNNER=<runner.go> go test patch_live_dns.go patch_live_dns_test.go` (`TestPinnedSourceTransformsToTheReviewedHashWhenProvided`, `TestReviewedReplacementRemovesOnlyPostRequestLiveDNS`, `TestReviewedReplacementRejectsAbsentDuplicateAndAlreadyPatchedBlocks`, `TestPatchCLIIsBoundToThePinnedContainerPath`).
- **Output shape.** Re-check `url`, `input`, `host`, `port`, `scheme`, `status_code`, `tls` and the DNS field names the launcher strips. Check what `host` carries through the proxy, because the adapter prefers it as the endpoint. Confirm `-no-fallback-scheme` and `-omit-body` still exist.
- **Tests.** Launcher: `TestStaticInvocationsCarryEveryFrozenLimit`, `TestEvidenceIsReattributedAndOutOfScopeRecordsFail`. Adapter: `src-tauri/tests/adapter_fixtures.rs` with `fixtures/adapters/httpx.jsonl` (`native_fixtures_normalize_without_inventing_inventory_findings`, `inventory_fixtures_preserve_typed_upstream_facts_and_exact_provenance`, `service_inventory_uses_a_path_free_endpoint_that_report_code_can_correlate`, `secret_values_and_target_instructions_never_enter_findings`, `missing_primary_result_shapes_are_incomplete_but_known_empty_shapes_are_complete`).
- **Hard-coded tag.** `1.12.0-1` appears in the workflow matrix, catalog `image.tag`, `plan.json` `final_artifact.tag`, the Dockerfile version label, `scripts/validate-engine-catalog.mjs`, `scripts/release/verify-publication-artifact.mjs`, `tests/release/verifyPublicationArtifact.test.mjs` and this page. A launcher change moves all three external tags ([external launcher](external-launcher.md#updating-this-engine)). `support_until` is 2026-12-07.
- **Compare with raw output.** Run the pinned image with `--entrypoint /usr/local/bin/httpx` and the launcher's flags against `<local-test-origin>`, then compare with the run's `httpx.jsonl`: the same records, with only the three scope keys added and the eleven keys above removed. Each record should appear as one service observation with the same host, port, scheme and status.

## 2026-10-14 source update

The replacement recipe targets `1.12.0-1` at upstream commit `4b6a9a9d476f94a4f3a630f37051f5671ecfb1f8`. The replacement is now published and pinned in the current catalog; the verified publication is recorded below. See the [batch update record](updates/2026-10-14.md) for changed inputs, retained rules and verification.

## 2026-10-15 verified publication

[Publication run](https://github.com/TED-H-com/ai-security-scanner/actions/runs/38761785926) binds both platform images to `f4489920283b9d897a8183469c9637f778e1310f`. Five source/SBOM attestations, four SBOMs, checksums and anonymous index, version tag, platform manifest and config bytes were independently verified before catalog activation. See the [batch verification record](updates/2026-10-14.md#verified-publication-and-catalog-activation) for native execution results and the remaining scope limits.
