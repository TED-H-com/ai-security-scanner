# Greenbone

Runs openvasd from the Greenbone OpenVAS Scanner, with an embedded signed Community Feed snapshot, against one exact internal host or service per grant through the managed SOCKS gateway. The internal-host path uses the feed-derived profile `greenbone_remote_safe_v1`; the internal device and endpoint paths send explicit OID allowlists.

| Item | Value |
| --- | --- |
| Upstream | [greenbone/openvas-scanner](https://github.com/greenbone/openvas-scanner) v23.50.24, revision `26465a11ff0e6a98d60a253265fab5974fc757b6`; Community Feed `202610010558-community` (`FEED_COMMIT` `816c24126e0375d32c667b78d20342ce7c58ec58`); Notus `202610010540` |
| Image | `ghcr.io/teddashh/ai-security-scanner-engine-greenbone:23.50.24-feed202610010558-1` (`plan_kind: multi_component_build`, license disposition `source_offer`). The published digest is pinned in `engines/catalog.json`. |
| Build inputs | `engines/images/greenbone/`: `Dockerfile`, eleven `openvasd-*.patch`, `SOURCE-OFFER.md`, `THIRD-PARTY-NOTICES.md`, `managed-socks-smoke.sh`, `plan.json`; launcher sources in `engines/images/greenbone-launcher/` |
| Launcher | `engines/images/greenbone-launcher/main.go` ([Greenbone launcher](greenbone-launcher.md)) |
| Wrapper | None beyond the launcher |
| Adapter | `parse_greenbone_xml` and `extract_greenbone` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-image-greenbone.yml`: native amd64 and arm64 builds, each with a real smoke scan, then the same smoke against the anonymously pulled index |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/greenbone/Dockerfile) and context `.`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Input.** Catalog asset kinds `ip_address`, `host` and `web_service`, each with an `active_external_testing` grant whose external scope names one canonical hostname or address, sorted TCP ports and a template policy bound to `greenbone-community-feed@<FEED_COMMIT>`. Product profiles:
  - internal host (`src/internalHostProfile.ts`): `greenbone_remote_safe_v1`, default ports 22, 23, 25, 80, 443, 445, 3389, 5900, 8080 and 8443, 2 requests per second, concurrency 1, 15 s timeout.
  - internal device and internal endpoint: explicit OID lists in `src/internalDeviceProfile.ts`, `src/internalEndpointProfile.ts`, and the `INTERNAL_DEVICE_*_OIDS` and `INTERNAL_ENDPOINT_*_OIDS` constants in `src-tauri/src/case_service.rs` and `src-tauri/src/beginner_report.rs`.
- **Network and resources.** `managed_allowlist` to the authorized target addresses only; the launcher reaches targets solely through `AI_SECURITY_SCANNER_PROXY`. Catalog `execution.resources`: 8192 MB memory, 2000 CPU millis, 256 pids, 7200 s. The `/tmp` tmpfs is `estimated_disk_mb` clamped to 4096 MB (`src-tauri/src/commands.rs`).
- **Invocation.** `--engine greenbone --scope /run/ai-security-scanner/scope.json --output /output`. The launcher starts a private openvasd on `127.0.0.1:3000` (in-memory storage, `--feed-signature-check`, one scan at a time), runs one scan per grant against loopback relays on `127.0.0.2:<approved port>`, and relays each connection to the exact target through the gateway.
- **Output.** Only `/output/greenbone.xml`, a GMP-shaped `<get_reports_response>` the launcher writes from openvasd's results and the feed metadata (mode 0600, at most 512 MiB). openvasd's own JSON never leaves the container.
- **Mapping.** `extract_greenbone`:
  - `alarm` with a positive `<severity>` becomes a finding rated by score (`parse_severity`: 9 Critical, 7 High, 4 Medium, above 0 Low). An `alarm` at `0.0` stays a finding with Unknown severity (`UnratedVulnerabilityTestAlarm`).
  - `log` produces nothing. `error` and `dead_host` become per-asset coverage gaps (`ScannerError`, `TargetDidNotRespond`).
  - Rule id is the NVT OID, else the first CVE. Title is the NVT name, location `<host>:<port>/tcp`. `<qod>` becomes a `quality-of-detection:N` tag; an absent QoD gives Unknown confidence (`MissingDetectionQualityScore`). `summary` and `solution` become scanner details; CVEs become `cve:` tags and NVD references.
  - `description`, `raw_host`, `raw_port`, `relay_mapping` and `scope_grant_id` stay in the raw artifact only.
  - An authorized asset with no `alarm` or `log` on a nonzero port and no `dead_host` gets `NoServiceIdentified` and is listed under Not tested: "No service identified on the approved ports. Vulnerability checks did not run for this host."
- **Failed, partial, not tested.** Any launcher error removes the XML and exits 126, so the run fails without normalizing (`src-tauri/src/orchestrator.rs`). This includes an invalid scope, a feed or selection failure, an openvasd scan failure in its grant, and one invalid result. New product runs isolate each grant into its own task/output; a failed grant cannot delete completed sibling grant results. The run is partial when the adapter warns: an unsupported `result_type`, a result naming no authorized asset, a result with neither OID nor CVE, a typeless result without a positive score (threat `Log` and `False Positive` are skipped), a read or parse warning (over 200,000 XML events, non-UTF-8 text, DOCTYPE or custom entity, depth over 64, more than 256 attributes), or exceeded streaming parser/record budgets. Artifacts above 16 MiB stream up to the 512 MiB serialized boundary; omitted evidence withholds complete coverage. `error` and `dead_host` keep the run complete and report the gap per asset.

## Downstream changes

Eleven focused openvasd source patches are rebased onto 23.52.9 and applied with `patch --batch --fuzz=0`. The 2026-11-06 audit records 18 source-file transitions, their native regression modules and a 2026-12-06 review deadline. The former mixed service-port patch is split into service ports, local declarations, dictionary, string and value-conversion fixes. Upstream now stores result ports as `u16`, so the obsolete storage/model widening is removed; the remaining NASL boundary accepts only valid ports. The source recipe retains upstream detection logic.

| Patch | Upstream files (`rust/src/`) | Change |
| --- | --- | --- |
| `rustls-provider` | `openvasd/main.rs` | Installs the AWS-LC rustls provider at process start; a NASL TLS client could build a `ClientConfig` before the lazy install and panic a worker. |
| `service-port` | `scanner/vt_runner.rs`, `nasl/builtin/find_service/`, `nasl/interpreter/` (4 files), `nasl/builtin/string/`, `nasl/utils/function/from_nasl_value.rs` | Required ports are alternatives and `Services/...` names are KB keys; find_service stores the port as a number. Also bundles unrelated NASL fixes: `local_var` keeps an argument's value, a missing dict key is NULL, `string()` and `strcat()` escapes match the C implementation. |
| `http-compat` | `nasl/builtin/http/mod.rs` | No trailing space in the request line, `Host: <host>:<port>` instead of `<host>/<port>`, auth from the per-port then global `http/auth` KB item instead of the literal text, CRLF after an HTTP/1.0 request line. |
| `nasl-array-compat` | `nasl/interpreter/nasl_value.rs`, `nasl/interpreter/tests/mod.rs` | An out-of-range array index returns NULL. Touches the same files as `service-port`, so order matters. |
| `eregmatch-captures` | `nasl/builtin/regex/` | `eregmatch` returns capture groups (at most 16, unmatched as NULL). |
| `report-port` | `models/result.rs`, `nasl/builtin/report/`, `openvas/result_collector.rs`, `openvasd/database/sqlite/results.rs` | Result port widened from i16 to i32; ports 1 to 65535 accepted as number, string or data. |
| `socket-eof` | `nasl/builtin/network/socket.rs` | `recv` stops at end of stream and when the one-second follow-up read returns WouldBlock (upstream matches only TimedOut); the FTP reply reader stops at end of stream. |

- **Feed and runtime base.** The feed and Notus come from `registry.community.greenbone.net/community/{vulnerability-tests,notus-data}` by digest, recorded in the plan with the rolling `community` tag. The build checks `FEED_COMMIT` in `plugin_feed_info.inc` and requires `vt-metadata.json`, `sha256sums` and `sha256sums.asc`; the launcher starts openvasd with `--feed-signature-check`. The runtime base is `ghcr.io/greenbone/openvas-scanner` 23.50.24 by digest, because GHCR keeps scanner release tags (5549628).
- **Image hardening.** The runtime stage removes `nmap` and the `openvas` binary after dropping their file capabilities, and asserts that no capabilities remain under `/usr/bin` and `/usr/local`.
- **Launcher translations.** openvasd results carry no severity, so the launcher computes it from the VT's CVSS vector and maps six QoD types to numbers; see [Greenbone launcher](greenbone-launcher.md#downstream-changes).

## Lessons from real runs

- 2026-09-17: the image could not be rebuilt -> the community registry had deleted every pinned base digest -> held at the last published image (85f92b1), then refreshed to 23.50.24 and feed 202609170605 (c668b6d) and pinned (070dcbf).
- 2026-10-01: a Greenbone scan failed with exit 126 when the launcher's status poll timed out after 30 s -> `cpu_millis` was never applied, so openvasd ran one worker that starved its own status API -> the container now gets the reviewed CPU allowance, capped at the host's CPUs (2ddaec2).
- 2026-10-01: a finished scan was recorded as partial -> removing the exited container took about 35 s, past the 30 s control deadline, and a cleanup error returns before the adapter runs -> removal gets two minutes (510e660).
- 2026-10-01: a local nginx fixture on port 18080 produced only host-level `0/tcp` results and the host read as checked -> openvasd runs service checks only after it identifies a service -> `NoServiceIdentified` under Not tested (c90aef1).
- 2026-10-01: a scan ran at 100% CPU for 76 minutes -> `recv` looped on a closed socket after `interchange_detect.nasl` -> `socket-eof` patch (6924f73). Its `-2` image never built because the registry had deleted the bases again 14 days after measurement; the runtime base moved to GHCR and the feed to 202610010558 (5549628), published and pinned as `-1` with five XML results, one alarm, one finding and no warnings in the smoke (5a8d14b).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Registry expiry.** The previous VT and Notus digests returned 404 fourteen days after they were measured. Re-measure the `community` tags in one sitting (index digest, per-platform digests, `PLUGIN_SET`, `FEED_COMMIT`, Notus timestamp) before rebuilding, and refresh before the current digests disappear rather than after a build fails. [Registry retention consequence](../greenbone-refresh-analysis.md#registry-retention-consequence) has the last measurement; a durable mirror is an open owner decision there.
- **Feed revision moves everywhere at once.** `FEED_COMMIT` appears in the workflow, `engines/catalog.json`, the Dockerfile, `SOURCE-OFFER.md`, `THIRD-PARTY-NOTICES.md`, the smoke, `feedRevision` in the launcher, `managedGreenboneContract` in `scripts/validate-engine-catalog.mjs`, `src/internalDeviceProfile.ts`, `src/internalEndpointProfile.ts`, `src/internalHostProfile.ts`, `src-tauri/src/beginner_report.rs`, `src-tauri/src/case_service.rs`, `src-tauri/src/export.rs`, `tests/frontend/internalDeviceProfile.test.ts`, `tests/frontend/internalEndpointProfile.test.ts` and `docs/greenbone-refresh-analysis.md`. A grant whose policy revision differs from the launcher's is refused.
- **New feed contents.** Every explicit OID in the product lists must still exist as `gather_info` with dependencies only in safe categories, and `2011/openvas_tcp_scanner.nasl` must keep OID `1.3.6.1.4.1.25623.1.0.10335`; otherwise every affected run fails. For `greenbone_remote_safe_v1`, one selected VT with an unresolved, cyclic or unsafe-category dependency fails every internal-host run. Renamed families, categories or `tag` fields change the remote-safe selection silently; see [Still silent or only partially visible](../greenbone-refresh-analysis.md#still-silent-or-only-partially-visible) (its QoD bullets predate 4ec35b0).
- **Patches.** On each scanner release, try dropping each patch first. Each kept patch must apply at `--fuzz=0`, its `cargo test` module must pass, and its SHA-256 must appear in the Dockerfile `io.ai-security-scanner.openvas-patch` label; `validateGreenboneBuildClosure` also checks the eleven patch names.
- **Two-step publication.** Change the build inputs with a new tag, set the plan to `publication_in_progress` with a null digest, and keep a temporary contract for the still-published image in the validator (5549628). After the workflow publishes, pin the digest and remove the temporary contract (5a8d14b). The tag `23.50.24-feed202610010558-1` is hard-coded in the workflow (`concurrency.group`, `IMAGE_TAG`), catalog `image.tag`, plan `final_artifact.tag`, the Dockerfile version label, and `managedGreenboneContract.tag` and `greenbonePublicationBlocker` in the validator. `support_until` is 2026-11-22.
- **Smoke.** The workflow greps `xml_results=5 actionable_alarms=1`, `"finding_count":1` and `"warnings":[]` for explicit OID `1.3.6.1.4.1.25623.1.0.108252` on an `Apache/2.4.27` fixture at port 8080, with a gateway built from source. It does not exercise `greenbone_remote_safe_v1`. If a new feed changes the counts, read the preserved `greenbone.xml` (`KEEP_GREENBONE_SMOKE=1`) before changing the expectations.
- **Tests.** Launcher `go test` runs in the image build. Adapter: the `greenbone_*` tests in `src-tauri/src/adapters/mod.rs` (including `greenbone_xml_contract_binds_launcher_field_names`) and in `src-tauri/tests/adapter_fixtures.rs`, with fixtures `greenbone.xml` and `greenbone-result-types.xml`; `src-tauri/examples/greenbone_adapter_smoke.rs` runs in the smoke. Mappings: the two prefixes `1.3.6.1.4.1.25623.` and `CVE-` in `mappings/control-mappings.json`.
- **Compare with raw output.** In the run's raw `greenbone.xml`, every `<result>` with `result_type` `alarm` should be one finding on its `asset_id`, with the `<nvt oid>` as rule id and `<severity>` deciding the band. `log` results should produce nothing, and each `error` or `dead_host` should appear as a coverage gap. A host whose results are all on `0/tcp` should be Not tested.
