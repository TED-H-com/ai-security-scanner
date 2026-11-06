# Nuclei

Runs upstream Nuclei HTTP templates against one approved website origin per grant port, under `active_external_testing` and the fixed profile `nuclei_web_safe_v1`. The profile is every template in the pinned snapshot that passes the launcher's read-only rules (4,777 at this pin), applied through Nuclei's technology-aware automatic scan.

| Item | Value |
| --- | --- |
| Upstream | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei), version `3.11.1`, revision `a8c88feb4a1c8e961b7902534ce3af97e9d524a4`. Rules/data identities are pinned in `engines/catalog.json`. |
| Image | `ghcr.io/ted-h-com/ai-security-scanner-engine-nuclei:3.11.1-9`, published for linux/amd64 and linux/arm64 by [run 42186918910](https://github.com/TED-H-com/ai-security-scanner/actions/runs/42186918910) from `5ba7d2e20f6eb8913aeb3097bed43860451ee522`. Exact digests and verified attestations are in [the publication record](updates/2026-11-06-publications.json). |
| Build inputs | `engines/images/nuclei/Dockerfile` (checksum-pinned source and template archives, version and `go.sum` checks, `go mod verify`, `-mod=readonly`, `CGO_ENABLED=0`, `FROM scratch`, revision marker `/opt/nuclei-templates/AI_SECURITY_SCANNER_REVISION`), `SOURCE.md`, `plan.json`, and the [external launcher](external-launcher.md) |
| Launcher | `nucleiInvocation`, `resolvedTemplateSelection` and `validateSafeTemplate` in `engines/images/external-launcher/main.go`; command `--engine nuclei --scope /run/ai-security-scanner/scope.json --output /output` |
| Adapter | `extract_nuclei` and the Nuclei branch of `normalize_artifacts` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-external.yml`, matrix entry `nuclei` / `3.11.1-9` |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/nuclei/Dockerfile) and context `.`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Scope.** The website path (`src/websiteQuickProfile.ts`) asks for `nuclei-templates@24858b4…`, profile `nuclei_web_safe_v1`, 10 requests/s, 5 concurrent and a 10 s timeout. `validateTemplatePolicy` requires that exact revision, exactly one of the profile or an explicit allowlist (at most 1,000 IDs, still supported), and all six `allow_*` capabilities false.
- **Template pool.** `verifyTemplateRevision` checks the marker file; `loadTemplateIndex` indexes `/opt/nuclei-templates/http`. `deriveNucleiWebSafeProfile` keeps each template `validateSafeTemplate` admits: top-level `http` only, method GET or HEAD, `max-request` 1 to 20, no redirects, no `payloads`, `attack`, `fuzzing`, `body` or `raw`, no `unsafe`, `race`, `iterate-all`, `cookie-reuse` or `threads`, no interactsh/OAST, multipart, `{{file` or `{{env`, none of the denied tags (for example `intrusive`, `dos`, `fuzz`, `default-login`, `rce`, `ssrf`), and request paths that stay on the input origin (`validateTemplateRequestOrigins`). If the result is not exactly `nucleiWebSafeTemplateCount` (4,777), the run stops.
- **Invocation.** `-target <scheme>://<host>:<port>`, template path and ID list files, `-type http`, `-rate-limit`, `-bulk-size` and `-concurrency` from the grant, `-payload-concurrency 1`, `-retries 0`, 4 MiB read and 1 MiB save, `-jsonl -matcher-status -disable-clustering -no-httpx -no-interactsh -disable-redirects -no-stdin -disable-update-check -omit-raw -omit-template`, and for the profile `-automatic-scan -update-template-dir <private copy>`. The deadline budgets 20 requests per template (doubled plus one for the profile) and saturates at the 2 h ceiling, so a profile run always gets 2 h.
- **Proxy.** Nuclei gets `socks5://<gateway-ip>:1080`. v3.11.1 rejects the `socks5h` spelling but still resolves names through the proxy (comment in `run`; bdfe4c9).
- **Output.** stdout is captured into the unit file (`StdoutPath`), because the pinned `-o` writer does not newline-terminate records. Each record needs an allowlisted `template-id` and a `matched-at`, `url` or `host` URL with the grant's scheme, host and port. The merged result is `/output/nuclei.jsonl`.
- **Mapping.** A `matcher-status: false` record with no `error` counts as execution evidence for its `asset_id` and never becomes a finding. Other records become findings: rule = template ID, title `info.name` (fallback "Nuclei template <id>"), severity `info.severity`, then `severity`, then `unknown`, location `matched-at` without query or fragment, tags `template-tag:` and `matcher:`, references, and CWE and CVSS attributed to `nuclei`. Records with the same template, asset and location merge into one finding (`merge_finding`).
- **Failed or partial.** A launcher error exits 126 and the check fails. An asset with no execution evidence gets `NoSecurityTemplateExecutionEvidence` (not tested, never "no findings"). Gateway rate refusals add a Truncated coverage row ([egress gateway](egress-gateway.md)).

## Downstream changes

No upstream source patch. The launcher narrows and adapts upstream behavior:

- **Template subset.** Only templates passing `validateSafeTemplate` run; the catalog notice discloses the 4,777-template profile. Keep it.
- **`socks5://` proxy spelling** (bdfe4c9). Remove when the pinned Nuclei accepts `socks5h://`.
- **stdout capture with `-jsonl -matcher-status`** instead of `-jsonl-export` (601da4b), so non-matches survive as execution evidence.
- **`-disable-clustering`** (51b8abf), so every record keeps its exact upstream template ID.

## Lessons from real runs

- 2026-08-24: the v3.11.1 proxy parser rejects the gateway's `socks5h://` spelling -> the launcher passes the same endpoint as `socks5://`, which Nuclei still resolves through the proxy (bdfe4c9).
- 2026-09-09: a clean run left no proof that any template executed, because `-jsonl-export` carries only matches -> `-jsonl -matcher-status` captured from stdout (601da4b); a non-match record is never a finding (59c97bf).
- 2026-09-24: against a three-page site with a login form, Nuclei sent 17,958 requests and reported 13 findings, all on `/`: it has no crawler -> ZAP recorded as a complementary passive engine, not yet runnable (9361a40).
- 2026-09-25: against a local site that closes every connection, the gateway refused 210 Nuclei connections over its rate bound, only 635 of 853 reached the target, and Nuclei (retries off) still reported a completed scan -> refusals became a Truncated coverage row (e8d9e96), then over-rate connections wait for a slot: 0 refused, 845 of 853 reached, detections 7 -> 10, same duration (84bde80).
- 2026-09-30: the `-5` image rejected website scopes carrying `template_policy.profile_id` as malformed (1614d72) -> rebuilt as `-6`.
- 2026-09-30: against a live site a check stopped with "Nuclei emitted a template outside the frozen allowlist": clustered non-matches are reported under a synthetic `cluster-<hash>` ID -> `-disable-clustering`; against a local nginx, 1 cluster record became 16 allowlisted records with the same two matches (51b8abf, pinned as `-7` in a493929).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Template snapshot.** The revision appears in 12 tracked files (`git grep -l <revision>`): `engines/catalog.json`, `engines/upstreams.lock.json`, `engines/images/external-launcher/main.go`, the Nuclei `Dockerfile`, `SOURCE.md` and `plan.json`, `scripts/validate-engine-catalog.mjs`, `NUCLEI_TEMPLATE_REVISION` in `src-tauri/src/beginner_report.rs`, `DECLARED_WEBSITE_TEMPLATE_REVISION` in `src-tauri/src/case_service.rs`, `src/websiteQuickProfile.ts`, `tests/component/coverageConciseBoundaries.test.tsx` and `tests/frontend/websiteQuickProfile.test.ts`.
- **Template count.** Nothing in CI or the image smoke recounts the profile; a wrong count shows only when a website check stops. Extract the new snapshot and run `NUCLEI_TEMPLATE_ROOT=<extracted-tree> go test -run TestPinnedNucleiTemplateTreeWhenProvided -v` in `engines/images/external-launcher`; it logs `templates=<n>` and fails until the constant matches. Update `nucleiWebSafeTemplateCount`, `plan.json` `derived_template_count`, the check at `scripts/validate-engine-catalog.mjs` line 2248, the catalog notice, `docs/engine-catalog.md` and this page.
- **Output shape.** Re-check `template-id`, `matcher-status`, `error`, `matched-at`, `matcher-name` and `info` (`name`, `severity`, `description`, `remediation`, `tags`, `reference`, `classification`). Confirm `-matcher-status` still writes non-matches to stdout, `-disable-clustering` still prevents `cluster-<hash>` IDs, and whether the proxy parser now accepts `socks5h`.
- **Tests.** Launcher: `TestNucleiTemplateIndexAllowsOnlyBoundedReadOnlyHTTP`, `TestNucleiWebSafeProfileIsMechanicalBroadAndRejectsSideEffects`, `TestNucleiProfilePolicyRequiresExactlyOneKnownSelectionMode`, `TestNucleiAutomaticProfileHasNoFullTreeFallback`, `TestRunCommandCapturesStdoutWithoutOverwritingEvidence`, `TestStaticInvocationsCarryEveryFrozenLimit`. Adapter: `src-tauri/tests/adapter_fixtures.rs` with `fixtures/adapters/nuclei.jsonl` and `malformed-nuclei.jsonl` (`empty_nuclei_jsonl_is_normalized_to_a_missing_template_execution_outcome`, `nuclei_non_match_is_positive_execution_evidence_without_becoming_a_finding`, `malformed_jsonl_is_contained_while_valid_records_survive`, `fingerprints_are_stable_across_repeat_runs`) and the `nuclei_*` unit tests in `adapters/mod.rs`.
- **Hard-coded tag.** `3.11.1-9` appears in the workflow matrix, catalog `image.tag`, `plan.json` `final_artifact.tag`, the Dockerfile version label, `scripts/validate-engine-catalog.mjs`, `scripts/release/verify-publication-artifact.mjs`, `tests/release/verifyPublicationArtifact.test.mjs` and this page. A launcher change moves all three external tags ([external launcher](external-launcher.md#updating-this-engine)). `support_until` is 2027-01-20.
- **Compare with raw output.** As in 51b8abf and 84bde80, run the pinned image with `--entrypoint /usr/local/bin/nuclei` and the launcher's flags against `<local-test-origin>`, then compare with the run's `nuclei.jsonl`. The launcher only adds `asset_id`, `scope_grant_id` and `scope_target` and removes `request`, `response`, `template`, `curl-command`, `body` and `raw`. Every match should appear as a finding with the same template ID, `info.name` and `info.severity`; every error-free non-match only adds to the asset's execution count.
